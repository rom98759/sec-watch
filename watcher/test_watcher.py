import datetime as dt
import tempfile
import unittest
from pathlib import Path

import watcher as w


def make_cfg(**overrides) -> w.Config:
    base = dict(
        discord_webhook="",
        github_token="token",
        docker_host="tcp://socket-proxy:2375",
        state_file=Path("/nonexistent/state.json"),
        trivy_cache=Path("/tmp/cache"),
        severities="CRITICAL,HIGH",
        scan_hour=4,
        weekly_day=0,
        github_interval_min=60,
        dry_run=True,
    )
    base.update(overrides)
    return w.Config(**base)


TRIVY_REPORT = {
    "Results": [
        {
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2 ", "PkgName": "zlib", "Severity": "HIGH"},
                {"VulnerabilityID": "CVE-1", "PkgName": "openssl", "InstalledVersion": "3.0",
                 "FixedVersion": "3.1", "Severity": "CRITICAL", "Title": "bad"},
            ]
        },
        # same CVE+pkg reported by two layers/targets must be counted once
        {"Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "openssl", "Severity": "CRITICAL"}]},
        {"Vulnerabilities": None},
    ]
}


class ParseTrivyTest(unittest.TestCase):
    def test_dedup_and_sort_by_severity(self):
        vulns = w.parse_trivy(TRIVY_REPORT)
        self.assertEqual([v.severity for v in vulns], ["CRITICAL", "HIGH"])
        self.assertEqual(len(vulns), 2)

    def test_empty_report(self):
        self.assertEqual(w.parse_trivy({}), [])

    def test_new_findings_only_unseen(self):
        vulns = w.parse_trivy(TRIVY_REPORT)
        fresh = w.new_findings(["CVE-1|openssl"], vulns)
        self.assertEqual([v.pkg for v in fresh], ["zlib"])

    def test_count_by_severity(self):
        self.assertEqual(w.count_by_severity(w.parse_trivy(TRIVY_REPORT)), "1 critical, 1 high")
        self.assertEqual(w.count_by_severity([]), "clean")


class ChunkTest(unittest.TestCase):
    def test_respects_limit(self):
        chunks = w.chunk_message(["x" * 900] * 5, limit=2000)
        self.assertTrue(all(len(c) <= 2000 for c in chunks))
        self.assertEqual(sum(c.count("x") for c in chunks), 4500)

    def test_truncates_single_long_line(self):
        self.assertTrue(len(w.chunk_message(["y" * 5000])[0]) <= 2000)


class LinkHeaderTest(unittest.TestCase):
    def test_next(self):
        h = '<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=5>; rel="last"'
        self.assertEqual(w.next_link(h), "https://api.github.com/x?page=2")

    def test_none(self):
        self.assertIsNone(w.next_link(None))
        self.assertIsNone(w.next_link('<https://a>; rel="prev"'))


class FetchRetryTest(unittest.TestCase):
    def setUp(self):
        self._orig = (w.urllib.request.urlopen, w.time.sleep)
        w.time.sleep = lambda s: None

    def tearDown(self):
        w.urllib.request.urlopen, w.time.sleep = self._orig

    def test_retries_incomplete_read_then_succeeds(self):
        calls = []

        class Resp:
            headers = {"Link": None}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b"[1, 2]"

        def urlopen(req, timeout):
            calls.append(1)
            if len(calls) == 1:
                raise w.http.client.IncompleteRead(b"", 10)
            return Resp()

        w.urllib.request.urlopen = urlopen
        body, nxt = w.fetch_json(w.urllib.request.Request("https://x"))
        self.assertEqual((body, nxt, len(calls)), ([1, 2], None, 2))

    def test_client_error_not_retried(self):
        calls = []

        def urlopen(req, timeout):
            calls.append(1)
            raise w.urllib.error.HTTPError("https://x", 403, "forbidden", {}, None)

        w.urllib.request.urlopen = urlopen
        with self.assertRaises(w.urllib.error.HTTPError):
            w.fetch_json(w.urllib.request.Request("https://x"))
        self.assertEqual(len(calls), 1)


class ScheduleTest(unittest.TestCase):
    def test_trivy_waits_for_scan_hour(self):
        state = w.State(github_last_check=dt.datetime(2026, 10, 19, 3).timestamp())
        _, trivy, _ = w.due_tasks(make_cfg(), state, dt.datetime(2026, 10, 19, 3, 59))
        self.assertFalse(trivy)

    def test_trivy_once_per_day_and_weekly_on_monday(self):
        cfg = make_cfg()
        monday = dt.datetime(2026, 10, 19, 4, 5)
        _, trivy, weekly = w.due_tasks(cfg, w.State(), monday)
        self.assertTrue(trivy and weekly)
        done = w.State(trivy_last_scan="2026-10-19", trivy_last_weekly="2026-10-19")
        self.assertEqual(w.due_tasks(cfg, done, monday)[1:], (False, False))

    def test_github_disabled_without_token(self):
        github, _, _ = w.due_tasks(make_cfg(github_token=""), w.State(), dt.datetime.now())
        self.assertFalse(github)


def alert(repo: str, number: int, severity: str = "HIGH", package: str = "next") -> w.Alert:
    return w.Alert(repo, number, severity, package, f"bug {number}", f"https://gh/{repo}/a/{number}")


def pr(repo: str, number: int, title: str = "Bump next from 14 to 15", body: str = "") -> w.PullRequest:
    return w.PullRequest(repo, number, title, body, f"https://gh/{repo}/pull/{number}")


class RepoCardTest(unittest.TestCase):
    def test_summary_card(self):
        alerts = [alert("o/r", 1, "HIGH"), alert("o/r", 2, "CRITICAL"), alert("o/r", 3, "HIGH", "ws")]
        card = w.repo_card("o/r", alerts, [pr("o/r", 7)])
        self.assertEqual(card["title"], "o/r")
        self.assertEqual(card["url"], "https://github.com/o/r/security/dependabot")
        self.assertEqual(card["color"], w.SEVERITY_COLOR["CRITICAL"])
        self.assertIn("1 critical", card["description"])
        self.assertIn("2 high", card["description"])
        self.assertIn("`next` (2)", card["description"])
        self.assertIn("[#7 Bump next from 14 to 15](https://gh/o/r/pull/7)", card["description"])
        # ws has no Dependabot PR mentioning it
        self.assertIn("No open PR for: `ws`", card["description"])

    def test_package_named_in_grouped_pr_body_counts_as_covered(self):
        grouped = pr("o/r", 8, "Bump the npm group with 2 updates", "Bumps [ws](https://x) and next")
        card = w.repo_card("o/r", [alert("o/r", 1, package="ws")], [grouped])
        self.assertNotIn("No open PR", card["description"])

    def test_package_names_grouped_case_insensitively(self):
        card = w.repo_card("o/r", [alert("o/r", 1, package="Pillow"), alert("o/r", 2, package="pillow")], [])
        self.assertIn("`Pillow` (2)", card["description"])
        self.assertNotIn("`pillow`", card["description"])

    def test_link_text_is_escaped(self):
        card = w.repo_card("o/r", [], [pr("o/r", 1, "Bump [x] from 1 to 2")])
        self.assertIn(r"\[x\]", card["description"])


class BatchEmbedsTest(unittest.TestCase):
    def test_limits(self):
        embeds = [{"title": "t", "description": "d" * 1000} for _ in range(25)]
        batches = w.batch_embeds(embeds)
        self.assertEqual(sum(len(b) for b in batches), 25)
        for b in batches:
            self.assertLessEqual(len(b), 10)
            self.assertLessEqual(sum(len(e["title"]) + len(e["description"]) for e in b), 6000)


class GithubDiffTest(unittest.TestCase):
    def setUp(self):
        self.sent: list[list[dict]] = []
        self._orig = (w.send_embeds, w.fetch_github, w.fetch_pr_state)
        w.send_embeds = lambda cfg, embeds: self.sent.append(embeds)

    def tearDown(self):
        w.send_embeds, w.fetch_github, w.fetch_pr_state = self._orig

    def fetch(self, alerts, prs):
        w.fetch_github = lambda cfg: ({a.key: a for a in alerts}, {p.key: p for p in prs}, 3)

    def test_bootstrap_one_card_per_repo_worst_first(self):
        self.fetch([alert("o/low", 1, "MEDIUM"), alert("o/bad", 1, "CRITICAL")], [pr("o/pr", 1)])
        w.run_github(make_cfg(), w.State())
        embeds = self.sent[0]
        self.assertIn("watch started", embeds[0]["title"])
        self.assertEqual([e["title"] for e in embeds[1:]], ["o/bad", "o/low", "o/pr"])

    def test_bootstrap_then_only_changes(self):
        state = w.State()
        self.fetch([alert("o/r", 1)], [pr("o/r", 2)])
        w.run_github(make_cfg(), state)
        self.sent.clear()
        w.run_github(make_cfg(), state)
        self.assertEqual(self.sent, [])

        self.fetch([alert("o/r", 1), alert("o/r", 9, "CRITICAL")], [pr("o/r", 2)])
        w.run_github(make_cfg(), state)
        (card,) = self.sent[0]
        self.assertEqual(card["color"], w.SEVERITY_COLOR["CRITICAL"])
        self.assertIn("https://gh/o/r/a/9", card["description"])
        self.assertNotIn("https://gh/o/r/a/1", card["description"])

    def test_merged_pr_and_resolved_alerts(self):
        state = w.State()
        self.fetch([alert("o/r", 1), alert("o/r", 2)], [pr("o/r", 5)])
        w.run_github(make_cfg(), state)
        self.sent.clear()

        w.fetch_pr_state = lambda cfg, key: "merged"
        self.fetch([alert("o/r", 2)], [])
        w.run_github(make_cfg(), state)
        (card,) = self.sent[0]
        self.assertEqual(card["color"], w.MERGED_COLOR)
        self.assertIn("Merged", card["description"])
        self.assertIn("[#5](https://github.com/o/r/pull/5)", card["description"])
        self.assertIn("1 alert resolved", card["description"])
        self.assertIn("1 still open", card["description"])


class TrivyRunTest(unittest.TestCase):
    def setUp(self):
        self.sent: list[list[str]] = []
        self._orig = (w.notify, w.running_images, w.scan_image, w.update_trivy_db)
        w.notify = lambda cfg, lines: self.sent.append(lines)
        w.running_images = lambda cfg: ["app:1", "db:1"]
        w.update_trivy_db = lambda cfg: None

    def tearDown(self):
        w.notify, w.running_images, w.scan_image, w.update_trivy_db = self._orig

    def test_db_failure_without_cache_aborts_scan(self):
        w.update_trivy_db = self._orig[3]
        orig_trivy = w._trivy

        def boom(args, timeout_s):
            raise RuntimeError("deadline exceeded")

        w._trivy = boom
        try:
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaisesRegex(RuntimeError, "no cached DB"):
                    w.run_trivy(make_cfg(trivy_cache=Path(d)), w.State(), weekly=False)
        finally:
            w._trivy = orig_trivy

    def test_db_failure_with_cache_warns_and_scans(self):
        w.update_trivy_db = self._orig[3]
        orig_trivy = w._trivy

        def boom(args, timeout_s):
            raise RuntimeError("deadline exceeded")

        w._trivy = boom
        w.scan_image = lambda cfg, image: []
        try:
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "db").mkdir()
                (Path(d) / "db" / "trivy.db").write_text("x")
                state = w.State(trivy_bootstrapped=True)
                w.run_trivy(make_cfg(trivy_cache=Path(d)), state, weekly=False)
        finally:
            w._trivy = orig_trivy
        self.assertIn("cached DB", "\n".join(self.sent[-1]))

    def test_failed_scan_keeps_previous_findings(self):
        state = w.State(trivy_bootstrapped=True, trivy_seen={"db:1": ["CVE-1|openssl"]})

        def scan(cfg, image):
            if image == "db:1":
                raise RuntimeError("registry down")
            return []

        w.scan_image = scan
        w.run_trivy(make_cfg(), state, weekly=False)
        self.assertEqual(state.trivy_seen["db:1"], ["CVE-1|openssl"])
        self.assertIn("could not be scanned", self.sent[-1][0])

    def test_only_new_cves_are_sent(self):
        state = w.State(trivy_bootstrapped=True, trivy_seen={"app:1": ["CVE-1|openssl"]})
        w.scan_image = lambda cfg, image: w.parse_trivy(TRIVY_REPORT) if image == "app:1" else []
        w.run_trivy(make_cfg(), state, weekly=False)
        self.assertEqual(len(self.sent), 1)
        self.assertIn("zlib", self.sent[0][1])

    def test_first_run_sends_summary_only(self):
        state = w.State()
        w.scan_image = lambda cfg, image: w.parse_trivy(TRIVY_REPORT)
        w.run_trivy(make_cfg(), state, weekly=True)
        self.assertEqual(len(self.sent), 1)
        self.assertIn("first Trivy scan", self.sent[0][0])
        self.assertTrue(state.trivy_bootstrapped)

    def test_first_run_all_failed_does_not_bootstrap(self):
        state = w.State()

        def scan(cfg, image):
            raise RuntimeError("db download failed")

        w.scan_image = scan
        w.run_trivy(make_cfg(), state, weekly=False)
        self.assertFalse(state.trivy_bootstrapped)


class StateTest(unittest.TestCase):
    def test_roundtrip_and_unknown_keys_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s" / "state.json"
            s = w.State(trivy_last_scan="2026-10-22", github_alerts=["a#1"])
            s.save(p)
            p.write_text(p.read_text().replace("{", '{"legacy": 1,', 1))
            loaded = w.State.load(p)
            self.assertEqual(loaded.trivy_last_scan, "2026-10-22")
            self.assertEqual(loaded.github_alerts, ["a#1"])

    def test_dry_run_never_persists(self):
        # a dry run sharing the volume must not mark findings as already notified
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "state.json"
            w.persist(make_cfg(state_file=p, dry_run=True), w.State(github_bootstrapped=True))
            self.assertFalse(p.exists())
            w.persist(make_cfg(state_file=p, dry_run=False), w.State(github_bootstrapped=True))
            self.assertTrue(w.State.load(p).github_bootstrapped)


if __name__ == "__main__":
    unittest.main()
