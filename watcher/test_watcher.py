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


class GithubDiffTest(unittest.TestCase):
    def setUp(self):
        self.sent: list[list[str]] = []
        self._orig_notify, self._orig_fetch = w.notify, w.fetch_github
        w.notify = lambda cfg, lines: self.sent.append(lines)

    def tearDown(self):
        w.notify, w.fetch_github = self._orig_notify, self._orig_fetch

    def test_bootstrap_then_only_new(self):
        state = w.State()
        w.fetch_github = lambda cfg: ({"r#1": "alert1"}, {"r#2": "pr2"}, 3)
        w.run_github(make_cfg(), state)
        self.assertEqual(len(self.sent), 1)
        self.assertIn("watch started", self.sent[0][0])

        self.sent.clear()
        w.run_github(make_cfg(), state)
        self.assertEqual(self.sent, [])

        w.fetch_github = lambda cfg: ({"r#1": "alert1", "r#9": "alert9"}, {"r#2": "pr2"}, 3)
        w.run_github(make_cfg(), state)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0][1:], ["alert9"])


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


if __name__ == "__main__":
    unittest.main()
