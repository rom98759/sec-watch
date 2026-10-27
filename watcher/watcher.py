"""Security watcher: Trivy scans of running images and Dependabot activity, sent to Discord.

Stdlib only. State lives in a JSON file so that only *new* findings are notified.
"""

from __future__ import annotations

import argparse
import datetime as dt
import http.client
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("sec-watch")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
SEVERITY_ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "⬜", "UNKNOWN": "⬜"}
SEVERITY_COLOR = {"CRITICAL": 0xE5484D, "HIGH": 0xF76B15, "MEDIUM": 0xFFC53D, "LOW": 0x8B8D98, "UNKNOWN": 0x8B8D98}
MERGED_COLOR = 0x8957E5
RESOLVED_COLOR = 0x2EA043
NEUTRAL_COLOR = 0x5865F2
DISCORD_LIMIT = 2000
# Discord caps: 10 embeds and 6000 characters per message, 4096 per description
EMBEDS_PER_MESSAGE = 10
EMBEDS_TOTAL_LIMIT = 6000
EMBED_DESCRIPTION_LIMIT = 4096
MAX_LINES_PER_IMAGE = 15
MAX_LINKS_PER_CARD = 5


@dataclass
class Config:
    discord_webhook: str
    github_token: str
    docker_host: str
    state_file: Path
    trivy_cache: Path
    severities: str
    scan_hour: int
    weekly_day: int
    github_interval_min: int
    dry_run: bool

    @classmethod
    def from_env(cls, dry_run: bool) -> Config:
        data = Path(os.environ.get("DATA_DIR", "/data"))
        return cls(
            discord_webhook=os.environ.get("DISCORD_WEBHOOK_URL", ""),
            github_token=os.environ.get("GITHUB_TOKEN", ""),
            docker_host=os.environ.get("DOCKER_HOST", "tcp://socket-proxy:2375"),
            state_file=data / "state.json",
            trivy_cache=data / "trivy-cache",
            severities=os.environ.get("TRIVY_SEVERITY", "CRITICAL,HIGH"),
            scan_hour=int(os.environ.get("SCAN_HOUR", "4")),
            weekly_day=int(os.environ.get("WEEKLY_DAY", "0")),
            github_interval_min=int(os.environ.get("GITHUB_INTERVAL_MIN", "60")),
            dry_run=dry_run or os.environ.get("DRY_RUN", "") == "1",
        )


@dataclass
class Vuln:
    id: str
    pkg: str
    installed: str
    fixed: str
    severity: str
    title: str

    @property
    def key(self) -> str:
        return f"{self.id}|{self.pkg}"


@dataclass
class State:
    trivy_seen: dict[str, list[str]] = field(default_factory=dict)
    trivy_bootstrapped: bool = False
    trivy_last_scan: str = ""
    trivy_last_weekly: str = ""
    github_alerts: list[str] = field(default_factory=list)
    github_prs: list[str] = field(default_factory=list)
    github_bootstrapped: bool = False
    github_last_check: float = 0.0

    @classmethod
    def load(cls, path: Path) -> State:
        if not path.exists():
            return cls()
        raw = json.loads(path.read_text())
        return cls(**{k: v for k, v in raw.items() if k in cls.__dataclass_fields__})

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        # write-then-rename so a crash never leaves a truncated state file
        with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as tmp:
            json.dump(self.__dict__, tmp, indent=2)
        os.replace(tmp.name, path)


def persist(cfg: Config, state: State) -> None:
    # dry runs share the data volume with the real service: saving would mark
    # findings as notified and the real run would never send them
    if not cfg.dry_run:
        state.save(cfg.state_file)


# --- Discord -----------------------------------------------------------------


def chunk_message(lines: list[str], limit: int = DISCORD_LIMIT) -> list[str]:
    chunks: list[str] = []
    current = ""
    for line in lines:
        line = line[: limit - 1]
        if current and len(current) + 1 + len(line) > limit:
            chunks.append(current)
            current = line
        else:
            current = f"{current}\n{line}" if current else line
    if current:
        chunks.append(current)
    return chunks


def post_discord(cfg: Config, payload: dict) -> None:
    payload = {**payload, "allowed_mentions": {"parse": []}}
    req = urllib.request.Request(
        cfg.discord_webhook,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "sec-watch"},
    )
    for attempt in range(3):
        try:
            urllib.request.urlopen(req, timeout=15).close()
            return
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 2:
                retry = float(json.loads(e.read() or b"{}").get("retry_after", 2))
                time.sleep(retry)
                continue
            log.error("discord post failed: HTTP %s", e.code)
            return
        except urllib.error.URLError as e:
            log.error("discord post failed: %s", e.reason)
            return


def notify(cfg: Config, lines: list[str]) -> None:
    for chunk in chunk_message(lines):
        if cfg.dry_run or not cfg.discord_webhook:
            print(f"--- discord (dry-run) ---\n{chunk}\n", flush=True)
            continue
        post_discord(cfg, {"content": chunk})


def embed_size(embed: dict) -> int:
    return len(embed.get("title", "")) + len(embed.get("description", ""))


def batch_embeds(embeds: list[dict]) -> list[list[dict]]:
    batches: list[list[dict]] = []
    current: list[dict] = []
    size = 0
    for embed in embeds:
        n = embed_size(embed)
        if current and (len(current) == EMBEDS_PER_MESSAGE or size + n > EMBEDS_TOTAL_LIMIT):
            batches.append(current)
            current, size = [], 0
        current.append(embed)
        size += n
    if current:
        batches.append(current)
    return batches


def render_embed(embed: dict) -> str:
    lines = [f"┃ {embed['title']} <{embed.get('url', '')}>"]
    lines += [f"┃ {line}" for line in embed.get("description", "").splitlines()]
    return "\n".join(lines)


def send_embeds(cfg: Config, embeds: list[dict]) -> None:
    for batch in batch_embeds(embeds):
        if cfg.dry_run or not cfg.discord_webhook:
            print("--- discord (dry-run) ---\n" + "\n\n".join(map(render_embed, batch)) + "\n", flush=True)
            continue
        post_discord(cfg, {"embeds": batch})


# --- Docker (through the read-only socket proxy) -------------------------------


def docker_api_base(docker_host: str) -> str:
    return docker_host.replace("tcp://", "http://", 1)


def running_images(cfg: Config) -> list[str]:
    url = f"{docker_api_base(cfg.docker_host)}/containers/json"
    with urllib.request.urlopen(url, timeout=15) as resp:
        containers = json.load(resp)
    return sorted({c["Image"] for c in containers})


# --- Trivy -------------------------------------------------------------------


def parse_trivy(report: dict) -> list[Vuln]:
    vulns: dict[str, Vuln] = {}
    for result in report.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            vuln = Vuln(
                id=v["VulnerabilityID"],
                pkg=v.get("PkgName", "?"),
                installed=v.get("InstalledVersion", "?"),
                fixed=v.get("FixedVersion", ""),
                severity=v.get("Severity", "UNKNOWN"),
                title=(v.get("Title") or "").strip(),
            )
            vulns[vuln.key] = vuln
    return sorted(vulns.values(), key=lambda x: (SEVERITY_ORDER.get(x.severity, 9), x.id))


def _trivy(args: list[str], timeout_s: int) -> str:
    proc = subprocess.run(["trivy", *args], capture_output=True, text=True, timeout=timeout_s, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip().splitlines()[-1][-300:] if proc.stderr.strip() else "trivy failed")
    return proc.stdout


def update_trivy_db(cfg: Config) -> str | None:
    """Download the vulnerability DB once per scan. Return a warning if a stale DB is used."""
    try:
        _trivy(["image", "--download-db-only", "--quiet", "--timeout", "30m",
                "--cache-dir", str(cfg.trivy_cache)], timeout_s=2000)  # fmt: skip
        return None
    except (RuntimeError, subprocess.TimeoutExpired) as e:
        if not (cfg.trivy_cache / "db" / "trivy.db").exists():
            raise RuntimeError(f"vulnerability DB download failed and no cached DB: {e}") from e
        return f"⚠️ DB update failed, scanned with cached DB: {e}"


def scan_image(cfg: Config, image: str) -> list[Vuln]:
    out = _trivy(
        [
            "image",
            "--quiet",
            "--format", "json",
            "--scanners", "vuln",
            "--severity", cfg.severities,
            "--ignore-unfixed",
            "--skip-db-update",
            "--timeout", "15m",
            "--image-src", "docker",
            "--docker-host", cfg.docker_host,
            "--cache-dir", str(cfg.trivy_cache),
            image,
        ],
        timeout_s=1000,
    )  # fmt: skip
    return parse_trivy(json.loads(out))


def format_vuln(v: Vuln) -> str:
    fix = f" → {v.fixed}" if v.fixed else ""
    title = f" — {v.title[:80]}" if v.title else ""
    return f"{SEVERITY_ICON.get(v.severity, '')} `{v.id}` {v.pkg} {v.installed}{fix}{title}"


def count_by_severity(vulns: list[Vuln]) -> str:
    counts: dict[str, int] = {}
    for v in vulns:
        counts[v.severity] = counts.get(v.severity, 0) + 1
    parts = [f"{counts[s]} {s.lower()}" for s in SEVERITY_ORDER if s in counts]
    return ", ".join(parts) if parts else "clean"


def new_findings(seen: list[str], current: list[Vuln]) -> list[Vuln]:
    known = set(seen)
    return [v for v in current if v.key not in known]


def run_trivy(cfg: Config, state: State, weekly: bool) -> None:
    images = running_images(cfg)
    first_run = not state.trivy_bootstrapped
    results: dict[str, list[Vuln]] = {}
    failed: list[str] = []
    errors: list[str] = []

    if db_warning := update_trivy_db(cfg):
        errors.append(db_warning)

    for image in images:
        log.info("scanning %s", image)
        try:
            results[image] = scan_image(cfg, image)
        except (RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            failed.append(image)
            errors.append(f"⚠️ `{image}`: {e}")

    if first_run:
        lines = [f"🛡️ **sec-watch: first Trivy scan** ({len(images)} images, fixable {cfg.severities})"]
        lines += [f"• `{img}`: {count_by_severity(v)}" for img, v in results.items()]
        notify(cfg, lines + errors)
    else:
        for image, vulns in results.items():
            fresh = new_findings(state.trivy_seen.get(image, []), vulns)
            if not fresh:
                continue
            lines = [f"🚨 **New CVE in `{image}`** ({len(fresh)})"]
            lines += [format_vuln(v) for v in fresh[:MAX_LINES_PER_IMAGE]]
            if len(fresh) > MAX_LINES_PER_IMAGE:
                lines.append(f"… +{len(fresh) - MAX_LINES_PER_IMAGE} more")
            notify(cfg, lines)
        if errors:
            notify(cfg, ["⚠️ **sec-watch: some images could not be scanned**", *errors])

    if weekly and not first_run:
        total = sum(len(v) for v in results.values())
        lines = [f"📋 **Weekly security summary**: {len(images)} images, {total} fixable {cfg.severities}"]
        lines += [f"• `{img}`: {count_by_severity(v)}" for img, v in results.items()]
        notify(cfg, lines + errors)

    # Only running images are kept: removed containers stop being tracked.
    # A failed scan keeps its previous findings so they are not re-sent as new tomorrow.
    seen = {img: [v.key for v in vulns] for img, vulns in results.items()}
    seen.update({img: state.trivy_seen[img] for img in failed if img in state.trivy_seen})
    state.trivy_seen = seen
    state.trivy_last_scan = dt.date.today().isoformat()
    # A first run where every scan failed must not count, or the next success
    # would report every existing CVE as new.
    if results:
        state.trivy_bootstrapped = True


# --- GitHub ------------------------------------------------------------------


def next_link(link_header: str | None) -> str | None:
    if not link_header:
        return None
    for part in link_header.split(","):
        url, _, rel = part.partition(";")
        if 'rel="next"' in rel:
            return url.strip()[1:-1]
    return None


def fetch_json(req: urllib.request.Request, attempts: int = 3) -> tuple[object, str | None]:
    """GET with retries on transient network/5xx errors. Return (body, next page URL)."""
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.load(resp), next_link(resp.headers.get("Link"))
        except urllib.error.HTTPError as e:
            if e.code < 500 or attempt == attempts:
                raise
        except (urllib.error.URLError, http.client.IncompleteRead, TimeoutError, ConnectionError):
            if attempt == attempts:
                raise
        time.sleep(2**attempt)
    raise AssertionError("unreachable")


@dataclass
class Alert:
    repo: str
    number: int
    severity: str
    package: str
    summary: str
    url: str

    @property
    def key(self) -> str:
        return f"{self.repo}#{self.number}"


@dataclass
class PullRequest:
    repo: str
    number: int
    title: str
    body: str
    url: str

    @property
    def key(self) -> str:
        return f"{self.repo}#{self.number}"


def gh_request(cfg: Config, url: str) -> urllib.request.Request:
    return urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {cfg.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "sec-watch",
        },
    )


def gh_get_all(cfg: Config, path: str) -> list[dict]:
    url: str | None = f"https://api.github.com{path}"
    items: list[dict] = []
    while url:
        body, url = fetch_json(gh_request(cfg, url))
        items.extend(body)  # type: ignore[arg-type]
    return items


def fetch_github(cfg: Config) -> tuple[dict[str, Alert], dict[str, PullRequest], int]:
    """Return ({key: alert}, {key: dependabot PR}, repo_count) for open items."""
    repos = [r for r in gh_get_all(cfg, "/user/repos?affiliation=owner&per_page=100") if not r["archived"]]
    alerts: dict[str, Alert] = {}
    prs: dict[str, PullRequest] = {}
    for repo in repos:
        name = repo["full_name"]
        try:
            for a in gh_get_all(cfg, f"/repos/{name}/dependabot/alerts?state=open&per_page=100"):
                adv = a["security_advisory"]
                alert = Alert(name, a["number"], adv["severity"].upper(), a["dependency"]["package"]["name"],
                              adv["summary"], a["html_url"])  # fmt: skip
                alerts[alert.key] = alert
        except urllib.error.HTTPError as e:
            # 403/404: Dependabot alerts disabled or not granted to the token
            log.debug("alerts skipped for %s: HTTP %s", name, e.code)
        for p in gh_get_all(cfg, f"/repos/{name}/pulls?state=open&per_page=100"):
            if p["user"]["login"] == "dependabot[bot]":
                pr = PullRequest(name, p["number"], p["title"], p.get("body") or "", p["html_url"])
                prs[pr.key] = pr
    return alerts, prs, len(repos)


def fetch_pr_state(cfg: Config, key: str) -> str:
    repo, number = key.rsplit("#", 1)
    body, _ = fetch_json(gh_request(cfg, f"https://api.github.com/repos/{repo}/pulls/{number}"))
    return "merged" if body.get("merged_at") else "closed"  # type: ignore[union-attr]


# --- GitHub cards --------------------------------------------------------------


def md_link(text: str, url: str) -> str:
    escaped = text.replace("\\", "\\\\").replace("[", r"\[").replace("]", r"\]")
    return f"[{escaped}]({url})"


def plural(n: int, word: str) -> str:
    return f"{n} {word}{'s' if n != 1 else ''}"


def worst_severity(alerts: list[Alert]) -> str | None:
    return min((a.severity for a in alerts), key=lambda s: SEVERITY_ORDER.get(s, 9), default=None)


def severity_counts(alerts: list[Alert]) -> str:
    counts: dict[str, int] = {}
    for a in alerts:
        counts[a.severity] = counts.get(a.severity, 0) + 1
    ordered = sorted(counts, key=lambda s: SEVERITY_ORDER.get(s, 9))
    return " · ".join(f"{SEVERITY_ICON.get(s, '')} {counts[s]} {s.lower()}" for s in ordered)


def with_more(lines: list[str], limit: int = MAX_LINKS_PER_CARD) -> list[str]:
    return lines[:limit] + ([f"… +{len(lines) - limit} more"] if len(lines) > limit else [])


def covered_by_pr(package: str, prs: list[PullRequest]) -> bool:
    # grouped Dependabot PRs only name their packages in the body
    pattern = re.compile(rf"(?<![\w-]){re.escape(package)}(?![\w-])", re.IGNORECASE)
    return any(pattern.search(f"{p.title}\n{p.body}") for p in prs)


def card(title: str, url: str, color: int, lines: list[str]) -> dict:
    return {"title": title[:256], "url": url, "color": color,
            "description": "\n".join(lines)[:EMBED_DESCRIPTION_LIMIT]}  # fmt: skip


def security_url(repo: str) -> str:
    return f"https://github.com/{repo}/security/dependabot"


def repo_card(repo: str, alerts: list[Alert], prs: list[PullRequest]) -> dict:
    # pip names are case-insensitive: "Pillow" and "pillow" are one package
    names: dict[str, str] = {}
    by_package: dict[str, int] = {}
    for a in alerts:
        name = names.setdefault(a.package.lower(), a.package)
        by_package[name] = by_package.get(name, 0) + 1
    packages = sorted(by_package, key=lambda p: -by_package[p])

    lines = [severity_counts(alerts) if alerts else "No open alert"]
    if packages:
        lines.append("Top: " + " · ".join(f"`{p}` ({by_package[p]})" for p in packages[:3]))
    if prs:
        lines.append("**Dependabot PRs**")
        lines += with_more([md_link(f"#{p.number} {p.title}", p.url) for p in sorted(prs, key=lambda p: p.number)])
    if uncovered := [p for p in packages if not covered_by_pr(p, prs)]:
        names = ", ".join(f"`{p}`" for p in uncovered[:MAX_LINKS_PER_CARD])
        extra = f" (+{len(uncovered) - MAX_LINKS_PER_CARD})" if len(uncovered) > MAX_LINKS_PER_CARD else ""
        lines.append(f"⚠️ No open PR for: {names}{extra}")
    worst = worst_severity(alerts)
    return card(repo, security_url(repo), SEVERITY_COLOR[worst] if worst else NEUTRAL_COLOR, lines)


def update_card(
    repo: str,
    new_alerts: list[Alert],
    new_prs: list[PullRequest],
    closed_prs: list[tuple[str, str]],
    resolved: int,
    still_open: int,
) -> dict:
    lines: list[str] = []
    if new_alerts:
        lines.append(f"**🚨 {plural(len(new_alerts), 'new alert')}**")
        ordered = sorted(new_alerts, key=lambda a: SEVERITY_ORDER.get(a.severity, 9))
        lines += with_more(
            [f"{SEVERITY_ICON.get(a.severity, '')} {md_link(f'{a.package} — {a.summary[:90]}', a.url)}" for a in ordered],
            MAX_LINES_PER_IMAGE,
        )
    if new_prs:
        lines.append(f"**🔧 {plural(len(new_prs), 'new Dependabot PR')}**")
        lines += with_more([md_link(f"#{p.number} {p.title}", p.url) for p in new_prs])
    for key, pr_state in closed_prs:
        number = key.rsplit("#", 1)[1]
        link = md_link(f"#{number}", f"https://github.com/{repo}/pull/{number}")
        lines.append(f"🟣 Merged {link}" if pr_state == "merged" else f"⚪ Closed without merge {link}")
    if resolved:
        lines.append(f"✅ {plural(resolved, 'alert')} resolved · {still_open} still open")

    worst = worst_severity(new_alerts)
    if worst:
        color = SEVERITY_COLOR[worst]
    elif any(s == "merged" for _, s in closed_prs):
        color = MERGED_COLOR
    elif resolved:
        color = RESOLVED_COLOR
    else:
        color = NEUTRAL_COLOR
    return card(repo, security_url(repo), color, lines)


def repo_of(key: str) -> str:
    return key.rsplit("#", 1)[0]


def closed_pr_state(cfg: Config, key: str) -> str:
    try:
        return fetch_pr_state(cfg, key)
    except (urllib.error.URLError, http.client.HTTPException, TimeoutError, ConnectionError) as e:
        log.warning("could not fetch closed PR %s: %s", key, e)
        return "closed"


def run_github(cfg: Config, state: State) -> None:
    alerts, prs, repo_count = fetch_github(cfg)
    alerts_by_repo: dict[str, list[Alert]] = {}
    for a in alerts.values():
        alerts_by_repo.setdefault(a.repo, []).append(a)
    prs_by_repo: dict[str, list[PullRequest]] = {}
    for p in prs.values():
        prs_by_repo.setdefault(p.repo, []).append(p)

    if not state.github_bootstrapped:
        all_alerts = list(alerts.values())
        header = card(
            "🛡️ sec-watch: GitHub watch started",
            "https://github.com/settings/security_analysis",
            NEUTRAL_COLOR,
            [f"{repo_count} repos · {plural(len(alerts), 'open alert')} · {plural(len(prs), 'Dependabot PR')}",
             severity_counts(all_alerts) if all_alerts else "No open alert"],
        )  # fmt: skip

        def rank(repo: str) -> tuple[int, int, str]:
            repo_alerts = alerts_by_repo.get(repo, [])
            return SEVERITY_ORDER.get(worst_severity(repo_alerts) or "", 9), -len(repo_alerts), repo

        repos = sorted(alerts_by_repo.keys() | prs_by_repo.keys(), key=rank)
        send_embeds(cfg, [header] + [repo_card(r, alerts_by_repo.get(r, []), prs_by_repo.get(r, [])) for r in repos])
        state.github_bootstrapped = True
    else:
        known_alerts, known_prs = set(state.github_alerts), set(state.github_prs)
        new_alerts = [a for k, a in alerts.items() if k not in known_alerts]
        new_prs = [p for k, p in prs.items() if k not in known_prs]
        resolved = sorted(known_alerts - alerts.keys())
        closed = [(k, closed_pr_state(cfg, k)) for k in sorted(known_prs - prs.keys())]

        changed = {a.repo for a in new_alerts} | {p.repo for p in new_prs}
        changed |= {repo_of(k) for k in resolved} | {repo_of(k) for k, _ in closed}
        cards = [
            update_card(
                repo,
                [a for a in new_alerts if a.repo == repo],
                [p for p in new_prs if p.repo == repo],
                [(k, s) for k, s in closed if repo_of(k) == repo],
                sum(1 for k in resolved if repo_of(k) == repo),
                len(alerts_by_repo.get(repo, [])),
            )
            for repo in sorted(changed)
        ]
        if cards:
            send_embeds(cfg, cards)
    state.github_alerts = sorted(alerts)
    state.github_prs = sorted(prs)
    state.github_last_check = time.time()


# --- Scheduling ----------------------------------------------------------------


def due_tasks(cfg: Config, state: State, now: dt.datetime) -> tuple[bool, bool, bool]:
    """Return (github_due, trivy_due, weekly_due)."""
    github_due = bool(cfg.github_token) and now.timestamp() - state.github_last_check >= cfg.github_interval_min * 60
    today = now.date().isoformat()
    trivy_due = state.trivy_last_scan != today and now.hour >= cfg.scan_hour
    weekly_due = trivy_due and now.weekday() == cfg.weekly_day and state.trivy_last_weekly != today
    return github_due, trivy_due, weekly_due


def run_task(name: str, func, cfg: Config) -> None:
    try:
        func()
    except Exception as e:  # noqa: BLE001 - a failing task must not kill the loop
        log.exception("%s failed", name)
        notify(cfg, [f"⚠️ **sec-watch: {name} failed**: `{type(e).__name__}: {str(e)[:300]}`"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", choices=["github", "trivy", "weekly"], help="run one task and exit")
    parser.add_argument("--dry-run", action="store_true", help="print Discord messages instead of sending them")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = Config.from_env(args.dry_run)
    # trivy extracts image layers into TMPDIR, kept on the data volume (rootfs is read-only)
    if tmpdir := os.environ.get("TMPDIR"):
        Path(tmpdir).mkdir(parents=True, exist_ok=True)
    state = State.load(cfg.state_file)

    if args.once:
        if args.once == "github":
            if not cfg.github_token:
                log.error("GITHUB_TOKEN not set")
                return 1
            run_github(cfg, state)
        else:
            run_trivy(cfg, state, weekly=args.once == "weekly")
        persist(cfg, state)
        return 0

    if not cfg.github_token:
        log.warning("GITHUB_TOKEN not set: GitHub watch disabled")
    log.info("started (scan at %02d:00, weekly day %d, github every %d min)",
             cfg.scan_hour, cfg.weekly_day, cfg.github_interval_min)
    while True:
        github_due, trivy_due, weekly_due = due_tasks(cfg, state, dt.datetime.now())
        if github_due:
            run_task("github check", lambda: run_github(cfg, state), cfg)
            persist(cfg, state)
        if trivy_due:
            run_task("trivy scan", lambda: run_trivy(cfg, state, weekly=weekly_due), cfg)
            # Mark the day as done even on failure to avoid re-scanning every minute.
            state.trivy_last_scan = dt.date.today().isoformat()
            if weekly_due:
                state.trivy_last_weekly = state.trivy_last_scan
            persist(cfg, state)
        time.sleep(60)


if __name__ == "__main__":
    sys.exit(main())
