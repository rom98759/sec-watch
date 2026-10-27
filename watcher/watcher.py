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
DISCORD_LIMIT = 2000
MAX_LINES_PER_IMAGE = 15


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


def notify(cfg: Config, lines: list[str]) -> None:
    for chunk in chunk_message(lines):
        if cfg.dry_run or not cfg.discord_webhook:
            print(f"--- discord (dry-run) ---\n{chunk}\n", flush=True)
            continue
        body = json.dumps({"content": chunk, "allowed_mentions": {"parse": []}}).encode()
        req = urllib.request.Request(
            cfg.discord_webhook,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "sec-watch"},
        )
        for attempt in range(3):
            try:
                urllib.request.urlopen(req, timeout=15).close()
                break
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < 2:
                    retry = float(json.loads(e.read() or b"{}").get("retry_after", 2))
                    time.sleep(retry)
                    continue
                log.error("discord post failed: HTTP %s", e.code)
                break
            except urllib.error.URLError as e:
                log.error("discord post failed: %s", e.reason)
                break


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


def gh_get_all(cfg: Config, path: str) -> list[dict]:
    url: str | None = f"https://api.github.com{path}"
    items: list[dict] = []
    while url:
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {cfg.github_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "sec-watch",
            },
        )
        body, url = fetch_json(req)
        items.extend(body)  # type: ignore[arg-type]
    return items


def fetch_github(cfg: Config) -> tuple[dict[str, str], dict[str, str], int]:
    """Return ({alert_key: line}, {pr_key: line}, repo_count) for open items."""
    repos = [r for r in gh_get_all(cfg, "/user/repos?affiliation=owner&per_page=100") if not r["archived"]]
    alerts: dict[str, str] = {}
    prs: dict[str, str] = {}
    for repo in repos:
        name = repo["full_name"]
        try:
            for a in gh_get_all(cfg, f"/repos/{name}/dependabot/alerts?state=open&per_page=100"):
                adv = a["security_advisory"]
                sev = adv["severity"].upper()
                pkg = a["dependency"]["package"]["name"]
                alerts[f"{name}#{a['number']}"] = (
                    f"{SEVERITY_ICON.get(sev, '')} **{name}** `{pkg}` — {adv['summary'][:90]} <{a['html_url']}>"
                )
        except urllib.error.HTTPError as e:
            # 403/404: Dependabot alerts disabled or not granted to the token
            log.debug("alerts skipped for %s: HTTP %s", name, e.code)
        for pr in gh_get_all(cfg, f"/repos/{name}/pulls?state=open&per_page=100"):
            if pr["user"]["login"] == "dependabot[bot]":
                prs[f"{name}#{pr['number']}"] = f"🔧 **{name}** {pr['title'][:100]} <{pr['html_url']}>"
    return alerts, prs, len(repos)


def run_github(cfg: Config, state: State) -> None:
    alerts, prs, repo_count = fetch_github(cfg)
    if not state.github_bootstrapped:
        notify(
            cfg,
            [
                f"🛡️ **sec-watch: GitHub watch started** ({repo_count} repos)",
                f"• {len(alerts)} open Dependabot alerts, {len(prs)} open Dependabot PRs",
                *list(alerts.values())[:MAX_LINES_PER_IMAGE],
            ],
        )
        state.github_bootstrapped = True
    else:
        new_alerts = [line for key, line in alerts.items() if key not in set(state.github_alerts)]
        new_prs = [line for key, line in prs.items() if key not in set(state.github_prs)]
        if new_alerts:
            notify(cfg, [f"🚨 **New Dependabot alert(s)** ({len(new_alerts)})", *new_alerts])
        if new_prs:
            notify(cfg, [f"🔧 **New Dependabot PR(s)** ({len(new_prs)})", *new_prs])
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
