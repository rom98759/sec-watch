# sec-watch

Self-hosted security watch for a single Docker host. It posts to one Discord channel when:

| Source | Trigger | Tool |
|---|---|---|
| Running containers | A newer image is published for a tag in use | [Diun](https://crazymax.dev/diun/) |
| Running containers | A **new** fixable CRITICAL/HIGH CVE appears in an image in use (nightly) | [Trivy](https://trivy.dev) |
| Running containers | Weekly summary of all open fixable CVEs (Mondays) | Trivy |
| GitHub repositories | A new Dependabot security alert is opened | GitHub API |
| GitHub repositories | Dependabot opens a pull request | GitHub API |

Only new findings are notified; the state is kept in a named volume.

## Design

```
                 internal network (no internet)
 docker.sock ──ro── socket-proxy ◄──── diun ─────► registries, Discord
                     GET only    ◄──── watcher ──► GitHub API, Discord
                                        (python + trivy)
```

- **No container gets the Docker socket.** `docker-socket-proxy` only forwards read requests on
  containers and images; everything else (create, exec, volumes, secrets, any `POST`) gets `403`.
- All containers run read-only, with every capability dropped and `no-new-privileges`.
- No port is published, so nothing is reachable from outside (and ufw/`DOCKER-USER` need no change).
- `watcher` is a single stdlib-only Python file: no third-party dependency to audit.

## Setup

1. Discord: *Channel settings → Integrations → Webhooks → New webhook*, copy the URL.
2. GitHub (optional): create a [fine-grained token](https://github.com/settings/personal-access-tokens/new)
   with *All repositories* and read-only **Dependabot alerts** + **Pull requests**.
3. Configure and start:

```bash
cp .env.example .env && chmod 600 .env   # fill DISCORD_WEBHOOK_URL and GITHUB_TOKEN
docker compose up -d --build
docker compose logs -f watcher
```

The first run posts one summary per source instead of every existing finding.

## Manual runs

```bash
docker compose run --rm watcher --once github --dry-run   # print instead of posting
docker compose run --rm watcher --once trivy
docker compose run --rm watcher --once weekly
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `DISCORD_WEBHOOK_URL` | — | Required, used by diun and watcher |
| `GITHUB_TOKEN` | empty | Empty disables the GitHub watch |
| `TRIVY_SEVERITY` | `CRITICAL,HIGH` | Severities reported (fixable only) |
| `SCAN_HOUR` | `4` | Local hour of the nightly scan |
| `WEEKLY_DAY` | `0` | Day of the weekly summary (0 = Monday) |
| `GITHUB_INTERVAL_MIN` | `60` | GitHub polling interval |
| `DRY_RUN` | empty | `1` prints messages to the logs instead of Discord |

## Development

```bash
cd watcher && python3 -m unittest -v
```

## License

[MIT](LICENSE)
