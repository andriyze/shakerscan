# ShakerScan Hosted Installer

This folder contains the script intended to be served from:

```bash
https://install.shakerscan.com
```

The public command is:

```bash
curl -fsSL https://install.shakerscan.com | sh
```

The hosted root path should serve `index.sh` as plain text or shell script content. The script downloads the minimal release runtime into `~/.shakerscan`:

- `scanner.sh`
- `docker-compose.release.yml`
- `db/init.sql`
- `VERSION`
- `README.md`
- `AGENTS.md`
- `CLAUDE.md`

It then creates a `shakerscan` launcher in `~/.local/bin` and runs `shakerscan start -y`, which uses the latest Docker Hub images by default. Users can also `cd ~/.shakerscan` and start Codex or Claude there so the agent reads the installed `AGENTS.md` or `CLAUDE.md`.

Re-running the install command upgrades the installed runtime files in place. It refreshes `scanner.sh`, `docker-compose.release.yml`, `VERSION`, `README.md`, `AGENTS.md`, and `CLAUDE.md`, keeps `.env`, `results`, and Docker volumes, then starts ShakerScan. Prebuilt starts pull Docker Hub images by default; set `SHAKERSCAN_PULL_IMAGES=0` to skip that pull.

Useful environment overrides:

```bash
curl -fsSL https://install.shakerscan.com | SHAKERSCAN_HOME="$HOME/.shakerscan-dev" sh
curl -fsSL https://install.shakerscan.com | SHAKERSCAN_START=0 sh
curl -fsSL https://install.shakerscan.com | SHAKERSCAN_RAW_BASE="https://raw.githubusercontent.com/andriyze/shakerscan/main" sh
```

Hosting options:

- Cloudflare Worker: deploy `cloudflare-worker.js` on `install.shakerscan.com`.
- Static host: configure the site root to return `index.sh` at `/`; `_headers` contains the intended content type.

Keep the response body unchanged; `curl | sh` must receive shell, not HTML.
