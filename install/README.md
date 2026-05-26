# ShakerScan Hosted Installer

This folder contains the script intended to be served from:

```bash
https://install.shakerscan.com
```

The public command is:

```bash
curl -fsSL https://install.shakerscan.com | sh
```

For a remote VPS that should be accessed over Tailscale, use:

```bash
curl -fsSL https://install.shakerscan.com | SHAKERSCAN_REMOTE=1 sh
```

The hosted root path should serve `index.sh` as plain text or shell script content. The script downloads the minimal release runtime into `~/.shakerscan`:

- `scanner.sh`
- `docker-compose.release.yml`
- `db/init.sql`
- `VERSION`
- `README.md`
- `AGENTS.md`
- `CLAUDE.md`
- `skills/`
- `.claude/`

It then creates a `shakerscan` launcher in `~/.local/bin`, adds that directory to future shell sessions when needed, and runs `shakerscan start -y`, which uses the latest Docker Hub images by default. Because a child install script cannot modify the current shell's PATH, installer output also shows absolute commands such as `~/.local/bin/shakerscan agent codex`. Users can also `cd ~/.shakerscan` and start Codex, Claude, or OpenCode there so the agent reads the installed docs and skills.

Re-running the install command upgrades the installed runtime files in place. It refreshes `scanner.sh`, `docker-compose.release.yml`, `VERSION`, `README.md`, `AGENTS.md`, `CLAUDE.md`, and the installed `skills/` files, keeps `.env`, `results`, and Docker volumes, then starts ShakerScan. Prebuilt starts pull Docker Hub images by default; set `SHAKERSCAN_PULL_IMAGES=0` to skip that pull.

Useful environment overrides:

```bash
curl -fsSL https://install.shakerscan.com | SHAKERSCAN_HOME="$HOME/.shakerscan-dev" sh
curl -fsSL https://install.shakerscan.com | SHAKERSCAN_START=0 sh
curl -fsSL https://install.shakerscan.com | SHAKERSCAN_REMOTE=1 sh
curl -fsSL https://install.shakerscan.com | SHAKERSCAN_RAW_BASE="https://raw.githubusercontent.com/andriyze/shakerscan/main" sh
```

Hosting options:

- Cloudflare Worker: deploy `cloudflare-worker.js` on `install.shakerscan.com`.
- Static host: configure the site root to return `index.sh` at `/`; `_headers` contains the intended content type.

Keep the response body unchanged; `curl | sh` must receive shell, not HTML.
