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

It then creates a `shakerscan` launcher in `~/.local/bin` and runs `shakerscan start -y`, which uses the latest Docker Hub images by default.

Useful environment overrides:

```bash
SHAKERSCAN_HOME="$HOME/.shakerscan-dev" curl -fsSL https://install.shakerscan.com | sh
SHAKERSCAN_START=0 curl -fsSL https://install.shakerscan.com | sh
SHAKERSCAN_RAW_BASE="https://raw.githubusercontent.com/andriyze/shakerscan/main" curl -fsSL https://install.shakerscan.com | sh
```

Hosting options:

- Cloudflare Worker: deploy `cloudflare-worker.js` on `install.shakerscan.com`.
- Static host: configure the site root to return `index.sh` at `/`; `_headers` contains the intended content type.

Keep the response body unchanged; `curl | sh` must receive shell, not HTML.
