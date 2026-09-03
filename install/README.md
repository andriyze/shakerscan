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

The full `docs/` tree is intentionally not part of the minimal runtime. Installed README, AGENTS,
CLAUDE, and skill files must therefore use public GitHub links when they refer to engineering
references outside this package.

The installed skills include the general ShakerScan workflow plus interactive security sessions,
JavaScript analysis, content discovery, bounded research/Deep Hunt, and skill-system review. The
Claude Code commands include the matching `/research` entry point.

It then creates a `shakerscan` launcher in `~/.local/bin`, adds that directory to future shell sessions when needed, and runs `shakerscan start -y`, which uses the latest Docker Hub images by default. Because a child install script cannot modify the current shell's PATH, installer output also shows absolute commands such as `~/.local/bin/shakerscan agent codex`. Users can also `cd ~/.shakerscan` and start Codex, Claude, or OpenCode there so the agent reads the installed docs and skills.

The release runtime enables confirmation-gated AI Operations execution by default so a first-time
user can launch Deep Hunt with the current coding agent as the keyless planner. Deep Hunt still
requires an authorized target and an expiring target-bound approval. Set
`AI_OPS_ROUTER_EXECUTE_ENABLED=false` in the install's `.env` and restart to disable all gated AI
Operations execution globally.

Re-running the install command upgrades the installed runtime files in place. It refreshes
`scanner.sh`, `docker-compose.release.yml`, `VERSION`, `README.md`, `AGENTS.md`, `CLAUDE.md`,
`skills/`, and `.claude/`; keeps `.env`, `results`, and Docker volumes; then starts ShakerScan.
Prebuilt starts pull Docker Hub images by default; set `SHAKERSCAN_PULL_IMAGES=0` to skip that pull.
Run `shakerscan backup` before upgrading. The supported database restore and previous-image procedure
is documented in [`../docs/upgrade-and-rollback.md`](../docs/upgrade-and-rollback.md).

Useful environment overrides:

```bash
curl -fsSL https://install.shakerscan.com | SHAKERSCAN_HOME="$HOME/.shakerscan-dev" sh
curl -fsSL https://install.shakerscan.com | SHAKERSCAN_START=0 sh
curl -fsSL https://install.shakerscan.com | SHAKERSCAN_REMOTE=1 sh
curl -fsSL https://install.shakerscan.com | SHAKERSCAN_RAW_BASE="https://raw.githubusercontent.com/andriyze/shakerscan/main" sh
```

## Integrity of the downloaded runtime

`install/MANIFEST.sha256` lists the SHA-256 of every file the installer downloads. The installer
fetches it first, verifies each file against it before activation, and checks the manifest's own
digest against `RUNTIME_MANIFEST_SHA256` in the published `release-image-lock.env`. A file the
manifest does not list, a digest mismatch, or a lock without the manifest digest aborts the install
without touching the existing tree. Regenerate the manifest whenever an installed file changes:

```bash
python3 scripts/generate_install_manifest.py          # rewrite
python3 scripts/generate_install_manifest.py --check  # CI gate
```

Hosting options:

- Cloudflare Worker: deploy `cloudflare-worker.js` on `install.shakerscan.com`. It resolves
  `install/STABLE_VERSION` from `main` and serves that release tag's `bootstrap.sh`, falling back
  to the `main` copy only for releases that predate the dispatcher. Redeploy the worker when this
  file changes; the release pipeline does not deploy it.
- Static host: configure the site root to return `index.sh` at `/`; `_headers` contains the intended content type.

Keep the response body unchanged; `curl | sh` must receive shell, not HTML.

## Release deployment check

The hosted endpoint is deployed separately from the Git repository and Docker images. For each
release candidate:

1. Verify local `index.sh` and `index.html` contain the same shell payload.
2. Deploy the current payload to `install.shakerscan.com`.
3. Confirm the response content type is text/shell content, not an HTML application page.
4. Install into an empty temporary home with `SHAKERSCAN_START=0`.
5. Confirm the runtime contains the general and research skills plus
   `.claude/commands/research.md`.
6. Run `shakerscan doctor`, start the stack, verify agent launch, and submit one fast passive Scan.
7. Re-run the installer over that test install and confirm `.env`, results, and Docker volumes are
   preserved.

The complete pre-release and post-publish sequence is maintained in
[`../docs/release-readiness.md`](../docs/release-readiness.md).
