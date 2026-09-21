# ShakerScan client

**Status:** shipped in the repository (`client/`); the `shakerscan` package on PyPI and the
Homebrew tap are published by `.github/workflows/publish-client.yml` on `client-v*` tags.

The ShakerScan client is the `shakerscan` command without the engine: the MCP adapter and the
scripted Hunt CLI, installed on a laptop or a CI runner with no Docker, pointed at any ShakerScan
instance (a local engine, a VPS, or an authenticating deployment such as ShakerScan Enterprise,
with a service token). This page documents the client itself; how an Enterprise deployment
issues tokens, assigns roles and enables Hunt is documented at
[shakerscan.com/docs/enterprise](https://shakerscan.com/docs/enterprise), not in this repository.

It is the same code the engine runtime already exposes as `scanner.sh mcp` and `scanner.sh hunt`:
the package vendors `scripts/shakerscan_mcp.py` and `scripts/v2_cli.py` at build time
(`client/hatch_build.py`), so a client and a runtime of the same release run identical code, and
every tool the adapter offers comes from the instance's live contracts (`GET /arsenal/commands`,
`GET /hunts/contract`), not from the client version.

## One command, two install channels

| Channel | What lands on the PATH | Runs the engine | `mcp`, `hunt` |
|---|---|---|---|
| `curl -fsSL https://install.shakerscan.com \| sh` | the launcher shim at `~/.local/bin/shakerscan` | yes | yes |
| `pipx install shakerscan`, `uv tool install shakerscan`, `brew install andriyze/shakerscan/shakerscan` | the client, as `shakerscan` | hands `start`, `stop`, `status`, `update`, … to a local engine install when one exists | yes |

The client looks for the engine at `SHAKERSCAN_HOME` (default `~/.shakerscan`, where the
installer puts it) and runs its `scanner.sh` with the same defaults as the launcher shim. Without
an engine, an engine subcommand prints the install one-liner and exits 2.

When both channels meet on one machine, the installer keeps a client it finds at
`~/.local/bin/shakerscan` instead of replacing it, because the client already forwards engine
commands to the install. If the launcher shim was there first and pipx refuses to overwrite it,
`pipx install --force shakerscan` (or `uv tool install --force shakerscan`) replaces it; nothing is
lost, `shakerscan start` still works through the client. Homebrew installs under its own prefix and
never collides.

## Install

```bash
pipx install shakerscan          # or: uv tool install shakerscan
shakerscan version
```

Homebrew (macOS and Linux), from the `andriyze/shakerscan` tap (Homebrew installs formulae only
from taps, so the release workflow publishes the formula there):

```bash
brew install andriyze/shakerscan/shakerscan
```

Run without installing:

```bash
uvx shakerscan mcp --url https://scanner.example.com --token-file ~/.config/shakerscan/token
```

From a repository checkout the client runs the runtime scripts in place:
`PYTHONPATH=client/src python -m shakerscan …`.

Python 3.10 or newer; no third-party dependencies.

## Public checks without an engine or account

A pipx/Homebrew client can use the bounded ShakerScan public service immediately:

```bash
shakerscan check example.com
shakerscan check https://example.com --json
shakerscan mcp
```

With no local, remote, or saved ShakerScan instance configured, the client defaults to
`https://pub.shakerscan.com`. Once an instance is configured, `check` and `mcp` use that instance;
a failed private connection never falls back to public. The public backend owns the
actual DNS/TLS/HTTP posture capabilities and rate limits; the lightweight client only validates
the target, submits the request, prints the result, or exposes the public MCP catalogue.

## Use an OSS server on the same LAN

Run `shakerscan start --lan` on the machine with the full OSS engine. On the laptop,
install only the pipx/Homebrew client and use the API URL printed by the server:

```bash
shakerscan doctor --url http://192.168.1.50:8080
shakerscan api --url http://192.168.1.50:8080 GET /findings
shakerscan mcp --url http://192.168.1.50:8080
```

An explicit `--url`, or `SHAKERSCAN_API_URL` plus `SHAKERSCAN_MCP_ALLOW_REMOTE_API=true`,
selects that server, with no public fallback. The laptop needs no Docker. The LAN is the
trust boundary: this mode adds no login, encryption, or remote shell. Existing API/Hunt
approvals remain enforced. See [LAN access](lan-access.md) for networking, multi-NIC selection,
MCP registration, persistence, and returning to localhost-only operation.

## Connect

The quickest way is the one-time link an administrator gets when creating a service token in
ShakerScan Enterprise's console. Paste the command it shows:

```bash
shakerscan connect https://scanner.example.com/_enterprise/connect/<code> --claude
```

The link works once and expires after ten minutes; the command carries no secret. `connect`
fetches the token through it, writes it to `~/.config/shakerscan/token` (owner-only) and the
instance address to `~/.config/shakerscan/config.json`, runs `doctor`, and with `--claude`
registers `shakerscan mcp` in Claude Code (user scope). From then on `mcp`, `hunt` and `doctor`
need no options. `shakerscan connect https://scanner.example.com` prompts for a token instead
(never on the command line); `shakerscan disconnect` forgets the instance and deletes the token
file; `SHAKERSCAN_CONFIG_DIR` relocates the files.

Explicit options and the environment still win over the saved profile:

- `--url` (or `SHAKERSCAN_API_URL`): the API origin. The default is `http://127.0.0.1:8080`, a
  local engine. An explicit `--url` authorizes a remote origin; a URL taken from the environment
  keeps the adapter's own rule and needs `SHAKERSCAN_MCP_ALLOW_REMOTE_API=true`.
- `--token-file` (or `SHAKERSCAN_API_TOKEN_FILE`, or `SHAKERSCAN_API_TOKEN`): a service token for
  an authenticating deployment such as self-hosted Enterprise. The token reaches the adapter
  through the environment, never on the command line, is sent only over `https://`, and is never
  printed; a token with a plain-http URL refuses to start.

Check a connection before handing it to an agent:

```bash
shakerscan doctor --url https://scanner.example.com --token-file ./token
```

`doctor` reports the client version, the URL rules, whether a token is set, engine reachability,
and the MCP tool catalogue the instance offers (read-only Arsenal tools plus Hunt tools). It
exits 1 when the catalogue cannot be read and 2 when the connection is misconfigured. For a
local engine (a loopback URL) it then hands off to the launcher's own `doctor`, the Docker and
host checks a curl-installed user expects from this command. Likewise `shakerscan version`
prints the client version and, when an engine install is present, the engine release beside it,
so both commands mean the same thing whichever channel put `shakerscan` on the PATH.

## Work with an agent: `shakerscan agent`

The open-source launcher's `shakerscan agent claude` starts the agent inside the runtime
directory, where `AGENTS.md`, `CLAUDE.md`, the skills and the `.claude` commands (`/scan`,
`/findings`, `/status`, `/deep-hunt`, …) tell it how to work. The client does the same against
the connected instance:

```bash
shakerscan agent claude        # or codex, opencode; the first one installed when omitted
shakerscan agent opencode --url http://192.168.1.50:8080   # an open-source engine on a trusted LAN
```

`--url` is for an open-source engine reached by address (the server printed it after
`shakerscan start --lan`; see `docs/lan-access.md`): there is no token and no per-person identity,
the workspace note says so, and the MCP registrations carry the address. Without `--url` the
saved `shakerscan connect` instance is used, then `SHAKERSCAN_API_URL`.

It materializes that kit (vendored into the package at build time) into a workspace
(`~/.config/shakerscan/agent`, or `--here` for the current directory, or `--workspace DIR`),
prepends a note naming the connected instance and the rules of a remote session (no local
engine, use `shakerscan api`/`scan`/`hunt` and the MCP tools, refusals name what is missing),
registers the MCP server for that workspace (`.mcp.json` for Claude Code, `opencode.json` for
OpenCode, `codex mcp add` for Codex), exports the connection with the token left in its file,
and starts the agent there. `--no-launch` prepares the workspace and prints how to start. The
kit's API calls go through `shakerscan api`, so the same commands work locally and remotely.

`shakerscan api METHOD PATH [JSON]` calls the instance directly (`shakerscan api GET
"/findings?limit=20"`, `shakerscan api POST /scans '{…}'`); `shakerscan scan …` is the runtime's
scan CLI against the instance; `shakerscan status` reports the instance when no engine is
installed on this machine.

## Hunt from an agent (MCP)

Claude Code, after `shakerscan connect` (or `connect --claude` does this for you):

```bash
claude mcp add --scope user shakerscan -- shakerscan mcp
```

Without a saved profile (a CI runner, say), pass the connection explicitly:

```bash
claude mcp add shakerscan \
  -e SHAKERSCAN_API_TOKEN_FILE=$HOME/.config/shakerscan/token \
  -- shakerscan mcp --url https://scanner.example.com
```

Any MCP client that spawns a stdio server:

```json
{
  "mcpServers": {
    "shakerscan": {
      "command": "shakerscan",
      "args": ["mcp", "--url", "https://scanner.example.com"],
      "env": {"SHAKERSCAN_API_TOKEN_FILE": "/home/me/.config/shakerscan/token"}
    }
  }
}
```

The tools, their trust levels, and the fail-closed rules are those of the runtime adapter, in
[mcp.md](mcp.md). The agent's own model does the reasoning; the instance's model credentials are
not involved. The MCP `serverInfo.version` reports `client-X.Y.Z`.

## Hunt from a script

```bash
shakerscan hunt --url https://scanner.example.com --token-file ./token list
shakerscan hunt --url https://scanner.example.com --token-file ./token start --help
```

`shakerscan hunt` forwards everything after its connection options to the runtime's product CLI
(`scripts/v2_cli.py … hunt`), so the subcommands are the runtime's: `start`, `get`, `list`,
`query`, `call`, `candidate`, `verify`, `finish`, `cancel`, `resume`. Connection options come
first; `shakerscan hunt --url URL` with nothing after it prints that CLI's own help.

## Versioning and release

The client has its own version (`client/src/shakerscan/__init__.py`), tagged `client-vX.Y.Z`,
independent of the engine release: because tool catalogues come from the live contracts, one
client works against any engine version that serves them. A tag runs `publish-client.yml`: build
the sdist and wheel, run the client tests, smoke the wheel (and a wheel rebuilt from the sdist) in
a clean environment, publish to PyPI through trusted publishing (no stored token; the `pypi`
environment), attach the files to a GitHub release (never marked as the repository's "latest",
which stays the engine's), and render the Homebrew formula
(`client/homebrew/`), pushing it to the `andriyze/homebrew-shakerscan` tap with that repository's
write deploy key (the `HOMEBREW_TAP_DEPLOY_KEY` secret) and attaching it as an artifact otherwise.
