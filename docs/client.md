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
the Arsenal and Hunt tools come from the instance's live contracts (`GET /arsenal/commands`,
`GET /hunts/contract`); the fixed posture-check tool calls that instance's `/public/check` route.

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
lost, `shakerscan start` still works through the client.

Homebrew links the command into its own `bin` (`/opt/homebrew/bin` on Apple silicon), which other
tools share: a global npm package installed with Homebrew's Node also lands there. If
`brew install` warns that it could not symlink `bin/shakerscan`, another program owns that name and
keeps answering `shakerscan`; `which -a shakerscan` shows which one runs, and
`brew link --overwrite shakerscan` makes it the ShakerScan client.

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
shakerscan check 1.1.1.1
shakerscan check https://example.com/api          # the URL path is used for the CORS probe
shakerscan check example.com --dkim-selector google --json
shakerscan mcp
```

`check` observes DNS (addresses, name servers, DNSSEC, CAA, HTTPS records), email policy (MX,
SPF, DMARC, DKIM with a selector, MTA-STS, TLS-RPT), bounded HTTP/HTTPS probes (response,
headers, CORS, redirects, security.txt) and TLS (certificate chain, protocols, ciphers), plus IP
network ownership. The answer (`schema_version` `2`) is a list of factual `observations` with the
probe scope of each; the service makes no pass/fail judgment. The CLI groups them and lists a few
clearly risky values (for example SPF `+all`/`?all`, DMARC `p=none`, a certificate close to
expiry) under "Review". An IP-address target gets the HTTP/TLS probes against the address itself
(the certificate is verified and reported with whether it lists the address) and its reverse
DNS; DNS and email observations do not apply to it.

The public MCP mode exposes only `shakerscan_public_check(target, path?, dkim_selector?)`. It
uses the same credential-free `/v1/check` pipeline as `check`; no private-engine discovery,
Hunt, Arsenal, shell or target management tools are available. When connected to an OSS or
Enterprise instance, MCP also exposes that check alongside the instance's existing tools and
sends it to the instance's `POST /public/check` using the saved connection, but only when the
instance serves that route: `tools/list` first probes it with a request the engine refuses before
doing any work (no body, not JSON). Only the engine's own answer to that, 415 with error code
`unsupported_media_type`, lists the tool. Any other answer leaves the tool out, so neither the
agent nor `doctor` counts it. That covers a gateway that keeps the route closed (403, as the
Enterprise beta does), an engine without the route (404), an engine image without the check
engine (503), a redirect, a gateway's own 400 or 429, a 200 page, and no answer at all. There
is no public fallback or per-check approval prompt on a connected client.

The hosted service accepts only public DNS names and global IP addresses, refuses government and
military targets, and applies per-caller limits: 30 requests a minute, and 25 uncached checks an
hour and 100 a day. Cached answers are reused for 10 minutes.

With no local, remote, or saved ShakerScan instance configured, the client defaults to
`https://pub.shakerscan.com`. Once an instance is configured, `check` sends the same request to
that instance's `POST /public/check`; a failed private connection never falls back to public.
The instance runs the same posture engine (`posture/`, bundled into the API image), so it answers
with the same schema and the CLI prints it the same way. An instance applies none of the hosted
restrictions: internal names, private addresses and any other target are the operator's decision,
with no quota or cache. `SHAKERSCAN_POSTURE_RESOLVER=system` makes the engine use the instance's
own DNS resolver (for internal names) instead of DNS over HTTPS, and
`SHAKERSCAN_POSTURE_IPINFO_TOKEN` enables IP ownership facts.
The OSS API is tokenless, so anyone who can reach it on the trusted LAN can invoke checks of
addresses reachable from the API container; keep its network boundary intentional.

## Connect the client to a server

The client talks to exactly one instance at a time: the one saved by `shakerscan connect`, or
the one named with `--url` on a command. There are two kinds of server, and the difference is
transport and identity, not features: both give the same `api`, `scan`, `hunt`, `mcp`, `doctor`
and `agent` commands.

| | Open-source engine on a trusted LAN | ShakerScan Enterprise |
|---|---|---|
| Transport | plain `http://`, unencrypted | `https://`, encrypted |
| Login | none: no token, no per-person identity | a service token with a role, issued by the console |
| Server side | `shakerscan start --lan` | the console creates a token and shows a one-time connect link |
| Client side | `shakerscan connect http://192.168.1.50:8080` | `shakerscan connect https://scanner.example.com/_enterprise/connect/<code>` |
| Where it is saved | `~/.config/shakerscan/config.json` (address only) | `config.json` (address) and `token` (owner-only, 0600) |
| Trust boundary | the network: anyone who can reach ports 8080/3000 can operate the engine | the token: every action runs under that person's identity and role and is audited |

### Open-source engine (unencrypted, no token)

On the machine with Docker and the engine:

```bash
curl -fsSL https://install.shakerscan.com | sh    # once
shakerscan start --lan                            # or: start --lan --bind-host 192.168.1.50
```

It prints the addresses it bound to (`API: http://192.168.1.50:8080`, `UI: http://192.168.1.50:3000`)
and the client commands. Postgres and Redis stay on loopback. On the laptop (no Docker):

```bash
pipx install shakerscan                           # or: uv tool install shakerscan / brew install andriyze/shakerscan/shakerscan
shakerscan connect http://192.168.1.50:8080       # saves the address; runs doctor
shakerscan doctor                                 # engine: reachable (healthy), mcp: N tools
shakerscan api GET /findings
shakerscan agent opencode                         # or claude, codex, pi: the full agent workspace
```

A plain-http address is always saved without a token (a bearer token is never sent over http);
an https engine that has no login needs `shakerscan connect https://… --no-token`. Only do this on
a network whose users you trust: LAN mode adds no login and no encryption, and the ports must
stay closed to everything else. To go back to localhost-only on the server:
`shakerscan restart --bind-host 127.0.0.1 --public-host localhost`. Networking details, multi-NIC
selection and hand-written MCP registration are in [LAN access](lan-access.md).

Scan links use port 3000 automatically for a direct private-IP or localhost API on
port 8080. Named gateways and URL prefixes keep their configured origin. For a custom
layout (including a reverse proxy on a private IP), specify the UI explicitly:
`shakerscan scan --ui-url https://scanner.example.com https://authorized-app.example`.

### ShakerScan Enterprise (encrypted, with a token)

An administrator creates a service token in the Enterprise console; it shows a one-time connect
link. On the laptop:

```bash
pipx install shakerscan
shakerscan connect https://scanner.example.com/_enterprise/connect/<code> --claude
shakerscan doctor                                 # token: set (sent as a bearer token, https only)
shakerscan api GET /findings
shakerscan agent claude
```

The link works once and expires after ten minutes; the command carries no secret. `connect`
fetches the token through it, writes it to `~/.config/shakerscan/token` (owner-only) and the
instance address to `~/.config/shakerscan/config.json`, runs `doctor`, and with `--claude`
registers `shakerscan mcp` in Claude Code (user scope). `shakerscan connect
https://scanner.example.com` prompts for a token instead (never on the command line). Before
anything is saved the token is checked against the instance: a token it refuses (HTTP 401), or an
instance that cannot be reached, saves nothing. The token is sent only over `https://` and is
never printed: `connect http://… --token-stdin` is refused with the https address to use instead,
and a token with a plain-http URL refuses to start.
How a deployment issues tokens, assigns roles and enables Hunt is documented at
[shakerscan.com/docs/enterprise](https://shakerscan.com/docs/enterprise).

### Either kind

- `shakerscan doctor` shows which instance is in use and whether it is reachable.
- `shakerscan disconnect` forgets the instance and deletes the token file.
- `--url` on any command wins over the saved instance for that one call, without saving anything.
- `SHAKERSCAN_CONFIG_DIR` relocates the saved files.
- Target authorization, budgets, credential admission and the deterministic proof rules are the
  server's in both cases; a route the instance keeps closed answers with a refusal that names what
  is missing.

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
directory, where `AGENTS.md`, the skills and the `.claude` commands (`/scan`,
`/findings`, `/status`, `/deep-hunt`, …) tell it how to work. The client does the same against
the connected instance:

```bash
shakerscan agent claude        # or codex, opencode, pi; omitted => codex, claude, opencode, then pi
shakerscan agent opencode --url http://192.168.1.50:8080   # an open-source engine on a trusted LAN
```

`--url` is for an open-source engine reached by address (the server printed it after
`shakerscan start --lan`; see `docs/lan-access.md`): there is no token and no per-person identity,
the workspace note says so, and the MCP registrations carry the address. Without `--url` the
saved `shakerscan connect` instance is used, then `SHAKERSCAN_API_URL`.

It materializes that kit (vendored into the package at build time) into a workspace
(`~/.config/shakerscan/agent`, or `--here` for the current directory, or `--workspace DIR`),
prepends a note naming the connected instance, the kit's release and client version, and the
rules of a remote session (no local engine, use `shakerscan api`/`scan`/`hunt` and the MCP
tools, refusals name what is missing),
registers the MCP server for that workspace (`.mcp.json` for Claude Code, `opencode.json` for
OpenCode, `codex mcp add` for Codex), exports the connection with the token left in its file,
and starts the agent there. Pi has no MCP client: it is started with `--no-approve`, `--skill`
for each kit skill, and `--prompt-template .claude/commands`. That keeps trust-gated project
settings/extensions out of the launch without a trust prompt while still loading AGENTS.md and
the explicitly named ShakerScan resources. Pi reaches the instance through `shakerscan api`,
`scan` and `hunt`. `--no-launch` prepares the workspace and prints a shell-safe command to
start it; with no supported agent on the PATH it says so instead of naming one. OpenCode
workspaces also load `skills/hunt/SKILL.md` as instructions (`opencode.json`), so the permission,
budget and view rules are in every session that drives a Hunt. The
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

## Approve what a Hunt asks for: `shakerscan approve`

When a Hunt action is refused for something a person can allow (a budget raise, a capability
flag, another service or host, another target's credential), the action waits as a permission
request and the agent tells you the command to run. Run it yourself, in your own terminal:

```bash
shakerscan approve 8f0c…                # shows the server's text, then asks for your proof
shakerscan approve --all-pending        # every pending request, one proof
shakerscan deny 8f0c…
shakerscan approve --watch              # stay open; decide each new request on a keypress
shakerscan hunt permissions list        # JSON: the pending requests, as the server words them
shakerscan hunt permissions wait 8f0c…  # JSON: granted, denied, expired, withdrawn or still_pending
```

- **Enterprise (a token).** You name your account and prove it with your TOTP code, typed at the
  prompt, or a USB/NFC security key (`--method security_key`, with python-fido2 installed:
  `pipx inject shakerscan fido2`). The proof goes to the gateway's step-up routes, which decide
  in your name; the token alone never approves. A gateway that does not serve those routes yet
  gets an exact error and nothing is decided. `--watch` opens a 30-minute approver session after
  one step-up; its secret is held only in that process's memory (see
  `docs/hunt-permission-requests.md` for what that does and does not protect against).
- **Open-source engine (no token).** A `y/N` at the prompt, sent to the engine's decision route.
  The engine has no accounts: anyone who can reach its API could decide, and the command says so.
- Neither runs without an interactive terminal, so an agent cannot run it in its own shell. Never
  type a code into an agent's chat.

Bounds set when you start an agent pre-authorize requests inside them, so they are granted as they
arise: `shakerscan agent opencode --allow budget.raise:2x --allow capability:state-changing`
(also `credential.use:<targets>`, `target.authorize:<patterns>`, `capability:active-testing`).
On Enterprise this asks for your step-up once, before the agent starts. `shakerscan hunt start
--allow …` does the same for one Hunt. Bounds an agent proposes itself become one pending request
you approve like any other.

## Hunt from a script

```bash
shakerscan hunt --url https://scanner.example.com --token-file ./token list
shakerscan hunt --url https://scanner.example.com --token-file ./token start --help
```

`shakerscan hunt` forwards everything except its connection options to the runtime's product CLI
(`scripts/v2_cli.py … hunt`), so the subcommands are the runtime's: `start`, `get`, `list`,
`query`, `call`, `candidate`, `verify`, `finish`, `cancel`, `resume`, `permissions` and the
`skill-*` commands.
The connection options (`--url`, `--token-file`, `--timeout`) may come before or after the
subcommand, and everything after a `--` is forwarded untouched. `--timeout` is the seconds to
wait for each API answer (default 60). `shakerscan hunt --help`, or `hunt` with nothing after
it, prints the connection options and then that CLI's own help. `query` takes every kind the
engine's `/hunts/{id}/query` accepts, the same as the MCP tool, including `hypotheses`,
`graph_nodes`, `graph_edges`, `endpoint_groups` and `service_intelligence`, and `--cursor` to
follow `next_cursor`.

## Versioning and release

A client built from a repository checkout (a release, or `pipx install
"git+https://github.com/andriyze/shakerscan@<commit>#subdirectory=client"`) also records the commit
it was built from: `shakerscan version` prints `shakerscan client 0.8.0 (source 1a2b3c4d5e6f)`,
`doctor` shows the same, and the MCP `serverInfo.version` is `client-0.8.0+1a2b3c4d5e6f`.

The client has its own version (`client/src/shakerscan/__init__.py`), tagged `client-vX.Y.Z`,
independent of the engine release: because tool catalogues come from the live contracts, one
client works against any engine version that serves them. A tag runs `publish-client.yml`: build
the sdist and wheel, run the client tests, smoke the wheel (and a wheel rebuilt from the sdist) in
a clean environment, publish to PyPI through trusted publishing (no stored token; the `pypi`
environment), attach the files to a GitHub release (never marked as the repository's "latest",
which stays the engine's), and render the Homebrew formula
(`client/homebrew/`), pushing it to the `andriyze/homebrew-shakerscan` tap with that repository's
write deploy key (the `HOMEBREW_TAP_DEPLOY_KEY` secret) and attaching it as an artifact otherwise.
