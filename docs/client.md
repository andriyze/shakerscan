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

Python 3.10 or newer. One third-party dependency since 0.11.2: python-fido2 (Yubico,
BSD-2-Clause; it brings `cryptography`, `cffi` and `pycparser`, and `typing-extensions` on Python
3.10), for a USB security key's touch. The package declares `fido2>=2.0,<3`, so a plain `pipx` or
`uv tool` install resolves the newest matching releases from the package index without hashes;
the reviewed resolution is hash-locked in `client/requirements/runtime.lock`, and
`pip install --require-hashes -r client/requirements/runtime.lock` installs exactly that. The client
is no longer pure Python through `cryptography` and `cffi`: they ship wheels for the common
platforms, and a platform without one (32-bit ARM, for example) builds them, which needs a Rust
toolchain. The Homebrew formula installs the client without python-fido2, so a Homebrew install has
no security-key support (it says so when asked for a touch); install with `pipx` or `uv tool` for
it.

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

An instance whose certificate comes from a private or corporate CA is reachable once this machine
trusts that CA. Point `SSL_CERT_FILE` at a PEM bundle that contains it (for example your system
bundle with the CA appended), and export it where you run `shakerscan` and where your agent starts:
the MCP server the agent spawns (`shakerscan mcp`) inherits it from that environment, not from the
saved profile. A certificate the client does not trust is reported with this hint by `connect`,
`doctor` and every command:

```bash
export SSL_CERT_FILE=/etc/ssl/certs/ca-with-corporate-root.pem
shakerscan connect https://scanner.example.com/_enterprise/connect/<code>
```

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
(`${XDG_DATA_HOME:-~/.local/share}/shakerscan/agent`, or `--here` for the current directory, or
`--workspace DIR`; a default workspace left at `~/.config/shakerscan/agent` by client 0.8.1 is
moved there once, with its record, and the move is reported),
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
budget and view rules are in every session that drives a Hunt. Running `shakerscan agent` again
on an existing workspace merges these files instead of rewriting them: the client updates only
its own parts (`mcp.shakerscan` and the Hunt skill instruction in `opencode.json`,
`mcpServers.shakerscan` in `.mcp.json`, the kit's hooks in `.claude/settings.json`) and keeps
everything else, such as an OpenCode `permission` block with a bash deny-list, Claude Code
`permissions`, other MCP servers and `.claude/settings.local.json`; each `kept:` line says what
was kept, hook command lines included. Because an agent can write these files too, each launch
records a fingerprint of the settings that change what an agent may do (permissions, plugins,
providers, other MCP servers, instructions, hooks) in the client's state directory
(`${XDG_STATE_HOME:-~/.local/state}/shakerscan/workspaces/`, never in the workspace an agent can
write), and the next launch lists under `changed:` exactly what changed in between (secret values
hidden); nothing is blocked. When the record of a workspace prepared before is missing or not
valid, the launch says that changes since the last launch could not be checked. A record that
would sit inside the workspace (`--here` from your home directory) is not used, and a workspace
that contains the client's configuration directory (it holds the token) is warned about.

Where the client keeps its state (workspace records) and data (the default agent workspace),
first match wins: `SHAKERSCAN_STATE_DIR` / `SHAKERSCAN_DATA_DIR`; beside `SHAKERSCAN_CONFIG_DIR`
when it is set (`<dir>.state`, `<dir>.data`, so an isolated profile stays isolated even when the
session sets XDG variables); `$XDG_STATE_HOME/shakerscan` / `$XDG_DATA_HOME/shakerscan`;
`~/.local/state/shakerscan` / `~/.local/share/shakerscan` (macOS too). Every path must be absolute (a relative XDG value is
ignored, as the XDG specification says). An isolated profile that kept its records and default
workspace under the session's XDG directories before 2.11 loses neither: the record of the workspace
it launches in is copied from `$XDG_STATE_HOME/shakerscan/workspaces` (never moved, another profile
may share it), and its first launch with its own default workspace names the old shared one
(`$XDG_DATA_HOME/shakerscan/agent`, left in place) and how to keep using it. A directory that cannot be created or written, or a
`SHAKERSCAN_CONFIG_DIR` without a usable sibling (such as `/`), or `/` as
`SHAKERSCAN_STATE_DIR` or `SHAKERSCAN_DATA_DIR`, stops `shakerscan agent` with an
error naming the variable to set. `scripts/clean-shakerscan.sh` removes the records, and the
default agent workspace only with `--agent-workspace` (docs/clean-reinstall.md). Kit files and hook entries the kit no longer ships are removed (a kit file you changed
is kept and named); your own files stay. `opencode.json` with comments or trailing commas is read
and written back as plain JSON, its original kept beside it; a file that is not JSON or JSONC is
moved aside (`.shakerscan-unreadable-*.bak`) with the reason. The client never writes through a
link: if any path it writes, or anything under `.claude/`, is a symbolic or hard link, it refuses
and writes nothing, and every file it writes is a new file renamed into place through directories
opened without following links. The
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

- **Enterprise (a token).** The approver is the person the connection's token acts for, named by
  the gateway (`--account` names someone else, and a token that acts for nobody needs it; a gateway
  that does not name one is answered by asking, as before). You prove it with your TOTP code, typed
  at the prompt, or a USB/NFC security key (`--method security_key`). Without `--method` the client
  uses a plugged-in security key when the gateway offers one and the key holds one of your
  credentials (asked silently, without a touch; with a PIN when the gateway asks for one), else
  the code as before; when several plugged-in keys can answer, you pick one before being asked to
  touch. A key error is said in plain words (not registered to your account, no touch in time, no
  PIN set). The key is asked for what the
  gateway asks: its PIN when the gateway requires user verification, a touch alone when it does
  not. The proof goes to the gateway's step-up routes, which decide in your name; the token alone
  never approves. A gateway that does not serve those routes yet gets an exact error and nothing
  is decided. `--watch` opens a 30-minute approver session after one step-up; its secret is held
  only in that process's memory (see `docs/hunt-permission-requests.md` for what that does and
  does not protect against).
- **A gateway that requires a security-key touch for each decision** (its administrator's
  choice): no approver session opens; `--watch` asks for one touch per decision, and `allow
  a[l]l N shown` decides every request it is showing (one touch per 50). A touch that fails or
  that you cancel with Ctrl-C leaves the request pending and shows it again; the watch goes on. On such a gateway, and on
  any gateway that offers it, `--watch` also prints a line for each decision only a person should
  make that a connection acting for you made (with a token, by key touch, or refused).
- **Open-source engine (no token).** A `y/N` at the prompt, sent to the engine's decision route.
  `--watch` says which Hunts it watches and ends with "stopped watching for permission
  requests".
- `--watch` (both): each request's prompt appears about 0.75 s after the request, and keys pressed
  before it are ignored (and said so), so a key meant for an earlier request never decides the
  next one; when a request ends elsewhere while its prompt waits, the switch to the next one is
  announced. Only a single lowercase key pressed on its own decides: arrow, function and Alt
  keys (however slowly their bytes arrive), terminal control strings (OSC, DCS, APC, PM, SOS,
  up to their BEL or ST, or a 1.5 s pause with no input, and said so), 8-bit CSI, uppercase
  letters and pastes are ignored. It keeps
  polling while it waits, and SIGTERM or a closed terminal ends it like Ctrl-C (terminal
  restored, Enterprise approver session revoked, also during the step-up), with exit status
  128 + the signal number.
  On an engine from 2.11 it reads one feed of every open Hunt's requests (only what changed since
  the previous read); an older engine, or a gateway that does not pass that route, is read Hunt by
  Hunt. It reads every 3 s after a request was shown and waits longer (up to 15 s) while nothing
  new arrives.
  The engine has no accounts: anyone who can reach its API could decide, and the command says so.
- Neither runs without an interactive terminal, so an agent cannot run it in its own shell. Never
  type a code into an agent's chat.

Bounds set when you start an agent pre-authorize requests inside them, so they are granted as they
arise: `shakerscan agent opencode --allow budget.raise:2x --allow capability:state-changing`
(also `credential.use:<targets>`, `target.authorize:<patterns>`, `capability:active-testing`).
On Enterprise this asks for your step-up once, before the agent starts. `shakerscan hunt start
--allow …` does the same for one Hunt. Bounds an agent proposes itself become one pending request
you approve like any other.

## Decisions only a person makes: a security-key touch

Some requests record a decision only a person should make: raising a Hunt's budget, authorizing a
target for active testing, sharing a saved credential with another target, widening a target's
Hunt permissions, and a few device and secret decisions. An Enterprise gateway's administrator can
require a touch of the person's security key for them when they come from a terminal. The gateway
then refuses such a request sent with the connection's token alone (HTTP 403,
`person_decision_required`, `x-shakerscan-step-up: required`, with the decision in plain words),
and every command of this client completes it the same way:

```text
$ shakerscan hunt budget raise 3f2a91c0-… --limit max_state_changing_requests=40
This needs your decision (your administrator requires a security-key touch):
  Raise state-changing requests 20 -> 40 (safety ceiling) for Hunt 3f2a91c0… on honey.example.com
Touch your security key to approve (Ctrl-C to cancel)...
done; decided by alice (security-key touch)
raised state-changing requests 20 -> 40 (safety ceiling) for Hunt 3f2a91c0-…
```

- **In your own terminal** (stdin a terminal, and stdout or stderr one: `--json | jq` still asks,
  on stderr): the client shows the decision whole (every limit a raise sets, the whole host; a
  decision too long for a terminal is never touched for), asks
  the gateway for a challenge bound to exactly that request (method, path and query, SHA-256 of the
  body bytes, this connection, the person it acts for), checks the binding, asks for one touch of
  a security key registered to your account (user presence; no PIN unless the gateway asks), and
  sends the same request once more with the one-time grant (`X-ShakerScan-Person-Proof`, valid two
  minutes, for that request only). `shakerscan api`, `shakerscan scan`, the Hunt, knowledge and
  secrets commands and the commands below all do this. Ctrl-C at the touch cancels it: nothing is
  changed, and the command exits with status 130. `shakerscan scan --active-testing` does not ask
  its own "Type 'yes'" as well when the gateway requires the touch: the touch is the confirmation.
  `shakerscan doctor` says whether the gateway requires the touch and whether one could happen
  here (python-fido2, a key plugged in), without asking the key anything.
- **Anywhere else** (an agent's tool call, a pipe, a script, or inside `shakerscan agent`): it
  never prompts and never asks a key anything. It prints one line, `person decision required:
  <the decision>. Nothing was changed. The person runs this in their own terminal and touches
  their security key: <command>`, and exits with status **3** (refused, nothing ran). No option
  skips the touch. The MCP adapter answers the same refusal as `outcome:
  person_decision_required` with the decision and the command, and tells the agent never to retry
  it.
- Two commands make the usual decisions directly:
  - `shakerscan targets authorize <url-or-id>` registers the target if needed and records its
    standing authorization for active testing (never intrusive; that is made in the browser).
    `shakerscan targets unauthorize <url-or-id> [--reason …]` withdraws it.
  - `shakerscan hunt budget raise <hunt> --limit NAME=N|NAME=+N [--resume]` raises limits to new
    totals (or by `+N`), reading the Hunt's budget and its revision first.

  On an open-source engine, or a gateway that does not require the touch, they are sent as they
  are.
- **What a touch proves.** A person was at the key: presence, not identity (anyone at a plugged-in
  key can touch it). A program running as your own computer user could change this client, or
  start a request of its own the moment you expect to touch, so the key blinks for its request; a
  key has no display. Touch only for a prompt you started, and read the decision it names. Running
  an agent as another computer user, or in a container, with its own connection, keeps your
  client, token file and key out of its reach.
- **Keys.** A USB FIDO2 key (a YubiKey 5, for example) over python-fido2. Touch ID, Windows Hello
  and synced passkeys are out of reach of a terminal client, and Windows is not supported for the
  touch in this release. On Linux, install your distribution's FIDO udev rules (the `libfido2` or
  `yubikey-manager` package); the client says so when a USB device is plugged in that your user
  cannot open. On a remote machine over SSH the key is not reachable: run the same
  command on the machine the key is plugged into, with a connection that acts for you.

## Secrets found on a target: `shakerscan secrets`

Values ShakerScan finds on a target (a password in an exposed configuration file, an API key in a
response, a value a Hunt withheld) are kept for that target, encrypted. A Hunt uses one by
reference and never sees it; these commands are yours.

```bash
shakerscan secrets list 4e1f…                    # reference, kind, field, length, sightings, uses; never a value
shakerscan secrets list 4e1f… --usable           # only those a Hunt can use now
shakerscan secrets revoke 4e1f… secret://9b2c…   # stop Hunts using it (later sightings keep it revoked)
shakerscan secrets reactivate 4e1f… 9b2c…
shakerscan secrets expiry 4e1f… 9b2c… --days 7
shakerscan secrets grant 4e1f… 9b2c… --to 7d3a…  # let another target's Hunts use it
shakerscan secrets ungrant 4e1f… 9b2c… --to 7d3a…
shakerscan secrets promote 4e1f… 9b2c… --name "Found API key" --auth-kind api_key_header --header-name X-Api-Key
shakerscan secrets reveal 4e1f… 9b2c…            # show the value, to you, in this terminal
```

`grant`, `promote` and `reveal` are your decisions and run only in your own interactive terminal:
on an open-source engine after a `y` keypress (a pipe or a paste never decides), on Enterprise with
your step-up for that one decision (the gateway applies it; a token alone never can). A revealed
value is shown in that terminal only, with control characters escaped.

**Trying a secret on another target's login.** A Hunt of target B may want to try a password found
on target A on B's login. It never does so on its own: the attempt is refused with
`secret_other_target` and a permission request is raised (`shakerscan approve <id>` shows the
secret by field name, kind and length, the target it was found on and the exact login). Allowing it
lets that Hunt try that secret on that login only, 3 times unless you choose 1-10, and never more
than 3 times per 15 minutes on one host across Hunts; each attempt is recorded with the login's
answer on the Hunt record. No start bound (`--allow`) covers it. Some logins never receive a
discovered secret at all (the shared `honey.shakerscan.com/hub` demonstration login, and any
`host/path` listed in `SHAKERSCAN_SECRET_TRY_DENY`), whether named by host or reached at one of
their addresses; a request carrying a discovered secret follows no redirect. Only secrets of
related targets (same root domain or host asset, the ones `secrets.inspect` lists) can be asked
about; any other needs your `shakerscan secrets grant`.

**Letting the agent see values.** By default a Hunt's agent never sees a discovered value.
`shakerscan hunt start ... --agent-may-see-secrets` (for a local model you trust with them) lets
that Hunt's `secrets.inspect` answer carry the values of secrets found on that target (never one
another target granted to it). The engine accepts it only with the person who chose it
(`allow_asserted_by`) and records that name; the agent's start tool never sends it, and nothing
changes it after the start. Be aware that on a local open-source install published only on
loopback, anyone with access to the local API, a local agent included, can make that same
assertion: your host is the boundary there. On any other install it needs a step-up, which the
Enterprise gateway does not offer for it yet (it strips the field). Each value shown is recorded as a reveal (`reveals` in `shakerscan secrets list`,
`disclosed_to_agent` on the Hunt record); stored actions, receipts, records and logs never hold the
value, and a retried call returns the answer without it. A connected (Enterprise) instance refuses
the option until its gateway records your step-up for it.

## Record a browser session: `shakerscan record`

```bash
pipx install --force 'shakerscan[record]' && python -m playwright install chromium
shakerscan record https://app.example.com        # or a target id
```

Opens Chromium on the target, keeps the requests to the target's exact origin as you browse and
sign in, and uploads them to a browser capture on the connected instance; close the browser or
press Ctrl-C to finish. Scans and Hunts use the capture like an imported HAR, and an agent can
follow it while it records (`shakerscan_captures`). Captured cookies and passwords are never
promoted to credentials. See [Browser capture](browser-capture.md).

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
`hunt call` exits 0 only when the action was admitted: a refusal, a pending permission request
and an action replayed as `blocked` (its permission was denied, expired or withdrawn) exit 2, with
the server's answer still printed as JSON.

## Scan from a script

`shakerscan scan` forwards to the runtime's scan CLI; `shakerscan scan --help` (or `scan help`)
prints its options and submits nothing. Active testing and credential use need a target-bound
approval receipt. Without `--approval-receipt` the server uses the target's standing
authorization, the same one New Scan in the UI uses, and refuses with its reason when there is
none or it does not cover the request: authorize the target once (New Scan, or
`POST /targets/{id}/authorization`). Credential use may need a credential-tier receipt from
`POST /arsenal/approvals`, passed as `--approval-receipt`; an instance may reserve creating one
to administrators. `--active-testing` off a terminal also needs `--confirm-active`.

## Versioning and release

A client built from a repository checkout (a release, or `pipx install
"git+https://github.com/andriyze/shakerscan@<commit>#subdirectory=client"`) also records the commit
it was built from: `shakerscan version` prints `shakerscan client 0.11.1 (source 1a2b3c4d5e6f)`,
`doctor` shows the same, and the MCP `serverInfo.version` is `client-0.11.1+1a2b3c4d5e6f`.

The client has its own version (`client/src/shakerscan/__init__.py`), tagged `client-vX.Y.Z`,
independent of the engine release: because tool catalogues come from the live contracts, one
client works against any engine version that serves them. A tag runs `publish-client.yml`: build
the sdist and wheel, run the client tests, smoke the wheel (and a wheel rebuilt from the sdist) in
a clean environment, publish to PyPI through trusted publishing (no stored token; the `pypi`
environment), attach the files to a GitHub release (never marked as the repository's "latest",
which stays the engine's), and render the Homebrew formula
(`client/homebrew/`), pushing it to the `andriyze/homebrew-shakerscan` tap with that repository's
write deploy key (the `HOMEBREW_TAP_DEPLOY_KEY` secret) and attaching it as an artifact otherwise.
