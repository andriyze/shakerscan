# Connect your agent to ShakerScan MCP

**Status:** maintained setup guide for the open-source engine; client formats checked against
OpenCode 2.4, Claude Code 2.1, Codex CLI 0.171 and each editor's documentation in November 2026.

This page registers the ShakerScan MCP server in your coding agent once, permanently, so every
session you open has the ShakerScan tools: list targets and findings, read evidence, and drive
target-bound Hunts. What the tools do and the rules they enforce are in [MCP](mcp.md).

`shakerscan agent opencode` (or `claude`, `codex`) is the other way in: it prepares a dedicated
agent workspace and starts the agent there for one session. How the two differ is at the
[end of this page](#how-this-differs-from-shakerscan-agent); you can use both.

## What you register

The server is a local stdio process, `shakerscan mcp`, which your agent starts itself. There is no
MCP port to open: the process talks to the engine's REST API (port 8080 by default) and to the
agent over its standard input and output.

Pick the line that matches where the engine runs:

| Engine | Server command | Needs |
|---|---|---|
| On this machine | `shakerscan mcp` | the engine install (`curl -fsSL https://install.shakerscan.com \| sh`) |
| On another host in LAN mode | `shakerscan mcp --url http://192.168.1.50:8080` | the client on this machine, the address the server printed |
| On another host, through an SSH tunnel | `shakerscan mcp --url http://127.0.0.1:8080` | the client on this machine, the tunnel below |

The client is `pipx install shakerscan` (or `uv tool install shakerscan`, or
`brew install andriyze/shakerscan/shakerscan`); see [Client](client.md). On the engine host the
installer's own `shakerscan` command already runs the server, with no client needed.

Two things to settle before writing any configuration:

1. **Use the absolute path.** Editors started from a dock or menu often have a shorter `PATH` than
   your terminal, and another program may own the name `shakerscan`. Find the right one with
   `command -v shakerscan` (and `which -a shakerscan` if `shakerscan version` does not print a
   ShakerScan client or engine version), then use that path wherever the examples below say
   `shakerscan`. Typical paths are `~/.local/bin/shakerscan` (installer, pipx, uv) and
   `/opt/homebrew/bin/shakerscan` (Homebrew on Apple silicon). Write it out in full; MCP
   configuration files do not expand `~`.
2. **Check the connection first.** Run the same command the agent will run, as `doctor`:

   ```bash
   shakerscan doctor                                     # engine on this machine
   shakerscan doctor --url http://192.168.1.50:8080      # engine on another host
   ```

   It should say `engine: reachable (healthy)` and `mcp: N tools`. A client with no engine on the
   machine, no `--url` and no saved `shakerscan connect` uses the public check service instead, which
   offers a single tool, `shakerscan_public_check`. That is the usual reason an agent sees only
   one ShakerScan tool.

Instead of `--url` you may save the address once with `shakerscan connect http://192.168.1.50:8080`;
then `shakerscan mcp` alone uses it. The examples keep `--url` so each configuration says which
engine it reaches.

## Security: the open-source engine has no login

The open-source API has no authentication and no per-person identity. Anyone who can reach port
8080 can do everything the MCP tools can, including starting Hunts. The MCP server adds no login
of its own.

- **Same machine:** the engine listens on loopback only; nothing else is needed.
- **LAN mode** (`shakerscan start --lan`): only on a network whose users and devices you trust
  to operate ShakerScan. Traffic is unencrypted. Restrict ports 8080 and 3000 to your own
  machines with a firewall, and never forward them from a router. See [LAN access](lan-access.md).
- **Anywhere else** (a VPS, a cloud host, a shared or untrusted network): keep the engine on
  loopback and reach it through an SSH tunnel. Do not bind it to a public address.

The tunnel, run on your laptop and kept open while you work (`-N` runs no remote command):

```bash
ssh -N -L 8080:127.0.0.1:8080 -L 3000:127.0.0.1:3000 you@scanner-host
```

Port 3000 is the UI, so the links the tools return open in your browser. If this laptop runs its
own engine on 8080, forward another local port (`-L 18080:127.0.0.1:8080`) and use
`--url http://127.0.0.1:18080`. The MCP server refuses a non-loopback API address unless `--url`
names it, and it never sends a bearer token over plain `http://`.

## OpenCode

OpenCode reads `opencode.json` (or `opencode.jsonc`) from the project directory and
`~/.config/opencode/opencode.json` for every project. Add the server under `mcp.servers`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "shakerscan": {
        "type": "local",
        "command": ["/home/me/.local/bin/shakerscan", "mcp"]
      }
    }
  }
}
```

For an engine on another host, extend `command`:
`["/home/me/.local/bin/shakerscan", "mcp", "--url", "http://192.168.1.50:8080"]`.

OpenCode 1.x put each server directly under `mcp` (`"mcp": {"shakerscan": {"type": "local", …,
"enabled": true}}`); OpenCode 2 still reads that shape. `opencode mcp add shakerscan --
/home/me/.local/bin/shakerscan mcp` writes the entry for you (add `--global` for every project).

Check: start `opencode` and type `/mcps`; `shakerscan` should be connected. A scripted run shows
it in the log: `opencode run --print-logs "list the ShakerScan tools"` prints
`mcp connected server=shakerscan tools=N`.

## Claude Code

Every project, for your user only:

```bash
claude mcp add --scope user shakerscan -- /home/me/.local/bin/shakerscan mcp
claude mcp add --scope user shakerscan -- /home/me/.local/bin/shakerscan mcp --url http://192.168.1.50:8080
```

Use one of the two lines. Everything after `--` is the server command. `--scope user` stores the
entry in `~/.claude.json`; without `--scope` it is added for the current project only, also in
`~/.claude.json`. `claude mcp remove --scope user shakerscan` takes it out again.

One project, shared through version control: `.mcp.json` in the project root (or
`claude mcp add --scope project …`, which writes it):

```json
{
  "mcpServers": {
    "shakerscan": {
      "type": "stdio",
      "command": "/home/me/.local/bin/shakerscan",
      "args": ["mcp", "--url", "http://192.168.1.50:8080"]
    }
  }
}
```

Claude Code asks once, in an interactive session, before it starts a server from a project's
`.mcp.json`. Until then `claude mcp list` shows it as pending approval.

Check: `claude mcp list` shows `shakerscan: … ✔ Connected`; inside a session, `/mcp` lists the
server and its tools. A scripted run can name the file directly:
`claude -p --mcp-config .mcp.json "…"`.

## Codex CLI

Codex keeps MCP servers in `~/.codex/config.toml` (or `.codex/config.toml` in a trusted project):

```bash
codex mcp add shakerscan -- /home/me/.local/bin/shakerscan mcp --url http://192.168.1.50:8080
```

That writes:

```toml
[mcp_servers.shakerscan]
command = "/home/me/.local/bin/shakerscan"
args = ["mcp", "--url", "http://192.168.1.50:8080"]
```

For an engine on this machine, `args = ["mcp"]`. Codex waits 10 seconds for a server to start
and 60 for a tool call. A Hunt action can keep a call open for up to two minutes before it answers
`outcome: "running"` (see [MCP](mcp.md)), so add a longer tool timeout to the table, and a longer
start-up one if the first start is slow:

```toml
tool_timeout_sec = 180
startup_timeout_sec = 30
```

Check: `codex mcp list` shows `shakerscan` as `enabled`; in a Codex session, `/mcp` lists the
connected server and its tools.

## Cursor

`~/.cursor/mcp.json` for every project, or `.cursor/mcp.json` in one project:

```json
{
  "mcpServers": {
    "shakerscan": {
      "type": "stdio",
      "command": "/home/me/.local/bin/shakerscan",
      "args": ["mcp", "--url", "http://192.168.1.50:8080"]
    }
  }
}
```

For an engine on this machine, `"args": ["mcp"]`. The Cursor CLI (`cursor-agent`) reads the same
files.

Check: the MCP section of Cursor's settings lists `shakerscan` with its tools; connection errors
are under Output, `MCP Logs`.

## VS Code (GitHub Copilot)

Current Copilot reads `~/.copilot/mcp-config.json` for every workspace, or `.mcp.json` at a
workspace root (still experimental: the `chat.mcp.workspaceRootConfig.enabled` setting), both with the `mcpServers` shape shown for Cursor above (`"type": "stdio"`,
`command`, `args`).

The older editor-managed files, `.vscode/mcp.json` in a workspace or the profile file opened with
**MCP: Open User Configuration**, use `servers` instead:

```json
{
  "servers": {
    "shakerscan": {
      "type": "stdio",
      "command": "/home/me/.local/bin/shakerscan",
      "args": ["mcp", "--url", "http://192.168.1.50:8080"]
    }
  }
}
```

VS Code says those files belong to its deprecated local harness; prefer the `mcpServers` files
for a new setup.

Check: **MCP: List Servers** in the Command Palette shows `shakerscan` running; in Copilot Chat's
agent mode its tools appear in the tools picker.

## Any other MCP client

Any client that starts a stdio server needs only the command and its arguments. Most accept this
shape:

```json
{
  "mcpServers": {
    "shakerscan": {
      "command": "/home/me/.local/bin/shakerscan",
      "args": ["mcp", "--url", "http://192.168.1.50:8080"]
    }
  }
}
```

The server reads these optional environment variables: `SHAKERSCAN_API_URL` (instead of `--url`;
a non-loopback address then also needs `SHAKERSCAN_MCP_ALLOW_REMOTE_API=true`),
`SHAKERSCAN_MCP_CALL_SECONDS` and `SHAKERSCAN_MCP_ACTION_WAIT_SECONDS` (see [MCP](mcp.md)). Pi has
no MCP client; use `shakerscan agent pi`, which gives it the ShakerScan skills and commands instead.

For a ShakerScan Enterprise instance, run `shakerscan connect` with the link the console gives you
and register `shakerscan mcp` with no `--url`: the saved connection carries the address and the
token, and the token never goes into the agent's configuration. See [Client](client.md).

## Check it works

1. `shakerscan doctor` (with the same `--url`) reports `engine: reachable (healthy)` and
   `mcp: N tools`.
2. Your client's list (above) shows `shakerscan` connected with the same number of tools, all named
   `shakerscan_…`: read-only ones such as `shakerscan_targets`, `shakerscan_findings` and
   `shakerscan_tool_status`, and the Hunt ones (`shakerscan_hunt_start`, `shakerscan_hunt_get`, …).
   Only `shakerscan_public_check` means the server is not connected to your engine; see step 2 of
   [What you register](#what-you-register).
3. Ask the agent something read-only first:

   > Use the ShakerScan tools: how many targets does the engine have, which scanner tools are
   > ready (`shakerscan_tool_status`), and what are the five most severe open findings?

   Then, on a target you are authorized to test and have already added to ShakerScan:

   > Start a ShakerScan Hunt on target `<target name>` with the goal "check the login and session
   > handling", tell me the budget it was given, and stop after the first capability call.

When a Hunt needs something only a person can allow (a larger budget, a state-changing
capability), the agent gives you a `shakerscan approve <id>` command. Run it in your own
terminal, never inside the agent; see [Hunt permission requests](hunt-permission-requests.md).

## How this differs from `shakerscan agent`

| | Permanent registration (this page) | `shakerscan agent opencode` |
|---|---|---|
| Where it applies | every session of the client, or one project you chose | one workspace the client prepares (`~/.local/share/shakerscan/agent` by default, or `--here`) |
| What the agent gets | the MCP tools | the MCP tools, plus the operating guide (`AGENTS.md`), the skills, the `/scan`, `/findings` and `/deep-hunt` commands and the Hunt skill as instructions |
| Your own projects and settings | unchanged; ShakerScan sits next to your other MCP servers | the client merges its own entries into the workspace's configuration and reports what else changed between launches |
| Launch bounds | none: bounds the agent proposes become one permission request you approve | `--allow budget.raise:2x` and similar pre-authorize requests inside the bounds you set |
| Kept up to date | the tools come from the engine's live contracts on every start | the guide and skills are refreshed on every launch |
| Agents | any MCP client | Codex, Claude Code, OpenCode and Pi |

Register the server permanently when you want the ShakerScan tools beside your own code and
agents; start `shakerscan agent` for a security session in which the agent should follow the
ShakerScan operating guide. They do not conflict.
