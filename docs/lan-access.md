# Control an OSS engine from another machine on a trusted LAN

**Status:** implemented on this branch. The server launcher and client changes must be released before the latest installer/pipx/Homebrew packages include them. This does not deploy the separate public lookup backend.

## Server: install the full engine, then opt into LAN access

On the machine that will run Docker and the scanners:

```bash
curl -fsSL https://install.shakerscan.com | sh
shakerscan start --lan
```

A fresh installation without `--lan` remains localhost-only. LAN mode discovers an up RFC1918 IPv4 interface, preferring the default-route interface when there is more than one candidate. It never chooses a wildcard bind, public IP, loopback, or common Docker/VPN/Tailscale interface. Discovery uses local interface/route information; it does not contact an Internet service.

For multiple NICs or an ambiguous choice, select an address already assigned to the intended LAN interface:

```bash
shakerscan start --lan --bind-host 192.168.1.50
```

No usable private address or an invalid explicit address is an error, not a fallback to `0.0.0.0` or Tailscale. `--lan` is supported on `start` and `restart`, and cannot be combined with `--remote`/`--tailscale`. Linux uses `ip`; macOS/BSD uses `ifconfig` and `route`. This first version is IPv4-only.

The launcher prints the actual API/UI addresses and laptop commands, using custom port settings when supplied. It changes only the UI/API binding, not the datastore bindings: Redis and Postgres remain loopback by default. Existing deliberately configured datastore/overlay networking is not rewritten.

## Laptop: install only the lightweight client

The two ways to connect a client (this unencrypted, token-less LAN engine, and an encrypted Enterprise instance with a token) are compared side by side in [docs/client.md](client.md#connect-the-client-to-a-server).

The laptop does not need Docker or a local scanning engine. Install the client and save the
engine's address once; every command then uses it, with no options and no environment variables:

```bash
pipx install shakerscan
# macOS alternative:
# brew install andriyze/shakerscan/shakerscan

shakerscan connect http://192.168.1.50:8080     # the address the server printed
shakerscan doctor
shakerscan api GET /health
shakerscan api GET /findings
shakerscan hunt list
shakerscan agent opencode                       # or claude, codex: the full agent workspace
shakerscan mcp
```

`connect` with a plain-http address saves the engine with no token (a bearer token is never sent
over http anyway); an https engine without a login needs `shakerscan connect https://… --no-token`.
The address lives in `~/.config/shakerscan/config.json`; `shakerscan disconnect` forgets it and
`shakerscan doctor` shows which instance is in use. An explicit `--url` on a command still wins
over the saved address, and `--url` alone works without saving anything:

```bash
shakerscan doctor --url http://192.168.1.50:8080
shakerscan api --url http://192.168.1.50:8080 GET /health
shakerscan agent opencode --url http://192.168.1.50:8080
```

`mcp` is a stdio server: normally an MCP-capable client launches it rather than a person interacting with it in a terminal. `shakerscan agent` registers it for the workspace it prepares; to register it in a client by hand, for example:

```json
{
  "mcpServers": {
    "shakerscan": {
      "command": "shakerscan",
      "args": ["mcp", "--url", "http://192.168.1.50:8080"]
    }
  }
}
```

After `shakerscan connect`, `["mcp"]` alone is enough: the saved address is used. `SHAKERSCAN_API_URL` (with `SHAKERSCAN_MCP_ALLOW_REMOTE_API=true` for `mcp`) remains available for scripts and CI that prefer the environment over a saved profile.

API reads/writes and the instance's available MCP/Hunt capabilities run on the server; existing target authorization, budgets, credential admission and protected administrative endpoints still apply. This is not unrestricted remote shell access, and it does not add remote Docker start/stop/update commands. Those lifecycle commands still run on the server. `shakerscan agent` also works against the LAN engine: `shakerscan agent opencode --url http://192.168.1.50:8080` (or `claude`, `codex`) prepares the full agent workspace (the operating guide, the skills and the `/scan`, `/findings`, `/deep-hunt` commands) on the laptop, registers the MCP server with that address, and starts the agent. The workspace note says the engine has no login and no per-person identity. The saved, authenticated `shakerscan connect` flow is unchanged and still wins for an Enterprise instance.

An explicit or environment-configured instance wins over the zero-config public service. Failure or an unsupported endpoint is reported as an error; it must never send the request to `pub.shakerscan.com`. The previously proposed `check` bundle still requires its server-side endpoint; LAN support does not manufacture that endpoint.

## Security and networking

**Only enable this on a network whose reachable users and devices you trust to operate ShakerScan.** Binding to a private address is not authentication or encryption. The OSS UI/API does not gain a general login screen or RBAC from this option. Use host/network firewall rules to restrict the published API/UI ports to intended clients. Do not forward them from an Internet router; on shared/untrusted networks use a VPN or an authenticated TLS gateway/Enterprise instead.

This command does not install firewall rules, create router forwards, disable existing authorization, or bypass API token transport requirements. Bearer credentials are still refused over plain HTTP. Do not carry an Enterprise token environment into an unauthenticated LAN session.

The selected UI/API bind and display host are persisted in the server's owner-only `.env`, like existing remote settings. Reserve the server's DHCP address, or rerun `start --lan` after an address change to rediscover it. Cached Tailscale addresses are not used for a new explicit LAN start.

Return to a persisted localhost-only binding with:

```bash
shakerscan restart --bind-host 127.0.0.1 --public-host localhost
```

For troubleshooting, use the printed IP (not `localhost` on the laptop), verify both machines can reach the same network/VLAN, check Wi-Fi client isolation and host/firewall rules, and confirm the API with `shakerscan doctor --url ...`. Do not solve reachability problems by exposing all interfaces or opening the service to the Internet.
