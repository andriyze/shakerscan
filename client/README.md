# shakerscan

The ShakerScan client: public posture checks plus the MCP adapter and Hunt CLI for a ShakerScan
instance, without the engine. Use the public service with no account, or point the client at a local
engine, VPS, or self-hosted Enterprise gateway and hand it to an agent or script.

```bash
pipx install shakerscan          # or: uv tool install shakerscan
shakerscan check example.com      # free public posture check, no engine/account
shakerscan mcp                    # public MCP when no instance is configured
shakerscan doctor --url https://scanner.example.com --token-file ./token
shakerscan mcp    --url https://scanner.example.com --token-file ./token
shakerscan hunt   --url https://scanner.example.com --token-file ./token list
```

It installs the same `shakerscan` command name as the engine installer
(`curl -fsSL https://install.shakerscan.com | sh`): `mcp`, `hunt`, `doctor` and `version` work
without Docker, and any engine subcommand (`start`, `stop`, `status`, `update`, ...) is handed to
a local engine install when one exists. The adapter and CLI are the runtime's own code, vendored
at build time, and the tools an agent sees come from the instance's live contracts.

Python 3.10 or newer, no third-party dependencies, AGPL-3.0-only. Documentation:
https://github.com/andriyze/shakerscan/blob/main/docs/client.md


With no local, remote, or saved ShakerScan instance configured, `check` and `mcp` use the hardcoded `https://pub.shakerscan.com` service. Once an instance is configured, the client prefers that instance for all such requests and never falls back to public on failure.
