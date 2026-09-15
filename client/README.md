# shakerscan

The ShakerScan client: the MCP adapter and the Hunt CLI for a ShakerScan instance, without the
engine. Point it at a local engine, a VPS, or a self-hosted Enterprise gateway with a service
token, and hand it to an agent (Claude Code, Codex, any MCP client) or to a script.

```bash
pipx install shakerscan          # or: uv tool install shakerscan
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
