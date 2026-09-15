# ADR 0003: One `shakerscan` command, two install channels

- Status: accepted
- Date: 2026-09-15
- Scope: the installer, the `shakerscan` client package, the MCP adapter and product CLI

## Context

The public installer (`curl -fsSL https://install.shakerscan.com | sh`) puts a launcher named
`shakerscan` on the PATH: a shell shim that forwards every argument to the runtime's `scanner.sh`,
which runs the engine and also exposes `mcp` (the MCP adapter) and `hunt` (the product CLI).

A pentester who drives Hunt from an agent on a laptop, against an instance that runs elsewhere
(a VPS, or a self-hosted Enterprise gateway with a service token), needs only the adapter and the
CLI. Both are dependency-free Python, and their tool catalogues come from the instance's live
contracts, so nothing about them requires the engine. Obtaining them by installing the whole
engine runtime is the wrong cost. Publishing them under a second name (`shakerscan-cli`,
`shakerscanctl`) avoids a collision with the launcher but leaves users learning two names for one
product and forks every documentation snippet.

## Decision

- The engine-less client is published as the `shakerscan` package (PyPI; `pipx`, `uv`, a
  Homebrew tap) and installs the same `shakerscan` command name. `mcp`, `hunt`, `doctor` and
  `version` work without Docker. Every other subcommand is handed to a local engine install when
  one exists (`SHAKERSCAN_HOME`, default `~/.shakerscan`, the installer's directory) with the
  launcher shim's defaults; without one, the client prints the install one-liner and exits 2.
- The installer does not replace a client it finds at `$BIN_DIR/shakerscan` (anything that is not
  its own shim); the client already forwards engine commands to the install. PATH order between
  the two therefore does not matter: both are the same program.
- The client vendors the runtime's `scripts/shakerscan_mcp.py` and `scripts/v2_cli.py` at build
  time (`client/hatch_build.py`) rather than carrying committed copies. In a checkout the client
  loads the runtime scripts in place, so `scanner.sh mcp` and the client never diverge.
- The client is versioned on its own (`client-vX.Y.Z`), independent of engine releases, because
  its tools are defined by the contracts the instance serves.

## Consequences

- One name in every guide: `claude mcp add shakerscan -- shakerscan mcp --url …` reads the same
  whether the engine is installed or not.
- The runtime scripts stay the single source of truth and remain under the install manifest;
  the client build fails if it can find neither the repository scripts nor sdist copies.
- A pipx or uv install onto a machine that already has the launcher shim needs `--force` once
  (their bin directories coincide); the reverse order needs nothing.
- Homebrew installs the package tree directly with the formula's interpreter (no virtualenv, no
  build backend at install time), which is what a zero-dependency package allows.
