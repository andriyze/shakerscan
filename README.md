# ShakerScan

[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/andriyze/shakerscan?filter=v*&label=release)](https://github.com/andriyze/shakerscan/releases)
[![Python suite](https://github.com/andriyze/shakerscan/actions/workflows/python-suite.yml/badge.svg?branch=main)](https://github.com/andriyze/shakerscan/actions/workflows/python-suite.yml)
[![CodeQL](https://github.com/andriyze/shakerscan/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/andriyze/shakerscan/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/andriyze/shakerscan/badge)](https://scorecard.dev/viewer/?uri=github.com/andriyze/shakerscan)

Open-source security testing for web applications, APIs, AI systems, and network-connected devices.

ShakerScan runs locally in Docker and provides a web UI, REST API, CLI, one deterministic **Scan**,
and an agent-driven **Hunt**. Every network action is bound to an authorized target, metered
against a budget, and recorded as evidence; only deterministic proof marks a finding verified.

> **Responsible use.** Test only systems you own or are explicitly authorized to assess.
> Unauthorized scanning may be illegal and can disrupt services. You are responsible for how you
> use this software; it is provided without warranty (see [LICENSE](LICENSE)).

## Quick start

Requirements: Linux or macOS with Docker and Docker Compose v2 (the installer can install them),
and at least 8 GB of RAM for the full engine.

Install and start ShakerScan:

```bash
curl -fsSL https://install.shakerscan.com | sh
```

The installer downloads a tagged release, verifies every file against the release manifest, and
pulls digest-pinned images. To read it first:
`curl -fsSL https://install.shakerscan.com -o install.sh`.

Targets groups root domains with expandable subdomains and keeps discovery on each domain.
Use **Web** and **IP / network** filters to focus the inventory; an IP with a web service can appear
in both views while retaining one target identity. Hunt can manage target metadata and instructions
by default. Target detail includes **Hunt permissions** to disable these edits, approve specific
shared inputs, and save SSH host trust once.

Then open:

- UI: http://localhost:3000
- API: http://localhost:8080

Check the installation:

```bash
shakerscan status
```

Run a scan:

```bash
shakerscan scan https://app.example.test
```

For authorized active testing:

```bash
shakerscan scan https://app.example.test \
  --budget-profile thorough \
  --active-testing \
  --confirm-active
```

## Use an AI agent

ShakerScan ships `AGENTS.md` and task skills for Codex, Claude Code, OpenCode, and Pi. Start the
agent through ShakerScan so runtime URLs, planner identity, and agent-specific integration are applied:

```bash
shakerscan agent             # auto-detects codex, claude, opencode, then pi
shakerscan agent opencode    # or name one: codex, claude, opencode, or pi
```

The agent can drive Hunt, inspect findings, use saved credentials and request collections, and work
through the same server-side authorization, scope, budget, evidence, and proof controls as the UI
and CLI. Pi has no MCP client; the launcher passes the canonical ShakerScan skills and slash
commands explicitly and Pi drives the instance through `shakerscan api`, `scan`, and `hunt`. The
`.claude/` directory contains the same commands and agents for Claude Code.

## What to use

- **Scan** — reproducible web/API assessment with `fast`, `balanced`, and `thorough` ceilings.
- **Hunt** — adaptive investigation of an authorized web, API, network, or device target.
- **Connected Devices** — inventory and assess network targets with dedicated scanning capacity started automatically. Use `shakerscan devices stop` to disable that capacity on smaller installations, and `shakerscan devices start` to re-enable it.

The Targets inventory groups root domains with their subdomains and keeps IP addresses and internal
hosts independently selectable. Add a bare domain or IP with optional port hints, or an application
URL. Domain grouping is navigation only; it does not share authorization or credentials across hosts.
- **AI Gate** — test chat, RAG, agent, and MCP application surfaces.
- **Model Intake** — inspect model artifacts before deployment.
- **ASM** — maintain attack-surface inventory and coverage.

## How it works

```text
 Browser UI / CLI / MCP client / coding agent
                  |
                  v
        API (FastAPI, loopback by default)
        - target binding, scope and authorization
        - budgets, evidence, proof contracts
                  |
       +----------+-----------+
       |                      |
  PostgreSQL + Redis     Scan / Hunt workers
  (loopback, generated   - bounded capabilities from one registry
   passwords)            - nuclei, httpx, katana, sqlmap, testssl.sh, Nmap NSE, ...
                         - every request pinned to the authorized target and metered
```

Hunt is planned by the coding agent you run (Codex, Claude Code, OpenCode, or Pi); ShakerScan keeps
target binding, scope, policy, approval, budget, execution, evidence, and proof on the server.
Architecture details are in the
[documentation index](https://github.com/andriyze/shakerscan/blob/main/docs/README.md).

Each target can store instructions, learned knowledge and named **Saved Hunt actions**. Actions
compose canonical tool calls or a remote SSH command with typed parameters; saving one performs
no testing. Hunt loads their index at startup and can read, create, update and delete them when
target metadata edits are enabled. The **Live SSH** tab streams command output with the selected
stored identity, supports cancellation and can save a useful command as an action.

Hunt can watch SSH logs while checking the same asset's web services. Its agent worker runs bounded
concurrent jobs; device Hunts allow one SSH command alongside one external traffic action while
preserving device health pauses and all budgets. Browser workflows can submit authorized forms and
clean up test objects. `authz.verify` supports object comparisons and repeated function-access
matrices; role intent is never inferred from a successful response. Camera/router methodologies
include RTSP OPTIONS, SSH algorithm/key inspection and bounded SNMPv3 engine discovery.

## LAN server

To run the engine on one trusted machine and control it from another:

```bash
# engine machine
shakerscan start --lan

# laptop/client
pipx install shakerscan
shakerscan connect http://192.168.1.50:8080
```

LAN mode does not add authentication or encryption. Fresh OSS installs remain localhost-only. See
the [LAN access guide](https://github.com/andriyze/shakerscan/blob/main/docs/lan-access.md).

## Security model

- The open-source API has **no login**; it binds to `127.0.0.1` by default. Anyone who can reach
  it can operate the engine, and the API can use the Docker socket, so keep it on loopback or a
  trusted network.
- Targets need explicit authorization before active testing; scope, budgets, and approvals are
  enforced server-side, not by the UI or the agent.
- Stored credentials, including secret headers in an AI target's header template, are encrypted at
  rest and never returned by the API or sent to planners.
- Release images are digest-pinned, scanned, and published with SBOMs and build attestations.

Read [SECURITY.md](SECURITY.md) for the full trust boundaries and how to report a vulnerability.

## Troubleshooting

```bash
shakerscan status          # engine and worker health
shakerscan doctor          # connectivity and configuration checks
./scanner.sh logs -f       # follow service logs (from ~/.shakerscan)
```

A scan that fails is best diagnosed from `shakerscan api GET /scans/<id>/actions` and the worker
logs. If start reports that storage preparation (`api-storage-init`) failed, the credential encryption
key `results/.credential_enc.key` is unreadable, empty or damaged: restore it from your safe copy.
Removing it starts the engine with a new key, and stored credentials can no longer be decrypted. Open an [issue](https://github.com/andriyze/shakerscan/issues/new/choose) if you are stuck.

## Documentation

Start with `shakerscan --help`, the UI, or the live API contracts:

```bash
shakerscan api GET /openapi.json
shakerscan api GET /scan/contracts
shakerscan api GET /hunts/contract
```

Engineering and architecture documentation is in the
[docs directory](https://github.com/andriyze/shakerscan/tree/main/docs). For agent behavior and
product invariants, see [AGENTS.md](AGENTS.md). Release notes are listed in
[CHANGELOG.md](CHANGELOG.md).

## Acknowledgements

ShakerScan is built on outstanding open-source security work, including ProjectDiscovery's
nuclei, httpx, katana, subfinder, naabu and tlsx; sqlmap by Bernardo Damele A. G. and Miroslav
Stampar; Nmap by Gordon Lyon and the Nmap Project; testssl.sh by Dirk Wetter; dalfox by hahwul;
ffuf by Joona Hoikkala; meg by Tom Hudson; gungnir by g0lden; SecLists by Daniel Miessler and
contributors; Retire.js; Playwright; Trivy; and many more. The full list of components, authors
and licences is in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Contributing

Bug reports, false-positive/false-negative reports, and feature requests are very welcome. The
project does not accept outside code contributions; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Copyright (C) 2026 Andriy ([@andriyze](https://github.com/andriyze)).

ShakerScan is licensed under the [GNU Affero General Public License v3.0 only](LICENSE)
(AGPL-3.0-only). Bundled third-party components keep their own licences; see
[NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). "ShakerScan" is a trademark
of its author; see [TRADEMARKS.md](TRADEMARKS.md).
