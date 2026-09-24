# ShakerScan

Open-source security testing for web applications, APIs, AI systems, and network-connected devices.

ShakerScan runs locally in Docker and provides a web UI, REST API, CLI, deterministic **Scan**, and
agent-driven **Hunt**.

> Test only systems you own or are explicitly authorized to assess.

## Quick start

Install and start ShakerScan:

```bash
curl -fsSL https://install.shakerscan.com | sh
```

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

ShakerScan ships `AGENTS.md` and task skills for Codex, Claude Code, and OpenCode. Start an
installed agent inside the ShakerScan runtime:

```bash
shakerscan agent codex
shakerscan agent claude
shakerscan agent opencode
```

The agent can drive Hunt, inspect findings, use saved credentials and request collections, and work
through the same server-side authorization, scope, budget, evidence, and proof controls as the UI
and CLI.

## LAN server

To run the engine on one trusted machine and control it from another:

```bash
# engine machine
shakerscan start --lan

# laptop/client
pipx install shakerscan
shakerscan api --url http://192.168.1.50:8080 GET /health
shakerscan mcp --url http://192.168.1.50:8080
```

LAN mode does not add authentication or encryption. Fresh OSS installs remain localhost-only.

## What to use

- **Scan** — reproducible web/API assessment.
- **Hunt** — adaptive investigation of an authorized web, API, network, or device target.
- **Connected Devices** — inventory and assess network-connected devices.
- **AI Gate** — test chat, RAG, agent, and MCP application surfaces.
- **Model Intake** — inspect model artifacts before deployment.
- **ASM** — maintain attack-surface inventory and coverage.

## Local source rebuilds

```bash
./scanner.sh rebuild          # infer the smallest safe scope
./scanner.sh rebuild ui       # UI only
./scanner.sh rebuild scanner  # scanner runtime, Model Intake overlay, and API
./scanner.sh rebuild all      # force the complete local image set
```

Automatic scope uses the last successful **clean full build** as its baseline. A partial, dirty,
missing or unknown receipt falls back to a full rebuild rather than missing reverted edits or
changes in untouched images. Shipped agent guides and skills are image inputs, not ignored docs.
`--no-cache` forces rebuilding the selected scope without cache; `--no-smoke` explicitly skips the
execution smoke. The summary and `.shakerscan-build-receipt.json` retain step timings, image-content
changes and smoke status. Image content includes runtime configuration, not only filesystem layers.
Only already-running rebuilt services are probed; stopped services remain stopped. UI-only rebuilds
retain their existing UI identity check without probing or restarting API/workers.

## Documentation

Start with `shakerscan --help`, the UI, or the live API contracts:

```bash
shakerscan api GET /openapi.json
shakerscan api GET /scan/contracts
shakerscan api GET /hunts/contract
```

Engineering and architecture documentation is in the
[docs directory](https://github.com/andriyze/shakerscan/tree/main/docs).

For agent behavior and product invariants, see
[AGENTS.md](https://github.com/andriyze/shakerscan/blob/main/AGENTS.md).

## License

AGPL-3.0.
