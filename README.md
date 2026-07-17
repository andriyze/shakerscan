# ShakerScan

ShakerScan is an open-source security testing platform for web applications, APIs, and AI systems.
It runs locally in Docker and gives you a web UI, REST API, CLI, persistent findings, and agent-ready
workflows.

Use it directly or ask Codex, Claude Code, or OpenCode in plain English:

```text
Start ShakerScan.
Run a quick scan on https://app.example.test.
Show active critical and high findings.
Red-team my chatbot API.
Check this model artifact before deployment.
```

ShakerScan covers:

- DAST for websites and APIs, from fast posture checks to authorized active XSS/SQLi testing
- Continuous attack-surface management (ASM), subdomain discovery, and certificate-transparency monitoring
- AI Gate tests for chat, RAG, agent, and MCP endpoints
- Model Intake checks for provenance, signatures, checksums, unsafe serialization, and policy readiness
- Interactive browser testing, finding retests, evidence, exceptions, campaigns, and bounded autonomous research

> Only scan systems you own or are explicitly authorized to test. Active scan modes can change
> application state, trigger alerts, and create significant traffic.

## Install and start

The supported first-run path installs ShakerScan to `~/.shakerscan`, creates the `shakerscan`
command, starts the Docker stack, and opens only local interfaces by default:

```bash
curl -fsSL https://install.shakerscan.com | sh
```

Open:

- Web UI: [http://localhost:3000](http://localhost:3000)
- API: [http://localhost:8080](http://localhost:8080)

Then choose how you want to work.

### Use an AI coding agent

Start the agent inside the installed runtime so it can load ShakerScan's instructions and skills:

```bash
shakerscan agent codex
shakerscan agent claude
shakerscan agent opencode
```

If the new command is not available in the current shell yet:

```bash
~/.local/bin/shakerscan env
~/.local/bin/shakerscan agent codex
```

The current agent session is also the default planner for Deep Hunt. No separate LLM API key is
required for agent-driven research; ShakerScan remains responsible for target scope, approvals,
budgets, execution, and proof.

### Use the CLI

```bash
shakerscan scan https://app.example.test
shakerscan status
```

`scan` submits a quick scan. Standard, deep, aggressive, authenticated, and advanced scans are
available in the web UI or REST API.

### Use the web UI

Open [http://localhost:3000](http://localhost:3000), select **New Scan**, enter an authorized target,
choose a scan type and coverage budget, and submit. The scan detail page shows live progress, logs,
findings, proof state, coverage, and the final report.

## Pick the right workflow

| Goal | Start here |
|---|---|
| Check DNS, TLS, and security headers | Quick scan |
| Add safe templates, CORS, cookies, and JS dependency checks | Standard scan |
| Add deeper discovery, ports, templates, and JS secret checks | Deep scan |
| Run authorized active XSS/SQLi and broader application checks | Full, Aggressive, or Smart scan |
| Test an authenticated application or API | New Scan → Authentication, or `POST /scans` |
| Keep an endpoint inventory fresh and close coverage gaps | **Continuous ASM** |
| Discover subdomains continuously | **Targets** or Gungnir CT monitoring |
| Test a chatbot, RAG pipeline, agent, or MCP server | **AI Gate** |
| Vet a model artifact before deployment | **Model Intake** |
| Reproduce a workflow or test two user roles | **Interactive** |
| Review, retest, suppress, or triage issues | **Findings** and **Exceptions** |
| Inspect retained proof or export evidence | **Evidence** |
| Run a bounded adaptive investigation | **Autonomous Hunt / Deep Hunt** |
| Preview a natural-language operation safely | **AI Operations Router** |

### Scan types and coverage budgets

Scan type controls what is tested. The coverage budget controls how much time and depth it receives.

| Scan type | Typical use | Active testing |
|---|---|---|
| `quick` | DNS, TLS, headers, and basic technology detection | No |
| `standard` | Safe web posture, Nuclei, cookies, CORS, and JS dependencies | No |
| `deep` | Broader discovery, full templates, ports, and JS secrets | No active XSS/SQLi |
| `full` | Comprehensive application assessment | Yes |
| `aggressive` | Maximum authorized depth and extended network coverage | Yes |
| `smart` | Adaptive discovery, XSS/SQLi, verification, and attack-chain analysis | Yes |

Coverage budgets are `fast`, `balanced`, `thorough`, and `exhaustive`. Prefer a deeper budget when
you want more coverage from the same scan type.

`full`, `aggressive`, and `smart` require explicit authorization. Smart scan policy and tuning are
documented in the [Smart Scan Policy](https://github.com/andriyze/shakerscan/blob/main/docs/SMART_SCAN_POLICY.md).

## Common workflows

### Submit scans

```bash
# Quick scan
shakerscan scan https://app.example.test

# Full or Smart scans require an explicit authorization confirmation
shakerscan scan-full https://app.example.test --confirm-active
shakerscan scan-smart https://app.example.test \
  --budget-profile thorough \
  --confirm-active
```

After a scan is queued, ShakerScan returns a scan ID. Follow it in the UI at
`http://localhost:3000/scans/{scan_id}`. Long-running scans are asynchronous.

### Scan with authentication

Use **New Scan → Authentication** for bearer tokens, cookies, custom headers, form login, or two-user
BOLA/IDOR testing. The REST API supports the same options:

```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.example.test",
    "options": {
      "scan_type": "smart",
      "auth_header": "Bearer REDACTED",
      "user2_header": "Bearer REDACTED"
    }
  }'
```

Treat authentication values as secrets. API responses redact stored credentials; ShakerScan can
also use managed credential profiles for interactive and research workflows.

### Review and retest findings

```bash
curl "http://localhost:8080/findings?status=active&severity=high"
curl "http://localhost:8080/findings?source_type=ai&status=active"

curl -X POST http://localhost:8080/findings/{finding_id}/retest \
  -H "Content-Type: application/json" \
  -d '{"requested_by":"api"}'
```

The findings workflow distinguishes reported, suspected, and verified issues. A label or HTTP 200
alone is not exploit proof; use the finding detail page and retest history to inspect the evidence.

### Test AI systems

AI Gate supports chat APIs, RAG APIs, agent traces, MCP traces, and embeddable widgets. In the UI:

1. Open **AI Gate**.
2. Add a target and its request/response mapping.
3. Test connectivity.
4. Select a probe pack and scan profile.
5. Review transcripts and findings after the scan finishes.

Production AI targets require explicit confirmation. See
[AI Test Workflows](https://github.com/andriyze/shakerscan/blob/main/docs/AI_TEST_WORKFLOWS.md).

### Check a model artifact

Open **Model Intake** to resolve a model reference, provide optional metadata, checksums, detached
signatures, and trust anchors, preview the trust policy, and submit a non-executing artifact check.
Results include provenance, serialization risk, license posture, model-card controls, and a
deployment decision.

### Run Continuous ASM

Continuous ASM maintains a target endpoint inventory and recommends the next bounded action:
discovery, an endpoint test batch, a focused SQLi/XSS/auth/BOLA wave, or waiting for active work.
Use **Continuous ASM** in the UI or:

```bash
curl http://localhost:8080/targets/{target_id}/asm/gaps

curl -X POST http://localhost:8080/targets/{target_id}/asm/improve \
  -H "Content-Type: application/json" \
  -d '{"batch_size":50,"stale_days":30}'
```

Auth checks require a primary auth context. BOLA testing also requires a distinct second user,
explicit deep intent, and the applicable approvals.

### Run bounded research

Autonomous Hunt uses immutable observations and one policy-checked action at a time. It can
investigate a target, verify one finding, or close ASM gaps without giving the planner raw shell or
credential access.

- `agent` is the default: the current Codex, Claude, or OpenCode session plans one step at a time.
- `configured_ai` uses the provider in Settings for unattended server autopilot.
- `local_codex` launches separate isolated Codex planner processes.

Deep Hunt campaigns can span multiple bounded episodes while preserving the original target,
approval, time, and episode limits.

## Web UI map

| Area | What it provides |
|---|---|
| Dashboard | Health, queue activity, worker freshness/scaling, Gungnir, recent work, and priority findings |
| Scans / New Scan | Submission, filters, cancellation, live logs, reports, proof, coverage, and PDF export |
| Targets / Exposure | Asset inventory, subdomains, exposure graph, and application graph |
| Continuous ASM | Endpoint inventory, proof-family coverage, gaps, recommendations, and activity |
| Findings / Exceptions | Triage, notes, retests, replay, cleanup, accepted risk, and exception lifecycle |
| AI Gate / Model Intake | AI endpoint red teaming and pre-deployment model checks |
| Interactive | Browser sessions, credentials, principals, auth expectations, replay, and manual findings |
| Evidence / Timeline / Campaigns | Proof inventory, exports, retention, mission history, and bounded action ledgers |
| Settings | AI providers, scan policy, automation, deployment policies, Arsenal, Router, and Research Agent |

The exhaustive route and capability catalog is in the
[Functionality Reference](https://github.com/andriyze/shakerscan/blob/main/docs/functionality-reference.md).

## Installation options

### Remote VPS over Tailscale

```bash
curl -fsSL https://install.shakerscan.com | SHAKERSCAN_REMOTE=1 sh
```

For an existing install:

```bash
shakerscan start --remote
```

Remote mode binds the UI and API to the VPS Tailscale IPv4 address and prints browser-facing URLs.
If Tailscale is unavailable:

```bash
SHAKERSCAN_BIND_HOST=0.0.0.0 \
SHAKERSCAN_PUBLIC_HOST=<server-ip-or-dns> \
shakerscan start --remote
```

Use `0.0.0.0` only behind a firewall, VPN, or authenticated reverse proxy. Do not expose ShakerScan
directly to the public internet.

### Build from source

```bash
git clone https://github.com/andriyze/shakerscan.git
cd shakerscan
./scanner.sh start --local
```

Use `./scanner.sh start` in a clone to run the published images instead.

### Upgrade

Re-run the installer:

```bash
curl -fsSL https://install.shakerscan.com | sh
```

It refreshes the runtime files and skills, preserves `.env`, `results`, and Docker volumes, and pulls
the selected images. Useful overrides:

```bash
# Update files without starting services
curl -fsSL https://install.shakerscan.com | SHAKERSCAN_START=0 sh

# Skip image pulls on the next start
SHAKERSCAN_PULL_IMAGES=0 shakerscan start
```

The installer supports macOS and common Linux distributions using `apt`, `dnf`/`yum`, `pacman`,
`zypper`, or `apk`. Windows users should run ShakerScan inside WSL2.

## CLI reference

```text
start                         Start the stack
stop | restart               Stop or restart the stack
reload                        Reload edited source and verify container parity
status                        Show services, queue state, workers, and access URLs
scale <N>                     Scale to 1-20 workers
logs [service] [-f]           Read API, worker, UI, PostgreSQL, or Redis logs
scan <target>                 Submit a quick scan
scan-full <target>            Submit an authorized full scan
scan-smart <target>           Submit an authorized smart scan
doctor | install-deps         Diagnose or install local prerequisites
env                           Show runtime, PATH, and agent-launch guidance
agent [codex|claude|opencode] Launch an agent in the runtime
mcp                           Start the read-only Command Arsenal MCP adapter
research <episode-id> [N]     Drive bounded local Codex decisions
gungnir <command>             Manage certificate-transparency monitoring
build | rebuild               Build local images
reset                         Delete scanner data and recreate the database
shell                         Open a shell in the scanner container
```

Run `shakerscan` or `./scanner.sh` without arguments for current options and examples. `reset` is
destructive.

## REST API

The API base URL is `http://localhost:8080` when commands run on the ShakerScan host.

```bash
# Health and queue
curl http://localhost:8080/health
curl http://localhost:8080/queue/stats

# Submit a quick scan
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target":"https://app.example.test","options":{"scan_type":"quick"}}'

# Read one scan
curl http://localhost:8080/scans/{scan_id}
```

The live OpenAPI document is available at
[http://localhost:8080/openapi.json](http://localhost:8080/openapi.json). Exact request examples and
agent safety rules are in [`AGENTS.md`](AGENTS.md); the generated inventory in the
[Functionality Reference](https://github.com/andriyze/shakerscan/blob/main/docs/functionality-reference.md)
lists every public route.

## Configuration

Most users can configure AI providers, scan execution, automation defaults, and deployment policies
from **Settings**. AI analysis and AI verification are optional; ordinary scans and agent-planned
research do not require a stored AI key.

Common `.env` settings:

```bash
AI_URL=https://api.openai.com/v1/chat/completions
AI_API_KEY=...
AI_MODEL=...

AI_VERIFY_ENABLED=false
AI_VERIFY_URL=https://api.openai.com/v1/chat/completions
AI_VERIFY_API_KEY=...
AI_VERIFY_MODEL=...
```

See the [Functionality Reference](https://github.com/andriyze/shakerscan/blob/main/docs/functionality-reference.md#14-configuration-and-integrated-tools)
for the current configuration map. Never commit real credentials.

## Troubleshooting

```bash
shakerscan doctor
shakerscan status
shakerscan logs api
shakerscan logs worker -f
docker stats
```

Common fixes:

- Docker unavailable: start Docker Desktop or the Docker service, then run `shakerscan doctor`.
- Ports `3000` or `8080` busy: stop the conflicting process or change the bind configuration.
- Scans remain pending: inspect `shakerscan status`, worker logs, and worker freshness; scale only
  when the host has enough memory.
- Memory pressure: reduce the worker count with `shakerscan scale 2`.
- Remote UI unavailable: use the exact URLs printed by `shakerscan status`; local mode binds only to
  `127.0.0.1`.

## Documentation

- [Documentation index](https://github.com/andriyze/shakerscan/blob/main/docs/README.md)
- [Full functionality reference](https://github.com/andriyze/shakerscan/blob/main/docs/functionality-reference.md)
- [Visual walkthrough](https://github.com/andriyze/shakerscan/blob/main/WALKTHROUGH.md)
- [Skill and agent guide](skills/README.md)
- [Smart Scan Policy](https://github.com/andriyze/shakerscan/blob/main/docs/SMART_SCAN_POLICY.md)
- [OWASP coverage matrix](https://github.com/andriyze/shakerscan/blob/main/docs/owasp-coverage-matrix.md)
- [AI security workflows](https://github.com/andriyze/shakerscan/blob/main/docs/AI_TEST_WORKFLOWS.md)
- [Interactive session guide](https://github.com/andriyze/shakerscan/blob/main/docs/INTERACTIVE_SESSIONS_GUIDE.md)

Historical implementation plans and point-in-time audits live under
[`docs/archive/`](https://github.com/andriyze/shakerscan/tree/main/docs/archive). They are retained
for traceability and are not current product instructions.

## Contributing

Issues and pull requests are welcome. For source changes:

1. Fork and clone the repository.
2. Create a feature branch.
3. Make and test the change.
4. Submit a pull request with the behavior and verification described.

## License and legal

ShakerScan is licensed under the
[Apache License 2.0](https://github.com/andriyze/shakerscan/blob/main/LICENSE).

Only use ShakerScan on targets you own or have explicit written permission to test. The software is
provided on an “AS IS” basis without warranties or conditions of any kind. The authors are not
responsible for unauthorized use, disruption, damage, or legal consequences.
