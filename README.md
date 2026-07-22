# ShakerScan

ShakerScan is an open-source security testing platform for web applications, APIs, and AI systems.
It runs locally in Docker and gives you a web UI, REST API, CLI, persistent findings, and agent-ready
workflows.

Use it directly or ask Codex, Claude Code, or OpenCode in plain English:

```text
Start ShakerScan.
Run a quick scan on https://app.example.test.
Show active critical and high findings.
Keep this authorized target covered over time.
Run a Deep Hunt on this registered staging target.
Red-team my chatbot API.
Check this model artifact before deployment.
```

ShakerScan covers:

- DAST for websites and APIs, from fast posture checks to authorized active XSS/SQLi testing
- Continuous attack-surface management (ASM), subdomain discovery, and certificate-transparency monitoring
- AI Gate tests for chat, RAG, agent, and MCP endpoints *(preview)*
- Model Intake checks for provenance, signatures, checksums, unsafe serialization, and policy readiness *(preview)*
- Interactive Testing, finding retests, evidence, exceptions, the mission ledger, and Deep Hunt

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

The first image pull may take several minutes, depending on the host and network. If the UI is not
ready yet, run `shakerscan status`. Then choose how you want to work.

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

Codex, Claude Code, or OpenCode must already be installed and signed in. The current agent session is
the planner for Deep Hunt, so no separate LLM API key needs to be stored in ShakerScan. Gated
execution is enabled in standard installs; ShakerScan still requires target authorization and an
expiring target-bound approval, and remains responsible for budgets, execution, and proof.

### Use the CLI

```bash
shakerscan scan https://app.example.test
shakerscan scan https://app.example.test --type standard --budget-profile thorough
shakerscan status
```

`scan` submits a quick scan by default. Use `--type` for `standard`, `deep`, `full`, `aggressive`, or
`smart`; coverage budgets and normal/parallel/Full Coverage execution are also available as CLI
options. Use the web UI or REST API for authentication values so secrets do not enter shell history.

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
| Reproduce a workflow or test two user roles manually | **Interactive Testing** |
| Review, retest, suppress, or triage issues | **Findings** and **Exceptions** |
| Inspect retained proof or export evidence | **Evidence** |
| Let the current AI agent explore and exploit autonomously | **Deep Hunt** |
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

The Advanced section also offers `Auto`, `Normal`, `Parallel`, and `Full Coverage` execution. Auto is
the recommended default and can shard eligible active scans across current workers. Full Coverage is
the heaviest breadth-first path: it discovers once, partitions the endpoint worklist, and presents
the merged result as one logical scan.

`full`, `aggressive`, and `smart` require explicit authorization. Smart scan policy and tuning are
documented in the [Smart Scan Policy](https://github.com/andriyze/shakerscan/blob/main/docs/SMART_SCAN_POLICY.md).

## Common workflows

### Submit scans

```bash
# Quick scan
shakerscan scan https://app.example.test

# Standard scan with a larger coverage budget
shakerscan scan https://app.example.test \
  --type standard \
  --budget-profile thorough

# Full, Aggressive, and Smart scans require an explicit authorization confirmation
shakerscan scan https://app.example.test \
  --type smart \
  --budget-profile thorough \
  --confirm-active

# Full Coverage discovers once and distributes the endpoint worklist
shakerscan scan https://app.example.test \
  --type smart \
  --execution coverage \
  --shards auto \
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
also use managed credential profiles for Interactive Testing and Deep Hunt.

### Review and retest findings

```bash
curl "http://localhost:8080/findings?status=active&severity=high"
curl "http://localhost:8080/findings?source_type=deep_hunt&status=active"

curl -X POST http://localhost:8080/findings/{finding_id}/retest \
  -H "Content-Type: application/json" \
  -d '{"requested_by":"api"}'
```

The findings workflow distinguishes reported, suspected, and verified issues. A label or HTTP 200
alone is not exploit proof; use the finding detail page and retest history to inspect the evidence.

### Test AI systems

> **Preview:** AI Gate and Model Intake are preview surfaces for this release. Deterministic
> real-stack smoke cases run in PR and release workflows, but their complete release-level E2E
> matrices are not yet implemented.

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
New web targets receive the conservative Continuous ASM policy by default; existing targets and
model artifacts are not silently changed. This can generate bounded background discovery and test
traffic. Global defaults are under **Settings → Scan execution**, while each target keeps its own
policy. Deep exploit mode remains off unless explicitly enabled.

In the UI:

1. Add an authorized web target under **Targets**.
2. Open **Attack surface → Coverage** and select the target.
3. Review its policy and choose **Improve coverage**.

The equivalent API flow is:

```bash
curl http://localhost:8080/targets/{target_id}/asm/gaps

curl -X POST http://localhost:8080/targets/{target_id}/asm/improve \
  -H "Content-Type: application/json" \
  -d '{"batch_size":50,"stale_days":30}'
```

Auth checks require a primary auth context. BOLA testing also requires a distinct second user and
explicit deep intent (`exploit_depth`).

### Run Deep Hunt

Deep Hunt uses the current Codex, Claude, or OpenCode session as an autonomous security
investigator. The AI composes its own same-origin probes, uses bounded active scanner tools, can
compare anonymous and authenticated behavior when managed principals are configured, and records
only claims backed by real tool output.

Deep Hunt works after a standard first-time install: gated execution is on by default and the current
coding-agent session supplies the planner. It still requires explicit target authorization and an
expiring target-bound approval. ShakerScan keeps credentials server-side, enforces turn/request/action
ceilings, blocks arbitrary write methods in the free-form loop, and promotes a Suspected finding to
Verified only through deterministic proof.

To start:

1. Add the authorized target under **Targets**.
2. Run `shakerscan agent codex` (or `claude` / `opencode`).
3. Ask: `Run a Deep Hunt on this authorized target.`

An administrator can disable every gated AI Operations execution path by setting
`AI_OPS_ROUTER_EXECUTE_ENABLED=false` in `.env` and restarting ShakerScan.

The UI launcher is **AI Investigator → Deep Hunt**. Through an agent, the routing is:

| Request | Workflow |
|---|---|
| “Scan example.com” | Quick DAST |
| “Run a deep scan” | Deep DAST |
| “Run a smart scan” | Smart DAST, after active-testing confirmation |
| “Run a Deep Hunt” | Keyless AI-driven `/agent/hunt/*` investigation |
| “Verify this finding” | Bounded deterministic verifier |
| “Test this manually” | Interactive Testing |

The older `/research/*` episode controller remains available for specialized guided verification
and compatibility. It is not the Deep Hunt launcher.

## Web UI map

| Area | What it provides |
|---|---|
| Dashboard | Security posture, prioritized actions, recent activity, queue operations, worker freshness/scaling, and Gungnir |
| Docs | In-app rendering of the installed README for setup, workflows, safety, and troubleshooting |
| DAST Scans / New Scan | Submission, filters, cancellation, live logs, reports, proof, coverage, and PDF export |
| Targets / Exposure | Asset inventory, subdomains, exposure graph, and application graph |
| Coverage (Continuous ASM) | Endpoint inventory, proof-family coverage, gaps, recommendations, and activity |
| Findings / Exceptions Queue | Triage, notes, retests, replay, cleanup, accepted risk, and exception lifecycle |
| AI Gate / Model Intake | AI endpoint red teaming and pre-deployment model checks |
| Deep Hunt / Leads | AI-driven exploration, bounded exploitation, proof promotion, and the hypothesis backlog |
| Interactive Testing | Browser sessions, credentials, principals, auth expectations, replay, and explicit findings |
| Evidence / Timeline / Campaigns | Proof inventory, exports, retention, mission history, and the read-only mission ledger |
| Settings | AI providers, scan policy, automation, deployment policies, Arsenal, and Router |

Turn on **Show all** at the bottom of the sidebar to reveal advanced areas such as Evidence,
Timeline, Exceptions Queue, Command Arsenal, and AI Ops Router.

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
directly to the public internet. ShakerScan is a trusted-operator, self-hosted product: it does not
provide application login, users, roles, tenant isolation, or comprehensive evidence-secret masking.
Treat results, evidence, configuration, and backups as sensitive.

### Build from source

```bash
git clone https://github.com/andriyze/shakerscan.git
cd shakerscan
./scanner.sh start --local
```

Local-build mode is remembered for later starts. Use `./scanner.sh start --prebuilt` to switch
explicitly to the published images.

### Upgrade

Create a database/results/configuration backup, then re-run the installer:

```bash
shakerscan backup
curl -fsSL https://install.shakerscan.com | sh
```

It refreshes the runtime files and skills, preserves `.env`, `results`, and Docker volumes, and pulls
the selected images. Required database migrations fail startup rather than continuing with an
incomplete schema. Do not use `shakerscan reset` to recover from an upgrade failure because it deletes
the database volume. The complete backup, verification, and database rollback procedure is in
[Upgrade and Rollback](https://github.com/andriyze/shakerscan/blob/main/docs/upgrade-and-rollback.md).

Useful overrides:

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
reload                        Reload edited source in local-build mode and verify parity
status                        Show services, queue state, workers, and access URLs
scale <N>                     Scale to 1-20 workers
logs [service] [-f]           Read API, worker, UI, PostgreSQL, or Redis logs
backup [directory]            Back up PostgreSQL, results, configuration, and release metadata
scan <target> [options]       Submit any DAST scan type (quick by default)
scan-full <target>            Compatibility alias for `scan --type full`
scan-smart <target>           Compatibility alias for `scan --type smart`
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
destructive. Run `shakerscan scan --help` for scan flags, including `--type`, `--budget-profile`,
`--execution`, `--shards`, `--shard-strategy`, `--endpoint`, `--approval-receipt`, and
`--require-current-workers`.

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

# Enabled by default so Deep Hunt works after first install. Set false to disable
# every confirmation-gated AI Operations execution path globally.
AI_OPS_ROUTER_EXECUTE_ENABLED=true
```

See the [Functionality Reference](https://github.com/andriyze/shakerscan/blob/main/docs/functionality-reference.md#14-configuration-and-integrated-tools)
for the current configuration map. Never commit real credentials.

## Integrated tools and credits

ShakerScan combines its own orchestration, safety controls, evidence model, and reporting with
established open-source security projects. We are grateful to their maintainers and contributors.

| Capability | Projects |
|---|---|
| Discovery and HTTP probing | [httpx](https://github.com/projectdiscovery/httpx), [Katana](https://github.com/projectdiscovery/katana), [Subfinder](https://github.com/projectdiscovery/subfinder), and [Gungnir](https://github.com/g0ldencybersec/gungnir) |
| Template-based checks | [Nuclei](https://github.com/projectdiscovery/nuclei) and the [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates) |
| Active web validation | [Dalfox](https://github.com/hahwul/dalfox), [sqlmap](https://github.com/sqlmapproject/sqlmap), and [ffuf](https://github.com/ffuf/ffuf) |
| TLS and network inspection | [TLSX](https://github.com/projectdiscovery/tlsx), [testssl.sh](https://github.com/testssl/testssl.sh), and [Nmap](https://nmap.org/) |
| Browser and client-side analysis | [Playwright](https://github.com/microsoft/playwright) and the [Retire.js](https://github.com/RetireJS/retire.js) vulnerability database |
| Security testing wordlists | [SecLists](https://github.com/danielmiessler/SecLists) |
| Design inspiration (not bundled) | ShakerScan adapted selected autonomous-research ideas from [T3MP3ST](https://github.com/elder-plinius/T3MP3ST) |

Tool availability and execution policy vary by scan type and release. The generated
[Functionality Reference](https://github.com/andriyze/shakerscan/blob/main/docs/functionality-reference.md#tool-and-local-agent-adapters)
records which adapters are wired, gated, or disabled; an installed binary is not automatically an
exposed ShakerScan action.

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
- [Release readiness checklist](https://github.com/andriyze/shakerscan/blob/main/docs/release-readiness.md)
- [ShakerScan 0.7.0 release notes](https://github.com/andriyze/shakerscan/blob/main/docs/releases/0.7.0.md)
- [First-run walkthrough](https://github.com/andriyze/shakerscan/blob/main/WALKTHROUGH.md)
- [Skill and agent guide](skills/README.md)
- [Smart Scan Policy](https://github.com/andriyze/shakerscan/blob/main/docs/SMART_SCAN_POLICY.md)
- [DAST and Continuous ASM architecture](https://github.com/andriyze/shakerscan/blob/main/docs/dast-asm-architecture.md)
- [OWASP coverage matrix](https://github.com/andriyze/shakerscan/blob/main/docs/owasp-coverage-matrix.md)
- [AI security workflows](https://github.com/andriyze/shakerscan/blob/main/docs/AI_TEST_WORKFLOWS.md)
- [Interactive session guide](https://github.com/andriyze/shakerscan/blob/main/docs/INTERACTIVE_SESSIONS_GUIDE.md)

Superseded plans and point-in-time audits are available through Git history and release tags; they
are not shipped as current product instructions.

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
