# ShakerScan

ShakerScan is an open-source security testing platform for web applications, APIs, AI systems, and
network-connected devices.
It runs locally in Docker and gives you a web UI, REST API, CLI, persistent findings, and agent-ready
workflows.

Use it directly or ask Codex, Claude Code, or OpenCode in plain English:

```text
Start ShakerScan.
Run a balanced passive Scan on https://app.example.test.
Show active critical and high findings.
Keep this authorized target covered over time.
Run a Hunt on this registered staging target.
Red-team my chatbot API.
Check this model artifact before deployment.
```

ShakerScan covers:

- DAST for websites and APIs, from fast posture checks to authorized active XSS/SQLi testing
- Connected-device posture for TVs, cameras, printers, routers, and appliances, including all-TCP
  inventory, service allowlists, SSH checks, and passive web-interface testing on any port
- Continuous attack-surface management (ASM), subdomain discovery, and certificate-transparency monitoring
- AI Gate tests for chat, RAG, agent, and MCP endpoints *(preview)*
- Model Intake reviews for provenance, dependencies, licenses, unsafe serialization, isolated runtime behavior, and deployment readiness
- Finding retests, evidence, the mission ledger, and Hunt; compatibility session and exception APIs
  remain available to agents without separate V1-oriented UI pages

> Only scan systems you own or are explicitly authorized to test. Active testing can change
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
the planner for Hunt, so no separate LLM API key needs to be stored in ShakerScan. Gated
execution is enabled in standard installs; ShakerScan still requires target authorization and an
expiring target-bound approval, and remains responsible for budgets, execution, and proof.

### Use the CLI

```bash
shakerscan scan https://app.example.test
shakerscan scan https://app.example.test --budget-profile thorough
shakerscan scan https://app.example.test --budget-profile thorough --active-testing --confirm-active
shakerscan hunt start --target-id "$TARGET_ID" --target-kind web
shakerscan credentials test "$PROFILE_ID"
shakerscan collections select "$COLLECTION_ID" --method GET
shakerscan evidence export --scan-id "$SCAN_ID" --format manifest
shakerscan status
```

`scan` submits the one deterministic DAST pipeline. `fast`, `balanced`, and `thorough` are resource
ceilings, while `--active-testing` is an explicit permission. Parallel placement and sharding are
internal decisions. Legacy `--type`, `scan-full`, and `scan-smart` writes have been removed. Use the
web UI or REST API for authentication values so secrets do not enter shell history. Credential create and
rotation requests are read from a file or stdin, never secret-bearing command-line flags. Hunt,
credential, and collection commands read their accepted fields from the running server contracts.
`credentials test` is deliberately a content-free storage, lifecycle, target-binding, and capability
admission check; it does not attempt a live login. Exercise a profile only through a separately
authorized, target-bound Scan or Hunt capability. Mutating CLI commands accept an opaque
`--idempotency-key`; retrying the exact method, path, and request with that key returns the original
successful public response, while different input with the same key fails closed. Never put a
credential or other secret in a retry key.

### Use the web UI

Open [http://localhost:3000](http://localhost:3000), select **New Scan**, enter an authorized target,
choose a coverage budget and whether active testing is authorized, and submit. The scan detail page shows live progress, logs,
findings, proof state, coverage, and the final report.

## Pick the right workflow

| Goal | Start here |
|---|---|
| Run reproducible web/API security testing | **Scan** |
| Trade time and traffic for breadth | **Scan → Fast, Balanced, or Thorough budget** |
| Run authorized active XSS/SQLi and broader application checks | **Scan → Active testing** |
| Test an authenticated application or API | New Scan → Authentication, or `POST /scans` |
| Keep an endpoint inventory fresh and close coverage gaps | **Continuous ASM** |
| Discover subdomains continuously | **Targets** or Gungnir CT monitoring |
| Inventory and assess a TV, camera, printer, or appliance | **Connected Devices** |
| Let the current AI agent investigate a web, API, network, or device target | **Hunt** |
| Test a chatbot, RAG pipeline, agent, or MCP server | **AI Gate** |
| Vet a model artifact before deployment | **Model Intake** |
| Reproduce a workflow or test two user roles manually | Ask the current agent to use the compatibility session API |
| Review, retest, suppress, or triage issues | **Findings**; exception lifecycle remains available through the API |
| Inspect retained proof or export evidence | **Evidence** |
| Let the current AI agent explore and exploit autonomously | **Hunt** |
| Preview a natural-language operation safely | Ask the current agent to use the AI operations API |

Connected-device scan capacity is opt-in to preserve existing DAST resources. Run
`./scanner.sh devices start` before the first device scan and `./scanner.sh devices status` to check
its dedicated worker/tool readiness.

### Scan policy and coverage budgets

Every submission runs the same deterministic pipeline. `fast`, `balanced`, and `thorough` set
duration, HTTP-request, endpoint, network, tool-time, and concurrency ceilings; they do not change
finding semantics. Active testing is off by default and requires explicit authorization. The runtime
selects compatible workers and shards internally, preserves partial discovery output at deadlines,
and reports incomplete coverage separately from failure.

## Common workflows

### Submit scans

```bash
# Passive deterministic Scan
shakerscan scan https://app.example.test \
  --budget-profile balanced

# The same pipeline with broader ceilings and authorized active capabilities
shakerscan scan https://app.example.test \
  --budget-profile thorough \
  --active-testing \
  --confirm-active
```

After a scan is queued, ShakerScan returns a scan ID. On a default install, follow it at
`http://localhost:3000/scans/{scan_id}`; remote installs use the UI URL printed by
`./scanner.sh status`. Long-running scans are asynchronous.

### Scan with authentication

Use **New Scan → Authentication** to create encrypted, exact-target credential profiles for bearer
tokens, cookies, custom headers, form login, or two-user BOLA/IDOR testing. The canonical REST API
accepts profile IDs only; reusable secret values never enter a Scan request or queue payload.

```bash
# Create this once after registering the target. The response contains profile.id.
curl -X POST http://localhost:8080/credential-profiles \
  -H "Content-Type: application/json" \
  -d '{
    "target_kind": "api",
    "target_id": "TARGET_UUID",
    "name": "Primary test principal",
    "auth_kind": "bearer_token",
    "principal_slot": "primary",
    "secret": "REDACTED_TOKEN",
    "allowed_capabilities": ["scan.execute"]
  }'

# Submit only the opaque reference. Credential use requires a current,
# target-bound approval receipt.
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.example.test",
    "budget_profile": "thorough",
    "policy": {"active_testing": true},
    "credential_profile_ids": ["PROFILE_UUID"],
    "approval_receipt_id": "TARGET_BOUND_APPROVAL_UUID"
  }'
```

Add a distinct `secondary` profile ID for differential BOLA/IDOR testing. The worker decrypts a
profile only after target, capability, version, expiry, and approval validation. New Scan writes are
canonical and secret-free; historical compatibility records remain readable for audit purposes.

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

> **Preview:** AI Gate remains a preview surface for this release. Model Intake now implements the
> complete acquisition, generated-evidence, no-egress inspection, evaluation, signed-admission, and
> revocation framework; production approval still requires operator-supplied tools, trust roots,
> runtime images, benchmarks, and evidence for the exact model and deployment.

AI Gate supports chat APIs, RAG APIs, agent traces, MCP traces, and embeddable widgets. In the UI:

1. Open **AI Gate**.
2. Add a target and its request/response mapping.
3. Test connectivity.
4. Select a probe pack and scan profile.
5. Review transcripts and findings after the scan finishes.

Production AI targets require explicit confirmation. See
[AI Test Workflows](https://github.com/andriyze/shakerscan/blob/main/docs/AI_TEST_WORKFLOWS.md).

### Check a model artifact

Open **Model Intake** to resolve a model reference, provide policy and trust evidence, and queue a
provider-neutral admission review. It supports Hugging Face, HTTPS, S3, GCS, Azure Blob, and bound
OCI/MLflow HTTPS exports; performs complete acquisition and generated static checks; can require the
no-egress sandbox and embedding/vector/graph evaluation; and emits a signed, revocable deployment
admission bound to the exact artifact and evidence digests.

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

### Run Hunt

Hunt uses the current Codex, Claude, or OpenCode session as an autonomous security
investigator. The AI composes its own same-origin probes, uses bounded active scanner tools, can
compare anonymous and authenticated behavior when managed principals are configured, and records
only claims backed by real tool output.

Hunt works after a standard first-time install: gated execution is on by default and the current
coding-agent session supplies the planner. It still requires explicit target authorization and an
expiring target-bound approval. ShakerScan keeps credentials server-side, enforces turn/request/action
ceilings, blocks arbitrary write methods in the free-form loop, and promotes a Suspected finding to
Verified only through deterministic proof.

To start:

1. Add the authorized target under **Targets**.
2. Run `shakerscan agent codex` (or `claude` / `opencode`).
3. Ask: `Run a Hunt on this authorized target.`

An administrator can disable every gated AI Operations execution path by setting
`AI_OPS_ROUTER_EXECUTE_ENABLED=false` in `.env` and restarting ShakerScan.

The UI launcher is **AI Investigator → Hunt**. Through an agent, the routing is:

| Request | Workflow |
|---|---|
| “Scan example.com” | Deterministic Scan with a balanced passive policy |
| “Run a thorough active Scan” | The same Scan with larger ceilings and explicit authorization |
| “Run a Hunt” | External-agent-driven `/hunts` investigation |
| “Verify this finding” | Bounded deterministic verifier |
| “Test this manually” | Agent-driven compatibility session API |

The older `/research/*` episode controller remains available for specialized guided verification
and compatibility. It is not the Hunt launcher.

## Web UI map

| Area | What it provides |
|---|---|
| Dashboard | Security posture, prioritized actions, recent activity, queue operations, worker freshness/scaling, and Gungnir |
| Docs | In-app rendering of the installed README for setup, workflows, safety, and troubleshooting |
| DAST Scans / New Scan | Submission, filters, cancellation, live logs, reports, proof, coverage, and PDF export |
| Connected Devices | Stable device identities, posture scans, service policy, credentials, generic request collections, and device-target Hunt capabilities |
| Targets / Exposure | Asset inventory, subdomains, exposure graph, and application graph |
| Coverage (Continuous ASM) | Endpoint inventory, proof-family coverage, gaps, recommendations, and activity |
| Findings | Triage, notes, retests, replay, cleanup, and accepted risk |
| AI Gate / Model Intake | AI endpoint red teaming and pre-deployment model checks |
| Hunt / Leads | AI-driven exploration through target-aware capabilities, bounded exploitation, proof promotion, and the hypothesis backlog |
| Evidence / Timeline / Campaigns | Proof inventory, exports, retention, mission history, and the read-only mission ledger |
| Settings | AI providers, scan policy, automation, deployment policies, and Arsenal |

Turn on **Show all** at the bottom of the sidebar to reveal advanced areas such as Evidence,
Timeline, Policy Profiles, and Command Arsenal.

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

The API accepts browser mutations from the UI origins derived from `SHAKERSCAN_PUBLIC_HOST`. If a
reverse proxy or alternate DNS name makes the browser-visible UI origin different, add that exact
origin with `SHAKERSCAN_CORS_ALLOW_ORIGINS=https://scanner.example.com` (comma-separated for more
than one), or use `SHAKERSCAN_CORS_ALLOW_ORIGIN_REGEX` for a controlled pattern. CLI, curl, and agent
requests without a browser `Origin` header are unaffected. On a trusted network, operators who
intentionally accept browser requests from every origin can explicitly set
`SHAKERSCAN_CORS_ALLOW_ORIGINS=*`.

Use `0.0.0.0` only behind a firewall, VPN, or authenticated reverse proxy. Do not expose ShakerScan
directly to the public internet. ShakerScan is a trusted-operator, self-hosted product: it does not
provide application login, users, roles, tenant isolation, or comprehensive evidence-secret masking.
Treat results, evidence, configuration, and backups as sensitive.

### Multi-node fleets

Multi-node Fleet is opt-in and requires Linux for both the control plane and worker hosts. macOS
continues to support standalone ShakerScan, but does not expose Fleet navigation or remote-worker
capacity; a direct Fleet-page visit explains the Linux requirement. Standalone Linux installs also
hide Fleet and remote placement until `fleet init` succeeds.

ShakerScan can add digest-pinned worker VPSs to one control plane. The supported 2.0.0 production
transport is the outbound-only HTTPS broker. Broker workers receive no Redis, PostgreSQL, or
object-store credentials:

```bash
# Control plane
shakerscan fleet init --network broker \
  --public-url https://scanner.example.com
shakerscan fleet join-token --ttl 24h --transport broker

# Worker VPS
shakerscan join https://scanner.example.com --token <join-token> --transport broker
```

If the public installer started a standalone stack on the worker VPS, a successful `join` stops
only that standalone project and preserves its data volumes before starting the worker-only Fleet
runtime. Unrelated Docker projects are not changed.

The built-in WireGuard workflow remains available as an operator preview for machines you own and
trust, but it is excluded from the 2.0.0 production support boundary until its own physical
two-host acceptance matrix passes in a future release cycle:

```bash
# Control plane
shakerscan fleet init --network wireguard \
  --endpoint fleet.example.com:51820 \
  --public-url https://scanner.example.com
shakerscan fleet join-token --ttl 24h

# Worker VPS
shakerscan join https://scanner.example.com --token <join-token>
```

Join tokens are single-use by default. For a controlled multi-worker rollout, generate one bounded
command with the exact host count, share it through an approved secret channel, and revoke unused
capacity immediately after enrollment:

```bash
shakerscan fleet join-token --ttl 1h --max-uses 5 --transport broker
shakerscan fleet revoke-join-token <token-id>
```

Every enrolled worker still receives its own node identity and durable credential. See the
[multi-node guide](https://github.com/andriyze/shakerscan/blob/main/docs/multi-node-guide.md#enroll-several-workers-with-one-bounded-token) for the
security and concurrency model.

Host-side `shakerscan fleet` commands automatically use the API bind and port persisted by
`scanner.sh`, including a verified Tailscale-only `--remote` bind. `--local-api` is an explicit
override, not a requirement for remote-mode control planes.

For source-checkout testing on a broker worker, append `--local-build`. This builds the worker image
on that host and skips pulling the fleet image; production joins remain digest-pinned registry pulls.

Both transports require a CA-verified HTTPS enrollment URL. For broker fleets, point the hostname at
the VPS and open TCP 80/443; when HTTPS is not already configured, `fleet init` provisions a pinned
Caddy gateway, obtains/renews the certificate, and exposes only worker enrollment and authenticated
broker routes. The UI and operator API remain local. `fleet init` preflights the host before
mutation, derives the installed worker image by default, and persists only its immutable digest.
Use `--worker-image` only for a custom worker build. It also
backs up a running standalone control plane before its first fleet conversion. For a
private-CA endpoint, pass `--ca-cert /path/to/ca.pem` to initialization and join; broker nodes persist
that CA and use it explicitly instead of the system trust store. Overlay traffic always requires the
private fleet CA returned during enrollment and fails with a configuration error if that CA is unavailable.
When the control-plane UI is opened over a verified Tailscale bind, enter the generated fleet operator
token on the Fleet page. Token-authenticated HTTP is accepted only when the live Tailscale IPv4 exactly
matches the published bind; other remote operator paths still require HTTPS.
The broker needs only outbound HTTPS from the worker; WireGuard additionally needs its configured UDP
port. Follow the [Multi-Node Fleet Guide](https://github.com/andriyze/shakerscan/blob/main/docs/multi-node-guide.md)
for setup and operations. See the
[Multi-Node Architecture](https://github.com/andriyze/shakerscan/blob/main/docs/multi-node-architecture.md)
for the trust model, capacity-weighted fleet scaling, placement labels, node audit trail, artifact
storage, drain, and rollout behavior.

### Build from source

```bash
git clone https://github.com/andriyze/shakerscan.git
cd shakerscan
./scanner.sh start --local
```

A source checkout defaults to local-build mode; `--local` makes that choice explicit. ShakerScan's
API, UI, worker, signer, and sandbox images are built from the current checkout before Compose starts
them, and synthetic local image tags are never pulled from a registry. Docker Compose v2 is required
for this source-build contract. Local-build mode is remembered for later starts. Use
`./scanner.sh start --prebuilt` to switch explicitly to the published images. Curl installations do
not contain Dockerfiles and continue to default to the versioned published images.

The source build downloads version-pinned Go scanner modules. It retries transient module-proxy or
DNS failures four times and preserves the Go module/build cache between attempts. A repeated error
such as `lookup proxy.golang.org ... i/o timeout` is a host/Docker DNS or internet-connectivity
failure, not a source compilation error; restore DNS/network access and rerun the build.

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
scan <target> [options]       Submit the deterministic DAST Scan
hunt start|call               Start a Hunt or call one returned capability
credentials create|rotate|test  Manage encrypted exact-target profiles
collections upload|bind|select  Manage encrypted request collections
evidence export                Export content-free evidence manifests or bundles
report-rebuild <bundle>        Rebuild a deterministic Scan report fully offline
doctor | install-deps         Diagnose or install local prerequisites
env                           Show runtime, PATH, and agent-launch guidance
agent [codex|claude|opencode] Launch an agent in the runtime
mcp                           Start the ShakerScan MCP adapter (Hunt plus read-only Arsenal)
research <episode-id> [N]     Drive bounded local Codex decisions
fleet init|join-token|revoke-join-token|accept  Provision a fleet or run physical acceptance
gungnir <command>             Manage certificate-transparency monitoring
build | rebuild               Build local images
reset                         Delete scanner data and recreate the database
shell                         Open a shell in the scanner container
```

Run `shakerscan` or `./scanner.sh` without arguments for current options and examples. `reset` is
destructive. Run `shakerscan scan --help` for the canonical `--budget-profile` and
`--active-testing` controls. Legacy `--type`, `scan-full`, and `scan-smart` write paths have been
removed. Explicit execution/sharding flags remain advanced placement inputs.

## REST API

The examples below assume the default loopback install. If `./scanner.sh status` prints a
non-loopback API URL (including Tailscale-only remote mode), use that URL even for commands run on
the ShakerScan host.

```bash
# Health and queue
curl http://localhost:8080/health
curl http://localhost:8080/queue/stats

# Submit the deterministic Scan
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target":"https://app.example.test","budget_profile":"balanced","policy":{"active_testing":false}}'

# Read one scan
curl http://localhost:8080/scans/{scan_id}
```

For a loopback install, the live OpenAPI document is available at
[http://localhost:8080/openapi.json](http://localhost:8080/openapi.json); remote installs use the API
URL printed by `./scanner.sh status`. Exact request examples and
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

# Enabled by default so confirmation-gated Hunt execution works after first install. Set false to disable
# every confirmation-gated AI Operations execution path globally.
AI_OPS_ROUTER_EXECUTE_ENABLED=true
```

`shakerscan start` generates owner-only random `POSTGRES_PASSWORD` and `REDIS_PASSWORD` values when
they are missing or weak, including when upgrading an older standalone install. The Compose files
have no well-known datastore-password fallback. Keep data services on the default loopback bind
unless you are using the documented private fleet overlay.

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
| TLS and network inspection | [TLSX](https://github.com/projectdiscovery/tlsx), [testssl.sh](https://github.com/testssl/testssl.sh), [Naabu](https://github.com/projectdiscovery/naabu), and [Nmap](https://nmap.org/) |
| Browser and client-side analysis | [Playwright](https://github.com/microsoft/playwright) and the [Retire.js](https://github.com/RetireJS/retire.js) vulnerability database |
| Security testing wordlists | [SecLists](https://github.com/danielmiessler/SecLists) |
| Design inspiration (not bundled) | ShakerScan adapted selected autonomous-research ideas from [T3MP3ST](https://github.com/elder-plinius/T3MP3ST) |

Tool availability and execution policy vary by target kind, authorization, and release. The generated
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
- [Build-once release process](https://github.com/andriyze/shakerscan/blob/main/docs/release-process.md)
- [ShakerScan 2.0.0 candidate release notes](https://github.com/andriyze/shakerscan/blob/v2/docs/releases/2.0.0.md)
- [ShakerScan 0.8.18 release notes](https://github.com/andriyze/shakerscan/blob/main/docs/releases/0.8.18.md)
- [ShakerScan 0.8.17 release notes](https://github.com/andriyze/shakerscan/blob/main/docs/releases/0.8.17.md)
- [ShakerScan 0.8.15 release notes](https://github.com/andriyze/shakerscan/blob/main/docs/releases/0.8.15.md)
- [ShakerScan 0.8.10 release notes](https://github.com/andriyze/shakerscan/blob/main/docs/releases/0.8.10.md)
- [ShakerScan 0.8.9 release notes](https://github.com/andriyze/shakerscan/blob/main/docs/releases/0.8.9.md)
- [ShakerScan 0.8.4 release notes](https://github.com/andriyze/shakerscan/blob/main/docs/releases/0.8.4.md)
- [ShakerScan 0.8.2 release notes](https://github.com/andriyze/shakerscan/blob/main/docs/releases/0.8.2.md)
- [ShakerScan 0.8.0 release notes](https://github.com/andriyze/shakerscan/blob/main/docs/releases/0.8.0.md)
- [First-run walkthrough](https://github.com/andriyze/shakerscan/blob/main/WALKTHROUGH.md)
- [Skill and agent guide](skills/README.md)
- [Canonical Scan and ASM architecture](https://github.com/andriyze/shakerscan/blob/main/docs/dast-asm-architecture.md)
- [DAST and Continuous ASM architecture](https://github.com/andriyze/shakerscan/blob/main/docs/dast-asm-architecture.md)
- [Connected-device security](https://github.com/andriyze/shakerscan/blob/v2/docs/connected-device-security.md)
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
