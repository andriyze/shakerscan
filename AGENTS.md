# AGENTS.md - ShakerScan

This is an open-source Dynamic Application Security Testing (DAST) scanner. Users interact with it via AI coding agents to scan websites for vulnerabilities.

## Quick Setup

If the scanner isn't running, start it:
```bash
./scanner.sh start
```

For a remote VPS that should be opened from another machine over Tailscale, start in remote mode:
```bash
./scanner.sh start --remote
```

Remote mode binds the UI/API to the VPS Tailscale IPv4 address and prints remote URLs. Local laptop mode intentionally binds to `127.0.0.1`. If Tailscale is unavailable, use `SHAKERSCAN_BIND_HOST=0.0.0.0 SHAKERSCAN_PUBLIC_HOST=<server-ip-or-dns> ./scanner.sh start --remote`, but only behind a firewall, VPN, or reverse proxy.

Check status:
```bash
./scanner.sh status
```

If the user installed with `curl -fsSL https://install.shakerscan.com | sh` and is still in `/root` or another unrelated directory, ask them to start the agent inside the ShakerScan runtime:
```bash
shakerscan agent codex      # or claude, or opencode
```

Equivalent manual form:
```bash
cd ~/.shakerscan
codex   # or claude, or opencode
```

Using the global `shakerscan` command from any directory is fine for CLI operations, but AI agents should run from `~/.shakerscan` or a source checkout so they can read `AGENTS.md`, `CLAUDE.md`, `skills/`, and `.claude/`.

If `shakerscan` is not found in the current shell immediately after install, use the absolute launcher or ask the user to open a new shell:
```bash
~/.local/bin/shakerscan env
~/.local/bin/shakerscan agent codex
```

## How This Works

The scanner runs as Docker containers:
- **API** at `http://localhost:8080` - REST API for all operations
- **UI** at `http://localhost:3000` - Web dashboard
- **Workers** - Process scan jobs in parallel
- **PostgreSQL** - Stores scans, findings, targets
- **Redis** - Job queue

For the exhaustive generated capability catalog (all REST operations, registries, UI pages, CLI
flags, skills, agents, adapters, modules, and durable tables) plus architecture/policy pointers, see
[the functionality reference](https://github.com/andriyze/shakerscan/blob/main/docs/functionality-reference.md).

## Current UI (Implemented)

- **Dashboard (`/`)**: security-posture summary, prioritized action center, recent meaningful activity, and a compact operations bar for live queue state, emergency clear, worker count/scaling/stale-build warning, and Gungnir CT status/toggle. Auto-refreshes every 10-30s.
- **Docs (`/docs`)**: safely renders the installed `README.md` in the web UI. Relative README links open the matching public GitHub document; raw HTML is not rendered.
- **Scans (`/scans`)**: filter by status/domain/search, pagination (50/page), cancel running/pending scans, re-scan dropdown (all 6 scan types), auto-refresh every 5s. Shows target, type, status, score/grade, findings count, duration, date.
- **Scan Detail (`/scans/{id}`)**: live logs with auto-scroll while running (5s refresh), progress bar + current phase, partial-results view for failed scans (warning banner), refreshed deployment decision, full report with PDF export, compliance section, resolved coverage budget, AI Gate evidence, and Model Intake artifact checks when complete. Preserves list filter context on back navigation.
- **Exposure (`/exposure`)**: graph linking domains, targets, APIs, auth roles, third-party JS/vendors, cloud hints, AI targets, MCP tools, model artifacts, scans, and findings. Registered web assets can be opened directly in **Deep Hunt**.
- **Continuous ASM (`/asm`)**: target coverage, family proof rollups, scheduler decisions, endpoint inventory, gaps, recommendations, and target campaign timeline. **Open Deep Hunt** carries the target and a coverage-gap objective into the canonical AI investigation flow; ordinary improve/test actions remain available separately.
- **Timeline (`/timeline`)**: cross-product mission feed for scans, schedules, command results, evidence bindings, refuters, and exports.
- **Campaigns (`/campaigns`, `/campaigns/{id}`)**: inspect the read-only mission ledger, lifecycle state, finding impact, and action history. It is not a Deep Hunt launcher.
- **Evidence (`/evidence`)**: browse evidence instances, inspect objects, export content-free manifests/bundles, and run immutable-preview, approval-gated retention cleanup.
- **New Scan (`/scan/new`)**: scan type grid (6 types with duration/description), coverage budget selector (`fast`, `balanced`, `thorough`, `exhaustive`), advanced option toggles (Active Testing, Nuclei Templates, Subdomain Discovery, Enhanced DNS, JS Dependency Scanning, JS Secret Scanning), and optional custom budget overrides. Warning for active testing types.
- **Targets (`/targets`)**: hierarchical tree (root domains with collapsible subdomains), filter by discovery source/grade/has-findings, sort by domain/last-scanned/findings/score/date, search. Actions: add target, scan individual (dropdown), scan all in domain set, discover subdomains, create schedule (icon link). Shows subdomain count, scan count, findings count, grade per target.
- **Schedules (`/schedules`)**: create/toggle/delete recurring daily/weekly normal scans and typed ASM coverage waves (`asm_improve`). Evidence cleanup is intentionally interactive-only; legacy `evidence_retention_sweep` schedules are disabled and cannot be created or resumed.
- **Findings (`/findings`)**: filter by DAST, Deep Hunt, Interactive, AI Gate, Model Intake, ASM, or Manual source plus severity/status/last-seen/domain/search; sort by severity/first-seen/last-seen/CVSS; bulk cleanup with dry-run preview.
- **Finding Detail (`/findings/{id}`)**: status triage buttons (active/resolved/false_positive/accepted_risk), **delete finding** with confirmation, source badge, analyst notes, CVSS, CWE link, evidence summary (URLs, payloads, parameters, status codes, response anomalies), remediation steps, AI analysis (verdict/confidence/rationale/recommendations), raw HTTP request/response, copy buttons for URLs/payloads/IDs, external links to vulnerable URLs, one-shot proof replay, and a bounded **Verify finding** action for target-linked DAST/Deep Hunt/ASM/manual web findings.
- **AI Gate (`/ai-gate`)**: create and manage AI targets, use Secure RAG + Agent presets, choose auth, target type, probe pack, profile, and environment, then queue AI safety scans for chat APIs, RAG APIs, agent traces, and MCP endpoints. *(Preview surface: deterministic real-stack PR smoke is implemented; planned policy/exception and deterministic-judge seams are not yet release-gated.)*
- **Model Intake (`/model-intake`)**: use model-intake presets and queue artifact checks with artifact URL, metadata URL/JSON, checksum, detached signature URL/value, public key URL/PEM, trusted key PEM/fingerprints, policy profile, model card, approval flags, timeout, and download cap. *(Preview surface: deterministic real-stack PR smoke is implemented; the planned policy/exception seam is not yet release-gated.)*
- **Policy Profiles (`/settings/policy-profiles`)**: create, edit, activate/deactivate, and delete deployment gate profiles for AI Gate, Model Intake, and DAST decisions. Model Intake can select saved active profiles.
- **Interactive Testing (`/interactive`)**: browser sessions, managed credential profiles, target principals, authz expectations, endpoint replay, screenshots, and explicit finding creation.
- **Exceptions (`/exceptions`)**: exception queue, owner/approver/control repair, expiry visibility, and lifecycle sweep.
- **Command Arsenal (`/settings/arsenal`)**: command contracts, plans, scope/approval receipts, action ledger, hypotheses, refuters, tools, local agents, context packs, and decision traces.
- **AI Operations Router (`/settings/ai-ops-router`)**: preview natural-language operations as bounded API plans with safety, missing-input, blast-radius, and confirmation details before optional execution.
- **Deep Hunt (`/deep-hunt`)**: launch a keyless, AI-driven investigation through `/agent/hunt/*`. The current Codex/Claude/OpenCode session composes its own requests and tools; ShakerScan enforces target scope, expiring approval, bounded tool/action units, per-tool traffic limits, evidence provenance, and deterministic proof promotion. The request-unit counter counts tool invocations, not every wire request issued by a bounded scanner. Deep Hunt performs bounded active testing but blocks arbitrary state-changing HTTP in the free-form loop.
- **Leads and Test Builder (`/deep-hunt/leads`, `/deep-hunt/experiment`)**: inspect the hypothesis backlog or hand-craft an advanced bounded experiment. They support Deep Hunt; they are not separate engines.
- **Bounded experiments (`/deep-hunt/runs/{id}`)**: inspect durable runs from the compatibility `/research/*` controller, retained for specialized guided verification. Do not route a user's "Deep Hunt" request there; `/deep-hunt/operator` and `/deep-hunt/explorer` are legacy URLs that redirect to `/deep-hunt`.
- **Settings (`/settings`)**: AI providers, scan execution policy, automation defaults, and approval-receipt enforcement.
- **Application Graph (`/targets/{id}/graph`)**: inspect persisted route/object/principal nodes, producer/consumer/auth-boundary edges, node/edge filters, search, and selected-node connections.

## Your Role

When users ask about security scanning, you should:

**Important**: After submitting a scan, report the scan ID and UI link, then stop. Do NOT poll or wait for completion - scans can take minutes to hours. Users can check results via UI or ask later.

**DAST-quality / benchmarking notes:**
- **Never measure on a build-stale fleet.** Check `GET /workers` `build_current` (fingerprint-authoritative) and restart workers before validation scans. Scans stamp `expected_build_fingerprint_at_submit`/`stale_worker_count_at_submit`; pass `require_current_workers: true` to fail-closed on a stale fleet.
- **For DAST-quality benchmarking use a single Smart scan, not parallel `coverage`.** Coverage mode detects fewer crit/high (zero-rediscovery children skip the browser/DOM-XSS + global posture checks where many crit/highs live). Coverage is for breadth.
- **Benchmark scorecards:** `python3 scripts/benchmark_targets.py <juice_shop|crapi|honey> --auth` (submits, polls, scores verified-vs-suspected, coverage, gates). Fixtures in `tests/fixtures/benchmarks/*.yaml`. Score an existing scan with `--scan-id`. A verified-BOLA gate also requires a persisted distinct-principal receipt and successful owner/attacker responses; a finding label alone cannot pass it.
- **Agent-safe benchmark submission:** use `python3 scripts/benchmark_targets.py <target> --auth --submit-only` to require a current fleet, mint required principals, queue exactly one scan, print a content-free receipt, and exit. Report the scan ID/UI link and stop; score it on a later request with `--scan-id`.
- **Model Intake validation:** use `make e2e-model-intake` for the real public-model path. It enables the bounded Nex-N2-mini Hugging Face shard check and verifies that a capped partial download is reported as `known_unverified_truncated`, never as a false hash mismatch. Use `make e2e-model-intake-fixture` only when external network access is intentionally unavailable.
- **ASM gaps** (`GET /targets/{id}/asm/gaps`) returns `family_coverage` (completed vs attempts) and `recommended_campaigns` (recon / add_credentials / sqli_wave / xss_wave / bola_wave / retest_stale). Reports carry `verification_summary` (verified vs suspected, unproven crit/high).

For commands you run on the same machine as ShakerScan, use `http://localhost:8080` for the API. For browser-facing links on a remote VPS, use the UI URL printed by `./scanner.sh status` or `./scanner.sh start --remote` instead of hardcoding `localhost:3000`.

1. **Check if scanner is running** first:
   ```bash
   curl -s http://localhost:8080/health 2>/dev/null || echo "not running"
   ```

2. **Offer to start it** if not running:
   ```bash
   ./scanner.sh start
   ```

3. **Use the API** to perform operations (see below)

## API Reference

Base URL: `http://localhost:8080`

### Submit a Scan

```bash
# Quick scan (1-2 min) - DNS, TLS, headers
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {"scan_type": "quick"}}'

# Standard scan (5-10 min) - + Nuclei, JS deps
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {"scan_type": "standard"}}'

# Deep scan (30-60 min) - + full Nuclei, top-ports scan (1000)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {"scan_type": "deep"}}'

# Full assessment (1-2 hrs) - + active XSS/SQLi - REQUIRES PERMISSION
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {"scan_type": "full"}}'

# Aggressive (2+ hrs) - maximum coverage - REQUIRES PERMISSION
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {"scan_type": "aggressive"}}'

# Smart (variable) - adaptive intelligent scanning - REQUIRES PERMISSION
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {"scan_type": "smart"}}'
```

**Important**: Never run `full`, `aggressive`, or `smart` scans without asking user permission first. These scan types include active XSS/SQLi probes.

### Check Scan Status

```bash
# Get scan by ID
curl http://localhost:8080/scans/{scan_id}

# List recent scans (filter by status, domain)
curl "http://localhost:8080/scans?limit=10"
curl "http://localhost:8080/scans?status=completed&root_domain=example.com&limit=50"

# The scan list hides implementation rows by default. Use these only for debugging:
curl "http://localhost:8080/scans?include_shards=true&include_internal=true&limit=50"

# Get full result JSON
curl http://localhost:8080/scans/{scan_id}/result

# Get recent scan logs (default 200 lines, max 1000)
curl "http://localhost:8080/scans/{scan_id}/logs?limit=200"

# Cancel a running or pending scan
curl -X POST http://localhost:8080/scans/{scan_id}/cancel
```

### Batch Scans

Batch submission accepts 1-50 targets, removes duplicates, and returns `queued_count`,
`failed_count`, and per-target `errors`; `status: partial` means some scans were queued and others
were rejected. Do not report the requested count as queued.

```bash
curl -X POST http://localhost:8080/scans/batch \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["https://a.example.com", "https://b.example.com"],
    "options": {"scan_type": "quick"}
  }'
```

### Findings

```bash
# List active findings
curl "http://localhost:8080/findings?status=active"

# Filter by severity
curl "http://localhost:8080/findings?severity=critical"
curl "http://localhost:8080/findings?severity=high"

# Filter by recency (last 30 days)
curl "http://localhost:8080/findings?seen_within_days=30"

# Combined filters with sorting
curl "http://localhost:8080/findings?severity=high&status=active&sort_by=cvss&sort_order=desc&limit=50"

# Update finding status (with optional notes)
curl -X PATCH http://localhost:8080/findings/{id} \
  -H "Content-Type: application/json" \
  -d '{"status": "resolved", "notes": "Fixed in v2.1 deploy"}'

# Delete a finding
curl -X DELETE http://localhost:8080/findings/{id}

# Bulk cleanup old findings (dry-run first)
curl -X POST http://localhost:8080/findings/cleanup \
  -H "Content-Type: application/json" \
  -d '{"older_than_days": 90, "dry_run": true}'

# Bulk cleanup (execute after reviewing dry-run count)
curl -X POST http://localhost:8080/findings/cleanup \
  -H "Content-Type: application/json" \
  -d '{"older_than_days": 90, "status": "resolved", "root_domain": "example.com", "dry_run": false}'

# Bulk update finding statuses
curl -X POST http://localhost:8080/findings/bulk \
  -H "Content-Type: application/json" \
  -d '{"finding_ids": ["id1", "id2"], "status": "false_positive", "notes": "Verified non-issue"}'

# Queue retest for one finding (tiered: deterministic then optional AI escalation)
curl -X POST http://localhost:8080/findings/{id}/retest \
  -H "Content-Type: application/json" \
  -d '{"requested_by": "api"}'

# Force AI-only retest for one finding
curl -X POST "http://localhost:8080/findings/{id}/retest?mode=ai" \
  -H "Content-Type: application/json" \
  -d '{"requested_by": "api"}'

# Bulk retest by IDs or filters (supports mode: ai|deterministic)
curl -X POST http://localhost:8080/findings/retest \
  -H "Content-Type: application/json" \
  -d '{"severity": "high", "status": "active", "limit": 25, "mode": "deterministic"}'

# List retest history for one finding
curl "http://localhost:8080/retests/finding/{id}?limit=20"

# Get one retest record with proof/artifacts/AI metadata
curl "http://localhost:8080/retests/{retest_id}"

# Create manual finding (from manual testing)
curl -X POST http://localhost:8080/findings/manual \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "title": "BOLA on User API",
    "severity": "critical",
    "description": "User2 can access User1 data via /api/users/{id}",
    "category": "BOLA",
    "cwe": "CWE-639",
    "evidence": "GET /api/users/1 with User2 token returns User1 profile"
  }'

# Create finding from Interactive Testing (compatibility `/session` API)
curl -X POST "http://localhost:8080/session/{session_id}/findings" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "BOLA on Basket API",
    "severity": "critical",
    "description": "User2 can read/delete User1 basket items",
    "category": "BOLA",
    "cwe": "CWE-639"
  }'
```

Status options: `active`, `resolved`, `false_positive`, `accepted_risk`

Finding source filters are first-class: `dast`, `deep_hunt`, `ai`, `ai_gate`, `ai_session`,
`autonomous`, `model_intake`, `asm`, and `manual`. The UI exposes DAST, Deep Hunt, Interactive,
AI Gate, Model Intake, ASM, and Manual controls. `deep_hunt` combines agent-native claims with
scanner findings driven by a hunt. Use the broader `ai` compatibility filter when AI Gate and
Interactive findings should be combined.

**Findings Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| `status` | Filter by status (active, resolved, false_positive, accepted_risk) |
| `severity` | Filter by severity (critical, high, medium, low, info) |
| `source_type` | `dast`, `deep_hunt`, `ai`, `ai_gate`, `ai_session`, `autonomous`, `model_intake`, `asm`, or `manual` |
| `seen_within_days` | Only findings seen within N days (e.g., 7, 30, 60, 90) |
| `root_domain` | Filter by root domain |
| `target_id` | Filter by target ID |
| `scan_id` | Filter by scan ID |
| `verification_verdict` | Filter by latest verification verdict (`exploited`, `likely_fixed`, etc.) |
| `verification_mode` | Filter findings with verification runs in mode `deterministic` or `ai_driven` |
| `verified_only` | If true, only return findings with `last_verification_verdict = exploited` |
| `driven_by` | Compatibility dimension: `autonomous_research` selects scanner work launched by a hunt. Prefer `source_type=deep_hunt` for the complete user-facing source. |
| `research_campaign_id` | Only findings driven by a specific research campaign/run (UUID) |
| `search` | Search by title or URL |
| `sort_by` | Sort field: severity, first_seen, last_seen, cvss |
| `sort_order` | asc or desc (default: desc) |
| `limit` | Results per page (default: 100, max: 500) |
| `offset` | Pagination offset |

Retest history records (`/retests/*`) include: `verification_mode`, `ai_plan`, `ai_reasoning`, `proof`, `artifacts`, and replay commands.

**Cleanup Parameters:**

| Parameter | Description |
|-----------|-------------|
| `older_than_days` | Required. Delete findings last seen more than N days ago |
| `status` | Optional. Only delete findings with this status |
| `root_domain` | Optional. Only delete findings for this domain |
| `dry_run` | If true, returns count without deleting (default: true) |

### Target Management

```bash
# List targets (flat)
curl http://localhost:8080/targets

# List targets grouped by root domain (hierarchical view)
curl "http://localhost:8080/targets/grouped?sort_by=active_findings_count&sort_order=desc"

# List root domains (for filter dropdowns)
curl http://localhost:8080/domains

# Add a target
curl -X POST http://localhost:8080/targets \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "name": "Production"}'

# Get target details with recent scans
curl http://localhost:8080/targets/{target_id}

# Update target
curl -X PATCH http://localhost:8080/targets/{target_id} \
  -H "Content-Type: application/json" \
  -d '{"name": "Staging", "scan_options": {"scan_type": "standard"}}'

# Deactivate target (soft delete)
curl -X DELETE http://localhost:8080/targets/{target_id}

# Start scan for a specific target
curl -X POST http://localhost:8080/targets/{target_id}/scan \
  -H "Content-Type: application/json" \
  -d '{"options": {"scan_type": "quick"}}'
```

**Grouped Targets Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| `search` | Search by URL or domain |
| `discovery_source` | Filter: manual, subfinder, gungnir-monitor, import, model-intake |
| `grade` | Filter by grade: A, B, C, D, F |
| `has_findings` | Filter: true (with findings) or false (no findings) |
| `sort_by` | root_domain, last_scanned_at, active_findings_count, last_score, created_at |
| `sort_order` | asc or desc |

### Continuous ASM

Continuous ASM keeps a persistent endpoint inventory per target, then lets users improve coverage without starting many separate visible scans. The `/asm/improve` endpoint is the simplest API for UI and AI agents: it queues discovery when no inventory exists, queues the next endpoint test batch when endpoints are untested/stale, or returns `wait` when work is already active for the target.

```bash
# Get inventory and coverage
curl http://localhost:8080/targets/{target_id}/asm/endpoints
curl http://localhost:8080/targets/{target_id}/asm/coverage

# Explain what remains untested and what to do next
curl http://localhost:8080/targets/{target_id}/asm/gaps

# Queue the recommended next action: discovery, endpoint test batch, or wait
curl -X POST http://localhost:8080/targets/{target_id}/asm/improve \
  -H "Content-Type: application/json" \
  -d '{"batch_size": 100, "stale_days": 30}'

# Force a discovery refresh only
curl -X POST http://localhost:8080/targets/{target_id}/asm/recon \
  -H "Content-Type: application/json" \
  -d '{}'

# Force an endpoint test batch over untested/stale inventory
curl -X POST http://localhost:8080/targets/{target_id}/asm/test \
  -H "Content-Type: application/json" \
  -d '{"batch_size": 100, "stale_days": 30, "exploit_depth": false}'

# Focus the next ASM test batch on one supported active family
curl -X POST http://localhost:8080/targets/{target_id}/asm/improve \
  -H "Content-Type: application/json" \
  -d '{"check_family": "sqli"}'

curl -X POST http://localhost:8080/targets/{target_id}/asm/test \
  -H "Content-Type: application/json" \
  -d '{"batch_size": 100, "check_family": "xss"}'

# Auth/access-control checks require primary auth context on the target
curl -X POST http://localhost:8080/targets/{target_id}/asm/improve \
  -H "Content-Type: application/json" \
  -d '{"check_family": "auth"}'

# High-risk BOLA/IDOR requires Lab/deep intent and two auth contexts on the target
curl -X POST http://localhost:8080/targets/{target_id}/asm/improve \
  -H "Content-Type: application/json" \
  -d '{"check_family": "bola", "exploit_depth": true}'

# Spend extra one-shot batch budget on API-like endpoints only
curl -X POST http://localhost:8080/targets/{target_id}/asm/improve \
  -H "Content-Type: application/json" \
  -d '{"endpoint_filter": "api", "batch_size": 100}'

# View recent ASM recon/test jobs without cluttering the normal scans list
curl http://localhost:8080/targets/{target_id}/asm/activity
```

ASM actions are target-scoped and reject new work while another pending/running scan exists for the same target. `check_family` currently supports `all`, `sqli`, `xss`, credential-gated `auth`, and gated `bola`; omit it or use `all` for the normal ASM mix. `endpoint_filter: "api"` narrows a batch to API-like endpoints without changing target-wide defaults. Auth requires primary auth on the target. BOLA requires `exploit_depth: true`, primary auth, and second-user auth. After submitting an ASM action that queues a scan, report the returned scan ID and UI link (`/scans/{scan_id}`), then stop. Do not poll unless the user explicitly asks.

### AI Operations Router

For natural-language agent requests, prefer the dry-run router first. It returns the planned API call, safety preset, missing inputs, blast radius, and confirmation requirements without queueing active work by default.

```bash
curl -X POST http://localhost:8080/ai/ops/route \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Run full coverage on this target", "target": "https://example.com"}'
```

Active or budget-increasing intents return `dry_run: true` unless `execute`, `confirm_execution`, and `confirm_authorized` are true. Standard installs set `AI_OPS_ROUTER_EXECUTE_ENABLED=true`; an administrator can set it to `false` as a global execution kill switch. High-risk BOLA also requires `confirm_high_risk` plus auth context hints.

### Deep Hunt

Natural-language routing is strict:

- `scan`, `quick scan`, `standard scan`, `deep scan`, `full scan`, `aggressive scan`, and
  `smart scan` are Web DAST.
- `deep hunt`, `autonomous hunt`, and `investigate autonomously` are the keyless `/agent/hunt/*`
  workflow below. Never translate Deep Hunt into `/research/campaigns/launch`.
- `verify this finding` uses the bounded finding verifier/retest.
- `interactive testing` uses `/session/*`.

Deep Hunt is AI-driven exploration plus bounded active exploitation. Before launch, confirm the
target is authorized and create a target-bound expiring credential-tier approval. Standard installs
enable gated execution by default; `AI_OPS_ROUTER_EXECUTE_ENABLED=false` is the administrator's
global kill switch. The current coding-agent session is the planner; no stored AI provider key is
required. ShakerScan seeds a redacted context pack, then suspends at each turn; the
session reads the transcript, requests tools with a fenced
` ```json {"tool_calls":[...]} ``` ` block (or ends with a `{"done":true,"findings":[...]}` debrief),
and the server executes the tools (same-origin/approval-gated) and returns the next observation. Tools:
`http_request` (send as a server-managed `as_principal` — credentials are never model-visible),
`query_kb`, `diff`, `note`, and a bounded argv-templated `run_tool`.

Deep Hunt enables bounded active `run_tool` templates. Arbitrary state-changing HTTP remains blocked
in the free-form loop; mutations belong to typed workflows with cleanup/restoration contracts.
Findings land in the **SUSPECTED** tier only after the provenance gate resolves real tool evidence.
Supported claims may become **VERIFIED** only through deterministic server re-execution.

Business-logic families (access_control, field_constraint, workflow_transition) verify through
operator-approved typed invariant contracts: the hunt auto-drafts review candidates from black-box
facts (endpoint expectations, app-graph auth_boundary edges, its own SUSPECTED findings) at board
seeding — drafts never auto-approve. Approve a draft, then re-verify. workflow_transition contracts
require a `probe_state` (the forbidden target state to attempt) at approval time.

The first observation returned by `session` is itself a full system prompt (tool arsenal, the
RECON→PLAN→EXECUTE→EVIDENCE→SELF-CRITIQUE cadence, and the exact debrief schema) — read it; the harness
self-describes the contract each turn. Three things trip up a first-time driver:
- **Evidence is `evidence_refs`, not prose.** Each debrief finding proves itself ONLY through
  `evidence_refs` — normally the `resp_N` refs returned by `http_request`; the runtime also accepts
  `scan_N` refs from successful `run_tool` calls, although the current text contract does not advertise
  them. The server resolves cited refs into tool-output evidence for the provenance gate. Inline
  `evidence`/`details` prose is NOT evidence; a prose-only finding fails the gate and persists nothing.
  Debrief shape:
  `{"done":true,"findings":[{"title","severity","family","predicate","route","method","cwe","details","evidence_refs":["resp_1","resp_2"],"remediation"}],"abstained":false}`.
- **The coding agent drives each turn** — reply while `status: awaiting_planner` and
  STOP on any terminal status (a run ends `completed`, `failed`, or `cancelled`, not only `completed`;
  check `stop_reason`). Do not keep replying to a terminal run.
- **Authenticated targets need principals configured FIRST.** Provision managed principals + credential
  profiles on the target (`POST /targets/{id}/principals` + credential profiles; `as_principal` reads
  the profile server-side) before starting, or the hunt runs anonymous-only. crAPI-style JWTs expire,
  so rotate stale profiles (`POST /targets/{id}/credential-profiles/{profile_id}/rotate`) first.

```bash
# Start Deep Hunt. The approval must be credential-tier, target-bound, and unexpired.
curl -X POST http://localhost:8080/agent/hunt/{target_id}/session \
  -H "Content-Type: application/json" \
  -d '{"objective":"Explore autonomously and verify the highest-value weaknesses",
       "mode":"deep_hunt","max_iterations":20,
       "approval_receipt_id":"approval-uuid"}'

# Optional grey-box grounding (B2): when you have the target's source locally, set
# SHAKERSCAN_SOURCE_ROOT on the API host to the containing tree (mounted into the api container),
# then pass source_dir. The hunt gets a security-ranked source_excerpt pack section + source-derived
# leads. Containment is enforced (realpath both sides; 400 outside the root). Black-box is the default.
curl -X POST http://localhost:8080/agent/hunt/{target_id}/session \
  -H "Content-Type: application/json" \
  -d '{"objective":"Explore autonomously and verify the highest-value weaknesses",
       "mode":"deep_hunt","max_iterations":20,
       "approval_receipt_id":"approval-uuid",
       "source_dir":"/srv/sources/juice-shop"}'

# Submit one planner reply (a tool_calls block or a final debrief); get the next observation.
curl -X POST http://localhost:8080/agent/hunt/session/{run_id}/reply \
  -H "Content-Type: application/json" \
  -d '{"reply": "```json\n{\"tool_calls\":[{\"name\":\"query_kb\",\"arguments\":{\"kind\":\"findings\"}}]}\n```"}'

# Final debrief — evidence_refs are the resp_N refs from prior http_request calls that PROVE the finding.
curl -X POST http://localhost:8080/agent/hunt/session/{run_id}/reply \
  -H "Content-Type: application/json" \
  -d '{"reply": "```json\n{\"done\":true,\"findings\":[{\"title\":\"Excessive data exposure in feed\",\"severity\":\"medium\",\"family\":\"data_exposure\",\"predicate\":\"sensitive_value_present\",\"route\":\"/api/feed\",\"method\":\"GET\",\"cwe\":\"CWE-200\",\"details\":\"non-requester email present; identical across principals\",\"evidence_refs\":[\"resp_1\",\"resp_2\"]}],\"abstained\":false}\n```"}'

# Inspect / cancel
curl http://localhost:8080/agent/hunt/session/{run_id}
curl -X POST http://localhost:8080/agent/hunt/session/{run_id}/cancel

# Two-tier finding view for the target (VERIFIED moat vs SUSPECTED agent)
curl http://localhost:8080/agent/findings/{target_id}
```

The compatibility `/research/*` episode controller remains available for specialized guided
verification, exact-finding missions, and legacy runs. It is not the Deep Hunt launcher.

### Subdomain Discovery

```bash
# Start subdomain discovery
curl -X POST "http://localhost:8080/discovery?root_domain=example.com"

# List discovery runs
curl http://localhost:8080/discovery

# Get discovery run details
curl http://localhost:8080/discovery/{discovery_id}
```

### Dashboard & Status

```bash
# Dashboard metrics
curl http://localhost:8080/dashboard

# Queue status
curl http://localhost:8080/queue/stats

# Emergency clear all pending jobs
curl -X DELETE http://localhost:8080/queue/clear
```

### Automation Settings

```bash
# Compact safe automation defaults: auto-sharding + default Continuous ASM policy
curl http://localhost:8080/settings/automation

curl -X PUT http://localhost:8080/settings/automation \
  -H "Content-Type: application/json" \
  -d '{"auto_sharding_enabled": true, "default_asm_enabled": true,
       "default_asm_config": {"batch_size": 50, "stale_days": 30},
       "default_research_planner_mode": "agent",
       "approval_receipts_required_for_state_changing_actions": false}'
```

`/settings/automation` is the preferred compact surface for UI/API/AI agents. It keeps global `exploit_depth` locked off; Lab/deep ASM still requires explicit per-target or per-action intent. Set `approval_receipts_required_for_state_changing_actions` to `true` to require a valid scope/approval receipt before queueing scans, ASM actions, AI Gate runs, Model Intake scans, or retests.
`default_research_planner_mode` accepts `agent`, `local_codex`, or `configured_ai`; clean installs default to `agent`.

### Worker Management

Control the number of scanner workers to handle parallel scans:

```bash
# Get current worker count and status
curl http://localhost:8080/workers

# Scale to 5 workers
curl -X POST http://localhost:8080/workers \
  -H "Content-Type: application/json" \
  -d '{"count": 5}'

# Scale to 10 workers for heavy workloads
curl -X POST http://localhost:8080/workers \
  -H "Content-Type: application/json" \
  -d '{"count": 10}'
```

Worker limits: 1-20 workers. Each worker uses ~1-2 CPU cores and 2-4GB RAM during scans.

### AI Settings

Configure scan AI and AI retest verification at runtime (stored in Redis), with optional local `.env` persistence:

```bash
# Get effective AI settings (API keys are masked)
curl http://localhost:8080/settings/ai

# Update runtime settings only (takes effect for new jobs immediately)
curl -X PUT http://localhost:8080/settings/ai \
  -H "Content-Type: application/json" \
  -d '{
    "ai_url": "https://api.openai.com/v1/chat/completions",
    "ai_api_key": "sk-...",
    "ai_model": "gpt-4o-mini",
    "ai_model_fallback": "deepseek/deepseek-chat,anthropic/claude-3-5-sonnet",
    "ai_verify_enabled": true,
    "ai_verify_url": "https://api.openai.com/v1/chat/completions",
    "ai_verify_api_key": "sk-...",
    "ai_verify_model": "gpt-4o-mini",
    "ai_verify_model_fallback": "openai/gpt-4o-mini,anthropic/claude-3-5-sonnet",
    "ai_verify_min_severity": "high",
    "persist_to_env": false
  }'

# Clear keys and persist to local .env (if API has LOCAL_ENV_FILE access)
curl -X PUT http://localhost:8080/settings/ai \
  -H "Content-Type: application/json" \
  -d '{
    "ai_url": "",
    "ai_api_key": "",
    "ai_model_fallback": "",
    "ai_verify_url": "",
    "ai_verify_api_key": "",
    "ai_verify_model_fallback": "",
    "persist_to_env": true
  }'

# Probe active settings for scan AI
curl -X POST http://localhost:8080/settings/ai/test \
  -H "Content-Type: application/json" \
  -d '{"scope":"scan"}'

# Probe retest AI with temporary override values (without persisting)
curl -X POST http://localhost:8080/settings/ai/test \
  -H "Content-Type: application/json" \
  -d '{
    "scope":"verify",
    "ai_model":"gpt-4o-mini",
    "ai_fallback_model":"deepseek/deepseek-chat"
  }'
```

Notes:
- Runtime settings apply to **new scans/retests** without restarting services.
- `persist_to_env: true` writes values to `LOCAL_ENV_FILE` (default `/workspace/.env` in Docker).

### AI Gate

AI Gate tests AI application surfaces for prompt injection, sensitive disclosure, unsafe tool use, RAG leakage, and MCP/tool boundary failures. It is managed in the UI at `/ai-gate` and through REST APIs, so Claude, Codex, OpenCode, or any agent that can call HTTP can use it as a ShakerScan tool. AI Gate is a **preview** surface for this release: deterministic real-stack PR smoke is implemented, while the planned policy/exception and deterministic-judge seams are not yet release-gated. DAST remains the manual full-release E2E area.

AI Gate evaluates probes with deterministic/regex detectors first. When an AI provider is configured in AI settings, it also runs semantic AI judging on probe transcripts, populates `ai_verdict`, `ai_confidence`, `ai_rationale`, and `ai_recommendations`, and can downgrade high-confidence false positives before the AI Gate score and deploy decision are computed.

AI Gate also builds an AI control-evidence pack from target `metadata_json`: asset owner, risk tier, data classification, RAG ACL/ingestion/tenant-isolation controls, agent tool scopes, delegated identity, token audience validation, approval/dry-run/transaction limits, sandboxing, audit logs, anomaly detection, kill switch, and governance mappings. Set `enforce_ai_control_baseline: true` to convert missing required controls into a finding.

Use the shared scenario catalog for focused AI demo/prod-like workflows:

```bash
curl http://localhost:8080/ai/test-scenarios
```

The `secure-rag-agent` scenario includes the canonical Honey demo endpoints (`/api/secure-demo/rag-agent/*`, `/api/secure-demo/governance/mapping`, `/api/ai-gate/scenarios`, `/api/v1/rag/answer`, `/api/v1/agent/trace`, and `/api/v1/mcp/trace`) plus target templates with control metadata for threat model, retrieval ACLs, tool authorization, logging, cloud security design, and governance mapping.

Target types:
| Type | Description |
|------|-------------|
| `api_chat` | Chat/completions-style JSON endpoint |
| `rag` | RAG answer endpoint |
| `agent_trace` | Agent/trace endpoint or trace replay API |
| `mcp_trace` | MCP HTTP/SSE endpoint or MCP trace-compatible API |
| `widget` | Browser widget target (API-supported; UI support may be limited) |

Probe packs:
| Pack | Focus |
|------|-------|
| `shaker-ai-smoke` | Small broad smoke test |
| `shaker-owasp-llm` | OWASP LLM risks |
| `shaker-agent-abuse` | Tool abuse, approval bypass, agent boundaries |
| `shaker-mcp-security` | MCP tool/resource/scope issues |
| `shaker-rag-lite` | RAG leakage and retrieval-boundary issues |

Scan profiles: `smoke`, `trace`, `standard`, `deep`. Environments: `preview`, `staging`, `development`, `production`.

```bash
# List AI Gate targets
curl http://localhost:8080/ai/targets

# Create a chat API target. The request template must contain {{prompt}}.
curl -X POST http://localhost:8080/ai/targets \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Support bot",
    "target_type": "api_chat",
    "endpoint_url": "https://example.com/api/chat",
    "method": "POST",
    "headers_template": {"Content-Type": "application/json"},
    "request_template": {"message": "{{prompt}}", "session_id": "{{session_id}}"},
    "response_path": "$.answer",
    "streaming_mode": "json",
    "rate_limit_rps": 2,
    "request_budget": 10,
    "production_mode": false,
    "metadata_json": {
      "asset_owner": "security",
      "risk_tier": "high",
      "data_classification": "restricted",
      "retrieval_acl_matrix": "tenant-user-doc",
      "tool_inventory": ["search_docs"],
      "enforce_ai_control_baseline": true
    },
    "credential": {"auth_kind": "bearer", "secret": "token-if-needed"}
  }'

# Queue an AI Gate scan
curl -X POST http://localhost:8080/ai/targets/{target_id}/scan \
  -H "Content-Type: application/json" \
  -d '{
    "probe_pack": "shaker-agent-abuse",
    "scan_profile": "standard",
    "environment": "staging"
  }'

# Production targets require explicit confirmation
curl -X POST http://localhost:8080/ai/targets/{target_id}/scan \
  -H "Content-Type: application/json" \
  -d '{"probe_pack":"shaker-ai-smoke","scan_profile":"smoke","environment":"production","confirm_production":true}'

# Get transcripts for a completed AI Gate scan
curl http://localhost:8080/ai/scans/{scan_id}/transcript

# Filter findings by product type
curl "http://localhost:8080/findings?source_type=ai&status=active"
curl "http://localhost:8080/findings?source_type=dast&status=active"
curl "http://localhost:8080/findings?source_type=deep_hunt&status=active"
```

After submitting an AI Gate scan, report the scan ID and UI link (`/scans/{scan_id}`), then stop. Do not poll; AI Gate scans can still take time depending on profile, target latency, and budget.

### Model Intake

Model Intake checks model artifacts before deployment without importing or executing model code. It is available in the UI at `/model-intake` and through REST APIs. Like AI Gate, Model Intake is a **preview** surface for this release. It is for provenance, unsafe serialization, checksum/signature, model card, license review, SBOM/dependency evidence, malware scan evidence, security evals, deployment restrictions, monitoring plan, and deployment approval checks.

Model Intake findings use `tool/source=model_intake`, filter with `source_type=model_intake`, and are
excluded from `source_type=dast`.

The `/ai/test-scenarios` catalog also includes `model-intake-pipeline` presets and the canonical Honey model-intake routes: scenario registry, index, artifact/manifest/signature/card reads, submit, status, scan, approve, and deploy.

```bash
# Queue a model intake scan
curl -X POST http://localhost:8080/model-intake/scan \
  -H "Content-Type: application/json" \
  -d '{
    "artifact_url": "https://example.com/models/model.safetensors",
    "metadata_url": "https://example.com/models/model.metadata.json",
    "expected_sha256": "optional-known-good-sha256",
    "signature_url": "https://example.com/models/model.sig",
    "signature_public_key_url": "https://example.com/models/signing-key.pem",
    "signature_trusted_key_sha256": ["optional-trusted-key-fingerprint"],
    "policy_profile": "production",
    "model_card_url": "https://example.com/models/model-card.md",
    "deployment_approved": true,
    "metadata_json": {
      "license": "apache-2.0",
      "sbom": {"components": []},
      "malware_scan_result": {"status": "clean"},
      "security_evals": {"status": "passed"},
      "deployment_restrictions": ["staging", "production"],
      "monitoring_plan": "model-monitoring-v1"
    }
  }'
```

After submitting a Model Intake scan, report the scan ID and UI link (`/scans/{scan_id}`), then stop. Do not poll unless the user explicitly asks.

### Schedules (Recurring Scans)

```bash
# List schedules
curl http://localhost:8080/schedules

# Create daily schedule
curl -X POST http://localhost:8080/schedules \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": "target-uuid",
    "schedule_kind": "normal_scan",
    "frequency": "daily",
    "time_of_day": "02:00",
    "scan_type": "standard"
  }'

# Create a recurring Continuous ASM coverage wave
curl -X POST http://localhost:8080/schedules \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": "target-uuid",
    "schedule_kind": "asm_improve",
    "frequency": "daily",
    "time_of_day": "02:00"
  }'

# Update/toggle schedule
curl -X PATCH http://localhost:8080/schedules/{schedule_id} \
  -H "Content-Type: application/json" \
  -d '{"is_active": false}'

# Delete schedule
curl -X DELETE http://localhost:8080/schedules/{schedule_id}
```

Evidence retention cannot be scheduled. Legacy retention schedules are fail-closed and disabled by
the scheduler; migrate them to a normal scan or ASM schedule, or delete them. Interactive deletion at
`POST /evidence/retention/sweep` starts with a target-scoped dry run that durably binds an immutable
candidate snapshot, criteria, storage effects, policy hash, and expiry to a `preview_id`. Preview TTL
defaults to 600 seconds and `EVIDENCE_RETENTION_PREVIEW_TTL_SECONDS` is clamped to 60-3600 seconds.

Deletion confirmation creates a one-use `dangerous` approval scoped to the preview target, with
`action_name: "evidence.retention_sweep"` and exact `action_context` keys `preview_id`,
`preview_hash`, and `target_id`. The approval must be created for that preview and expire no later
than it. The execution request must contain only `dry_run:false`, `preview_id`, and
`approval_receipt_id`; resubmitting target or retention criteria is rejected.

Before blob deletion, the server locks and revalidates the exact previewed objects, commits durable
`executing` intent, and marks the candidate rows as pending for that preview. A retry with the same
preview/approval resumes unfinished finalization safely; already-missing content-addressed blobs are
treated as completed work. Once consumed, the same retry returns the stored result idempotently
without repeating deletion. Expired, changed, mismatched, or reused preview/approval pairs fail
closed. A committed `executing` intent remains authoritative if finding state changes later, and
canonical target merges are blocked until that intent is finalized.

### Certificate Transparency Monitoring (Gungnir)

Monitor CT logs in real-time to discover new certificates issued for your domains:

```bash
# Start Gungnir CT monitoring
./scanner.sh gungnir start

# Check Gungnir status
curl http://localhost:8080/gungnir/status

# Start/stop via API (alternative to CLI)
curl -X POST http://localhost:8080/gungnir/start
curl -X POST http://localhost:8080/gungnir/stop
```

Gungnir watches Certificate Transparency logs and automatically discovers new subdomains when certificates are issued. Useful for:
- Detecting shadow IT and unauthorized services
- Finding new attack surface as it appears
- Monitoring for certificate mis-issuance

### Authenticated Scanning

Run scans with authentication to test protected endpoints:

```bash
# Bearer token auth (JWT, API keys)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.example.com",
    "options": {
      "scan_type": "smart",
      "auth_header": "Bearer eyJhbGciOiJIUzI1NiIs..."
    }
  }'

# Cookie-based auth (session cookies)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "options": {
      "scan_type": "smart",
      "auth_cookies": "session_id=abc123; csrf_token=xyz789"
    }
  }'

# Form-based login (scanner auto-authenticates)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "options": {
      "scan_type": "smart",
      "login_username": "testuser@example.com",
      "login_password": "password123"
    }
  }'

# Custom headers (API keys, etc.)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.example.com",
    "options": {
      "scan_type": "smart",
      "auth_headers_json": "{\"X-API-Key\": \"your-api-key\", \"X-Custom\": \"value\"}"
    }
  }'

# Focused SQLi-only scan with auth
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.example.com",
    "options": {
      "scan_type": "smart",
      "sqli": true,
      "auth_header": "Bearer eyJhbGciOiJIUzI1NiIs..."
    }
  }'

# Focused XSS-only scan with session cookies
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "options": {
      "scan_type": "smart",
      "xss": true,
      "auth_cookies": "session_id=abc123; csrf_token=xyz789"
    }
  }'

# Multi-user auth for BOLA/IDOR testing
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.example.com",
    "options": {
      "scan_type": "smart",
      "auth_header": "Bearer user1_token",
      "user2_header": "Bearer user2_token"
    }
  }'
```

**Authentication Options:**
| Option | Description |
|--------|-------------|
| `auth_header` | Authorization header value (e.g., "Bearer token" or "Basic base64") |
| `auth_cookies` | Session cookies (e.g., "session=abc; token=xyz") |
| `auth_headers_json` | Custom headers as JSON object |
| `login_username` | Username for form-based login |
| `login_password` | Password for form-based login |
| `login_url` | Login page URL (auto-detected if not provided) |
| `login_extra_fields` | Extra form fields as JSON (e.g., '{"remember": "true"}') |
| `auth_scenario_json` | Auth scenario JSON DSL for custom login flow/success checks/TOTP |
| `user2_cookies` | Second user cookies for BOLA/IDOR comparison testing |
| `user2_header` | Second user auth header for BOLA/IDOR comparison testing |

Auth is propagated to Playwright crawl, Nuclei, Dalfox, SQLmap, and custom checks. Long scans will attempt re-authentication when a session expires.

**Active Check Filters (API options):**
| Option | Description |
|--------|-------------|
| `xss` | Run only XSS active checks |
| `sqli` | Run only SQLi active checks |

**Reporting Options (API options):**
| Option | Description |
|--------|-------------|
| `include_partial_attack_chains` | Include partial attack chains in the human-readable report (analyst mode). Full chains always appear in `result.attack_chains.chains`. |

### Attack Chain Analysis

Smart scans correlate findings into attack chains - multi-step vulnerability combinations:

**Chain Types:**
| Chain | Findings Required | Business Impact |
|-------|-------------------|-----------------|
| `xss_to_account_takeover` | XSS + weak cookie flags | Session theft, account compromise |
| `sqli_to_privilege_escalation` | SQLi + admin panel access | Database compromise, admin access |
| `ssrf_to_cloud_breach` | SSRF + cloud metadata access | Cloud IAM credential theft |
| `idor_to_data_breach` | BOLA + predictable IDs | Mass user data exfiltration |
| `lfi_to_credential_theft` | LFI + sensitive file access | Credential file exposure |
| `cors_to_data_theft` | CORS misconfig + sensitive endpoints | Cross-origin data theft |
| `weak_jwt_to_impersonation` | JWT weakness + user endpoints | User impersonation |
| `xxe_to_data_exfil` | XXE + file read / SSRF-via-XXE | Server file / credential exfiltration |
| `deserialization_to_rce` | Insecure deserialization sink + gadget | Remote code execution / server compromise |

**JSON Output Structure (`result.attack_chains`):**
```json
{
  "chains": [
    {
      "chain_type": "xss_to_account_takeover",
      "name": "XSS to Account Takeover",
      "severity": "critical",
      "confidence": 0.85,
      "completeness": 1.0,
      "steps": [
        {"step_number": 1, "finding_type": "xss", "description": "..."},
        {"step_number": 2, "finding_type": "insecure_cookie", "description": "..."}
      ],
      "remediation": ["Add HttpOnly flag...", "Implement CSP..."]
    }
  ],
  "partial_chains": [...],  // Chains missing some findings
  "summary": {
    "total_chains": 1,
    "total_partial_chains": 2,
    "critical_chains": 1,
    "partial_chains_included": false
  }
}
```

**Interpretation Guidance:**
- `completeness: 1.0` = all required findings present (complete chain)
- `completeness < 1.0` = partial chain, check `missing_required` field
- Partial chains have downgraded severity (critical→high, high→medium)
- Use `include_partial_attack_chains: true` for analyst reports

### Smart Coverage Metrics

The `result.smart_coverage` field tracks scan coverage:

```json
{
  "endpoints": {"discovered": 127, "tested": 89, "coverage": 0.70, "by_method": {"GET": 85, "POST": 35}},
  "parameters": {"discovered": 234, "tested": 156, "coverage": 0.67, "by_location": {"query": 120, "body": 95}},
  "nuclei_templates": {"run": 1847, "matched": 23, "hit_rate": 0.012},
  "discovery_sources": ["har_network_capture", "url_crawl", "js_bundle_analysis"],
  "auth_states_tested": ["anonymous"]
}
```

Low coverage may indicate rate limiting or incomplete discovery.

**Coverage Interpretation:**
- `coverage < 0.5`: Possible rate limiting or WAF blocking
- `coverage 0.5-0.8`: Normal for large applications
- `coverage > 0.8`: Excellent coverage

**Workflow for authenticated scanning:**
1. Create account on target app (or use existing test account)
2. Login and capture the auth token/cookies
3. Pass credentials to scanner via API options
4. Scanner uses credentials for all authenticated requests

### Advanced Scan Options

Additional options for fine-tuning scan behavior:

```bash
# Enable JSON link following (discovers API endpoints from responses)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.example.com",
    "options": {
      "scan_type": "smart",
      "json_link_following": true
    }
  }'

# Enable HTTP OPTIONS method discovery
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.example.com",
    "options": {
      "scan_type": "smart",
      "options_method_discovery": true
    }
  }'

# Enable gRPC reflection discovery
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://grpc.example.com",
    "options": {
      "scan_type": "smart",
      "grpc_discovery": true
    }
  }'

# Specify custom endpoints to test
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.example.com",
    "options": {
      "scan_type": "smart",
      "custom_endpoints": [
        "GET /api/v1/users?id=1&name=test",
        "POST /api/v1/login json:{\"username\":\"test\",\"password\":\"test\"}",
        "POST /api/v1/search form:query=test&limit=10",
        "/graphql"
      ]
    }
  }'
```

**Custom Endpoint Format:**
Each endpoint string follows the format: `[METHOD] /path [params]`
- **METHOD** (optional): GET, POST, PUT, PATCH, DELETE (default: GET)
- **params** (optional but recommended): Parameters to test for injection
  - Query params: `?key=value` or `query:key=value`
  - JSON body: `json:{"key":"value"}`
  - Form body: `form:key=value&key2=value2`
  - Simple params: `param1 param2 param3`

**Important**: Endpoints without parameters will only be crawled, not tested for SQLi/XSS. Always include parameters you want tested.

**Advanced Options:**
| Option | Description |
|--------|-------------|
| `json_link_following` | Follow links in JSON API responses (HATEOAS, pagination) |
| `options_method_discovery` | Use HTTP OPTIONS to discover allowed methods |
| `grpc_discovery` | Use gRPC reflection to discover services |
| `custom_endpoints` | Array of endpoints with params to test (see format above) |
| `focus_rules_json` | JSON array of rules to include only specific endpoint scope |
| `avoid_rules_json` | JSON array of rules to exclude endpoint scope |
| `verified_findings_only` | Keep only findings that have exploit verification evidence |
| `budget_profile` | Coverage budget profile: `fast`, `balanced`, `thorough`, or `exhaustive` |
| `custom_budget` | Advanced budget overrides such as `max_urls`, `browser_max_pages`, `api_probe_limit`, `nuclei_max_targets`, `active_max_seconds`, `active_max_endpoints`, and `active_params_per_endpoint` |
| `no_early_stop` | Disable early stopping in smart scan (continue even after finding many vulns) |
| `thorough_params` | Legacy shortcut for deeper smart active checks; when no budget is specified it promotes the scan to the `thorough` budget |
| `include_partial_attack_chains` | Include incomplete attack chains in human-readable report (analyst mode) |
| `deep_domxss` | Enable deep DOM XSS analysis (more thorough but slower) |
| `oob_callback_url` | Out-of-band callback URL for blind SQLi/SSRF detection |

**Performance/Safety Limits:**
| Option | Description | Default |
|--------|-------------|---------|
| `smart_bola_max_endpoints` | Max endpoints for BOLA testing | 80 |
| `dom_xss_max_files` | Max JS files for DOM XSS analysis | 20 |
| `sqli_extract_max` | Max SQLi findings for data extraction | 3 |
| `oob_max_findings` | Max findings for OOB SQLi test | 3 |

Defaults are sourced from `scanner/constants.py` via `SMART_SCAN_BUDGETS` and `SCAN_BUDGET_DEFAULTS`.

### Smart Scan Tuning

For thorough penetration testing, you can disable early stopping and increase parameter coverage:

```bash
# Thorough smart scan (disable early stopping, test more params)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "options": {
      "scan_type": "smart",
      "no_early_stop": true,
      "thorough_params": true
    }
  }'
```

Preferred depth control is `budget_profile`; scan type controls which modules run and budget controls how much depth/time they receive:

```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "options": {
      "scan_type": "smart",
      "budget_profile": "thorough",
      "custom_budget": {
        "max_urls": 2500,
        "browser_max_pages": 100,
        "active_max_endpoints": 150,
        "active_params_per_endpoint": 12
      }
    }
  }'
```

By default, smart scan:
- **Stops early** when 3+ critical or 5+ high severity findings are found
- **Uses the `balanced` budget** unless `budget_profile` or `custom_budget` is provided

With `no_early_stop` and `thorough_params`:
- **Continues scanning** after high-severity findings instead of stopping at the normal threshold;
  this increases coverage but does not guarantee that every vulnerability will be found
- **Promotes to the `thorough` budget** when no explicit budget is provided, increasing discovery, browser, nuclei, and active-test coverage

## Scan Types Explained

Scan type controls **what** ShakerScan tests. `budget_profile` controls **how hard** it tests. Keep the scan type stable when you want the same modules, then adjust budget between `fast`, `balanced`, `thorough`, and `exhaustive`.

| Type | API Option | Time | What It Does |
|------|------------|------|--------------|
| **quick** | `"scan_type": "quick"` | 1-2 min | DNS, TLS cert, HTTP headers, basic tech detection |
| **standard** | `"scan_type": "standard"` | 5-10 min | + Nuclei (safe), cookies, CORS, JS dependencies (no port scan by default) |
| **deep** | `"scan_type": "deep"` | 30-60 min | + Full Nuclei, top-ports scan (1000), JS secrets |
| **full** | `"scan_type": "full"` | 1-2 hrs | + Broad active XSS/SQLi and WebSocket testing |
| **aggressive** | `"scan_type": "aggressive"` | 2+ hrs | + Aggressive exploits, extended ports, threat intel |
| **smart** | `"scan_type": "smart"` | Variable | Adaptive: staged templates, DBMS-aware SQLi, context-aware XSS |

### Scan Type Details

**quick** - Fast passive recon:
- DNS records (A, AAAA, MX, SPF, DMARC, DNSSEC)
- TLS certificate analysis
- HTTP security headers
- Basic technology fingerprinting

**standard** - Balanced assessment:
- Everything in quick
- Nuclei vulnerability scan (safe templates)
- Cookie security analysis
- CORS misconfiguration checks
- JS dependency vulnerability scanning
- No port scan by default (enable gRPC discovery or use deep/full/aggressive)

**deep** - Thorough passive scan:
- Everything in standard
- Full Nuclei template scan
- Port scanning (top 1000 ports)
- Deep directory/file discovery (opt-in via `--deep-discovery`, enabled in aggressive)
- JS secret scanning
- Enhanced DNS checks

**full** - Complete active assessment:
- Everything in deep
- Active XSS testing (dalfox)
- Active SQLi testing (sqlmap)
- WebSocket security testing
- Auth/session vulnerability tests
- File upload, open redirect, CSRF tests
- API security testing
- Advanced probes (SSRF/command injection) only run with non-safe exploit level and parameterized endpoints

**aggressive** - Maximum coverage:
- Everything in full
- Aggressive exploit level
- Full port scan (65535 ports)
- Threat intelligence checks
- Extended fuzzing and discovery

**smart** - Adaptive intelligent scan:
- Staged Nuclei template scanning (4 waves based on tech + signals)
  - Wave 1: Critical CVEs + tech-specific (~60s budget)
  - Wave 2: Signal-based expansion (~120s budget)
  - Wave 3: Injection-focused (~300s budget, conditional)
  - Wave 4: Deep scan (~480s budget, conditional)
  - Yield-based budget adjustment (high-yield waves extend next budget)
- Early stopping when confidence-weighted score >= 12 (3+ critical or 5+ high findings)
- Verification phase for high-severity findings (browser proofs, timing analysis)
- DBMS fingerprinting (SQLite, MySQL, PostgreSQL, MSSQL, Oracle)
- DBMS-specific SQLi payloads with data extraction chaining
- Context-aware XSS (detects reflection context: in_script, in_attribute, etc.)
- DOM XSS static analysis (source-to-sink flow detection)
- Recursive directory discovery (adapts depth based on findings)
- Light port scan (top 33) for service hints and gRPC discovery
- Post-nuclei discovery refinement based on signals
- Authenticated Playwright crawl (multi-page) with API capture
- Adaptive rate limiting (backs off on 429/503, speeds up on success)
- JS bundle analysis for hidden endpoints
- Auth-aware tool routing (Nuclei/Dalfox use discovered endpoints + auth headers)
- Synthetic endpoints only generated when API hints exist (or `--thorough-params`)
- Attack chain analysis (correlates findings into exploitable attack paths)
- Coverage tracking (endpoint/parameter/template metrics)

## Response Interpretation

Scans return:
- **score**: 0-100 (higher is better)
- **grade**: A, B, C, D, F
- **findings**: Array of vulnerabilities
- **result**: Rich object with detailed scan data (see below)

Finding severities: `critical`, `high`, `medium`, `low`, `info`

### Rich Scan Data (in `result` object)

The `/scans/{id}` endpoint returns detailed data you should report:

| Path | Description |
|------|-------------|
| `result.http.csp_evaluation` | CSP grade, score, issues, parsed directives |
| `result.http.security_headers` | HSTS, X-Frame-Options, Referrer-Policy, COOP, CORP |
| `result.tls.certificate` | Subject, issuer, days_remaining, key_size, key_algo |
| `result.tls.ocsp.stapled` | OCSP stapling status |
| `result.dns` | A, AAAA, MX, SPF, DMARC, DNSSEC, CAA records |
| `result.discovery.tech.items` | Technologies with version and confidence |
| `result.discovery.browser_api_endpoints` | Discovered API endpoints |
| `result.discovery.browser_crawl` | Headless crawl stats + sampled page URLs |
| `result.discovery.waf_detection` | WAF product detection |
| `result.attack_chains` | Attack chain analysis (complete chains + optional partial chains when enabled) |

When AI is enabled, the report also includes `ai_correlations` (cross-finding correlations and an overall risk assessment) plus `ai_logs.summary.cross_finding_correlations`.

### Example Rich Report Output

```
✓ Scan completed

┌─────────────────────────────────────┐
│  Grade: C    Score: 72/100          │
└─────────────────────────────────────┘

📋 SUMMARY
├─ TLS: Let's Encrypt R3, 45 days, RSA 4096-bit
├─ CSP: Grade D (64/100) - 3 issues
├─ Headers: HSTS ✓  XFO ✓  Referrer ✓
└─ Tech: React 18 (confirmed), Django (likely)

⚠️  CSP Issues:
  • script-src allows 'unsafe-inline'
  • script-src allows 'unsafe-eval'

🔍 Findings: 0 Critical, 0 High, 3 Medium, 4 Low

📊 Full report: http://localhost:3000/scans/{id}
```

## Example Interactions

**User**: "Scan my site example.com"
1. Check if scanner running
2. Submit quick scan
3. Report scan ID and UI link - done (don't poll/wait)

**User**: "Show me critical vulnerabilities"
1. GET /findings?severity=critical&status=active
2. Format results nicely

**User**: "Do a full security audit of example.com"
1. **Ask permission** for active testing first
2. If approved, submit with `"scan_type": "full"`
3. Report scan ID and UI link - done (don't poll/wait)

**User**: "Find subdomains for example.com"
1. POST /discovery?root_domain=example.com
2. Report that discovery was started - done (don't wait)

**User**: "Scale up workers to handle more scans"
1. GET /workers to check current count
2. POST /workers with increased count
3. Confirm new worker count

**User**: "Test for BOLA vulnerabilities on api.example.com"
1. **Ask permission** for active testing first
2. Ask user for two different user auth tokens
3. Submit smart scan with `auth_header` and `user2_header`
4. Report scan ID and UI link - done (don't poll/wait)

**User**: "Let's do interactive security testing"
1. Use the AI Security Session feature (see below)
2. Start a session, analyze the target, and test collaboratively

## AI Security Sessions

Interactive security testing sessions enable collaborative manual penetration testing. Unlike automated scans, this is a real-time workflow where:

1. AI bootstraps from existing scan data (endpoints, tech, findings)
2. AI analyzes the target and suggests testing approaches
3. User directs which areas to focus on
4. AI executes tests and reports findings immediately
5. Validated findings are saved to the database

**Recommended Workflow**: When the user has authorized active testing and a Smart scan would add
useful context, run it first; otherwise bootstrap from an existing scan or use the interactive
session directly. After submitting any scan, report its ID and UI link and stop.

### Bootstrapping from Scan Data

Before exploring manually, check for existing scan data:

```bash
# Find existing scans
curl -s "http://localhost:8080/scans?limit=5" | jq '[.scans[] | select(.target_url | contains("example.com"))]'

# Get scan results with discovered endpoints
curl -s "http://localhost:8080/scans/{scan_id}/result" | jq '{
  endpoints: .discovery.browser_api_endpoints[:10],
  tech: .discovery.tech.items
}'

# Get existing findings to validate
curl -s "http://localhost:8080/findings?root_domain=example.com&status=active"
```

### Session API

```bash
# Start a session
curl -X POST http://localhost:8080/session/start \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'

# Get session state
curl http://localhost:8080/session/{session_id}

# Take a screenshot
curl -X POST "http://localhost:8080/session/{session_id}/screenshot"

# Get raw screenshot PNG
curl -s "http://localhost:8080/session/{session_id}/screenshot.png" -o screenshot.png

# Execute browser action
curl -X POST "http://localhost:8080/session/{session_id}/action" \
  -H "Content-Type: application/json" \
  -d '{"action": "navigate", "data": {"url": "/login"}}'

# Login as a user
curl -X POST "http://localhost:8080/session/{session_id}/action" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "login",
    "user": "user1",
    "data": {"email": "user1@test.com", "password": "pass123"}
  }'

# Test endpoint for BOLA (cross-user access)
curl -X POST "http://localhost:8080/session/{session_id}/test-endpoint" \
  -H "Content-Type: application/json" \
  -d '{
    "endpoint": "/api/items/42",
    "method": "GET",
    "as_user": "user2"
  }'

# Save a finding discovered during the session
curl -X POST "http://localhost:8080/session/{session_id}/findings" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "BOLA on Basket API",
    "severity": "critical",
    "description": "User2 can access User1 basket",
    "category": "BOLA",
    "cwe": "CWE-639",
    "evidence": "GET /rest/basket/9 with User2 token returns User1 data"
  }'

# End session
curl -X DELETE "http://localhost:8080/session/{session_id}"

# List active sessions
curl http://localhost:8080/sessions
```

### Session Actions

| Action | Description | Data Fields |
|--------|-------------|-------------|
| `navigate` | Go to URL | `url`, `allow_out_of_scope` (optional) |
| `click` | Click element | `selector` |
| `fill` | Fill input field | `selector`, `value` |
| `register` | Register new account | `email`, `password` |
| `login` | Login to app | `email`, `password` |
| `submit` | Submit form | `selector` (optional) |
| `wait` | Wait for element/time | `selector`, `timeout` |
| `extract` | Extract data from page | `selector`, `attribute` |

Same-origin is enforced by default for navigation and endpoint tests (SSRF protection). Only use `allow_out_of_scope: true` when user explicitly requests cross-origin testing.

### BOLA Testing Workflow

1. Start session for target
2. Register/login as user1
3. Navigate and discover resource IDs
4. Register/login as user2 (separate browser context)
5. Test endpoints with `as_user: "user2"` to check cross-user access
6. **Save findings** with `POST /session/{id}/findings`
7. Report findings with evidence

### Interactive Session Testing Scenarios

| Category | Scenarios | Best For |
|----------|-----------|----------|
| **Access Control** | BOLA/IDOR, privilege escalation, tenant isolation, function-level access | Multi-user apps, APIs with resource ownership |
| **Authentication** | Session fixation, JWT flaws, concurrent sessions, token invalidation | Apps with login functionality |
| **Business Logic** | Price manipulation, coupon abuse, workflow bypass, race conditions | E-commerce, financial apps |
| **API Security** | Mass assignment, GraphQL abuse, parameter pollution, rate limiting | REST/GraphQL APIs |
| **Client-Side** | Stored/DOM XSS, open redirect, clickjacking, sensitive data exposure | Apps with user-generated content |

**When to Use Interactive Sessions:**
- Validating findings from automated scans
- Testing vulnerabilities requiring human judgment
- Verifying BOLA with real user contexts
- Chaining findings into attack paths
- Demonstrating vulnerabilities to stakeholders

**Saving Findings:** All discoveries can be persisted with `POST /session/{id}/findings` and will appear in the UI with `source: "ai_session"`.

## CLI Shortcuts

Users can also use the CLI directly:
```bash
# Basic scans
./scanner.sh scan https://example.com       # Quick scan
./scanner.sh scan-full https://example.com --confirm-active  # Full assessment
./scanner.sh scan-smart https://example.com --confirm-active # Smart adaptive scan

# Management
./scanner.sh status                          # Check status
./scanner.sh scale 5                         # Scale to 5 workers
./scanner.sh logs -f                         # Follow logs
./scanner.sh rebuild                         # Full rebuild (code changes)
./scanner.sh restart                         # Restart services
./scanner.sh gungnir status                  # CT monitor status
```

For authenticated scans, focused XSS/SQLi-only checks, budget profiles/custom budgets, and advanced smart tuning (`budget_profile`, `custom_budget`, `no_early_stop`, `thorough_params`, `custom_endpoints`, etc.), use the REST API `POST /scans` options.

## Files Structure

```
shakerscan/
├── scanner.sh           # CLI tool (start, stop, scan, scale, etc.)
├── docker-compose.yml   # Docker stack orchestration
├── CLAUDE.md            # Claude Code instructions
├── AGENTS.md            # This file (cross-tool AI agent instructions)
├── scanner/             # Core scanner engine
│   ├── scanner.py       # Main orchestrator
│   ├── scanner_tools/   # 83 specialized security modules
│   │   ├── nuclei.py    # Nuclei vulnerability scanning
│   │   ├── active_checks.py  # XSS/SQLi testing
│   │   ├── discovery.py # Endpoint discovery
│   │   └── ...          # DNS, TLS, ports, auth, etc.
│   ├── payloads/        # Attack payloads (SQLi, XSS)
│   └── wordlists/       # Directory discovery wordlists
├── api/                 # FastAPI backend
│   ├── api.py           # REST API server
│   ├── worker.py        # Redis job worker
│   ├── gungnir_worker.py # CT log monitor worker
│   └── session_manager.py # Interactive session management
├── ui/                  # Next.js dashboard
│   └── src/             # React components + pages
├── db/                  # PostgreSQL
│   └── init.sql         # Schema definition
└── results/             # Scan results (JSON)
```

## Troubleshooting

### Scanner Won't Start

```bash
# Check Docker is running
docker info

# Check for port conflicts
lsof -i :8080
lsof -i :3000

# View startup logs
./scanner.sh logs

# Full rebuild if needed
./scanner.sh rebuild
```

### Database Connection Errors

```bash
# Check PostgreSQL is healthy
docker compose ps postgres

# View database logs
docker compose logs postgres

# Reset database (WARNING: deletes all data)
./scanner.sh reset
```

### Scans Stuck in Pending

```bash
# Check worker status
curl http://localhost:8080/workers

# Check queue stats
curl http://localhost:8080/queue/stats

# Scale up workers if queue is backed up
curl -X POST http://localhost:8080/workers \
  -H "Content-Type: application/json" \
  -d '{"count": 5}'

# View worker logs
docker compose logs worker -f
```

### Out of Memory

Workers use 2-4GB RAM each. If running multiple workers:

```bash
# Scale down workers
curl -X POST http://localhost:8080/workers \
  -H "Content-Type: application/json" \
  -d '{"count": 2}'

# Or restart with fewer workers
./scanner.sh restart -w 2
```

### API Not Responding

```bash
# Check API health
curl http://localhost:8080/health

# Restart API service
docker compose restart api

# View API logs
docker compose logs api -f
```
