# CLAUDE.md - ShakerScan

This is an open-source Dynamic Application Security Testing (DAST) scanner. Users interact with it via Claude Code to scan websites for vulnerabilities.

## Quick Setup

If the scanner isn't running, start it:
```bash
./scanner.sh start     # Start stack
./scanner.sh status    # Check status
```

For a remote VPS that should be opened from another machine over Tailscale:
```bash
./scanner.sh start --remote
./scanner.sh status
```

Remote mode binds the UI/API to the VPS Tailscale IPv4 address and prints remote URLs. Local laptop mode intentionally binds to `127.0.0.1`. If Tailscale is unavailable, use `SHAKERSCAN_BIND_HOST=0.0.0.0 SHAKERSCAN_PUBLIC_HOST=<server-ip-or-dns> ./scanner.sh start --remote`, but only behind a firewall, VPN, or reverse proxy.

If the user installed with `curl -fsSL https://install.shakerscan.com | sh` and is still in `/root` or another unrelated directory, ask them to start Claude inside the ShakerScan runtime:
```bash
shakerscan agent claude
```

Equivalent manual form:
```bash
cd ~/.shakerscan
claude
```

Using the global `shakerscan` command from any directory is fine for CLI operations, but AI agents should run from `~/.shakerscan` or a source checkout so they can read `AGENTS.md`, `CLAUDE.md`, `skills/`, and `.claude/`.

If `shakerscan` is not found in the current shell immediately after install, use the absolute launcher or ask the user to open a new shell:
```bash
~/.local/bin/shakerscan env
~/.local/bin/shakerscan agent claude
```

## How This Works

The scanner runs as Docker containers:
- **API** at `http://localhost:8080` - REST API for all operations
- **UI** at `http://localhost:3000` - Web dashboard
- **Workers** - Process scan jobs in parallel
- **PostgreSQL** - Stores scans, findings, targets
- **Redis** - Job queue

## Your Role

When users ask about security scanning:

**Important**: After submitting a scan, report the scan ID and UI link, then stop. Do NOT poll or wait for completion - scans can take minutes to hours. Users can check results via UI or ask later.

For commands you run on the same machine as ShakerScan, use `http://localhost:8080` for the API. For browser-facing links on a remote VPS, use the UI URL printed by `./scanner.sh status` or `./scanner.sh start --remote` instead of hardcoding `localhost:3000`.

1. **Check if scanner is running**: `curl -s http://localhost:8080/health 2>/dev/null || echo "not running"`
2. **Offer to start it** if not running: `./scanner.sh start`
3. **Use the API** to perform operations (see below)

## API Reference

Base URL: `http://localhost:8080`. All POST/PATCH bodies are JSON (`Content-Type: application/json`).

### Submit a Scan

```bash
# Template - swap scan_type per the table below
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {"scan_type": "quick"}}'
```

Valid `scan_type` values: `quick`, `standard`, `deep`, `full`, `aggressive`, `smart`.

**Important**: Never run `full`, `aggressive`, or `smart` scans without asking user permission first. These scan types include active XSS/SQLi probes.

### Check Scan Status

```bash
curl http://localhost:8080/scans/{scan_id}                         # Get scan by ID
curl "http://localhost:8080/scans?limit=10"                        # List recent scans
curl "http://localhost:8080/scans?status=completed&root_domain=example.com&limit=50"
curl "http://localhost:8080/scans?include_shards=true&include_internal=true&limit=50"  # Debug implementation rows
curl http://localhost:8080/scans/{scan_id}/result                  # Full result JSON
curl "http://localhost:8080/scans/{scan_id}/logs?limit=200"        # Logs (default 200, max 1000)
curl -X POST http://localhost:8080/scans/{scan_id}/cancel          # Cancel running/pending scan
```

### Findings

```bash
# List / filter (combine params freely)
curl "http://localhost:8080/findings?status=active"
curl "http://localhost:8080/findings?severity=critical"
curl "http://localhost:8080/findings?seen_within_days=30"
curl "http://localhost:8080/findings?severity=high&status=active&sort_by=cvss&sort_order=desc&limit=50"

# Update finding status (with optional notes)
curl -X PATCH http://localhost:8080/findings/{id} \
  -d '{"status": "resolved", "notes": "Fixed in v2.1 deploy"}'

# Delete a finding
curl -X DELETE http://localhost:8080/findings/{id}

# Bulk cleanup old findings (always dry-run first to see count)
curl -X POST http://localhost:8080/findings/cleanup \
  -d '{"older_than_days": 90, "dry_run": true}'
curl -X POST http://localhost:8080/findings/cleanup \
  -d '{"older_than_days": 90, "status": "resolved", "root_domain": "example.com", "dry_run": false}'

# Bulk update statuses
curl -X POST http://localhost:8080/findings/bulk \
  -d '{"finding_ids": ["id1", "id2"], "status": "false_positive", "notes": "Verified non-issue"}'

# Create manual finding (from manual testing)
curl -X POST http://localhost:8080/findings/manual \
  -d '{
    "target": "https://example.com",
    "title": "BOLA on User API",
    "severity": "critical",
    "description": "User2 can access User1 data via /api/users/{id}",
    "category": "BOLA",
    "cwe": "CWE-639",
    "evidence": "GET /api/users/1 with User2 token returns User1 profile"
  }'

# Create finding from AI session (target auto-populated)
curl -X POST "http://localhost:8080/session/{session_id}/findings" \
  -d '{"title": "BOLA on Basket API", "severity": "critical",
       "description": "User2 can read/delete User1 basket items",
       "category": "BOLA", "cwe": "CWE-639"}'
```

Status options: `active`, `resolved`, `false_positive`, `accepted_risk`.

Finding type filter: `source_type=dast` for non-AI findings, `source_type=ai` for AI Gate or AI-session findings. The UI exposes only these two product categories: **DAST** and **AI**.

**Findings Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| `status` | active, resolved, false_positive, accepted_risk |
| `severity` | critical, high, medium, low, info |
| `source_type` | `dast` or `ai` |
| `seen_within_days` | Only findings seen within N days |
| `root_domain` | Filter by root domain |
| `target_id` | Filter by target ID |
| `scan_id` | Filter by scan ID |
| `search` | Search by title or URL |
| `sort_by` | severity, first_seen, last_seen, cvss |
| `sort_order` | asc or desc (default: desc) |
| `limit` | Results per page (default: 100, max: 500) |
| `offset` | Pagination offset |

### Target Management

```bash
curl http://localhost:8080/targets                                # List targets (flat)
curl "http://localhost:8080/targets/grouped?sort_by=active_findings_count&sort_order=desc"
curl http://localhost:8080/domains                                # Root domains (for filters)
curl http://localhost:8080/targets/{target_id}                    # Details with recent scans

# Add target
curl -X POST http://localhost:8080/targets \
  -d '{"url": "https://example.com", "name": "Production"}'

# Update target
curl -X PATCH http://localhost:8080/targets/{target_id} \
  -d '{"name": "Staging", "scan_options": {"scan_type": "standard"}}'

# Soft delete
curl -X DELETE http://localhost:8080/targets/{target_id}

# Scan a specific target
curl -X POST http://localhost:8080/targets/{target_id}/scan \
  -d '{"options": {"scan_type": "quick"}}'
```

### Subdomain Discovery

```bash
curl -X POST "http://localhost:8080/discovery?root_domain=example.com"   # Start
curl http://localhost:8080/discovery                                     # List runs
curl http://localhost:8080/discovery/{discovery_id}                      # Details
```

### Dashboard & Status

```bash
curl http://localhost:8080/dashboard         # Dashboard metrics
curl http://localhost:8080/queue/stats       # Queue status
curl -X DELETE http://localhost:8080/queue/clear   # Emergency: clear pending jobs
```

### Worker Management

Control parallel-scan capacity. Worker limits: 1-20. Each worker uses ~1-2 CPU cores and 2-4GB RAM during scans.

```bash
curl http://localhost:8080/workers                                # Current count + status
curl -X POST http://localhost:8080/workers -d '{"count": 5}'      # Scale to 5
curl -X POST http://localhost:8080/workers -d '{"count": 10}'     # Scale to 10
```

### AI Gate

AI Gate tests AI application surfaces for prompt injection, sensitive disclosure, unsafe tool use, RAG leakage, and MCP/tool boundary failures. UI: `/settings/ai-gate`. Claude Code and other AI coding agents can use ShakerScan as a local AI-safety testing tool.

AI Gate evaluates probes with deterministic/regex detectors first. When an AI provider is configured in AI settings, it also runs semantic AI judging on probe transcripts, populates `ai_verdict`, `ai_confidence`, `ai_rationale`, and `ai_recommendations`, and can downgrade high-confidence false positives before the AI Gate score and deploy decision are computed.

AI Gate also builds an AI control-evidence pack from target `metadata_json`: asset owner, risk tier, data classification, RAG ACL/ingestion/tenant-isolation controls, agent tool scopes, delegated identity, token audience validation, approval/dry-run/transaction limits, sandboxing, audit logs, anomaly detection, kill switch, and governance mappings. Set `enforce_ai_control_baseline: true` to convert missing required controls into a finding.

Use the shared scenario catalog for focused AI demo/prod-like workflows: `curl http://localhost:8080/ai/test-scenarios`. The `secure-rag-agent` scenario includes the canonical Honey demo endpoints (`/api/secure-demo/rag-agent/*`, `/api/secure-demo/governance/mapping`, `/api/ai-gate/scenarios`, `/api/v1/rag/answer`, `/api/v1/agent/trace`, `/api/v1/mcp/trace`) plus target templates with control metadata for threat model, retrieval ACLs, tool authorization, logging, cloud security design, and governance mapping.

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
curl http://localhost:8080/ai/targets         # List AI Gate targets

# Create a chat API target. The request_template must contain {{prompt}}.
curl -X POST http://localhost:8080/ai/targets \
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
      "asset_owner": "security", "risk_tier": "high",
      "data_classification": "restricted",
      "retrieval_acl_matrix": "tenant-user-doc",
      "tool_inventory": ["search_docs"],
      "enforce_ai_control_baseline": true
    },
    "credential": {"auth_kind": "bearer", "secret": "token-if-needed"}
  }'

# Queue an AI Gate scan
curl -X POST http://localhost:8080/ai/targets/{target_id}/scan \
  -d '{"probe_pack": "shaker-agent-abuse", "scan_profile": "standard", "environment": "staging"}'

# Production targets require explicit confirmation
curl -X POST http://localhost:8080/ai/targets/{target_id}/scan \
  -d '{"probe_pack":"shaker-ai-smoke","scan_profile":"smoke","environment":"production","confirm_production":true}'

# Transcripts for a completed AI Gate scan
curl http://localhost:8080/ai/scans/{scan_id}/transcript

# Filter findings by product type
curl "http://localhost:8080/findings?source_type=ai&status=active"
curl "http://localhost:8080/findings?source_type=dast&status=active"
```

After submitting an AI Gate scan, report the scan ID and UI link (`/scans/{scan_id}`), then stop. Do not poll; AI Gate scans can still take time depending on profile, target latency, and budget.

### Model Intake

Model Intake checks model artifacts before deployment without importing or executing model code. UI: `/settings/model-intake`. Covers provenance, unsafe serialization, checksum/signature, model card, license review, SBOM/dependency evidence, malware scan evidence, security evals, deployment restrictions, monitoring plan, and deployment approval checks.

Model Intake findings are stored as non-AI findings with `tool=model_intake`; `source_type=dast` includes them until the product adds a separate model-intake source filter.

The `/ai/test-scenarios` catalog also includes `model-intake-pipeline` presets and the canonical Honey model-intake routes: scenario registry, index, artifact/manifest/signature/card reads, submit, status, scan, approve, and deploy.

```bash
curl -X POST http://localhost:8080/model-intake/scan \
  -d '{
    "artifact_url": "https://example.com/models/model.safetensors",
    "metadata_url": "https://example.com/models/model.metadata.json",
    "expected_sha256": "optional-known-good-sha256",
    "signature_url": "https://example.com/models/model.sig",
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
curl http://localhost:8080/schedules                              # List

# Daily schedule
curl -X POST http://localhost:8080/schedules \
  -d '{"target_id": "target-uuid", "frequency": "daily",
       "time_of_day": "02:00", "scan_type": "standard"}'

# Weekly schedule
curl -X POST http://localhost:8080/schedules \
  -d '{"target_id": "target-uuid", "frequency": "weekly",
       "day_of_week": 1, "time_of_day": "03:00", "scan_type": "deep"}'

# Update/toggle
curl -X PATCH http://localhost:8080/schedules/{schedule_id} \
  -d '{"is_active": false}'

# Delete
curl -X DELETE http://localhost:8080/schedules/{schedule_id}
```

Schedule fields: `target_id` (required), `frequency` (daily/weekly), `time_of_day` (HH:MM UTC), `day_of_week` (0-6, for weekly), `scan_type`, `name` (optional), `scan_options` (optional JSONB).

### Certificate Transparency Monitoring (Gungnir)

Monitor CT logs in real-time to discover new certificates issued for your domains. Useful for detecting shadow IT, finding new attack surface as it appears, and monitoring for certificate mis-issuance.

```bash
./scanner.sh gungnir start                                                # Start CT monitoring
curl http://localhost:8080/gungnir/status                                 # Status
curl "http://localhost:8080/gungnir/discoveries?domain=example.com"       # Discovered subdomains
```

### Authenticated Scanning

Auth is propagated to Playwright crawl, Nuclei, Dalfox, SQLmap, and custom checks. Long scans will attempt re-authentication when a session expires. Pass one or more of these auth fields in the scan `options`:

```bash
# Bearer token
curl -X POST http://localhost:8080/scans \
  -d '{"target": "https://api.example.com",
       "options": {"scan_type": "smart", "auth_header": "Bearer eyJ..."}}'

# Cookie-based
curl -X POST http://localhost:8080/scans \
  -d '{"target": "https://example.com",
       "options": {"scan_type": "smart", "auth_cookies": "session_id=abc; csrf_token=xyz"}}'

# Form-based login (scanner auto-authenticates)
curl -X POST http://localhost:8080/scans \
  -d '{"target": "https://example.com",
       "options": {"scan_type": "smart",
                   "login_username": "testuser@example.com",
                   "login_password": "password123"}}'

# Custom headers (API keys, etc.)
curl -X POST http://localhost:8080/scans \
  -d '{"target": "https://api.example.com",
       "options": {"scan_type": "smart",
                   "auth_headers_json": "{\"X-API-Key\": \"your-api-key\"}"}}'

# Multi-user auth for BOLA/IDOR testing
curl -X POST http://localhost:8080/scans \
  -d '{"target": "https://api.example.com",
       "options": {"scan_type": "smart",
                   "auth_header": "Bearer user1_token",
                   "user2_header": "Bearer user2_token"}}'

# Focused XSS-only or SQLi-only scan with auth
curl -X POST http://localhost:8080/scans \
  -d '{"target": "https://api.example.com",
       "options": {"scan_type": "smart", "sqli": true,
                   "auth_header": "Bearer eyJ..."}}'
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
| `user2_cookies` | Second user cookies for BOLA/IDOR comparison |
| `user2_header` | Second user auth header for BOLA/IDOR comparison |

**Active Check Filters:** `xss: true` runs only XSS active checks; `sqli: true` runs only SQLi.

**Workflow:** create test account → login + capture token/cookies → pass via API options → scanner uses creds for all authenticated requests.

### Advanced Scan Options

```bash
# Specify custom endpoints to test
curl -X POST http://localhost:8080/scans \
  -d '{"target": "https://api.example.com",
       "options": {"scan_type": "smart",
                   "custom_endpoints": [
                     "GET /api/v1/users?id=1&name=test",
                     "POST /api/v1/login json:{\"username\":\"test\",\"password\":\"test\"}",
                     "POST /api/v1/search form:query=test&limit=10",
                     "/graphql"
                   ]}}'
```

Discovery toggles available in `options`: `json_link_following`, `options_method_discovery`, `grpc_discovery` (all booleans).

**Custom Endpoint Format:** `[METHOD] /path [params]`
- **METHOD** (optional): GET, POST, PUT, PATCH, DELETE (default: GET)
- **params** (optional but recommended): trigger injection testing
  - Query: `?key=value` or `query:key=value`
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
| `custom_endpoints` | Array of endpoints with params (see format above) |
| `budget_profile` | Coverage budget: `fast`, `balanced`, `thorough`, `exhaustive` |
| `custom_budget` | Overrides such as `max_urls`, `browser_max_pages`, `api_probe_limit`, `nuclei_max_targets`, `active_max_seconds`, `active_max_endpoints`, `active_params_per_endpoint` |
| `no_early_stop` | Disable early stopping in smart scan |
| `thorough_params` | Legacy shortcut for deeper smart active checks; with no budget set, promotes to `thorough` |
| `include_partial_attack_chains` | Include incomplete attack chains in human-readable report (analyst mode) |
| `deep_domxss` | Enable deep DOM XSS analysis (slower) |
| `oob_callback_url` | Out-of-band callback URL for blind SQLi/SSRF |

**Performance/Safety Limits** (defaults from `scanner/constants.py` via `SMART_SCAN_BUDGETS` and `SCAN_BUDGET_DEFAULTS`):
| Option | Description | Default |
|--------|-------------|---------|
| `smart_bola_max_endpoints` | Max endpoints for BOLA testing | 80 |
| `dom_xss_max_files` | Max JS files for DOM XSS analysis | 20 |
| `sqli_extract_max` | Max SQLi findings for data extraction | 3 |
| `oob_max_findings` | Max findings for OOB SQLi test | 3 |

### Smart Scan Tuning

Preferred depth control is `budget_profile`; scan type controls which modules run, budget controls how much depth/time they receive:

```bash
# Thorough smart scan (legacy shortcut)
curl -X POST http://localhost:8080/scans \
  -d '{"target": "https://example.com",
       "options": {"scan_type": "smart", "no_early_stop": true, "thorough_params": true}}'

# Explicit budget profile with overrides
curl -X POST http://localhost:8080/scans \
  -d '{"target": "https://example.com",
       "options": {"scan_type": "smart", "budget_profile": "thorough",
                   "custom_budget": {"max_urls": 2500, "browser_max_pages": 100,
                                     "active_max_endpoints": 150,
                                     "active_params_per_endpoint": 12}}}'
```

By default, smart scan stops early when 3+ critical or 5+ high findings are found, and uses the `balanced` budget. With `no_early_stop` and `thorough_params`, it keeps scanning regardless of findings and promotes to `thorough` (unless an explicit budget is set).

### Parallel Scanning

Split one scan of a single target across the worker fleet. The parent scan fans out into shard sub-scans (run by any free workers), then a merge step aggregates the deduped findings into the parent report. Design + status: `docs/parallel-scan-architecture.md`.

```bash
# Family strategy (default for non-endpoint scans): one broad shard + deeper
# SQLi- and XSS-focused shards. More coverage/budget in ~the same wall-clock.
curl -X POST http://localhost:8080/scans \
  -d '{"target": "https://example.com",
       "options": {"scan_type": "smart", "parallel": true, "shard_strategy": "family"}}'

# Scope strategy: partition custom_endpoints across shards (genuine speed-up for APIs).
curl -X POST http://localhost:8080/scans \
  -d '{"target": "https://api.example.com",
       "options": {"scan_type": "smart", "parallel": true, "shards": 4,
                   "shard_strategy": "scope",
                   "custom_endpoints": ["GET /api/a?id=1", "GET /api/b?id=2", "..."]}}'

# Full Coverage: discover once, partition the harvested endpoint worklist, merge one parent report.
curl -X POST http://localhost:8080/scans \
  -d '{"target": "https://example.com",
       "options": {"scan_type": "smart", "parallel": true,
                   "shard_strategy": "coverage",
                   "budget_profile": "thorough"}}'
```

| Option | Description |
|--------|-------------|
| `parallel` | Fan this scan out into shards (default false) |
| `shards` | Shard count: integer or `"auto"` (scales to the worker fleet; family caps at 3: broad/sqli/xss) |
| `shard_strategy` | `auto` (default), `scope` (partition `custom_endpoints`), `family` (broad + deep sqli/xss), or `coverage` (discover once, then shard the harvested worklist) |

The parent appears as one row on the Scans page; shard rows are hidden by default. `GET /scans/{id}` returns `shard_rollup` + a per-shard list. `family` requires an active scan type (`smart`/`full`/`aggressive`); passive types degrade to a single normal scan. Continuous ASM batch/recon rows are also hidden from `/scans` by default; use `include_internal=true` only for debugging.

### Continuous ASM

Continuous ASM keeps a persistent endpoint inventory per target and improves coverage over time. Prefer `/asm/improve` for AI/agent workflows because it chooses recon vs. test batch vs. wait from the current gaps.

```bash
# Explain gaps and next action
curl http://localhost:8080/targets/{target_id}/asm/gaps

# Queue the recommended next action
curl -X POST http://localhost:8080/targets/{target_id}/asm/improve \
  -H "Content-Type: application/json" \
  -d '{}'

# Focus the next test batch on a supported family
curl -X POST http://localhost:8080/targets/{target_id}/asm/improve \
  -H "Content-Type: application/json" \
  -d '{"check_family": "sqli"}'

# High-risk BOLA/IDOR requires Lab/deep intent and two auth contexts on the target
curl -X POST http://localhost:8080/targets/{target_id}/asm/improve \
  -H "Content-Type: application/json" \
  -d '{"check_family": "bola", "exploit_depth": true}'

# Spend extra one-shot batch budget on API-like endpoints only
curl -X POST http://localhost:8080/targets/{target_id}/asm/improve \
  -H "Content-Type: application/json" \
  -d '{"endpoint_filter": "api", "batch_size": 100}'

# Show ASM activity instead of using the normal scans list
curl http://localhost:8080/targets/{target_id}/asm/activity
```

Supported `check_family` values today: `all`, `sqli`, `xss`, and gated `bola`. Omit it for the normal active mix. `endpoint_filter: "api"` narrows a batch to API-like endpoints without changing target-wide defaults. BOLA requires `exploit_depth: true`, primary auth, and second-user auth. After queueing an ASM action, report the scan ID and `/scans/{scan_id}` link, then stop unless the user asks you to poll.

### AI Operations Router

For natural-language requests, prefer the dry-run router before composing active calls manually:

```bash
curl -X POST http://localhost:8080/ai/ops/route \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Run full coverage on this target", "target": "https://example.com"}'
```

Active or budget-increasing intents dry-run unless explicit execution confirmations are present and
`AI_OPS_ROUTER_EXECUTE_ENABLED=true` is set.

### Custom Dictionaries (wordlists & payloads)

Additive extension points (off by default — absence = no behavior change):

```bash
# Inline content-discovery keywords appended to ffuf directory fuzzing
curl -X POST http://localhost:8080/scans \
  -d '{"target": "https://example.com",
       "options": {"scan_type": "smart",
                   "custom_wordlist": ["admin", "backup", "api/internal/v2", ".git/config"],
                   "custom_sqli_payloads": ["'\'' OR pg_sleep(5)--"],
                   "custom_xss_payloads": ["<x onfocus=alert(1) autofocus>"]}}'
```

Payloads can also be dropped into `scanner/payloads/sqli/custom.txt` / `scanner/payloads/xss/custom.txt`. Custom SQLi/XSS payloads are appended to the active selection in `_select_sqli_payloads` / `_select_xss_payloads`; custom wordlist words feed an extra ffuf pass via `enhanced_url_discovery`.

## Scan Types Explained

Scan type controls **what** ShakerScan tests. `budget_profile` controls **how hard** it tests. Keep the scan type stable when you want the same modules; adjust budget between `fast`, `balanced`, `thorough`, and `exhaustive`.

| Type | Time | What It Does |
|------|------|--------------|
| **quick** | 1-2 min | DNS, TLS cert, HTTP headers, basic tech detection |
| **standard** | 5-10 min | + Nuclei (safe), cookies, CORS, JS deps (no port scan by default) |
| **deep** | 30-60 min | + Full Nuclei, top-ports scan (1000), JS secrets |
| **full** | 1-2 hrs | + Active XSS/SQLi, WebSocket, auth/session/file-upload/redirect/CSRF/API tests |
| **aggressive** | 2+ hrs | + Aggressive exploits, full port scan (65535), threat intel, extended fuzzing |
| **smart** | Variable | Adaptive: staged Nuclei, DBMS-aware SQLi, context-aware XSS, attack chains |

`full` advanced probes (SSRF/command injection) only run with non-safe exploit level and parameterized endpoints.

**smart scan specifics:**
- Staged Nuclei (4 waves, ~60s/120s/300s/480s budgets, yield-adjusted)
- Early stop at confidence-weighted score ≥ 12 (3+ critical or 5+ high)
- Verification phase for high-severity findings (browser proofs, timing analysis)
- DBMS fingerprinting (SQLite, MySQL, PostgreSQL, MSSQL, Oracle) with DBMS-specific SQLi + data extraction chaining
- Context-aware XSS (in_script, in_attribute, etc.) + DOM XSS static analysis
- Recursive directory discovery (depth adapts to findings)
- Light port scan (top 33) for service hints and gRPC discovery
- Authenticated Playwright crawl (multi-page) with API capture; adaptive rate limiting
- JS bundle analysis for hidden endpoints; auth-aware tool routing
- Synthetic endpoints only when API hints exist (or `--thorough-params`)
- Attack chain analysis + coverage tracking

## Response Interpretation

Scans return:
- **score**: 0-100 (higher is better)
- **grade**: A, B, C, D, F
- **findings**: Array of vulnerabilities (severities: `critical`, `high`, `medium`, `low`, `info`)
- **result**: Rich object with detailed scan data (see below)

### Rich Scan Data (in `result` object)

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
| `result.attack_chains` | Attack chain analysis (null if no chains) |
| `result.smart_coverage` | Endpoint/parameter/template coverage metrics |

When AI is enabled, the report also includes `ai_correlations` (cross-finding correlations and overall risk assessment) plus `ai_logs.summary.cross_finding_correlations`.

### Attack Chain Analysis

Smart scans correlate findings into exploitable attack chains:

| Chain | Findings Required | Business Impact |
|-------|-------------------|-----------------|
| `xss_to_account_takeover` | XSS + weak cookie flags | Session theft |
| `sqli_to_privilege_escalation` | SQLi + admin panel access | DB / admin compromise |
| `ssrf_to_cloud_breach` | SSRF + cloud metadata access | Cloud IAM credential theft |
| `idor_to_data_breach` | BOLA + predictable IDs | Mass user data exfiltration |
| `lfi_to_credential_theft` | LFI + sensitive file access | Credential file exposure |
| `auth_bypass_to_admin_access` | Auth bypass + admin functions | Unauthorized admin access |
| `cors_to_data_theft` | CORS misconfig + sensitive endpoints | Cross-origin data theft |
| `weak_jwt_to_impersonation` | JWT weakness + user endpoints | User impersonation |
| `open_redirect_to_phishing` | Open redirect + auth pages | Credential phishing |
| `info_disclosure_to_exploitation` | Info leak + known CVE | Targeted exploitation |

Enable partial chains in the human-readable report with `"include_partial_attack_chains": true`. `result.attack_chains` structure: `{chains, partial_chains, report, summary: {total_chains, total_partial_chains, critical_chains, high_chains, chain_types, partial_chain_types, partial_chains_included}}`.

### Smart Coverage Metrics

`result.smart_coverage` tracks discovery vs testing coverage:

| Path | Description |
|------|-------------|
| `.endpoints` | discovered, tested, coverage, by_method |
| `.parameters` | discovered, tested, coverage, by_location (query/body/path) |
| `.nuclei_templates` | run, matched, hit_rate, by_category |
| `.discovery_sources` | Methods used (e.g. har_network_capture, url_crawl, js_bundle_analysis) |
| `.auth_states_tested` | e.g. anonymous, user1, user2 |

### Example Rich Report Output

```
✓ Scan completed
Grade: C    Score: 72/100

SUMMARY
- TLS: Let's Encrypt R3, 45 days, RSA 4096-bit
- CSP: Grade D (64/100) - 3 issues
- Headers: HSTS, XFO, Referrer all set
- Tech: React 18 (confirmed), Django (likely)

CSP Issues:
- script-src allows 'unsafe-inline'
- script-src allows 'unsafe-eval'

Findings: 0 Critical, 0 High, 3 Medium, 4 Low
Full report: http://localhost:3000/scans/{id}
```

## Example Interactions

- **"Scan my site example.com"** → check scanner running → submit quick scan → report scan ID + UI link, stop.
- **"Show me critical vulnerabilities"** → `GET /findings?severity=critical&status=active` → format.
- **"Do a full security audit of example.com"** → ask permission for active testing → submit `scan_type: full` → report scan ID + UI link, stop.
- **"Find subdomains for example.com"** → `POST /discovery?root_domain=example.com` → report started, stop.
- **"Scale up workers"** → `GET /workers`, then `POST /workers` with new count.
- **"Test for BOLA on api.example.com"** → ask permission → ask for two user auth tokens → smart scan with `auth_header` + `user2_header` → report scan ID + UI link, stop.
- **"Interactive security testing on juice-shop.example.com"** → run `/ai-security-session juice-shop.example.com` (see below).

## AI Security Sessions

The `/ai-security-session` skill enables interactive, collaborative security testing. Unlike automated scans, you and Claude collaborate:

1. Claude bootstraps from existing scan data (endpoints, tech, findings)
2. Claude suggests testing approaches
3. You direct which areas to test
4. Claude executes tests and reports findings in real-time
5. You can ask follow-up questions and explore deeper
6. Validated findings are saved to the database

**Recommended Workflow**: Run `/scan-smart <url>` first, then `/ai-security-session <url>` to validate findings and explore areas scanners miss.

### Session API

```bash
# Start a session
curl -X POST http://localhost:8080/session/start \
  -d '{"target": "https://example.com"}'

curl http://localhost:8080/session/{session_id}                            # Get state
curl -X POST "http://localhost:8080/session/{session_id}/screenshot"       # Screenshot

# Browser action (navigate, click, fill, register, login, submit, wait, extract)
curl -X POST "http://localhost:8080/session/{session_id}/action" \
  -d '{"action": "navigate", "data": {"url": "/login"}}'

# Login as a user (separate contexts per user label, e.g. user1/user2)
curl -X POST "http://localhost:8080/session/{session_id}/action" \
  -d '{"action": "login", "user": "user1",
       "data": {"email": "user1@test.com", "password": "pass123"}}'

# Test endpoint for BOLA (cross-user access)
curl -X POST "http://localhost:8080/session/{session_id}/test-endpoint" \
  -d '{"endpoint": "/api/items/42", "method": "GET", "as_user": "user2"}'

# Save a finding
curl -X POST "http://localhost:8080/session/{session_id}/findings" \
  -d '{"title": "BOLA on Basket API", "severity": "critical",
       "description": "User2 can access User1 basket",
       "category": "BOLA", "cwe": "CWE-639",
       "evidence": "GET /rest/basket/9 with User2 token returns User1 data"}'

# End session
curl -X DELETE "http://localhost:8080/session/{session_id}"
```

### Session Actions

| Action | Description | Data Fields |
|--------|-------------|-------------|
| `navigate` | Go to URL | `url` |
| `click` | Click element | `selector` |
| `fill` | Fill input field | `selector`, `value` |
| `register` | Register new account | `email`, `password` |
| `login` | Login to app | `email`, `password` |
| `submit` | Submit form | `selector` (optional) |
| `wait` | Wait for element/time | `selector`, `timeout` |
| `extract` | Extract data from page | `selector`, `attribute` |

### BOLA Testing Workflow

1. Start session → 2. Register/login user1 → 3. Discover resource IDs → 4. Register/login user2 (separate context) → 5. Test endpoints with `as_user: "user2"` → 6. Save findings via `POST /session/{id}/findings` → 7. Report.

### Bootstrapping from Scan Data

```bash
# Find existing scans for the target
curl -s "http://localhost:8080/scans?limit=5" | jq '[.scans[] | select(.target_url | contains("example.com"))]'

# Get scan results with discovered endpoints
curl -s "http://localhost:8080/scans/{scan_id}/result" | jq '{
  endpoints: .discovery.browser_api_endpoints[:10],
  tech: .discovery.tech.items,
  urls: .discovery.browser_crawl.sampled_urls[:5]
}'

# Get existing findings to validate
curl -s "http://localhost:8080/findings?target_url=https://example.com&status=active"
```

**Scan Context to Use:** `browser_api_endpoints` for BOLA/IDOR candidates; `browser_crawl.sampled_urls` for navigation; `tech.items` for tailored vectors; active findings for validation/exploitation.

### Interactive Session Testing Scenarios

| Category | Scenarios | Best For |
|----------|-----------|----------|
| **Access Control** | BOLA/IDOR, privilege escalation, tenant isolation, function-level access | Multi-user apps, APIs with resource ownership |
| **Authentication** | Session fixation, JWT flaws, concurrent sessions, token invalidation | Apps with login |
| **Business Logic** | Price manipulation, coupon abuse, workflow bypass, race conditions | E-commerce, financial |
| **API Security** | Mass assignment, GraphQL abuse, parameter pollution, rate limiting | REST/GraphQL APIs |
| **Client-Side** | Stored/DOM XSS, open redirect, clickjacking, sensitive data exposure | User-generated content |

**Use Interactive Sessions for:** validating automated-scan findings; vulnerabilities requiring human judgment; BOLA with real user contexts; chaining findings into attack paths; stakeholder demos.

**Saving Findings:** persist via `POST /session/{id}/findings`; they appear in the UI with `source: "ai_session"`.

## Pre-Scan Helpers

Slash commands that turn ShakerScan evidence into seeds for smart scans, plus a skill audit command:

- `/js-analyze <target_url|scan_id|js_path>` — analyze JS bundles, frontend routes, browser-captured APIs → `custom_endpoints` block. Backed by `skills/js-analyze/SKILL.md` + `js-analysis-agent`.
- `/content-discovery <target_url|scan_id>` — high-signal route/file discovery plan (`custom_list` for ffuf + `custom_endpoints` for smart scans). Backed by `skills/content-discovery/SKILL.md` + `content-discovery-agent`.
- `/review-skills [scope]` — audit local skill/command/agent surface for prompt bugs, broken refs, weak output contracts. Backed by `skills/review-skills/SKILL.md` + `skills-reviewer`.

Typical pre-scan flow: `/js-analyze` → optionally pipe into `/content-discovery` → submit combined `custom_endpoints` to `/scan-smart`.

## CLI Shortcuts

```bash
# Basic scans
./scanner.sh scan https://example.com         # Quick scan
./scanner.sh scan-full https://example.com --confirm-active    # Full assessment
./scanner.sh scan-smart https://example.com --confirm-active   # Smart adaptive scan

# Deeper smart coverage budget
./scanner.sh scan-smart https://example.com --budget-profile thorough --confirm-active

# Use POST /scans for auth, focused XSS/SQLi, dual-auth BOLA, or custom budgets.

# Management
./scanner.sh status                   # Check status
./scanner.sh scale 5                  # Scale to 5 workers
./scanner.sh logs -f                  # Follow logs
./scanner.sh rebuild                  # Full rebuild (code changes)
./scanner.sh restart                  # Restart services
```

## Files Structure

```
scanner-oss/
├── scanner.sh           # CLI tool (start, stop, scan, scale, etc.)
├── docker-compose.yml   # Docker stack orchestration
├── CLAUDE.md            # This file
├── AGENTS.md            # Cross-tool AI agent instructions
├── scanner/             # Core scanner engine
│   ├── scanner.py       # Main orchestrator
│   ├── scanner_tools/   # 61 specialized security modules (nuclei.py, active_checks.py, discovery.py, ...)
│   ├── payloads/        # Attack payloads (SQLi, XSS)
│   └── wordlists/       # Directory discovery wordlists
├── api/                 # FastAPI backend (api.py, worker.py, gungnir_worker.py, session_manager.py)
├── ui/                  # Next.js dashboard
├── db/init.sql          # PostgreSQL schema
└── results/             # Scan results (JSON)
```

## Troubleshooting

### Scanner Won't Start

```bash
docker info                  # Docker running?
lsof -i :8080; lsof -i :3000 # Port conflicts?
./scanner.sh logs            # Startup logs
./scanner.sh rebuild         # Full rebuild
```

### Database Connection Errors

```bash
docker compose ps postgres   # Health
docker compose logs postgres # Logs
./scanner.sh reset           # WARNING: deletes all data
```

### Scans Stuck in Pending

```bash
curl http://localhost:8080/workers          # Worker status
curl http://localhost:8080/queue/stats      # Queue stats
curl -X POST http://localhost:8080/workers -d '{"count": 5}'   # Scale up
docker compose logs worker -f               # Worker logs
```

### Out of Memory

Workers use 2-4GB RAM each. Scale down:
```bash
curl -X POST http://localhost:8080/workers -d '{"count": 2}'
./scanner.sh restart -w 2
```

### API Not Responding

```bash
curl http://localhost:8080/health    # Health
docker compose restart api           # Restart
docker compose logs api -f           # Logs
```
