---
name: ShakerScan
description: DAST security scanner. USE WHEN scan, security, vulnerability, XSS, SQLi, findings, subdomain discovery, pentest, AI Gate, model intake.
---

# ShakerScan Skill

You have access to a local DAST (Dynamic Application Security Testing) scanner running at `http://localhost:8080`.

## Capabilities

- **Security Scanning**: Scan websites for vulnerabilities (XSS, SQLi, misconfigurations, etc.)
- **Subdomain Discovery**: Enumerate subdomains using CT logs and passive sources
- **Finding Management**: Track, triage, and manage security findings
- **Target Management**: Maintain a list of assets to scan
- **Exposure Graph**: Link domains, endpoints, APIs, auth roles, vendors, AI targets, MCP tools, model artifacts, scans, and findings
- **Recurring Schedules**: Automate daily/weekly scans per target
- **Worker Control**: Scale worker pool based on queue pressure
- **CT Monitoring**: Start/stop Gungnir certificate transparency monitoring
- **Interactive Testing**: Use `/session` APIs for manual browser-driven security validation
- **AI Gate Testing**: Register AI targets and run probe packs against chat, RAG, agent trace, and MCP surfaces
- **Model Intake**: Check model artifacts for unsafe serialization, provenance, signatures, checksums, model cards, and deployment approval

## Scan Types

Scan type controls **what** ShakerScan tests. `budget_profile` controls **how hard** it tests (`fast`, `balanced`, `thorough`, `exhaustive`).

| Type | API Option | Time | Description |
|------|------------|------|-------------|
| **quick** | `"scan_type": "quick"` | 1-2 min | DNS, TLS, headers, basic tech detection |
| **standard** | `"scan_type": "standard"` | 5-10 min | + Nuclei (safe), cookies, JS dependencies |
| **deep** | `"scan_type": "deep"` | 30-60 min | + Full Nuclei, port scan, JS secrets |
| **full** | `"scan_type": "full"` | 1-2 hrs | + Active XSS/SQLi, ALL security tests |
| **aggressive** | `"scan_type": "aggressive"` | 2+ hrs | + Extended ports, aggressive exploits |
| **smart** | `"scan_type": "smart"` | Variable | Adaptive: staged templates, DBMS-aware SQLi, context-aware XSS |

**Important**: `full`, `aggressive`, and `smart` require user permission (active testing).

### Smart Scan Features
- **Staged Nuclei scanning**: 4 waves based on tech detection + signals, with early stopping
- **DBMS fingerprinting**: Detects SQLite, MySQL, PostgreSQL, MSSQL, Oracle
- **DBMS-specific SQLi payloads**: Uses targeted payloads based on detected database
- **Context-aware XSS**: Detects reflection context (in_script, in_attribute, etc.) and uses appropriate payloads
- **DOM XSS analysis**: Static source-to-sink flow detection in JavaScript bundles
- **POST body injection**: Tests JSON/form POST parameters for SQLi (not just GET query params)
- **Recursive discovery**: Adapts depth based on findings
- **Adaptive rate limiting**: Backs off on 429/503, speeds up on success
- **Attack chain analysis**: Correlates findings into exploitable attack paths (XSS->ATO, SQLi->data exfil, etc.)
- **Coverage tracking**: Monitors endpoint/parameter/template coverage metrics
- **Authenticated Playwright crawl**: Multi-page headless crawl with API capture
- **JS bundle analysis**: Discovers hidden endpoints from JavaScript bundles

### Smart Scan Tuning

```bash
# Thorough coverage budget with optional custom limits
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {
    "scan_type": "smart",
    "budget_profile": "thorough",
    "custom_budget": {
      "max_urls": 2500,
      "browser_max_pages": 100,
      "active_max_endpoints": 150,
      "active_params_per_endpoint": 12
    }
  }}'

# Custom endpoints with params
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://api.example.com", "options": {
    "scan_type": "smart",
    "custom_endpoints": [
      "GET /api/v1/users?id=1&name=test",
      "POST /api/v1/login json:{\"username\":\"test\",\"password\":\"test\"}",
      "POST /api/v1/search form:query=test&limit=10"
    ]
  }}'
```

**Advanced Options:**

| Option | Description |
|--------|-------------|
| `no_early_stop` | Disable early stopping (continue scanning even after finding many vulns) |
| `thorough_params` | Legacy shortcut for deeper smart active checks; promotes to `thorough` budget when no explicit budget is provided |
| `custom_endpoints` | Array of endpoints with params to test (format: `[METHOD] /path [params]`) |
| `budget_profile` | Coverage budget profile: `fast`, `balanced`, `thorough`, or `exhaustive` |
| `custom_budget` | Advanced depth/time overrides such as `max_urls`, `browser_max_pages`, `api_probe_limit`, `nuclei_max_targets`, `active_max_seconds`, `active_max_endpoints`, and `active_params_per_endpoint` |
| `json_link_following` | Follow links in JSON API responses (HATEOAS, pagination) |
| `options_method_discovery` | Use HTTP OPTIONS to discover allowed methods |
| `grpc_discovery` | Use gRPC reflection to discover services |
| `focus_rules_json` | JSON array of rules to include only specific endpoint scope |
| `avoid_rules_json` | JSON array of rules to exclude endpoint scope |
| `verified_findings_only` | Keep only findings with exploit verification evidence in final output |
| `deep_domxss` | Enable deep DOM XSS analysis (more thorough but slower) |
| `oob_callback_url` | Out-of-band callback URL for blind SQLi/SSRF detection |

**Performance/Safety Limits:**

| Option | Description | Default |
|--------|-------------|---------|
| `smart_bola_max_endpoints` | Max endpoints for BOLA testing | 80 |
| `dom_xss_max_files` | Max JS files for DOM XSS analysis | 20 |
| `sqli_extract_max` | Max SQLi findings for data extraction | 3 |
| `oob_max_findings` | Max findings for OOB SQLi test | 3 |

## API Reference

### Submit a Scan

```bash
# Quick scan (default)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {"scan_type": "quick"}}'

# Full assessment (requires permission)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {"scan_type": "full"}}'
```

### Authenticated Scanning

```bash
# Bearer token (JWT, API key)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://api.example.com", "options": {
    "scan_type": "smart",
    "auth_header": "Bearer eyJhbGciOiJIUzI1NiIs..."
  }}'

# Session cookies
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {
    "scan_type": "smart",
    "auth_cookies": "session=abc123; csrf_token=xyz"
  }}'

# Form-based login (scanner auto-authenticates)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {
    "scan_type": "smart",
    "login_username": "user@test.com",
    "login_password": "password123"
  }}'

# Custom headers (API keys, tenant IDs)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://api.example.com", "options": {
    "scan_type": "smart",
    "auth_headers_json": "{\"X-API-Key\": \"key123\"}"
  }}'

# Multi-user BOLA/IDOR testing
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://api.example.com", "options": {
    "scan_type": "smart",
    "auth_header": "Bearer user1_token",
    "user2_header": "Bearer user2_token"
  }}'
```

**Authentication Options:**

| Option | Description |
|--------|-------------|
| `auth_header` | Authorization header (Bearer, Basic, API key) |
| `auth_cookies` | Session cookies |
| `auth_headers_json` | Custom headers as JSON object |
| `login_username` | Username for form-based login |
| `login_password` | Password for form-based login |
| `login_url` | Login page URL (auto-detected if not provided) |
| `login_extra_fields` | Extra form fields as JSON |
| `auth_scenario_json` | Auth scenario JSON DSL for custom login flow/success checks/TOTP |
| `user2_header` | Second user auth for BOLA/IDOR testing |
| `user2_cookies` | Second user cookies for BOLA/IDOR testing |

### Reporting Options

| Option | Description |
|--------|-------------|
| `include_partial_attack_chains` | Include partial attack chains in the human-readable report (analyst mode). Full chains always appear in `result.attack_chains.chains`. |

### Check Scan Status

```bash
curl http://localhost:8080/scans/{scan_id}
curl "http://localhost:8080/scans/{scan_id}/logs?limit=200"
curl -X POST http://localhost:8080/scans/{scan_id}/cancel
```

### Findings

```bash
# List with filters
curl "http://localhost:8080/findings?status=active"
curl "http://localhost:8080/findings?severity=critical&seen_within_days=30&sort_by=cvss&sort_order=desc"
curl "http://localhost:8080/findings?verification_verdict=exploited&verification_mode=ai_driven&verified_only=true"
curl "http://localhost:8080/findings?source_type=ai&status=active"
curl "http://localhost:8080/findings?source_type=dast&status=active"

# Update status (with optional notes)
curl -X PATCH http://localhost:8080/findings/{id} \
  -H "Content-Type: application/json" \
  -d '{"status": "resolved", "notes": "Fixed in v2.0"}'

# Delete a finding
curl -X DELETE http://localhost:8080/findings/{id}

# Bulk cleanup old findings (dry-run first)
curl -X POST http://localhost:8080/findings/cleanup \
  -H "Content-Type: application/json" \
  -d '{"older_than_days": 90, "dry_run": true}'

# Bulk cleanup (execute)
curl -X POST http://localhost:8080/findings/cleanup \
  -H "Content-Type: application/json" \
  -d '{"older_than_days": 90, "status": "resolved", "dry_run": false}'

# Bulk update statuses
curl -X POST http://localhost:8080/findings/bulk \
  -H "Content-Type: application/json" \
  -d '{"finding_ids": ["id1", "id2"], "status": "false_positive"}'

# Queue retest for one finding (tiered)
curl -X POST http://localhost:8080/findings/{id}/retest \
  -H "Content-Type: application/json" \
  -d '{"requested_by":"api"}'

# Force AI-only retest
curl -X POST "http://localhost:8080/findings/{id}/retest?mode=ai" \
  -H "Content-Type: application/json" \
  -d '{"requested_by":"api"}'

# Bulk retest by filters
curl -X POST http://localhost:8080/findings/retest \
  -H "Content-Type: application/json" \
  -d '{"severity":"high","status":"active","limit":25,"mode":"deterministic"}'

# Retest history/details
curl "http://localhost:8080/retests/finding/{id}?limit=20"
curl "http://localhost:8080/retests/{retest_id}"
```

Status options: `active`, `resolved`, `false_positive`, `accepted_risk`

**Query Parameters:** `status`, `severity`, `source_type` (`dast` or `ai`), `seen_within_days` (7/30/60/90), `root_domain`, `target_id`, `scan_id`, `verification_verdict`, `verification_mode`, `verified_only`, `search`, `sort_by` (severity/first_seen/last_seen/cvss), `sort_order`, `limit`, `offset`

### AI Gate

Use AI Gate when the user wants to test an AI app, chatbot, RAG endpoint, agent/tool workflow, or MCP endpoint. The UI is at `http://localhost:3000/settings/ai-gate`; the API is fully usable by agents.

AI Gate uses deterministic/regex detectors first. If AI settings have a configured provider, semantic AI judging also reviews probe transcripts, fills the standard AI analysis fields on findings, and can downgrade high-confidence false positives before scoring.

AI Gate target `metadata_json` can carry control evidence: `asset_owner`, `risk_tier`, `data_classification`, RAG ACL/ingestion/isolation controls, agent tool scopes, token audience validation, approval/dry-run/transaction controls, sandboxing, audit logs, anomaly detection, kill switch, and governance mappings. Set `enforce_ai_control_baseline: true` to create a finding when required controls are missing.

Target types: `api_chat`, `rag`, `agent_trace`, `mcp_trace`, `widget`.
Probe packs: `shaker-ai-smoke`, `shaker-owasp-llm`, `shaker-agent-abuse`, `shaker-mcp-security`, `shaker-rag-lite`.
Scan profiles: `smoke`, `trace`, `standard`, `deep`.

```bash
# List AI Gate targets
curl http://localhost:8080/ai/targets

# Create a target. request_template must include {{prompt}} for non-GET API targets.
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
    "metadata_json": {
      "asset_owner": "security",
      "risk_tier": "high",
      "data_classification": "restricted",
      "enforce_ai_control_baseline": true
    },
    "credential": {"auth_kind": "bearer", "secret": "token-if-needed"}
  }'

# Queue an AI Gate scan
curl -X POST http://localhost:8080/ai/targets/{target_id}/scan \
  -H "Content-Type: application/json" \
  -d '{"probe_pack":"shaker-agent-abuse","scan_profile":"standard","environment":"staging"}'

# Read transcripts for a completed AI Gate scan
curl http://localhost:8080/ai/scans/{scan_id}/transcript
```

After submitting an AI Gate scan, report the scan ID and UI link, then stop. Do not poll unless the user explicitly asks.

### Model Intake

Use Model Intake when the user wants to check a model artifact before deployment. The UI is at `http://localhost:3000/settings/model-intake`. The scanner reads artifact bytes and metadata without importing or executing model code, including provenance, serialization, signing/checksum, license, SBOM, malware scan, eval, deployment restriction, monitoring, and approval evidence.

Model Intake findings are stored as non-AI findings with `tool=model_intake`; `source_type=dast` includes them until the product adds a separate model-intake source filter.

```bash
curl -X POST http://localhost:8080/model-intake/scan \
  -H "Content-Type: application/json" \
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

After submitting a Model Intake scan, report the scan ID and UI link, then stop. Do not poll unless the user explicitly asks.

### Target Management

```bash
# List targets grouped by root domain
curl "http://localhost:8080/targets/grouped"

# List root domains
curl http://localhost:8080/domains

# Add a target
curl -X POST http://localhost:8080/targets \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "name": "Production"}'

# Scan a specific target
curl -X POST http://localhost:8080/targets/{target_id}/scan \
  -H "Content-Type: application/json" \
  -d '{"options": {"scan_type": "quick"}}'
```

### Subdomain Discovery

```bash
curl -X POST "http://localhost:8080/discovery?root_domain=example.com"
```

### Dashboard & Queue

```bash
curl http://localhost:8080/dashboard
curl http://localhost:8080/queue/stats
curl http://localhost:8080/health
curl -X DELETE http://localhost:8080/queue/clear  # emergency clear
```

### Additional Operational Endpoints

```bash
# Batch scans
POST /scans/batch

# Workers
GET /workers
POST /workers  # {"count": 5}

# AI settings
GET /settings/ai
PUT /settings/ai

# Schedules
GET /schedules
POST /schedules
PATCH /schedules/{schedule_id}
DELETE /schedules/{schedule_id}

# Gungnir CT monitor
GET /gungnir/status
POST /gungnir/start
POST /gungnir/stop

# Target CRUD
GET /targets/{target_id}
PATCH /targets/{target_id}
DELETE /targets/{target_id}

# Interactive sessions
POST /session/start
GET /session/{session_id}
POST /session/{session_id}/action
POST /session/{session_id}/test-endpoint
POST /session/{session_id}/screenshot
GET /session/{session_id}/screenshot.png
POST /session/{session_id}/findings
GET /sessions
DELETE /session/{session_id}
```

## Rich Scan Response Data

The `/scans/{id}` endpoint returns detailed data in the `result` object:

### HTTP & CSP (`result.http`)
- `security_headers` - HSTS, CSP, X-Frame-Options, Referrer-Policy, etc.
- `csp_evaluation` - grade, score, issues, parsed directives
- `cookies` - cookie security analysis
- `http2`, `http3_advertised` - protocol support

### TLS Certificate (`result.tls`)
- `certificate` - subject, issuer, days_remaining, key_size, key_algo
- `ocsp.stapled` - OCSP stapling status
- `cipher_suites` - supported ciphers

### DNS Records (`result.dns`)
- `a`, `aaaa`, `mx`, `cname` - basic records
- `spf`, `dmarc` - email authentication
- `dnssec`, `caa` - security records

### Technology Detection (`result.discovery.tech`)
- `items` - detected technologies with version and confidence
- `by_category` - technologies grouped by category

### Other Discovery (`result.discovery`)
- `browser_api_endpoints` - discovered API endpoints
- `browser_crawl` - headless crawl stats + sampled page URLs
- `waf_detection` - WAF product detection
- `cors` - CORS misconfiguration
- `nuclei` - Nuclei vulnerability findings

### Attack Chains (`result.attack_chains`)
- `chains` - complete attack chains (always included)
- `partial_chains` - incomplete chains (in JSON; in human report only with `include_partial_attack_chains`)
- `summary` - total/critical/high chain counts

Chain types: `xss_to_account_takeover`, `sqli_to_privilege_escalation`, `ssrf_to_cloud_breach`, `idor_to_data_breach`, `lfi_to_credential_theft`, `auth_bypass_to_admin_access`, `cors_to_data_theft`, `weak_jwt_to_impersonation`, `open_redirect_to_phishing`, `info_disclosure_to_exploitation`

### Smart Coverage (`result.smart_coverage`)
- `endpoints` - discovered/tested counts, coverage ratio, by_method breakdown
- `parameters` - by location (query, body, path) with discovered/tested counts
- `nuclei_templates` - templates run vs matched, hit_rate
- `discovery_sources` - array of methods used (har_network_capture, url_crawl, js_bundle_analysis)
- `auth_states_tested` - array of auth states tested (anonymous, user1, user2)

Coverage interpretation: `< 0.5` possible rate limiting, `0.5-0.8` normal, `> 0.8` excellent

## Example Report Format

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

## Usage Guidelines

1. **Default to quick** for initial assessments
2. **Ask permission** before running `full`, `aggressive`, or `smart` scans
3. **Use smart** for sophisticated targets - it adapts based on what it finds
4. **Report rich data** - include CSP grade, TLS info, tech stack
5. **Link to UI** - always include the report URL
6. **CLI scope** - `scanner.sh` wraps `scan`, `scan-full`, `scan-smart`, and `scan-smart --budget-profile`; use API for auth, focused checks, and custom budgets
