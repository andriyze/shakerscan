---
name: ShakerScan
description: DAST security scanner. USE WHEN scan, security, vulnerability, XSS, SQLi, findings, subdomain discovery, pentest.
---

# Shaker Scan Skill

You have access to a local DAST (Dynamic Application Security Testing) scanner running at `http://localhost:8080`.

## Capabilities

- **Security Scanning**: Scan websites for vulnerabilities (XSS, SQLi, misconfigurations, etc.)
- **Subdomain Discovery**: Enumerate subdomains using CT logs and passive sources
- **Finding Management**: Track, triage, and manage security findings
- **Target Management**: Maintain a list of assets to scan
- **Recurring Schedules**: Automate daily/weekly scans per target
- **Worker Control**: Scale worker pool based on queue pressure
- **CT Monitoring**: Start/stop Gungnir certificate transparency monitoring
- **Interactive Testing**: Use `/session` APIs for manual browser-driven security validation

## Scan Types

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
# Thorough mode: no early stop + more params
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {
    "scan_type": "smart",
    "no_early_stop": true,
    "thorough_params": true
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
| `thorough_params` | Test 100 endpoints x 10 params per method instead of default 50x5 |
| `custom_endpoints` | Array of endpoints with params to test (format: `[METHOD] /path [params]`) |
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

**Query Parameters:** `status`, `severity`, `seen_within_days` (7/30/60/90), `root_domain`, `target_id`, `scan_id`, `verification_verdict`, `verification_mode`, `verified_only`, `search`, `sort_by` (severity/first_seen/last_seen/cvss), `sort_order`, `limit`, `offset`

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
6. **CLI scope** - `scanner.sh` wraps `scan`, `scan-full`, `scan-smart`; use API for advanced options
