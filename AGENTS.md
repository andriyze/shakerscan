# AGENTS.md - Shaker Scan

This is an open-source Dynamic Application Security Testing (DAST) scanner. Users interact with it via AI coding agents to scan websites for vulnerabilities.

## Quick Setup

If the scanner isn't running, start it:
```bash
./scanner.sh start
```

Check status:
```bash
./scanner.sh status
```

## How This Works

The scanner runs as Docker containers:
- **API** at `http://localhost:8080` - REST API for all operations
- **UI** at `http://localhost:3000` - Web dashboard
- **Workers** - Process scan jobs in parallel
- **PostgreSQL** - Stores scans, findings, targets
- **Redis** - Job queue

## Your Role

When users ask about security scanning, you should:

**Important**: After submitting a scan, report the scan ID and UI link, then stop. Do NOT poll or wait for completion - scans can take minutes to hours. Users can check results via UI or ask later.

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

# List recent scans
curl "http://localhost:8080/scans?limit=10"

# Get full result JSON
curl http://localhost:8080/scans/{scan_id}/result
```

### Findings

```bash
# List active findings
curl "http://localhost:8080/findings?status=active"

# Filter by severity
curl "http://localhost:8080/findings?severity=critical"
curl "http://localhost:8080/findings?severity=high"

# Update finding status
curl -X PATCH http://localhost:8080/findings/{id} \
  -H "Content-Type: application/json" \
  -d '{"status": "resolved"}'

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

# Create finding from AI session (target auto-populated)
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

Finding sources: `scan` (automated), `manual` (manual testing), `ai_session` (AI security session)

### Subdomain Discovery

```bash
curl -X POST "http://localhost:8080/discovery?root_domain=example.com"
```

### Dashboard & Status

```bash
# Dashboard metrics
curl http://localhost:8080/dashboard

# Queue status
curl http://localhost:8080/queue/stats
```

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

### Certificate Transparency Monitoring (Gungnir)

Monitor CT logs in real-time to discover new certificates issued for your domains:

```bash
# Start Gungnir CT monitoring
./scanner.sh gungnir start

# Check Gungnir status
curl http://localhost:8080/gungnir/status

# View discovered subdomains for a domain
curl "http://localhost:8080/gungnir/discoveries?domain=example.com"
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
| `auth_bypass_to_admin_access` | Auth bypass + admin functions | Unauthorized admin access |
| `cors_to_data_theft` | CORS misconfig + sensitive endpoints | Cross-origin data theft |
| `weak_jwt_to_impersonation` | JWT weakness + user endpoints | User impersonation |
| `open_redirect_to_phishing` | Open redirect + auth pages | Credential phishing |
| `info_disclosure_to_exploitation` | Info leak + known CVE | Targeted exploitation |

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
| `no_early_stop` | Disable early stopping in smart scan (continue even after finding many vulns) |
| `thorough_params` | Test more parameters: 100 endpoints × 10 params per method instead of default 50×5 per method |
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

Defaults are sourced from `scanner/constants.py` via `SMART_SCAN_BUDGETS`.

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

By default, smart scan:
- **Stops early** when 3+ critical or 5+ high severity findings are found
- **Tests 50 endpoints × 5 params per method (GET + POST)** for SQLi/XSS

With `no_early_stop` and `thorough_params`:
- **Continues scanning** regardless of findings (finds all vulnerabilities, not just first few)
- **Tests 100 endpoints × 10 params per method (GET + POST)** for more complete coverage

## Scan Types Explained

| Type | API Option | Time | What It Does |
|------|------------|------|--------------|
| **quick** | `"scan_type": "quick"` | 1-2 min | DNS, TLS cert, HTTP headers, basic tech detection |
| **standard** | `"scan_type": "standard"` | 5-10 min | + Nuclei (safe), cookies, CORS, JS dependencies (no port scan by default) |
| **deep** | `"scan_type": "deep"` | 30-60 min | + Full Nuclei, top-ports scan (1000), JS secrets |
| **full** | `"scan_type": "full"` | 1-2 hrs | + Active XSS/SQLi, all security tests, WebSocket |
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

**Recommended Workflow**: Run a smart scan first, then use interactive session to validate findings and explore areas scanners miss.

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
curl -s "http://localhost:8080/findings?target_url=https://example.com&status=active"
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
./scanner.sh scan-full https://example.com  # Full assessment
./scanner.sh scan-smart https://example.com # Smart adaptive scan

# Authenticated scans
./scanner.sh scan-smart https://example.com --auth-header "Bearer token"
./scanner.sh scan-smart https://example.com --auth-cookies "session=abc123"

# Focused active checks
./scanner.sh scan-smart https://example.com --sqli --auth-header "Bearer token"   # SQLi-only
./scanner.sh scan-smart https://example.com --xss --auth-cookies "session=abc123" # XSS-only

# Dual-auth BOLA testing
./scanner.sh scan-smart https://api.example.com --auth-header "Bearer user1_token" --user2-header "Bearer user2_token"

# Thorough mode (no early stop, more params)
./scanner.sh scan-smart https://example.com --no-early-stop --thorough-params

# Management
./scanner.sh status                          # Check status
./scanner.sh scale 5                         # Scale to 5 workers
./scanner.sh logs -f                         # Follow logs
./scanner.sh rebuild                         # Full rebuild (code changes)
./scanner.sh restart                         # Restart services
```

## Files Structure

```
scanner-oss/
├── scanner.sh           # CLI tool (start, stop, scan, scale, etc.)
├── docker-compose.yml   # Docker stack orchestration
├── CLAUDE.md            # Claude Code instructions
├── AGENTS.md            # This file (cross-tool AI agent instructions)
├── scanner/             # Core scanner engine
│   ├── scanner.py       # Main orchestrator
│   ├── scanner_tools/   # 61 specialized security modules
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
