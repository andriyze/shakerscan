# Shaker Scan Skills for Claude Code

This directory contains skills files for integrating Shaker Scan with Claude Code.

## Setup

1. Start the scanner:
   ```bash
   cd /path/to/scanner-oss
   ./scanner.sh start
   ```

2. Copy the skills file to your Claude Code skills directory:
   ```bash
   cp scanner-skill.md ~/.claude/skills/
   ```

3. Now Claude Code can use the scanner via natural language:
   - "Scan example.com for vulnerabilities"
   - "Show me the latest scan results"
   - "List all critical findings"
   - "Run a full security assessment on my-app.com"

Available skills in this folder:
- `scanner-skill.md` - primary scanning operations (scans/findings/targets/workers/schedules/AI Gate)
- `ai-security-session/` - interactive `/session` Playwright workflows (BOLA/IDOR/manual testing)

## API Endpoints

The scanner exposes these endpoints at `http://localhost:8080`:

Agents that support HTTP tools can call these endpoints directly. Agents that support OpenAPI/tool import can use the live FastAPI schema at `http://localhost:8080/openapi.json`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scans` | POST | Submit a new scan |
| `/scans/batch` | POST | Submit scans for multiple targets |
| `/scans` | GET | List all scans (filter by status, domain, search) |
| `/scans/{id}` | GET | Get scan details with findings |
| `/scans/{id}/result` | GET | Get full scan result JSON |
| `/scans/{id}/logs` | GET | Get live scan logs tail (limit param, default 200, max 1000) |
| `/scans/{id}/cancel` | POST | Cancel a running or pending scan |
| `/findings` | GET | List findings (filter by DAST/AI `source_type`, severity, status, seen_within_days, domain, search, verification filters) |
| `/findings/{id}` | GET | Get finding details |
| `/findings/{id}` | PATCH | Update finding status and notes |
| `/findings/{id}` | DELETE | Delete a finding |
| `/findings/{id}/retest` | POST | Queue retest for one finding (`mode=ai` or `mode=deterministic` optional) |
| `/findings/retest` | POST | Queue bulk retests by IDs or filters |
| `/findings/cleanup` | POST | Bulk delete old findings (dry_run support) |
| `/findings/bulk` | POST | Bulk update finding statuses |
| `/findings/manual` | POST | Create manual finding |
| `/retests/finding/{id}` | GET | List retest history for a finding |
| `/retests/{id}` | GET | Get one retest record with proof/artifacts/AI metadata |
| `/targets` | GET/POST | List/create targets |
| `/targets/grouped` | GET | Hierarchical targets view (root + subdomains, with filtering/sorting) |
| `/targets/{id}` | GET | Get target details with recent scans |
| `/targets/{id}` | PATCH | Update target (name, is_active, scan_options) |
| `/targets/{id}` | DELETE | Deactivate target (soft delete) |
| `/targets/{id}/scan` | POST | Start a scan for a specific target |
| `/domains` | GET | List unique root domains |
| `/discovery` | POST | Start subdomain discovery |
| `/discovery` | GET | List discovery runs |
| `/discovery/{id}` | GET | Get discovery run details |
| `/schedules` | GET/POST | Manage recurring scans |
| `/schedules/{id}` | GET | Get schedule details |
| `/schedules/{id}` | PATCH/DELETE | Update or remove a schedule |
| `/workers` | GET/POST | View/scale worker count (1-20) |
| `/settings/ai` | GET/PUT | View/update runtime AI settings (optional `.env` persistence) |
| `/ai/targets` | GET/POST | List/create AI Gate targets |
| `/ai/targets/{id}` | PATCH/DELETE | Update/deactivate an AI Gate target |
| `/ai/targets/{id}/scan` | POST | Queue an AI Gate probe-pack scan |
| `/ai/scans/{id}/transcript` | GET | Get completed AI Gate scan transcripts |
| `/gungnir/status` | GET | CT monitor status |
| `/gungnir/start` | POST | Start CT monitor |
| `/gungnir/stop` | POST | Stop CT monitor |
| `/session/start` | POST | Start interactive browser session |
| `/session/{id}` | GET/DELETE | Read/end interactive session |
| `/session/{id}/action` | POST | Execute browser action |
| `/session/{id}/test-endpoint` | POST | Run BOLA/IDOR endpoint test |
| `/session/{id}/screenshot` | POST | Capture screenshot (base64 JSON) |
| `/session/{id}/screenshot.png` | GET | Capture screenshot (PNG bytes) |
| `/session/{id}/findings` | POST | Save finding from session |
| `/sessions` | GET | List active sessions |
| `/dashboard` | GET | Get dashboard metrics |
| `/queue/stats` | GET | Get queue status |
| `/queue/clear` | DELETE | Emergency clear all pending jobs |
| `/health` | GET | Health check |

## Scan Types

| Type | Duration | Description |
|------|----------|-------------|
| `quick` | 1-2 min | DNS, TLS, headers, basic tech detection |
| `standard` | 5-10 min | + Nuclei (safe), cookies, JS dependencies |
| `deep` | 30-60 min | + Full Nuclei, port scan, JS secrets |
| `full` | 1-2 hrs | + Active XSS/SQLi, ALL security tests |
| `aggressive` | 2-5 hrs | + Extended ports, aggressive exploits |
| `smart` | Variable | Adaptive: staged templates, DBMS-aware SQLi, context-aware XSS |

## Example API Calls

```bash
# Quick scan (1-2 min)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {"scan_type": "quick"}}'

# Standard scan (5-10 min)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {"scan_type": "standard"}}'

# Full assessment (1-2 hrs) - requires permission
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {"scan_type": "full"}}'

# List findings (with recency filter)
curl "http://localhost:8080/findings?severity=critical&status=active&seen_within_days=30"

# Filter to verified and AI-driven findings
curl "http://localhost:8080/findings?verification_verdict=exploited&verification_mode=ai_driven&verified_only=true"

# Filter by product type
curl "http://localhost:8080/findings?source_type=ai&status=active"
curl "http://localhost:8080/findings?source_type=dast&status=active"

# Queue retest (tiered)
curl -X POST http://localhost:8080/findings/{finding_id}/retest \
  -H "Content-Type: application/json" \
  -d '{"requested_by":"api"}'

# Force AI-only retest
curl -X POST "http://localhost:8080/findings/{finding_id}/retest?mode=ai" \
  -H "Content-Type: application/json" \
  -d '{"requested_by":"api"}'

# Delete a finding
curl -X DELETE http://localhost:8080/findings/{finding_id}

# Bulk cleanup old findings (dry-run first)
curl -X POST http://localhost:8080/findings/cleanup \
  -H "Content-Type: application/json" \
  -d '{"older_than_days": 90, "dry_run": true}'

# Subdomain discovery
curl -X POST "http://localhost:8080/discovery?root_domain=example.com"

# Cancel a scan
curl -X POST http://localhost:8080/scans/{scan_id}/cancel

# AI runtime settings (keys masked on read)
curl http://localhost:8080/settings/ai
curl -X PUT http://localhost:8080/settings/ai \
  -H "Content-Type: application/json" \
  -d '{"ai_verify_enabled": true, "ai_verify_min_severity": "high", "persist_to_env": false}'

# AI Gate target + scan
curl -X POST http://localhost:8080/ai/targets \
  -H "Content-Type: application/json" \
  -d '{"name":"Support bot","target_type":"api_chat","endpoint_url":"https://example.com/api/chat","method":"POST","request_template":{"message":"{{prompt}}","session_id":"{{session_id}}"},"response_path":"$.answer"}'

curl -X POST http://localhost:8080/ai/targets/{target_id}/scan \
  -H "Content-Type: application/json" \
  -d '{"probe_pack":"shaker-ai-smoke","scan_profile":"smoke","environment":"staging"}'

# Authenticated scan (Bearer token)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://api.example.com", "options": {
    "scan_type": "smart",
    "auth_header": "Bearer your-jwt-token"
  }}'

# Authenticated scan (session cookies)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {
    "scan_type": "smart",
    "auth_cookies": "session=abc123"
  }}'

# Form-based login (auto-authenticates)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {
    "scan_type": "smart",
    "login_username": "user@test.com",
    "login_password": "password123"
  }}'

# SQLi-only scan with auth (Bearer token)
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://api.example.com", "options": {
    "scan_type": "smart",
    "sqli": true,
    "auth_header": "Bearer your-jwt-token"
  }}'

# XSS-only scan with session cookies
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {
    "scan_type": "smart",
    "xss": true,
    "auth_cookies": "session=abc123"
  }}'
```

## Authentication Options

| Option | Description |
|--------|-------------|
| `auth_header` | Authorization header (Bearer, Basic, API key) |
| `auth_cookies` | Session cookies |
| `auth_headers_json` | Custom headers as JSON |
| `login_username` | Form login username |
| `login_password` | Form login password |
| `login_url` | Login page URL (auto-detected) |
| `auth_scenario_json` | Auth scenario JSON DSL for custom login flow/success checks/TOTP |
| `user2_header` | Second user auth for BOLA testing |
| `user2_cookies` | Second user cookies for BOLA testing |

## Reporting Options

| Option | Description |
|--------|-------------|
| `include_partial_attack_chains` | Include partial attack chains in the human-readable report (analyst mode). Full chains always appear in `result.attack_chains.chains`. |

## Scope/Output Options

| Option | Description |
|--------|-------------|
| `focus_rules_json` | JSON array of rules to include only specific endpoint scope |
| `avoid_rules_json` | JSON array of rules to exclude endpoint scope |
| `verified_findings_only` | Keep only findings with exploit verification evidence in final output |

## Focused Active Checks (API)

Use `xss` or `sqli` in scan options:

```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target":"https://api.example.com","options":{"scan_type":"smart","sqli":true}}'

curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.com","options":{"scan_type":"smart","xss":true}}'
```

## CLI Notes

Current `scanner.sh` scan wrappers are:
- `scan` (quick)
- `scan-full`
- `scan-smart`

For `standard`/`deep`/`aggressive` and advanced auth/tuning options, use the API or web UI.
