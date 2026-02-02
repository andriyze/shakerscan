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

## API Endpoints

The scanner exposes these endpoints at `http://localhost:8080`:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scans` | POST | Submit a new scan |
| `/scans` | GET | List all scans |
| `/scans/{id}` | GET | Get scan details |
| `/scans/{id}/result` | GET | Get full scan result JSON |
| `/scans/{id}/cancel` | POST | Cancel a running scan |
| `/findings` | GET | List findings |
| `/findings/{id}` | PATCH | Update finding status |
| `/targets` | GET/POST | Manage targets |
| `/discovery` | POST | Start subdomain discovery |
| `/dashboard` | GET | Get dashboard metrics |
| `/queue/stats` | GET | Get queue status |
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

# List findings
curl "http://localhost:8080/findings?severity=critical&status=active"

# Subdomain discovery
curl -X POST "http://localhost:8080/discovery?root_domain=example.com"

# Cancel a scan
curl -X POST http://localhost:8080/scans/{scan_id}/cancel

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
| `user2_header` | Second user auth for BOLA testing |
| `user2_cookies` | Second user cookies for BOLA testing |

## Reporting Options

| Option | Description |
|--------|-------------|
| `include_partial_attack_chains` | Include partial attack chains in the human-readable report (analyst mode). Full chains always appear in `result.attack_chains.chains`. |

## Focused Active Checks (CLI)

Use `--sqli` or `--xss` to run only those active checks (implies `--active`):

```bash
./scanner.sh scan-smart https://example.com --sqli --auth-header "Bearer token"
./scanner.sh scan-smart https://example.com --xss --auth-cookies "session=abc123"
```
