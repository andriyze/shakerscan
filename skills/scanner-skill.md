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
- **Recursive discovery**: Adapts depth based on findings
- **Adaptive rate limiting**: Backs off on 429/503, speeds up on success

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
| `user2_header` | Second user auth for BOLA/IDOR testing |
| `user2_cookies` | Second user cookies for BOLA/IDOR testing |

### Reporting Options

| Option | Description |
|--------|-------------|
| `include_partial_attack_chains` | Include partial attack chains in the human-readable report (analyst mode). Full chains always appear in `result.attack_chains.chains`. |

### Check Scan Status

```bash
curl http://localhost:8080/scans/{scan_id}
```

### List Findings

```bash
curl "http://localhost:8080/findings?status=active"
curl "http://localhost:8080/findings?severity=critical"
```

### Update Finding Status

```bash
curl -X PATCH http://localhost:8080/findings/{id} \
  -H "Content-Type: application/json" \
  -d '{"status": "resolved", "notes": "Fixed in v2.0"}'
```

Status options: `active`, `resolved`, `false_positive`, `accepted_risk`

### Subdomain Discovery

```bash
curl -X POST "http://localhost:8080/discovery?root_domain=example.com"
```

### Dashboard & Queue

```bash
curl http://localhost:8080/dashboard
curl http://localhost:8080/queue/stats
curl http://localhost:8080/health
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
- `waf_detection` - WAF product detection
- `cors` - CORS misconfiguration
- `nuclei` - Nuclei vulnerability findings
- `attack_chains` - attack chain analysis (complete + optional partial chains)

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
