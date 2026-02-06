# Full Security Assessment

Run a comprehensive security assessment with ALL security tests including active XSS/SQLi.

**Usage**: `/scan-full <target_url>`

## Instructions

1. **IMPORTANT**: First ask user for confirmation:
   "This will run a FULL security assessment including active vulnerability testing (XSS, SQLi probes). This may trigger security alerts on the target. Do you have permission to test this target? (yes/no)"

2. Only proceed if user confirms with "yes"

3. Check if scanner is running:
   ```bash
   curl -s http://localhost:8080/health
   ```

4. Submit **full** assessment:
   ```bash
   curl -X POST http://localhost:8080/scans \
     -H "Content-Type: application/json" \
     -d '{"target": "$ARGUMENTS", "options": {"scan_type": "full"}}'
   ```

5. Report scan ID and UI link, then STOP:
   ```
   Full assessment submitted: {scan_id}
   Expected duration: 1-2 hours
   View progress: http://localhost:3000/scans/{scan_id}
   ```

**Important**: Do NOT poll or wait for completion - full scans take 1-2 hours. Users can check results via UI or ask later.

6. When user asks for results later, provide a comprehensive report

## What Full Scan Includes

Everything in **deep** scan PLUS:
- Active XSS testing (dalfox)
- Active SQLi testing (sqlmap)
- WebSocket security testing
- CSRF vulnerability testing
- IDOR/BOLA testing
- File upload vulnerability testing
- Open redirect testing
- Host header injection testing
- Business logic vulnerability detection
- API security testing (mass assignment, BFLA)
- Session management testing
- Rate limiting testing
- 2FA bypass testing
- Password reset vulnerability testing
- Default credentials testing

## Report Format

```
✓ Full assessment completed in 1h 23m

┌─────────────────────────────────────┐
│  Grade: B    Score: 82/100          │
└─────────────────────────────────────┘

🔒 TLS/SSL
├─ Certificate: example.com (Let's Encrypt R3)
├─ Expires: 45 days remaining
├─ Key: RSA 4096-bit
└─ OCSP Stapling: Enabled

🛡️  Security Headers
├─ HSTS: ✓ (max-age=31536000, includeSubDomains)
├─ CSP: Grade D (64/100)
│   ⚠️  script-src allows 'unsafe-inline'
│   ⚠️  script-src allows 'unsafe-eval'
├─ X-Frame-Options: ✓ SAMEORIGIN
├─ Referrer-Policy: ✓ no-referrer
└─ Permissions-Policy: ✓ Set

🔧 Technology Stack
├─ React 18 (confirmed)
├─ Django (likely)
└─ Python (implied)

🌐 API Endpoints Discovered: 3
├─ POST /api/send
├─ GET /rest/v1/users (auth)
└─ GET /rest/v1/data (auth)

🔍 Findings Summary
├─ 🔴 0 Critical
├─ 🟠 1 High
├─ 🟡 5 Medium
├─ 🔵 8 Low
└─ ⚪ 12 Info

📋 Critical & High Findings:
1. [High] SQL Injection in /api/search (CWE-89)
   Parameter: query
   Payload: ' OR 1=1--

📊 Full report: http://localhost:3000/scans/{id}
```

## Alternative: Aggressive Scan

For maximum coverage (2+ hours), use aggressive mode:
```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "options": {"scan_type": "aggressive"}}'
```

Aggressive adds:
- Full port scan (65535 ports)
- Aggressive exploit level
- Threat intelligence checks
- Extended fuzzing and discovery
