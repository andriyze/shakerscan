# Scan a target

Run a security scan on the specified target.

**Usage**: `/scan <target_url>`

## Instructions

1. First check if the scanner is running:
   ```bash
   curl -s http://localhost:8080/health
   ```
   If not running, ask user if they want to start it with `./scanner.sh start`

2. Submit a **quick** scan (default):
   ```bash
   curl -X POST http://localhost:8080/scans \
     -H "Content-Type: application/json" \
     -d '{"target": "$ARGUMENTS", "options": {"scan_type": "quick"}}'
   ```

3. Extract the `scan_id` from response

4. Poll for completion every 10 seconds:
   ```bash
   curl http://localhost:8080/scans/{scan_id}
   ```

5. When status is "completed", extract and report the rich data:

   The API returns a `result` object with detailed scan data:
   - `result.http.csp_evaluation` - CSP grade, score, issues, directives
   - `result.http.security_headers` - HSTS, X-Frame-Options, Referrer-Policy, etc.
   - `result.tls.certificate` - subject, issuer, days_remaining, key_size, key_algo
   - `result.discovery.tech.items` - detected technologies with versions and confidence
   - `result.dns` - A, AAAA, MX, SPF, DMARC, DNSSEC records

6. Format output like the example below

## Scan Types

| Type | Option | Time | Description |
|------|--------|------|-------------|
| quick | `"scan_type": "quick"` | 1-2 min | DNS, TLS, headers (default) |
| standard | `"scan_type": "standard"` | 5-10 min | + Nuclei, JS deps |
| deep | `"scan_type": "deep"` | 30-60 min | + port scan, discovery |
| full | `"scan_type": "full"` | 1-2 hrs | + active XSS/SQLi |
| aggressive | `"scan_type": "aggressive"` | 2+ hrs | maximum coverage |

**Note**: `full` and `aggressive` require user permission (active testing).

## Example Output

```
Scanning https://example.com...

✓ Scan completed in 1m 23s

┌─────────────────────────────────────┐
│  Grade: C    Score: 72/100          │
└─────────────────────────────────────┘

📋 SUMMARY
├─ TLS: Let's Encrypt R3, expires in 45 days, RSA 4096-bit
├─ CSP: Grade D (64/100) - 3 issues
├─ HSTS: ✓  X-Frame-Options: ✓  Referrer-Policy: ✓
└─ Tech: React 18, Django, Python

⚠️  CSP Issues:
  • script-src allows 'unsafe-inline'
  • script-src allows 'unsafe-eval'

🔍 Findings (12 total):
  • 0 Critical, 0 High, 3 Medium, 4 Low, 5 Info

Top Issues:
1. [Medium] CSP: script-src allows 'unsafe-inline'
2. [Medium] CSP: script-src allows 'unsafe-eval'
3. [Low] OCSP stapling not detected

📊 View full report: http://localhost:3000/scans/{scan_id}
```

## Data Extraction

```bash
# Get CSP details
curl -s http://localhost:8080/scans/{id} | jq '.result.http.csp_evaluation'

# Get security headers
curl -s http://localhost:8080/scans/{id} | jq '.result.http.security_headers'

# Get TLS cert info
curl -s http://localhost:8080/scans/{id} | jq '.result.tls.certificate'

# Get tech stack
curl -s http://localhost:8080/scans/{id} | jq '.result.discovery.tech.items'
```
