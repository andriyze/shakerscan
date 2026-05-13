# Smart Adaptive Scan

Run an intelligent adaptive security scan that adjusts based on findings.

**Usage**: `/scan-smart <target_url> [options]`

## Instructions

1. **IMPORTANT**: First ask user for confirmation:
   "This will run a SMART scan which includes active vulnerability testing (XSS, SQLi probes). Do you have permission to test this target? (yes/no)"

2. Only proceed if user confirms with "yes"

3. Check if scanner is running:
   ```bash
   curl -s http://localhost:8080/health
   ```

4. If the user asks for pre-scan route seeding, JS route analysis, or custom endpoint coverage, run these helpers before the scan and feed their output into the payload:
   - `/js-analyze <target>` to build `custom_endpoints` from JS bundles and captured APIs
   - `/content-discovery <target>` to expand with `custom_list`, route seeds, and additional `custom_endpoints`

   Either or both can be used; if both, run `/js-analyze` first so content-discovery can build on its output.

   Example:
   ```bash
   curl -X POST http://localhost:8080/scans \
     -H "Content-Type: application/json" \
     -d '{
       "target": "https://example.com",
       "options": {
         "scan_type": "smart",
         "custom_endpoints": [
           "GET /api/users?id=1",
           "POST /graphql json:{\"query\":\"query Health { health }\"}"
         ]
       }
     }'
   ```

5. Submit **smart** scan:
   ```bash
   curl -X POST http://localhost:8080/scans \
     -H "Content-Type: application/json" \
     -d '{"target": "$ARGUMENTS", "options": {"scan_type": "smart"}}'
   ```

6. Report scan ID and UI link, then STOP:
   ```
   Smart scan submitted: {scan_id}
   View progress: http://localhost:3000/scans/{scan_id}
   ```

**Important**: Do NOT poll or wait - smart scans adapt dynamically and can take variable time.

## What Smart Scan Does

- **Staged Nuclei scanning** (4 waves based on tech + signals)
- **Early stopping** when high-confidence findings detected
- **DBMS fingerprinting** (SQLite, MySQL, PostgreSQL, MSSQL, Oracle)
- **Context-aware XSS** (detects reflection context)
- **DOM XSS static analysis** (source-to-sink flow detection)
- **Adaptive rate limiting** (backs off on 429/503)
- **Attack chain analysis** (correlates findings into exploitable paths)

## Common Options

### With Authentication
```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.example.com",
    "options": {
      "scan_type": "smart",
      "auth_header": "Bearer eyJhbGciOiJIUzI1NiIs..."
    }
  }'
```

### Dual Auth for BOLA/IDOR Testing
```bash
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

### Focused SQLi-only
```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.example.com",
    "options": {
      "scan_type": "smart",
      "sqli": true,
      "auth_header": "Bearer token"
    }
  }'
```

### Focused XSS-only
```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "options": {
      "scan_type": "smart",
      "xss": true
    }
  }'
```

### Thorough Mode (No Early Stop)
```bash
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

## Authentication Options

| Option | Description |
|--------|-------------|
| `auth_header` | Authorization header (e.g., "Bearer token") |
| `auth_cookies` | Session cookies (e.g., "session=abc; token=xyz") |
| `auth_headers_json` | Custom headers as JSON object |
| `user2_header` | Second user auth for BOLA testing |
| `user2_cookies` | Second user cookies for BOLA testing |

## Tuning Options

| Option | Description |
|--------|-------------|
| `xss` | Run only XSS checks |
| `sqli` | Run only SQLi checks |
| `no_early_stop` | Disable early stopping (find all vulns) |
| `thorough_params` | Test more parameters (100×10 vs 50×5) |
| `deep_domxss` | Deep DOM XSS analysis |
| `custom_endpoints` | Array of specific endpoints to test |
