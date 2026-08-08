# ShakerScan Fields For JS Analysis

Set `API_BASE` to the API URL printed by `./scanner.sh status`; it is normally
`http://localhost:8080` for a loopback install.

Use these fields first when a completed scan already exists.

## Pull Scan Context

```bash
curl -s "$API_BASE/scans/{scan_id}/result"
```

Useful jq snippets:

```bash
curl -s "$API_BASE/scans/{scan_id}/result" | jq '{
  endpoints: .discovery.browser_api_endpoints[:25],
  tech: .discovery.tech.items,
  browser_crawl: .discovery.browser_crawl,
  js_dependencies: .js_dependencies,
  js_secrets: .js_secrets,
  smart_coverage: .smart_coverage
}'
```

## High-Value Result Fields

- `result.discovery.browser_api_endpoints`
  Browser-captured API requests. Best seed source for BOLA, IDOR, and API-only scans.
- `result.discovery.tech.items`
  Structured framework and library fingerprinting with evidence.
- `result.discovery.browser_crawl`
  Sample visited pages and depth reached during browser crawling.
- `result.smart_coverage.endpoints`
  Counts for discovered vs tested endpoints.
- `result.smart_coverage.parameters`
  Counts for discovered vs tested query, body, and path parameters.
- `result.smart_coverage.auth_states_tested`
  Anonymous vs multi-user coverage hints.
- `result.js_dependencies`
  Vulnerable/outdated frontend libraries and detected framework versions.
- `result.js_secrets`
  Hardcoded API keys, tokens, or credential-like material in JS.

## ShakerScan-Native Behaviors To Reuse

ShakerScan already performs:

- browser request capture
- JS bundle route and endpoint extraction
- GraphQL and WebSocket string extraction
- React and Next.js version detection
- JS dependency review
- JS secret scanning

Use the scan results before repeating any of that work by hand.

## Output Contract

Return a `custom_endpoints` block in the exact ShakerScan format:

```json
[
  "GET /api/users?id=1",
  "POST /api/search json:{\"query\":\"test\"}",
  "POST /graphql json:{\"query\":\"query Health { health }\"}"
]
```

Also include a ready scan payload:

```bash
curl -X POST "$API_BASE/scans" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "options": {
      "scan_type": "smart",
      "custom_endpoints": [
        "GET /api/users?id=1"
      ]
    }
  }'
```
