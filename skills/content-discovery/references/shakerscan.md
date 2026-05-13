# ShakerScan Fields For Content Discovery

## Pull Existing Discovery First

```bash
curl -s http://localhost:8080/scans/{scan_id}/result
```

Useful jq snippets:

```bash
curl -s http://localhost:8080/scans/{scan_id}/result | jq '{
  endpoints: .discovery.browser_api_endpoints[:25],
  tech: .discovery.tech.items,
  browser_crawl: .discovery.browser_crawl,
  smart_coverage: .smart_coverage,
  attack_chains: .attack_chains.summary
}'
```

## Relevant ShakerScan Inputs

- `result.discovery.browser_api_endpoints`
  Good seeds for API path discovery and targeted route fuzzing.
- `result.discovery.tech.items`
  Framework and server fingerprints to derive app-specific paths.
- `result.discovery.browser_crawl`
  Visited pages and crawl depth to avoid rediscovering obvious paths.
- `result.smart_coverage.discovery_sources`
  Indicates whether JS bundle analysis, HAR capture, or URL crawling already ran.
- `result.smart_coverage.parameters`
  Helps decide whether to build file or route seeds around path params, body params, or query params.

## ShakerScan APIs To Reuse

- `POST /discovery?root_domain=example.com`
  Subdomain discovery.
- `POST /scans`
  Use `custom_endpoints` to steer smart scans toward content-discovery output.
- `GET /scans/{id}/result`
  Preferred source of existing discovery data.

## Output Contract

Return two machine-usable blocks.

### `custom_list`

Plain text paths only:

```text
/admin
/api/admin
/swagger
/.env
/backup.zip
```

### `custom_endpoints`

Only include entries that make sense as ShakerScan scan inputs:

```json
[
  "GET /api/admin/users?id=1",
  "GET /swagger.json",
  "POST /graphql json:{\"query\":\"query Introspection { __typename }\"}"
]
```

### Examples

`ffuf`:

```bash
ffuf -u https://example.com/FUZZ -w custom_list.txt -mc all -fc 404
```

ShakerScan:

```bash
curl -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "options": {
      "scan_type": "smart",
      "custom_endpoints": [
        "GET /swagger.json"
      ]
    }
  }'
```
