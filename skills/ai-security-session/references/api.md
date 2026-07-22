# AI Security Session API Reference

## Base URL
`http://localhost:8080`

## Endpoints

### Start Session
`POST /session/start`

Request body:
```json
{
  "target": "https://example.com/login"
}
```

Response (example):
```json
{
  "success": true,
  "session_id": "...",
  "target": "https://example.com/login",
  "current_url": "https://example.com/login",
  "message": "Session started successfully"
}
```

Notes:
- URLs with embedded credentials (`user:pass@host`) are rejected.

### Get Session State
`GET /session/{session_id}`

Response includes:
- `users` auth state
- `discovered_endpoints`
- `discovered_ids`
- `network_log_count`

### Screenshot
`POST /session/{session_id}/screenshot`

Query params:
- `full_page` (boolean, default false)
- `user` (string, default `default`)

Use `GET /session/{session_id}/screenshot.png` for raw PNG bytes.

### Browser Action
`POST /session/{session_id}/action`

Request body:
```json
{
  "action": "navigate",
  "user": "default",
  "data": {"url": "/login"}
}
```

Common actions:
- `navigate`: `data.url`, optional `data.allow_out_of_scope`
- `click`: `data.selector`
- `fill`: `data.selector`, `data.value`
- `set_auth`: bearer header or cookie data
- `use_credential_profile`: `data.credential_profile_id`; supported for managed `user1` or `user2`
- `submit`: optional `data.selector`
- `wait`: optional `data.selector` or `data.timeout`
- `extract`: optional `data.selector`, `data.attribute`
- `register`: `data.email`, `data.password`, optional `data.extra_fields`
- `login`: `data.email`, `data.password`

### Test Endpoint (BOLA/IDOR)
`POST /session/{session_id}/test-endpoint`

Request body:
```json
{
  "endpoint": "/api/items/42",
  "method": "GET",
  "as_user": "user2",
  "allow_out_of_scope": false
}
```

Notes:
- `body` may be provided for `POST`, `PUT`, `PATCH`.
- `allow_out_of_scope: true` allows explicitly authorized cross-origin tests.
- A 200 response or response difference is a lead, not proof by itself. Confirm distinct principals,
  ownership, sensitive data or state impact, and control behavior.

### Save A Session Finding

`POST /session/{session_id}/findings`

Provide `title` and `severity` plus evidence-backed fields such as `description`, `category`, `cwe`,
`url`, `evidence`, `request`, `response`, and `remediation`. The target is derived from the session.

### End Session
`DELETE /session/{session_id}`

### List Sessions
`GET /sessions`

## Example BOLA Flow
1. Login as `user1` and create a resource.
2. Identify the resource ID (from `GET /session/{id}` or API responses).
3. Login as `user2` in a separate context.
4. Call `test-endpoint` with `as_user: "user2"` and the `user1` resource ID.

Example:
```bash
curl -X POST "http://localhost:8080/session/{id}/test-endpoint" \
  -H "Content-Type: application/json" \
  -d '{"endpoint":"/api/items/42","method":"GET","as_user":"user2"}'
```
