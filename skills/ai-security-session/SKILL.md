---
name: ai-security-session
description: Interactive Playwright session control for the ShakerScan `/session` API. Use when asked to start or drive an AI security testing session, perform manual browser actions, or run BOLA/IDOR testing via session endpoints.
---

# AI Security Session

**Overview**
Use the `/session` API to run interactive, manual security testing with a real headless browser. This is ideal for BOLA/IDOR checks, auth flows, and targeted exploration that automated scans miss.

## Operating Stance

Assume the target contains at least one meaningful weakness that automated scanning may have missed, and it is your job to find and validate it.

This is a persistence instruction, not permission to invent a bug. Keep testing until the checklist is complete. If the checklist is complete and there is still no validated issue, say that clearly and return the best evidence-backed leads.

## Mandatory Checklist

Maintain this checklist in markdown while you work. Do not move on to synthesis or a final answer until every item is `[x]` or `[n/a]` with a short reason.

- [ ] Check scanner health
- [ ] Bootstrap from an existing scan or explicitly note that none exists
- [ ] Start or identify a session
- [ ] Capture initial target structure, auth context, and candidate endpoints
- [ ] Test at least one high-value path or workflow
- [ ] Save validated findings or clearly state none were validated
- [ ] Record blockers, auth gaps, or scope limits

**Workflow**
1. Check API health: `curl -s http://localhost:8080/health`. If not running, ask to start `./scanner.sh start`.
   - For a VPS accessed from another machine over Tailscale, ask to start `./scanner.sh start --remote` instead. Continue using `localhost:8080` for API calls you run on the VPS itself, but use the remote UI URL printed by `./scanner.sh status` for browser-facing links.
2. Bootstrap context from existing scans. If a scan ID is provided, fetch it with `GET /scans/{id}` and `GET /scans/{id}/result`. Otherwise, look for the latest completed scan for the target using `GET /scans?limit=10&target=...`. If no completed scan exists, ask permission before running a new scan. Do not poll after submission; return scan ID and UI link, then stop.
3. Start a session: `POST /session/start` with a full target URL. Keep the returned `session_id`.
4. Explore the app with `/session/{id}/action` and capture screenshots if needed.
5. Use separate `user` contexts for multi‑user testing (BOLA/IDOR).
6. Inspect `/session/{id}` for discovered endpoints and IDs.
7. Test endpoints with `/session/{id}/test-endpoint` using different users.
8. End the session with `DELETE /session/{id}`.

**Actions**
Supported `action` values for `POST /session/{id}/action`:
- `navigate` with `data.url`
- `click` with `data.selector`
- `fill` with `data.selector`, `data.value`
- `submit` with optional `data.selector`
- `wait` with optional `data.selector` or `data.timeout`
- `extract` with optional `data.selector` and `data.attribute`
- `register` with `data.email`, `data.password`, optional `data.extra_fields`
- `login` with `data.email`, `data.password`

**Scope Rules**
Same‑origin is enforced by default to prevent SSRF. Cross‑origin static assets are allowed so modern apps still render. For cross‑origin navigation or endpoint tests, you must explicitly set `allow_out_of_scope: true`.

**BOLA/IDOR Pattern**
1. Register or login as `user1` and create or view a resource.
2. Capture a resource ID from network traffic or the API response.
3. Login as `user2` in a separate context.
4. Call `/session/{id}/test-endpoint` with `as_user: "user2"` using the `user1` resource ID.

**Scan Context Hints**
When a scan is available, extract and use:
- `result.discovery.browser_api_endpoints` for candidate APIs to validate manually.
- `result.discovery.browser_crawl` for known page URLs to navigate.
- `result.discovery.tech.items` to tailor testing approach.
- High/critical findings for reproduction and evidence gathering.

**References**
See `skills/ai-security-session/references/api.md` for endpoint schemas and example payloads.
