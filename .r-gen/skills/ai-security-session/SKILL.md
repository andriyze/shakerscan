---
name: ai-security-session
description: Interactive Testing through ShakerScan's `/session` API. Use when asked to test manually, open an interactive browser session, exercise authentication workflows, or perform BOLA/IDOR endpoint replay.
---

# Interactive Testing

**Overview**
Use the `/session` API to run interactive, manual security testing with a real headless browser. This is ideal for BOLA/IDOR checks, auth flows, and targeted exploration that automated scans miss.

## Operating Stance

Work evidence-first. Test the authorized workflow thoroughly, but do not assume a weakness exists.
A successful response, cross-user difference, or unusual UI state is a lead until the applicable
authorization and proof checks confirm impact.

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
1. Check API health at the API URL printed by `./scanner.sh status` (normally
   `http://localhost:8080` for a loopback install). If it is not running, ask to start
   `./scanner.sh start`.
   - For a VPS accessed from another machine over Tailscale, ask to start
     `./scanner.sh start --remote` instead. Remote mode can bind only to the Tailscale address, even
     for calls made on that VPS, so use both the API and UI URLs printed by `./scanner.sh status`.
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
- `set_auth` with a bearer header or cookie data
- `use_credential_profile` with `data.credential_profile_id` for a managed `user1` or `user2` profile
- `submit` with optional `data.selector`
- `wait` with optional `data.selector` or `data.timeout`
- `extract` with optional `data.selector` and `data.attribute`
- `register` with `data.email`, `data.password`, optional `data.extra_fields`
- `login` with `data.email`, `data.password`

**Scope Rules**
Same-origin is enforced by default to prevent SSRF. Cross-origin static assets are allowed so modern
apps still render. Set `allow_out_of_scope: true` only when the user has explicitly authorized that
additional origin.

**BOLA/IDOR Pattern**
1. Apply distinct managed profiles or register/login separately as `user1` and `user2`.
2. Verify the profiles represent distinct account identities.
3. As `user1`, create or view a resource and capture its identifier.
4. Replay the `user1` identifier as `user2`.
5. Compare with an owner control and a denied/nonexistent-object control.
6. Save a finding only when the replay proves unauthorized sensitive access or state change.

**Scan Context Hints**
When a scan is available, extract and use:
- `result.discovery.browser_api_endpoints` for candidate APIs to validate manually.
- `result.discovery.browser_crawl` for known page URLs to navigate.
- `result.discovery.tech.items` to tailor testing approach.
- High/critical findings for reproduction and evidence gathering.

**References**
See `skills/ai-security-session/references/api.md` for endpoint schemas and example payloads.
