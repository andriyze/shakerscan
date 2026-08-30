# Archived interactive testing guide

> **Historical only (archived 2026-08-29).** This describes the pre-2.0 standalone Interactive
> Testing workflow. The UI was removed; `/session*` survives as an agent/Command Arsenal
> compatibility API. Use [`../INTERACTIVE_SESSIONS_GUIDE.md`](../INTERACTIVE_SESSIONS_GUIDE.md)
> for current boundaries and Hunt for new adaptive investigations.

**Status:** live user guide, reconciled 2026-07-20.

Interactive Testing lets you and a coding agent investigate an authorized web application with a
real headless browser. They are useful for authentication flows, multi-step business logic, visual
evidence, and access-control checks that need more context than an automated scan.

An interactive session is not proof by itself and does not expand testing permission. ShakerScan
keeps navigation same-origin by default, separates user contexts, and saves a finding only when the
operator or agent explicitly submits evidence.

## Before you begin

- Test only systems you own or have explicit permission to test.
- Use dedicated test accounts and non-production data when possible.
- Define the target origin and any additional authorized origins.
- Do not paste credentials into findings, chat summaries, or screenshots.
- Treat an HTTP 200, response difference, reflection, or visible route as a lead until controls
  prove security impact.

## Start a session

The easiest route is the project command:

```text
/ai-security-session https://app.example.test
```

Or ask naturally:

```text
Start an interactive security session for my authorized staging app.
Use the two managed test principals to check order ownership.
```

The agent follows `skills/ai-security-session/SKILL.md` and uses the local `/session` API.

### Optional scan context

Existing scan results can provide known routes, browser-captured APIs, technology hints, and
findings to reproduce. If a suitable completed scan exists, the agent can load it first.

If a new scan would help, choose a canonical `fast`, `balanced`, or `thorough` resource budget.
Budget does not imply permission: enable active testing only after explicit authorization.

After a scan is submitted, the agent reports the scan ID and UI link and stops. Start or continue
the interactive session after the scan completes or proceed without that context.

## Session workflow

1. Confirm the authorized origin and objective.
2. Check ShakerScan health.
3. Load an existing scan or note that no scan context is available.
4. Start the browser session and capture the initial page state.
5. Apply the required auth context.
6. Exercise one bounded workflow and record controls.
7. Save only validated findings.
8. End the browser session.

Supported browser actions include:

- same-origin navigation
- click, fill, submit, wait, and extract
- registration and login with dedicated test accounts
- direct bearer/cookie auth setup
- managed credential profiles for `user1` and `user2`
- screenshots
- bounded endpoint replay

Cross-origin navigation or endpoint testing requires explicit authorization and
`allow_out_of_scope: true`.

## Access-control and BOLA/IDOR testing

Use two provably distinct principals. Reusing the same account, token, tenant identity, or copied
session in both browser contexts cannot prove a cross-user authorization failure.

A strong BOLA/IDOR workflow is:

1. Bind distinct managed profiles to `user1` and `user2`, or log in separately.
2. Verify the profiles map to different account identities.
3. As `user1`, create or read a resource and record its identifier.
4. Run the owner control as `user1`.
5. Replay the same identifier as `user2`.
6. Run a denied/nonexistent-object control to rule out generic success pages.
7. Compare status, response structure, sensitive fields, and before/after state.
8. Save a finding only if `user2` receives unauthorized sensitive data or performs an unauthorized
   state change.

For write or delete tests, use disposable records and prove state before and after. Do not infer a
successful mutation from the response status alone.

## Other useful investigations

| Area | Example bounded question |
|---|---|
| Authentication | Does logout invalidate this test session? |
| Tenant isolation | Can a test principal from tenant A read a tenant B object? |
| Business logic | Does the server reject an invalid workflow transition? |
| Mass assignment | Are server-controlled fields ignored or rejected? |
| CSRF | Does a state-changing test action require the expected anti-CSRF control? |
| Finding reproduction | Does the exact recorded request still reproduce under the same scope? |
| Visual evidence | Does the browser show the security-relevant state described by the request proof? |

Keep tests narrow and reversible. Use automated scans for broad discovery, template checks, headers,
TLS, and large endpoint coverage.

## API quick reference

Base URL on the ShakerScan host: `http://localhost:8080`.

```bash
# Start
curl -X POST http://localhost:8080/session/start \
  -H "Content-Type: application/json" \
  -d '{"target":"https://app.example.test"}'

# Read state
curl http://localhost:8080/session/{session_id}

# Capture a PNG
curl -s http://localhost:8080/session/{session_id}/screenshot.png \
  -o /tmp/shakerscan-session.png

# Navigate
curl -X POST http://localhost:8080/session/{session_id}/action \
  -H "Content-Type: application/json" \
  -d '{"action":"navigate","user":"user1","data":{"url":"/orders"}}'

# Apply a managed profile
curl -X POST http://localhost:8080/session/{session_id}/action \
  -H "Content-Type: application/json" \
  -d '{
    "action":"use_credential_profile",
    "user":"user1",
    "data":{"credential_profile_id":"PROFILE_UUID"}
  }'

# Replay one endpoint as user2
curl -X POST http://localhost:8080/session/{session_id}/test-endpoint \
  -H "Content-Type: application/json" \
  -d '{"endpoint":"/api/orders/42","method":"GET","as_user":"user2"}'

# End and clean up
curl -X DELETE http://localhost:8080/session/{session_id}
```

See [`../../skills/ai-security-session/references/api.md`](../../skills/ai-security-session/references/api.md)
for the request shapes.

## Saving a finding

Session findings are linked to the session target and marked with `source_type=ai_session`.

Before saving, include:

- exact endpoint and method
- principal roles and proof they are distinct
- owner and attacker results
- a negative or nonexistent-object control
- sensitive data or state impact
- redacted request and response evidence
- remediation

```bash
curl -X POST http://localhost:8080/session/{session_id}/findings \
  -H "Content-Type: application/json" \
  -d '{
    "title":"BOLA on order detail API",
    "severity":"high",
    "description":"A distinct second principal can read the first principal order.",
    "category":"BOLA",
    "cwe":"CWE-639",
    "url":"/api/orders/42",
    "evidence":"Owner, attacker, and negative-control evidence...",
    "request":"GET /api/orders/42 ...",
    "response":"Redacted sensitive response...",
    "remediation":"Enforce object ownership on every order lookup."
  }'
```

Review saved findings at `http://localhost:3000/findings` or filter them:

```bash
curl "http://localhost:8080/findings?source_type=ai_session&status=active"
```

If the proof is incomplete, do not save a confirmed vulnerability. Record the lead and missing
evidence in the session notes or research workflow instead.

## Troubleshooting

### The session expired

Sessions close after inactivity. Start a new session and reapply the managed profiles.

### A screenshot does not load

Use the raw PNG endpoint again and verify the requested user context exists:

```bash
curl -s "http://localhost:8080/session/{session_id}/screenshot.png?user=user1" \
  -o /tmp/shakerscan-session.png
```

### The endpoint is rejected as out of scope

Verify the URL. Keep the request same-origin unless the additional origin is explicitly authorized.
Only then use `allow_out_of_scope: true`.

### The two users behave identically

Confirm they are truly distinct accounts and that the resource belongs to only one of them. A
shared, public, or nonexistent resource does not prove BOLA.

### The browser or API contains secrets

Stop, avoid copying the value into notes, and rotate the credential if it was exposed unexpectedly.

## Related workflows

- [`../../README.md`](../../README.md) for installation and workflow selection
- [`../AI_TEST_WORKFLOWS.md`](../AI_TEST_WORKFLOWS.md) for AI Gate and Model Intake
- [`../functionality-reference.md`](../functionality-reference.md) for the exhaustive API and UI map
- `/save-finding` for the evidence-gated finding workflow
- `/deep-hunt` for the canonical AI-driven investigation; compatibility `/research/*` workflows are
  reserved for specialized guided verification and legacy runs
