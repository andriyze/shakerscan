# Operator-authored browser login checks

## Implemented component and current integration status

`api/capabilities/browser_login.py` supplies a shared **internal functional-QA
helper**. It compares the protected page anonymously, performs an explicit
username/password login in an isolated browser context, verifies an operator-defined
authenticated DOM marker, and keeps that same context alive for read-only checks.
It rechecks the protected page and settles admitted requests before finishing QA.
Cookies and localStorage stay in that context; neither is exported to a public
receipt or written to a session-state export by this helper.

`run_browser_login_checks` is the bounded functional-QA wrapper. It accepts at most
20 operator-authored `BrowserReadOnlyCheck` entries (a same-origin URL and visible
CSS selector), performs GET navigations, and returns finalized counts and per-check
indices/statuses. It does not give its caller a raw page or browser-state export.

The canonical **`browser.login_check`** capability is connected to both runtimes.
The Scan compiler emits an explicit, required `qa.browser_login_<slot>` action;
Hunt queues it through the existing `worker_browser` path. Both construct the same
adapter and keep the credential values and browser context inside that action.
This is a login plus fixed read-only QA operation, not a session-export operation.
It does not change existing `browser.navigate`/`browser.interact` permissions,
authenticate other Scan actions, or produce candidates, vulnerability proof or
request observations for subsequent active testing.

The workflow is saved inside the existing encrypted credential envelope. Public
metadata exposes only `browser_login_configured: true`; no selectors, private
URLs, username or password appear in action inputs, metadata or receipts. Profile
version and principal slot are frozen at admission and checked against the exact
ciphertext record **before decryption**. Every transported request rechecks the
owner, target, scope, approval, current profile version and capability binding.
An inactive, expired, rotated or revoked profile fails closed without retry.

Production execution requires the image's installed `/usr/bin/chromium`, a local
credential-enabled worker, TLS verification for HTTPS, and an approved single-origin
workflow. The explicit action reserves 128 HTTP attempts, one state-changing request,
32 browser actions and 210 tool-wall seconds. The saved workflow may only narrow
these limits. Use a budget with enough capacity (for example `balanced`); the Hunt
`fast` profile's 20 browser-action ceiling cannot fund this action.

Remote broker execution, cross-origin SSO, multi-step login, MFA/CAPTCHA automation,
multiple `Set-Cookie` response fields, and browser state handoff to other actions
are not supported. Unsupported transports fail closed. No new workflow-editor UI
is included: configuration and invocation use the APIs below and the existing
Hunt capability interface. Production acceptance still requires the real-browser
and application-stack gates described below.

## Configure and invoke

Save a `form_login` or `json_login` profile through `POST /credential-profiles`,
using the existing target ID, primary/secondary/service slot and operator-provided
username/secret. The profile must explicitly allow `browser.login_check` and set
`allow_active_capabilities: true` because this capability uses credentials and submits
a login POST. The new `browser_login` field has this shape (replace the fixture URLs/selectors with the
application's actual single-origin login and protected-page assertions):

```json
{
  "schema_version": "browser-login-profile/v1",
  "workflow": {
    "origin": "https://app.example.test",
    "login_url": "https://app.example.test/login",
    "submit_url": "https://app.example.test/session",
    "check_url": "https://app.example.test/account",
    "username_selector": "#username",
    "password_selector": "#password",
    "submit_selector": "#sign-in",
    "authenticated_selector": "#private-account",
    "rejected_selector": "#login-error",
    "challenge_selector": "#mfa",
    "timeout_ms": 30000,
    "qa_timeout_ms": 60000,
    "max_requests": 64
  },
  "checks": [
    {"url": "https://app.example.test/account", "visible_selector": "#private-account"}
  ]
}
```

The credential profile's `endpoint_url` remains required by its existing auth-kind
contract. `browser_login` is not an action input. Rotating a browser-configured
profile requires explicitly resubmitting the saved workflow, or explicitly setting
`browser_login: null` to remove it; omission is rejected to prevent silent loss.
Old queued actions do not adopt the new version after rotation.

For **Scan**, use `POST /scans` with the new `browser_login_profile_ids` array,
separate from ordinary `credential_profile_ids`. Select one or two distinct
profiles with different principal slots. The existing approval must be target-bound,
credential-tier, unexpired and authorize `scan.submit`.

```json
{
  "target": "https://app.example.test",
  "budget_profile": "balanced",
  "browser_login_profile_ids": ["<saved-profile-uuid>"],
  "approval_receipt_id": "<approved-scan-receipt-uuid>",
  "policy": {
    "preset": "custom",
    "include_families": ["recon"],
    "active_testing": true,
    "allow_state_changing_http": true
  },
  "options": {"parallel": false}
}
```

Selection narrows Scan execution to one worker. Explicit parallel/remote requests
are rejected; the action cannot be copied into shards or continuation rounds.
Action status and sanitized QA observations use the existing Scan actions/results
interfaces. A failed required QA action is not a successful authenticated result.

For **Hunt**, select the saved profile in the existing start request's
`credential_refs.primary_credential_profile_id`, allow `browser.login_check` in
`capabilities`, and supply the existing target-bound credential approval/scope.
The persisted policy must explicitly include `authorization_confirmed`,
`active_testing` and `allow_state_changing_http`. Then invoke:

```text
POST /hunts/{hunt_id}/capabilities/browser.login_check
```

```json
{"idempotency_key": "browser-login-check-001", "input": {"as_principal": "primary"}}
```

Use `secondary` or `service` only when that slot has exactly one admitted profile
allowing this capability. Planners cannot substitute profile IDs, profile versions,
selectors, login steps or raw credentials in this call. The profile reference is
resolved from the persisted Hunt context again in the worker and compared with the
admitted input digest. Results use existing Hunt action, receipt and budget storage.
Reuse the same idempotency key only to retrieve the same action; select a new key
for a deliberately repeated check.

## Execution contract

A trusted caller supplies a worker-owned Playwright browser, an operator-authored
`BrowserLoginWorkflow`, worker-private `BrowserLoginValues`, and an asynchronous
`transport(request, phase)` returning `BrowserLoginResponse`.

The transport **must reuse existing runtime authority**, including exact target
binding, frozen destination validation, encrypted credential resolution, approval
revalidation, durable budget accounting, response limits and HTTP redaction. It
must not be replaced by an unrestricted HTTP client. This module is not a second
credential store, approval system, network scanner or execution capability.

All document, XHR, fetch and subresource requests are intercepted at context level.
The helper fulfills responses supplied by the transport; it never calls
`route.continue_()` or `route.fallback()`. Off-origin or ambiguous `Location`
headers are rejected before delivery to the browser, independently of redirect
interception behavior. A POST-preserving 307/308 login redirect is unsupported
because it would require a second credential submission. Same-origin 301/302/303
redirect behavior still needs real-browser acceptance on the deployed build.
Service workers, downloads and WebSockets are disabled or blocked. The worker still
owns browser-process containment and shutdown; context interception is not an
OS-level egress audit.

Only the exact configured login endpoint may receive one POST, and only during
submission. GET, HEAD and OPTIONS are the remaining admitted methods. After login,
all further POST/PUT/PATCH/DELETE requests are blocked. A method allowlist cannot
make a badly designed state-changing GET harmless: operators must select ordinary
read-only application workflows. The local request/response ceilings only narrow
execution; they never enlarge the caller's durable budget or permissions.

`timeout_ms` bounds login and each transported request; `qa_timeout_ms` bounds the
entire post-login block, its fixed page checks, and final session verification.
The request ceiling is cumulative across all phases. Even with no extra assets or
application redirects, a successful check now needs five requests: anonymous
protected page, login page, login POST, protected verification, and final protected
verification. Real applications may need more. A too-small ceiling fails closed;
the helper never increases it to make the check pass.

Transport response headers are bounded by count and total bytes, validated before
browser fulfillment, and stripped of hop-by-hop headers and `Connection`-nominated
fields. Case-insensitive duplicates are rejected. The current mapping interface
cannot represent multiple `Set-Cookie` fields faithfully; callers must not fold
them into a single ambiguous value. This limitation remains explicit, not an SSO
or multi-cookie compatibility claim.

## Verification and failure semantics

Before credentials are filled, the same configured protected page must show an
explicit rejection or redirect to the exact configured login form. A marker
already visible anonymously is rejected as `ambiguous_success_assertion`; an
unknown anonymous result is `anonymous_verification_incomplete`, not success.
The authenticated marker must also be absent on the initial login page. A visible
marker after the click alone is insufficient: one login submission must have
received a non-error response, and the marker must survive fresh navigation to
the protected page. `verification_basis=operator_dom_assertion`
qualifies the result. This is a functional authentication assertion, not a finding's
`proof_state`, a guarantee of principal identity, or authorization proof.

An explicit rejection, MFA/CAPTCHA/manual challenge, stale session on the protected
page, transport failure, request exhaustion, timeout or unavailable verification
cannot produce a successful receipt. There is no credential retry, brute force,
challenge bypass or automatic reauthentication. Cross-origin SSO is not supported.
`browser_authentication_state(page, workflow)` can observe expiry after a later
protected-page navigation without resubmitting credentials.

After the read-only block, the helper waits for already admitted requests and
revisits the protected page. Expiry, cancellation, a late transport error, exhausted
request budget or missing verification invalidates the result. Transport failure
is sticky: later requests are blocked rather than silently resuming a failed run.
There is no automatic login retry. Background transports remain the enclosing
worker's responsibility if context teardown fails.

The receipt contains counts and fixed status codes, never credentials, page HTML,
request bodies, response headers, URLs or cookie/storage values. `requests_routed`
counts attempts handed to the transport, **not exact wire use or durable admission**;
`responses_received` counts bounded transport responses. The transport retains
responsibility for exact wire accounting. The context manager yields a **live,
read-only mapping**, so later counts and failures cannot leave a stale successful
snapshot. `requests_in_flight` tracks callbacks still using the transport. Only
normal exit after final verification and context close sets `status=completed`,
`qa_completed=true`, and `context_closed=true`. Copy the mapping after exit to
serialize the finalized receipt; it is not a claim that authentication remains
valid after the check or a continuous monitor of session expiry.

Failed login and cancellation close the context. Close failures cannot replace the
primary cancellation/error and are surfaced as `cleanup_failed` or a fixed
cancellation note. Normal close failure raises `browser_cleanup_failed`. Context
teardown is bounded separately to five seconds; the enclosing worker remains
responsible for reclaiming the browser if teardown fails.

## Internal usage

The following is an integration outline, not a public API or an unrestricted
transport implementation:

```python
result = await run_browser_login_checks(
    worker_browser,
    workflow=operator_workflow,
    values=worker_resolved_values,
    transport=existing_target_bound_authorized_transport,
    checks=(BrowserReadOnlyCheck(operator_read_only_url, "#expected-panel"),),
)
assert result["qa_completed"]
```

Do not expose the raw page/context or private values to a planner. The trusted caller
must not install competing route handlers, change the context's permissions or
interpret successful login as authorization for subsequent active testing.

## Validation

Offline tests exercise orchestration, input validation, private diagnostics,
rejection/challenge/expiry, per-context isolation, single submission, exact origin,
post-login write denial, response/request ceilings and cancellation/cleanup. They
also exercise anonymous negative controls, live receipt updates, late/background
failures, final expiry, full QA deadlines, fixed checks, and malformed headers.

```bash
PYTHONPATH=. python3 -m pytest -q tests/test_browser_login_check.py
```

The real-browser fixture serves every response locally through the injected
transport. It uses synthetic values and tests cookie and localStorage login,
fixed-page QA completion and rejected final verification after expiry. It does not
contact an external application:

```bash
SHAKERSCAN_BROWSER_TEST_EXECUTABLE=/usr/bin/chromium PYTHONPATH=. \
  python3 -m pytest -q tests/integration/test_browser_login_flow.py
```

An administrative policy blocking the loopback navigation is an environment
blocker, not a pass. Do not disable browser policy to make this test green.
Real-browser and full Scan/Hunt acceptance are required before production exposure.
