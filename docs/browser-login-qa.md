# Operator-authored browser login checks

## Implemented component and current integration status

`api/capabilities/browser_login.py` supplies a shared **internal functional-QA
helper**. It performs an explicit username/password login in an isolated browser
context, verifies an operator-defined authenticated DOM marker, navigates again to
a protected page, and keeps that same context alive for read-only browser checks.
Cookies and localStorage stay in that context; neither is exported to a public
receipt or written to a session-state export by this helper.

This is **not yet a public DAST/Hunt login feature**. No capability-registry entry,
credential-profile schema, worker dispatch, encrypted browser-state persistence,
UI workflow editor, MCP action, or automatic DAST candidate/proof integration has
been added. Existing read-only capabilities and attack dispatch are unchanged.
The helper must not be advertised as an enabled Scan/Hunt action before that
integration and its real-stack acceptance pass.

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

## Verification and failure semantics

The authenticated marker must be absent on the initial anonymous login page. A
visible marker after the click alone is insufficient: one login submission must
have received a non-error response, and the marker must survive fresh navigation
to the configured protected page. `verification_basis=operator_dom_assertion`
qualifies the result. This is a functional authentication assertion, not a finding's
`proof_state`, a guarantee of principal identity, or authorization proof.

An explicit rejection, MFA/CAPTCHA/manual challenge, stale session on the protected
page, transport failure, request exhaustion, timeout or unavailable verification
cannot produce a successful receipt. There is no credential retry, brute force,
challenge bypass or automatic reauthentication. Cross-origin SSO is not supported.
`browser_authentication_state(page, workflow)` can observe expiry after a later
protected-page navigation without resubmitting credentials.

The receipt contains counts and fixed status codes, never credentials, page HTML,
request bodies, response headers, URLs or cookie/storage values. `requests_routed`
counts attempts handed to the transport, **not exact wire use or durable admission**;
`responses_received` counts bounded transport responses. The transport retains
responsibility for exact wire accounting. Login receipts are snapshots, not a
continuous assertion that a session remains valid.

Failed login and cancellation close the context. Close failures cannot replace the
primary cancellation/error and are surfaced as `cleanup_failed` or a fixed
cancellation note. Normal close failure raises `browser_cleanup_failed`. Context
teardown is bounded separately to five seconds; the enclosing worker remains
responsible for reclaiming the browser if teardown fails.

## Internal usage

The following is an integration outline, not a public API or an unrestricted
transport implementation:

```python
async with authenticated_browser_page(
    worker_browser,
    workflow=operator_workflow,
    values=worker_resolved_values,
    transport=existing_target_bound_authorized_transport,
) as (page, login_receipt):
    await page.goto(operator_read_only_url, wait_until="domcontentloaded")
    state = await browser_authentication_state(page, operator_workflow)
```

Do not expose the raw page/context or private values to a planner. The trusted caller
must not install competing route handlers, change the context's permissions or
interpret successful login as authorization for subsequent active testing.

## Validation

Offline tests exercise orchestration, input validation, private diagnostics,
rejection/challenge/expiry, per-context isolation, single submission, exact origin,
post-login write denial, response/request ceilings and cancellation/cleanup.

```bash
PYTHONPATH=. python3 -m pytest -q tests/test_browser_login_check.py
```

The real-browser fixture serves every response locally through the injected
transport. It uses synthetic values and tests cookie and localStorage login,
protected-page navigation and expiry. It does not contact an external application:

```bash
SHAKERSCAN_BROWSER_TEST_EXECUTABLE=/usr/bin/chromium PYTHONPATH=. \
  python3 -m pytest -q tests/integration/test_browser_login_flow.py
```

An administrative policy blocking the loopback navigation is an environment
blocker, not a pass. Do not disable browser policy to make this test green.
Real-browser and full Scan/Hunt acceptance are required before production exposure.
