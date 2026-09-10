# Browser session materialization is not login verification

The existing `seed_browser_profile` helper prepares private browser state. It does not
submit a login form or prove that the application accepts a session. A session already
stored in cookies or localStorage also does not reproduce the request that originally
created that session.

## Materialization contract

Inputs come from worker-resolved credential material, not planner-supplied secrets.
The helper validates the origin, seed, Cookie request-header form, executable, and
fresh profile path before allocating the profile. Cookie-header attributes such as
`Domain`, `Path`, `Secure`, and `HttpOnly` are rejected rather than silently treated as
ordinary Cookie request-header data. Empty cookie values remain represented. Private profile copies receive a bounded
one-hour expiry so Chromium retains them across bootstrap-process restart; the
worker still removes its scratch profile after use, and this does not extend
server-side authentication or credential/approval expiry.

During materialization, service workers are blocked. A context-level request handler
locally fulfills only the exact-origin GET bootstrap navigation needed for
localStorage; it aborts other routed requests. The bootstrap is inert HTML with a
restrictive Content Security Policy. This handler applies only to seeding, not to the
later crawl. It neither grants target permission nor replaces the worker's existing
scope, destination, and budget enforcement.

Readback must confirm that the requested state was installed before the helper emits
success. Its receipt retains the existing fields and adds:

```json
{
  "storage_seed_verified": true,
  "authentication_verified": false
}
```

`storage_seed_verified` means local readback succeeded before closing the bootstrap
browser. It does not prove persistence across arbitrary consumer launch settings,
application authentication, principal identity, authorization, or vulnerability proof.
`target_requests: 0` continues to describe the locally fulfilled bootstrap operation;
it is not a claim of OS-level capture of all browser background traffic.

Browser failures produce a fixed public error without private browser diagnostics.
Failed materialization removes only the newly allocated profile. Cancellation stays
cancellation even when context close also raises an ordinary exception. Cleanup failure
is explicitly reported; the enclosing worker still owns scratch-directory teardown.
An existing directory or symlink is never adopted or deleted. After success, normal
worker scratch teardown remains responsible for removing the profile.

## Discovery metadata integrity

`public_request_body_shape` never stringifies non-text bodies. JSON arrays, strings,
malformed object-like inputs, decoder-depth failures, and BOM-prefixed inputs must not
fall through to form parsing and expose JSON values as public field names. The existing
valid JSON-object and URL-encoded-form shapes remain supported. This does not execute
requests or generate missing login observations.

## Tests

The unit suite uses a fake browser that models writes, rejection, cancellation, routing,
and close failures. It is not evidence of a successful application login.

```bash
PYTHONPATH=. python3 -m pytest -q \
  tests/test_request_shape_integrity.py tests/test_request_shape_bom.py \
  tests/test_browser_profile.py tests/test_browser_profile_runtime.py
```

The opt-in browser suite uses an installed Chromium executable and synthetic state.
No application credentials or external targets are required. Its localStorage scenario
uses a locally intercepted loopback URL. It must fail, rather than silently pass, when
browser policy prevents that navigation.

```bash
SHAKERSCAN_BROWSER_TEST_EXECUTABLE=/usr/bin/chromium PYTHONPATH=. \
  python3 -m pytest -q tests/integration/test_browser_profile_restore.py
```

## Boundary for subsequent login work

Do not make read-only browser capabilities silently admit login POSTs. Interactive
login needs an operator-defined workflow, separately authorized state-changing
requests, exact approved destinations, encrypted credential references, and a
post-login assertion. Successful login, session expiry, and application authorization
must be observable independently of crawl completion. Reuse the existing credential
store, target binding, approval and budget machinery rather than adding a parallel
browser authority model. These interactive-login features are not implemented by
this materialization patch; automated exploit execution is unchanged.
