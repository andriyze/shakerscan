# AI Boundary regression handoff

**Status:** versioned offline export and evaluation for completed deterministic
AI Boundary scans.

`POST /ai/targets/{target_id}/boundary/regressions/export` accepts a ready
proposal, the existing `boundary_base` fixture definition, and a completed
`source_scan_id`. It returns a versioned, content-addressed artifact only when
the source scan belongs to that AI target, used the same deterministic Boundary
contract, completed coverage, and passed the backend denial plus both principals'
legitimate chat controls. A failed source also needs a matching deterministic
verified finding. An inconclusive source cannot seed a regression artifact.

The artifact carries the proposal, fixture definition, environment, scan profile,
contract digest, source scan identity and time, and exact acceptance criteria.
It contains no approval receipt and grants no execution or proof authority.
Treat the proposal and fixture definition as operator data; do not put secrets in
them. CI may keep the artifact and separately submit its `verify_request` to
the existing `/ai/targets/{target_id}/boundary/verify` route under current
authorization. Queueing and polling remain the client's responsibility.

`POST /ai/targets/{target_id}/boundary/regressions/evaluate` accepts that artifact
and a later `scan_id`. The server reloads both scans for the exact AI target and
rebuilds the source artifact before comparing the later scan. It requires the
same contract, environment, profile, complete coverage, no violations, and all
three legitimate controls. Its result is `pass`, `fail`, or `inconclusive`; it
does not change findings or proof. This is an offline comparison of stored
results, not a second AI verifier.
