# AI Boundary regression handoff

**Status:** versioned offline export and evaluation for completed deterministic
AI Boundary scans.

## Operator workflow

Open **AI Gate → Agent boundary workflow**, or follow a candidate link from a
Hunt's final debrief. Load the Hunt and choose its candidate, then deliberately
select the AI target that represents the same application. The page displays
both the Hunt asset and the AI endpoint for review. Enter the two controlled
principals and any operator-confirmed business rule. Candidate inspection and
proposal compilation use the existing read-only routes; a ready proposal is
still unverified.

Use the AI target's saved Boundary fixture, or enter its base contract without
credentials. Validate the fixture, select the environment and scan profile, and
choose **Queue verification**. This explicit action enters the existing AI Gate
authorization, credential, scope, budget, worker, evidence, and proof path.
Refresh the queued Scan's status; a completed, matching scan can export a
regression artifact. Download that artifact to keep it between sessions.

To rerun, paste the saved artifact into the page and choose **Load saved
artifact**. Review the displayed target and allowed controls, then explicitly
queue a new verification. Once its Scan completes, evaluate the later Scan
against the artifact. The server reloads both Scan rows and validates the
source-bound artifact before returning `pass`, `fail`, or `inconclusive`.
Loading the saved artifact also rebuilds it from the stored source Scan and
compares its content hash before the page enables a rerun.

The fixture-backed workflow test in `tests/test_ai_boundary_hunt_workflow.py`
exercises Hunt candidate ownership, route handoff, canonical verification
queueing, the real loopback Boundary verifier, deterministic proof, and later
regression evaluation. Its queue adapter is isolated; live target authorization
and worker admission remain covered by their own API and acceptance tests.

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
