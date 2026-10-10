# Hunt instruction, learning and planner boundaries

**Status:** Instruction CRUD (behind its own opt-in), proposals, the startup briefing and automatic learning implemented; scoped ingress is opt-in.

These controls keep default-on metadata editing, operator opt-outs, standing
authorization and same-asset service reuse. Editing operator instructions is a
separate permission, off by default. It is not an AISVS compliance claim.

## Effective instruction changes, not hidden drafts

The existing versioned `target_skill` record has two bounded sections, not two
target inventories. `operator_skill` retains its compatibility field name but now
means effective instructions: operator-written, written by Hunt under the
target's saved `instruction_changes` permission, or applied from an accepted
instruction proposal. `knowledge` contains learned advisory
context. Each section is limited to 12,000 characters. They share the existing
revision check and 20-entry history.

`targets.skill.create|update|delete` defaults to `purpose: instructions`, which
is refused unless the operator turned on the target's `instruction_changes`
permission (saved through `PUT /targets/{id}/hunt-authority` or the UI's Hunt
permissions; off for every target, including targets whose permissions were
saved before the setting existed). Metadata delegation never permits it. The
refusal names `targets.skill.propose`. A successful authorized update changes
the instructions loaded by future Hunts.
A successful deletion removes those active instructions; it does not leave a
hidden operator baseline in force. Existing Hunt admission snapshots and revision
history remain immutable. No additional UI save is required.

Use `purpose: knowledge` on those same capabilities to create, update or remove
learned context. Future Hunts automatically receive that context in
`target_skill.advisory`, including its writer, source Hunt, digest and timestamp.
It is clearly advisory even when it contains instructions copied from target
responses. Removing knowledge does not erase the operator's instructions, and
removing instructions does not discard useful learning. The editor and Hunt
review show the two sections separately.

The API derives writer and delegation provenance. Client-supplied writer, trust,
or delegation fields are rejected. Saved operator opt-outs still stop metadata
writes. Neither instructions nor learning can create testing authority, credential
grants, or budget increases. Turning on `instruction_changes` intentionally
permits broad instruction edits: this is not a claim that a compromised delegated
planner cannot abuse the permission that the operator chose to give it.

## Instruction proposals

Without `instruction_changes`, a Hunt suggests guidance with
`targets.skill.propose`: the complete proposed text, the `base_revision` it read
(it must be the current revision), a title, a reason and up to 20 ids of this
Hunt actions or receipts, findings, candidates or scans on the target's asset.
A proposal is stored
in `target_instruction_proposals` as `pending` and applies nothing. A Hunt files
at most 5; a target holds at most 20 pending Hunt proposals and, separately, 20
pending operator proposals; a Hunt's newer proposal supersedes its earlier
pending one. Proposal text may not contain terminal control characters.

Operators list proposals (`GET /instruction-proposals`,
`GET /targets/{id}/instruction-proposals`, each pending one with a unified diff
against the current instructions and a `stale` flag), accept, reject or rebase
them (`POST /targets/{id}/instruction-proposals/{proposal_id}/accept|reject|rebase`),
or review them in a terminal with `shakerscan knowledge review [target]`
(`--accept ID`, `--reject ID`), which decides each one with a single keypress
and ignores arrow keys, escape sequences and pastes; it offers accept only when
the whole difference was shown, and sends the digest of the text it showed,
which the server checks. Accepting writes the text
through the ordinary revision-checked operator write. A proposal is stale when
the instructions changed after its base revision; a stale proposal cannot be
accepted until it is rebased, which files the same text against the current
instructions as a new pending proposal so the new difference is reviewed.
Pending proposal text never reaches a Hunt's instructions, briefing or planner
context; the briefing carries only the count.

## Startup briefing

Every Hunt start response, `GET /hunts/{id}` and the summary query carry a
bounded `briefing` (`hunt-briefing/v1`, at most about 24 KB): the operator
instructions snapshotted at start (whole, or headings and a leading part with
`more_available` and where to read the rest), the objective, an authority
summary (scope, permissions, target delegation, approval requirements, budget
limits and use), knowledge counts by kind, the pending proposal count and
unresolved work (open candidates, inconclusive experiments, in-progress
actions). The compact MCP view never omits it; anything shortened is listed in
`briefing.trimmed`.

### Example

```json
{
  "idempotency_key": "target-learning-001",
  "input": {
    "purpose": "knowledge",
    "expected_revision": 3,
    "methodology": "The management API is on port 8443; the selected viewer account cannot open the admin screen."
  }
}
```

Send to the current Hunt's `targets.skill.create` capability when no knowledge
section exists, or `targets.skill.update` otherwise. Read current state through
`targets.skill.read`; revisions are shared across the two sections. For an
operator-directed instruction change, use the default `instructions` purpose
where `instruction_changes` is on, and `targets.skill.propose` otherwise.

## Optional scoped planner listener

`api/hunt/planner_gateway.py` wraps the existing API, not another executor. An
operator-created expiring lease permits one already-admitted Hunt. The canonical
runtime still validates capability inputs, authorization, credentials, budgets
and proof. The listener does not expose operator authorization, sharing, budget
increases, unrelated Hunts or arbitrary new routes.

Under the listener service's OS identity, create a lease:

```bash
PYTHONPATH=api:scanner python -m hunt.planner_lease \
  --hunt-id "$HUNT_ID" \
  --grant-file /run/shakerscan/planner-grant.json \
  --token-file /secure-transfer/planner-token
```

Start the optional listener in the API environment with trusted TLS material:

```bash
SHAKERSCAN_HUNT_PLANNER_GRANT_FILE=/run/shakerscan/planner-grant.json \
  uvicorn hunt.planner_gateway:create_app --factory \
  --host 0.0.0.0 --port 8444 --no-proxy-headers --no-access-log \
  --ssl-certfile /run/tls/server.pem --ssl-keyfile /run/tls/server-key.pem
```

Transfer only the bearer file to the planner; the existing API helper uses
`SHAKERSCAN_API_TOKEN_FILE`. The planner must not independently reach the ordinary
operator API, database, grant file or operator filesystem. This listener does not
install network/filesystem isolation. Normal trusted-local operation is unchanged.

Lease removal, expiry or disablement rejects new requests, including a revocation
observed during body upload. It does not stop work already dispatched: use Hunt
cancellation for that. Logs omit raw bearer values and request bodies.

## Verification scope

`test_target_instruction_trust.py` tests effective update/delete, automatic
learning, malformed provenance, history churn and immutable snapshots with the
real writer/projection and a storage double.

`test_target_asset_planner_runtime_postgres.py` exercises the actual FastAPI app
behind the gateway, actual Hunt admission, capability execution, PostgreSQL
mutations, action receipts, budget settlement, idempotency and revocation. It
uses controlled DNS, not a success-returning backend. Existing PostgreSQL tests
cover admission for web, API, network and device targets. The required runtime CI
job rejects skipped tests. The existing real-HTTPS CLI test remains transport
coverage, not a substitute for this runtime coverage.

UI tests cover automatically available learning, effective delegated instructions,
editing and deletion without an extra promotion step. Committed public API/Hunt
contracts, inventory and installer hashes are regenerated from their canonical
sources and checked rather than hand-edited.

Direct SSH commands, worker-owned connection reuse, streamed output and cancellation
are implemented by the same capability runtime; see [Hunt SSH](hunt-ssh.md). The
command fixture executes real processes through the production worker, not just
an authentication check. This is exec-channel reuse, not a persistent PTY terminal.

## AISVS mapping and limits

The released AISVS 1.0 requirements guide this work:
[C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md)
for runtime authorization and controlled self-modification;
[C5](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C05-Access-Control-and-Identity.md)
for authorization separation;
[C8](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C08-Memory-Embeddings-and-Vector-Database.md)
by analogy for structured knowledge provenance;
[C12](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C12-Monitoring-and-Logging.md)
for provenance and observability. Requirements are linked, not vendored; OWASP
AISVS is CC BY-SA 4.0. No vector-store conformance, complete prompt-injection
resistance, isolated local planner, or live-model benchmark is claimed.
