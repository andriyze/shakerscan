# Evidence-driven agent boundary discovery

**Status:** first capture-driven read-boundary slice implemented in this PR; broader workstreams below remain design direction.

## Objective

Move upstream from a manually constructed AI Boundary candidate to an evidence-backed model that lets Hunt propose useful authorization tests with minimal operator configuration:

```text
Discover -> Model -> Hypothesize -> Confirm ambiguity -> Attack -> Prove -> Regress
```

This phase focuses on **Discover -> Model -> Hypothesize**. It reuses the existing AI Boundary verifier and regression machinery rather than adding another execution or proof engine.

## First slice

Use existing authorized Hunt traffic and immutable runtime records to build a bounded, explainable authorization-surface model:

```text
authenticated principal
  -> observed service/origin
  -> request/response structure
  -> resource/object candidate
  -> agent-facing endpoint
  -> candidate cross-principal boundary test
```

The implementation should:

1. derive candidate agent/resource relationships from Hunt-owned HTTP evidence;
2. keep exact origin, scheme, port, method and source action IDs;
3. preserve uncertainty: successful access is not ownership or entitlement;
4. prefill only facts established by evidence;
5. leave subject, tenant, business rule, approval semantics and other unproven facts explicit;
6. feed resulting candidates into the existing Boundary proposal/materialization/verification flow.

No discovered fact may grant testing authority or credential access.

### Implemented interface and limits

`POST /hunts/{hunt_id}/boundary-discovery` reads a repeatable-read, read-only
snapshot of at most 500 recent same-Hunt, same-target HTTP transactions from
completed/partial actions. It does not read body blobs, decrypt credentials,
contact targets, create candidates, or reserve execution budget. It returns up
to 20 read-boundary drafts, field provenance, missing facts, and explicit
truncation/structure-unavailable counts. Partial actions may contribute a
complete successful exchange; failed, truncated or unsuccessful exchanges do not.

Prospective captures in full archive mode retain an allowlisted JSON shape
under `metadata_json.boundary_structure`. It contains field paths and scalar
types only. Parsing is bounded to 64 KiB, six container levels and 48 fields;
duplicate keys, nonfinite constants, malformed/truncated JSON and array roots
are unavailable. Unknown property names/subtrees, credentials and tool arguments
are omitted. Metadata/off modes and private workflow exchanges retain no shape.
Old captures are not backfilled or retroactively decrypted.

Resource hypotheses pair different terminal path IDs observed under primary
and secondary slots on one exact service and path template. Numeric and opaque
IDs are supported. Scheme and nonstandard ports remain distinct; equivalent
default ports normalize. Query-dependent and encoded paths are omitted because
the existing Boundary fixture cannot faithfully represent them. POST responses
with compatible answer/text fields suggest possible agent endpoints; they do
not establish the presence of an agent or its relationship to the resource.
Ambiguous field, identity-path and agent-response bindings stay missing.

AI Gate → Agent boundary verification offers discovery and explicit preparation.
The browser submits only the selected discovery draft ID. The server reloads the
Hunt under lock, recomputes that draft from Hunt-owned captures, enforces the
normal candidate budget, and then writes the existing unverified candidate. A
client cannot substitute its own candidate payload for a discovered draft.

The draft carries a source binding: Hunt ID, asset ID, exact origin and the
observed agent paths. Preparation stores it on the candidate observation for that
Hunt; re-preparing the same draft supersedes the earlier binding, and later
metadata edits never shadow it. Each draft reports `evidence_refs_total`,
`evidence_refs_truncated` and `provenance_omitted` when the bounded candidate
evidence list (100 references, one capture per prefilled fact first) or the
identity/agent field provenance (4 and 2 captures) could not hold everything.

The handoff attaches the stored binding to the compiled Boundary proposal and
refuses principal declarations whose resource IDs differ from the discovered
pair. The proposal is client-held JSON, so the verify route admits a binding only
after checking it against the Hunt record: the Hunt exists and is for the bound
asset, the proposal cites exactly one Hunt candidate, the binding equals the one
preparation last stored for that candidate in that Hunt, and the contract tests
the discovered resource pair and path template. A proposal that cites a
discovery-prepared candidate (or, citing no candidate, a discovery capture)
without its binding is refused rather than verified unbound. The selected AI
target must then match the exact source origin/path, and both declared Boundary
roles must exist as exactly one active principal each on that AI target.

The admitted binding becomes part of the executable contract, so the contract
digest the worker records covers it, and it is stored in the run's scan options.
The worker refuses a contract that carries a binding the verify route did not
admit. Regression export copies a binding only when it equals the one the source
run recorded and the AI target endpoint still matches it; evaluation requires the
later run to have recorded the same binding. A proposal without Hunt discovery
provenance, including one compiled from a hand-built Hunt candidate, verifies
unchanged. None of these checks grant target authority or
credential access: the selected AI target still passes its normal authorization,
credential, budget and worker admission.

Repeated observations of the same principal/resource are merged only when their
structural bindings agree. Conflicts are counted as explicit coverage gaps rather
than first-match-wins input. Observed POST/PUT/PATCH/DELETE exchanges are retained
as non-executing action leads with missing business-rule, independent-postcondition
and approval-semantics prerequisites. They are not automatically converted into
state-changing Boundary tests.

The partial read fixture still leaves subject, tenant and role declarations empty.
Confirm that the resources are controlled synthetic fixtures and that the agent
belongs to the application, then complete any missing shape bindings. Principal
form edits also update the fixture declarations. Compilation, materialization and
explicit verification continue through the existing workflow. Preparing a
candidate never queues a scan or marks a finding verified.

This slice does not infer body values, provision canaries, prove ownership,
discover delegated tools, or autonomously construct action/approval hypotheses.
Same-origin membership and structural field names remain observations. The
verifier must still establish distinct principals, ownership, tenants and
synthetic canaries.

## Research implications adopted in this phase

### PACE: execution-time provenance beats prompt hardening

PACE's central result is directly aligned with ShakerScan's architecture: authorization must be enforced at the tool-call boundary using authority derived from the authenticated request, while untrusted context carries provenance rather than authority.

ShakerScan already has server-owned capability schemas, saved Hunt policy, target binding, approval receipts, budget reservations, action digests and immutable execution receipts. We should extend that model rather than introduce another policy engine.

For this phase:

- every discovered model edge carries provenance back to Hunt actions/captures;
- discovery output is advisory input to planning, never execution authority;
- the existing capability lifecycle remains the enforcement point immediately before execution;
- later work may add a provenance/effect envelope to executable calls, but the model must be additive to the canonical capability registry rather than a parallel gate;
- benign mismatches should surface as missing/repairable bindings where possible, not blanket refusals.

### Chaining Skills to Hijack LLM Agents: progress records are not authority

The reported skill-chain attack demonstrates why a legitimate-looking record written by an upstream skill cannot establish approval for a downstream action.

Current ShakerScan already distinguishes library skills from runtime authority and labels learned target knowledge as advisory. This phase makes the rule explicit for all discovery/model artifacts:

- skills and skill-produced records can propose hypotheses and evidence relationships;
- neither skill content, candidate prose, learned knowledge, progress records nor prior tool output can create scope, approval, credentials, budget or a policy decision;
- model nodes/edges include `origin_kind` and source action/record IDs;
- only the saved Hunt run authority plus server-side target/approval/credential checks may authorize execution;
- a record that says an action was approved is treated as data unless it references a server-owned immutable authority object that validates for the current action.

This should be tested with synthetic cross-skill records carrying fabricated approval claims.

### TAILOR: prerequisite state should become explicit investigation state

TAILOR's type- and state-aware reproduction work is highly relevant to the next slice after discovery. Authorization tests frequently require a reproducible prerequisite state: authenticated sessions, owned objects, tenant membership, an approval state, or a specific workflow stage.

The discovery model should therefore be designed to grow into state transitions rather than a flat endpoint list:

```text
principal -> session -> resource ownership -> workflow state -> action -> postcondition
```

This PR should not build a new workflow engine. It should emit state/precondition gaps in a form future strategy modules can consume.

### CATP: decision evidence and execution evidence are different

ShakerScan already records action digests and capability receipts. CATP reinforces two improvements we should keep in scope for follow-up hardening:

- bind decisions to the exact normalized action, target identity, current authority references and the policy/contract revision that was evaluated;
- keep authorization evidence separate from execution evidence, because an authorized action is not proof the action occurred.

The discovery model must never infer execution truth from a receipt that only proves an authorization decision.

### KaliBench: benchmark the planner separately from the runtime

KaliBench is useful primarily as an evaluation pattern, not a product feature. We should add a Hunt benchmark that scores:

- correct capability/tool selection;
- exact target/service binding;
- parameter/schema correctness;
- required prerequisite state;
- whether the proposed call would remain within saved authority.

This can be deterministic and fixture-based. It should not require an LLM judge for basic tool correctness.

### Innocent Courier: URL components need provenance

The web-fetch exfiltration result matters to Hunt and agent testing because an allowed fetch can still transmit influenced data through hostname, path or query components.

Not in the first discovery slice, but the model should leave room to represent:

```text
source content -> transform -> URL component -> network effect
```

A later agent-security test family should track influence on host/path/query separately and verify the actual outbound request.

### Malicious retrievers and self-replicating injections

These are important but should not expand this PR.

They point to later test families:

- compare clean-versus-candidate retriever trajectories for evidence suppression, forced promotion and cost inflation;
- track persistence/propagation of untrusted instructions into memory, files, findings, code comments, summaries and downstream agent messages.

Both should reuse the same provenance model introduced here.

## Trust model

The model distinguishes:

- **authority:** saved server-owned Hunt policy, scope, approvals, target bindings, credential grants and budgets;
- **operator declarations:** business rules and controlled-principal semantics explicitly supplied by the operator;
- **observations:** target responses, captures, tool outputs and deterministic server evidence;
- **advisory context:** skills, learned knowledge, model hypotheses and prior progress records.

Only authority can authorize execution. Operator declarations may define an expected invariant but never prove it. Observations may support a hypothesis. Advisory context may choose what to investigate but cannot change any of the preceding categories.

## Evidence and uncertainty

A successful request establishes observed access, not ownership, entitlement, tenant isolation or the presence of an LLM. Two credential slots do not prove two distinct users. A shared origin suggests an integration but does not prove a delegation relationship.

Every prefilled field must cite its evidence source. Missing fields and competing bindings stay explicit. Discovery never fills business-policy or authority fields from model output, skill text or target content.

## Capture and privacy

The initial implementation may retain bounded, value-free structural metadata for eligible Hunt HTTP exchanges so discovery can recognize resource shapes without exposing body content.

Requirements:

- no response body values;
- no credentials, cookies, authorization headers or tool arguments;
- bounded input bytes, nesting and field count;
- malformed/truncated payloads reported as unavailable, never interpreted as empty;
- private workflow captures and disabled archive modes remain unaffected;
- no retroactive decryption/backfill of historical content.

## Operator flow

The expected UX is:

1. run an authorized Hunt with controlled principals;
2. open Agent Boundary discovery;
3. review observed agent/resource surfaces and provenance;
4. select a candidate relationship;
5. fill only genuinely unknown principal/business-policy facts;
6. create the existing Boundary proposal;
7. queue deterministic verification explicitly;
8. export a regression artifact after proof.

Discovery never queues active work automatically.

## Non-goals for this PR

- no generic AI governance platform;
- no new approval/authorization system;
- no model-written permission records;
- no native MCP implementation yet;
- no browser-agent automation yet;
- no retriever backdoor scanner yet;
- no self-propagating injection engine yet;
- no automatic state-changing attack from discovery output;
- no replacement for the existing deterministic Boundary verifier.

## Acceptance

The implementation must prove that:

1. foreign-Hunt and foreign-target evidence cannot enter the model;
2. skill/target/progress text cannot promote authority;
3. exact origin including scheme and port is preserved;
4. value-free structural metadata cannot leak body values;
5. incomplete evidence creates explicit gaps;
6. candidate preparation makes no network calls and spends no execution budget;
7. deterministic verification still happens only through the existing AI Boundary lifecycle;
8. secure and vulnerable loopback fixtures produce different proof outcomes;
9. allowed control workflows remain represented for regression;
10. repeated conflicting resource observations are rejected rather than selected by order;
11. a discovered proposal cannot be queued against a different AI endpoint, a missing or ambiguous principal role,
    a Hunt/asset/binding the Hunt record does not hold, or a resource pair discovery did not observe,
    and cannot be stripped of its binding to avoid those checks;
12. discovered candidate preparation is recomputed server-side from the selected Hunt;
13. a verified run and its regression artifact carry the admitted binding, covered by the contract digest,
    and export refuses a binding the source run did not record.

## Follow-on order

1. state/prerequisite model and strategy selection (TAILOR-inspired);
2. execution-time provenance/effect envelope over the canonical capability lifecycle (PACE-inspired);
3. cross-skill authority-confusion benchmark and hardening;
4. native MCP tool/principal observation;
5. URL-component influence/exfiltration tests;
6. persistence/propagation tests;
7. retriever/model-component trajectory comparison;
8. Hunt tool-use benchmark and scorecard.
