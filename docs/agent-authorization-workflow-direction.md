# AI security direction: discover, model, prove, regress

**Status:** implementation direction for AI Gate and Hunt. This is a product/engineering direction, not a release claim.

## Decision

ShakerScan will sharpen its AI red-team work around **agent authorization and workflow security**.

The product should answer a concrete question:

> When an AI agent reads private data or takes an action, did the application preserve the user's identity, tenant, object, action, parameter, and approval boundaries?

This is a refinement, not a rewrite. We already have two complementary foundations:

- **Hunt** is the adaptive investigator. It discovers surfaces, identities, objects, workflows and candidate boundary crossings.
- **AI Gate boundary verification** is the deterministic verifier. It proves or refutes configured cross-principal reads, forbidden actions, approval bypasses, indirect-injection effects, tool-principal failures and multi-turn effects using authoritative postconditions.

The direction is to join those strengths into one workflow instead of creating a third execution engine.

## Product thesis

Generic prompt injection is useful coverage but is not the center of gravity. A model saying something unsafe is not the same as an application violating an authorization boundary.

ShakerScan should prioritize **real system consequences**:

1. another controlled principal's data was returned;
2. a tool ran under the wrong principal;
3. an object outside the caller's tenant was read or changed;
4. a sensitive action occurred without the required approval;
5. untrusted retrieved content caused a verified state change or disclosure;
6. a multi-turn workflow crossed one of those boundaries.

Model output is evidence for investigation. It is not proof by itself.

## Canonical workflow

The target workflow is:

```text
Discover -> Model -> Hypothesize -> Confirm ambiguity -> Attack -> Prove -> Regress
```

### 1. Discover

Hunt maps the AI-enabled application using its existing authorized capabilities:

- agent/chat endpoints;
- principals, roles and tenants;
- resource identifiers and ownership relationships;
- tools and connectors;
- state-changing actions;
- approval points;
- RAG/document/memory inputs;
- observable verifier/read-back endpoints.

Discovery creates **candidate facts and hypotheses**, not authority.

### 2. Model

Convert evidence into a small authorization/workflow model:

```text
principal -> tenant -> resource -> action -> tool -> approval -> postcondition
```

The model must distinguish observed facts from inferred expectations. ShakerScan must not invent a customer's business authorization policy.

### 3. Hypothesize

Hunt proposes testable boundary hypotheses such as:

- principal A may be able to read principal B's resource;
- principal A may be able to mutate B's resource through an agent/tool;
- the agent may call a tool using a service principal broader than the initiating user;
- an action may execute while required approval remains absent;
- an indirect source may influence a privileged action.

A hypothesis is a lead, not a finding.

### 4. Confirm ambiguity

When the expected business rule cannot be derived from authoritative application evidence, ask the operator for the minimum missing fact. Do not ask the operator to restate authorization already granted for the Hunt.

Examples:

- "Should support agents be allowed to refund orders from other tenants?"
- "Is manager approval required above this amount?"

The answer defines the expected invariant; it does not prove a vulnerability.

### 5. Attack

Hunt chooses and varies the attack strategy. AI Gate remains available for repeatable configured scenarios.

The operator's standing authorization remains authoritative. This direction must **not** reintroduce blanket refusals, HTTPS-only assumptions, standard-port assumptions, or repeated consent prompts for already-authorized actions.

### 6. Prove

Promotion requires an authoritative predicate, for example:

- synthetic canary disclosure tied to an independently established owner;
- cross-principal differential;
- independent read-back showing a forbidden state;
- approval state independently observed as absent;
- tool execution telemetry bound to the wrong principal plus a required postcondition.

"Agent says it did X" is never sufficient.

### 7. Regress

A verified or explicitly approved invariant should be exportable as a stable regression contract. The same deterministic verifier can then run after changes to:

- model/provider/version;
- system prompts;
- agent orchestration;
- tools/connectors;
- authorization code;
- retrieval/memory configuration.

CI should report both security failures and whether the legitimate control workflow still succeeds. "Block everything" is not a passing security design.

## Architecture rule: Hunt discovers, verifier proves

Do not duplicate policy, scope, credential custody, budgets, or evidence semantics.

Hunt owns adaptive exploration and hypothesis generation.

The server owns authorization, scope, credentials, execution and evidence.

AI Gate boundary contracts own deterministic, repeatable verification for AI application boundaries.

A Hunt candidate may become a boundary-verification proposal, but it must not become a verified finding until the corresponding proof predicate is executed successfully.

## Near-term implementation

### Phase A — bridge the two existing systems

1. Introduce a typed, secret-free **boundary hypothesis** representation.
2. Let Hunt/callers submit discovered authorization/workflow hypotheses to a deterministic compiler.
3. Compile only hypotheses that contain enough observed/confirmed facts into AI Boundary contract fragments.
4. Return explicit missing facts when deterministic verification cannot yet be constructed.
5. Preserve provenance: which Hunt/candidate/evidence produced every compiled field.

### Phase B — first-class verification

Prioritize:

1. cross-tenant read;
2. cross-tenant state change;
3. approval bypass;
4. wrong tool principal;
5. indirect-injection-caused disclosure/action;
6. stateful multi-turn boundary crossing.

Reuse the existing PR #149 boundary executors rather than implementing parallel verifiers.

### Phase C — broader transports

After the bridge works end to end:

- native MCP transport and tool-call observation;
- streaming/SSE;
- WebSocket agents;
- browser/GUI agents;
- richer indirect sources.

Transport support should not redefine proof semantics.

### Phase D — regression handoff

Allow a confirmed invariant + fixture definition to become a versioned regression artifact suitable for CI. Preserve the negative/legitimate control next to the attack case.

## What we are deliberately not doing

- We are not turning ShakerScan into a generic AI governance platform.
- We are not making LLM-as-judge output a vulnerability proof.
- We are not creating a second Hunt permission system.
- We are not requiring every AI test to use synthetic fixtures; synthetic fixtures remain the preferred deterministic proof mechanism where they can be safely created.
- We are not declaring arbitrary production agents safe because configured scenarios passed.
- We are not making MCP the product boundary. MCP is one transport/integration surface; authorization and workflow integrity are the durable problem.

## Success criteria

This direction is working when ShakerScan can take an authorized AI-enabled application with two controlled principals and:

1. discover enough of the identity/resource/action topology to propose useful boundary hypotheses;
2. tell the operator exactly which business-policy facts remain ambiguous;
3. execute supported hypotheses through deterministic proof contracts;
4. distinguish model claims from backend effects;
5. retain evidence and provenance;
6. turn confirmed/approved invariants into repeatable regression checks;
7. verify that allowed workflows still work.

## First implementation slice in this PR

The first code commits after this document will add the **typed boundary-hypothesis/compiler seam**. It is intentionally small: no new execution engine and no speculative autonomous policy inference.

That seam gives Hunt a safe way to hand discovered facts to the existing AI Boundary verifier and makes missing information explicit. Follow-up commits will wire it into the existing API/capability surface and add tests before broader transport work.
