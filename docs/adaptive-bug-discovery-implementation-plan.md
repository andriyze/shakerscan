# Adaptive Bug Discovery Implementation Plan

**Status:** Active implementation plan  
**Started:** 2026-07-12  
**Primary objective:** Increase verified vulnerability recall on unfamiliar owned applications without increasing false-positive findings.  
**Authority model:** LLMs propose one bounded action; ShakerScan enforces scope, identity, budgets, execution, evidence, and proof.

## 1. Success criteria

The work is successful when ShakerScan can explore unfamiliar web/API workflows adaptively, retain useful state between steps, and convert promising signals into existing deterministic verification paths. It must improve verified rediscovery and novel-lead yield while preserving these invariants:

- live tests run only against local targets or targets explicitly owned and controlled by the operator;
- every active request is bound to a registered target and matching scope/approval receipt;
- planners cannot provide credentials, receipts, arbitrary URLs, shell, or executable code;
- request, response, time, action, and model-token budgets fail closed;
- distinct-principal and ownership checks precede authorization conclusions;
- experiment anomalies remain unverified signals until a family proof contract succeeds;
- benchmark hostnames, product nouns, and answer-key routes are prohibited detector/planner inputs;
- no LLM response can directly create or verify a finding;
- symmetrically, no LLM response can dismiss or close a finding/hypothesis: a `refuted`/`false_positive` transition requires a deterministic, re-executed basis and a concrete `refuted_by` reference (a verification or experiment-signal id), and an uncorroborated (`signal_only`) refutation fail-safe downgrades to "stands";
- wave and family acceptance is re-derived from committed artifacts (tool receipts, evidence instances, comparisons), never a stored or asserted verdict — and "fails closed" means the failure is *recorded as evidence*, not merely rejected.

## 2. Planner entry points

All entry points use the same persisted research episode and Arsenal execution controller.

| Entry point | Planner brain | Execution authority |
|---|---|---|
| Codex launcher | Isolated ephemeral Codex process via `./scanner.sh research` | ShakerScan only |
| Claude/agent skill | Calling agent submits one structured decision | ShakerScan only |
| Research Agent UI | Provider/model configured in `/settings/ai` (OpenRouter or OpenAI-compatible) | ShakerScan only |
| Direct API | Caller submits a typed decision or configured-provider step | ShakerScan only |

## 3. Wave plan

### Wave 1: Bounded HTTP differential actuator

**Status: complete; commit `e786806`.**

Implemented:

- `experiment.http_diff` gated Arsenal command;
- two to four same-origin requests using relative paths;
- path, query, non-sensitive headers, and JSON mutations;
- no redirects and no model-supplied authorization/cookie/host/API-key headers;
- request/time/body limits and four-request research-budget reservation;
- status, length, body hash/similarity, and JSON-key comparison;
- durable ToolReceipt, EvidenceInstance, and CommandResult records;
- explicit `unverified_experiment_signal`, with zero direct findings;
- Compose propagation for `AI_OPS_ROUTER_EXECUTE_ENABLED`;
- unit, full-suite, rebuild, and owned local Juice Shop E2E validation.

Acceptance evidence:

- operation `2ee92849-7aaf-4f29-98c6-a295834c20b7`;
- evidence instance `45b6e38d-9c5a-4183-b835-d660add81be4`;
- tool receipt `44675428-6d22-4e04-b271-ca5875153a48`;
- two successful owned-target requests, structural differential recorded, zero findings created.

### Wave 2: Chained values and richer differentials

**Status: complete and committed (`332ae2b`), hardened in `5f0482e` (contract `http-experiment-2026-07-12.v3`). One residual acceptance-hardening item is open — see "Residual" below.**

Scope:

- JSON and form request bodies;
- named scalar extraction from non-sensitive JSON paths and response headers;
- `${name}` substitution in later path/query/header/body fields;
- revalidation after substitution;
- selected JSON-path and response-header comparison;
- elapsed-time and timing-delta evidence;
- `control`, `mutation`, and `verify` roles;
- explicit `compare_to` for before/after side-effect checks;
- streaming response cap rather than post-download truncation;
- missing/ambiguous variables fail closed.

Acceptance:

- chained owned-target E2E extracts a resource ID and uses it in a later request;
- form and JSON paths have unit coverage;
- response cap is enforced during streaming;
- evidence remains redacted and unverified;
- full suite, rebuild, and runtime smoke pass.

Acceptance evidence:

- real Arsenal execution against an ephemeral owned localhost fixture reused an extracted resource ID in a later request;
- operation `ef1992a5-c89f-4995-80ba-e622a81edeed`;
- evidence instance `7c8ef07a-c27c-4018-9d43-f8f7623db03c`;
- tool receipt `d957cb65-b4c5-44dc-9a90-73cd531dad7b`;
- two successful requests, JSON/header/timing deltas recorded, extracted value persisted only as hash/length, zero findings created;
- the global execution gate was restored to disabled and the ephemeral target/server were removed after validation.

Residual (open, tracked under §4.3): a non-ASCII header name or value still fails *open* — `client.build_request` raises an uncaught `UnicodeEncodeError` before the recording transaction, so the run returns 500 with no tool receipt / evidence / command result written, and it is reachable from the target's own response (a Unicode value extracted into a later step's header). This violates the §1 "fails closed = recorded" invariant; the missing/ambiguous-variable and post-substitution origin-escape paths already fail closed correctly. Fix: reject non-ASCII header names/values in `normalize`/rendered-header checks and widen the executor `except` to `UnicodeError`.

### Wave 3: Principal-bound stateful workflow runtime

**Status: core runtime committed (`75680a7`). Deterministic acceptance and rebuild pass; owned-target live validation remains pending because the local fixture approval was unavailable.**

Scope:

- typed API workflow steps and bounded browser actions;
- browser navigation, click, fill, submit, wait, and extraction;
- named variables and resource references shared across workflow steps;
- principal slots: `anonymous`, `user1`, `user2`, `admin`, and tenant-labelled principals;
- managed credential profiles resolved server-side only;
- no credential material in planner observations or persisted options;
- principal profile, subject/account identity, role, and tenant receipts;
- hard rejection when compared principals resolve to the same account;
- cross-principal and same-principal controls;
- before/mutation/after workflow checkpoints;
- bounded cleanup/rollback steps where supported.

Acceptance:

- two-profile same-account input is rejected before BOLA comparison;
- distinct owned test principals execute a multi-step object workflow;
- browser and API state are visible in one bounded observation;
- cancellation closes browser contexts and stops further requests;
- no finding is promoted by workflow output alone.

### Wave 4: Adaptive hypothesis engine

**Status: lifecycle implemented & live-verified. `blocked`/`exhausted` states added (idempotent schema migration); pure `api/hypothesis_lifecycle.py` state machine (host-tested) enforces legal edges, requires a falsifier + expected signal before `testing`, and applies the deterministic negative gate on `refuted`; gated `POST /arsenal/hypotheses/{id}/transition` endpoint. Signal-source ingestion + canonical dedupe pre-date this and remain as below.**

Signal sources:

- JavaScript routes, client bases, request bodies, and object keys;
- OpenAPI/Swagger operations and schemas;
- persisted application graph routes, objects, producers, consumers, and auth boundaries;
- existing findings and suspected proof gaps;
- validation errors and response-guided required fields;
- observed browser/API workflows and extracted resource references;
- ASM untested/stale inventory and prior experiment outcomes.

Lifecycle:

- `open`, `claimed`, `testing`, `supported`, `refuted`, `blocked`, `exhausted`, `promoted`, `dead`;
- expected signal and falsifier required;
- canonical dedupe dimensions for family, method, route template, object, principals, tenant, parameter/body path, and proof surface;
- equivalent hypotheses merge signals rather than repeat requests;
- attempt count, request cost, last outcome, blockers, and next eligibility persisted;
- repeated falsification or exhausted budget closes the hypothesis;
- a `refuted`/`blocked` transition records a deterministic `refuted_by` (a verification or experiment-signal id) and is rejected when the basis is not deterministic — the negative gate of §4.1; a model label alone can never close a lead;
- new evidence can reopen only through an explicit versioned transition.

Acceptance:

- every source produces bounded generic hypotheses without benchmark nouns;
- duplicate/equivalent source hints produce one hypothesis;
- supported/refuted/blocked/exhausted transitions are tested;
- planner cannot skip required falsifiers or revive terminal leads silently.

### Wave 5: Deterministic finding-family handoffs

Experiment evidence may request, but never replace, these verifiers:

- BOLA/IDOR: distinct identity, ownership, cross-principal access, denial/control, reproducibility;
- mass assignment: accepted forbidden field plus observable state change and control;
- injection: payload/control differential plus family-specific deterministic proof;
- authentication bypass: protected resource access with an independent authenticated/unauthenticated control;
- workflow/business-logic bypass: expected transition invariant plus before/after state evidence;
- data exposure: sensitive value evidence, not name-only classification.

Each adapter returns one of: `verified`, `supported_unverified`, `refuted`, `inconclusive`, or `blocked`. Only `verified` output satisfying the existing family proof contract can create/promote a finding. `verified` requires the family proof contract to be **re-executed live at handoff** (a stored outcome is a claim; a contract that fires at promotion time is proof), and promotion, refutation, and the evidence-strength ladder all run through the shared deterministic adjudicator (§4).

Acceptance:

- adapter mappings are registry-authoritative;
- unsupported experiment families fail closed;
- family proof receipts link exact experiment, target, route, principals, and evidence;
- tests prove LLM labels and generic anomalies cannot promote findings.

### Wave 6: Bug-bounty-oriented scheduling

**Status: deterministic ranking implemented & live-verified. Pure `api/hypothesis_scheduler.py` (host-tested) computes the stored, explainable priority breakdown; terminal/blocked/exhausted leads are excluded, over-budget leads deferred, and an LLM `hint_delta` is clamped to ±2 so it can never override the scope/proof/identity/budget gates. Read-only `GET /arsenal/hypotheses/schedule`. Novelty is computed against completed/refuted dedupe dimensions.**

Priority signals:

- authenticated and undocumented APIs;
- object IDs and producer/consumer workflows;
- role and tenant boundaries;
- money, entitlement, order, approval, and state-transition operations;
- file upload, import/export, webhook, OAuth, GraphQL, WebSocket, and integration surfaces;
- validation-error hints and client/server schema disagreement;
- high-impact suspected findings lacking proof;
- novelty relative to completed/refuted hypothesis dimensions.

Ranking model:

`priority = impact + boundary_value + novelty + evidence_strength + reachability - request_cost - prior_failures - blocker_penalty`

The ranking inputs must be explainable and stored. LLM hints may adjust ordering within bounded limits but cannot override scope, proof, identity, or budget gates.

Acceptance:

- deterministic score breakdown is present for every scheduled hypothesis;
- terminal/equivalent hypotheses are excluded;
- cost-aware selection respects remaining episode requests/time;
- authenticated high-impact workflows outrank generic low-impact probes when prerequisites exist.

### Wave 7: Recall measurement

**Status: re-derivable acceptance + anti-fitting guard implemented (host-tested). `scripts/verify_acceptance.py` recomputes each app's scorecard from the committed raw artifact via the shared `benchmark_targets` predicate (never trusts a stored score) and fails on drift against a committed `acceptance.json` oracle; `tests/test_no_fitting.py` is a build-failing guard rejecting benchmark nouns in detector/planner string literals (comments/docstrings are allowed rationale). The broader metric surface + evaluation-set automation remain as below.**

Metrics:

- verified vulnerabilities rediscovered;
- verified critical/high recall by family;
- endpoint and workflow coverage;
- hypotheses generated, attempted, supported, refuted, blocked, exhausted, and promoted;
- useful-signal rate;
- requests and model tokens per supported lead and verified finding;
- time to first supported lead and verified finding;
- false-positive and unproven critical/high rates;
- identity/precondition failure rates;
- planner rejection and duplicate-avoidance rates.

Evaluation sets:

- Juice Shop, crAPI, and Honey as owned regression targets;
- additional unfamiliar local/owned applications not represented in detector logic;
- clean controls and legitimately public endpoints for false-positive measurement;
- benchmark manifests remain external scorecards and are never planner/detector inputs.

Acceptance:

- scorecards distinguish discovery, signal, proof, and promotion failures;
- build fingerprint and worker freshness are mandatory;
- baseline and candidate runs use comparable budgets;
- every headline metric re-derives from committed artifacts via a `verify-acceptance` recompute — the stored score is never trusted; the verdict is recomputed from raw receipts/evidence plus a committed per-family oracle, and CI fails on drift;
- a build-failing anti-fitting guard rejects any benchmark hostname, product noun, or answer-key route that leaks into detector/planner code (mechanising the §1 invariant);
- no benchmark-specific route or noun enters production detector/planner code.

### Wave 8: Research Agent UI

Scope:

- dedicated experiment builder inside `/settings/research-agent`;
- owned registered target selection;
- scope/approval receipt status and execution-gate state;
- control/mutation/verify step editor with method, path, query, headers, JSON/form body, extraction, selected fields, role, and comparison target;
- clear request/time/body budget display;
- configured-provider “run next step” and manual typed-experiment execution;
- running, blocked, partial, completed, refuted, and unverified states;
- structured comparison table and before/after side-effect view;
- extracted variable names without secret values;
- links to command result, evidence instance, tool receipt, hypothesis, verifier, and resulting finding when proof exists;
- prominent “unverified signal” treatment distinct from verified findings;
- responsive desktop/mobile QA and no duplicated settings controls.

Acceptance:

- operator can build and execute an owned-target experiment without raw JSON;
- all blocked gate reasons are visible;
- UI never implies a partial/rejected/unverified experiment ran cleanly;
- Playwright desktop and mobile screenshots have no overlap or clipped controls.

### Wave 9: Agent and provider integration

- Codex local runner receives the same command schema and bounded observations;
- Claude/agent skill documents typed experiments and proof handoffs;
- UI provider uses `/settings/ai`, including OpenRouter/OpenAI-compatible endpoints;
- provider output is server-bound to the current observation and target;
- schema omissions are normalized only when deterministic and unambiguous;
- all planner paths produce equivalent DecisionEpisode records.

## 4. Verification and proof architecture

Recall is only useful if precision holds, so every state change — promotion *and* dismissal — is gated by a deterministic, re-executable predicate rather than a model's opinion. These mechanics are cross-wave: Waves 4–5 consume them and Wave 7 re-derives against them.

### 4.1 Shared adjudicator — `api/adjudicate.py` (implemented)

One pure module (no db/httpx/engine imports) holds the promotion and refutation predicates, so the live path and any offline recompute (§4.3 / Wave 7) cannot drift; it is pinned by a self-test and `tests/test_adjudicate.py`.

- **Negative gate (implemented, wired, live-verified).** The mirror of "no LLM output can create a finding": no refutation can *dismiss* one unless a deterministic re-run observed the claimed mitigation. Enforced at the universal refuter-review record chokepoint (`_canonical_refuter_review` → `_apply_refuter_negative_gate` in `api/api.py`): a `refuted` verdict carrying a deterministic *label* but no corroborating evidence/proof fail-safe **downgrades** to non-refuting and records the reason. Verified against the running API — an uncorroborated `refuted` review persists as `inconclusive` with a `negative_gate` audit stamp; a receipt/proof-backed one stands.
- **Deterministic cite-check.** A refutation counts only when its claimed mitigation is observed in a deterministic re-run — a real 403 / ownership-enforcement signal from a control-leg `experiment.http_diff`, backed by a tool receipt / evidence instance (or the verification's proof/artifacts/replay commands). The HTTP-behaviour analogue of "the cited guard exists in source."
- **Refuter panel, strict majority, ties → survive (available).** `adjudicate_panel` dismisses only on a strict majority of *counted* refutations (`refuted * 2 > participating`); an even split or an inconclusive panel leaves the finding standing. Single-vote enforcement is wired today; multi-vote generation is the next increment.

### 4.2 Evidence-strength ladder and re-execute-at-promotion

The ladder `claimed < signal < reproduced < cross_principal_verified` ships in `api/adjudicate.py`. Target state: promotion requires the top rung **and** a *fresh* re-execution of the family proof contract at handoff — generalising the authz-replay differential-at-promotion check to every Wave 5 family; a stored `reproduced: true` is a claim, a contract that fires live at promotion time is proof. The `evidence_instances` strength column and the generalised promotion gate are the next increment.

### 4.3 Re-derivable acceptance

Wave and family acceptance are executable predicates over committed artifacts, not prose. Each wave commits its raw tool receipts, evidence instances, and comparisons plus a per-family expected-outcome oracle; a `verify-acceptance` recompute re-derives the verdict at CI and fails on drift (the stored verdict is never trusted). "Fails closed" is defined to mean the failure is *recorded* — an unrecorded crash (the Wave 2 residual) does not satisfy it. A build-failing anti-fitting guard mechanises the §1 no-benchmark-nouns invariant. The discipline is borrowed from a reviewed reference implementation whose every headline number re-derives from committed data by a single command.

## 5. Commit boundaries

1. `feat(research): add bounded HTTP differential experiments` — complete (`e786806`).
2. `feat(research): add chained experiment values and rich comparisons` — complete (`332ae2b`), hardened (`5f0482e`). *(Shipped under commit titles "Enhance HTTP experiment diffing…" / "Harden HTTP experiment normalization…".)*
3. `feat(research): add principal-bound stateful workflows` — core runtime complete (`75680a7`).
4. `feat(research): add adaptive hypothesis lifecycle`.
5. `feat(research): add deterministic experiment proof handoffs`.
6. `feat(research): add impact-aware hypothesis scheduling`.
7. `feat(metrics): add adaptive discovery recall scorecards`.
8. `feat(ui): add adaptive experiment workbench`.
9. `docs: reconcile adaptive discovery implementation status`.

Each feature commit requires focused tests. Each runtime wave requires a full suite and rebuild before live validation. The execution gate must be restored to disabled after temporary local E2E use.

## 6. Out of scope until separately approved

- unrestricted shell, arbitrary code, or arbitrary URL execution;
- cross-origin experiment requests;
- unattended production execution;
- raw credential entry in planner requests;
- direct LLM finding creation or proof classification;
- destructive cleanup without explicit typed rollback and approval;
- distributed/multi-node execution without fencing and stale-owner-write protection.
