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

**Status: complete and committed (`332ae2b`), hardened in `5f0482e`; the non-ASCII-header fail-open residual is now fixed (contract `http-experiment-2026-07-12.v4`). See "Residual (resolved)" below.**

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

Residual (RESOLVED): the non-ASCII-header fail-*open* is fixed. `normalize_experiment` and the rendered-header check reject non-ASCII header names/values, and the executor `except` now also catches `UnicodeError`/`ValueError`, so a non-ASCII header — including one extracted from the target's own response and rendered into a later step — now fails *closed*: a static header is rejected at the contract boundary (422) and a variable-rendered one is recorded as a step error (never an uncaught 500). Regression-tested in `tests/test_http_experiment.py`.

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

Autonomous research projections and decision validation expose only `GET`, `HEAD`, `OPTIONS`, and
`POST` HTTP steps for both `experiment.http_diff` and `experiment.workflow`. Manual typed experiment
execution retains `PUT`, `PATCH`, and `DELETE` for explicitly controlled workflows with cleanup.

Acceptance:

- two-profile same-account input is rejected before BOLA comparison;
- distinct owned test principals execute a multi-step object workflow;
- browser and API state are visible in one bounded observation;
- cancellation closes browser contexts and stops further requests;
- no finding is promoted by workflow output alone.

### Wave 4: Adaptive hypothesis engine

**Status: core lifecycle implemented; acceptance remains partial.** `blocked`/`exhausted` states and the pure state machine are present. The transition endpoint now resolves a terminal refutation/dead transition to an existing, completed, deterministic, proof-backed verification on the same target; caller-supplied IDs alone are insufficient. Direct `promoted` transitions are rejected in favor of the approval-gated proof-reconciliation path. Parked leads are excluded from both the public `claimable` result and the compare-and-set claim query. Broader signal-source acceptance and repeated-falsification policy still need artifact-backed validation.

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

**Status: contract registry and claim preflight implemented; live family handoffs remain incomplete.** Pure `api/family_proof.py` contains the family predicates and promotion gate. `POST /arsenal/family-proof/evaluate` accepts caller assertions, so it is deliberately limited to an unverified signal receipt: it cannot return `verified`, terminally `refuted`, `cross_principal_verified`, or promotable evidence. Per-family server-side actuators, provenance validation, and promotion-time re-execution remain required (authz replay already covers part of BOLA).

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

**Status: deterministic request-cost ranking implemented; acceptance remains partial.** The pure scheduler returns an explainable score breakdown, excludes inactive leads, defers over-request-budget work, and clamps `hint_delta`. The breakdown is returned rather than durably stored, remaining-time cost is not enforced, and `auth_available` is currently caller-provided rather than derived from target principal receipts. Novelty uses completed dedupe keys but needs stronger dimension-level validation.

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

**Status: initial acceptance fixture and noun guard implemented; acceptance remains partial.** `scripts/verify_acceptance.py` rechecks the committed sample against its oracle. `tests/test_no_fitting.py` scans production Python string literals without the former broad path-substring exclusions that accidentally skipped modules named `*_tests.py`. It currently guards named benchmark products, not the full hostname/answer-key-route invariant, and the broader metric/evaluation-set automation remains outstanding.

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

**Status: full hypothesis-to-proof loop implemented; execution remains server-gated.** `/settings/research-agent` is now the primary product surface: choose a target and objective, select Analyze / Autonomous Hunt / Relentless / **Deep Hunt** intensity, explicitly confirm target authorization for active modes, and optionally let server-side autopilot keep requesting LLM decisions until input, a gate, an evidence-backed stop, or budget exhaustion. Deep Hunt is credential-tier and enables app-specific multi-principal workflows using only server-managed target principals; credentials never enter model context. Research observations include deterministically ranked residue/graph-backed hypotheses, bounded concrete graph nodes/edges, next-test actions, and typed experiment comparisons/receipts. Novel experiments must reference a persisted target hypothesis backed by DAST unexplained residue or the application graph, and provenance is copied into command results, evidence instances, and tool receipts. Principal workflows support typed invariant assertions and cleanup/rollback checkpoints. State-changing PUT/PATCH/DELETE steps are exposed only in Deep Hunt and require a later restoration step plus a deterministic restoration assertion. A trusted verifier independently re-executes the workflow, requires stable assertion outcomes and successful restoration in both runs, derives the family-proof predicates without accepting an LLM verdict, and creates or refreshes a canonical verified finding only when `family_proof.promotion_gate` passes. The resulting regression evidence links episode, decision, hypothesis, workflow, replay, receipt, evidence instance, and finding. A read-only benchmark endpoint compares net-new verified autonomous findings with an explicitly equal-request-budget completed Smart baseline. Subject-bound launch profiles support target hunts, exact-finding verification, and ASM-gap closure. Finding Detail exposes the exact-finding flow as a one-click **Investigate autonomously** action, ASM exposes **Close gaps autonomously**, and registered web assets in Exposure expose a target-hunt action. A Postgres lease permits only one controller to plan an episode at a time. Linked scans and finding retests settle before the next decision; launch profiles reserve a final synthesis turn. Transient planner failures meter provider usage, refresh the observation, back off, and pause after three consecutive failures. The UI shows model/harness diagnostics, linked work, trusted proof verdict, reproduction/restoration state, resulting finding, immutable evidence refreshes, budgets, errors, and prior runs.

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

**Status: common decision submission is substantially implemented (pre-existing); cross-wave integration is not complete.** The launcher, configured provider, and direct API share typed decision submission and DecisionEpisode persistence. The new lifecycle, scheduler, and family-preflight endpoints are separate surfaces and have not yet been demonstrated as uniformly enforced on every planner-produced action.

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

- **Negative gate (implemented, strengthened; runtime revalidation pending).** A terminal refuter review now needs a real completed deterministic `finding_verifications` row, a refuting outcome, matching finding/target context, and persisted proof or artifacts. A replay command by itself is not proof. Arbitrary receipt IDs or caller-set `cite.observed` no longer suffice. Hypothesis `refuted`/`dead` transitions resolve the same class of verification rather than accepting a syntactically non-empty reference.
- **Deterministic cite-check.** A refutation counts only when its claimed mitigation is observed in a deterministic re-run — a real 403 / ownership-enforcement signal from a control-leg `experiment.http_diff`, backed by a tool receipt / evidence instance (or the verification's proof/artifacts/replay commands). The HTTP-behaviour analogue of "the cited guard exists in source."
- **Refuter panel, strict majority, ties → survive (wired).** `adjudicate_panel` dismisses only on a strict majority of terminal participants and requires the minimum quorum to be terminal participants; downgraded/inconclusive rows cannot pad quorum. The endpoint is read-only and does not itself change a finding.

### 4.2 Evidence-strength ladder and re-execute-at-promotion

The ladder `claimed < signal < reproduced < cross_principal_verified` ships in `api/adjudicate.py` and is durable on evidence instances. The public family preflight writes only `signal`; it cannot stamp the top rung. `family_proof.promotion_gate` expresses the intended predicate, but uniform wiring across every finding-creation path has not yet been established. Remaining: invoke trusted per-family live actuators at promotion and prove every creation path consults the same gate.

### 4.3 Re-derivable acceptance

Wave and family acceptance are executable predicates over committed artifacts, not prose. Each wave commits its raw tool receipts, evidence instances, and comparisons plus a per-family expected-outcome oracle; a `verify-acceptance` recompute re-derives the verdict at CI and fails on drift (the stored verdict is never trusted). "Fails closed" is defined to mean the failure is *recorded* — an unrecorded crash (the Wave 2 residual) does not satisfy it. A build-failing anti-fitting guard mechanises the §1 no-benchmark-nouns invariant. The discipline is borrowed from a reviewed reference implementation whose every headline number re-derives from committed data by a single command.

## 5. Commit boundaries

1. `feat(research): add bounded HTTP differential experiments` — complete (`e786806`).
2. `feat(research): add chained experiment values and rich comparisons` — complete (`332ae2b`), hardened (`5f0482e`). *(Shipped under commit titles "Enhance HTTP experiment diffing…" / "Harden HTTP experiment normalization…".)*
3. `feat(research): add principal-bound stateful workflows` — core runtime complete (`75680a7`).
4. `feat(research): Wave 4 hypothesis lifecycle` — core landed (`a608b59`); acceptance partial.
5. `feat(research): Wave 5 deterministic family proof handoffs` — registry/preflight landed (`3642b4b`); live actuators incomplete.
6. `feat(research): Wave 6 deterministic hypothesis scheduling` — request-cost ranking landed (`ebf2fca`); time/auth/storage gaps remain.
7. `feat(metrics): Wave 7 re-derivable acceptance + anti-fitting guard` — initial fixture/guard landed (`725397a`); full metrics and contamination coverage incomplete.
8. `feat(ui): Wave 8 adaptive workbench` — partial workbench landed (`d1762aa`); execution and QA scope incomplete.
9. `docs(research): Wave 9 status reconcile` — status documentation landed (`984d96d`); uniform gate integration remains to prove.

The shared verification-and-proof architecture (§4) landed first in `f32ef38`
(pure `api/adjudicate.py` + the symmetric negative gate). Remaining depth per
wave is noted inline in each wave's Status line above.

Each feature commit requires focused tests. Each runtime wave requires a full suite and rebuild before live validation. The execution gate must be restored to disabled after temporary local E2E use.

## 6. Out of scope until separately approved

- unrestricted shell, arbitrary code, or arbitrary URL execution;
- cross-origin experiment requests;
- unattended production execution;
- raw credential entry in planner requests;
- direct LLM finding creation or proof classification;
- destructive cleanup without explicit typed rollback and approval;
- distributed/multi-node execution without fencing and stale-owner-write protection.
