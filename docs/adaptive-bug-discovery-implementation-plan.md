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
- no LLM response can directly create or verify a finding.

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

**Status: in progress.**

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

### Wave 3: Principal-bound stateful workflow runtime

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

Each adapter returns one of: `verified`, `supported_unverified`, `refuted`, `inconclusive`, or `blocked`. Only `verified` output satisfying the existing family proof contract can create/promote a finding.

Acceptance:

- adapter mappings are registry-authoritative;
- unsupported experiment families fail closed;
- family proof receipts link exact experiment, target, route, principals, and evidence;
- tests prove LLM labels and generic anomalies cannot promote findings.

### Wave 6: Bug-bounty-oriented scheduling

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

## 4. Commit boundaries

1. `feat(research): add bounded HTTP differential experiments` - complete (`e786806`).
2. `feat(research): add chained experiment values and rich comparisons`.
3. `feat(research): add principal-bound stateful workflows`.
4. `feat(research): add adaptive hypothesis lifecycle`.
5. `feat(research): add deterministic experiment proof handoffs`.
6. `feat(research): add impact-aware hypothesis scheduling`.
7. `feat(metrics): add adaptive discovery recall scorecards`.
8. `feat(ui): add adaptive experiment workbench`.
9. `docs: reconcile adaptive discovery implementation status`.

Each feature commit requires focused tests. Each runtime wave requires a full suite and rebuild before live validation. The execution gate must be restored to disabled after temporary local E2E use.

## 5. Out of scope until separately approved

- unrestricted shell, arbitrary code, or arbitrary URL execution;
- cross-origin experiment requests;
- unattended production execution;
- raw credential entry in planner requests;
- direct LLM finding creation or proof classification;
- destructive cleanup without explicit typed rollback and approval;
- distributed/multi-node execution without fencing and stale-owner-write protection.

