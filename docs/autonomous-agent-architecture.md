# Autonomous Pentest Agent — Architecture & First-Slice Build Plan

_Goal: an autonomous pentest agent that uses the **brains of an LLM to try new things**, driving the
**existing tools** and the **knowledge already in our DB**, while keeping the zero-false-positive
verification moat. This document is the target architecture and a concrete first slice to build._

## 0. Why this document exists (the honest gap)

What the deep-hunt loop is today: the LLM is a **menu-selector**. Leads are produced by deterministic
code (`_endpoint_inventory_hypothesis_requests`, the app-graph producer); the families are a fixed set
(bola, mass_assignment, auth_bypass, data_exposure, sqli, xss); the exploit comes from a server-side
template (e.g. `_MASS_ASSIGNMENT_CREATE_TEMPLATE`, `_server_materialize_create_ma`, with `role=admin`
hardcoded); the verdict is 100% server-deterministic and the LLM is explicitly ignored. That design
buys zero-FP by **not trusting the LLM at all** — and, taken as far as the code takes it, it also
strangles the *propose* side down to "trigger a pre-approved template." Net effect: it can only
re-find **known bug classes**, which is why it took 100+ commits to make one family work end to end.

**The reframe: free process, verified output.** Let the LLM explore creatively with real tools + our
DB. Keep the moat as the gate on what gets **promoted**. Add a **suspected** tier for what can't yet be
auto-verified. Most of the pieces already exist; the missing part is an agentic loop that uses them
freely, plus one hard bridge (novel-claim → server-verified proof).

Legend: **[EXISTS]** reuse as-is · **[PARTIAL]** exists but not shaped for this · **[MISSING]** build it.

---

## 1. Layer 1 — Knowledge context ("use our DB")

A reasoning-grade **context pack** assembled per target from tables that already exist:

| Source | Table / component | Gives the agent |
|---|---|---|
| Surface | `target_endpoints` | routes, methods, `param_shape`, `auth_state`, `last_http_status` |
| Structure | application graph (route/object/principal nodes; producer/consumer/auth-boundary edges) | how the app is wired, where authz boundaries are |
| Prior results | `findings` (+ coverage), `retests` | what's known, verified vs suspected, what's covered |
| History | `tool_receipts`, `research_observations` | what's already been tried + outcomes (don't repeat) |
| Identity | `target_principals` / `target_credential_profiles` | which authenticated contexts are available |
| Fingerprint | scan `result.discovery.tech`, `waf_detection` | tech stack, WAF |

- **[PARTIAL]** the observation pack and arsenal "context packs" already assemble a compacted/redacted
  view — but built for a *selector*, not a *reasoner*.
- **[MISSING]** `GET /agent/context/{target_id}` → a single richer, reasoning-oriented pack (less
  redaction of structure, more "what's interesting/uncovered"), token-bounded.

## 2. Layer 2 — The agent loop (the brains)

A ReAct loop bounded by scope + budget: **read context → hypothesize → act (tool) → observe → update**.
The LLM's model comes from AI settings (`_load_effective_ai_settings`, `ai_verifier.shared_call`,
OpenRouter). Real capabilities are exposed to the model as **function-calls**:

| Tool | Backed by | Status |
|---|---|---|
| `http_request(method, path, headers, body, as_principal)` | new thin proxy; same-origin; principal auth resolved server-side (`_resolve_workflow_principal_contexts`) | **[MISSING]** the core "try it" primitive |
| `browser(action, ...)` | `InteractiveSessionManager` / `POST /session/{id}/action` (navigate/click/fill/login/extract/screenshot) | **[EXISTS]** — wrap as a tool |
| `run_tool(name, target, options)` | `scanner/scanner_tools/*` (nuclei, sqlmap, dalfox, ffuf…) | **[PARTIAL]** tools exist; no free per-tool invocation surface |
| `query_kb(kind, filter)` | the Layer-1 tables | **[MISSING]** read-only DB tool |
| `diff(a, b)` / `diff_principals(...)` | `compare_summaries` (workflow_experiment) | **[EXISTS]** — wrap as a tool |
| `note(kind, payload)` | `hypotheses` / `research_observations` | **[PARTIAL]** persist agent scratchpad |

**The biggest gap:** today the planner may only emit a **fixed command catalog**
(`experiment.workflow`, `scan.focused_family`, ASM). It cannot make a free request or run a tool of its
choosing. The AI Ops Router (`POST /ai/ops/route`) is the closest existing thing — NL → *bounded API
plan* — but it's bounded to the product API, not free tool use.

## 3. Layer 3 — The claim → proof bridge (the crux)

The agent emits a **CLAIM**:
```
{ narrative, evidence: [ {request, response} … ], assertion }
```
Promotion **reduces the claim to a server-verifiable proof** — the LLM's words are never the proof:

- **Known family** (bola/mass_assignment/…): build the family-proof workflow → the existing two-run
  verifier runs → promote. Reuse `family_proof.evaluate_family_proof`, `_trusted_workflow_family_proof`,
  `_arsenal_dispatch_workflow`, `_promote_trusted_workflow_finding`. **[EXISTS]**
- **Novel claim**: the `assertion` must come from a **constrained, server-evaluable predicate
  vocabulary** — the server re-runs the exact `evidence` requests and computes the predicate itself:

  | Predicate | Server check (deterministic, two-run) |
  |---|---|
  | `status_differential` | request A → 2xx while request B (other/anon principal) → deny |
  | `value_present` | a server-classified sensitive value (`_classify_sensitive_values`) appears in a response that should not carry it |
  | `cross_principal_equivalent` | two distinct verified principals get the *same* protected body (BOLA shape) |
  | `state_change_persisted` | before/after read of a resource differs after a mutation, and re-reads confirm |
  | `invariant_violated` | a typed target invariant (`target_invariant_contracts`) is broken |

- **Zero-FP invariant (non-negotiable):** the LLM picks *which* predicate + supplies the exact
  requests; the **server derives the verdict** from a fixed vocabulary via re-execution. This is the
  `workflow-proof-predicate-must-be-server-derived` lesson generalized. The predicate vocabulary is
  closed and each entry maps to existing server-side signal code (`_server_confirms_predicate`,
  `_server_corroborated_evidence`).
- **[EXISTS]** `experiment.http_diff` (read-only differential), `target_invariant_contracts`,
  `promotion_gate`, two-run. **[MISSING]** the general "LLM-proposes-a-constrained-assertion →
  server-verifies-and-promotes" path (today a novel claim can only promote by squeezing into a family;
  invariants must be operator-pre-approved).

## 4. Two output tiers (how real pentest teams work)

- **VERIFIED** — passed the server proof → promoted, zero-FP. *Trust.*
- **SUSPECTED** — the agent found/flagged it but it cannot be reduced to a server-checkable predicate
  (much business logic, or a judgment call) → surfaced clearly, **never** shown as verified. *Creativity
  without false trust.* The verifier is the boundary; a human promotes SUSPECTED → VERIFIED if they judge it real.
- **[PARTIAL]** finding `source_type` already separates `ai_session` (LLM-asserted) from `dast`.
  **[MISSING]** a first-class `verified | suspected` status with the verifier as the line, and a UI lane.

## 5. Layer 4 — Safety (free to explore, gated to promote)

The agent explores **freely within scope + budget**; only **promotion** needs the verifier and (for
active/credential-tier actions) approval. All the guardrails exist:
- Scope: same-origin enforcement, `scope_receipts`. **[EXISTS]**
- Budget: request / action / model-token caps (`budget_limits`, `RESEARCH_RECON_ACTION_CAP`). **[EXISTS]**
- Destructive writes: state-changing steps gated, best-effort restoration/cleanup. **[EXISTS]**
- Credentials: managed, **never model-visible** (only sha256 receipts persist). **[EXISTS]**
- Approval: credential-tier `arsenal/approvals` for active execution. **[EXISTS]**

## 6. Layer 5 — Learning

Persist every attempt → future episodes read it, don't repeat, build on it; a per-`(model, technique,
family)` **yield ledger** to learn what works (each `research_decisions.planner` already records
`model_used`/`fallback_index`). **[PARTIAL]** hypotheses/receipts/recent-action memory exist;
**[MISSING]** reasoning-over-history and the yield ledger view (see `docs/archive/…multi-model…` notes).

## 7. One iteration, concretely (a *novel*, un-templated example)

Target exposes `/api/coupons`. Agent:
1. `query_kb(graph)` → finds the coupon-apply endpoint + a cart/order object.
2. `http_request(POST /api/coupon/apply, {code}) as user1` → observes a discount.
3. Reasons: *"can I apply it twice?"* → `http_request` again → total drops **again**.
4. Emits **CLAIM** { evidence: [apply₁, read-total, apply₂, read-total], assertion:
   `state_change_persisted` on the order total across the second apply }.
5. Server re-runs the two applies + the reads, computes the total delta deterministically → **VERIFIED**
   (or, if not expressible in the vocabulary → **SUSPECTED**, surfaced for a human).

No template, no hardcoded family, no pre-seeded lead — the LLM's reasoning drove it; the server proved it.

## 8. Smallest first slice (proves the paradigm) — build order

1. **Context pack** — `GET /agent/context/{target_id}` from the Layer-1 tables (token-bounded). Reuse
   the existing observation-pack assembly, less redaction of structure.
2. **Four LLM tools** (function-call schemas), each a thin server proxy that enforces scope + budget:
   - `http_request` — same-origin only; `as_principal` resolves via `_resolve_workflow_principal_contexts`;
     record every call as a `tool_receipt`.
   - `query_kb` — read-only over endpoints / graph / findings / receipts.
   - `diff` — wrap `compare_summaries`.
   - `note` — persist a hypothesis/observation.
3. **Generalized differential verifier** — extend `experiment.http_diff`: input `{ evidence request-sets,
   one predicate from the closed vocabulary }`; the server re-executes twice and evaluates the
   server-derived predicate; on pass, promote via `_promote_trusted_workflow_finding` (tier=verified).
   Anything else → tier=suspected.
4. **Two-tier output** — `verified | suspected` on the finding; suspected never counts as proven.
5. **Unsteered test** — point it at Juice Shop with **no seeding and no hardcoded field**, budget-bounded,
   and measure: does it find *and verify* anything on its own, with **0 false positives** in the verified
   tier? Then repeat on crAPI / honey.

This is ~one agent loop + one verifier generalization, **reusing the moat wholesale**, and it directly
tests the real question: *can the LLM's brains + our tools + our DB find and verify something we did not
pre-build?*

## 9. Honest risks

- Verifying **novel** claims to zero-FP is genuinely hard. Expect most creative findings to land in
  **SUSPECTED**, not VERIFIED — that is the honest ceiling and it is acceptable (a human promotes the
  real ones). Do not widen the predicate vocabulary to "make more things verify" — that is where FP risk
  re-enters (see `trust-gate-antipatterns`).
- Free tool use costs tokens + requests; the budget discipline is what keeps a run bounded.
- This is a real re-architecture of the *propose* side, not a patch — but it keeps the verification moat
  (`family_proof` / two-run / `promotion_gate`) intact and unchanged.

## 10. Reuse map (do not rebuild)

`family_proof.*` · `_trusted_workflow_family_proof` · `_server_confirms_predicate` /
`_server_corroborated_evidence` · `_promote_trusted_workflow_finding` · `_arsenal_dispatch_workflow` ·
`experiment.http_diff` · `target_invariant_contracts` · `InteractiveSessionManager` + `/session/*` ·
`scanner/scanner_tools/*` · `compare_summaries` · `scope_receipts` / `arsenal/approvals` ·
`_resolve_workflow_principal_contexts` (managed creds) · `ai_verifier.shared_call` (LLM provider) ·
`research_episodes/observations/decisions` (lifecycle, leasing, budgets).
