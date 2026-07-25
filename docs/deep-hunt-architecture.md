# Deep Hunt Engine Architecture

**Status (2026-07-23):** current implementation reference for the Deep Hunt AI-investigator engine.
This is the single design authority for the engine; it restores the design content previously spread
across `product-model.md` and `functionality-reference.md` §11.6 after the older
`autonomous-agent-architecture.md` was retired. User-facing vocabulary lives in
[product-model.md](product-model.md); the exhaustive route/schema inventory is in
[functionality-reference.md](functionality-reference.md); the shared local execution model is in
[dast-asm-architecture.md](dast-asm-architecture.md); the post-0.7.0 acceptance backlog is
[proposed-next-steps.md](proposed-next-steps.md) §5.

Code, schema, and tests remain authoritative when this document disagrees. Symbols (functions,
constants, tables) are named rather than line-numbered so the references survive edits.

## What Deep Hunt is

Deep Hunt is the keyless, AI-driven investigation workflow reached through `/agent/hunt/*`. A coding
agent (Claude/Codex/OpenCode) — or a configured provider model — drives a bounded ReAct loop: it reads
a redacted target context, composes its own same-origin probes and bounded active-scanner runs,
records only tool-evidence-backed claims, and asks the server's deterministic proof workflows to
promote supported claims. ShakerScan owns scope, credentials, ceilings, evidence provenance, and every
promotion to VERIFIED. The model never sees credentials and can never self-stamp a verdict.

Two dimensions carry the entire trust story:

- **Two tiers.** SUSPECTED (passed the provenance gate; an agent-native claim) versus VERIFIED
  (re-proven by a deterministic server workflow). The VERIFIED tier is the moat and is never reachable
  from model assertion alone.
- **Two drivers, one core.** The keyless session (`POST /agent/hunt/{target}/session` → per-turn
  `.../session/{run_id}/reply`; the server suspends each turn and persists state in `agent_hunt_runs`)
  and the in-process loop (`_run_agent_hunt`, configured-provider) share one applied-reply core
  (`_agent_apply_reply`) and one finalizer (`_agent_finalize_and_persist`). They cannot diverge in gate
  or promotion behavior.

## Engine modules

| File | Role |
|---|---|
| `api/agent_loop.py` | Pure ReAct orchestration: system prompt, anti-stall messages, tool-output capping, duplicate/hallucination classifier |
| `api/agent_tools.py` | Tool schemas + pure guards (same-origin, header allowlist, `run_tool` argv templates, BOLA target derivation) |
| `api/agent_provenance.py` | SUSPECTED-tier provenance gate + self-verification stripping |
| `api/agent_text_toolcalls.py` | Keyless text-contract shim: render the contract, parse `tool_calls`/debrief, detect refusals |
| `api/agent_context_pack.py` | Token-bounded context packer with honest drop telemetry |
| `api/api.py` | Async execution, DB, both drivers, endpoints, and the verification bridge |

## The ReAct turn

1. **Seed** — build a token-bounded context pack from the target (redacted endpoints, findings, leads,
   principals, application-graph facts), render the tool contract, and assemble the system + user
   messages. The first observation the driver receives is itself a full system prompt: the tool
   arsenal, the RECON → PLAN → EXECUTE → EVIDENCE → SELF-CRITIQUE cadence, and the exact debrief schema.
2. **Plan** — the driver replies with a fenced ` ```json {"tool_calls":[…]} ``` ` block, or a terminal
   ` ```json {"done":true,"findings":[…],"abstained":false} ``` ` debrief.
3. **Apply** — `_agent_apply_reply` classifies each call, executes it, shapes evidence, records the
   event, and runs anti-stall. A successful `http_request` with tool provenance is assigned a stable
   `resp_N` reference; a successful `run_tool` gets `scan_N`. The runtime accepts either kind in a
   debrief's `evidence_refs`. The currently rendered text contract still teaches only `resp_N`, so a
   planner should use scanners for discovery and confirm a claim with `http_request` until that
   contract gap is closed. `diff` marks progress but does not currently receive a citeable reference.
4. **Terminate** — on an explicit debrief, on a terminal status (`completed` / `failed` / `cancelled`),
   or on a ceiling breach that forces a debrief. The keyless driver replies **only** while
   `status: awaiting_planner` and stops on any terminal status.

### Tool arsenal (five tools)

`CALLABLE_TOOL_NAMES = {http_request, query_kb, diff, note, run_tool}`:

- **`http_request`** — same-origin path only (absolute URLs, `//host`, and control characters are
  rejected); request headers pass an allowlist that strips forbidden/sensitive headers; auth is
  injected server-side from a resolved `as_principal` slot, so credentials are never model-visible;
  write methods are gated (`needs_approval` unless the hunt is write-authorized); bounded body, 15s
  timeout. A successful **tool-provenance** request produces a `resp_N` evidence ref.
- **`query_kb`** — read-only bounded SELECTs over `{endpoints, findings, hypotheses, principals,
  graph_nodes, graph_edges, tool_receipts, notes}`, row-capped. Produces **no** evidence ref, so a KB
  read can never back a finding.
- **`diff`** — compares two `resp_N` refs (or inline summaries) via the shared `compare_summaries`.
- **`note`** — scratchpad only (`hypothesis` / `observation` / `todo`); does **not** seed the lead
  board or create a finding.
- **`run_tool`** — argv-templated scanner runs (`httpx` read-only; `nuclei` / `katana` / `ffuf` are
  active and require write/active authorization). Argv is hardcoded per tool with only regex-gated
  tunables; same-origin is forced; output is capped; the subprocess is wall-clock killed. A
  successful run receives a `scan_N` evidence ref, although the current prompt does not advertise it.

Arbitrary state-changing HTTP stays blocked in the free-form loop; controlled mutations belong to typed
verification workflows with cleanup/restoration contracts.

### Ceilings and anti-stall

The two drivers do not yet have identical accounting. Keyless sessions enforce an action ceiling, a
request-**unit** ceiling of `min(400, iters·12)`, an active-action ceiling of
`min(24, iters)`, and ≤ 12 tool calls per turn. A request unit is currently one `http_request` or one
`run_tool` invocation; it is **not a wire-request count**. A bounded scanner may issue many target
requests while consuming one unit, so the request-unit ceiling must not be described as a hard target
request budget. Scanner argv templates still impose their own rate, duration, and subprocess limits.

Configured-provider research episodes additionally pass wall-clock and model-token budgets into the
in-process loop. A keyless session uses `token_budget` to size its seed context, but the server cannot
measure the external coding agent's tokens and does not currently impose a whole-session wall-clock
deadline. It does enforce per-tool timeouts and cancellation checks. Both drivers default to 20
iterations with a hard maximum of 40; the transcript is soft-capped with head+tail retention and each
tool result is capped at 8000 characters. Anti-stall covers duplicate calls, hallucinated tools,
≥ 4 no-progress turns, > 2 empty replies, and a transient planner-error cap; a likely refusal is
honored, not overridden.

These ceilings are **breadth/depth knobs** — loosening them cannot manufacture a false SUSPECTED or
VERIFIED, so they are safe to tune independently of the trust gates. Keep that separation explicit: the
trust gates below are never relaxed for throughput.

## The provenance gate (→ SUSPECTED)

A debrief finding is stamped `provenance:"model"` at parse time, and self-verification keys are
stripped (`strip_self_verification` removes `verified`, `verified_at`, `verify_gate`, `promotable`,
etc.), so a debrief can never self-assert VERIFIED. `gate_live_finding` then admits it to SUSPECTED
**only** if it carries ≥ 1 evidence item of a tool kind (`{output, command, response, request, log,
file}`) with non-empty content; a critical/high asserted with zero evidence is blocked as overclaim.

Evidence resolution is per-finding and fail-closed: each finding's `evidence_refs` resolve against
**its own** cited `resp_N` or `scan_N` refs only — never another finding's, never the uncited run pool.
A ref that does not resolve yields empty evidence, and the finding is **blocked** (surfaced to the
operator but never persisted). Inline `details` / `evidence` prose is **not** evidence.

This is the single thing a first-time driver most often gets wrong: proof is `evidence_refs` pointing
at real tool refs, normally `resp_N` responses, not prose. A prose-only finding persists nothing.

Persistence writes `tool='autonomous_agent'`, `source='autonomous'`, and leaves
`last_verification_verdict` NULL. Rediscovery updates visibility only; it never reopens a
human-triaged row.

## The verification bridge (SUSPECTED → VERIFIED)

Three promotion paths, routed by family. The paths differ in what supplies the verdict, never in who
may assert it — the server always does.

| Path | Families | Mechanism |
|---|---|---|
| **A — deterministic DAST retest** | xss, sqli, nosqli, ssrf, path_traversal, open_redirect, ssti, command_injection, cors (route-only) | The SUSPECTED lead carries `retest_type` + `param` + `payload` in evidence; it is auto-queued as a `deterministic` retest job. The worker prover is the **sole arbiter**; the finding stays SUSPECTED until the prover writes `verdict='exploited'`. The model supplies only the injection point, never a verdict. |
| **B — family_proof moat** | bola, auth_bypass, data_exposure, mass_assignment | A two-run workflow dispatched through the unchanged arsenal moat (distinct-principal / control differential), guarded by a cross-process advisory lock. |
| **C — invariant contract** | access_control, field_constraint, workflow | Uses the same moat machinery as B, but the predicate comes from an operator-**approved** `target_invariant_contracts` row (`source="invariant"`). **No approved contract → HTTP 422 → the finding stays SUSPECTED.** The server never guesses policy; a draft contract cannot promote. The `workflow_transition` contract requires a `probe_state` at approval time. |

### `family` is a closed vocabulary

A debrief's `family` must be a value some promoter accepts — the moat set above, or a Path-A DAST
type. `agent_text_toolcalls.ADVERTISED_FAMILIES` is that vocabulary, and the rendered contract
enumerates it exactly (no open `…`). A family outside it passes the provenance gate, persists as
SUSPECTED, and can then never be promoted by any path.

Two spellings the system itself used to invite are the reason this is pinned by
`test_every_advertised_debrief_family_is_promotable`, which asserts the contract and the promoters
agree in **both** directions:

- **`injection`** — the old schema line advertised it, but neither path takes it: the deterministic
  prover dispatches on the *specific* type. Use `xss` / `sqli` / `nosqli` / `ssti`, never the generic.
- **`workflow_transition`** — the invariant **contract kind**, not a family.
  `invariant_contracts.CONTRACT_KINDS` maps it back to family `workflow`, and
  `family_proof.canonical_family` has no alias for it, so claiming it 422s at the bridge. Use
  `workflow`. (`bfla` and `business_logic` *are* aliases, of `auth_bypass` and `workflow`.)

When the moat cannot verify a family, `_agent_auto_verify` now records why rather than dropping it
silently: `family_routed_to_dast_retest` (a Path-A lead, promoted by the retest pipeline instead) or
`family_not_verifiable` (a taxonomy mismatch — the finding is stuck at SUSPECTED). These records carry
no budget reservation and do not consume `_AGENT_AUTO_VERIFY_LIMIT`, which caps real verification
traffic.

### Auto-promotable today

`_agent_auto_verify` runs unattended only when the hunt carries an approval receipt and gated execution
is enabled, capped per run with per-family request/second reservations:

- **auth_bypass, data_exposure** — GET-only; auto-promotable from a read-only gated hunt.
- **access_control** — auto-promotable **only** when an approved invariant contract exists (GET-only
  role differential).
- **mass_assignment (create/POST only), field_constraint, workflow** — mutating
  (`_AGENT_MUTATING_VERIFY_FAMILIES`); auto-verify **only** on a write-authorized hunt, otherwise
  skipped as `mutating_verification_requires_gated_hunt`.

### Deliberately NOT auto-promotable (known limitations, by design)

- **BOLA never auto-verifies.** The family_proof moat proves a *managed/distinct reference*, not
  *ownership* — a shared-behind-login collection would false-VERIFY. BOLA is promotable only through the
  manual `POST /agent/findings/{id}/verify` endpoint. The sound fix is an ownership oracle
  (invariant-contract style), mirroring access_control. This is the biggest recall gap and the top
  backlog item.
- **Update-based mass_assignment** (PUT/PATCH of a privileged field) is not yet bridged; only
  create-based POST is server-materialized.
- The upstream refusal-**reframe** helper was deliberately **not ported**. ShakerScan detects and
  honors a planner refusal; it does not automatically override the model's safety decision.

## Planner model

Modes (`RESEARCH_PLANNER_MODES`):

- **`agent` (keyless — the default).** The coding-agent session is the planner. No stored provider key
  is required; the server suspends per turn and the reply arrives as the POST body of
  `.../session/{run_id}/reply`. State is durable **between completed turns**, so an API restart while
  the run is `awaiting_planner` can continue. A restart during an in-flight `planning` turn is
  deliberately not reclaimed because replay could duplicate active traffic; the run remains fenced
  until the operator cancels and relaunches it. Mid-turn idempotent recovery is backlog work.
- **`configured_ai`.** A provider model is invoked in-process (`_agent_planner_reply`: temperature 0.3,
  JSON-object mode, bounded max-tokens, with model fallbacks). There is no hardcoded default model — an
  unconfigured `configured_ai` run fails closed (`configured_ai_not_ready`). **This loop is not
  per-turn checkpointed:** a mid-hunt restart cannot resume, and the run-once guard fails closed to
  `interrupted_no_resume` (relaunch required). Closing this is backlog item 5.
- **`local_codex`.** A separate research-episode adapter, not the ReAct hunt planner.

## Tests and the coverage gap

Pure decision logic is well covered: `tests/test_agent_ports.py` (~60 tests across all five engine
modules — provenance gate, text-contract parse/interpret/refusal, loop helpers, context pack, tool
guards, and BOLA target derivation including zero-FP unrelated-ref cases) and the bridge *builders* in
`tests/test_api_helpers.py` (workflow shapes, materializers, invariant approval/binding, route
abstain).

**Gap:** no integration test exercises the orchestration drivers or HTTP endpoints end-to-end (they
need a DB + provider fixture) — `_run_agent_hunt`, `_agent_apply_reply`, `submit_agent_hunt_reply`,
`start_agent_hunt_session`, `_agent_finalize_and_persist`, `_agent_auto_verify`,
`_agent_auto_queue_dast_retests`, and the actual moat dispatch are unit-untested. The pure logic and
workflow shapes are tested; the wiring that runs them is not. Closing this is the highest-value test
investment for the §5 work (backlog item 6).

## Improvement backlog (maps to proposed-next-steps.md §5)

**Do-not-change trust invariants while pursuing any item below:** the `family_proof` moat and its
two-run proof stay untouched; business-logic VERIFIED comes only from operator-approved invariants; and
arbitrary shell, model-supplied credentials, and AI-only VERIFIED findings stay excluded. Every item is
a recall/quality gain that must preserve the zero-false-VERIFIED guarantee.

1. **Honest active-traffic metering** — reserve or measure the wire requests generated by each
   `run_tool` adapter, expose metering quality, and add a whole-session deadline for keyless runs.
2. **Unified evidence-reference contract** — advertise `scan_N` honestly or require HTTP
   confirmation, and give useful `diff` results a citeable provenance-bearing ref.
3. **Integration test harness** — end-to-end driver/endpoint tests behind a DB + provider fixture,
   including cancellation, traffic accounting, persistence, deterministic retest queueing, and proof
   promotion.
4. **BOLA ownership oracle** — give BOLA a sound auto-promotion path via an invariant-style ownership
   contract (the access_control pattern) instead of leaving it manual-only. Highest-value recall win.
5. **Update-based mass_assignment** — bridge PUT/PATCH privileged-field writes with a restoration
   contract, not just create-based POST.
6. **Object-instance route induction & surface persistence** (§5) — induce concrete `{id}` instances
   from observed responses and persist authorized OpenAPI / custom-endpoint ingestion into the canonical
   target surface, so `{id}` placeholders resolve in the no-captured-ref verification workflows.
7. **Driver-quality measurement** (§5) — instrument useful-action selection, verified net-new yield,
   false-promotion rate, cost, retry behavior, cleanup success, and stop quality across the `agent` and
   `configured_ai` planners.
8. **Driver resumability** — checkpoint the configured-provider loop per turn and design idempotent,
   receipt-backed recovery for a keyless turn interrupted while `planning`. Between-turn keyless
   durability already works; neither driver should replay uncertain active traffic.

## API surface

```text
POST /agent/hunt/{target_id}/session        # start a keyless Deep Hunt
POST /agent/hunt/session/{run_id}/reply     # one planner turn (a tool_calls block or a final debrief)
GET  /agent/hunt/session/{run_id}           # inspect the run / transcript
POST /agent/hunt/session/{run_id}/cancel
POST /agent/hunt/{target_id}                # in-process (configured_ai) hunt
POST /agent/findings/{finding_id}/verify    # manual SUSPECTED -> VERIFIED (the only BOLA path)
GET  /agent/findings/{target_id}            # two-tier finding view (VERIFIED moat vs SUSPECTED agent)
```
