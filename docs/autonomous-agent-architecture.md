# Autonomous Pentest Agent — Architecture & Build Plan (borrowed from T3MP3ST)

_Goal: an autonomous pentest agent that uses the **brains of an LLM to try new things**, driving the
**existing tools** and the **knowledge already in our DB**, while keeping the zero-false-positive moat.
This is the target architecture. It is deliberately built by **borrowing T3MP3ST's proven implementation**
(the T3MP3ST reference checkout, cited as `T:path:line`), not by inventing our own scaffolding — that was
the mistake of the last 100 commits._

## 0. The honest gap, and T3MP3ST's lesson

**What our deep-hunt loop is today: a menu-selector.** Leads are produced by deterministic code
(`_endpoint_inventory_hypothesis_requests`); families are a fixed set; the exploit is a server-side template
(`_server_materialize_create_ma`, with `role=admin` hardcoded); the verdict is 100% server-deterministic and
the LLM is explicitly ignored. That buys zero-FP by **not trusting the LLM at all** — and strangles the
*propose* side down to "trigger a pre-approved template." It can only re-find **known bug classes**. That is
why it took 100+ commits to make one family (create-MA) work end-to-end.

**T3MP3ST's v4 breakthrough (their `docs/COGNITIVE_ARCHITECTURE.md`): removing the hand-coded recipes *raised*
the solve rate.** Their words: *"the bottleneck was never the agent's knowledge — Opus knows the attacks. The
bottleneck was persistence. A hand-coded recipe is a crutch that also caps the agent at what we thought to
write down."* Our templates are exactly that crutch. **The reframe: free process, verified output.** Let the
LLM explore with real tools; keep the moat only as the **promotion gate**; add a **suspected** tier for what
can't be auto-verified.

Legend: **[EXISTS]** reuse as-is · **[PARTIAL]** exists but not shaped for this · **[BORROW]** port T3MP3ST's
mechanism · **[BUILD]** new.

---

## 1. What T3MP3ST actually does (the thing to borrow, not reinvent)

There are **three distinct mechanisms** in T3MP3ST — do not conflate them. The reusable one is the plain
production loop, **not** the elaborate cognitive harness that the vision docs describe.

| Mechanism | Location | What it is | For us |
|---|---|---|---|
| **Production ReAct loop** | `T:src/agent/index.ts` | Native tool-calling observe→reason→act loop. **The real autonomy engine.** | **BORROW — this is the core** |
| Cognitive CTF harness | `T:scripts/cybench-bench.mjs:404` (`TOOLS_SYSTEM`) | The 5-phase recon→plan→execute→reflect→self-critique loop + anti-give-up floor. Benchmark brain, **not wired to the server.** | Borrow only the *system-prompt* discipline |
| Decomposition orchestrator | `T:src/orchestration/orchestrator.ts` | Two-model white-box code-analysis (guardrail decomposition). | Not now (source-analysis, not live pentest) |

### 1a. The production loop mechanics (`T:src/agent/index.ts`)

A bounded `for` loop; the transcript **is** the working memory; it stops when the model stops calling tools:

```
for i in range(maxIterations):                 # default 15 (:95); CTF harness uses 60
    resp = llm.chatWithTools(messages, toolDefs, temperature=0.3)
    if resp.tool_calls:                        # ── ACT ──
        for call in resp.tool_calls:
            result = execute_tool(call)         # OBSERVE (scope+approval gated first)
            messages.append(role="tool", content=result)
    else:                                       # ── natural stop = final answer ──
        return parse_final_debrief(resp)
```

**The four anti-stall mechanisms are what make it autonomous instead of a menu-selector — borrow all four:**
- **Dup-call suppression** (`T:...:170-183`): hash `name:json(args)`; a byte-identical repeat returns a
  synthetic *"do NOT repeat it — change args or finish"* instead of re-running.
- **No-progress steering** (`T:...:208-215`): after 4 iterations with **no new findings**, inject a nudge to
  pursue a genuinely different vector or debrief.
- **Hallucinated-tool recovery** (`T:...:317-331`): an unknown tool name returns the callable-tool list so
  the model self-corrects — it does not crash the loop.
- **Error recovery** (`T:...:252-261`): a thrown tool error is fed back as a message; the loop continues.

Tool output is capped **HEAD+TAIL** to protect the window (`formatToolResult`, `T:...:435-467`, ~4000 chars).
The CTF harness adds the persistence discipline the production loop lacks: an explicit phase cadence and a
**hard anti-give-up floor** ("you may NOT give up before iteration 20"). That discipline belongs in our
**system prompt**, not in more code.

### 1b. The honesty spine — how they get trustworthy findings WITHOUT re-execution

This is the most important part for us, and it maps directly onto our moat. **The LLM cannot self-assert a
verified finding:**
- Every finding carries **provenance** from birth: tool-emitted = `provenance:'tool'` with the raw output
  that backs it (`T:src/agent/index.ts:187-192`); the model's own debrief = `provenance:'model'`, parsed from
  **one mandatory fenced ```json block** — *"the ONLY finding channel the harness records; prose is dropped"*
  (`parseFinalFindings`, `T:...:474-499`).
- `gateLiveFinding()` (`T:src/evidence/gate.ts:33`) marks a finding **verified only if backed by real
  tool-output evidence** (`output/command/response/request/log/file` — `T:...:18`); critical/high with zero
  evidence = overclaim, **blocked**. `EvidenceVault.verifyFinding` strips any caller-supplied `verifiedAt`
  (`T:src/evidence/index.ts:139`) so **nothing can self-verify**.
- They do **not** run a scripted exploit-replay in the live loop; their verification = **provenance** (did a
  real tool produce this?). The heavier refuter-panel + source-cite-check lives on the disclosure side
  (`adjudicate`, `T:src/mission/adjudicate.ts:95`).

**Our moat is strictly stronger than their bar** (we *re-execute* and derive the predicate). So the two
compose perfectly (§2).

### 1c. Containment lives in code, not in the model (`T:src/arsenal/index.ts`)

- **Egress scope gate** `scopeViolation()` runs **before any handler** (`T:...:264-266`), fails **closed** on
  bypass shapes (`//evil`, `file://`), validates CIDR. We have this: same-origin + `scope_receipts`.
- **Capability approval gate** (`T:src/arsenal/approval.ts`): `intrusive|credential|dangerous` tools are inert
  until approved; **fail-safe** — gated + unapproved + no approver ⇒ DENIED (`T:...:188-195`). We have
  `arsenal/approvals`.
- **No generic "run arbitrary shell" tool.** External scanners are exposed through **hardcoded argv
  templates** (`adapterToCustomTool`, `T:src/arsenal/adapter-tools.ts:415`; `ARG_TEMPLATES:122`): the LLM
  picks *tool + target*, never raw flags. Only `safe_command`/`receipt_required` adapters are mintable.

---

## 2. The synthesis: free ReAct process → provenance gate → server re-execution

```
                 ┌─────────────────── the LLM's free process (BORROW T3MP3ST loop) ──────────────────┐
  context pack → │ ReAct loop over REAL tools: http_request · browser · run_tool · query_kb · diff    │
   (our DB)      │ anti-stall: dup-hash · no-progress steer · tool-recovery · anti-give-up persistence │
                 └───────────────────────────────────┬────────────────────────────────────────────────┘
                                                      │ single JSON debrief, tool-backed evidence only
                                    ┌─────────────────▼─────────────────┐
                                    │ PROVENANCE GATE (borrow gate.ts)  │  prose → dropped
                                    │ evidence must be real tool output │  model self-claim → not verified
                                    └─────────────────┬─────────────────┘
                                                      │
                        ┌─────────────────────────────┴─────────────────────────────┐
        server RE-EXECUTES the evidence request-set                     cannot reduce to a closed predicate
        & derives a closed-vocabulary predicate (OUR MOAT)              (business logic / judgment call)
                        │                                                             │
                        ▼                                                             ▼
                  ✅ VERIFIED tier  (zero-FP, promoted)                        🟡 SUSPECTED tier
                  family_proof.evaluate_family_proof                          (surfaced, a human promotes)
```

- **VERIFIED** ⊃ T3MP3ST's "verified": they stop at provenance; **we additionally re-run the evidence and
  derive the verdict server-side** (`family_proof` / two-run / `promotion_gate`, unchanged). *Trust.*
- **SUSPECTED**: provenance-backed (real tool evidence, never prose) but not reducible to a server predicate.
  *Creativity without false trust.* This tier is exactly T3MP3ST's provenance gate, adopted wholesale.
- The zero-FP invariant is untouched: **the LLM picks which predicate + supplies the exact requests; the
  server derives the verdict** (the `workflow-proof-predicate-must-be-server-derived` lesson).

---

## 3. The loop to build (borrow `T:src/agent/index.ts` wholesale)

Map T3MP3ST's loop onto our durable lifecycle so it survives restarts (our advantage — theirs is in-process):

| T3MP3ST | Ours | Status |
|---|---|---|
| `messages[]` transcript-as-memory | `research_observations` + decision trail per episode | **[PARTIAL]** persist the ReAct transcript, not just a selector obs |
| `chatWithTools(messages, toolDefs)` | `_plan_research_episode_step` → `ai_verifier.shared_call` | **[PARTIAL]** must pass **tool schemas**, not a menu |
| natural stop (no tool calls) | `stop_recommended` / conclusion turn | **[EXISTS]** |
| dup-call suppression | `excluded_actions` (per-hash) | **[PARTIAL]** add the *synthetic-steer* reply, not just rejection |
| no-progress steering (4 iters) | `planner_guidance` | **[BORROW]** wire the 4-iter no-new-finding nudge |
| anti-give-up floor | planner system prompt | **[BORROW]** system-prompt discipline |
| `maxIterations`/token cap | `max_steps` / budget caps | **[EXISTS]** |

The single biggest change: today the planner may only emit a **fixed command catalog** (`experiment.workflow`,
`scan.focused_family`, ASM). **Open it into a real tool loop** (§4). The AI Ops Router (`POST /ai/ops/route`)
is the closest existing surface — NL → *bounded API plan* — but it's bounded to the product API, not free
tool use.

## 4. The tools to expose (borrow `T:src/arsenal` + `adapter-tools`)

Expose our real capabilities as **function-call schemas** (`Arsenal.getToolDefinitions`,
`T:src/arsenal/index.ts:347`), each a thin server proxy that enforces **scope + approval before the handler**:

| Tool | Backed by (ours) | Borrow from T3MP3ST | Status |
|---|---|---|---|
| `http_request(method, path, headers, body, as_principal)` | new thin proxy; same-origin; principal via `_resolve_workflow_principal_contexts`; every call → `tool_receipt` | `http_request` builtin | **[BUILD]** the core "try it" primitive |
| `browser(action, …)` | `InteractiveSessionManager` / `/session/{id}/action` | (they have no browser) | **[EXISTS]** wrap as a tool |
| `run_tool(name, target, options)` | `scanner/scanner_tools/*` (nuclei/sqlmap/dalfox/ffuf) | **`ARG_TEMPLATES`** — hardcoded argv, LLM never sets flags | **[PARTIAL]** add the argv-template wrapper |
| `query_kb(kind, filter)` | Layer-1 tables (endpoints/graph/findings/receipts) | context assembly | **[BUILD]** read-only DB tool |
| `diff(a, b)` / `diff_principals(…)` | `compare_summaries` (workflow_experiment) | — | **[EXISTS]** wrap |
| `note(kind, payload)` | `hypotheses` / `research_observations` | pack-board leads | **[PARTIAL]** agent scratchpad |

**Two borrows are decisive:**
1. **Text-contract fallback** (`renderToolContract`/`parseTextToolCalls`, `T:src/llm/index.ts:835/881`). Our
   **default `planner_mode: "agent"` is keyless** — the coding-agent session is the planner, with no stored
   API key and no native tool API. T3MP3ST solves exactly this: describe the tools in-prompt, emit a
   ` ```json {"tool_calls":[…]} ``` ` block, parse it back with a ReDoS-safe balanced-brace scanner. **This is
   how a keyless local planner still drives a real tool loop** — port it directly instead of inventing.
2. **Hardcoded argv templates** for scanners (`T:src/arsenal/adapter-tools.ts:122`) + **no arbitrary shell**.
   Preserves our containment while giving the LLM real tools.

## 5. The finding gate (borrow `T:src/evidence/gate.ts`; keep our moat as the VERIFIED tier)

- **Provenance from birth** (borrow): tool-emitted evidence = `provenance:tool`; the model's debrief is the
  **only** model channel, one mandatory JSON block; prose is dropped.
- **SUSPECTED gate** (borrow `gateLiveFinding`): a finding is surfaced only if backed by real tool output
  (`request/response/command/log`), never prose; critical/high with no evidence = blocked overclaim.
- **VERIFIED gate** (ours, unchanged): the server re-runs the evidence request-set and derives a
  closed-vocabulary predicate via two-run (`family_proof.evaluate_family_proof`,
  `_promote_trusted_workflow_finding`). **[EXISTS]** — do not touch.
- **[BUILD]** a first-class `verified | suspected` status with the verifier as the boundary + a UI lane.
  `source_type` already separates `ai_session` from `dast`; this makes the trust line explicit.

The closed predicate vocabulary (unchanged, server-derived — do not widen to "make more things verify"):

| Predicate | Server check (deterministic, two-run) |
|---|---|
| `status_differential` | request A → 2xx while other/anon principal → deny |
| `cross_principal_equivalent` | two distinct verified principals get the same protected body (BOLA) |
| `sensitive_value_present` | a server-classified sensitive value appears where it must not |
| `state_change_persisted` | before/after read differs after a mutation, re-reads confirm |
| `invariant_violated` | a typed `target_invariant_contract` is broken |

## 6. Context pack — "use our DB" (borrow `T:src/orchestration/context-pack.ts` honesty)

A reasoning-grade pack per target from tables that already exist (`target_endpoints`, application graph,
`findings`+coverage, `tool_receipts`/`research_observations`, `target_principals`, scan tech/WAF). Borrow
`packContext`'s **honest telemetry**: an always-present map header, relevance ranking, head/tail elision, and
an explicit `includedFiles/droppedFiles` list — **"no silent loss"** (our `trust-gate-antipatterns` lesson:
silent truncation reads as coverage). **[PARTIAL]** the observation pack assembles a *redacted selector* view;
**[BUILD]** `GET /agent/context/{target_id}` — richer, structure-preserving, token-bounded, with drop telemetry.

## 7. Planner hierarchy + shared board (borrow `T:src/admiral` → `mission` → `pack`)

T3MP3ST layers command above the loop; we already have most of it — map, don't rebuild:

| T3MP3ST | Ours | Status |
|---|---|---|
| **Admiral** NL intake, **dry-run default** (`T:src/admiral/index.ts:99` — "a typed 'I'm authorized' is a claim, not authorization") | `POST /research/launch` + approval receipts | **[EXISTS]** |
| **Op General** strategic plan, hunt-lane decomposition (`T:src/prompts/index.ts:915`) | campaign → episode objective | **[PARTIAL]** |
| **MissionControl / TaskQueue** kill-chain task factories (`T:src/mission/index.ts:558`) | ranked hypothesis board / producers | **[PARTIAL]** |
| **tick()** dispatch, reaping (`T:src/index.ts:853`) | supervisor + lease/heartbeat | **[EXISTS]** |
| **PackBoard** append-only log + `claim()` **compare-and-set** so two agents don't chase one lead (`T:src/pack/board.ts:257`) | the ranked board + `excluded_hypothesis_ids` | **[PARTIAL]** add a real CAS claim for parallel agents |

**Model fallback ladder** (`T:src/llm/index.ts:1260`): advance on error **or** on a detected refusal, and on
refusal prepend an **honest authorization restatement** (`reframeWithAuthorizedContext`, `T:...:1133` — "NOT a
jailbreak"). We have `ai_verifier.shared_call` fallback (reliability-only); **[BORROW]** the honest-reframe
retry.

## 8. Safety (free to explore, gated to promote) — we already have T3MP3ST's layers

Scope (same-origin + `scope_receipts`) · budget (`budget_limits`, `RESEARCH_RECON_ACTION_CAP`) · destructive
writes gated + best-effort restoration · credentials **never model-visible** (sha256 receipts only) ·
credential-tier `arsenal/approvals` for active execution · fail-closed on unknown. All **[EXISTS]**. The
borrow is only the *tool-execution* placement: **scope + approval run before every tool handler**, exactly as
T3MP3ST's `execute()` does — never left to the model.

## 9. Smallest first slice (borrow-first, proves the paradigm)

**BUILD STATUS (2026-07-18): slices 1–4 DONE; keyless default (Gap A) DONE + live-validated.**
Both drivers now share one loop core (`_agent_seed_state` / `_agent_apply_reply` / `_agent_finalize_and_persist`
in `api/api.py`): the in-process `configured_ai` loop and a durable, turn-based **keyless** driver
(`agent_hunt_runs` table + `POST /agent/hunt/{target}/session`, `.../session/{run_id}/reply|cancel`). Live
keyless proof on Juice Shop (this coding-agent session as planner, no key): 4 turns / 7 tool calls; all four
tools executed server-side; a tool-proven BOLA passed the provenance gate → SUSPECTED, while a zero-evidence
"critical SQLi" was **blocked and never persisted** (fail-closed); the `family_proof` VERIFIED moat added
nothing (0 FP). Remaining: **(B)** auto-bridge a gate-passing SUSPECTED finding into `family_proof` re-execution
(unattended promotion), and **(C)** present keyless turns from the durable campaign supervisor so a
`planner_mode:"agent"` deep-hunt campaign drives this loop end-to-end.

1. **Context pack** — `GET /agent/context/{target_id}` from Layer-1 tables, token-bounded, **with drop
   telemetry** (borrow `packContext`). **[DONE]**
2. **The ReAct loop** — port `T:src/agent/index.ts`: bounded loop, transcript-as-memory, **the four anti-stall
   mechanisms**, natural stop. Driven server-side for `configured_ai`, and **turn-by-turn for keyless
   `planner_mode:"agent"`** via the shared `_agent_apply_reply` core + the **text-contract fallback**. **[DONE]**
3. **Four tools** as function-calls, scope+approval-gated: `http_request` (the "try it" primitive; every call a
   `tool_receipt`), `query_kb` (read-only), `diff`, `note` + argv-templated `run_tool`. **[DONE]**
4. **Provenance + two-tier output** — borrow `gateLiveFinding` for the SUSPECTED bar; keep `family_proof`
   re-execution as VERIFIED; `GET /agent/findings/{target}` splits `verified | suspected`. **[DONE]**
5. **Unsteered test** — point it at Juice Shop with **no seeding, no hardcoded field**, budget-bounded, and
   measure: does the LLM's brains + our tools + our DB **find and verify** something we did not pre-build,
   with **0 false positives in the verified tier**? Then crAPI / honey. (Contrast with today's `role=admin`
   hardcoded create-MA — that is the crutch we are removing.) **[keyless plumbing validated 0-FP; a genuinely
   net-new *verified* promotion still needs Gap B.]**

## 10. Borrow map (T3MP3ST) + Reuse map (ours)

**Borrow (port the mechanism):** `T:src/agent/index.ts` ReAct loop + anti-stall quartet + `parseFinalFindings`
· `T:src/llm/index.ts` text-contract fallback (`renderToolContract`/`parseTextToolCalls`) + fallback ladder +
honest-reframe · `T:src/arsenal/adapter-tools.ts` argv templates · `T:src/evidence/gate.ts` provenance gate ·
`T:src/orchestration/context-pack.ts` honest packing · `T:src/pack/board.ts` CAS claim · CTF system-prompt
persistence discipline.

**Reuse (do not rebuild):** `family_proof.*` · `_trusted_workflow_family_proof` ·
`_server_confirms_predicate` / `_server_corroborated_evidence` · `_promote_trusted_workflow_finding` ·
`_arsenal_dispatch_workflow` · `experiment.http_diff` · `target_invariant_contracts` ·
`InteractiveSessionManager` + `/session/*` · `scanner/scanner_tools/*` · `compare_summaries` ·
`scope_receipts` / `arsenal/approvals` · `_resolve_workflow_principal_contexts` · `ai_verifier.shared_call` ·
`research_episodes/observations/decisions` (lifecycle, leasing, budgets).

## 11. Honest risks

- Verifying **novel** claims to zero-FP is genuinely hard; expect most creative findings to land in
  **SUSPECTED**, not VERIFIED — that is the honest ceiling and it is acceptable (a human promotes the real
  ones). **Do not widen the predicate vocabulary to "make more things verify"** — that is where FP risk
  re-enters (`trust-gate-antipatterns`).
- Free tool use costs tokens + requests; the anti-stall discipline + budget caps are what keep a run bounded.
- This re-architects the *propose* side (menu-selector → ReAct agent) but keeps the verification moat intact
  and unchanged. It is a **port of T3MP3ST's loop onto our moat**, not a new invention — that distinction is
  the whole point of this revision.

## 12. Shipped: the business-logic VERIFIED bridge (Explorer vs T3MP3ST, phases 0–B2)

Follow-up to §11's honest ceiling: business-logic findings now reach VERIFIED **from operator-approved
invariant contracts**, not from any vocabulary growth. The moat already verified
access_control / field_constraint / workflow_transition from live observations
(`_trusted_invariant_execution_evidence` + unchanged two-run `evaluate_family_proof`); what shipped is
the wiring plus the auto-draft pipeline, black-box first.

| Phase | Content | Status |
|---|---|---|
| **0** | access_control auto-verify against an APPROVED role oracle + `invariant_proposals` drafts | shipped |
| **A1** | field_constraint auto-verify (first mutating family; runtime-captured baseline; mandatory field-scoped restoration) | shipped, live-validated |
| **A2** | workflow_transition auto-verify (contract's `probe_state` = the forbidden target attempted) | shipped, live-validated |
| **A3** | generalized auto-draft flow: ownership (graph auth_boundary edges), field_constraint (numeric caps), workflow_transition (state hints), SUSPECTED findings → matching drafts; auto-persisted at board seeding; `invariant_candidates` pack section | shipped |
| **B1** | black-box observed-artifact grounding: inventory-sourced leads (already residue-backed) + `observed_artifacts` pack section | shipped |
| **B2** | opt-in grey-box source ingester (`source_dir` on hunt start; `SHAKERSCAN_SOURCE_ROOT` containment; security-ranked `source_excerpt` pack section + source-derived leads) | shipped |
| — | decomposition orchestrator | **skipped** per plan (blind-worker decomposition solves refusal-avoidance + >1-context-window repos; neither is our black-box-first case) |

**Non-negotiable invariants (reaffirmed, enforced by tests):** the model never supplies a verdict —
only the two-run server binder derives predicates; the new families never enter the non-invariant
proof branch or `_server_confirms_predicate`; `VERIFIABLE_PREDICATES` / `FAMILY_CONTRACTS` stay closed
(`invariant_violated` already means "a typed contract is broken"); the free-form loop stays read-only —
all mutation lives in the server-materialized verify workflow with a mandatory restoration contract;
auto-proposed invariants are always `status='draft'` (approval is a human action).

**Zero-FP guardrails added during this work (audit fixes):** the workflow_transition binder derives
`transition_invariant_broken` ONLY when the object started in the approved `from_state` AND the app
persisted the contract-declared forbidden `probe_state` (a wrong starting state or a coerced write
derives nothing); a mutation never fires unless every rollback/cleanup step is renderable with what is
already bound (a failed baseline read stops the workflow before any state change); restoration replays
the full captured parent object with original JSON types (a PUT-replace API gets every sibling field
back); `probe_state` is an approval-time requirement for workflow_transition contracts.

**Re-validated live at HEAD after the audit fixes:** a keyless deep_hunt on the local Juice Shop
honey target drove a `field_constraint` finding (`BasketItem.quantity<=3`) SUSPECTED→VERIFIED through
the *post-fix* full-body typed restore — `family_proof.verdict=verified`, and the live object was
left at `quantity=1` (int) with every sibling field intact (only the server `updatedAt` bumped, which
field-scoped restoration tolerates). Confirms the F1/F3/F4 changes preserve the A1/A2 live positives
end-to-end, not just in unit tests.

Tests: `tests/test_invariant_binder.py` (two-run binder: verified/supported_unverified/refuted/no-restoration
+ the FP shapes), `tests/test_invariant_proposals.py`, `tests/test_source_ingest.py`, plus
workflow-executor regression tests for the restoration gate and full-body restore.
