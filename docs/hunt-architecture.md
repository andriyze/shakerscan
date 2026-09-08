# Hunt architecture — AI-augmented penetration testing

**Status:** Implemented direction with explicitly pending release acceptance; reconciled 2026-09-07.

This is the canonical product direction for Hunt (operator direction, 2026-09-07), followed by the
current measured state and how the 2.3.0 workstreams map onto it. It supersedes the earlier A0
findings-only version of this file; those findings are preserved below under "Current state."

## Goal

Design Hunt as an AI-powered penetration-testing workspace that makes a skilled human pentester
materially more effective. The objective is **not** a fully autonomous scanner that replaces the
pentester. It is:

> **Human judgment + AI reasoning + deterministic execution and proof.**

- The human owns scope, objectives, risk decisions, and final judgment.
- The AI is a fast research partner: observe, hypothesize, investigate, correlate, propose the next
  best action.
- ShakerScan provides the controlled execution environment, target memory, tools, evidence, and
  verification.

## Core product model — three layers

```text
┌──────────────────────────────────────────────────────┐
│                 HUMAN PENTESTER                       │
│ objectives • intuition • authorization • judgment     │
│ attack ideas • prioritization • final conclusions     │
└───────────────────────┬───────────────────────────────┘
                        ▼
┌──────────────────────────────────────────────────────┐
│                  AI HUNT BRAIN                        │
│ observe → hypothesize → investigate → correlate       │
│ challenge assumptions → propose next actions          │
│ maintain target model → explain reasoning/results     │
└───────────────────────┬───────────────────────────────┘
                        ▼
┌──────────────────────────────────────────────────────┐
│             SHAKERSCAN EXECUTION PLANE                │
│ HTTP • Browser • Auth • Nuclei • SQLMap • JS          │
│ GraphQL • OOB • Diff • Replay • Evidence • Proof       │
│ scope • budgets • approvals • logging • safety         │
└──────────────────────────────────────────────────────┘
```

The division is strict, and it maps directly onto invariants ShakerScan already enforces:

- The human decides **what matters**.
- The AI decides **what may be worth trying next** (candidates/notes only — AGENTS.md invariant 7).
- ShakerScan decides **whether an action is allowed** and executes it safely (target binding,
  policy, budgets, approvals — invariants 4/5/6).
- Evidence/proof decides **whether a vulnerability is real** (deterministic proof contract, the
  hard boundary in section "Deterministic proof").

## Hunt is a research session, not a scan

Not `start → run predetermined tests → report`, but a persistent investigation loop whose state
survives any single AI context window:

```text
observe → build target model → generate hypotheses → rank → choose evidence needed
   → execute bounded action → analyze → update target model → prove / reject / defer → repeat
```

The AI must never rediscover the whole application from scratch each turn. A Hunt runs for minutes
or hours; its state is durable.

## Human and AI roles

**Human controls:** engagement scope, allowed targets, active-testing and state-changing
permission, credentials/personas, high-risk techniques, the Hunt objective, areas of interest,
business context, manual observations, and final severity/impact judgment. The human can inject a
hypothesis at any time.

**AI specializes in what humans are slow at:** reading thousands of endpoints; correlating traffic;
reading large JS bundles and API schemas; spotting unusual parameters; comparing principals;
recognizing repeated object relationships; generating and adapting attack hypotheses; tracking
failed experiments; noticing unexplored areas; chaining weak observations; summarizing evidence.
The AI must also argue **against** its own hypotheses (record contradictory evidence, deprioritize,
propose alternatives) so Hunt does not become an expensive payload generator.

## Persistent target knowledge graph

Model relationships, not a bag of URLs. Persisted entities: application (hosts, services,
technologies, API specs, JS bundles, GraphQL schemas, auth mechanisms); endpoints (method, route,
params, body schema, discovery source, auth requirement, observed responses); principals (id, role,
tenant, observed ownership, session state); objects (type, ids, owner principal, relationships,
referencing endpoints); observations (interesting responses, errors, reflections, authz
differences, leaked metadata, controls); hypotheses (statement, supporting/contradictory evidence,
confidence, required next evidence, status); findings (suspected/verified/rejected/needs-review).
The graph persists across Hunts. The AI gets compact structured memory plus retrieval, never
thousands of raw transactions.

## Hypothesis engine

Hunt thinks in hypotheses, not scanner families. The taxonomy classifies the result **afterward**.

```text
Observation: GET /api/orders/4121 returned owner_id=84; a second principal is available.
Hypothesis:  authorization may depend only on the order id.
Evidence:    response.diff(GET /api/orders/4121, principal=A, principal=B)
```

## Capability architecture

The AI receives small, strongly typed capabilities, never arbitrary shell or planner-supplied argv
(invariant 3). Each capability declares input schema, risk, permissions, target restrictions,
request/time budget, expected evidence, and output schema. Target families: HTTP (request/replay/
mutate/compare/sequence), browser (navigate/interact/observe_network/execute_candidate/
capture_state), auth (principal.select/compare, session.refresh, auth.observe), discovery
(surface.query, openapi/graphql/javascript.inspect, traffic.search), verification (sqlmap.verify,
xss.browser_verify, nuclei.run_selected, oob.allocate/check), evidence (record/query,
finding.propose/verify_request). Scan and Hunt call the **same** registry entries (invariant 5/10).

## Human–AI collaboration modes

Modes differ by **authority, not engine**:

- **Copilot** — AI only recommends; the human executes/approves. For sensitive engagements.
- **Assisted** — AI auto-runs low-risk actions; higher-risk actions request approval. The intended
  default. This is the existing approval-receipt + policy model applied per action.
- **Autonomous** — AI runs everything the engagement policy permits; the human observes and can
  interrupt. For labs, staging, long-running research.

## The AI learns from the pentester (session-scoped, never global)

The human teaches Hunt during an engagement ("403 vs 404 here is an authz side channel"; "ignore
missing-CSP findings, focus on exploitable flaws"). This becomes **target/session guidance**, never
a permanent global detector rule. This is a hard constraint: it must not contaminate the universal
engine with application-specific heuristics (see the universal-engine rule).

## Skills become expert playbooks

Skills teach the AI how an expert reasons about a problem (e.g. `skill.web.authorization`: map
object relationships and principals, distinguish collection/object endpoints, inspect ownership
identifiers, replay with alternate principals, test nested resources, check read/write asymmetry,
look for indirect references). The AI decides which ideas apply. Skills never contain
target-specific routes or benchmark answers.

## Deterministic proof — a hard invariant

> **AI reasoning is not proof.** (AGENTS.md invariant 7.)

AI reasoning creates a *candidate*. Verification requires deterministic evidence: a boolean/time
differential, a controlled-mutation database error, sqlmap proof for injection; a genuine
cross-principal comparison for BOLA (not merely HTTP 200). This is one of ShakerScan's strongest
advantages and must not be weakened. It is also why the A3/A4 BOLA work is a careful build — see
"Current state."

## Scan and Hunt relationship

Keep Scan; simplify its role to a fast deterministic baseline (crawl, API/schema and JS discovery,
technology detection, known-exposure checks, basic injection, baseline proof). Its output is
*initial target knowledge + obvious verified findings*, which Hunt consumes for adaptive
investigation. A pentester can also start Hunt without a full Scan first.

## Pentester-focused outputs

Not thousands of findings. Verified vulnerabilities (counted by severity), strong leads (unresolved
hypotheses worth manual review), interesting observations, and explicit coverage gaps (with the
reason, e.g. "payment workflow untested: no payment test account supplied"). Every verified issue
carries a minimal reproduction: principal/context, request, response, proof, impact, retest action.

## Benchmark the AI against humans

The primary success criterion is **Human + Hunt materially outperforms either alone**, measured on
controlled pentest benchmarks across four arms (Scan only / AI Hunt only / Human only / Human + AI)
on: verified and severe vulnerabilities, unique findings, false positives, time to first important
finding, requests sent, investigation time, attack chains, and the share of AI leads useful to the
pentester. This is a new evaluation axis beyond DAST recall, and it is what justifies added Hunt
complexity.

## What not to build

- A giant deterministic expert system (thousands of `if route contains "order"…` rules). Let the AI
  reason from observed facts.
- An unrestricted shell agent. Keep typed capabilities and server-side enforcement.
- A chatbot bolted onto a scanner. The AI needs real structured memory, evidence, tools, and the
  ability to drive investigation.
- A replacement for the pentester. The product is one strong pentester with the leverage of several
  researchers.

---

## Current state (measured 2026-09-06/07)

What exists today, honestly, and where it sits against the vision.

- **Deterministic proof boundary: already enforced.** Hunt creates only unverified candidates;
  verification runs through the deterministic proof moat (`validate_object_authorization`, the
  sqli/xss proof contracts). This is the vision's strongest invariant and it is real now.
- **Scan-as-baseline: real.** Scan produces the target knowledge (endpoints, principals, objects)
  and the obvious verified findings. On Juice Shop it reaches 4/9 answer-key classes (verified SQLi
  + the sensitive-exposure cluster).
- **A0 baseline measured.** Hunt currently adds **zero** verified classes over Scan on Juice Shop,
  for two structural reasons the vision's Phase 2/3 address:
  1. *Auth/session primitives had diverged* — the Hunt's cross-principal proof needed an interactive
     session the JSON+JWT login could not produce. **Fixed:** the `json_login` session auth kind
     (commit `a0e0511a`) converges the credential primitive so a JSON+JWT target drives
     `authz.verify` through the same registry entry Scan uses. Live-verified: both principals
     establish sessions and the proof runs with them recognized as distinct.
  2. *Endpoint knowledge is a raw, phantom-dominated URL list* (~3,000 rows, ~two-thirds
     content-discovery phantoms). This is exactly the unstructured-target problem the knowledge
     graph (Phase 2) exists to fix. Not yet built.
- **First verified Hunt finding: not yet.** Getting Hunt to verify a class Scan misses (the A3
  gate) needs a targeted-id BOLA proof. It is designed and **fail-closed** (the proof validator is
  unchanged, so a wrong evidence-gather can only fail to verify), with one critical caveat: the
  target route and the attacker's own baseline route must be the same resource collection, or a
  public object would falsely verify. Because a new proof path is the most false-positive-sensitive
  change in the system, it is scoped for a focused build with positive-and-negative validation, not
  shipped opportunistically.

## Phase 2a — endpoint frontier de-noising: two failed approaches, measured (2026-09-07)

**Status: not solved.** A ranking attempt failed, data limitations were identified, and the
decoy-based replacement was then evaluated and also found insufficient. Both results are measured,
and both experiments are reproducible from the repo. Nothing here is a validated replacement.

### Reproducing these results

```bash
# labeled sample: tests/fixtures/hunt/endpoint_reality_sample.json
docker compose exec -T api sh -lc \
  'cd /workspace && PYTHONPATH=/workspace:/workspace/api:/workspace/scanner \
   python3 scripts/evaluate_endpoint_reality.py --base-url http://host.docker.internal:3001'
```

Labels are ground truth from the application's known route structure, never from the probe being
evaluated. The sample deliberately includes protected routes, a method-specific route, client-side
fragment routes, and entries whose correct answer is `unknown`, so an evaluator is scored on
abstention as well as separation.

### Experiment 1 — evidence-based ranking (failed, reverted)

Ranked the frontier by evidence of interaction and reachability. Measured against the live
inventory it promoted the wordlist phantom `/api/Cards/search/` to the top, so it was reverted.
What this supports, stated no more strongly than the evidence allows:

| Signal | Defensible conclusion |
|---|---|
| `source` provenance | Too coarse **as currently written**: values are `scan`/`coverage_recon`/`asm`/`recon`, not the column comment's `crawl\|ffuf\|openapi`, so it does not separate. Not proof the concept is useless. |
| `attempt_count`, `last_verdict` | Interaction does not prove existence: probed phantoms acquire both because the app answers them. |
| HTTP status | Not usable as a fixed rule: on this target the wordlist paths return 401/400 and real routes 200. Any hardcoded status rule would be app-fitting. |
| `content_hash` | Unavailable (never populated) — untested, not disproven. |

One failed ranking does not eliminate every combination of these signals. It does show that no
ranking over these columns alone worked here.

Separately measured: the current `priority_score` ordering genuinely misranks, putting a
never-probed guess (65) above the heavily-tested real `/api/Users` (20).

### Experiment 2 — the existing decoy / soft-404 comparison (insufficient)

Evaluated the shipping comparison (`_learn_not_found_signatures`, `_probe_path_status`,
`_soft404_matches`) against the labeled sample. It is **not an existence oracle**:

> **These numbers are WITHDRAWN.** They came from scoring the low-level `_soft404_matches`
> matcher, not the shipping `filter_reachable_worklist`, which already keeps fragment routes and
> already drops only GET entries so a method-specific route survives. Re-scored against the real
> entry point, production made **no errors on the sample**: absent routes dropped 2/2, real or
> client routes dropped 0, and no useful representative lost. There was nothing here for a
> replacement to improve. Reproduce with `scripts/evaluate_endpoint_reality.py`.

The five realistic wordlist phantoms return `401 / 83 bytes` — and so do the real protected routes
`/api/Addresss` and `/api/Cards`. When auth middleware answers a real protected route and a
nonexistent one identically, the comparison cannot distinguish them, and the correct outcome is
**unknown**, not phantom. HTTP also permits 404 for an existing forbidden resource. The real-route
demotion comes from probing GET against a POST-only route, so method-specific endpoints are at risk
from a path-only probe.

### Defects found while measuring — both now addressed

Both were in `api/asm_inventory.py`:

1. **The filter disabled itself silently on large batches.** Above `max_probe` (default 2,000)
   unique paths it returns every entry unfiltered. **Mitigated** (`17f97acb`): the skip is now
   logged with its counts, so the question is answerable from production. The limit is unchanged,
   and whether real ingestion batches exceed it remains **unverified**.
2. **The matcher treated an unmeasurable size as a match**, dropping an endpoint on an undecidable
   comparison and contradicting the module's own stated bias. **Fixed** (`02fa0c27`): an
   inconclusive size now keeps the endpoint, with tests that fail without the fix.

Also corrected: an earlier claim that ASM "only filters at write time" was wrong. A sweep already
persists `last_http_status`, `unreachable_streak` and `last_reachability_at`, and retires rows to
`gone`. What is missing is the richer *comparison* evidence, not persisted reachability.

### Phase 2a state: implemented / live-validated / pending

**Implemented and live-validated.** An opt-in grouped frontier, `kind="endpoint_groups"` on the
existing `/hunts/{id}/query` (`kind="endpoints"` unchanged). Groups carry `route_template`,
`grouping_evidence`, `sample_count`, `representatives`, `principal_contexts`, `prior_results`,
`open_questions` and every member `sample_id`, so a grouping is reversible and drill-down through
`filter.id` loses no lead. Ordering puts groups with prior results first and never lets repeated
parameter samples occupy the first page. Verified end to end against the running API.

**Implemented, deliberately conservative.** Status-only sibling-to-route inference was removed as
unsupported (`20b62611`). Grouping now merges only on identifier-shaped segments or a declared
specification, and identifier-shaped grouping is labelled tentative. Removing unsupported merges
can *increase* group counts, so **no measured live de-noising or recall improvement is claimed.**

**Pending.** Persisting comparison evidence with its context (method, principal/auth context,
control reference, outcome, timestamp) rather than a boolean; evaluating any new signal on the
labeled sample in both directions before adoption; authenticated evaluation (the evaluator probes
anonymously only).

**Not the goal.** A smaller endpoint list is supporting evidence of usability, never proof that
Hunt finds more. Phase 2a is finished when a pentester gets an actionable target view without
losing leads — not when every URL carries a label.

## Workstream-to-phase mapping

The 2.3.0 architecture workstreams (`release-2.3.0-plan.md`) are this vision's phases:

| Vision phase | Plan workstream | State |
|---|---|---|
| Phase 1 — pentester-friendly Hunt (timeline, observations/hypotheses/actions, approve/skip/modify) | (new, UX) | not started |
| Phase 2 — target knowledge graph | A2 structured target memory | de-noising design settled by measurement (below); relationship layer not started |
| Phase 3 — unified capability API (Scan and Hunt share primitives) | A1 shared capability layer | **first primitive converged** (`json_login`); more to audit |
| Phase 4 — adaptive reasoning loop | A3 reasoning loop | blocked on the targeted-id proof + Phase 2 |
| Phase 5 — deep workflow reasoning (authz, multi-user, business logic, GraphQL, SPA, chains) | A4 advanced discovery in Hunt | designed for BOLA (targeted-id proof); pending |
| Phase 6 — human + AI benchmarks | (new, eval) | not started; replaces recall-only as the success axis |

## Recommended direction (one line)

> An AI-augmented penetration-testing environment where humans provide judgment and creativity, AI
> provides scale and adaptive reasoning, and ShakerScan provides safe execution and trustworthy
> proof.

DAST remains underneath as baseline discovery and deterministic verification. Hunt becomes the
product. The competitive advantage is not more payloads than Burp or Nuclei; it is a pentester and
an AI researcher sharing one target model, evidence, tools, and history — and together finding more
real vulnerabilities, faster.
