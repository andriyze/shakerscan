# Proposed Next Steps — DAST & ASM Quality (deep-audit priority reset)

**Status:** proposal, rewritten 2026-06-22 from what the last 7 days and the
past-70-commit audit actually proved.

This replaces the prior 11-section plan. That plan was **fully implemented** (benchmark
runner, raised budgets, XSS/SQLi packs, BOLA blocked-reasons, ASM family coverage +
recommended campaigns + schedules, verification summaries, docs) — and then a further
verification-depth plan (provers, prioritized retest, AI-never-promotes, calibration)
was also implemented. Despite all of it, the only metric that measures success did **not
move**.

The deeper audit changes the diagnosis: this is not just a benchmark discipline problem
or a stale-worker problem. Those are symptoms. The product has been changing without a
small set of enforced contracts for scan success, finding identity, proof state, report
canonicalization, budget ownership, and worker-fleet truth. That is how we ended up with
real work that does not compound.

## The blunt result

248 commits since 2026-06-15, across 107 files and roughly 43k lines of churn. Across
that span the Juice Shop benchmark is **flat**:

| Metric | Start of week | End of week | Gate |
|---|---|---|---|
| Crit/high classes found | 5/9 | 5/9 | — |
| **Verified H/C** | 3 | 3 | need ≥6 ❌ |
| **Unverified-high ratio** | 0.73 | 0.73 | need ≤0.35 ❌ |
| Verified SQLi present | ✅ | ✅ | PASS |
| Browser-proven XSS | ✅ | ✅ | PASS |
| Persistent misses | sqli-login, xss-reflected, bfla-users, nosqli-reviews | same | — |

Two of four gates have failed all week. crAPI's headline is worse: one templated BOLA
route is reported as ~46 separate HIGH findings (one per object ID), and one Juice Shop
SQLi param as 7 separate criticals — so the counts a user sees are inflated noise.

The latest live scan rows add an even more basic warning: scans can still reach
`finalizing` after validation/attack-chain work and then fail with no result persisted;
some completed smart scans report a headline grade even when active checks made zero
endpoint attempts; and parent reports still disagree internally (`findings[]`,
`quality_metrics`, `verification_summary`, triage, and headline counts are not always
computed from the same source of truth).

The audit of the last 70 commits shows repeated repair loops: finalization was blamed on
heartbeats, then verification time, then NUL-byte persistence; parallel coverage was
added, then had to regain detector classes it lost; parent summaries were recomputed, then
other report blocks still drifted; budget paths were raised in one place while another
path silently re-clamped them.

**The core lesson is sharper now: we kept patching symptoms because the scanner did not
have product invariants strong enough to reject inconsistent states.**

## Lessons learned (the actual deliverable of this week)

1. **Measure the outcome, not the activity.** Volume of commits, tests passing, and
   "feature implemented" are not evidence of DAST quality. The benchmark is. It barely
   gets run between changes, and its results aren't even tracked in git, so "are we
   better?" was unanswerable for most of the week. **Make the scorecard the unit of
   progress**: no DAST/ASM change is "done" until a benchmark run shows the targeted
   metric moved (and the scorecard is recorded).

2. **Shipping ≠ reachable ≠ visible.** The verification-depth provers (BFLA, NoSQLi)
   were *inert* for days — real findings never inferred to `bola`/`nosqli`, so the
   provers never ran. The new `/asm/gaps` proof metrics were returned by the API but
   *invisible in the UI*. A detector/prover/field is not delivered until it is proven
   end-to-end: **does a real finding route into it, and does the user see the result?**
   Every new prover/detector/field needs a reachability + visibility test, not just a
   unit test of the function in isolation.

3. **Diagnose before fixing.** The "finalize hang" cost ~6 commits on heartbeat
   resilience, finalize-timeout tuning, verification caps, and budget cuts — all
   symptom-chasing. The actual cause was a **NUL-byte crash** on the Postgres finding
   INSERT (from our own `%2500` file-bypass harvest), on *two* persist paths. One
   `docker logs <worker> | grep -i exception` at the start would have saved all of it.
   Rule: read the actual error from the actual failing component before theorizing.

4. **A scan is not successful until the result and side effects are durable.** Reaching
   `phase=finalizing pct=97` is not good enough if the row ends as `failed` and
   `/result` returns "not found". Finalization/persistence is part of the product
   contract, not cleanup. If validation produced findings, the system should preserve a
   recoverable partial or final report before slow report assembly, retest scheduling, or
   other tail work can be killed by a duration guard. A scan row should also not claim a
   clean `completed` state while finding persistence, ASM attempt accounting, or retest
   bookkeeping failed silently.

5. **Parallelism is a substrate, never a win by itself.** Parallel coverage was
   *strictly worse* than a single scan (2/9 vs 5/9, 0 vs 3 verified) until we made the
   recon pass the global/DOM/verification backbone and unioned its findings into the
   merge. Shard count is not progress. A coverage run is only as good as: recon backbone
   (global+browser+verify, once) + shards (per-endpoint breadth) + merge (union + verify
   + recompute grade/triage). Keep proving parallel ≥ single before trusting it.

6. **Verification has preconditions; "prover ran" ≠ "verified".** BFLA/BOLA need a second
   user; the cross-user prover *correctly* returns `out_of_scope_internal`/inconclusive
   without user2. So "we added a prover" does not raise the verified count unless the run
   actually supplies the precondition. The benchmark runs user1-only, which is *why*
   bfla-users stays unproven. Don't conflate plumbing-works with metric-moved.

7. **Result presentation is dishonest in five ways that actively mislead** and must be
   fixed before any more detector work:
   - **Finding-count explosion**: fingerprints embed concrete object IDs / payload
     variants, so one templated BOLA = ~46 HIGHs and one SQLi param = 7 criticals. This
     *also* inflates the suspected denominator that fails the unverified-ratio gate.
   - **Unverified-as-HIGH**: findings with `confidence 0.55, needs_verification:true`
     render at full HIGH/CRITICAL; the "this is a lead, not proof" signal is buried
     inside the `evidence` JSON.
   - **Coverage numbers don't reconcile**: `tested/total` ≠ the displayed coverage
     (denominator silently excludes `gone`), three different "untested" numbers appear
     side by side, and `total` is inflated by thousands of phantom auth-path rows.
   - **Report blocks don't reconcile**: `findings[]`, `result.summary`,
     `quality_metrics.total_findings`, `quality_metrics.severity_distribution`,
     `verification_summary.total`, and triage counts can disagree after parent/shard
     merge. The UI cannot be trusted if each section is recomputed from a different
     intermediate object.
   - **Active-zero scans can still look successful**: a smart scan with active checks
     requested but zero active endpoint attempts can still show a normal headline grade.
     That must be a degraded/partial result at the top level, not a buried coverage note.

8. **There is no single owner for budgets.** Worker watchdogs, API stale cleanup,
   coverage shard sizing, dynamic ASM batches, and scanner-internal active budgets each
   resolve or mutate time/endpoint caps. That explains why one commit can "fix" a budget
   while another path still silently re-clamps it. Budget should be a resolved immutable
   contract stamped once, then consumed everywhere.

9. **Finding identity is too concrete for a scanner report.** Parent merge and DB
   persistence still key heavily on concrete URL/object ID/payload variants. A scanner
   report should identify the vulnerability route/parameter/family, then store concrete
   object IDs and payload techniques as evidence instances. Otherwise one bug becomes
   dozens of findings and every quality metric is distorted.

10. **Proof semantics are split.** Retest code says AI never promotes to verified, but
    scan-time precision policy can still treat high-confidence AI `true_positive` as
    `verified`. We need one proof taxonomy: deterministic proof, AI-supported likely
    vulnerable, false-positive downgrade, inconclusive. The same fields must drive DB,
    report, UI, grade, and benchmark gates.

11. **The universal-engine rule held and must keep holding.** Every prover added this week
   is a generic technique (operator-injection differential, cross-user replay,
   content-marker re-fetch). No filenames/routes/model-names were hardcoded to pass a
   target. Do not regress this to chase the benchmark.

12. **Operational discipline is non-negotiable.** Most "it didn't work" moments traced to
   stale workers. Always: full rebuild → restart → confirm `build_current N/N` →
   re-mint auth → run. Bake this into the benchmark runner so a stale fleet aborts the
   run instead of silently producing bad numbers. Also reconcile `/workers`,
   `scanner.sh status`, and Docker reality: current build fingerprint is not enough if
   unmanaged old worker containers are still counted as capacity.

## Revised next steps — ordered by impact on the failing gates

### 1. Freeze detector expansion until product invariants exist (P0)
**Why:** the last 70 commits added real capability, but the system still accepts
impossible states: completed scans without trustworthy results, parent reports whose
sections disagree, active scans with no active attempts, and fleet counts that do not
match the managed runtime. More detectors will only produce more confusing evidence.
**Do:** define a report/scan invariant harness and run it after unit tests, after parent
merge, and after every benchmark. The invariants should cover terminal result durability,
canonical finding totals, proof-state consistency, active-execution honesty, budget
provenance, and worker-fleet consistency.
**Done when:** a scan/report cannot pass CI or benchmark gates if `findings[]`,
`quality_metrics`, `verification_summary`, triage, grade, scan status, active attempt
counts, or fleet metadata contradict each other.

### 2. Make finalization/result persistence and completion atomic enough (P0)
**Why:** benchmarks and UI reports are meaningless if a scan can do useful work, reach
validation, then disappear as "result not found" because finalization exceeded a budget.
It is also misleading if a row is marked `completed` before findings persistence or ASM
attempt accounting fails.
**Do:** persist a durable partial/final result before slow final report assembly,
auto-retest scheduling, PDF/report enrichment, or other tail work. Treat finalization and
post-processing as bounded phases with explicit degraded states. If saving findings,
attempt telemetry, or required side effects fail, surface that as `completed_with_errors`
or `degraded`, not a clean success.
**Done when:** scans that reach validation always have `/result`; a timeout after
validation produces `completed(partial)` or `failed_with_partial_result` with visible
findings and an explicit finalization error; a scan cannot report clean completion when
required persistence failed.

### 3. Rebuild reports from one canonical finding set (P0)
**Why:** recent parent scans still show impossible combinations such as 23 findings in
`findings[]` but 7 in `quality_metrics.total_findings`. Users cannot reason about grade,
proof, or remediation if sections disagree.
**Do:** replace "richest child report + selective recompute" with a canonical report
builder. Parent/shard merge should produce one merged finding list, then derive
`result.summary`, score/grade, `quality_metrics`, `verification_summary`, triage,
severity distribution, confidence distribution, attack chains, UI counters, and DB
`findings_count` from that list only.
**Done when:** for every completed parent scan, `findings.length`,
`verification_summary.total`, quality total/severity sum, headline summary count, and
triage buckets reconcile or explain their intentionally different denominators.

### 4. Create one resolved budget contract and delete hidden budget paths (P0)
**Why:** budget bugs recurred because the worker watchdog, stale checker, static coverage
planner, dynamic ASM batch path, and scanner active logic each made local decisions.
That is how dynamic coverage re-clamped SQLi to 8s/endpoint after the planner had already
raised the budget.
**Do:** resolve the budget once at scan submission/planning, stamp it into the scan, and
require every runtime path to consume that exact object. The stale checker, watchdog,
child shard options, dynamic pull workers, and scanner internals should all expose which
budget field they consumed.
**Done when:** there is one source of truth for max duration, active seconds, active
endpoint count, per-family caps, and shard/batch caps; benchmark output records the
resolved budget and no path can silently override it.

### 5. Reconcile worker/fleet truth before benchmarking (P0)
**Why:** stale-worker checks improved, but capacity can still be misleading when
`/workers`, `scanner.sh status`, and Docker disagree about how many worker containers are
actually part of the managed fleet. Bad capacity assumptions distort shard timing,
contention, and benchmark conclusions.
**Do:** make worker discovery authoritative and consistent across the API, CLI status,
and Docker labels/project scope. Either manage old scaled workers explicitly, exclude
them from capacity, or stop them. Benchmark runs should record worker count, build
fingerprint, scanner version, and container age.
**Done when:** status surfaces the same worker set as `/workers`; stale/unmanaged workers
cannot silently contribute to scans or capacity math.

### 6. Make active-execution honesty a hard gate (P0)
**Why:** a smart scan with active checks requested but zero selected/tested active
endpoints should not receive a confident headline grade. That is an execution failure or
severe coverage gap, not a clean security result.
**Do:** if `active=true` and active endpoint attempts are zero, mark the scan
`partial/degraded`, set `grade_reliable=false`, surface the reason at the top of the
report, and fail the benchmark gate for active coverage. Distinguish "no injectable
surface found after real discovery" from "active lane never received endpoints".
**Done when:** active-zero scans cannot look healthy in the scans list, detail page,
report summary, benchmark output, or API response.

### 7. Collapse finding-count explosion at the identity layer (P0)
**Why:** directly cleans the misleading counts AND deflates the suspected denominator
behind the failing `unverified-high ratio` gate.
**Do:** template the path (`/orders/{id}`), normalize object IDs, and drop the
payload/technique variant from the *finding identity* (not just the inventory). One
templated BOLA route = one finding with N evidence instances; one SQLi param = one
finding with attempted techniques listed as evidence. Strict tests must prove distinct
real vulnerabilities do not merge.
**Done when:** crAPI BOLA collapses from ~46 to ~1–3 findings; Juice SQLi from 7 to 1;
unverified-ratio drops measurably on the next benchmark.

### 8. Unify proof semantics and stop overloading `verified` (P0)
**Why:** report fields, DB state, retest verdicts, grading, UI, and benchmark gates do
not all use the same proof contract. "AI never promotes" must be enforceable everywhere,
not true in one merge path and false in scan-time policy.
**Do:** define one proof-state model: deterministic `exploited`, `likely_vulnerable`
from AI/strong heuristics, `false_positive`, `likely_fixed`, `inconclusive`, and
`blocked`. Make the report carry that state explicitly, and derive legacy booleans from
it only at compatibility boundaries.
**Done when:** a finding cannot become benchmark-verified or grade-capping solely from
AI classification; list/detail/API/DB agree on whether it is proven or suspected.

### 9. Make the benchmark able to PROVE auth-gated classes + measure the right window
**Why:** bfla-users/bola can't be verified without user2; workstream-B's lift is the
*async retest after* the scan, but the scorecard reads at scan-finish.
**Do:** run the benchmark with user1 **and** user2 creds; add a post-retest re-score pass
(wait for the auto-retest wave, then re-read verdicts) so the verified count reflects
deterministic proof, not just scan-time triage. Record both scorecards in git.
**Done when:** bfla-users/bola move to verified on a two-user run; the verified gate can
actually pass.

### 10. Make severity presentation reflect proof state
**Why:** unverified leads shown as HIGH/CRITICAL are the trust problem, and they distort
the grade.
**Do:** an unproven High/Critical (confidence below the high threshold,
`needs_verification`) is presented as "suspected High" with a visible badge in the
findings *list* (not only the detail page), and does not count as a proven High/Critical
in the headline grade. Single `is_verified` boolean on the finding so list and detail
agree.
**Done when:** the findings list distinguishes proven from suspected at a glance; grade
reflects proven counts.

### 11. Coverage-number honesty + phantom-inventory cleanup
**Why:** ASM coverage looks artificially low/confusing because `total` is dominated by
`gone`/phantom auth-path rows and the denominator isn't labeled.
**Do:** headline coverage uses a single, labeled denominator (`testable = total − gone`);
collapse the three "untested" numbers to one with the others behind a detail toggle;
aggressively GC/never-create the speculative auth-path fan-out that inflates `total`.
**Done when:** `tested / denominator = displayed coverage` reproduces, and Juice Shop's
`total` reflects real reachable endpoints.

### 12. Recall gaps (real detection, not verification)
`sqli-login` (POST-body SQLi on `/rest/user/login`), `xss-reflected`
(`/rest/track-order`), `nosqli-reviews` (`/rest/products/reviews`) are *missed*, not
merely unverified. These need the endpoints actually discovered + the right body/param
probes — verification routing can't help find what isn't tested. Do this only after the
P0 contracts above are enforced, otherwise new findings will land in the same broken
reporting and proof pipeline.

### 13. Standing guardrails (process, not features)
- No detector/prover feature work lands while P0 invariants are red.
- Benchmark results committed to `results/benchmark-runs/` (or a tracked log) so success
  is visible in git history.
- Every new prover/detector/field ships with a reachability/visibility test.
- The benchmark runner aborts on a stale, unmanaged, or internally inconsistent fleet.
- Report-invariant checks run after every benchmark and fail on mismatched finding,
  quality, verification, triage, or grade totals.
- Active checks requested with zero active attempts fails the benchmark unless the report
  explicitly proves there was no reachable active surface.
- A commit that claims "root cause" must cite the observed error/log/trace and the test
  that would have failed before the fix.
- Budget changes must identify which resolved budget field changed and which runtime
  paths consume it.

## Non-goals (unchanged, and reinforced by this week)
- Do not hardcode target facts (filenames/routes/models) to pass a benchmark.
- Do not treat more shards, more commits, or "feature implemented" as success.
- Do not promote a finding to verified without deterministic proof (AI never promotes).
- Do not raise scan budgets so high that finalize/persistence falls over (we already
  learned this the expensive way).
- Do not call an active scan reliable when the active lane made zero attempts.
- Do not trust benchmark capacity until the worker API, CLI status, and Docker agree.
- Do not ship new detector breadth while scan/report invariants are failing.
