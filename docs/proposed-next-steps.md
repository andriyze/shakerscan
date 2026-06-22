# Proposed Next Steps — DAST & ASM Quality (rewritten from 7 days of evidence)

**Status:** proposal, rewritten 2026-06-22 from what the last 7 days actually proved.

This replaces the prior 11-section plan. That plan was **fully implemented** (benchmark
runner, raised budgets, XSS/SQLi packs, BOLA blocked-reasons, ASM family coverage +
recommended campaigns + schedules, verification summaries, docs) — and then a further
verification-depth plan (provers, prioritized retest, AI-never-promotes, calibration)
was also implemented. Despite all of it, the only metric that measures success did **not
move**. This document records why, so we stop repeating the pattern, and redirects effort
at the few things that will actually move the needle.

## The blunt result

~70 commits in 7 days. Across that entire span the Juice Shop benchmark is **flat**:

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

**The work was real and mostly necessary — but it was plumbing, and we kept declaring
victory on plumbing.** That is the core lesson.

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

4. **Parallelism is a substrate, never a win by itself.** Parallel coverage was
   *strictly worse* than a single scan (2/9 vs 5/9, 0 vs 3 verified) until we made the
   recon pass the global/DOM/verification backbone and unioned its findings into the
   merge. Shard count is not progress. A coverage run is only as good as: recon backbone
   (global+browser+verify, once) + shards (per-endpoint breadth) + merge (union + verify
   + recompute grade/triage). Keep proving parallel ≥ single before trusting it.

5. **Verification has preconditions; "prover ran" ≠ "verified".** BFLA/BOLA need a second
   user; the cross-user prover *correctly* returns `out_of_scope_internal`/inconclusive
   without user2. So "we added a prover" does not raise the verified count unless the run
   actually supplies the precondition. The benchmark runs user1-only, which is *why*
   bfla-users stays unproven. Don't conflate plumbing-works with metric-moved.

6. **Result presentation is dishonest in three ways that actively mislead** and must be
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

7. **The universal-engine rule held and must keep holding.** Every prover added this week
   is a generic technique (operator-injection differential, cross-user replay,
   content-marker re-fetch). No filenames/routes/model-names were hardcoded to pass a
   target. Do not regress this to chase the benchmark.

8. **Operational discipline is non-negotiable.** Most "it didn't work" moments traced to
   stale workers. Always: full rebuild → restart → confirm `build_current N/N` →
   re-mint auth → run. Bake this into the benchmark runner so a stale fleet aborts the
   run instead of silently producing bad numbers.

## Revised next steps — ordered by impact on the failing gates

### 1. Collapse finding-count explosion (highest leverage)
**Why:** directly cleans the misleading counts AND deflates the suspected denominator
behind the failing `unverified-high ratio` gate.
**Do:** template the path (`/orders/{id}`) and drop the payload/technique variant from
the *finding identity* (not just the inventory). One templated BOLA route = one finding
with N evidence instances; one SQLi param = one finding with the techniques listed as
evidence. Strict tests so distinct real vulns don't merge.
**Done when:** crAPI BOLA collapses from ~46 to ~1–3 findings; Juice SQLi from 7 to 1;
unverified-ratio drops measurably on the next benchmark.

### 2. Make the benchmark able to PROVE auth-gated classes + measure the right window
**Why:** bfla-users/bola can't be verified without user2; workstream-B's lift is the
*async retest after* the scan, but the scorecard reads at scan-finish.
**Do:** run the benchmark with user1 **and** user2 creds; add a post-retest re-score pass
(wait for the auto-retest wave, then re-read verdicts) so the verified count reflects
deterministic proof, not just scan-time triage. Record both scorecards in git.
**Done when:** bfla-users/bola move to verified on a two-user run; the verified gate can
actually pass.

### 3. Make severity reflect proof state
**Why:** unverified leads shown as HIGH/CRITICAL are the trust problem, and they distort
the grade.
**Do:** an unproven High/Critical (confidence below the high threshold,
`needs_verification`) is presented as "suspected High" with a visible badge in the
findings *list* (not only the detail page), and does not count as a proven High/Critical
in the headline grade. Single `is_verified` boolean on the finding so list and detail
agree.
**Done when:** the findings list distinguishes proven from suspected at a glance; grade
reflects proven counts.

### 4. Coverage-number honesty + phantom-inventory cleanup
**Why:** ASM coverage looks artificially low/confusing because `total` is dominated by
`gone`/phantom auth-path rows and the denominator isn't labeled.
**Do:** headline coverage uses a single, labeled denominator (`testable = total − gone`);
collapse the three "untested" numbers to one with the others behind a detail toggle;
aggressively GC/never-create the speculative auth-path fan-out that inflates `total`.
**Done when:** `tested / denominator = displayed coverage` reproduces, and Juice Shop's
`total` reflects real reachable endpoints.

### 5. Recall gaps (real detection, not verification)
`sqli-login` (POST-body SQLi on `/rest/user/login`), `xss-reflected`
(`/rest/track-order`), `nosqli-reviews` (`/rest/products/reviews`) are *missed*, not
merely unverified. These need the endpoints actually discovered + the right body/param
probes — verification routing can't help find what isn't tested.

### 6. Standing guardrails (process, not features)
- Benchmark results committed to `results/benchmark-runs/` (or a tracked log) so success
  is visible in git history.
- Every new prover/detector/field ships with a reachability/visibility test.
- The benchmark runner aborts on a stale fleet.

## Non-goals (unchanged, and reinforced by this week)
- Do not hardcode target facts (filenames/routes/models) to pass a benchmark.
- Do not treat more shards, more commits, or "feature implemented" as success.
- Do not promote a finding to verified without deterministic proof (AI never promotes).
- Do not raise scan budgets so high that finalize/persistence falls over (we already
  learned this the expensive way).
