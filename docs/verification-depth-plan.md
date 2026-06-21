# Verification Depth Plan — lift the verified-vs-suspected ratio

**Status:** proposal, 2026-06-20. A *new* effort, separate from `proposed-next-steps.md`
(which is fully implemented). That plan put the verification *mechanisms* in place
(suspected vs verified labeling, `verification_summary`, confidence tiers, the
`/asm/gaps` proof distribution). This plan is about the *outcome*: the engine still
proves under half of what it reports.

## Problem statement

Across single and parallel benchmark runs the **verified-vs-suspected ratio is ~0.65–0.8
unverified** — i.e. only ~20–35% of reported High/Critical findings are proven
(`last_verification_verdict='exploited'` or browser/timing proof). Measured signals:

- Benchmark scorecards: `max_unverified_high_ratio` gate fails (0.62–0.9 vs 0.35 target);
  `min_verified_high_critical` often 1–5 vs the 6 target.
- `/asm/gaps` `confidence_distribution` shows large `suspected` buckets with `high_critical>0`.

This matters because the product direction is **verified exploit discovery first**. A wall
of suspected High/Critical is low-trust output.

## Why findings stay suspected (root causes to confirm/fix)

1. **Scan-time verification is bounded** (`SCAN_VERIFICATION_MAX=40` + per-finding budget).
   Eligible findings beyond the budget are deferred to async retest — but the async retest
   must actually run and flip status, or they stay suspected forever.
2. **Prover coverage gaps.** `verify_high_severity_findings` only proves the finding types
   with a mapped prover ladder (XSS browser, SQLi timing/validator, a few others). Types with
   no prover (exposure, BFLA/auth, BOLA, path traversal, webhook/approval, NoSQLi) fall through
   unproven even when a cheap deterministic check exists.
3. **Prover reliability.** Browser proofs can fail on auth/navigation/timing flakiness; SQLi
   timing proofs need statistical confidence to avoid both false negatives and false positives.
4. **Routing.** Inconclusive findings are not always routed deterministic-first; AI judging
   should be the last step, not a substitute for a deterministic retest.
5. **Confidence calibration.** Confidence scores don't always track proof strength, so the
   `verified` tier isn't a clean "proven" signal.

## Goal

Raise proven High/Critical so the benchmark gates pass on the lab targets **without
benchmark-fitting** — i.e. by adding generic deterministic provers and reliable retest
follow-through, not by hardcoding Juice Shop/crAPI specifics.

Target: `max_unverified_high_ratio <= 0.35` and `min_verified_high_critical` met on Juice Shop
and crAPI, with no increase in false positives (`false_positive_risk` stable).

## Workstreams

### A. Deterministic provers for currently-unproven families
**Files:** `scanner/scanner_tools/proof_of_exploit.py`, `scanner/scanner_tools/verification_engine.py`,
`scanner/scanner_tools/verification_phase.py`, `scanner/scanner_tools/access_control_checks.py`,
`tests/test_sqli_poe_precision.py`, `tests/test_dast_precision.py`.

1. Add/extend cheap deterministic provers, each generic (technique, not app fact):
   - **exposure / sensitive files**: re-fetch the URL and confirm the sensitive marker (secret
     pattern, listing markers, metrics format) is still present → verified.
   - **BFLA / auth bypass**: re-issue the privileged request without/with downgraded auth and
     confirm the privileged response shape → verified read/write distinction.
   - **BOLA**: replay the producer-harvested object ID as user2 and diff against user1 → verified
     (already partially present; make it a first-class prover with read/write separation).
   - **path traversal**: confirm the traversal returns the canonical file signature.
   - **NoSQLi**: confirm the operator-injection differential (true vs false payload) deterministically.
2. Map each new prover into the `verification_engine` ladder + `normalize_finding_type` so
   `verify_high_severity_findings` actually invokes it.
3. Keep false-positive guards strict (differential/二-sample confirmation, not single-response).

**Acceptance:** each family has a deterministic prover; a finding of that family is either
`verified` or stays clearly `suspected` with a recorded reason — never silently unproven.

### B. Reliable async retest follow-through
**Files:** `api/worker.py` (`queue_auto_retests_for_scan`, retest job handler),
`api/retest_contract.py`, `tests/test_worker_evidence_triage.py`.

1. Confirm deferred (budget-exhausted) and inconclusive findings are queued for retest and that
   the retest flips `last_verification_status/verdict` and confidence on success.
2. Bound and observe: a finding should not sit `needs_verification` indefinitely — add a retest
   age/attempt ceiling and surface "stuck unverified" in `/asm/gaps`.
3. Make the scan-time verification budget (`SCAN_VERIFICATION_MAX`) spend on the highest-value
   families first (already sorted) and ensure the remainder reliably get an async pass.

**Acceptance:** the proven ratio improves *after* the async retest wave, visible in
`verification_summary` and `/asm/gaps` over time, not just at scan finish.

### C. Deterministic-first routing + AI last
**Files:** `scanner/findings.py`, `api/evidence_triage.py`, `scanner/scanner_tools/proof_of_exploit.py`.

1. Route inconclusive High/Critical to deterministic retest before any AI judgment.
2. Use AI only to triage what deterministic proof cannot settle; never to *promote* to verified.
3. Ensure weak indicators don't drag the score as if proven (already a §10 goal — add tests).

**Acceptance:** AI verdicts never create a `verified` finding; deterministic proof is the only
path to `verified`.

### D. Confidence calibration + measurement
**Files:** `scanner/findings.py` (`get_confidence_tier`), `scripts/benchmark_targets.py`,
`tests/fixtures/benchmarks/*.yaml`.

1. Align confidence with proof strength: proven → `verified` tier; deterministic-strong →
   `high`; single-signal → `medium`/`low`.
2. Make the **unverified-high ratio a first-class benchmark metric** with a gate (already
   present) and trend it across runs in `results/benchmark-runs/`.
3. Add a regression test asserting that a proven finding lands in the `verified` tier and an
   unproven High lands in `suspected` (not silently dropped, not promoted).

**Acceptance:** `verified` tier == proven; benchmark trends the ratio; regressions are visible.

## Execution order

1. B (retest follow-through) — cheapest lift; many findings are *provable* but never get a
   second deterministic pass.
2. A (deterministic provers per family) — the structural lift.
3. C (routing) + D (calibration + measurement) — make the gains trustworthy and durable.

## Non-goals

- No hardcoding Juice Shop/crAPI/honey filenames, routes, or model names to pass a gate
  (universal-engine rule). Provers must be techniques that work on a random real target.
- Do not promote to `verified` without deterministic proof.
- Do not raise scan-time verification so high it reintroduces the finalize-time blowups
  (bounded scan-time proof + reliable async retest is the model).
