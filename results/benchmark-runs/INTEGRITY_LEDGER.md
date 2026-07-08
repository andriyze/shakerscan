# Benchmark Integrity Ledger

This ledger records benchmark contamination, stale-fleet runs, methodology
corrections, target-specific hardcoding discoveries, and score reinterpretations.
Entries should point to the affected benchmark artifact and preserve the original
claim instead of deleting it.

## Entry Format

- Date:
- Artifact:
- Issue:
- Impact:
- Correction:
- Follow-up:

## Entries

### 2026-07-08 — Juice Shop retest loop did not improve recall

- Date: 2026-07-08
- Artifact: `results/benchmark-runs/benchmark-juice_shop.json`
- Issue: The scorecard shows `scan_finish.expected_recall=0.22` and
  `post_retest.expected_recall=0.22` for scan
  `91af7f60-9373-43c1-93ca-bff36f764f29`. The retest loop settled, but it did
  not close any expected benchmark misses.
- Impact: Do not cite the hypothesis/refuter/retest pipeline as evidence that
  detector recall is improving on Juice Shop. On this artifact it moved recall
  by zero. Treat the seven missed expectations (`sqli-search`, `xss-reflected`,
  `bfla-users`, `exposed-metrics`, `exposed-ftp-listing`,
  `exposed-confidential`, `nosqli-reviews`) as unresolved detector/proof gaps.
- Correction: Interpret this artifact as a failed anonymous benchmark scorecard
  with real detector debt: 2 expected findings found, 7 missed,
  `verified_high_critical=2`, and `false_positive_risk=0.6`. The anonymous run
  is not a valid two-user BOLA/authz proof, but its unauthenticated SQLi/XSS and
  exposure misses are still actionable.
- Follow-up: Prioritize universal detector/proof improvements and rerun a clean
  single Smart Juice Shop scorecard plus an authenticated/two-user run before
  claiming recall progress. Benchmark-followup hypotheses are worklist entries,
  not proof that recall has moved.
