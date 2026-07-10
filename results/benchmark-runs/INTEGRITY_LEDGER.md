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

### 2026-07-09 — Product-specific frontend route expansion was removed

- Date: 2026-07-09
- Artifact: Commits `3ee716b` and `17d2612`; tracked scorecards under
  `results/benchmark-runs/benchmark-{juice_shop,crapi}.json`.
- Issue: `3ee716b` mapped generic coupon/shop/mechanic route nouns onto crAPI's
  community/workshop service mounts. Describing those as generic route-shape
  rules did not make them universal; they fabricated target-specific candidates.
- Impact: Builds between `3ee716b` and `17d2612` could spend discovery and active
  budgets on benchmark-fitted routes. Inspection of the API results referenced by
  the currently tracked scorecards reported scanner version `a6956df`, which
  predates `3ee716b`, so those recorded scores were not produced by the fitted
  expansion and must not be retroactively marked contaminated.
- Correction: `17d2612` removed the product-specific mappings. Commits `39259f8`,
  `08af65c`, and `0faab3c` recover frontend request methods, body/query fields,
  and client-bound base URLs only from static call/config facts in the target's
  own frontend assets.
- Follow-up: Route composition must remain tied to observed traffic, schemas, or
  statically linked client configuration. Benchmark hostnames, product nouns,
  and answer-key routes are prohibited detector inputs; score movement still
  requires a fresh build-current benchmark run.

### 2026-07-09 — Residual product-specific discovery inputs removed

- Date: 2026-07-09
- Artifact: `scanner/scanner_tools/discovery.py` and
  `scanner/scanner_tools/active_prioritization.py` after the `17d2612` correction.
- Issue: The mount rewrite was gone, but direct community/identity/workshop API-doc
  probes, coupon/mechanic route filters, and benchmark-workflow score boosts remained.
- Impact: Those rules could still spend discovery or active budgets based on product
  vocabulary rather than target-observed request facts.
- Correction: Removed the direct service probes and product filters, restored generic
  versioned-route extraction, and retained method/body/source-based prioritization.
- Follow-up: Enforce the universal-engine rule in regression tests and treat observed
  HTTP calls, schemas, browser/HAR traffic, and discovered client bases as route facts.
  `tests/test_detector_integrity_gate.py` originally blocked known benchmark hostnames
  and service-mount answer strings in only `discovery.py` and
  `active_prioritization.py`; that narrow scope was an incomplete release guard.

### 2026-07-09 — Detector integrity release gate scope corrected

- Date: 2026-07-09
- Artifact: `tests/test_detector_integrity_gate.py`
- Issue: The initial release gate inspected two modules while executable detector,
  orchestration, and proof logic spans `scanner.py` and roughly 80 modules under
  `scanner/scanner_tools`. The ledger wording could be read as broader protection.
- Impact: A benchmark hostname, product noun, or answer-key service mount added to an
  uninspected scanner module would not have failed the release gate.
- Correction: The gate now AST-parses `scanner.py` and every Python file under
  `scanner/scanner_tools`, excludes only docstrings, and asserts a minimum module count
  so accidental scope shrinkage also fails.
- Follow-up: Keep benchmark fixtures/tooling outside detector inputs; any future
  exclusion must identify a non-executable or non-detector boundary explicitly.
