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

### 2026-07-10 — Post-retest scoring discarded browser proof

- Date: 2026-07-10
- Artifact: `results/benchmark-runs/benchmark-juice_shop-20260710T142656Z.json`
  and `results/benchmark-runs/benchmark-juice_shop-20260710T142926Z.json` for scan
  `6b869eae-66a8-4098-85ef-9a17cbde35c7`.
- Issue: The scan report contained an explicit successful headless-browser proof
  for a verified hash-route DOM XSS finding. Finding persistence omitted the
  top-level `browser_proof`, and post-retest scoring replaced the scan finding
  with the lossy database row. The first scorecard therefore reported 4/9 recall
  and failed the browser-XSS gate despite the recorded execution proof.
- Impact: The false miss affected benchmark interpretation only. It did not
  change finding severity, verified High/Critical count, scanner detector inputs,
  or production proof promotion.
- Correction: Structured browser/PoE proof contracts are now persisted inside
  redacted evidence, and post-retest scoring overlays live verdicts onto the
  original scan finding instead of discarding immutable scan-time proof. The
  corrected scorecard reports 5/9 recall and passes the browser-XSS gate while
  retaining the honest overall failure at 5 verified High/Critical against 6.
- Follow-up: Keep post-processing additive to original proof artifacts. A retest
  verdict may update verification state, but must not erase the evidence that
  established the original deterministic or browser proof.

### 2026-07-11 — Juice Shop scorecard flipped FAIL→PASS (recorded late)

- Date: 2026-07-11 (documenting a flip that landed 2026-07-10 with no ledger entry).
- Artifacts: `results/benchmark-runs/benchmark-juice_shop-20260710T150424Z.json`
  (scan `148dd7f2`) and `results/benchmark-runs/benchmark-juice_shop.json` /
  `…155033Z.json` (scan `330f5679`), both on fleet fingerprint `ddc6173b5b4864b4`.
- Change: `verified_high_critical` moved 5→6 and `expected_recall` 5/9→6/9 (0.67),
  flipping the `min_verified_high_critical: 6` gate to PASS. The driver is a single
  genuine, universal, anonymous detection — `exposed-metrics` (`/metrics` accessible
  debug/dev endpoint) — that started firing on the rebuilt `ddc6173b` fleet. Verified
  by the raw scan `results/host.docker.internal/20260710_152629_95668e9f.json`, which
  holds 6 genuinely-distinct verified High/Critical findings (2 SQLi, 1 browser-proven
  DOM XSS, acquisitions.md, encrypt.pyc, /metrics).
- Honesty caveats (why this is not a clean "current-fleet passes" claim):
  1. The pass is **anonymous** (`two_user: False`, `auth_workflow.status: "blocked"`);
     the auth-gated expectations `xss-reflected`, `bfla-users`, and `nosqli-reviews`
     remain **missed**. Recall improved via one more anonymous finding, not authed coverage.
  2. The passing run is on fleet `ddc6173b`, **not** the current fleet `bc6c357`; it has
     not been re-run on the current build.
  3. Scorecard evidence-label defect: `expected_found[exposed-ftp-listing].evidence`
     shows the `/metrics` title, not its real `encrypt.pyc` evidence — the matcher's
     `route_tokens()` drops sub-4-char routes (`/ftp`) and has no finding→expectation
     dedup. The underlying distinct `/ftp` finding exists, so the count is honest, but
     the label is wrong and the matcher is fragile.
  4. `broken_access_control` appears in `verified_high_critical_families` via a COMPAT
     alias (`sensitive_exposure → broken_access_control`) with **zero** backing
     access-control findings — a cosmetic overclaim (flips no active gate).
- Impact: benchmark interpretation only; no change to finding severity, detector inputs,
  or production proof promotion.
- Follow-up: (a) re-run on the current `bc6c357` fleet before any "current-fleet passes"
  claim; (b) fix the matcher evidence-label + add finding→expectation dedup; (c) drop the
  zero-backing `broken_access_control` alias; (d) the auth-gated misses require a working
  two-principal authed run (see the architecture review's increment 0).

### 2026-07-11 — First current-fleet authenticated crAPI scorecard (honest FAIL; discovery blocker confirmed)

- Date: 2026-07-11.
- Artifacts: `results/benchmark-runs/benchmark-crapi.json` and
  `benchmark-crapi-20260711T053205Z.json`, scan `85d3bafb-40a5-472e-8d64-eb954213f247`,
  fleet fingerprint `bc6c357126e7fe53` (the **current** fleet).
- What this establishes (positive): the first crAPI benchmark run where the harness minted JWTs with
  **two different stable identity claims** and the scanner scheduled both auth lanes —
  `two_user: True`, `two_principal_observed: True`, `auth_workflow.status: "ready"`. The auth-bootstrap
  fixes (`1fb3bac` host.docker.internal→127.0.0.1 mint bridge, `c146bdf` mint retry,
  `bd1a5d5` distinct-identity guard) work end-to-end on current HEAD. The BOLA
  differential lane ran (`bola_status.mode: cross_principal_read`,
  `cross_user_enabled: True`, `candidate_endpoints: 325`).
- Evidence limit: `two_principal_observed` is a compatibility name derived from the presence of
  `user1`/`user2` coverage lanes. The scorecard does not yet persist a redacted distinct-identity
  receipt or prove that the target accepted each authenticated context. Do not read it as
  server-observed identity proof.
- Result (honest FAIL): `passed: False`, `expected_recall: 0.0`, `verified_high_critical: 1`
  (an unrelated `.env` exposure). All 4 expected findings MISSED
  (`bola-vehicle-location`, `bola-mechanic-report`, `bola-orders`, `sqli-coupon`);
  `require_verified_bola` gate FAILED ("no verified BOLA").
- Confirmed blocker: an **authenticated API discovery gap**. None of the
  4 vulnerable crAPI routes (`/identity/api/v2/vehicle`, `/workshop/api/mechanic`,
  `/workshop/api/shop/orders`, `/community/api/v2/coupon`) appear anywhere in the report —
  discovery/crawl (235 endpoints) never enumerated crAPI's authenticated API surface, so the
  BOLA engine's 325-candidate set did not include the vulnerable endpoints. The engine can
  only prove BOLA on endpoints discovery feeds it. This run does **not** exonerate the detector: a
  seeded endpoint-control run is still required to show that BOLA/SQLi proof succeeds when the
  missing routes are supplied.
- Impact: benchmark interpretation + roadmap sequencing. Auth bootstrap is partially proven at
  submission, while accepted-auth observation, detector isolation, and authenticated API discovery
  remain separate acceptance boundaries. Candidate universal discovery work includes OpenAPI/spec
  ingestion, OPTIONS/JSON-link discovery, and JS/browser endpoint extraction.
- Follow-up: persist a redacted principal-validation receipt, fix the impossible completion ratio,
  run seeded detector controls outside detector inputs, then close discovery as a universal
  technique and rerun unseeded. Never add crAPI route names to detector inputs.

### 2026-07-11 — Seeded crAPI detector-isolation run: discovery is the primary gap (BOLA fires)

- Date: 2026-07-11.
- Artifacts: `results/benchmark-runs/benchmark-crapi.json` /
  `benchmark-crapi-20260711T181451Z.json`, scan `230900f2-d587-4153-92fb-77d18e26e8d4`,
  fleet `bdc8f1f724ec5043`.
- Method (detector isolation, endpoints supplied OUTSIDE detector inputs): an authenticated
  two-principal smart scan with the 4 crAPI routes supplied via the `custom_endpoints` scan
  option (not a detector route list). Auto-sharded (4 shards) with the new heavy-shard budget
  and BOLA producer/consumer affinity (`api/parallel_scan.py`, commit `6e796c4`): all 4 shards
  completed (vs 3/4 killed by the 6-min cap on the unseeded run `85d3bafb`).
- Result — the BOLA differential DOES fire once the route is supplied: a finding
  "BOLA: Cross-user data access at /workshop/api/shop/orders/{id}" with cross-principal evidence
  (`user1_status: 200, user2_status: 200`, numeric-id, response leaks another user's order+email).
  The unseeded run found this route nowhere in the report; the seeded run detects a genuine BOLA.
- But the scorecard is still 0/4 (`require_verified_bola` FAIL) because the finding is graded
  `severity: medium, verified: False, confidence: 0.5` — below the fixture's `verified`/`high` bar.
  Tier A (coupon NoSQL) was tested but did not fire; vehicle was not testable (fresh principal
  owns no vehicle).
- Verdict — the crAPI recall gap is TWO isolated, universal problems:
  1. **Discovery gap (dominant):** authenticated API routes are never enumerated (auth-gated, no
     links, auth-gated OpenAPI at `/identity/v3/api-docs` → 401), so the detector never runs on
     them. This is the primary blocker. Fix = universal authed API discovery (OpenAPI/spec
     ingestion, OPTIONS/JSON-link, JS/browser extraction).
  2. **Proof-tier gap (secondary):** a confirmed cross-principal differential (matching user1/user2
     200s on a numeric-id resource that leaks another principal's data) is under-graded to
     medium/unverified. Fix = promote to verified/high when the returned object's owner is provably
     a different principal than the requester.
- Note: the fixes are universal engine techniques, not crAPI facts. Seeding here is a scan option
  used for detector isolation, never a detector route list.
- Impact: benchmark interpretation + roadmap. Re-scopes increment 0: auth works; the real work is
  (1) authed API discovery, then (2) BOLA proof-tier promotion. Also validated the parallel scope
  heavy-shard budget + affinity fix end-to-end (authed BOLA now completes under auto-sharding).
