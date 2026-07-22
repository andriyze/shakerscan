# Smart Scan Policy

**Status:** reconciled 2026-07-17. Resolved profile budgets, hard override ceilings, phase watchdogs,
request-meter telemetry, adaptive throttling, and proof-aware reporting are shipped. Yield-based
cross-phase budget reallocation below is a target policy, not current runtime behavior. Release SLOs
are acceptance goals and must not be represented as passing without a current scorecard. The named
release-gate runner and benchmark commands exist, but the GitHub Release workflow does not yet
enforce this full policy; that automation gap is tracked in `release-readiness.md`.

## Purpose
Define how ShakerScan budgets time and attack effort in `smart` mode, while keeping scans safe, explainable, and commercially defensible.

## Scope
- Applies to automated `smart` scans and quality gates for scanner releases.
- Covers budgeting, safety controls, verification, and benchmark acceptance criteria.

## Budget Model
Scan type controls which modules run. Coverage budget controls how much depth, time, and active probing those modules receive.

Supported coverage profiles:
- `fast`: small coverage budget for smoke/CI feedback.
- `balanced`: default depth and runtime limits.
- `thorough`: release/staging scans where useful findings matter more than speed.
- `exhaustive`: long-running authorized testing with maximum coverage.

Resolved smart-scan budget fields include:
- `max_duration_minutes`
- `discovery_depth`
- `max_urls`
- `browser_max_pages`
- `browser_max_depth`
- `api_probe_limit`
- `param_discovery_url_limit`
- `param_discovery_max_params`
- `phase4_max_seconds`
- `nuclei_max_targets`
- `nuclei_early_stop`
- `active_max_seconds`
- `active_max_endpoints`
- `active_params_per_endpoint`
- `max_findings_per_family`
- `smart_bola_max_endpoints`
- `dom_xss_max_files`
- `sqli_extract_max`
- `oob_max_findings`
- `active_worklist_max`
- `request_max`

Smart-specific adaptive values are centralized in `scanner/constants.py` as `SMART_SCAN_BUDGETS`.
General scan-type and coverage-profile defaults use `SCAN_BUDGET_DEFAULTS`. Per-scan overrides are
accepted through `custom_budget` and capped by the configured ceilings.

## Target Phase Allocation

The following allocation is a design target for future cross-phase accounting. Current execution
uses resolved per-module limits and watchdogs; it does not reserve these percentages in one shared
runtime allocator.

| Phase | Time | Request | Payload |
|---|---:|---:|---:|
| Discovery (crawl, JS/HAR, endpoint graph) | 20% | 30% | 0% |
| Nuclei staged waves | 25% | 25% | 0% |
| Active checks (SQLi/XSS/BOLA/NoSQLi) | 30% | 30% | 100% |
| Verification/proof | 15% | 10% | 0% |
| Reserve | 10% | 5% | 0% |

## Proposed Dynamic Reallocation Rules

These rules are not implemented in the current scanner. They require exact-enough per-adapter request
accounting, a shared phase allocator, and benchmark evidence before activation.
- Reallocate reserve only to phases with positive yield.
- Yield metric: `confirmed_high_or_critical / 100 requests`.
- Continue a high-cost phase only if yield is above threshold for the last window.
- Stop or downshift a phase after two consecutive low-yield windows.
- Never borrow from safety caps.

Recommended thresholds:
- High-yield threshold: `>= 0.15` confirmed `high+` per 100 requests.
- Low-yield threshold: `< 0.05` confirmed `high+` per 100 requests.

## Safety and Legal Guardrails
- Default to in-scope origin only for active requests.
- Exclude auth/session endpoints from synthetic BOLA URL generation.
- Cap active probes per endpoint and per parameter family.
- Apply adaptive backoff on `429`/`503`.
- Downgrade unverified `critical/high` findings after verification budget exhaustion.
- Require explicit operator consent for active modes. Agent workflows enforce this conversationally;
  server-authoritative approval receipts for every local scan are deferred beyond 0.7.0 under the
  trusted-operator scope in `release-readiness.md`.

## Verification Policy
- `critical/high` findings require proof or independent corroboration.
- Verification methods may include:
- Browser proof (for XSS)
- Timing/statistical confirmation (for blind SQLi)
- Data extraction indicators (for injection findings)
- If proof fails or is skipped, lower severity and mark rationale in evidence.

## Quality SLOs
These are release targets, not claims about the latest build. A release artifact satisfies them only
when its fingerprint-current benchmark scorecard records the required measurements.
Severity-level precision targets:
- `critical`: `>= 0.95`
- `high`: `>= 0.90`

Coverage and confidence targets:
- `unverified_high_ratio`: `<= 0.10`
- `uncertain_ratio`: `<= 0.20`
- `expected_recall`: benchmark-specific known-vulnerability recall, normally `>= 0.50` for broad vulnerable corpora and `1.00` for small Honey fixtures
- `smart_endpoint_coverage`: `>= 0.50` on authenticated test apps
- `benchmark_quality_score`: `>= 60` for reference corpora

## Release Acceptance Policy

The release owner must block a release if any of these fail. These are policy requirements; they are
not all automatically enforced by the current GitHub Release workflow:
- Schema/API compatibility checks for upgraded environments.
- Benchmark assertion suite (`tests/benchmark/*`) fails.
- Precision or confidence SLO regressions exceed tolerance.
- New smart-scan features ship without at least one deterministic test.

CI gate command examples:
```bash
# Absolute SLO gates
python3 tests/benchmark/run_benchmarks.py --benchmarks tests/benchmark/benchmarks.json

# Absolute + regression gates against baseline artifacts
python3 tests/benchmark/run_benchmarks.py \
  --benchmarks tests/benchmark/benchmarks.json \
  --results-dir /tmp/current-results \
  --baseline-results-dir /tmp/baseline-results \
  --baseline-result juice-shop=host.docker.internal/latest.json \
  --baseline-result crapi=cr.shakerscan.com/latest.json \
  --strict

# Queue a live Honey calibration scan, export it, then assert known true/false positives
python3 scripts/dast_calibration.py \
  --benchmarks tests/benchmark/honey_benchmarks.json \
  --benchmark honey-smart-fast \
  --allow-active \
  --wait \
  --export-results
python3 tests/benchmark/run_benchmarks.py --benchmarks tests/benchmark/honey_benchmarks.json

# Queue a local vulnerable-corpus run (example: Juice Shop on host port 3001)
docker run -d --rm --name shakerscan-juice-shop -p 3001:3000 bkimminich/juice-shop
python3 scripts/dast_calibration.py \
  --benchmarks tests/benchmark/benchmarks.json \
  --benchmark juice-shop \
  --allow-active \
  --wait \
  --export-results
python3 tests/benchmark/run_benchmarks.py --benchmarks tests/benchmark/benchmarks.json
```

## Upgrade Policy
- In-place upgrades are the default production assumption.
- DB schema changes must ship with executable migration steps.
- Startup should fail fast with actionable guidance if schema is incompatible.

## Presales Positioning
How to answer common buyer questions:
- "How do you control scan cost?" -> "We resolve explicit time, endpoint, parameter, and request budgets. Request enforcement is adapter-dependent and reported in receipts."
- "How do you limit false positives?" -> "High-impact promotion requires deterministic proof contracts; unproven findings remain suspected or require review."
- "How do you prove quality over time?" -> "We retain fingerprinted benchmark scorecards and keep release acceptance open when the current build has not passed them."
- "Can we run safely in production?" -> "Active smart scans require explicit authorization. Use bounded profiles and review adapter enforcement before targeting production."

## Implementation Notes
Recent policy-aligned hardening:
- Smart budget defaults are centralized in `scanner/constants.py` as `SMART_SCAN_BUDGETS` and consumed by scanner CLI/API.
- Scan depth/time defaults are centralized in `scanner/constants.py` as `SCAN_BUDGET_DEFAULTS` and resolved from `scan_type + budget_profile + custom_budget`.
- Scan reports include the resolved coverage budget under `scan_config.resolved_budget`.
- Session startup cleanup avoids lock re-entry deadlock.
- Synthetic BOLA generation excludes auth/session-style paths.
- Synthetic query URLs preserve valid URL encoding.
- Smart BOLA default budget is now consistent across scanner and docs.
