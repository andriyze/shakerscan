# Smart Scan Policy

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

Default profile values are centralized in `scanner/constants.py` as `SCAN_BUDGET_DEFAULTS`. Per-scan overrides are accepted through `custom_budget`.

## Phase Allocation
Initial allocation before reserve rebalancing:

| Phase | Time | Request | Payload |
|---|---:|---:|---:|
| Discovery (crawl, JS/HAR, endpoint graph) | 20% | 30% | 0% |
| Nuclei staged waves | 25% | 25% | 0% |
| Active checks (SQLi/XSS/BOLA/NoSQLi) | 30% | 30% | 100% |
| Verification/proof | 15% | 10% | 0% |
| Reserve | 10% | 5% | 0% |

## Dynamic Reallocation Rules
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
- Require explicit operator consent for aggressive active modes.

## Verification Policy
- `critical/high` findings require proof or independent corroboration.
- Verification methods may include:
- Browser proof (for XSS)
- Timing/statistical confirmation (for blind SQLi)
- Data extraction indicators (for injection findings)
- If proof fails or is skipped, lower severity and mark rationale in evidence.

## Quality SLOs
Severity-level precision targets:
- `critical`: `>= 0.95`
- `high`: `>= 0.90`

Coverage and confidence targets:
- `unverified_high_ratio`: `<= 0.10`
- `uncertain_ratio`: `<= 0.20`
- `smart_endpoint_coverage`: `>= 0.50` on authenticated test apps
- `benchmark_quality_score`: `>= 60` for reference corpora

## Release Gates
A release is blocked if any of these fail:
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
```

## Upgrade Policy
- In-place upgrades are the default production assumption.
- DB schema changes must ship with executable migration steps.
- Startup should fail fast with actionable guidance if schema is incompatible.

## Presales Positioning
How to answer common buyer questions:
- "How do you control scan cost?" -> "We use explicit time/request/payload/verification budgets with adaptive reallocation and hard safety caps."
- "How do you limit false positives?" -> "High-impact findings must be verified or they are downgraded, and we track precision SLOs per severity."
- "How do you prove quality over time?" -> "We run benchmark gates in CI and reject releases that regress coverage or verified-finding quality."
- "Can we run safely in production?" -> "Yes, smart mode is safe-by-default, with scoped targets, throttling, and opt-in controls for aggressive behavior."

## Implementation Notes
Recent policy-aligned hardening:
- Smart budget defaults are centralized in `scanner/constants.py` as `SMART_SCAN_BUDGETS` and consumed by scanner CLI/API.
- Scan depth/time defaults are centralized in `scanner/constants.py` as `SCAN_BUDGET_DEFAULTS` and resolved from `scan_type + budget_profile + custom_budget`.
- Scan reports include the resolved coverage budget under `scan_config.resolved_budget`.
- Session startup cleanup avoids lock re-entry deadlock.
- Synthetic BOLA generation excludes auth/session-style paths.
- Synthetic query URLs preserve valid URL encoding.
- Smart BOLA default budget is now consistent across scanner and docs.
