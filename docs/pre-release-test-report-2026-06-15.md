# ShakerScan Pre-Release Test Report — 2026-06-15

**Scope:** Full pre-release pass focused on parallel scans, plus UI, API, tests, retest, and AI Gate.
**Targets:** Juice Shop (`http://host.docker.internal:3001`, DAST) and Honey (`https://honey.shakerscan.com`, DAST + AI Gate).
**Build under test:** `main` @ `669c203` (+ uncommitted shard-leak read-filter fix in `api/api.py`).

## Verdict: GO with caveats

Core functionality — including the new parallel-scan stack — works end-to-end. No release blockers found. Several non-blocking issues are listed under **Issues**; the most user-visible is the pre-existing **unreachable-target → "completed"** mislabel.

---

## Results by area

### 1. Build & unit tests — PASS
- **pytest:** `661 passed, 4 errors`. The 4 errors are pre-existing and unrelated (`scanner/tests/test_injection_extra.py` — a `targets` fixture that doesn't exist; reproduces on clean `HEAD`).
- **UI typecheck:** `tsc --noEmit` clean (0 errors). **UI build:** `npm run build` success, all routes compiled incl. `/scan/new`, `/scans`, `/scans/[id]`. (node 26.3.0, Next 16.2.4.)

### 2. API smoke — PASS
All core GETs returned 200: `/health`, `/workers`, `/settings/scan-execution`, `/dashboard`, `/scans` (+`include_shards`), `/findings`, `/targets`, `/targets/grouped`, `/domains`, `/queue/stats`, `/ai/targets`, `/ai/test-scenarios`, `/schedules`.
Validation: bad `scan_type` → 400 (good). **Minor:** `GET /scans/{invalid-uuid}` → **500** (should be 400/404).

### 3. Parallel scans — PASS
- **Scope strategy (clean run):** parent completed 3/3 shards, merged **2 deduped** findings (CSP missing, Referrer-Policy missing), conservative aggregate score. Partial-shard resilience confirmed (1 shard returned 0 during a target blip; parent still merged the rest).
- **Family strategy:** shard plan correct — `broad` (no focus), `sqli` (`sqli=true,xss=false,thorough,no_early_stop`), `xss` (`xss=true,sqli=false,...`). Full clean run: _(family-on-honey result appended below)_. (An earlier same-build run produced broad=4/sqli=2/xss=4 → merged 4 deduped.)
- **Auto-sharding policy:** setting **ON** → smart scan → `parent` (3 shards); setting **OFF** → smart → `standalone`; `quick` → `standalone` (ineligible); explicit `parallel:false` → `standalone` (override). Gate respects the setting both directions. UI uses **PUT** (correct); setting restored to OFF after testing.
- **Cancellation:** cancelling a parent → parent + all 3 shards → `cancelled` (`cancelled_child_shards: 3`), merge guard set to `cancelled` (merge blocked), and **late shard writes did not revive** the cancelled rows.
- **Shard hiding:** default `/scans` shows 0 shard rows (10 parent + 190 standalone); `include_shards=true` shows 33. 
- **Shard stat-leak fix (this session):** all 7 fixed read queries (dashboard, target recent_scans, exposure/graph, ai/inventory, grouped-targets latest, failed-scans feed, attack-chains agg) verified clean against 39 live shard rows — zero leaks.

### 4. Retest — PASS
- Two honey findings (`/.env`, `/admin.php`), both still serving HTTP 200 (ground truth) → retest verdict **`exploited` / `still_vulnerable`** (conf 0.9 and 0.75). Correct.
- Findings correctly **stayed `active`** (no inappropriate auto-status-change; auto-FP only fires on FP verdicts).
- **Separation:** retests created `finding_verifications` rows only — **zero** scan rows; they stay off the Scans page by design.

### 5. AI Gate / Honey — PASS
- Smoke scan (`shaker-ai-smoke`) on honey chat target completed: **5 findings** (PII/credential disclosure, sensitive-info disclosure, simulated roleplay, unbounded-output/cost abuse), grade **F** (correct — honey is a deliberately-vulnerable honeypot). Transcript present (3 entries).

### 6. UI render — PASS
- `/settings` serves the **Scan Execution** card + **Auto-shard** toggle. `/scan/new` serves **Auto / Normal / Parallel** + shard tuning controls. `/`, `/scans`, `/scan/new`, `/settings` all HTTP 200.
- The earlier "nothing in settings" report was a **stale browser cache** — the panel is in the deployed bundle.

---

## Issues found

| # | Severity | Area | Issue |
|---|---|---|---|
| 1 | **Major (UX)** | scanner/worker | **FIXED 2026-06-15.** Unreachable target was marked `completed` with a placeholder `78 C*` grade instead of `failed`. Two paths fixed: (a) `scanner.py` pre-scan-fail branch now sets `report["error"]`; (b) `worker.py` `run_scan` JSONDecodeError fallback now always returns a non-empty error (silent/crashed scanner no longer mislabeled completed). Regression tests in `tests/test_pre_scan_unreachable.py`. Verified live: juice-shop-down `:3001` → `failed` ("Port 3001 is not reachable…"), `192.0.2.1` → `failed`, both with no grade. |
| 2 | Minor | API | `GET /scans/{invalid-uuid}` → 500 instead of 400/404 (unhandled `uuid.UUID()` ValueError). |
| 3 | Observation | parallel/targets | **Family strategy multiplies target load** (N× full discovery). Two concurrent parallel smart scans (6 shards) crashed Juice Shop (`Exited 133`). Not a ShakerScan defect, but worth documenting; reinforces the deferred "discover-once" Phase 2 work. |
| 4 | Pre-existing | tests | 4 `test_injection_extra.py` collection errors (missing `targets` fixture). |

## Test footprint
- Parallel parents exercised: scope (clean), family (honey), auto-policy decisions; cancellations: 2 parents + standalones, all clean.
- Setting left at safe default: `auto_sharding_enabled = false`.
