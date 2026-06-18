# Proposed Next Steps — DAST Engine Quality Plan

**Status:** proposal, 2026-06-18. Grounded against live scans of the crAPI + Juice Shop honey
targets on the rebuilt engine, plus code audit. The headline problem is no longer "which detector
to build" — it is **why scans find only the tip of the iceberg**. This plan leads with that.

## TL;DR — why we find so little
On both targets the engine found a *fraction* of the known bugs (Juice Shop: 2 SQLi, 0 XSS, 0 IDOR;
crAPI: 13 read-BOLA, 0 write-BOLA / mass-assignment / JWT). The audit shows the cause is **not weak
detectors** — it is **discovery + scope + auth**:

| Symptom (measured) | Evidence | Consequence |
|---|---|---|
| API surface never discovered | `discovery_sources = [manual_endpoints, url_crawl]` on every scan; only **35 (Juice) / 8 (crAPI)** endpoints found | On an SPA/API app, crawling the HTML shell finds ~nothing → the routes with the bugs are never tested |
| Browser crawl disabled for focused/coverage scans | `scanner.py:3884` `enable_browser_crawl = … and not focused_manual_active_scope`; coverage shards run `check_family`+harvested endpoints → "focused" → no crawl | Focusing to find SQLi also turns off the discovery needed to find where SQLi is |
| Coverage recon skips param enumeration | `parallel_scan.py:147` `param_discovery_url_limit: 0` | Harvested endpoints carry no params → injection probes have nothing to inject into |
| Anonymous-only | `auth_states_tested: ['anonymous']` (Juice Shop) | Every authenticated SQLi/XSS/IDOR is invisible — and that's most of them |
| Wrong endpoints/methods selected | active set was `PUT/POST/PATCH`, **no GET**; `GET /rest/products/search?q=` (famous SQLi) not in the tested set | The single most famous Juice Shop SQLi is never sent a payload |

**The detectors mostly work** (login auth-bypass SQLi ✅, cross-principal read-BOLA ✅, and a full
JWT + mass-assignment suite already exists in code). They just never receive the right
endpoints/params/auth. **Fix discovery + scope + auth first; it unlocks the existing detectors.**

## Where the real findings live (the target map)
Use these as benchmark fixtures (expected families/routes, not hardcoded answers).
- **Juice Shop** — SQLi: `/rest/user/login` ✅, `/rest/products/search?q=` (UNION), `/rest/track-order/:id`.
  XSS: DOM `#/search?q=`, reflected product search, stored (review / last-login-IP).
  IDOR: `/rest/basket/:id`, `/api/Feedbacks`, `PUT /api/Users/:id`.
- **crAPI** — BOLA read ✅ (vehicle location, mechanic reports, orders) + **write**; mass-assignment
  (profile/video, internal coupon); JWT alg/signature bypass; SSRF (mechanic `?url=`).

---

## P0 — Discovery & scope (the unlock; do these first)
- **D1 — Decouple discovery from active focus.** A focused or coverage scan must still run full
  browser + JS-bundle discovery to *find* what to test. Gate `enable_browser_crawl`
  (`scanner.py:3884`) and the SPA seed-route step (`3889`) on **"explicit endpoints supplied"**
  (custom_endpoints / `zero_rediscovery`), **not** on `focused_manual_active_scope`. A
  `check_family=sqli` run with no custom endpoints should browser-crawl like a broad scan.
- **D2 — Coverage recon must enumerate params.** Stop forcing `param_discovery_url_limit: 0` in the
  coverage recon (`parallel_scan.py:147`); enumerate query/body params (bounded) so the harvested
  worklist carries injectable params. Verify body shapes (now array-aware via `3cb0ff0`) survive into shards.
- **D3 — Capture & feed SPA/API calls into the worklist.** Ensure browser-captured XHR/fetch
  endpoints (`browser_api_endpoints`, scanner.py:4327) with method+params reach both the active
  selection **and** the coverage harvest (`harvest_endpoints`) — for API-only apps (crAPI) too.
- **D4 — Authenticated discovery + multi-auth by default.** When creds exist, crawl and test as
  user1/user2 (and admin); the post-login API surface is where most Highs live. Auto-login
  (form/JSON), keep the session warm, and record `auth_states_tested` honestly.
- **D5 — Per-family deep passes, unioned.** A full-mix *dilutes* (measured: crAPI full-mix found
  **0 High** vs **13** focused). A single family misses the others. Orchestrate focused-deep
  sqli + xss + bola/idor passes over the **same discovered surface**, then union — instead of one
  diluted mix or one narrow family.

## P1 — Detector depth (after discovery feeds them)
- **W1 — Safe write-BOLA / BOPLA.** The one genuine *capability* gap: `smart_authz` proves
  cross-principal **reads** only (read-safe by design). Add a **non-destructive** cross-principal
  **write** proof (idempotent re-PUT of the foreign object's own values, gated on `exploit_depth`)
  → turns crAPI's read-Highs into more-severe write-Highs.
- **W2 — Make existing detectors fire, don't rebuild them.** Mass-assignment
  (`mass_assignment_test_json_body`) and the full JWT suite (`jwt_vulnerability_test`,
  `jwt_comprehensive_test`, `jwt_algorithm_confusion_test`, `jwt_kid_injection_test`,
  `jwt_claim_manipulation_test`, scanner.py:1221/1642-1645) already exist; they under-fire because
  of scan focus + dispatch. Verify each runs with auth context on crAPI and emits a finding.
- **W3 — Stored/DOM XSS proof depth on SPAs.** Juice Shop's XSS is DOM/stored; ensure
  `deep_domxss` + the stored-XSS workflow run on browser-discovered sinks, not just reflected GET params.

## P2 — Architecture (enables the above to scale; mostly already-scaffolded)
- **N5 — Registry-driven dispatch** (keystone): `build_report()` still uses the per-module boolean
  ladder (`scanner.py:5148,5156` + ~7 `if run_sqli/run_xss`). Migrate to iterate
  `ACTIVE_CHECK_FAMILIES` / `check_registry.CheckFamilySpec` so families are independently
  schedulable — this is what makes D5 (per-family passes) and W2 (firing all detectors) clean.
- **N1/N2 — Workflow/state modeling + persisted resource graph.** Multi-step
  register→login→create→access→mutate sequences (only single-hop producer→consumer exists today),
  persisted so detectors and Continuous ASM reuse object IDs/ownership instead of re-discovering.
- **N4 — Discovery imports** (OpenAPI/Postman/GraphQL-introspection into the inventory) — high
  leverage for crAPI-class API coverage; complements D1–D3.
- **N6 — Proof contracts per family** + benchmark `proof_gap` enforcement.

## Already shipped — do NOT rebuild
| Capability | Where |
|---|---|
| Benchmark miss-analysis harness | `fefe781` `benchmark_summary.py`, `tests/benchmark/analyze_dast_benchmark.py` |
| Cross-principal **read**-BOLA replay | `c88f54f` `authz_resource_replay_test` |
| Mass-assignment + telemetry | `017a186`/`4277c17` `mass_assignment_test_json_body` |
| Forced browsing + vertical priv-esc | `access_control_checks.py:722,3269` |
| Full JWT attack suite | `scanner.py:1221,1642-1645` |
| Per-family active-time budget split | `active_checks.py::_split_active_family_budget` |
| Login auth-bypass SQLi | `ddd3de9` |
| Object-id route prioritization · array-body reconstruction · real-id propagation | this session: `1a6d9d2`, `3cb0ff0`, `641edcc` (help id-in-URL apps; crAPI ids live in response bodies, so D1–D4 + W1 matter more there) |

## Benchmark loop (the spine)
Wire crAPI + Juice Shop as fixtures (`benchmarks/<target>/{profile,auth,expected_families}.yml`),
run `analyze_dast_benchmark.py` each pass, and gate progress on **confirmed High/Critical up**,
`expected_family_misses` **down**, `proof_gaps` **down**. Every item above is a hypothesis the
miss-analysis must justify before it's built.

## Sequencing
| Priority | Step | Why |
|---|---|---|
| **P0** | D1 decouple discovery from focus · D2 recon param enumeration | Single biggest lift — feeds every detector the real surface |
| **P0** | D4 authenticated + multi-auth discovery/test | Unlocks the majority of Highs (authn-gated) |
| **P0** | D3 SPA/API capture → worklist · D5 per-family union passes | Right endpoints, no dilution |
| **P1** | W1 safe write-BOLA · W2 fire JWT/mass-assign · W3 DOM/stored XSS | Detector depth on the now-discovered surface |
| **P1** | N5 registry-driven dispatch | Makes D5/W2 clean and per-family schedulable |
| **P2** | N1/N2 workflow+graph · N4 spec imports · N6 proof contracts | Business-logic depth + scale |

## Operational cautions (learned live, 2026-06-18)
- **Authenticated `exploit_depth` scans mutate the test account** (our crAPI creds were burned
  mid-loop). Register fresh users per authenticated run; W1/W2 writes MUST be non-destructive.
  Self-mint crAPI tokens via signup/login — see `[[crapi-juiceshop-validation-setup]]`.
- **Single-file mount staleness:** after editing `scanner.py`, `docker compose up -d
  --force-recreate worker` and verify each worker (`grep`/`ast.parse`) before trusting results —
  `restart` left a truncated copy. See `[[docker-single-file-mount-staleness]]`.
- **Verify against current HEAD before acting** — it advances between turns. `[[reaudit-head-before-acting]]`.
