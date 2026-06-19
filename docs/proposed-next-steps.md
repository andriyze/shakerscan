# Proposed Next Steps — DAST Engine Quality Plan

**Status:** proposal, 2026-06-18 (rev. for hunter-campaign north star). Grounded against live scans of
the crAPI + Juice Shop honey targets on the rebuilt engine, plus code audit. The headline problem is
no longer "which detector to build" — it is **why scans find only the tip of the iceberg**. This plan
leads with that, then ladders to the hunter-campaign architecture (see "North star" below).

## TL;DR — why we find so little
On both targets the engine found a *fraction* of the known bugs (Juice Shop: 2 SQLi, 0 XSS, 0 IDOR;
crAPI: 13 read-BOLA, 0 write-BOLA / mass-assignment / JWT). The audit shows the cause is **not weak
detectors** — it is **discovery + scope + auth**:

| Symptom (measured) | Evidence | Consequence |
|---|---|---|
| **Synthetic phantom-endpoint explosion drowns the active scan** | live log: SQLi phase grinding through `{api,rest}×{v1,v2,v3}×{auth,oauth,oauth2}×{login,logout,refresh,authorize}` permutations (`/api/v2/oauth2/authorize`, …) each with `[email,username,password,token]`; `endpoints=172 params=914`, **hung 10+ min**, `findings=1`. Generator: `discovery.py:377/2704` blind permutation wordlist. **No reachability gate** — phantom 404s are fuzzed anyway | Active budget is spent on endpoints that don't exist; the real routes (`/rest/products/search?q=`) never get a payload, and the scan **hangs** before XSS/IDOR ever run |
| API surface never discovered (coverage/focused scans) | `discovery_sources = [manual_endpoints, url_crawl]`; only **35 (Juice) / 8 (crAPI)** endpoints found | On an SPA/API app, crawling the HTML shell finds ~nothing → the routes with the bugs are never tested |
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

## P0 — Stop the active scan from drowning (do this FIRST — it's why scans hang & miss)
- **D0a — Reachability-gate the active worklist.** Before fuzzing, probe each candidate's baseline
  once (concurrent, cached); **drop hard-404 / not-found endpoints** so SQLi/XSS payloads are never
  spent on phantom routes. Reuse the ASM soft-404 logic (`asm_inventory._probe_path_status`,
  `filter_reachable_worklist`) on the scanner's active worklist. This alone reclaims most of the
  wasted budget and stops the hangs.
- **D0b — Cap & demote blind synthetic permutations.** The API-permutation wordlist
  (`discovery.py:377/2704`) generates a combinatorial blowup of unverified auth/oauth/version paths.
  Hard-cap synthetic/inferred endpoints, and rank **observed** (har/browser/crawl/openapi) endpoints
  strictly above synthesized ones in active selection (extends `active_prioritization.py`).
- **D0c — Enforce a real active time budget.** With `no_early_stop` + `thorough`, the SQLi phase
  ground for 10+ min with no cap. The per-family deadline (`_split_active_family_budget`) must be a
  hard ceiling even under `no_early_stop`, and the loop must honor cooperative cancel.

## P0 — Discovery & scope (the second unlock)
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

## North star: the hunter campaign (and how this plan ladders to it)
A "hunter_campaign" spec (senior-DAST design) describes the destination: recon → **application
graph** → auth/role matrix → prioritize-by-impact → **hypotheses** → minimal safe probes → **prove
impact** → feed back into ASM. That is the right target. **But you cannot run a hunter campaign on
an engine that hangs and can't see the API surface** — which is exactly what the live evidence shows.
Per the spec's own rule ("start with P0/P1 unless a strong benchmark harness *and* application graph
already exist"), we have neither working, so the foundation comes first.

**Status preflight (hunter spec assumptions vs. code):**

| Claim | Verdict | Evidence |
|---|---|---|
| dynamic Full Coverage allocation default | ✅ confirmed | `283b1be` default coverage; `parallel_scan.py` |
| zero-rediscovery child execution | ✅ confirmed | coverage shards run `check_family`+harvested manual endpoints (`focused_scope.active`) |
| endpoint `replay_spec` preservation | ✅ confirmed | `db/init.sql:399`, `asm_inventory.py:389` |
| auth-state sharding / user1 / user2 | ✅ confirmed | `parallel_scan.py:159,519,543` (`auth_state_shards`, `user2_header`) |
| check-registry runnable families | ✅ confirmed | recon/sqli/xss/bola/auth runnable; headers/ssrf/lfi/rce/business_logic/nuclei gated off |
| focused Auth/BOLA gate behavior | ✅ confirmed | `_enforce_asm_family_preconditions` / `check_registry` fail-closed |
| scanner telemetry → `asm_endpoint_attempts` | ✅ confirmed | `endpoint_attempts` → ledger |
| benchmark/live tests for Juice Shop/crAPI | 🟡 partial | harness exists (`fefe781`); **no fixtures wired** |
| application/resource graph support | 🔴 missing | none; only in-memory single-hop producer→consumer inside `smart_authz` |
| scans complete reliably on SPA/API targets | 🔴 problem | hung in active (synthetic explosion) **and** slow nuclei waves; D0a landed, discovery now finds **1337** Juice Shop endpoints (was 35) with browser+auth |

**The 14-stage hunter pipeline mapped to our reality (build only the 🔴/🟡):**
- S0 scope/policy ✅ (`check_registry`) · S1 recon ✅ (browser/HAR/crawl/JS — D1–D4 make it fire) ·
  **S2 application graph 🔴** · **S3 auth/role matrix 🔴** · S4 prioritize 🟡 (`active_prioritization`
  + object-id; needs criticality scoring) · **S5 hypothesis engine 🔴** · S6–S10 probes ✅ (read-BOLA,
  SQLi, XSS, mass-assign, JWT) + **W1 write-BOLA / BFLA 🔴** · **S11 workflow 🔴** · S12
  evidence/severity 🟡 (`severity_rationale`; needs proof contracts) · S13 merge/correlate ✅
  (`attack_chains` post-merge) · S14 ASM feedback 🟡 (ledger/gaps exist; add blocked-hypotheses + proof-gaps).

**The ladder (each rung is shippable and benchmark-gated):**
- **FND — Foundation (IN PROGRESS):** the D-series below. Reliability + real discovery + auth. `D0a`
  (reachability gate) shipped (`8a2c0c6`); live discovery now 1337 vs 35 endpoints. *Nothing hunter-y
  is worth building until scans complete and see the surface.*
- **P0 — Hunter benchmark harness + `hunter_summary`:** wire crAPI/Juice Shop fixtures into `fefe781`,
  emit `hunter_summary` (discovered/attempted/confirmed/missed/proof-gap/blocked) even with 0 findings.
- **P1 — Application graph + auth matrix (S2/S3):** routes, resources, producer/consumer edges,
  sensitive fields, principal×endpoint matrix — fed from inventory/crawl/JS/OpenAPI/HAR/browser.
- **P2 — Authz pack (S7):** two-principal read-BOLA (have) → **BFLA role-matrix** + **safe write-BOLA
  (W1)**, Lab/resettable-gated, deterministic proof.
- **P3 — BOPLA/mass-assignment (S8):** read-side exposure first; mutation Lab-only.
- **P4 — Workflow/business-logic hypothesis engine (S5/S11):** generate hypotheses + blocked gaps first.
- **P5 — Proof-depth (S10):** SQLi/XSS/SSRF/LFI/RCE — only after benchmark shows them as the top miss; keep high-risk Lab-gated.

**Safety invariants carried from the spec (non-negotiable):** Safe mode = passive/safe-authz only;
Lab/deep required for any mutation/SSRF/LFI/RCE/mass-assign-write/destructive workflow; BOLA needs
≥2 principals (or 1+anon); never mark tested without telemetry; never inflate severity without
deterministic proof; redact secrets; preserve rate budgets; don't auto-enable high-risk families in
broad fan-out. (All already enforced by `check_registry` + `_enforce_asm_family_preconditions` — keep it.)

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

## Sequencing (foundation → hunter ladder)
| Rung | Step | Why |
|---|---|---|
| **FND (now)** | D0a reachability-gate ✅ · D0b cap synthetic perms · D0c hard active time budget | Stops the hang + reclaims budget wasted on phantom 404s — nothing completes without this |
| **FND** | D1 decouple discovery from focus · D2 recon param enumeration · D3 SPA/API capture → worklist | Biggest discovery lift — live: 1337 endpoints with browser+auth vs 35 |
| **FND** | D4 authenticated + multi-auth discovery/test · D5 per-family union passes (not diluted) | Unlocks authn-gated Highs; right endpoints |
| **P0** | Hunter benchmark fixtures + `hunter_summary` emission | Objective miss-analysis; turns the ladder into numbers (spec P0) |
| **P1** | Application graph + auth matrix (S2/S3) | The attacker model BFLA/BOLA/workflow all read from |
| **P2** | Authz pack: BFLA role-matrix + W1 safe write-BOLA (S7) | Highest-impact crAPI lift; Lab/resettable-gated, deterministic proof |
| **P2** | N5 registry-driven dispatch · W2 fire JWT/mass-assign | Makes per-family passes + all detectors clean |
| **P3** | BOPLA/mass-assignment depth (S8) · W3 DOM/stored XSS | Read-side first; mutation Lab-only |
| **P4** | Workflow/business-logic hypothesis engine (S5/S11) · N1/N2 graph persistence | Business-logic Highs |
| **P5** | Proof-depth SQLi/XSS/SSRF/LFI/RCE (S10) · N6 proof contracts | Only after benchmark shows them as top miss; high-risk stays Lab-gated |

## Operational cautions (learned live, 2026-06-18)
- **Authenticated `exploit_depth` scans mutate the test account** (our crAPI creds were burned
  mid-loop). Register fresh users per authenticated run; W1/W2 writes MUST be non-destructive.
  Self-mint crAPI tokens via signup/login — see `[[crapi-juiceshop-validation-setup]]`.
- **Single-file mount staleness:** after editing `scanner.py`, `docker compose up -d
  --force-recreate worker` and verify each worker (`grep`/`ast.parse`) before trusting results —
  `restart` left a truncated copy. See `[[docker-single-file-mount-staleness]]`.
- **Verify against current HEAD before acting** — it advances between turns. `[[reaudit-head-before-acting]]`.
