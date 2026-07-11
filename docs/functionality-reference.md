# ShakerScan Functionality Reference — DAST + AI Red Teaming

**Status:** Comprehensive functional reference for the whole product. This is the "what can ShakerScan
actually do" map across both pillars: **DAST** (Dynamic Application Security Testing) and **AI red
teaming** (AI Gate, Model Intake, AI Security Sessions, AI-assisted analysis).
**Date:** 2026-07-07
**Audience:** users, operators, AI coding agents, and engineers who need one place that explains the
product's functionality end to end.

> **Source of truth.** This document describes shipped behavior, grounded in the code at the time of
> writing. As with the sibling architecture docs, **the code, DB schema, and tests remain
> authoritative** — file paths drift, so this reference prefers named files/symbols over line numbers.
> Verify before depending on a detail. For implementation-depth and roadmap material, follow the
> cross-links in [§13](#13-where-to-go-deeper).

---

## Table of contents

1. [What ShakerScan is](#1-what-shakerscan-is)
2. [System architecture](#2-system-architecture)
3. [DAST — scan types and coverage budgets](#3-dast--scan-types-and-coverage-budgets)
4. [DAST — the scan pipeline (phases)](#4-dast--the-scan-pipeline-phases)
5. [DAST — discovery and reconnaissance](#5-dast--discovery-and-reconnaissance)
6. [DAST — vulnerability checks](#6-dast--vulnerability-checks)
7. [DAST — authentication support](#7-dast--authentication-support)
8. [DAST — scoring, attack chains, coverage, and reports](#8-dast--scoring-attack-chains-coverage-and-reports)
9. [Scaling DAST: parallel scanning and Continuous ASM](#9-scaling-dast-parallel-scanning-and-continuous-asm)
10. [Attack-surface management: discovery, CT monitoring, schedules](#10-attack-surface-management-discovery-ct-monitoring-schedules)
11. [AI red teaming](#11-ai-red-teaming)
12. [Cross-cutting: findings, exposure graph, workers, queue](#12-cross-cutting-findings-exposure-graph-workers-queue)
13. [REST API reference (by area)](#13-rest-api-reference-by-area)
14. [Configuration and integrated tools](#14-configuration-and-integrated-tools)
15. [Safety model](#15-safety-model)
16. [Where to go deeper](#16-where-to-go-deeper)

---

## 1. What ShakerScan is

ShakerScan is an open-source security scanner for **web applications, APIs, and AI systems**. It runs
locally as a Docker stack with a web UI, a REST API, a PostgreSQL database, a Redis job queue, and a
scalable pool of scan workers. It is designed to be driven either directly (CLI / UI / REST) or
through an AI coding agent (Claude Code, Codex, OpenCode) using plain-English requests.

It covers two complementary pillars:

- **DAST** — actively probes a running website or API for real vulnerabilities the way an attacker
  would: injection (XSS, SQLi), broken access control (BOLA/IDOR), exposed secrets and files,
  misconfigured TLS/headers/CORS, SSRF/LFI/RCE, weak auth/session/JWT, and more — then grades what it
  finds and correlates findings into attack chains.
- **AI red teaming** — attacks AI features the same way: chatbots, RAG endpoints, agents, and MCP
  tools are probed for prompt injection, sensitive-data disclosure, unsafe tool use, approval bypass,
  and RAG/MCP boundary failures. A separate **Model Intake** capability statically vets model
  artifacts before deployment.

Both pillars write into one shared findings store and one exposure graph, so DAST and AI results are
triaged, filtered, and reported through the same workflow.

---

## 2. System architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Web UI (:3000)  — Next.js dashboard                           │
└──────────────────────────────────────────────────────────────┘
                              │
┌──────────────────────────────────────────────────────────────┐
│  API server (:8080) — FastAPI + asyncpg + Redis                │
│  background loops: stale_scan_checker, schedule_runner,        │
│  asm_dispatcher                                                │
└──────────────────────────────────────────────────────────────┘
        │ RPUSH scan_jobs / retest_jobs           ▲ findings, scans
        ▼                                          │ (dedup at DB)
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  Worker 1    │  │  Worker 2    │  │  Worker N    │  (1–20, BLPOP loop)
│  → scanner   │  │  → scanner   │  │  → scanner   │  subprocess per job
└──────────────┘  └──────────────┘  └──────────────┘
        │                 │                 │
        ▼                 ▼                 ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  PostgreSQL  │  │    Redis     │  │ ./results    │
│ (persistent) │  │   (queue)    │  │ (JSON files) │
└──────────────┘  └──────────────┘  └──────────────┘
```

**Components**

- **API server** (`api/api.py`): FastAPI app over an asyncpg PostgreSQL pool and Redis. Serves the
  full REST surface (scans, findings, targets, AI Gate, model intake, sessions, ASM, schedules,
  workers, exposure graph). It runs three background asyncio loops in its lifespan:
  - `stale_scan_checker` — fails scans stuck beyond `MAX_SCAN_DURATION`.
  - `schedule_runner` — fires due recurring schedules and recomputes their next run.
  - `asm_dispatcher` — for each ASM-enabled target, picks **one** safe next action (recon vs. test
    batch vs. wait) within freshness/rate/window budgets.
- **Workers** (`api/worker.py`): each worker is a stateless process running a `BLPOP` loop over the
  Redis queues (`scan_jobs`, optionally `retest_jobs`), processing one job to completion and spawning
  the scanner as a subprocess. Job types: `scan` (standard), `scan_plan`/`scan_shard`/`scan_merge`
  (parallel), `discovery` (subdomains), `finding_retest` (verification), and `exploit_batch` (ASM).
- **Scanner engine** (`scanner/scanner.py` → `build_report()`): the DAST orchestrator. Runs the scan
  phases, invokes the 70+ specialized modules in `scanner/scanner_tools/`, and emits the result JSON.
- **PostgreSQL** (`db/init.sql`): durable storage for scans, findings, targets, schedules, AI
  targets/credentials/principals, scan campaigns, the ASM endpoint inventory, attempt ledger, and
  discovery runs. Findings are de-duplicated at the DB with `UNIQUE(target_id, fingerprint)`, which
  makes concurrent writes from many workers against one target race-safe.
- **Redis**: job queue plus coordination keys (barrier counters, rate-token buckets, endpoint leases,
  cancel flags, circuit breakers).
- **Session manager** (`api/session_manager.py`): headless Playwright browser sessions for
  interactive AI security testing.
- **Gungnir worker** (`api/gungnir_worker.py`): Certificate Transparency log monitor.

**Worker scaling.** Workers are identical Docker replicas scaled 1–20 through the Docker socket
(`POST /workers`, `./scanner.sh scale N`). `N workers = N parallel scans`. Each worker uses roughly
1–2 CPU cores and 2–4 GB RAM during active scans.

---

## 3. DAST — scan types and coverage budgets

Two orthogonal dials control DAST:

- **Scan type** controls **what** runs (which modules/phases are enabled).
- **Coverage budget** controls **how hard** it runs (depth/time/limits).

### Scan types

Validated set (`scanner/constants.py` `SCAN_BUDGET_DEFAULTS`): `quick`, `standard`, `deep`, `full`,
`aggressive`, `smart`.

| Type | Typical time | What it does |
|------|--------------|--------------|
| **quick** | 1–2 min | DNS, TLS cert, HTTP headers, basic tech detection |
| **standard** | 5–10 min | + Nuclei (safe), cookies, CORS, JS deps (no port scan by default) |
| **deep** | 30–60 min | + full Nuclei, top-1000 port scan, JS secrets |
| **full** | 1–2 hrs | + active XSS/SQLi, WebSocket, auth/session/file-upload/redirect/CSRF/API tests |
| **aggressive** | 2+ hrs | + aggressive exploits, full 65535-port scan, threat intel, extended fuzzing |
| **smart** | variable | Adaptive: staged Nuclei, DBMS-aware SQLi, context-aware XSS, attack chains, early stop |

`full`, `aggressive`, and `smart` include active probing and must only be run against authorized
targets. `full` advanced probes (SSRF/command injection) only run with a non-safe exploit level and
parameterized endpoints.

### Coverage budgets

Profiles: `fast`, `balanced` (default), `thorough`, `exhaustive`. Scan type controls which modules
run; the budget controls their depth/time. Prefer `budget_profile` over switching scan types when you
just want more or less depth.

`custom_budget` overrides individual knobs, capped at generous `SCAN_BUDGET_CEILINGS` (e.g.
`active_max_endpoints` up to 10000, `max_urls` up to 100000, `active_max_seconds` up to 24h). Common
knobs: `max_urls`, `browser_max_pages`, `api_probe_limit`, `nuclei_max_targets`, `active_max_seconds`,
`active_max_endpoints`, `active_params_per_endpoint`, `smart_bola_max_endpoints`, `dom_xss_max_files`,
`sqli_extract_max`, `oob_max_findings`, `active_worklist_max`.

The **smart** scan applies its own adaptive budget matrix (`SMART_SCAN_BUDGETS`) and supports
`no_early_stop` + `thorough_params` shortcuts. See [`smart.md`](../smart.md) and
[`docs/SMART_SCAN_POLICY.md`](SMART_SCAN_POLICY.md) for the full smart-scan policy.

---

## 4. DAST — the scan pipeline (phases)

`build_report()` runs as a phased waterfall. Tasks within a phase run concurrently (async I/O), but
phases have hard barriers because downstream stages depend on discovery output and early signals.

1. **Baseline infrastructure** — DNS (A/AAAA/MX/SPF/DMARC/DKIM/DNSSEC/CAA), TLS/cert analysis,
   HTTP security headers, HTTP/2-3 support, `security.txt`, virtual-host enumeration, tech
   fingerprinting, WAF detection, optional light port scan.
2. **Discovery** (hard barrier — produces the work-list) — crawl + content discovery + browser
   capture + JS analysis + API endpoint discovery. Everything downstream needs the harvested
   `crawl_urls` / endpoint work-list.
3. **Nuclei** — template-based vulnerability scanning. In smart mode this is **staged into four
   waves** (~60s/120s/300s/480s budgets) with yield-driven early stopping; signals from early waves
   steer later active testing.
4. **Passive checks** — cookies, CORS, security posture, info disclosure.
5. **Client-side checks** — JS dependency/secret scanning, DOM-XSS static analysis.
6. **Infrastructure-leak checks** — exposed files, backups, CI/CD config, cloud buckets, default
   creds, directory listing.
7. **Active web checks (Phase 4)** — file upload, open redirect, host-header injection, CSRF,
   business logic, WebSocket, generic API security sweep.
8. **Smart active checks (Phase 5)** — context-aware XSS and DBMS-aware SQLi over prioritized
   endpoint slices; BOLA/IDOR multi-user comparison.
9. **Verification phase** — high/critical findings get browser proofs, SQLi timing analysis, OOB
   callbacks, and BOLA differential-auth confirmation.
10. **Attack-chain + AI correlation** — runs once over the full finding set.
11. **Report assembly** — coverage merge, score/grade, result JSON.

---

## 5. DAST — discovery and reconnaissance

The scanner's `scanner_tools/` directory holds 70+ specialized modules. Key discovery/recon
capabilities:

**DNS & domain** (`discovery.py`, `dns_enhanced.py`): A/AAAA/MX/TXT/NS/SOA/CAA records; SPF/DMARC/DKIM
enumeration; DNSSEC validation; zone-transfer attempts; virtual-host enumeration.

**TLS & certificates** (`tls_scanner.py`): certificate subject/issuer/expiry/key-size/chain analysis,
OCSP stapling, cipher-suite enumeration, and TLS version detection — using `sslyze`, `testssl.sh`, and
`nmap` in combination.

**HTTP fingerprinting**: server/framework detection, security-header analysis (HSTS, CSP, X-Frame-
Options, Referrer-Policy, COOP/CORP), and HTTP/2 / HTTP/3 detection. CSP is graded with parsed
directives.

**Web application discovery**:
- **Crawling** — `katana` recursive crawl + `httpx` probing (`discovery.py`).
- **Browser crawl** — headless Playwright multi-page crawl with HAR/network capture and API capture
  (`http_scanner.py`); SPA hash-route crawling (`hash_routes.py`).
- **Content discovery** — `ffuf` directory/file fuzzing against bundled and custom wordlists.
- **Parameter discovery** — query/body parameter inference from observed requests.
- **JS bundle analysis** — extracts hidden endpoints and routes from JavaScript bundles.
- **API discovery** — HTTP `OPTIONS` method discovery, gRPC reflection (`grpc_discovery.py`),
  GraphQL introspection (`graphql_schema_recovery.py`), and JSON link following (HATEOAS/pagination).
- **HAR-driven prioritization** — `har_discovery.py` / `active_prioritization.py` rank real
  network-captured endpoints first.

**WAF detection**: response-pattern fingerprinting of the protecting WAF product.

**Port scanning** (`nmap.py`): top-N ports (light scan in smart mode) up to full 65535-port scans in
aggressive mode, with service/version detection.

**Subdomain enumeration**: `subfinder` (passive), `gungnir` (CT logs), and crt.sh — see
[§10](#10-attack-surface-management-discovery-ct-monitoring-schedules).

Discovery toggles available in scan `options`: `json_link_following`, `options_method_discovery`,
`grpc_discovery`, plus `custom_endpoints`, `custom_wordlist`, `custom_sqli_payloads`, and
`custom_xss_payloads` for extension.

---

## 6. DAST — vulnerability checks

### Active injection

- **XSS** (`active_checks.py`, `dom_xss_analyzer.py`): `dalfox`-based reflected/DOM detection plus a
  custom **context-aware** tester that detects reflection context (in-script, in-attribute, event
  handler, HTML body, SVG/CSS/JSON/URL-path) and selects context-specific payloads; canary-based
  reflection detection; browser proof for GET reflections and HTML-like POST/PUT/PATCH response
  reflections; hash-route testing; static DOM-XSS source-to-sink analysis over JS files.
- **SQLi** (`active_checks.py`): `sqlmap`-based testing that is **DBMS-aware** (SQLite, MySQL,
  PostgreSQL, MSSQL, Oracle) — it fingerprints the database, then chooses DBMS-specific payloads,
  techniques, and optional data-extraction chaining. Supports out-of-band (blind) detection via
  `oob_callback_url`.
- **Other injection** (`injection_extra_checks.py`): SSI/ESI, prototype pollution, CSV/formula
  injection, RFI, LDAP/XPath, XXE/XML injection.
- **SSRF / command injection / LFI / RCE**: high-risk active families, gated behind non-safe exploit
  level and parameterized endpoints; SSRF includes cloud-metadata and Gopher payloads
  (`gopher_payloads.py`) with OOB verification.

### Access control

- **BOLA / IDOR** (`bola_comparison.py`, `access_control_checks.py`): dual-user testing — replay the
  same endpoint as user1 and user2, normalize volatile fields (timestamps, UUIDs, nonces), and detect
  cross-user data exposure with concrete PII matching. Also forced browsing, path traversal,
  privilege escalation, and unauthenticated-access detection.

### Web/API security (Phase 4)

File upload bypass (`file_upload_tests.py`), open redirect, host-header injection, CSRF token
presence/reuse/randomness, HTTP method tampering, content-type switching, WebSocket auth/message
handling (`websocket_security.py`), OAuth flow tests (`oauth_tests.py`), and a generic API-security
sweep (`api_security.py`).

### Auth/session/crypto

Weak JWT/session/cookie checks, default-credential testing (`credential_check.py`), and
deserialization tests (`deserialization_tests.py`) for Java/PHP/Python unsafe deserialization.

### Business logic

Race conditions (`race_condition_tests.py`) for checkout, coupons, balance, votes, and invitations.

### Template & infra

Nuclei template checks (`nuclei.py`, wave-staged in smart mode); infrastructure-leak checks
(`infrastructure_checks.py`) for CI/CD config, cloud buckets, registries, k8s/terraform artifacts;
critical checks (`critical_checks.py`) for default creds, directory listing, and verbose error pages.

**Focused active filters** are available in `options`: `xss: true` runs only XSS active checks;
`sqli: true` runs only SQLi.

For OWASP-mapped coverage and intentional gaps, see [`docs/owasp-coverage-matrix.md`](owasp-coverage-matrix.md).

---

## 7. DAST — authentication support

Auth is propagated to the Playwright crawl, Nuclei, Dalfox, SQLmap, and custom checks; long scans
re-authenticate when sessions expire (`auth_session.py`, `form_login.py`, `oauth_auth.py`).

| Option | Purpose |
|--------|---------|
| `auth_header` | Authorization header value (`Bearer …` / `Basic …`) |
| `auth_cookies` | Session cookies (`session=abc; token=xyz`) |
| `auth_headers_json` | Arbitrary custom headers as a JSON object (API keys, etc.) |
| `login_username` / `login_password` | Form-based login (scanner auto-authenticates) |
| `login_url` / `login_extra_fields` | Login page + extra form fields (auto-detected if omitted) |
| `user2_header` / `user2_cookies` | Second user context for BOLA/IDOR comparison |

OAuth 2.0/OIDC (client-credentials and auth-code grants, refresh handling, optional TOTP) is
supported. The scanner tracks `auth_state` per request (`anonymous` / `user1` / `user2`) so coverage
is counted separately per identity.

**Workflow:** create a test account → log in and capture token/cookies → pass via scan `options` →
the scanner uses the credentials for all authenticated requests, and re-auths on expiry.

---

## 8. DAST — scoring, attack chains, coverage, and reports

**Scoring & grading** (`scanner/grading.py`): findings are scored on a CVSS-style scale by
vulnerability type with context modifiers (auth/payment/admin endpoints raise severity; static/dev
endpoints lower it) and exploit-maturity bonuses. The scan returns:

- `score`: 0–100 (higher is better)
- `grade`: A / B / C / D / F
- `findings`: array with severities `critical` / `high` / `medium` / `low` / `info`
- `result`: the rich object below

**Finding processing**: deduplication (`deduplication_engine.py`), false-positive validation
(`finding_validator.py`), correlation (`finding_correlator.py`), and a verification ladder
(`verification_engine.py`, `verification_phase.py`, `proof_of_exploit.py`) that produces reproducible
evidence for high-severity findings.

**Attack-chain analysis** (`attack_chains.py`): correlates findings into exploitable chains with
business impact. The nine implemented chain types (`CHAIN_TEMPLATES`) are
`xss_to_account_takeover`, `sqli_to_privilege_escalation`, `ssrf_to_cloud_breach`,
`idor_to_data_breach`, `lfi_to_credential_theft`, `cors_to_data_theft`,
`weak_jwt_to_impersonation`, `xxe_to_data_exfil`, and `deserialization_to_rce`.
Partial chains can be surfaced with `include_partial_attack_chains: true`.

**Coverage tracking** (`coverage_tracker.py`, `completion_status.py`): `result.smart_coverage` reports
endpoints/parameters/templates discovered vs tested, by method and parameter location, plus discovery
sources and auth states tested.

**Compliance mapping** (`compliance_mapper.py`): OWASP Top 10, CWE, and control-framework context
(SOC 2 / GDPR / PCI-DSS).

**Rich result object** (`result.*`): `http.csp_evaluation`, `http.security_headers`,
`tls.certificate`, `tls.ocsp`, `dns`, `discovery.tech.items`, `discovery.browser_api_endpoints`,
`discovery.browser_crawl`, `discovery.waf_detection`, `attack_chains`, `smart_coverage`, and — when AI
is enabled — `ai_correlations` and `ai_logs.summary.cross_finding_correlations`. SARIF export is
available (`sarif_output.py`); the UI offers PDF export.

---

## 9. Scaling DAST: parallel scanning and Continuous ASM

These two subsystems share the same durable primitives (endpoint inventory, work allocator, attempt
ledger). They are two views over the same facts: "run full coverage now" vs. "keep this target covered
over time."

### Parallel scanning

One logical scan can fan out across the worker fleet via a **parent → plan → shard → merge** model on
the Redis queue (`api/parallel_scan.py`, worker job types `scan_plan`/`scan_shard`/`scan_merge`).
Findings dedupe automatically at the DB; attack-chain/AI correlation runs once at merge.

Strategies (`options.shard_strategy`):

| Strategy | Behavior |
|----------|----------|
| `auto` | scope when ≥2 `custom_endpoints` are present; otherwise coverage for Smart/Full/Aggressive active scans |
| `scope` | partition `custom_endpoints` across shards — genuine speed-up for APIs |
| `family` | broad + deeper SQLi-focused + XSS-focused shards (capped at 3) — more depth |
| `coverage` | discover once, harvest the full endpoint worklist, partition it across auto-sized shards — maximum breadth (UI: **Full Coverage**) |
| `coverage_family` | advanced: coverage × broad/SQLi/XSS lanes; explicit focused requests such as BOLA/Auth stay single-family |

Full Coverage uses **dynamic pull-based allocation** by default (workers claim campaign-scoped
endpoint batches from the allocator); `coverage_allocation=static` keeps the legacy round-robin
slices as a fallback. Coverage children run in zero-rediscovery mode (no re-crawl). The parent appears
as one row on the Scans page; shard rows are hidden unless `include_shards=true`.

Automatic broad active coverage uses smaller endpoint batches by default so workers can keep claiming
new work instead of leaving one large straggler: 50 endpoints per dynamic batch for normal active
mixes, 35 for exploit-depth/exhaustive scans. Focused SQLi/XSS lanes and explicit caller overrides can
still use larger batches through `coverage_per_shard_cap` or `coverage_dynamic_batch_size`.

Full design and current status: [`docs/parallel-scan-architecture.md`](parallel-scan-architecture.md).

### Continuous ASM

Continuous ASM keeps a **persistent endpoint inventory** per target (`target_endpoints`) and improves
coverage over time within safe budgets and allowed windows (`api/asm_inventory.py`, the
`asm_dispatcher` loop, and the `exploit_batch` worker job).

- Endpoint identity includes auth state, HTTP method, normalized path, and parameter location/shape,
  so the same path under anonymous/user1/user2 is tracked as distinct coverage obligations.
- The dispatcher reserves per-root-domain rate budget in Redis before queueing, claims rows with
  `FOR UPDATE SKIP LOCKED` under durable leases, and never stacks load on a target.
- Coverage derives from a normalized **attempt ledger** (`asm_endpoint_attempts`): an endpoint is only
  marked `tested` when scanner telemetry proves it was attempted/completed. Timeouts/partial results
  do not count unattempted endpoints as covered.
- For AI/agent workflows, prefer `POST /targets/{id}/asm/improve`, which chooses recon vs. test batch
  vs. wait from current gaps. Focused families: `sqli`, `xss`, and gated `bola` (requires
  `exploit_depth: true` plus primary and second-user auth). Planned families (`auth`, `ssrf`, `lfi`,
  `rce`, `business_logic`) are registered but rejected for ASM execution until their scanner
  integrations ship.
- `GET /targets/{id}/asm/activity` is the read-only operator summary for one target: recent hidden ASM
  recon/test jobs, the scheduler decision, campaign timeline events, active ASM scans, and a bounded
  target-scoped hypothesis situation report. The embedded hypothesis report surfaces proof leads and
  missing preconditions next to coverage state, but it does not queue work, create findings, or change
  proof state.

Full design and current status: [`docs/continuous-asm-architecture.md`](continuous-asm-architecture.md).
Multi-VPS fleet plans: [`docs/multi-node-architecture.md`](multi-node-architecture.md).

---

## 10. Attack-surface management: discovery, CT monitoring, schedules

**Subdomain discovery** (`POST /discovery`, `process_discovery_job`): enumerates subdomains for a root
domain via Gungnir, Subfinder, and crt.sh, then upserts discovered hosts as targets.

**Certificate Transparency monitoring (Gungnir)** (`api/gungnir_worker.py`): a long-running worker
that watches CT logs in real time, discovering new certificates for monitored domains. New subdomains
are auto-added as targets (`discovery_source = gungnir-monitor`); if the root domain has ASM enabled,
discovered surface inherits the ASM policy. Controlled via `./scanner.sh gungnir start|stop|status`
and `/gungnir/*` endpoints.

**Schedules** (`schedule_runner`, `/schedules`): recurring daily/weekly scans per target with
`time_of_day` (UTC), optional `day_of_week`, scan type, and `scan_options`, so important targets stay
continuously monitored. Schedule listings include derived `schedule_health` when recent scan results
show repeated failures or timeout/heartbeat failures for the same active target/type pair, and the
Dashboard Action Center links operators to the affected schedule plus the latest failed scan.

---

## 11. AI red teaming

The AI side has four capabilities:

1. **AI Gate** — probe-driven runtime testing of chat, RAG, agent, MCP, and widget surfaces.
2. **Model Intake** — static artifact and supply-chain vetting before deployment.
3. **AI Security Sessions** — interactive browser/session testing with separate user contexts.
4. **AI-assisted analysis** — correlation, explanation, and retest planning for DAST findings.

**Design principle.** AI may help judge, correlate, and explain, but verified security decisions must
be backed by deterministic, cryptographic, parser-backed, protocol-backed, or replay-backed evidence.
Findings carry proof quality explicitly (see [AI proof and evidence states](#ai-proof-and-evidence-states)
below); AI is never the sole authority for verified status or severity promotion. For engineering-depth
onboarding see [`AI_REDTEAM_AND_MODEL_INTAKE.md`](AI_REDTEAM_AND_MODEL_INTAKE.md); current hardening
work is tracked in [`proposed-next-steps.md`](proposed-next-steps.md). The completed June fix plan is
preserved only as an [archived implementation record](archive/ai-redteam-model-intake-fix-plan-2026-06.md).

### AI capability status quick read

Status reflects shipped behavior last reconciled against code (2026-07-11). "Partial" means the capability
runs but the listed caveat applies — treat the caveat as load-bearing, not cosmetic.

| Capability | Status | Trust / proof caveat |
|---|---|---|
| AI Gate REST / RAG / agent / MCP probing | Shipped | Production probe-safety filter now effective (3-tier derived classification; `non_production_only` probes dropped in production). |
| AI Gate widget target | Shipped | Playwright-driven target honors shared request-budget and response-byte cap contracts; deterministic proof still outranks AI judgment. |
| AI Gate per-finding retest | Shipped | Deterministic proof still outranks AI judgment. |
| Cross-principal AI testing | Shipped | Requires configured principals. |
| MCP readiness checks | Shipped | Safe `resources/list` added; audience/scope still partly from declared metadata. |
| Transcript retention / purge | Shipped | Response-time redaction by default + audited admin gate (`AI_TRANSCRIPT_ALLOW_SENSITIVE`). |
| Model Intake checksum / range / local-file gates | Shipped | Solid baseline. |
| Model Intake signature / provenance crypto | Shipped | Real detached-sig verification (`cryptography`: Ed25519/RSA-PSS/ECDSA); metadata booleans are claims, not proof. |
| Model Intake governance evidence | Shipped | SPDX normalization + expression parsing added (`MIT OR Apache-2.0`). |
| Agent execution receipts | Shipped | Verifies content-hash, prev_hash chain, and signature (Ed25519/RSA/ECDSA). |
| Deployment gate API | Shipped | Should converge on the unified proof/policy states. |
| Durable policy + exception registry | Shipped | DB-backed `policy_profiles` + `finding_exceptions` + CRUD; consumed by the deployment decision; exceptions expire and re-open blocks. |

### AI proof and evidence states

Today a finding exposes a three-state proof level — `verified` (deterministic proof), `suspected`, or
`unverified` (`api/api.py`), with `proof_state` `exploited` / `likely_vulnerable` at the scanner — and
deterministic proof blocks any AI downgrade. The **target** is one taxonomy unified across DAST and AI
(`deterministic_verified`, `cryptographically_verified`, `claimed_present`, `ai_judged_likely`,
`inconclusive`, `blocked`, `false_positive`) so that *claimed* metadata and *AI-judged* results can
never render as *verified*. Current proof-state hardening is tracked in
[`proposed-next-steps.md`](proposed-next-steps.md); the original AI taxonomy design is retained in the
[archived fix plan](archive/ai-redteam-model-intake-fix-plan-2026-06.md).

### 11.1 AI Gate

AI Gate tests AI application surfaces by sending crafted probes and grading the responses.

**Target types** (`api/ai_gate_scan.py`, adapters under `api/ai_gate/targets/`):

| Type | Surface |
|------|---------|
| `api_chat` | Chat/completions-style JSON endpoint |
| `rag` | RAG answer endpoint |
| `agent_trace` | Agent/trace endpoint or trace-replay API |
| `mcp_trace` | MCP HTTP/SSE endpoint or MCP trace-compatible API |
| `widget` | Browser widget target (Playwright-driven) |

REST/JSON adapters use a `request_template` containing `{{prompt}}` (and optionally `{{session_id}}` /
`{{previous_response}}`), extract the model's answer via a JSONPath `response_path` (e.g. `$.answer`),
and support `json` or `sse` streaming modes plus a `headers_template` for auth.

**Probe packs** (`api/ai_gate/probe_registry.py`):

| Pack | Focus |
|------|-------|
| `shaker-ai-smoke` | Small broad smoke test |
| `shaker-owasp-llm` | OWASP LLM Top-10 risks |
| `shaker-agent-abuse` | Tool abuse, approval bypass, agent boundaries |
| `shaker-mcp-security` | MCP tool/resource/scope/OAuth issues |
| `shaker-rag-lite` | RAG leakage and retrieval-boundary issues |

**Vulnerability classes probed**: prompt injection, sensitive/secret disclosure, system-prompt
leakage, improper output handling, excessive agency, unbounded consumption, encoding-bypass; agent
families like approval bypass, tool-result injection, secret exfiltration, cross-account/cross-tenant
actions, identity/approval-token replay; MCP families like untrusted-server trust, tool-metadata
change, OAuth audience confusion, PKCE downgrade; and RAG families like retrieval-ACL bypass, citation
fabrication, poisoned/deleted-document recall, and canary leakage.

**Profiles** (`smoke` / `trace` / `standard` / `deep`) scale the probe set and the max conversation
turns; **environments** (`preview` / `staging` / `development` / `production`) gate which probes run —
production blocks probes flagged unsafe for production, and production scans require
`confirm_production: true`.

**Detection — two layers**:
1. **Deterministic detectors** run first (`api/ai_gate_scan.py`): regex/keyword markers for token and
   secret patterns (AWS/GitHub/Slack keys, private keys, JWTs, DB connection strings), prompt-leakage
   markers, approval-bypass markers, metadata-injection markers, agent/tool markers, MCP/OAuth
   markers, and RAG markers.
2. **Semantic AI judging** (`scanner/scanner_tools/ai_classifier.py`), when an AI provider is
   configured: judges probe transcripts and populates `ai_verdict`, `ai_confidence`, `ai_rationale`,
   and `ai_recommendations`. Sensitive headers/bodies are redacted before being sent to the judge; a
   circuit breaker and retry/backoff protect against provider failures. A verdict policy
   (`scanner/ai_verdict_policy.py`) governs trust thresholds — high-confidence false positives can be
   downgraded, but never when deterministic proof of exploitation exists.

**AI control-evidence baseline** (`api/ai_control_requirements.py`): from a target's `metadata_json`,
AI Gate builds a control-evidence pack (asset owner, risk tier, data classification; RAG
ACL/ingestion/tenant-isolation controls; agent tool scopes, delegated identity, token-audience
validation, approval/dry-run/transaction limits, sandboxing, audit logs, anomaly detection, kill
switch; governance mappings to NIST AI RMF / ISO 27001 / OWASP LLM). With
`enforce_ai_control_baseline: true`, missing required controls become findings. The AI Gate score and
the **deploy decision** combine deterministic findings, AI verdicts, and control evidence.

**Principals** (`/ai/targets/{id}/principals`): multiple named identities (roles `attacker`/`victim`/
`admin`/`service`/`observer`) with separate credentials, enabling cross-user/cross-tenant RAG and
agent tests.

**Transcripts & reporting**: `GET /ai/scans/{id}/transcript` returns probe transcripts; AI findings
carry probe family/technique/OWASP refs, classifier output, and raw evidence. Post-scan AI red-team
reports are available via `/scans/{id}/ai-redteam-report` and a CI/CD `deployment-decision` endpoint.

### 11.2 Model Intake

Model Intake (`scanner/scanner_tools/model_intake.py`) statically vets model artifacts **without
importing or executing model code**. Inputs: `artifact_url`, `metadata_url`, `expected_sha256`,
`signature_url`, `model_card_url`, and inline `metadata_json`, plus `require_*` gates.

> **Signature/provenance (R1, shipped 2026-06-24).** Model Intake performs real detached-signature
> verification (Ed25519 / RSA-PSS / ECDSA via the `cryptography` lib) over the artifact or its digest
> when a public key + signature are supplied (`signature_public_key`/`_url`, `signature_value`/
> `signature_url`); `require_cryptographic_signature_verification` makes a metadata-only claim fail.
> Metadata booleans such as `sigstore_verified: true` are treated as **claims**, never as cryptographic
> proof. (A cosign/Sigstore-rekor transparency-log layer is an optional future add-on.)

Checks include:
- **Unsafe serialization** — flags pickle-like formats (`.pkl`, `.pickle`, `.joblib`, `.pt`, `.pth`,
  `.ckpt`, `.bin`, `.mar`) vs. safer ones (`.safetensors`, `.onnx`, `.tflite`, `.gguf`); scans for
  pickle opcode markers and suspicious loader markers (`os.system`, `subprocess`, `eval`/`exec`,
  `pickle.loads`, network downloaders, base64 decode).
- **Archive payload analysis** — enumerates `.tar.gz`/`.zip` contents and flags executable extensions
  without decompressing/running anything.
- **Provenance & integrity** — checksum (`sha256`) verification; signature/attestation **presence**;
  **claimed** signature/provenance metadata; **cryptographic** detached-signature verification
  (Ed25519/RSA-PSS/ECDSA via the `cryptography` lib, over the artifact or its digest); Hugging Face
  reference normalization.
- **Governance evidence** — model card presence, license policy (permissive vs. restrictive),
  SBOM/AIBOM, malware-scan evidence, security-eval evidence, deployment restrictions, monitoring plan,
  and deployment approval.

Result shape: `model_intake.checks.*`, `aibom`, `supply_chain`, `summary` (with the `decision`), and
`artifact`. Findings are stored with `tool = model_intake`; `source_type=dast` includes them until a
dedicated model-intake source filter exists. Sensitive URL params and metadata keys are redacted.

### 11.3 AI Security Sessions (interactive)

`api/session_manager.py` plus `/session/*` endpoints provide collaborative, interactive testing in a
headless browser. You start a session, drive browser actions (`navigate`, `click`, `fill`, `register`,
`login`, `submit`, `wait`, `extract`), maintain **separate per-user contexts** (e.g. user1/user2),
capture screenshots, and test endpoints for cross-user access (`test-endpoint` with `as_user`).
Endpoint tests that name a user require that user to exist and be authenticated in the session; authz
replay automation also requires at least two authenticated principals before it can make a
cross-principal claim.
Validated findings are saved via `POST /session/{id}/findings` (they appear with `source: ai_session`).
This is the engine behind the `/ai-security-session` skill; see
[`docs/INTERACTIVE_SESSIONS_GUIDE.md`](INTERACTIVE_SESSIONS_GUIDE.md).

### 11.4 AI-assisted analysis of DAST findings

When an AI provider is configured (`AI_URL` / `AI_API_KEY` / `AI_MODEL`), ShakerScan adds
cross-finding correlation and an overall risk assessment to DAST reports, and can run AI-driven retest
verification of findings (`AI_VERIFY_*`). The AI retest tier generates an exploitation plan and
replays it (optionally via a browser), and can downgrade false positives — but deterministic proof of
exploitation blocks any downgrade.

### 11.5 AI Operations Router

`POST /ai/ops/route` maps natural-language DAST/ASM requests to concrete API calls with **dry-run
defaults**. It recognizes intents such as "run full coverage", "keep this target covered" (enable ASM
with a safe preset), "what is still untested?" (ASM gaps), "spend more budget on APIs", and focused
SQLi/XSS/BOLA requests. Active, state-changing, or budget-increasing intents stay dry-run unless
`execute=true`, explicit confirmations, and `AI_OPS_ROUTER_EXECUTE_ENABLED=true` are all present;
BOLA additionally requires primary + second-user auth context. Ambiguous language never upgrades a
Safe/Balanced plan to Lab.

### 11.6 Test scenario catalog and Honey demo

`GET /ai/test-scenarios` returns ready-made templates — notably `secure-rag-agent` (canonical Honey
RAG/agent/MCP endpoints with full control metadata) and `model-intake-pipeline` (safe/unsafe-pickle/
missing-signature/missing-approval model presets). Probe/test-case metadata is exportable to
`promptfoo`, `pyrit`, and `garak` formats (`/ai/test-cases/export`). See
[`docs/AI_TEST_WORKFLOWS.md`](AI_TEST_WORKFLOWS.md).

---

## 12. Cross-cutting: findings, exposure graph, workers, queue

**Findings lifecycle**: every DAST, AI Gate, AI-session, and model-intake result lands in one
`findings` table, de-duplicated by `(target_id, fingerprint)`. Findings have a status
(`active` / `resolved` / `false_positive` / `accepted_risk`), CVSS, CWE/OWASP tags, evidence,
optional AI verdict fields, and verification history. The UI groups findings into two product
categories — **DAST** and **AI** — but the API `source_type` filter is first-class and granular:
`dast`, `ai`, `ai_gate`, `ai_session`, `model_intake`, `asm`, `manual`. `model_intake` and the AI
sources filter **separately** from `dast` (R8).
Findings support filtering, sorting, bulk update/cleanup, manual creation, and per-finding retest.

**Evidence objects**: finding evidence is indexed by hash, storage URI, retention class, scan/finding
links, and redaction profile. Large evidence can live in local content-addressed storage or an opt-in
S3/MinIO-compatible backend; evidence reads verify SHA-256 before returning remote or local content.
Retention sweeps are dry-run by default, skip legal hold, can delete local object files only when
explicitly executed, and report remote-object candidates as preserved because remote deletion is not
yet supported.

**Exposure graph** (`/exposure/*`): a derived graph across domains, targets, APIs, auth roles,
vendors, AI surfaces, MCP tools, model artifacts, scans, and findings, with asset-centric breakdowns
(by owner/tier/classification), change deltas over time, and attack-path views. Backs the UI
`/exposure` page.

**Dashboard & queue**: `/dashboard` (active/critical counts, average score, running scans),
`/queue/stats`, and `/queue/clear`.

**Verification & retest**: deterministic provers exist for xss, sqli, ssrf, path_traversal,
open_redirect, cors, command_injection, ssti, xxe, jwt, idor, bola, and exposed_file; others can be
replayed by the AI tier. Retests are slot-limited (`RETEST_MAX_PARALLEL`) with a watchdog and
auto-retest-on-scan-complete policy.

---

## 13. REST API reference (by area)

Base URL `http://localhost:8080`. All POST/PATCH bodies are JSON. FastAPI also serves the live schema
at `/openapi.json`. (Endpoints grouped by area; see `api/api.py` for handlers. The agent-facing
how-to with request bodies is in [`CLAUDE.md`](../CLAUDE.md) / [`AGENTS.md`](../AGENTS.md).)

**Health & settings**: `GET /` · `GET /health` · `GET|PUT /settings/ai` · `POST /settings/ai/test` ·
`GET|PUT /settings/scan-execution` · `GET|PUT /settings/automation`

**Command Arsenal**: `GET /arsenal/commands` · `GET /arsenal/contracts` ·
`POST|GET /arsenal/plans` · `POST|GET /arsenal/context-packs` ·
`POST /arsenal/context-packs/from-target` · `POST|GET /arsenal/decision-traces` ·
`GET /arsenal/command-results` · `POST /arsenal/scope/preview` · `POST /arsenal/approvals` ·
`GET /arsenal/tools` · `GET|POST /arsenal/refuter-reviews` ·
`GET /arsenal/refuter-reviews/summary` · `POST /arsenal/refuter-reviews/queue-from-summary` ·
`POST /arsenal/refuter-reviews/{id}/execute` ·
`POST /arsenal/refuter-reviews/{id}/derive-verdict` ·
`POST /arsenal/hypotheses/source-ingest` · `POST /arsenal/hypotheses/from-plan` ·
`POST /arsenal/hypotheses/{id}/reconcile-proof` ·
`GET /agents/local` · `POST /agents/local/test` · `POST /agents/local/plan`. Source/spec hints and
saved dry-run plan actions can be recorded as source-only hypotheses; they never create findings or
queue scans. Worker finalization also routes uncertain medium-or-higher scanner findings into
`scanner_signal` hypotheses with deterministic `finding.retest` next actions; verified findings stay
on the finding/proof path instead of duplicating into the lead queue. The `/settings/arsenal` UI
includes a Source Hint Ingest panel for bounded source/spec/route facts. Refuter verdict derivation is
gated and derives only from a linked or explicit verification row; failed/error/AI-driven results remain signal-only. Authz replay promotion
requires an authenticated cross-principal differential, treats login/forbidden soft-200 bodies and
redirect denials as non-violations, and validates approval receipts against the campaign action's
actual target before a manual BOLA finding can be created.
Hypothesis proof reconciliation is separately approval-gated and can only link an existing
`exploited` canonical finding with exact campaign-action, target, family, and route dimensions; it
never creates or verifies a finding from lead context.

**Read-only MCP**: `./scanner.sh mcp` starts a stdio MCP adapter over `POST /arsenal/execute`.
It exposes targets, ASM gaps, findings, content-free evidence manifests, the mission timeline,
saved dry-run plans, and tool status. The adapter revalidates the live Arsenal catalog on every
listing/call and fails closed if a mapped command is no longer `read_only` / `GET` / read-only risk.
State-changing commands are not exposed. See [`docs/read-only-mcp.md`](read-only-mcp.md).

**Scans (DAST)**: `POST /scans` · `POST /scans/batch` · `GET /scans` · `GET /scans/{id}` ·
`GET /scans/{id}/result` · `GET /scans/{id}/logs` · `POST /scans/{id}/cancel` ·
`GET /scans/{id}/deployment-decision` · `GET /scans/{id}/ai-redteam-report`

**Findings**: `GET /findings` · `GET /findings/{id}` · `PATCH /findings/{id}` · `DELETE /findings/{id}`
· `POST /findings/bulk` · `POST /findings/cleanup` · `POST /findings/manual` ·
`POST /findings/{id}/retest` · `POST /findings/retest` · `GET /retests/{id}` ·
`GET /retests/finding/{id}`

**Targets & domains**: `GET /targets` · `GET /targets/grouped` · `GET /domains` · `POST /targets` ·
`GET /targets/{id}` · `PATCH /targets/{id}` · `DELETE /targets/{id}` · `POST /targets/{id}/scan`

**Continuous ASM**: `GET /asm/check-families` · `GET /targets/{id}/asm/endpoints` ·
`GET /targets/{id}/asm/coverage` · `POST /targets/{id}/asm/test` · `POST /targets/{id}/asm/recon` ·
`POST /targets/{id}/asm/prune` · `POST /targets/{id}/asm/improve` · `GET|PUT /targets/{id}/asm/policy`
· `GET /targets/{id}/asm/diff` · `GET /targets/{id}/asm/gaps` · `GET /targets/{id}/asm/activity`

**AI Gate**: `GET /ai/test-scenarios` · `GET /ai/test-cases` · `GET /ai/test-cases/export` ·
`GET /ai/learning-guide` · `POST /ai/demo/run` · `GET /ai/inventory` · `GET|POST /ai/targets` ·
`PATCH|DELETE /ai/targets/{id}` · `POST /ai/targets/{id}/scan` · `POST /ai/targets/{id}/test` ·
`POST /ai/targets/{id}/mcp/live-readiness` · `GET /ai/targets/{id}/runtime-risk` ·
`GET|POST /ai/targets/{id}/principals` · `PATCH|DELETE /ai/targets/{id}/principals/{pid}` ·
`GET|DELETE /ai/scans/{id}/transcript` · `POST /ai/findings/{id}/retest` ·
`POST /ai/surfaces/sync` · `GET /ai/surfaces` · `GET /ai/surfaces/{id}/attempts`

**Model Intake**: `POST /model-intake/resolve` · `POST /model-intake/scan` ·
`POST /model-intake/targets/{id}/rescan`

**Governance (deployment gate)**: `GET|POST /policy-profiles` · `PATCH|DELETE /policy-profiles/{id}` ·
`GET|POST /finding-exceptions` · `PATCH|DELETE /finding-exceptions/{id}`

**AI Ops Router**: `POST /ai/ops/route`

**Interactive sessions**: `POST /session/start` · `GET /session/{id}` · `POST /session/{id}/screenshot`
· `GET /session/{id}/screenshot.png` · `POST /session/{id}/action` · `POST /session/{id}/test-endpoint`
· `POST /session/{id}/findings` · `DELETE /session/{id}` · `GET /sessions`

**Target credentials and principals**: `GET|POST /targets/{id}/credential-profiles` ·
`PATCH|DELETE /targets/{id}/credential-profiles/{profile_id}` ·
`POST /targets/{id}/credential-profiles/{profile_id}/rotate` · `GET|POST /targets/{id}/principals` ·
`PATCH|DELETE /targets/{id}/principals/{principal_id}` · `GET|POST /targets/{id}/principal-matrix`.
Credential profile responses expose only a masked preview, storage/expiry state, and metadata; secret
material is write-only. Profiles support exact Authorization-header values and cookie strings,
expiry warnings, explicit rotation, and soft deactivation. Active, unexpired profiles referenced by
active `user1`/`user2` principals resolve server-side into normal and Continuous ASM scan jobs;
explicit per-scan auth fields retain precedence, and undecryptable/expired profiles fail closed.

**Discovery & exposure**: `POST|GET /discovery` · `GET /discovery/{id}` · `GET /dashboard` ·
`GET /exposure/graph` · `GET /exposure/nodes` · `GET /exposure/assets` · `GET /exposure/changes` ·
`GET /exposure/attack-paths`

**Schedules**: `GET|POST /schedules` · `GET|PATCH|DELETE /schedules/{id}`

**Workers, queue, gungnir, results**: `GET|POST /workers` · `GET /queue/stats` · `DELETE /queue/clear`
· `GET /gungnir/status` · `POST /gungnir/start` · `POST /gungnir/stop` · `GET /results` ·
`GET /results/{folder}/latest`

---

## 14. Configuration and integrated tools

**Key environment variables** (`.env`):

- AI analysis: `AI_URL`, `AI_API_KEY`, `AI_MODEL`, `AI_FALLBACK_MODEL`.
- AI retest verification: `AI_VERIFY_ENABLED`, `AI_VERIFY_URL`, `AI_VERIFY_API_KEY`,
  `AI_VERIFY_MODEL`, `AI_VERIFY_USE_BROWSER`, `AI_VERIFY_MAX_PER_SCAN`, `AI_VERIFY_MIN_SEVERITY`.
- AI Ops Router execution gate: `AI_OPS_ROUTER_EXECUTE_ENABLED`.
- AI Gate transcripts: `AI_GATE_TRANSCRIPT_RETENTION_DAYS` (retention label, default 30);
  `AI_TRANSCRIPT_ALLOW_SENSITIVE` (default off — when on, `GET /ai/scans/{id}/transcript?include_sensitive=true` returns raw, audit-logged bodies; otherwise responses are redacted at response time).
- Credential encryption-at-rest: `AI_CREDENTIAL_ENC_KEY` (a Fernet key; when set, AI-target and DAST
  target-profile credential secrets are encrypted at rest with an `enc:fernet:` prefix; unset =
  plaintext, backward compatible). Profile responses report whether their stored value is encrypted.
- Allocation fallback: `COVERAGE_ALLOCATION_DEFAULT`. Shard ceilings: `SHAKERSCAN_MAX_SHARDS`,
  `SHAKERSCAN_COVERAGE_MAX_SHARDS`, `PARALLEL_SHARD_MAX_PER_PARENT`, etc.
- Custom dictionaries: `SHAKERSCAN_CUSTOM_WORDLIST`, `SHAKERSCAN_CUSTOM_<CAT>_PAYLOADS`.
- Deployment/binding: `SHAKERSCAN_BIND_HOST`, `SHAKERSCAN_PUBLIC_HOST`, `SHAKERSCAN_REMOTE`.

**Integrated external tools**: `httpx` (HTTP probing), `katana` (crawling), `nuclei` (templates),
`dalfox` (XSS), `sqlmap` (SQLi), `subfinder` (passive subdomains), `gungnir` (CT logs), `sslyze` +
`testssl.sh` (TLS), `nmap` (ports), and Playwright (browser). Subprocess execution is concurrency-
limited with per-tool timeouts and a global deadline.

---

## 15. Safety model

- **Authorization**: only scan targets you own or are explicitly authorized to test. `full`,
  `aggressive`, and `smart` send active probes; AI Gate production scans and ASM BOLA require explicit
  confirmation.
- **Bounded automation**: passive recon and ASM new-surface tracking can be safe-on by default;
  active exploitation uses small safe batches and requires an explicit Lab/deep policy for deep
  exploit mode. Rate tokens are reserved before active work is queued.
- **Coverage honesty**: an endpoint is only counted `tested` when scanner telemetry proves it was
  attempted/completed; timeouts/partials never inflate coverage.
- **Local binding**: laptop mode binds to `127.0.0.1`; remote mode binds to a Tailscale IP. Exposing
  on `0.0.0.0` is only safe behind a firewall/VPN/reverse proxy.
- **AI redaction and credential handling**: sensitive headers/bodies and secret-bearing URL
  params/metadata are redacted
  before any content is sent to an AI provider, via the shared `redact_sensitive()` helper (R2a).
  AI-target and target-profile credential secrets can be encrypted at rest, opt-in via
  `AI_CREDENTIAL_ENC_KEY` (R2b), and
  transcript responses are redacted at response time by default (R3). Normal DAST worker launches pass
  auth material through a short-lived `0600` auth-config file rather than raw scanner subprocess argv,
  and scan-time AI provider keys are supplied through the child environment instead of `--ai-api-key`.

---

## 16. Where to go deeper

| Topic | Document |
|-------|----------|
| Agent-facing API how-to (request bodies, examples) | [`CLAUDE.md`](../CLAUDE.md) · [`AGENTS.md`](../AGENTS.md) |
| Getting started, install, product tour | [`README.md`](../README.md) |
| Smart scan internals (phase-by-phase) | [`smart.md`](../smart.md) |
| Smart scan budgets, SLOs, release gates | [`SMART_SCAN_POLICY.md`](SMART_SCAN_POLICY.md) |
| OWASP coverage and intentional gaps | [`owasp-coverage-matrix.md`](owasp-coverage-matrix.md) |
| AI red teaming + model intake (engineering onboarding) | [`AI_REDTEAM_AND_MODEL_INTAKE.md`](AI_REDTEAM_AND_MODEL_INTAKE.md) |
| Current product hardening roadmap | [`proposed-next-steps.md`](proposed-next-steps.md) |
| Historical AI red teaming + model intake fix ledger | [`archive/ai-redteam-model-intake-fix-plan-2026-06.md`](archive/ai-redteam-model-intake-fix-plan-2026-06.md) |
| AI test workflows + Honey contract | [`AI_TEST_WORKFLOWS.md`](AI_TEST_WORKFLOWS.md) |
| Interactive AI security sessions | [`INTERACTIVE_SESSIONS_GUIDE.md`](INTERACTIVE_SESSIONS_GUIDE.md) |
| Parallel scan architecture | [`parallel-scan-architecture.md`](parallel-scan-architecture.md) |
| Continuous ASM architecture | [`continuous-asm-architecture.md`](continuous-asm-architecture.md) |
| Multi-node fleet architecture (RFC) | [`multi-node-architecture.md`](multi-node-architecture.md) |

> Reminder: where any doc and the code disagree, the **code, DB schema, and tests win**. This
> reference is a map, not the territory.
