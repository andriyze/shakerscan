# ShakerScan Functionality Reference — DAST + AI Red Teaming

**Status:** Canonical exhaustive functional reference for the whole product. This is the "what can
ShakerScan actually do" map across DAST, attack-surface management, AI security, evidence,
governance, automation, UI, CLI, API, and agent-facing surfaces. The human-readable sections explain
the behavior; the generated inventory in §17 enumerates every current public route, registry command,
CLI flag, wrapper command, Make target, release gate, runtime configuration key, UI page, skill,
agent, adapter, scanner module, and durable table.
**Reconciled:** 2026-07-28
**Audience:** users, operators, AI coding agents, and engineers who need one place that explains the
product's functionality end to end.

> **Source of truth.** This document describes shipped behavior, grounded in the code at the time of
> writing. As with the sibling architecture docs, **the code, DB schema, and tests remain
> authoritative** — file paths drift, so this reference prefers named files/symbols over line numbers.
> Verify before depending on a detail. For implementation-depth and roadmap material, follow the
> cross-links in [§18](#18-where-to-go-deeper).

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
16. [UI, CLI, skills, and agent surfaces](#16-ui-cli-skills-and-agent-surfaces)
17. [Generated capability inventory](#17-generated-capability-inventory)
18. [Where to go deeper](#18-where-to-go-deeper)

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
`sqli_extract_max`, `oob_max_findings`, `active_worklist_max`, `request_max`,
`param_discovery_url_limit`, `param_discovery_max_params`, and `phase4_max_seconds`.

The **smart** scan applies its own adaptive budget matrix (`SMART_SCAN_BUDGETS`) and supports
`no_early_stop` + `thorough_params` shortcuts. See
[`docs/SMART_SCAN_POLICY.md`](SMART_SCAN_POLICY.md) for the current operator policy. Superseded
phase-by-phase implementation notes remain available in Git history and are not a current
source-location map.

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

**Historical and source-assisted discovery**: OpenAPI/Swagger schema discovery uses prioritized,
bounded concurrent probes under one global deadline and reuses the result across later active phases;
explicit schemas can also be exercised through Schemathesis. Wayback/Common Crawl/GAU helpers;
JavaScript and browser-derived API bases; GraphQL schema
recovery; gRPC reflection; virtual hosts; custom endpoint files, focus/avoid rules, and agent-produced
`custom_endpoints`/`custom_list` seeds.

**Threat intelligence and external posture**: opt-in DNSBL, AbuseIPDB, and VirusTotal IP reputation;
typosquatting/lookalike-domain generation and resolution; WHOIS/RDAP domain age, expiry, and registrar
analysis; certificate-transparency posture; ASN/hosting-provider/prefix/geography/multihoming facts;
HIBP/GitHub-oriented breach and credential-leak checks; and third-party resource/vendor risk.

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

Opt-in infrastructure families also cover SSH authentication posture; SMTP STARTTLS, banner, MX, and
safe open-relay checks; VPN, RDP/VNC, IoT, industrial-protocol, and database-service exposure; IP/ASN
and domain intelligence; third-party vendor resources; webhook signature bypass; package-manager and
backup artifacts; container registries; and Kubernetes/Terraform/cloud-storage exposure.

OpenAPI schemas can be supplied explicitly or discovered and exercised through Schemathesis. The
scanner records schema/test errors as evidence rather than treating process exit as proof.

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

Principal and benchmark receipts distinguish configured contexts, redacted identity fingerprints,
server-observed accepted authentication, family attempts, and cross-principal proof. A verified
BOLA result requires distinct accepted principals and a deterministic owner/attacker differential;
two configured or merely attempted lanes do not satisfy that gate.

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

**Compliance mapping** (`compliance_mapper.py`): OWASP Top 10, CWE, PCI DSS, SOC 2, HIPAA, GDPR, CIS
Controls, control evidence requirements, business impact, remediation priority, and a GRC evidence
matrix. These are evidence mappings, not certification claims.

**Rich result object** (`result.*`): `http.csp_evaluation`, `http.security_headers`,
`tls.certificate`, `tls.ocsp`, `dns`, `discovery.tech.items`, `discovery.browser_api_endpoints`,
`discovery.browser_crawl`, `discovery.waf_detection`, `attack_chains`, `smart_coverage`, and — when AI
is enabled — `ai_correlations` and `ai_logs.summary.cross_finding_correlations`. SARIF 2.1 output,
fingerprinted baselines, known-finding suppression, and severity-count quality gates are available
through the scanner CLI; the UI offers PDF export.

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

Current execution design: [`docs/dast-asm-architecture.md`](dast-asm-architecture.md).

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
  vs. wait from current gaps. Focused families: `sqli`, `xss`, credential-gated `auth` (requires a
  primary auth context), and gated `bola` (requires `exploit_depth: true` plus primary and
  second-user auth). Planned families (`ssrf`, `lfi`, `rce`, `business_logic`) are registered but
  rejected for ASM execution until their scanner integrations ship.
- `GET /targets/{id}/asm/activity` is the read-only operator summary for one target: recent hidden ASM
  recon/test jobs, the scheduler decision, campaign timeline events, active ASM scans, and a bounded
  target-scoped hypothesis situation report. The embedded hypothesis report surfaces proof leads and
  missing preconditions next to coverage state, but it does not queue work, create findings, or change
  proof state.

Current execution design: [`docs/dast-asm-architecture.md`](dast-asm-architecture.md).

**Multi-node boundary:** the first owned-fleet trust foundation is implemented: durable node identity,
hashed usage-bounded join tokens (single-use by default), HTTPS enrollment, authenticated heartbeat, one-time overlay connection
bundles, and credential rotation/revocation. A digest-pinned worker/agent-only Compose runtime and
pull-based local node-agent now apply versioned worker-count/drain desired state without an inbound
listener or remote Docker API. The opt-in fleet Compose profile adds a CA-verified HTTPS listener on
the private data address, preserves the real overlay socket peer with Linux host networking, and
disables duplicate background controllers in that edge process. Linux host automation now implements
persistent `fleet init`, aggregated read-only `fleet preflight`, tag-to-digest image resolution,
automatic pre-conversion backup, bounded/revocable `fleet join-token`, automatic/manual peer reconciliation,
automatic restricted public HTTPS for broker fleets with pinned Caddy, certificate renewal and
secret-bound proxy trust, minimal public health, protected-route/rollback verification, bounded
enrollment attempts, and worker-only `join` with HTTPS preflight and WireGuard handshake
diagnostics. The installed worker image is derived automatically; `--worker-image` selects a custom
build. Fleet is host-aware and opt-in: standalone installs hide Fleet navigation, remote capacity,
and remote placement; direct macOS visits explain the Linux requirement, while uninitialized Linux
visits show setup guidance. `GET /health` and `GET /workers` expose the same non-secret capability
state. The enabled Fleet UI also flags WireGuard nodes awaiting their first connection. Leased delivery and
fencing, central artifact transfer, placement, capacity-weighted scaling, rolling lifecycle,
outbound-only HTTPS broker transport, and fleet-wide
admission/request controls are implemented. The remaining release-topology gate is executing the
physical two-VPS acceptance. Follow the [operator guide](multi-node-guide.md); the design authority is
[`docs/multi-node-architecture.md`](multi-node-architecture.md).

---

## 10. Attack-surface management: discovery, CT monitoring, schedules

**Subdomain discovery** (`POST /discovery`, `process_discovery_job`): enumerates subdomains for a root
domain via Gungnir, Subfinder, and crt.sh, then upserts discovered hosts as targets.

**Certificate Transparency monitoring (Gungnir)** (`api/gungnir_worker.py`): a long-running worker
that watches CT logs in real time, discovering new certificates for monitored domains. New subdomains
are auto-added as targets (`discovery_source = gungnir-monitor`); if the root domain has ASM enabled,
discovered surface inherits the ASM policy. Controlled via `./scanner.sh gungnir start|stop|status`
and `/gungnir/*` endpoints.

**Schedules** (`schedule_runner`, `/schedules`): recurring daily/weekly actions with timezone and
jitter support. New schedules support normal scans and bounded `asm_improve` coverage waves.
Legacy `evidence_retention_sweep` records remain readable for migration but are automatically
disabled and cannot be created or resumed. Interactive deletion requires a fresh immutable preview
and an exact-action, target-matching approval created through the interactive flow.
Schedule listings include derived `schedule_health` when recent scan results
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
below); AI is never the sole authority for verified status or severity promotion. Operator workflows
are in [`AI_TEST_WORKFLOWS.md`](AI_TEST_WORKFLOWS.md), and future hardening belongs only in
[`proposed-next-steps.md`](proposed-next-steps.md).

### AI capability status quick read

These implemented components were last reconciled against code on 2026-07-21. AI Gate and Model
Intake remain preview product surfaces for 0.7.0. Their deterministic PR smoke matrix is implemented,
but the policy/exception and deterministic-judge seams marked Planned in
[`E2E_TEST_PLAN.md`](E2E_TEST_PLAN.md) are not yet release-gated. "Partial" means the capability runs
but the listed caveat applies — treat the caveat as load-bearing, not cosmetic.

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
| AI surface inventory and attempt ledger | Shipped | Stored surface/attempt facts are separate from findings and do not imply proof. |
| AI campaign replay and longitudinal history | Shipped | Supports selected probe/family/error/skipped reruns; replay remains budgeted and production-gated. |
| Model Intake saved trust anchors | Shipped | Write-managed public keys/fingerprints; inactive anchors do not satisfy strict policy. |
| Model Intake evidence export | Shipped | Content-free/hashed export contracts preserve provenance and redaction boundaries. |

### AI proof and evidence states

Today a finding exposes a three-state proof level — `verified` (deterministic proof), `suspected`, or
`unverified` (`api/api.py`), with `proof_state` `exploited` / `likely_vulnerable` at the scanner — and
deterministic proof blocks any AI downgrade. The **target** is one taxonomy unified across DAST and AI
(`deterministic_verified`, `cryptographically_verified`, `claimed_present`, `ai_judged_likely`,
`inconclusive`, `blocked`, `false_positive`) so that *claimed* metadata and *AI-judged* results can
never render as *verified*. Future proof-state hardening is tracked in
[`proposed-next-steps.md`](proposed-next-steps.md).

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

Model Intake (`scanner/scanner_tools/model_intake.py`) is a provider-neutral model admission pipeline.
It resolves and completely acquires immutable subjects, creates content-addressed quarantine objects and
repository manifests, runs generated static evidence, optionally invokes a separate no-egress semantic
sandbox and content-free embedding/data-plane evaluation, and emits a signed, revocable decision package.
It never imports publisher model code in the API or worker process. A purpose-built isolated runtime image
is still required when a model-specific approval procedure requires actual custom-code load/inference.

> **Signature/provenance (R1, shipped 2026-06-24).** Model Intake performs real detached-signature
> verification (Ed25519 / RSA-PSS / ECDSA via the `cryptography` lib) over the artifact or its digest
> when a public key + signature are supplied (`signature_public_key`/`_url`, `signature_value`/
> `signature_url`); `require_cryptographic_signature_verification` makes a metadata-only claim fail.
> Metadata booleans such as `sigstore_verified: true` are treated as **claims**, never as cryptographic
> proof. Offline DSSE/in-toto subject verification is supported. A policy requiring transparency evidence
> fails closed unless an independently trusted transparency verifier/bundle is available.

Checks include:
- **Unsafe serialization** — flags pickle-like formats (`.pkl`, `.pickle`, `.joblib`, `.pt`, `.pth`,
  `.ckpt`, `.bin`, `.mar`) vs. safer ones (`.safetensors`, `.onnx`, `.tflite`, `.gguf`); scans for
  pickle opcode markers and suspicious loader markers (`os.system`, `subprocess`, `eval`/`exec`,
  `pickle.loads`, network downloaders, base64 decode).
- **Archive payload analysis** — recursively inspects ZIP and TAR families without extraction, enforcing
  entry/depth/expanded-size/ratio bounds and rejecting traversal, links, devices, collisions, nested unsafe
  serialization, and executables.
- **Provenance & integrity** — checksum (`sha256`) verification; signature/attestation **presence**;
  **claimed** signature/provenance metadata; **cryptographic** detached-signature verification
  (Ed25519/RSA-PSS/ECDSA via the `cryptography` lib, over the artifact or its digest); Hugging Face
  reference normalization.
- **Generated evidence** — normalized fail-closed adapters for model/pickle scanners, Python AST, secrets,
  malware, CycloneDX SBOM/SCA, native binaries, licenses, plus explicit tool/rules/version/coverage status.
- **Model/application evaluation** — computes retrieval quality, vector integrity, poisoning, ACL/tenant and
  sensitive-data leakage, stability, capacity, graph boundaries, deletion receipts, cache context, and
  index/model digest compatibility without persisting source text or benchmark vectors.
- **Admission lifecycle** — signs the complete decision, registers it durably, enforces exact subjects at
  deployment, and supports expiry, supersession, reassessment triggers, revocation, and audit history.

Saved trust anchors can be created, updated/deactivated, selected by policy, and previewed before a
scan. `POST /model-intake/resolve` normalizes HTTP, Hugging Face, S3, GCS, Azure, OCI, and MLflow
references. OCI/MLflow use an operator gateway or signed HTTPS export bound to the exact provider subject
and expected digest, so provider credentials never enter scanner output. Completed scans expose a
content-free evidence export and durable admission lifecycle APIs.

Result shape: `model_intake.checks.*`, `aibom`, `supply_chain`, `summary` (with the `decision`), and
`artifact`. Findings are stored with `tool = model_intake` and filter independently through
`source_type=model_intake`; they are excluded from `source_type=dast`. Sensitive URL params and
metadata keys are redacted.

### 11.3 Interactive Testing

`api/session_manager.py` plus `/session/*` endpoints provide collaborative, interactive testing in a
headless browser. You start a session, drive browser actions (`navigate`, `click`, `fill`, `register`,
`login`, `submit`, `wait`, `extract`), maintain **separate per-user contexts** (e.g. user1/user2),
capture screenshots, and test endpoints for cross-user access (`test-endpoint` with `as_user`).
Endpoint tests that name a user require that user to exist and be authenticated in the session; authz
replay automation also requires at least two authenticated principals before it can make a
cross-principal claim.
Validated findings are saved via `POST /session/{id}/findings` (the compatibility source value is
`ai_session`; the user-facing source label is **Interactive**). This is the engine behind the
`/ai-security-session` compatibility skill; see
[`docs/INTERACTIVE_SESSIONS_GUIDE.md`](INTERACTIVE_SESSIONS_GUIDE.md).

### 11.4 AI-assisted analysis of DAST findings

When an AI provider is configured (`AI_URL` / `AI_API_KEY` / `AI_MODEL`), ShakerScan adds
cross-finding correlation and an overall risk assessment to DAST reports, and can run AI-driven retest
verification of findings (`AI_VERIFY_*`). The AI retest tier generates an exploitation plan and
replays it (optionally via a browser), and can downgrade false positives — but deterministic proof of
exploitation blocks any downgrade.

### 11.5 AI Operations Router

`POST /ai/ops/route` maps natural-language DAST/ASM requests to concrete API calls with **dry-run
defaults**. It recognizes unqualified scans (Quick by default), all six exact DAST scan types,
"run full coverage", "keep this target covered" (enable ASM with a safe preset), "what is still
untested?" (ASM gaps), "spend more budget on APIs", and focused SQLi/XSS/BOLA requests. Active,
state-changing, or budget-increasing intents stay dry-run unless
`execute=true` and the explicit confirmations are all present. Standard installs enable the server
execution gate; `AI_OPS_ROUTER_EXECUTE_ENABLED=false` disables all gated execution globally. BOLA
additionally requires primary + second-user auth context. Ambiguous language never upgrades a
Safe/Balanced plan to Lab.
The UI binds execution confirmation to the exact prompt and target that produced the visible preview;
editing either input invalidates the preview and clears its confirmations.

### 11.6 Deep Hunt

Deep Hunt is the canonical AI-driven web-investigation workflow. The current Codex, Claude, or
OpenCode session plans turns through the keyless `POST /agent/hunt/{target_id}/session` and
`POST /agent/hunt/session/{run_id}/reply` loop; ShakerScan alone executes tools. Starting with
`mode: deep_hunt` requires a live, target-bound, expiring credential-tier approval. Gated execution
is enabled in standard installs and can be disabled globally with
`AI_OPS_ROUTER_EXECUTE_ENABLED=false`. The approval is revalidated before every turn.

The free-form loop can issue same-origin read probes, compare managed principal contexts when they
are configured, query stored knowledge, record notes, and invoke bounded active scanner templates. It cannot issue
arbitrary state-changing HTTP. Tool calls, request units, active actions, and turns are bounded. A
request unit is one tool invocation, not one wire request — a bounded scanner may issue many target
requests within a single unit. Model-token budgets bound the configured-provider loop only; a keyless
session uses its token budget to size the seed context pack, because the server cannot meter an
external coding agent's tokens. A debrief can persist only evidence-backed **Suspected** findings;
supported families reach **Verified** only through server-run deterministic proof. The compatibility `/research/*`
controller remains available for specialized guided verification and is not the Deep Hunt launcher.

Natural-language routing treats an unqualified “scan” as Quick DAST, named scan types as DAST,
“Deep Hunt” as this workflow, “verify this finding” as deterministic retest/verification, and manual
browser work as Interactive Testing. See [`product-model.md`](product-model.md).

### 11.7 Test scenario catalog and Honey demo

`GET /ai/test-scenarios` returns ready-made templates — notably `secure-rag-agent` (canonical Honey
RAG/agent/MCP endpoints with full control metadata) and `model-intake-pipeline` (safe/unsafe-pickle/
missing-signature/missing-approval model presets). Probe/test-case metadata is exportable to
`promptfoo`, `pyrit`, and `garak` formats (`/ai/test-cases/export`). See
[`docs/AI_TEST_WORKFLOWS.md`](AI_TEST_WORKFLOWS.md).

### 11.8 AI surface inventory, histories, replay, and evidence

`/ai/surfaces/*` persists normalized AI surfaces and attempt facts independently of findings.
AI-target and AI-scan campaign-history endpoints expose longitudinal decision, coverage, blocked,
errored, and readiness-trend context; target history also has an export endpoint. Scan replay can
rerun all probes or bounded slices selected by probe ID/family/error/skipped state while preserving
the original target context and safety gates. Transcript reads support redacted default output and
audited sensitive access only when the server policy allows it.

---

## 12. Cross-cutting: findings, exposure graph, workers, queue

**Findings lifecycle**: every DAST, Deep Hunt, Interactive, AI Gate, ASM, manual, and model-intake
result lands in one
`findings` table, de-duplicated by `(target_id, fingerprint)`. Findings have a status
(`active` / `resolved` / `false_positive` / `accepted_risk`), CVSS, CWE/OWASP tags, evidence,
optional AI verdict fields, and verification history. The UI exposes DAST, Deep Hunt, Interactive,
AI Gate, Model Intake, ASM, and Manual filters. The API `source_type` filter accepts the canonical
`deep_hunt` value plus compatibility values:
`dast`, `ai`, `ai_gate`, `ai_session`, `autonomous`, `deep_hunt`, `model_intake`, `asm`, `manual`.
Scanner findings driven by a hunt are included in `deep_hunt` and excluded from `dast`, so one row
does not present two competing sources. `model_intake` and the AI sources also filter separately
from `dast` (R8).
Findings support filtering, sorting, bulk update/cleanup, manual creation, and per-finding retest.

**Evidence objects**: finding evidence is indexed by hash, storage URI, retention class, scan/finding
links, and redaction profile. Large evidence can live in local content-addressed storage or an opt-in
S3/MinIO-compatible backend; evidence reads verify SHA-256 before returning remote or local content.
Retention sweeps are target-scoped and dry-run by default. A preview persists the exact candidate
snapshot, criteria, storage effects, policy hash, and expiry in PostgreSQL and cannot be altered at
execution time. The preview TTL defaults to 600 seconds; `EVIDENCE_RETENTION_PREVIEW_TTL_SECONDS`
is clamped to 60-3600 seconds.

Deletion requires a target-scoped, one-use `dangerous` approval whose `action_name` is exactly
`evidence.retention_sweep` and whose canonical action context is exactly `preview_id`,
`preview_hash`, and `target_id` from that preview. The approval must expire no later than the
preview. The execution body contains only `dry_run:false`, `preview_id`, and
`approval_receipt_id`; resubmitted target, age, class, limit, or storage-deletion criteria are
rejected.

Execution locks and revalidates the immutable rows, storage-reference effects, and finding/scan
ownership, then commits durable `executing` intent and per-object pending markers before external
blob deletion. A retry with the same preview and approval resumes unfinished work, treats an
already-missing content-addressed blob as completed, and finalizes the persisted intent. Once the
preview is consumed, the same retry returns the stored result idempotently instead of repeating
side effects. Legal hold and evidence attached to active findings are never candidates. Local or
remote blob failures preserve their database rows, and drift or a reused/mismatched approval fails
closed.

**Evidence instances and exports**: proof instances bind a concrete route/object/payload/principal
pair to evidence objects, tool receipts, campaign actions, proof state, and retention policy. APIs
list/record instances, export content-free manifests or bounded bundles, verify object hashes on
read, and record export events. Retention classes are `short`, `standard`, `audit`, `legal_hold`, and
`sensitive`; legal hold is never swept.

**Mission campaigns and action ledger**: campaigns are durable operating wrappers over Continuous
ASM, authenticated DAST, API authorization, AI red-team, Model Intake, benchmark, and retest work.
Campaign actions retain plan/command/scope/approval/evidence/hypothesis/tool-receipt links and
explicit execution state. The cross-product `/timeline` merges actions, scans, evidence, exports,
refuter reviews, and upcoming schedules.
Campaign list/detail reads compute current finding impact across every linked action in one live
rollup. The displayed critical/high blocker count is explicitly a default-policy estimate, not the
authoritative per-scan deployment decision.

**Batch scan submission**: `POST /scans/batch` accepts 1-50 targets, de-duplicates them, and returns
accepted jobs plus per-target failures. Partial queueing is explicit (`status: partial`) rather than
being reported as all-or-nothing success.

**Hypothesis lifecycle**: source/spec hints, operation plans, benchmark artifacts, scanner signals,
and application-graph producer/object/consumer facts can create source-only hypotheses. Hypotheses
support dedupe, optimistic versions, leased claims, endorsements/refutations, signals, next-test
planning, situation reports, and campaign linkage. Only exact existing deterministic finding proof
can reconcile a hypothesis into the canonical finding path.

**Refuter reviews**: durable support/question/weaken/refute signals challenge weak or high-impact
claims. Summary, queue, execution, and verdict derivation APIs delegate to existing gated replay or
retest primitives. Signal-only, failed, error, and AI-only results cannot create proof-backed verdicts.

**Scope, approval, context, and decision contracts**: scope previews create bounded receipts;
approval/denial receipts bind confirmations and expiry to that scope. Operation plans, command
results, agent context packs, agent decision traces, tool receipts, evidence instances, and campaign
actions are versioned/redacted audit records. Local-agent planning remains dry-run and parser-
validated; it has no raw-shell command or direct finding authority.

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

Base URL `http://localhost:8080`. Most structured POST/PATCH operations accept JSON, while some
control and discovery operations use query parameters or no body. FastAPI also serves the live schema
at `/openapi.json`. The curated groups below explain product areas; §17 is the exhaustive generated
method/path catalog. (See `api/api.py` for handlers. The agent-facing
how-to with request bodies is in [`CLAUDE.md`](../CLAUDE.md) / [`AGENTS.md`](../AGENTS.md).)

**Health & settings**: `GET /` · `GET /health` · `GET|PUT /settings/ai` · `POST /settings/ai/test` ·
`GET|PUT /settings/scan-execution` · `GET|PUT /settings/automation`

**Multi-node fleet**: `POST|DELETE /fleet/join-tokens[/{token_id}]` · `POST /fleet/nodes/join` ·
`GET /fleet/nodes` · `POST /fleet/scale` · `GET|PATCH /fleet/nodes/{id}/state` ·
`GET /fleet/nodes/{id}/activity` · `GET /fleet/nodes/{id}/events` · `POST /fleet/nodes/{id}/heartbeat` ·
`POST /fleet/nodes/{id}/connection-bundle` · `POST /fleet/nodes/{id}/credentials/rotate` ·
`POST /fleet/nodes/{id}/revoke` · `/fleet/broker/*`. Join tokens and node credentials are returned once and stored only
as hashes. Enrollment returns the public fleet CA alongside one-time node identity material. Fleet
operator reads and lifecycle operations require either an actual loopback socket peer or the
high-entropy bearer generated by `fleet init`; a loopback host-port publish does not authenticate
Docker-network peers, and non-loopback operator traffic additionally requires HTTPS. Enrollment and
secret delivery require HTTPS, and connection bundles
also require the actual socket peer to be inside the configured overlay CIDR. Node state pulls and
heartbeats likewise reject plaintext transport so node bearer credentials are never sent over HTTP.
The worker-only Compose
WireGuard worker runtime requires a digest-pinned image and starts no UI, API, Redis, or Postgres. Its pull-based agent
uses owner-only local state, reconciles only node-labeled workers on the local Docker engine, and
reports applied state/capacity/errors. `scanner.sh fleet init`, `fleet join-token`, `fleet reconcile`,
and `scanner.sh join` provide the Linux host workflow with owner-only state, explicit system/private
CA trust, CA-verified overlay proof, one-time bundle persistence, and pinned-image startup. Broker
nodes receive no Redis, PostgreSQL, or object-store credentials and use outbound HTTPS only. On an
initialized Linux control plane, the Fleet UI manages capacity, drift, drain/resume, image rollout,
lifecycle events, and revocation. It stays hidden on standalone installs.
`shakerscan fleet accept` is implemented; its physical two-VPS release run remains pending.

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

**Bounded Research Agent**: `GET /research/readiness` · `POST /research/launch` ·
`POST|GET /research/episodes` · `GET /research/episodes/{id}` ·
`POST /research/episodes/{id}/plan-step` · `POST /research/episodes/{id}/decisions` ·
`POST /research/episodes/{id}/observe` · `POST /research/episodes/{id}/settle` ·
`POST /research/episodes/{id}/cancel`. An episode is a target-bound state machine over immutable,
redacted `ObservationPack` rows and exactly-one-action `DecisionEpisode` rows. Decisions are bound to
the current observation ID/hash, cannot carry receipts or credentials, must declare an expected
signal and falsifier, and consume bounded step/action/time/request/model-token budgets. The launch
API supplies server-owned target-hunt, exact-finding, and ASM-gap missions, deduplicates concurrent
one-click launches, and reserves a final synthesis step. The UI launches these missions from Finding
Detail, Continuous ASM, and registered web assets in Exposure as well as from the main Autonomous
Hunt page. Linked scans and finding retests must settle
before exactly one result-bearing observation is attached. No-progress duplicate actions are rejected
until a state-changing action occurs, and provider failures meter model usage before retry. Scan/ASM
request values are conservative reservation units rather than exact HTTP counts. Shadow mode
records decisions without dispatch. Read-only mode dispatches only the target-scoped inspection
allowlist. Gated mode can additionally dispatch `asm.improve`, `asm.recon`, `asm.test`,
`finding.retest`, `scan.focused_family`, `experiment.http_diff`, and `experiment.workflow` through the existing Arsenal gateway when a matching
scope/approval receipt and the global execution flag are present. Target IDs/URLs and receipts are
injected by the server. Research campaigns persist one of three planner modes. `agent` is the
clean-install default: the current Codex/Claude/OpenCode session reads the immutable observation and
submits one bounded decision without a stored provider. `configured_ai` uses AI settings and durable
server autopilot. `local_codex` uses the host-side
`./scanner.sh research <episode-id> [max-decisions]` with an isolated ephemeral Codex process and
fails fast when server autopilot is enabled for the episode, preventing two planners from racing the
same immutable observation. Pause server autopilot before invoking the local runner. The command
prints a compact decision/episode receipt and UI path instead of the full observation pack. A planner
cannot mint proof or findings. A trusted server-side workflow replay may create or refresh a finding
only after deterministic family proof and the promotion gate pass. Cancellation terminates the
episode, cancels linked queued retests and pending/running scans where possible, and reports
already-running retests as continuing rather than pretending they stopped.

`experiment.http_diff` is the first typed adaptive experiment actuator. It accepts two to four
anonymous control/mutation/verification requests using relative same-origin paths, JSON or form
bodies, bounded query/header mutations, and named scalar extraction from non-sensitive JSON paths
or response headers. Later steps may reference extracted resource values as `${name}`; every
rendered request is revalidated before dispatch. It forbids model-supplied credential/host headers
and redirects. Autonomous planner proposals are limited to `GET`, `HEAD`, and `OPTIONS`;
`experiment.http_diff` cannot receive cleanup-safe write authority because it has no restoration
contract. The manual typed-experiment surface retains the broader runtime method contract. Variable
references and extract names are preflighted across the complete experiment,
so undeclared, forward, duplicate, or over-budget variables fail before any request is sent. Query
and form values are constrained to bounded scalars. Responses are closed after a capped streaming
prefix, extracted values are persisted as hash/length metadata, and failed steps are marked
non-comparable instead of producing synthetic deltas. The result records status/body/JSON-shape,
selected JSON/header, timing, and before/after comparisons in a tool receipt plus an `unverified` evidence instance. The
research budget reserves four requests before dispatch. Experiment signals cannot directly create
or verify findings; a family-specific deterministic verifier must establish proof.

`experiment.workflow` extends the actuator with two to twelve typed HTTP/browser steps and
server-resolved principal slots (`anonymous`, `user1`, `user2`, `admin`, or `tenant:<id>`). It
supports before/mutation/after/action/cleanup/rollback checkpoints, same-origin navigation, click,
fill, submit, bounded wait, scalar extraction, and shared `${name}` resources. Credential profiles
are decrypted only in API memory and are never accepted in planner parameters. Cross-principal
workflows require distinct profile IDs and distinct verified account fingerprints before any target
or browser request. Results contain content-free principal/profile/role/tenant identity receipts,
bounded mixed HTTP/browser observations, comparisons, assertions, and restoration outcomes. A
caller-supplied workflow UUID allows cooperative cancellation through
`POST /experiments/workflows/{id}/cancel`; cancellation is checked between steps and browser contexts
always close in a `finally` block. Credential-tier Deep Hunt may receive `PUT`, `PATCH`, and `DELETE`
steps only through the typed workflow contract, with later cleanup/rollback and restoration
assertions. The server independently re-executes a promotable workflow, derives family predicates
from observed results, and may create or refresh a canonical finding only when deterministic family
proof and promotion gates pass. Create-based mass-assignment workflows may leave explicitly labeled
test objects when the discovered target has no delete route; this bounded exception is limited to
server-materialized create/read-back proof and is surfaced in the run outcome.

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
`POST /model-intake/targets/{id}/rescan` · `GET|POST /model-intake/trust-anchors` ·
`PATCH|DELETE /model-intake/trust-anchors/{id}` ·
`GET /model-intake/scans/{id}/evidence-export` · `GET /model-intake/capabilities` ·
`POST /model-intake/admission/verify` · `GET /model-intake/admissions` ·
`GET /model-intake/admissions/{id}` · `POST /model-intake/admissions/{id}/revoke` ·
`POST /model-intake/reassessment/events` · `POST /model-intake/retention/cleanup`

**Governance (deployment gate)**: `GET|POST /policy-profiles` · `PATCH|DELETE /policy-profiles/{id}` ·
`GET|POST /finding-exceptions` · `PATCH|DELETE /finding-exceptions/{id}` ·
`POST /finding-exceptions/lifecycle/sweep`

**Evidence and mission control**: `GET|POST /evidence/instances` · `GET /evidence/{id}` ·
`GET /evidence/export-manifest` · `GET /evidence/export-bundle` ·
`POST /evidence/retention/sweep` · `GET /timeline` · `GET|POST /arsenal/campaigns` ·
`GET /arsenal/campaigns/{id}` · `POST /arsenal/campaigns/{id}/actions` ·
`GET|POST /arsenal/tool-receipts`

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
- AI Ops Router execution gate: `AI_OPS_ROUTER_EXECUTE_ENABLED` (default on; set `false` for a global
  kill switch).
- Evidence-retention preview lifetime: `EVIDENCE_RETENTION_PREVIEW_TTL_SECONDS` (default 600
  seconds, clamped to 60-3600 seconds).
- AI Gate transcripts: `AI_GATE_TRANSCRIPT_RETENTION_DAYS` (retention label, default 30);
  `AI_TRANSCRIPT_ALLOW_SENSITIVE` (default off — when on, `GET /ai/scans/{id}/transcript?include_sensitive=true` returns raw, audit-logged bodies; otherwise responses are redacted at response time).
- Credential encryption-at-rest: `AI_CREDENTIAL_ENC_KEY` (a Fernet key; when set, AI-target and DAST
  target-profile credential secrets are encrypted at rest with an `enc:fernet:` prefix; unset =
  plaintext, backward compatible). Profile responses report whether their stored value is encrypted.
- Allocation fallback: `COVERAGE_ALLOCATION_DEFAULT`. Shard ceilings: `SHAKERSCAN_MAX_SHARDS`,
  `SHAKERSCAN_COVERAGE_MAX_SHARDS`, `PARALLEL_SHARD_MAX_PER_PARENT`, etc.
- Custom dictionaries: `SHAKERSCAN_CUSTOM_WORDLIST`, `SHAKERSCAN_CUSTOM_<CAT>_PAYLOADS`.
- Deployment/binding: `SHAKERSCAN_BIND_HOST` (UI/API), `SHAKERSCAN_DATA_BIND_HOST`
  (Redis/Postgres; loopback by default), `SHAKERSCAN_PUBLIC_HOST`, `SHAKERSCAN_REMOTE`.
- Data-store authentication: `REDIS_PASSWORD`, `POSTGRES_PASSWORD` (`shakerscan start` generates
  strong owner-only values when missing/weak and migrates the historical standalone Postgres
  default; Compose has no well-known password fallback).
- Owned-fleet bootstrap: `FLEET_OVERLAY_CIDR`, `FLEET_CONTROL_PLANE_OVERLAY_URL`,
  `FLEET_WIREGUARD_PUBLIC_KEY`, `FLEET_WIREGUARD_ENDPOINT`, digest-pinned
  `FLEET_WORKER_IMAGE_DIGEST`, generated `FLEET_OPERATOR_TOKEN`, and one-time
  `FLEET_CONNECTION_BUNDLE_JSON`. Insecure enrollment is disabled by default and its explicit test
  escape hatch works only from loopback.

**Integrated external tools**: `httpx` (HTTP probing), `katana` (crawling), `nuclei` (templates),
`ffuf`/`meg`/`dirb`/`gobuster` (content discovery), `dalfox`/XSStrike (XSS), `sqlmap`/commix
(injection), `subfinder`/Gungnir/dnsrecon (domain discovery), `tlsx`/SSLyze/testssl.sh/OpenSSL (TLS),
`nmap`/masscan/netcat (ports and services), `nikto`, `hydra`/`medusa`, `whois`, Shodan client support,
and Playwright (browser). The authoritative execution-facing adapter catalog is generated in §17;
an installed binary is not automatically a runnable ShakerScan adapter. Subprocess execution is
concurrency-limited with per-tool timeouts and a global deadline.

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

## 16. UI, CLI, skills, and agent surfaces

### Web UI routes

| Route | Operator capability |
|---|---|
| `/` | Security posture, prioritized action center, recent activity, and a compact operations header for queue state, emergency clear, worker scaling/freshness, and Gungnir CT |
| `/docs` | Safe in-app rendering of the installed README, including GitHub-flavored tables and code blocks |
| `/scan/new` | Scan type, parallel strategy, coverage budget, active options, auth, custom budget, and bounded batch submission with partial-failure receipts |
| `/scans` | Filter, inspect, cancel, and rescan logical scans without exposing internal rows by default |
| `/scans/{id}` | Live progress/logs, durable Model Intake activity, report, proof/coverage, deployment decision, AI/Model Intake panels, replay, history, and PDF |
| `/targets` | Hierarchical target inventory, search/filter/sort, scanning, discovery, duplicate merge, and schedule entry points |
| `/targets/{id}/graph` | Route/object/principal graph, producer/consumer/auth edges, and graph-derived hypotheses |
| `/asm` | Coverage, scheduler state, proof-family gaps, recommendations, endpoint inventory, inventory prune, and campaign timeline |
| `/timeline` | Cross-product mission feed of command results, scans, schedules, evidence bindings, refuters, and exports |
| `/campaigns` | Read-only mission campaign records with lifecycle status and live linked-finding impact |
| `/campaigns/{id}` | Campaign detail: live default-policy impact estimate, all-action status rollup, and the bounded action ledger |
| `/exposure` | Cross-product graph, asset inventory, deltas, and attack paths |
| `/findings` | Granular source/severity/status/domain/date filters, sorting, bulk triage, cleanup, and retest entry points |
| `/findings/{id}` | Evidence, raw request/response, proof/retest history, notes, status, deletion, and remediation |
| `/evidence` | Evidence-instance inventory, single-object inspection, content-free export manifests/bundles, and immutable-preview, exact-approval retention cleanup |
| `/interactive` | Browser sessions, credential profiles, principals, authorization expectations, endpoint replay, and manual findings |
| `/schedules` | Recurring normal scans and target-scoped ASM waves; evidence cleanup is interactive-only and legacy retention schedules are disabled |
| `/settings` | AI provider, scan execution, and automation policy settings |
| `/ai-gate` | AI target/principal lifecycle, inventory, readiness, probe packs, scans, longitudinal history, and durable AI surface inventory |
| `/settings/ai-ops-router` | Natural-language → safe API plan preview, with confirmation-gated execution |
| `/model-intake` | Reference resolution, trust preview/anchors, presets, policy selection, and intake submission |
| `/settings/policy-profiles` | Deployment policy profile lifecycle across DAST, AI Gate, and Model Intake |
| `/exceptions` | Finding-exception queue, repair, expiry visibility, and lifecycle sweep |
| `/settings/arsenal` | Command contracts, receipts, plans, actions, hypotheses (claim/signal/plan-campaign, from-plan/from-benchmark generators), refuters, tools, local agents, context packs, and traces |
| `/deep-hunt` | Launch and drive a keyless, AI-driven Deep Hunt through `/agent/hunt/*`: start/pause/resume/cancel hunt sessions, read the live transcript and observations, inspect run state and hunt-driven findings |
| `/deep-hunt/experiment` | Create bounded HTTP-differential or managed-principal workflow experiments |
| `/deep-hunt/runs/{id}` | Inspect a durable experiment run and its proof handoff |
| `/deep-hunt/leads` | Review durable research leads and route them to the appropriate product workflow |
| `/deep-hunt/operator`, `/deep-hunt/explorer` | Compatibility redirects to `/deep-hunt` (former split-page URLs) |

### API-only or partially UI-backed workflows

Not every public operation should have a dedicated screen. The following remain intentionally available
primarily to CI, agents, integrations, or advanced operators: raw result/result-folder reads; direct
evidence-instance/tool-receipt recording; read-only MCP over Arsenal execute; generic Arsenal execution;
local-agent output parsing; host-side Codex episode driving; and bulk finding retest/update/manual creation. §17 lists every operation so
this boundary is visible rather than accidental.

Several workflows that were previously API-only now have UI surfaces: the cross-product mission timeline
(`/timeline`), read-only mission campaign list/detail (`/campaigns`), evidence browsing plus content-free
manifest/bundle export and approval-gated retention sweeps (`/evidence`), the durable AI surface inventory
(inside `/ai-gate`), hypothesis claim/signal/plan-campaign and the from-plan/from-benchmark
generators (inside `/settings/arsenal`), the natural-language AI Operations Router (`/settings/ai-ops-router`),
and the one-click operational actions batch scan (`/scan/new`), target dedupe (`/targets`), queue emergency
clear (`/`), and ASM inventory prune (`/asm`).

### Scanner CLI

`scanner/scanner.py` supports direct quick/standard/deep/full/aggressive/smart execution, focused
XSS/SQLi/family modes, public-only collection, explicit endpoints/files/OpenAPI schemas, browser and
discovery controls, complete/threat-intel/exposure bundles, one- and two-user auth, OAuth and login
flows, custom dictionaries, OOB callbacks, coverage budgets, compliance output, SARIF, baselines,
quality gates, subdomain and Nuclei-only modes, tool health checks, and internal zero-rediscovery/
focused-child execution. Every current flag and help string is generated in §17.

`scanner.sh` is the operational wrapper for service lifecycle, health/doctor checks, scaling, logs,
builds, dependency installation, direct scan submission, agent/MCP launch, bounded host-side Codex
research-episode driving, Gungnir, environment
inspection, and container shells. The Make targets provide stable end-to-end and release-gate entry
points. Their complete current command names, release-gate names, and every explicit runtime
environment key referenced by Python or Compose are generated in §17; values are intentionally
never read into documentation.

### Skills, slash commands, and specialized agents

- `ai-security-session`: drives authorized interactive Playwright testing with explicit evidence and
  finding-save boundaries.
- `shakerscan`: routes general scans, targets, findings, Continuous ASM, AI Gate, Model Intake,
  operations, and bounded research while enforcing authorization and asynchronous handoff rules.
- `js-analyze`: converts bundles and browser evidence into routes, APIs, libraries, secret leads,
  `custom_endpoints`, and content-discovery seeds.
- `content-discovery`: builds generic and app-specific route/file/API lists and scanner/ffuf inputs.
- `research-agent`: creates or continues bounded research episodes and Deep Hunt campaigns with one
  policy-controlled decision per observation.
- `review-skills`: audits skills, commands, and subagents for broken references, unsafe prompts, and
  missing gates or output contracts.

The slash-command layer provides scan, smart/full scan, AI Gate, interactive session, finding list/
save, subdomain, worker, status, JS analysis, content discovery, bounded research, and skill-review
workflows. Three specialized Claude subagents back JS analysis, content discovery, and skill review.
The product also
catalogs Codex, Claude Code, OpenCode, and Hermes local-agent capabilities. The Codex research runner
can submit one schema-constrained decision at a time, but only the API policy controller can dispatch
an accepted Arsenal action; local-agent output never grants execution or finding authority.

---

## 17. Generated capability inventory

This appendix is generated directly from code and repository manifests. It is intentionally verbose:
it is the exhaustive backstop behind the human-readable product map above.

<!-- BEGIN GENERATED CAPABILITY INVENTORY -->

> **Generated source inventory.** Run `python3 scripts/generate_capability_inventory.py` after
> changing any inventoried surface. CI uses `--check`; do not edit this block manually.

### Inventory Summary

| Surface | Count | Source |
|---|---|---|
| Public REST operations | 264 | `api/api.py` FastAPI decorators |
| Unique REST paths | 221 | `api/api.py` |
| Check families | 14 | `api/check_registry.py` |
| Command Arsenal commands | 82 | `api/command_arsenal.py` |
| Tool adapters | 13 | `api/command_arsenal.py` |
| Local-agent adapters | 4 | `api/command_arsenal.py` |
| Scanner CLI flags | 158 | `scanner/scanner.py` |
| Scanner wrapper commands | 26 | `scanner.sh` |
| Make targets | 11 | `Makefile` |
| Release gates | 14 | `scripts/release_gates.py` |
| Runtime environment keys | 278 | Python sources + Compose manifests |
| Scanner modules | 92 | `scanner/scanner_tools/` |
| UI pages | 31 | `ui/src/app/` |
| Skills | 6 | `skills/` |
| Slash commands | 15 | `.claude/commands/` |
| Specialized subagents | 3 | `.claude/agents/` |
| Durable tables | 55 | `db/init.sql` + migrations |

### Public REST Operations

| Method | Path | Handler |
|---|---|---|
| `GET` | `/` | `root` |
| `GET` | `/agent/context/{target_id}` | `get_agent_context_pack` |
| `POST` | `/agent/findings/{finding_id}/verify` | `verify_suspected_agent_finding` |
| `GET` | `/agent/findings/{target_id}` | `get_agent_two_tier_findings` |
| `GET` | `/agent/hunt/runs` | `list_agent_hunt_runs` |
| `GET` | `/agent/hunt/session/{run_id}` | `get_agent_hunt_session` |
| `POST` | `/agent/hunt/session/{run_id}/cancel` | `cancel_agent_hunt_session` |
| `POST` | `/agent/hunt/session/{run_id}/reply` | `submit_agent_hunt_reply` |
| `POST` | `/agent/hunt/{target_id}` | `run_agent_hunt_endpoint` |
| `POST` | `/agent/hunt/{target_id}/session` | `start_agent_hunt_session` |
| `POST` | `/agent/tools/{target_id}/execute` | `execute_agent_tool_endpoint` |
| `GET` | `/agents/local` | `local_agents` |
| `POST` | `/agents/local/plan` | `local_agent_dry_run_plan` |
| `POST` | `/agents/local/plan/parse` | `local_agent_parse_candidate_plan` |
| `POST` | `/agents/local/test` | `local_agent_test` |
| `POST` | `/ai/demo/run` | `run_ai_honey_demo` |
| `POST` | `/ai/findings/{finding_id:path}/retest` | `retest_ai_finding` |
| `GET` | `/ai/inventory` | `get_ai_inventory` |
| `GET` | `/ai/learning-guide` | `get_ai_learning_guide` |
| `POST` | `/ai/ops/route` | `ai_ops_route` |
| `GET` | `/ai/scans/{scan_id}/campaign-history` | `get_ai_scan_campaign_history` |
| `POST` | `/ai/scans/{scan_id}/replay` | `replay_ai_scan` |
| `DELETE` | `/ai/scans/{scan_id}/transcript` | `purge_ai_scan_transcript` |
| `GET` | `/ai/scans/{scan_id}/transcript` | `get_ai_scan_transcript` |
| `GET` | `/ai/surfaces` | `list_ai_surfaces` |
| `POST` | `/ai/surfaces/sync` | `sync_ai_surfaces` |
| `GET` | `/ai/surfaces/{surface_id}/attempts` | `list_ai_surface_attempts` |
| `GET` | `/ai/targets` | `list_ai_targets` |
| `POST` | `/ai/targets` | `create_ai_target` |
| `DELETE` | `/ai/targets/{target_id}` | `delete_ai_target` |
| `PATCH` | `/ai/targets/{target_id}` | `update_ai_target` |
| `GET` | `/ai/targets/{target_id}/campaign-history` | `get_ai_target_campaign_history` |
| `GET` | `/ai/targets/{target_id}/campaign-history/export` | `get_ai_target_campaign_history_export` |
| `POST` | `/ai/targets/{target_id}/mcp/live-readiness` | `test_ai_target_mcp_live_readiness` |
| `GET` | `/ai/targets/{target_id}/principals` | `list_ai_target_principals` |
| `POST` | `/ai/targets/{target_id}/principals` | `create_ai_target_principal` |
| `DELETE` | `/ai/targets/{target_id}/principals/{principal_id}` | `delete_ai_target_principal` |
| `PATCH` | `/ai/targets/{target_id}/principals/{principal_id}` | `update_ai_target_principal` |
| `GET` | `/ai/targets/{target_id}/runtime-risk` | `get_ai_target_runtime_risk` |
| `POST` | `/ai/targets/{target_id}/scan` | `scan_ai_target` |
| `POST` | `/ai/targets/{target_id}/test` | `test_ai_target_connectivity` |
| `GET` | `/ai/test-cases` | `list_ai_test_cases` |
| `GET` | `/ai/test-cases/export` | `export_ai_test_cases` |
| `GET` | `/ai/test-scenarios` | `list_ai_test_scenarios` |
| `POST` | `/arsenal/approvals` | `arsenal_create_approval` |
| `GET` | `/arsenal/campaign-actions` | `arsenal_campaign_actions` |
| `POST` | `/arsenal/campaign-actions/{campaign_action_id}/authz-promote` | `arsenal_promote_authz_replay` |
| `POST` | `/arsenal/campaign-actions/{campaign_action_id}/authz-replay` | `arsenal_execute_authz_replay` |
| `GET` | `/arsenal/campaigns` | `arsenal_campaigns` |
| `POST` | `/arsenal/campaigns` | `arsenal_create_campaign` |
| `GET` | `/arsenal/campaigns/{campaign_id}` | `arsenal_campaign_detail` |
| `POST` | `/arsenal/campaigns/{campaign_id}/actions` | `arsenal_link_campaign_action` |
| `GET` | `/arsenal/command-results` | `arsenal_command_results` |
| `GET` | `/arsenal/commands` | `arsenal_commands` |
| `GET` | `/arsenal/context-packs` | `arsenal_agent_context_packs` |
| `POST` | `/arsenal/context-packs` | `arsenal_create_agent_context_pack` |
| `POST` | `/arsenal/context-packs/from-target` | `arsenal_create_agent_context_pack_from_target` |
| `GET` | `/arsenal/contracts` | `arsenal_contracts` |
| `GET` | `/arsenal/decision-traces` | `arsenal_agent_decision_traces` |
| `POST` | `/arsenal/decision-traces` | `arsenal_create_agent_decision_trace` |
| `POST` | `/arsenal/execute` | `arsenal_execute` |
| `GET` | `/arsenal/family-proof/contracts` | `arsenal_family_proof_contracts` |
| `POST` | `/arsenal/family-proof/evaluate` | `arsenal_family_proof_evaluate` |
| `GET` | `/arsenal/findings/{finding_id}/refuter-panel` | `arsenal_finding_refuter_panel` |
| `GET` | `/arsenal/hypotheses` | `arsenal_hypotheses` |
| `POST` | `/arsenal/hypotheses` | `arsenal_record_hypothesis` |
| `POST` | `/arsenal/hypotheses/from-benchmark` | `arsenal_generate_hypotheses_from_benchmark` |
| `POST` | `/arsenal/hypotheses/from-plan` | `arsenal_generate_hypotheses_from_plan` |
| `GET` | `/arsenal/hypotheses/schedule` | `arsenal_schedule_hypotheses` |
| `GET` | `/arsenal/hypotheses/situation-report` | `arsenal_hypothesis_situation_report` |
| `POST` | `/arsenal/hypotheses/source-ingest` | `arsenal_generate_hypotheses_from_source` |
| `POST` | `/arsenal/hypotheses/{hypothesis_id}/claim` | `arsenal_claim_hypothesis` |
| `POST` | `/arsenal/hypotheses/{hypothesis_id}/plan-campaign` | `arsenal_plan_hypothesis_campaign` |
| `POST` | `/arsenal/hypotheses/{hypothesis_id}/reconcile-proof` | `arsenal_reconcile_hypothesis_proof` |
| `POST` | `/arsenal/hypotheses/{hypothesis_id}/signals` | `arsenal_append_hypothesis_signal` |
| `POST` | `/arsenal/hypotheses/{hypothesis_id}/transition` | `arsenal_transition_hypothesis` |
| `GET` | `/arsenal/plans` | `arsenal_operation_plans` |
| `POST` | `/arsenal/plans` | `arsenal_create_operation_plan` |
| `GET` | `/arsenal/refuter-reviews` | `arsenal_refuter_reviews` |
| `POST` | `/arsenal/refuter-reviews` | `arsenal_record_refuter_review` |
| `POST` | `/arsenal/refuter-reviews/queue-from-summary` | `arsenal_queue_refuter_reviews_from_summary` |
| `GET` | `/arsenal/refuter-reviews/summary` | `arsenal_refuter_review_summary` |
| `POST` | `/arsenal/refuter-reviews/{refuter_review_id}/derive-verdict` | `arsenal_derive_refuter_review_verdict` |
| `POST` | `/arsenal/refuter-reviews/{refuter_review_id}/execute` | `arsenal_execute_refuter_review_plan` |
| `POST` | `/arsenal/scope/preview` | `arsenal_scope_preview` |
| `GET` | `/arsenal/tool-receipts` | `arsenal_tool_receipts` |
| `POST` | `/arsenal/tool-receipts` | `arsenal_record_tool_receipt` |
| `GET` | `/arsenal/tools` | `arsenal_tools` |
| `GET` | `/artifacts/storage/health` | `get_artifact_storage_health` |
| `GET` | `/asm/check-families` | `asm_check_families` |
| `GET` | `/dashboard` | `dashboard` |
| `GET` | `/discovery` | `list_discovery_runs` |
| `POST` | `/discovery` | `start_discovery` |
| `GET` | `/discovery/{discovery_id}` | `get_discovery` |
| `GET` | `/domains` | `list_domains` |
| `GET` | `/evidence/export-bundle` | `evidence_export_bundle` |
| `GET` | `/evidence/export-manifest` | `evidence_export_manifest` |
| `GET` | `/evidence/instances` | `list_evidence_instances` |
| `POST` | `/evidence/instances` | `record_evidence_instance` |
| `GET` | `/evidence/retention/executions` | `list_evidence_retention_executions` |
| `POST` | `/evidence/retention/sweep` | `evidence_retention_sweep` |
| `GET` | `/evidence/{evidence_id}` | `get_evidence_object` |
| `POST` | `/experiments/workflows/{workflow_id}/cancel` | `cancel_workflow_experiment` |
| `GET` | `/exposure/assets` | `exposure_assets` |
| `GET` | `/exposure/attack-paths` | `exposure_attack_paths` |
| `GET` | `/exposure/changes` | `exposure_changes` |
| `GET` | `/exposure/graph` | `exposure_graph` |
| `GET` | `/exposure/nodes` | `exposure_nodes` |
| `GET` | `/finding-exceptions` | `list_finding_exceptions` |
| `POST` | `/finding-exceptions` | `create_finding_exception` |
| `POST` | `/finding-exceptions/lifecycle/sweep` | `finding_exception_lifecycle_sweep` |
| `DELETE` | `/finding-exceptions/{exception_id}` | `delete_finding_exception` |
| `PATCH` | `/finding-exceptions/{exception_id}` | `update_finding_exception` |
| `GET` | `/findings` | `list_findings` |
| `POST` | `/findings/bulk` | `bulk_update_findings` |
| `POST` | `/findings/cleanup` | `cleanup_findings` |
| `POST` | `/findings/manual` | `create_manual_finding` |
| `POST` | `/findings/retest` | `bulk_retest_findings` |
| `DELETE` | `/findings/{finding_id:path}` | `delete_finding` |
| `GET` | `/findings/{finding_id:path}` | `get_finding` |
| `PATCH` | `/findings/{finding_id:path}` | `update_finding` |
| `POST` | `/findings/{finding_id:path}/retest` | `retest_finding` |
| `GET` | `/findings/{finding_id}/evidence` | `list_finding_evidence` |
| `POST` | `/fleet/acceptance/lease-probe` | `run_fleet_acceptance_lease_probe` |
| `POST` | `/fleet/broker/nodes/{node_id}/lease` | `lease_broker_job` |
| `PUT` | `/fleet/broker/nodes/{node_id}/leases/{lease_id}/artifacts` | `upload_broker_job_artifact` |
| `POST` | `/fleet/broker/nodes/{node_id}/leases/{lease_id}/heartbeat` | `heartbeat_broker_job` |
| `POST` | `/fleet/broker/nodes/{node_id}/leases/{lease_id}/result` | `submit_broker_job_result` |
| `POST` | `/fleet/join-tokens` | `create_fleet_join_token` |
| `DELETE` | `/fleet/join-tokens/{token_id}` | `revoke_fleet_join_token` |
| `GET` | `/fleet/nodes` | `list_fleet_nodes` |
| `POST` | `/fleet/nodes/join` | `join_fleet_node` |
| `GET` | `/fleet/nodes/{node_id}/activity` | `get_fleet_node_activity` |
| `POST` | `/fleet/nodes/{node_id}/connection-bundle` | `get_fleet_connection_bundle` |
| `POST` | `/fleet/nodes/{node_id}/credentials/rotate` | `rotate_fleet_node_credential` |
| `GET` | `/fleet/nodes/{node_id}/events` | `get_fleet_node_events` |
| `POST` | `/fleet/nodes/{node_id}/heartbeat` | `heartbeat_fleet_node` |
| `POST` | `/fleet/nodes/{node_id}/revoke` | `revoke_fleet_node` |
| `GET` | `/fleet/nodes/{node_id}/state` | `get_fleet_node_state` |
| `PATCH` | `/fleet/nodes/{node_id}/state` | `update_fleet_node_state` |
| `GET` | `/fleet/public-health` | `fleet_public_health` |
| `POST` | `/fleet/scale` | `scale_fleet_workers` |
| `POST` | `/gungnir/start` | `gungnir_start` |
| `GET` | `/gungnir/status` | `gungnir_status` |
| `POST` | `/gungnir/stop` | `gungnir_stop` |
| `GET` | `/health` | `health` |
| `POST` | `/model-intake/admission/verify` | `verify_model_intake_admission` |
| `GET` | `/model-intake/admissions` | `list_model_intake_admissions` |
| `GET` | `/model-intake/admissions/{admission_id}` | `get_model_intake_admission` |
| `POST` | `/model-intake/admissions/{admission_id}/revoke` | `revoke_model_intake_admission` |
| `GET` | `/model-intake/capabilities` | `model_intake_capabilities` |
| `POST` | `/model-intake/reassessment/events` | `create_model_intake_reassessment_event` |
| `POST` | `/model-intake/resolve` | `resolve_model_intake` |
| `POST` | `/model-intake/retention/cleanup` | `cleanup_model_intake_quarantine` |
| `POST` | `/model-intake/scan` | `scan_model_intake` |
| `GET` | `/model-intake/scans/{scan_id}/evidence-export` | `get_model_intake_evidence_export` |
| `POST` | `/model-intake/targets/{target_id}/rescan` | `rescan_model_intake_target` |
| `GET` | `/model-intake/trust-anchors` | `list_model_intake_trust_anchors` |
| `POST` | `/model-intake/trust-anchors` | `create_model_intake_trust_anchor` |
| `DELETE` | `/model-intake/trust-anchors/{anchor_id}` | `deactivate_model_intake_trust_anchor` |
| `PATCH` | `/model-intake/trust-anchors/{anchor_id}` | `update_model_intake_trust_anchor` |
| `GET` | `/policy-profiles` | `list_policy_profiles` |
| `POST` | `/policy-profiles` | `create_policy_profile` |
| `DELETE` | `/policy-profiles/{profile_id}` | `delete_policy_profile` |
| `PATCH` | `/policy-profiles/{profile_id}` | `update_policy_profile` |
| `DELETE` | `/queue/clear` | `clear_queue` |
| `GET` | `/queue/stats` | `queue_stats` |
| `POST` | `/research/campaigns/launch` | `launch_research_campaign` |
| `POST` | `/research/campaigns/{campaign_id}/control` | `control_research_campaign` |
| `GET` | `/research/episodes` | `list_research_episodes` |
| `POST` | `/research/episodes` | `create_research_episode` |
| `GET` | `/research/episodes/{episode_id}` | `get_research_episode` |
| `PUT` | `/research/episodes/{episode_id}/autopilot` | `set_research_episode_autopilot` |
| `GET` | `/research/episodes/{episode_id}/benchmark` | `research_episode_benchmark` |
| `POST` | `/research/episodes/{episode_id}/cancel` | `cancel_research_episode` |
| `POST` | `/research/episodes/{episode_id}/decisions` | `submit_research_decision` |
| `POST` | `/research/episodes/{episode_id}/observe` | `refresh_research_observation` |
| `POST` | `/research/episodes/{episode_id}/plan-step` | `plan_research_episode_step` |
| `POST` | `/research/episodes/{episode_id}/settle` | `settle_research_episode` |
| `POST` | `/research/launch` | `launch_research_episode` |
| `GET` | `/research/readiness` | `research_readiness` |
| `GET` | `/results` | `list_results` |
| `GET` | `/results/{target_folder}/latest` | `get_latest_result` |
| `GET` | `/retests/finding/{finding_id:path}` | `list_finding_retests` |
| `GET` | `/retests/{retest_id}` | `get_retest` |
| `GET` | `/scans` | `list_scans` |
| `POST` | `/scans` | `submit_scan` |
| `POST` | `/scans/batch` | `submit_batch` |
| `GET` | `/scans/{scan_id}` | `get_scan` |
| `GET` | `/scans/{scan_id}/ai-redteam-report` | `get_ai_redteam_report` |
| `GET` | `/scans/{scan_id}/artifacts` | `list_scan_artifacts` |
| `GET` | `/scans/{scan_id}/artifacts/{artifact_id}` | `download_scan_artifact` |
| `POST` | `/scans/{scan_id}/cancel` | `cancel_scan` |
| `GET` | `/scans/{scan_id}/deployment-decision` | `get_scan_deployment_decision` |
| `GET` | `/scans/{scan_id}/logs` | `get_scan_logs` |
| `GET` | `/scans/{scan_id}/queue-delivery` | `get_scan_queue_delivery` |
| `GET` | `/scans/{scan_id}/result` | `get_scan_result` |
| `GET` | `/schedules` | `list_schedules` |
| `POST` | `/schedules` | `create_schedule` |
| `DELETE` | `/schedules/{schedule_id}` | `delete_schedule` |
| `GET` | `/schedules/{schedule_id}` | `get_schedule` |
| `PATCH` | `/schedules/{schedule_id}` | `update_schedule` |
| `POST` | `/session/start` | `start_session` |
| `DELETE` | `/session/{session_id}` | `end_session` |
| `GET` | `/session/{session_id}` | `get_session_state` |
| `POST` | `/session/{session_id}/action` | `session_action` |
| `POST` | `/session/{session_id}/findings` | `create_session_finding` |
| `POST` | `/session/{session_id}/screenshot` | `session_screenshot` |
| `GET` | `/session/{session_id}/screenshot.png` | `session_screenshot_raw` |
| `POST` | `/session/{session_id}/test-endpoint` | `session_test_endpoint` |
| `GET` | `/sessions` | `list_sessions` |
| `GET` | `/settings/ai` | `get_ai_settings` |
| `PUT` | `/settings/ai` | `update_ai_settings` |
| `POST` | `/settings/ai/test` | `test_ai_settings` |
| `GET` | `/settings/automation` | `get_automation_settings` |
| `PUT` | `/settings/automation` | `update_automation_settings` |
| `GET` | `/settings/scan-execution` | `get_scan_execution_settings` |
| `PUT` | `/settings/scan-execution` | `update_scan_execution_settings` |
| `GET` | `/system/resources` | `get_system_resources` |
| `GET` | `/targets` | `list_targets` |
| `POST` | `/targets` | `create_target` |
| `POST` | `/targets/dedupe` | `dedupe_targets` |
| `GET` | `/targets/grouped` | `list_targets_grouped` |
| `DELETE` | `/targets/{target_id}` | `delete_target` |
| `GET` | `/targets/{target_id}` | `get_target` |
| `PATCH` | `/targets/{target_id}` | `update_target` |
| `GET` | `/targets/{target_id}/asm/activity` | `asm_activity` |
| `GET` | `/targets/{target_id}/asm/coverage` | `asm_coverage` |
| `GET` | `/targets/{target_id}/asm/diff` | `asm_diff` |
| `GET` | `/targets/{target_id}/asm/endpoints` | `asm_list_endpoints` |
| `GET` | `/targets/{target_id}/asm/gaps` | `asm_gaps` |
| `POST` | `/targets/{target_id}/asm/improve` | `asm_improve` |
| `GET` | `/targets/{target_id}/asm/policy` | `asm_get_policy` |
| `PUT` | `/targets/{target_id}/asm/policy` | `asm_set_policy` |
| `POST` | `/targets/{target_id}/asm/prune` | `asm_prune` |
| `POST` | `/targets/{target_id}/asm/recon` | `asm_recon` |
| `POST` | `/targets/{target_id}/asm/test` | `asm_test` |
| `GET` | `/targets/{target_id}/credential-profiles` | `list_target_credential_profiles` |
| `POST` | `/targets/{target_id}/credential-profiles` | `create_target_credential_profile` |
| `DELETE` | `/targets/{target_id}/credential-profiles/{profile_id}` | `delete_target_credential_profile` |
| `PATCH` | `/targets/{target_id}/credential-profiles/{profile_id}` | `update_target_credential_profile` |
| `POST` | `/targets/{target_id}/credential-profiles/{profile_id}/rotate` | `rotate_target_credential_profile` |
| `GET` | `/targets/{target_id}/graph` | `get_application_graph` |
| `POST` | `/targets/{target_id}/graph/hypotheses` | `generate_application_graph_hypotheses` |
| `GET` | `/targets/{target_id}/invariants` | `list_target_invariant_contracts` |
| `POST` | `/targets/{target_id}/invariants` | `create_target_invariant_contract` |
| `POST` | `/targets/{target_id}/invariants/compile` | `compile_target_invariant_rule` |
| `POST` | `/targets/{target_id}/invariants/hypotheses` | `generate_target_invariant_hypotheses` |
| `POST` | `/targets/{target_id}/invariants/{contract_id}/approve` | `approve_target_invariant_contract` |
| `POST` | `/targets/{target_id}/invariants/{contract_id}/retire` | `retire_target_invariant_contract` |
| `GET` | `/targets/{target_id}/invariants/{contract_id}/verification-plan` | `get_target_invariant_verification_plan` |
| `POST` | `/targets/{target_id}/inventory/hypotheses` | `generate_endpoint_inventory_hypotheses` |
| `GET` | `/targets/{target_id}/principal-matrix` | `list_target_principal_matrix` |
| `POST` | `/targets/{target_id}/principal-matrix` | `upsert_target_principal_matrix` |
| `DELETE` | `/targets/{target_id}/principal-matrix/{expectation_id}` | `delete_target_principal_expectation` |
| `GET` | `/targets/{target_id}/principals` | `list_target_principals` |
| `POST` | `/targets/{target_id}/principals` | `create_target_principal` |
| `POST` | `/targets/{target_id}/principals/auto-provision` | `auto_provision_target_principals` |
| `DELETE` | `/targets/{target_id}/principals/{principal_id}` | `delete_target_principal` |
| `PATCH` | `/targets/{target_id}/principals/{principal_id}` | `update_target_principal` |
| `POST` | `/targets/{target_id}/scan` | `scan_target` |
| `GET` | `/timeline` | `mission_timeline` |
| `GET` | `/workers` | `get_workers` |
| `POST` | `/workers` | `scale_workers` |

### Check-Family Registry

| Name | Phase | Family | Active | Risk | Runnable | Adapter | Telemetry | Description |
|---|---|---|---|---|---|---|---|---|
| `auth` | active | access_control | True | medium | True | `asm_endpoint_batch` | `active_endpoint_attempt_v1` | Read-only authenticated-vs-anonymous access checks for focused ASM endpoint batches. |
| `bola` | active | access_control | True | high | True | `asm_endpoint_batch` | `active_endpoint_attempt_v1` | Multi-user object authorization comparisons. Requires Lab/deep policy and two auth contexts. |
| `business_logic` | active | workflow | True | high | False | `none` | `planned_workflow_attempt` | Workflow/business-logic testing. Planned for AI/manual-assisted campaigns. |
| `endpoint_security` | passive | endpoint_surface | False | low | True | `endpoint_scoped_surface` | `endpoint_surface_attempt_v1` | Target-wide API data exposure, webhook signature, and approval/authorization checks over the discovered endpoint inventory. |
| `headers` | passive | headers | False | low | True | `legacy_config_findings` | `planned_passive_attempt` | HTTP security header posture checks. |
| `jwt` | active | authentication | True | medium | True | `legacy_advanced_jwt` | `jwt_probe_attempt_v1` | JWT algorithm, signature, key, and claim mutation checks with acceptance proof. |
| `lfi` | active | server_side | True | high | False | `none` | `planned_high_risk_attempt` | File inclusion and path traversal checks. Planned and permission-gated. |
| `mass_assignment` | active | access_control | True | medium | True | `legacy_phase4_mass_assignment` | `mass_assignment_attempt_v1` | Bounded privileged-field mutation with baseline-vs-response effect proof. |
| `nuclei` | template | nuclei | False | low | True | `legacy_nuclei_template` | `nuclei_template` | Nuclei template checks by severity/tag. Not an ASM endpoint-test family yet. |
| `rce` | active | server_side | True | high | False | `none` | `planned_high_risk_attempt` | Command/code execution checks. Planned and permission-gated. |
| `recon` | recon | passive | False | low | True | `legacy_discovery` | `discovery` | Crawl, API/HAR/OpenAPI discovery, and passive surface refresh. |
| `sqli` | active | injection | True | medium | True | `legacy_active_loop` | `active_endpoint_attempt_v1` | SQL injection probes and proof/extraction depth. |
| `ssrf` | active | server_side | True | high | False | `none` | `planned_high_risk_attempt` | Server-side request forgery checks. Planned and permission-gated. |
| `xss` | active | client | True | medium | True | `legacy_active_loop` | `active_endpoint_attempt_v1` | Reflected, stored, and DOM XSS probes. |

### Command Arsenal

| Command | Family | Status | Risk | HTTP | Path | Description |
|---|---|---|---|---|---|---|
| `agent_context_pack.generate_from_target` | governance | dry_run | read_only | POST | `/arsenal/context-packs/from-target` | Generate and persist a bounded AgentContextPack from stored target facts without executing work. |
| `agent_context_pack.list` | governance | read_only | read_only | GET | `/arsenal/context-packs` | Read recent bounded AgentContextPack records. |
| `agent_context_pack.record` | governance | dry_run | read_only | POST | `/arsenal/context-packs` | Validate and persist a bounded redacted AgentContextPack without executing work. |
| `agent_decision_trace.list` | governance | read_only | read_only | GET | `/arsenal/decision-traces` | Read recent AgentDecisionTrace audit records. |
| `agent_decision_trace.record` | governance | dry_run | read_only | POST | `/arsenal/decision-traces` | Validate and persist a dry-run AgentDecisionTrace without executing actions. |
| `ai_gate.replay_probe` | ai_gate | gated | active | POST | `/ai/scans/{scan_id}/replay` | Queue focused AI Gate replay using original target/profile/probe context. |
| `ai_gate.scan` | ai_gate | gated | active | POST | `/ai/targets/{target_id}/scan` | Queue an AI Gate scan for a saved AI target through the existing production and approval gates. |
| `ai_gate.target_history_export` | ai_gate | read_only | read_only | GET | `/ai/targets/{target_id}/campaign-history/export` | Read a content-free AI Gate target campaign-history export with readiness trends, trend series, and report links. |
| `ai_target.list` | ai_gate | read_only | read_only | GET | `/ai/targets` | List configured AI Gate targets and control metadata. |
| `approval.record` | governance | gated | credential | POST | `/arsenal/approvals` | Persist an approval or denial receipt for an existing scope receipt without executing work. |
| `asm.activity` | asm | read_only | read_only | GET | `/targets/{target_id}/asm/activity` | Read recent Continuous ASM recon/test activity and the target campaign timeline. |
| `asm.gaps` | asm | read_only | read_only | GET | `/targets/{target_id}/asm/gaps` | Explain remaining Continuous ASM gaps and recommended campaigns for one target. |
| `asm.improve` | asm | gated | active | POST | `/targets/{target_id}/asm/improve` | Queue or preview the next Continuous ASM action for one target. |
| `asm.recon` | asm | gated | passive | POST | `/targets/{target_id}/asm/recon` | Queue an explicit Continuous ASM recon refresh for a target's persistent endpoint inventory. |
| `asm.test` | asm | gated | active | POST | `/targets/{target_id}/asm/test` | Queue an async exploitation batch over untested/stale Continuous ASM inventory endpoints. |
| `authz.promote_replay_finding` | authz | gated | credential | POST | `/arsenal/campaign-actions/{campaign_action_id}/authz-promote` | Promote a stored authz replay violation into a manual-source finding with replay evidence refs. Requires explicit authorization. |
| `authz.replay_plan` | authz | gated | credential | POST | `/arsenal/campaign-actions/{campaign_action_id}/authz-replay` | Execute a stored deterministic authorization replay plan through an existing interactive session. Does not create findings automatically. |
| `campaign.create` | governance | dry_run | read_only | POST | `/arsenal/campaigns` | Create a mission campaign record (the operating wrapper over ASM/scan/AI Gate/Model Intake/retest actions). Records only; queues no work and creates no findings. |
| `campaign.get` | governance | read_only | read_only | GET | `/arsenal/campaigns/{campaign_id}` | Read one mission campaign plus its linked action-ledger rollup. |
| `campaign.link_action` | governance | dry_run | read_only | POST | `/arsenal/campaigns/{campaign_id}/actions` | Link an existing command-result/action-ledger row to a mission campaign. Bookkeeping link only; changes no proof state and creates no findings. |
| `campaign.list` | governance | read_only | read_only | GET | `/arsenal/campaigns` | Read recent mission campaign records. |
| `campaign_action.list` | governance | read_only | read_only | GET | `/arsenal/campaign-actions` | Read recent campaign/action execution records derived from product actions and command results. |
| `command_result.list` | governance | read_only | read_only | GET | `/arsenal/command-results` | Read recent Command Arsenal result/audit records for queued, partial, or blocked product actions. |
| `deployment.decision` | governance | read_only | read_only | GET | `/scans/{scan_id}/deployment-decision` | Read deployment gate decision for a scan and policy profile. |
| `evidence.export_bundle` | evidence | read_only | read_only | GET | `/evidence/export-bundle` | Read a content-free evidence export bundle descriptor or metadata zip with manifest hash, API replay paths, and retention/integrity summaries. |
| `evidence.export_manifest` | evidence | read_only | read_only | GET | `/evidence/export-manifest` | Read a content-free evidence export manifest with hashes, storage URIs, retention classes, and integrity status. |
| `evidence.get` | evidence | read_only | read_only | GET | `/findings/{finding_id}/evidence` | Read redacted durable evidence objects for a finding. |
| `evidence.retention_sweep` | evidence | gated | dangerous | POST | `/evidence/retention/sweep` | Preview or execute target-scoped evidence-object retention cleanup. Preview is read-only and needs no approval. Gated execution requires dry_run=false, that exact preview ID, and a matching approval receipt. Scheduled deletion is not supported. |
| `evidence_instance.list` | evidence | read_only | read_only | GET | `/evidence/instances` | Read concrete evidence instances split from canonical findings. |
| `evidence_instance.record` | evidence | dry_run | read_only | POST | `/evidence/instances` | Record a concrete evidence instance without updating finding proof state. |
| `experiment.http_diff` | research | gated | active | POST | `/arsenal/execute` | Run a bounded same-origin read-only HTTP differential and record unverified evidence. |
| `experiment.workflow` | research | gated | credential | POST | `/arsenal/execute` | Run a bounded principal-bound HTTP/browser workflow and record unverified state-transition evidence. |
| `exposure.graph.get` | inventory | read_only | read_only | GET | `/exposure/graph` | Read the exposure graph built from existing targets, scans, AI targets, model artifacts, and findings. |
| `finding.get` | findings | read_only | read_only | GET | `/findings/{finding_id}` | Read one finding by id or fingerprint. |
| `finding.list` | findings | read_only | read_only | GET | `/findings` | List findings with filters and proof-state fields. |
| `finding.retest` | findings | gated | active | POST | `/findings/{finding_id}/retest` | Queue deterministic or AI-assisted retest for one finding through existing retest gates. |
| `finding_exception.lifecycle_sweep` | policy | gated | active | POST | `/finding-exceptions/lifecycle/sweep` | Preview or execute a bounded one-way exception lifecycle sweep. Only effective exceptions whose expires_at is in the past are marked expired; the sweep never renews, revokes, or deletes exceptions. |
| `hypothesis.claim` | governance | dry_run | read_only | POST | `/arsenal/hypotheses/{hypothesis_id}/claim` | Claim a hypothesis using compare-and-set leasing; does not queue scanner work. |
| `hypothesis.generate_from_benchmark` | governance | dry_run | read_only | POST | `/arsenal/hypotheses/from-benchmark` | Record benchmark scorecard follow-up rows as hypotheses only; benchmark misses cannot create findings or satisfy proof. |
| `hypothesis.generate_from_graph` | governance | dry_run | read_only | POST | `/targets/{target_id}/graph/hypotheses` | Generate app-graph authorization hypotheses from persisted producer/object/consumer facts without queueing tests. |
| `hypothesis.generate_from_plan` | governance | dry_run | read_only | POST | `/arsenal/hypotheses/from-plan` | Record saved dry-run OperationPlan actions as planner-signal hypotheses only; planner output cannot execute work or satisfy proof. |
| `hypothesis.generate_from_source` | governance | dry_run | read_only | POST | `/arsenal/hypotheses/source-ingest` | Record bounded source/spec/package hints as hypotheses only; source text cannot create findings or satisfy runtime proof. |
| `hypothesis.list` | governance | read_only | read_only | GET | `/arsenal/hypotheses` | Read deduped claimable/refutable hypotheses that have not become findings. |
| `hypothesis.plan_campaign` | governance | dry_run | read_only | POST | `/arsenal/hypotheses/{hypothesis_id}/plan-campaign` | Create or link a mission campaign and planned action from a hypothesis next_test_action without executing the action. |
| `hypothesis.reconcile_proof` | governance | gated | active | POST | `/arsenal/hypotheses/{hypothesis_id}/reconcile-proof` | Reconcile one executed campaign action back to its hypothesis using only exact deterministic finding proof already persisted by ShakerScan. |
| `hypothesis.record` | governance | dry_run | read_only | POST | `/arsenal/hypotheses` | Record or endorse a deduped hypothesis without creating a finding or queueing work. |
| `hypothesis.signal` | governance | dry_run | read_only | POST | `/arsenal/hypotheses/{hypothesis_id}/signals` | Append an endorsement or refutation signal to a hypothesis without changing findings or gates. |
| `hypothesis.situation_report` | governance | read_only | read_only | GET | `/arsenal/hypotheses/situation-report` | Read a bounded hypothesis situation report with hot unclaimed leads, owned claims, blockers, terminal leads, missing preconditions, and application-graph context. |
| `local_agent.list` | planner | read_only | read_only | GET | `/agents/local` | Read local planner capability records without reading auth artifacts or executing prompts. |
| `local_agent.parse_plan` | planner | dry_run | read_only | POST | `/agents/local/plan/parse` | Fail-closed validation for raw local-agent planner JSON before any candidate can become an OperationPlan. |
| `local_agent.plan_dry_run` | planner | dry_run | read_only | POST | `/agents/local/plan` | Persist a local-agent-labeled dry-run OperationPlan from a saved AgentContextPack without spawning a local agent. |
| `local_agent.test` | planner | dry_run | read_only | POST | `/agents/local/test` | Run a bounded harmless local-agent capability ping without sending prompts or enabling planner execution. |
| `mission.timeline` | governance | read_only | read_only | GET | `/timeline` | Read the cross-product mission timeline: command results, campaign actions, recent scans, evidence bindings, export events, refuter reviews, and upcoming schedules. |
| `model_intake.evidence_export` | model_intake | read_only | read_only | GET | `/model-intake/scans/{scan_id}/evidence-export` | Read a content-free Model Intake evidence export with trust, AIBOM, policy, and replay hashes. |
| `model_intake.scan` | model_intake | gated | passive | POST | `/model-intake/scan` | Queue a Model Intake artifact check through existing policy and artifact-fetch gates. |
| `model_intake.trust_preview` | model_intake | read_only | read_only | CLIENT | `/model-intake` | Preview Model Intake trust mode and policy readiness in the UI before queueing a scan. |
| `operation_plan.list` | governance | read_only | read_only | GET | `/arsenal/plans` | Read recent dry-run OperationPlan records. |
| `operation_plan.preview` | governance | dry_run | read_only | POST | `/arsenal/plans` | Validate and persist a dry-run OperationPlan without executing any action. |
| `refuter_review.derive_verdict` | governance | gated | read_only | POST | `/arsenal/refuter-reviews/{refuter_review_id}/derive-verdict` | Record a refuter signal or deterministic proof-backed verdict from a completed finding verification row without changing product truth. |
| `refuter_review.execute_plan` | governance | gated | active | POST | `/arsenal/refuter-reviews/{refuter_review_id}/execute` | Execute the next planned refuter automation step through existing gated retest/replay primitives. Does not directly change proof state or gates. |
| `refuter_review.list` | governance | read_only | read_only | GET | `/arsenal/refuter-reviews` | Read durable refuter signals and proof-backed verdict records without changing findings. |
| `refuter_review.queue_from_summary` | governance | dry_run | read_only | POST | `/arsenal/refuter-reviews/queue-from-summary` | Record signal-only refuter review work from the current weak-claim summary without mutating findings. |
| `refuter_review.record` | governance | dry_run | read_only | POST | `/arsenal/refuter-reviews` | Record a refuter signal or evidence-backed verdict without directly changing findings, proof state, or gates. |
| `refuter_review.summary` | governance | read_only | read_only | GET | `/arsenal/refuter-reviews/summary` | Read a bounded worklist of weak/high-impact findings that should be challenged, with non-executing deterministic automation plans. |
| `scan.focused_family` | scans | gated | active | POST | `/scans` | Submit a focused DAST family campaign through existing scan submission gates. |
| `scan.result` | scans | read_only | read_only | GET | `/scans/{scan_id}/result` | Read scan status and stored result JSON. |
| `scope.preview` | governance | dry_run | read_only | POST | `/arsenal/scope/preview` | Validate and persist a fail-closed scope receipt preview without executing work. |
| `target.get` | inventory | read_only | read_only | GET | `/targets/{target_id}` | Get one target and recent scan metadata. |
| `target.invariant.compile` | authorization_policy | dry_run | read_only | POST | `/targets/{target_id}/invariants/compile` | Compile one short business/security rule into non-authoritative typed draft candidates. |
| `target.invariant.generate_hypotheses` | authorization_policy | dry_run | read_only | POST | `/targets/{target_id}/invariants/hypotheses` | Convert approved typed invariants into deduplicated worklist leads without executing tests. |
| `target.invariant.verification_plan` | authorization_policy | read_only | read_only | GET | `/targets/{target_id}/invariants/{contract_id}/verification-plan` | Read the deterministic proof family and missing runtime bindings for one target invariant. |
| `target.invariant_contract.approve` | authorization_policy | gated | active | POST | `/targets/{target_id}/invariants/{contract_id}/approve` | Approve a validated typed invariant for planning, never direct finding promotion. |
| `target.invariant_contract.record` | authorization_policy | gated | active | POST | `/targets/{target_id}/invariants` | Record a typed target invariant as a non-authoritative draft. |
| `target.invariant_contract.retire` | authorization_policy | gated | active | POST | `/targets/{target_id}/invariants/{contract_id}/retire` | Retire a target invariant so it no longer guides autonomous planning. |
| `target.invariants` | authorization_policy | read_only | read_only | GET | `/targets/{target_id}/invariants` | Read typed target invariants; only approved rows can guide autonomous planning. |
| `target.list` | inventory | read_only | read_only | GET | `/targets` | List configured targets. |
| `target.principal_matrix` | inventory | read_only | read_only | GET | `/targets/{target_id}/principal-matrix` | Read endpoint x principal/role expectations for authorization planning without queueing tests. |
| `target.principal_matrix.record` | authorization_policy | gated | active | POST | `/targets/{target_id}/principal-matrix` | Record a non-executing endpoint principal expectation for future authz campaigns. |
| `target.principals` | inventory | read_only | read_only | GET | `/targets/{target_id}/principals` | Read role/tenant principals configured for one web/API target. |
| `tool.status` | tool_status | read_only | read_only | GET | `/arsenal/tools` | Read installed/runnable/waived/catalog status for integrated adapters. |
| `tool_receipt.list` | evidence | read_only | read_only | GET | `/arsenal/tool-receipts` | Read durable receipts for existing tools/executors. |
| `tool_receipt.record` | evidence | dry_run | read_only | POST | `/arsenal/tool-receipts` | Record an existing tool/executor receipt without running tools or creating findings. |

### Tool And Local-Agent Adapters

| Tool | Family | Status | Risk | Parser | Proof contract | Description |
|---|---|---|---|---|---|---|
| `ai_gate_probe_executor` | ai_red_team | runnable | active | `ai-gate-transcript-v1` | `deterministic-or-judge-evidence` | Internal AI Gate probe runner. |
| `dalfox` | xss | wired | active | `dalfox-json-v1` | `xss-reflection-or-browser-proof` | Dalfox XSS scanner. |
| `ffuf` | content_discovery | wired | active | `ffuf-json-v1` | `content-discovery-observation` | ffuf content discovery. |
| `httpx` | http_probe | wired | passive | `httpx-json-v1` | `http-observation` | ProjectDiscovery httpx HTTP probing. |
| `katana` | crawl | wired | passive | `katana-jsonl-v1` | `crawl-observation` | ProjectDiscovery katana crawler. |
| `model_intake_signature_verifier` | model_trust | runnable | passive | `model-intake-summary-v1` | `cryptographic-signature-verification` | Internal cryptographic signature verifier. |
| `nmap` | port_scan | gated | active | `nmap-xml-v1` | `open-port-observation` | nmap network service discovery. |
| `nuclei` | template_vuln_scan | wired | active | `nuclei-jsonl-v1` | `template-match-with-request-response` | Nuclei template scanner. |
| `playwright` | browser_proof | wired | active | `playwright-proof-v1` | `browser-observation` | Playwright browser proof execution. |
| `sqlmap` | sqli | gated | active | `sqlmap-output-v1` | `sqli-dbms-or-error-proof` | sqlmap SQL injection verifier. |
| `sslyze` | tls | disabled | passive | `sslyze-json-v1` | `tls-protocol-observation` | SSLyze TLS scanner (disabled until upstream supports the audited cryptography runtime). |
| `subfinder` | subdomain_discovery | wired | passive | `subfinder-lines-v1` | `passive-discovery` | ProjectDiscovery subfinder passive subdomain discovery. |
| `testssl.sh` | tls | wired | passive | `testssl-json-v1` | `tls-protocol-observation` | testssl.sh TLS scanner. |

| Agent | Display | Headless prompt | Timeout | Workdir isolation | Max prompt bytes | Max output bytes |
|---|---|---|---|---|---|---|
| `claude-code` | Claude Code | True | True | True | 120000 | 32000 |
| `codex` | Codex | True | True | True | 120000 | 32000 |
| `hermes` | Hermes | False | True | True | 64000 | 16000 |
| `opencode` | OpenCode | True | True | True | 120000 | 32000 |

### Scanner CLI Flags

| Flag | Choices | Purpose |
|---|---|---|
| `--abuseipdb-key` | - | AbuseIPDB API key for enhanced IP reputation (env: ABUSEIPDB_API_KEY) |
| `--active` | - | Run active security checks (dalfox/sqlmap) on discovered/synthetic URLs |
| `--aggressive` | - | Aggressive mode - maximum coverage with aggressive testing (2+ hours) |
| `--ai` | - | Enable AI-assisted verification of findings (non-invasive) |
| `--ai-api-key` | - | AI provider API key |
| `--ai-fallback-model` | - | Comma-separated fallback AI model IDs |
| `--ai-mask-host` | - | Replacement host sent to AI instead of the real target (default: example.com) |
| `--ai-url` | - | AI provider URL (HTTP endpoint) |
| `--api-security-testing` | - | Test for API security issues (mass assignment, BFLA) |
| `--api-token` | - | Bearer token for API testing (Authorization header) |
| `--asn-discovery` | - | Enable ASN/IP discovery (hosting provider, geographic distribution, multi-homing) |
| `--auth-config-file` | - | - |
| `--auth-cookies` | - | Session cookies for authenticated scanning (e.g., 'session=abc; token=xyz') |
| `--auth-header` | - | Authorization header for authenticated scanning (e.g., 'Bearer token123') |
| `--auth-headers-json` | - | Custom auth headers as JSON (e.g., '{"X-API-Key": "abc"}') |
| `--auth-scenario-json` | - | Auth scenario DSL JSON (login flow, credentials, success condition) |
| `--auto-auth` | - | Attempt API login with provided credentials (JSON/form endpoints) |
| `--avoid-rules-json` | - | JSON array of avoid rules to exclude endpoint scope |
| `--backup-file-testing` | - | Test for exposed backup files |
| `--baseline` | - | Baseline file to filter known issues (suppress matching findings) |
| `--bola-testing` | - | Test for BOLA/IDOR vulnerabilities (API1:2023, broken object-level authorization) |
| `--breach-check` | - | Check for credential breaches and leaks (HIBP, GitHub) |
| `--budget-active-max-endpoints` | - | - |
| `--budget-active-max-seconds` | - | - |
| `--budget-active-params-per-endpoint` | - | - |
| `--budget-active-worklist-max` | - | - |
| `--budget-api-probe-limit` | - | - |
| `--budget-browser-max-depth` | - | - |
| `--budget-browser-max-pages` | - | - |
| `--budget-disable-nuclei-early-stop` | - | - |
| `--budget-discovery-depth` | - | - |
| `--budget-max-duration-minutes` | - | - |
| `--budget-max-findings-per-family` | - | -1 disables the per-family active finding cap |
| `--budget-max-urls` | - | - |
| `--budget-nuclei-max-targets` | - | - |
| `--budget-param-discovery-max-params` | - | - |
| `--budget-param-discovery-url-limit` | - | - |
| `--budget-phase4-max-seconds` | - | - |
| `--budget-profile` | fast, balanced, thorough, exhaustive | Depth/time budget profile. Scan type selects checks; budget controls how hard they run. |
| `--budget-request-max` | - | - |
| `--business-logic-testing` | - | Detect business logic vulnerability indicators |
| `--check-family` | - | Run a scanner-supported active check family: all, sqli, or xss |
| `--cicd-exposure` | - | Test for exposed CI/CD configuration files |
| `--cloud-bucket-testing` | - | Test for publicly accessible cloud storage buckets |
| `--cloud-ssrf` | - | Test for SSRF vulnerabilities targeting cloud metadata |
| `--complete` | - | Complete scan mode - broader passive plus selected active checks (30-60 min) |
| `--complete-tier` | safe, full, aggressive | Scan tier for complete mode: safe (30-45min), full (2-3hr), aggressive (3+hr) |
| `--compliance-report` | - | Generate compliance report (PCI DSS, SOC 2, HIPAA, GDPR, CIS) |
| `--create-baseline` | - | Create baseline file from scan results (save known issues) |
| `--csrf-testing` | - | Test for CSRF vulnerabilities |
| `--ct-monitoring` | - | Enable certificate transparency monitoring (CA diversity, suspicious certs) |
| `--deep` | - | Deep scan - thorough passive assessment (30-60 min, alias for --complete) |
| `--deep-discovery` | - | Enable deep discovery with ffuf (complete mode) |
| `--deep-domxss` | - | Enable dalfox deep DOM XSS (spawns headless browser; heavy) |
| `--default-creds-testing` | - | Test for default credentials (safe mode) |
| `--deserialization-testing` | - | Test for insecure deserialization (detection only) |
| `--dkim-enumeration` | - | Enumerate DKIM selectors |
| `--dkim-selectors` | - | Comma-separated DKIM selectors to check (e.g., default,google) |
| `--dom-xss-max-files` | - | - |
| `--domain-intelligence` | - | Enable domain intelligence (WHOIS, age, expiration, registrar reputation) |
| `--endpoints` | - | Manual endpoint (e.g., 'GET /api/v1/users id,email' or '/api/login') |
| `--endpoints-file` | - | File with manual endpoints (one per line, same format as --endpoints) |
| `--enhanced-dns` | - | Enable enhanced DNS checks (DKIM, SPF validation, zone transfer) |
| `--exploit-level` | safe, moderate, aggressive | Exploit level for active tests |
| `--exposure-client` | - | Enable client-side exposure checks (JS Dependencies, JS Secrets) |
| `--exposure-infra` | - | Enable infrastructure exposure checks (CI/CD, Packages, Cloud Buckets, Backups, SSH, SMTP, Network Services, K8s/Terraform/Registry) |
| `--fail-on-high` | - | Fail quality gate on high severity findings (alias for --max-high 0) |
| `--file-upload-testing` | - | Test for file upload vulnerabilities |
| `--focus-rules-json` | - | JSON array of focus rules to constrain endpoint scope |
| `--focused-endpoints-only` | - | - |
| `--forced-browsing` | - | Test for forced browsing/direct request vulnerabilities (privileged path enumeration) |
| `--full` | - | Broad full assessment including active XSS/SQLi (1-2 hours; bounded modules and budgets apply) |
| `--github-token` | - | GitHub token for code search (env: GITHUB_TOKEN) |
| `--grpc-discovery` | - | Enable gRPC reflection discovery (requires grpcurl) |
| `--health-check` | - | Run tool health check and exit (validate all scanner tools are available) |
| `--hibp-api-key` | - | HIBP API key for email breach lookups (env: HIBP_API_KEY) |
| `--host-header-testing` | - | Test for host header injection |
| `--idor-testing` | - | Test for IDOR/BOLA vulnerabilities |
| `--include-partial-attack-chains` | - | Include partial attack chains in report (analyst mode) |
| `--ip-reputation` | - | Check IP reputation against DNS blacklists and threat intelligence |
| `--js-dependency-scanning` | - | Scan for vulnerable JavaScript dependencies (Retire.js methodology) |
| `--js-secret-scanning` | - | Scan for hardcoded secrets in JavaScript files |
| `--json-link-following` | - | Follow JSON/HATEOAS links to expand API endpoints |
| `--kubernetes-exposure` | - | Test for exposed Kubernetes API servers |
| `--login-extra-fields` | - | Extra form fields as JSON (e.g., '{"remember_me": "1"}') |
| `--login-password` | - | Password for form-based login |
| `--login-url` | - | Login page URL for form-based authentication (auto-detected if not provided) |
| `--login-username` | - | Username for form-based login |
| `--mass-assignment-testing` | - | Test for mass assignment vulnerabilities (CWE-915, privilege escalation via parameters) |
| `--max-active` | - | Max URLs for active checks (default 10) |
| `--max-critical` | - | Max critical findings before quality gate fails (default: 0) |
| `--max-high` | - | Max high findings before quality gate fails (default: 0) |
| `--max-medium` | - | Max medium findings before quality gate fails (-1 = unlimited) |
| `--max-ports` | - | Max ports to scan in complete mode (default 1000) |
| `--max-typo-checks` | - | Maximum typosquatting permutations to check (default: 100) |
| `--model` | - | AI model identifier (provider specific) |
| `--network-services` | - | Enable network services detection (VPN, RDP, VNC, IoT, Industrial, databases) |
| `--no-browser` | - | Disable browser-based scanning, use curl only (faster but less data) |
| `--no-early-stop` | - | Disable early stopping in smart scan (continue even after finding many vulns) |
| `--no-verified-findings-only` | - | Keep all findings regardless of verification status |
| `--nuclei` | - | Nuclei scan mode - vulnerability scan with the configured template set (10-30 min) |
| `--oauth-client-id` | - | OAuth 2.0 client ID |
| `--oauth-client-secret` | - | OAuth 2.0 client secret |
| `--oauth-password` | - | Password for OAuth password grant flow |
| `--oauth-scope` | - | OAuth scopes (space-separated) |
| `--oauth-token-url` | - | OAuth token endpoint URL (auto-discovered via OIDC if not provided) |
| `--oauth-username` | - | Username for OAuth password grant flow |
| `--oob-callback-url` | - | Out-of-band callback URL for blind SQLi verification (e.g., Burp Collaborator) |
| `--oob-max-findings` | - | - |
| `--oob-max-payloads` | - | - |
| `--open-redirect-testing` | - | Test for open redirect vulnerabilities |
| `--openapi` | - | OpenAPI/Swagger schema URL to test with Schemathesis |
| `--options-method-discovery` | - | Use HTTP OPTIONS to enumerate allowed methods |
| `--package-exposure` | - | Test for exposed package manager files |
| `--password-reset-testing` | - | Test for password reset vulnerabilities |
| `--path-traversal-testing` | - | Test for path traversal vulnerabilities |
| `--port` | - | Server port |
| `--pretty` | - | Pretty-print JSON |
| `--public` | - | Public data collection only (no active scans) |
| `--quality-gate` | - | Enable quality gate (exit code 1 if critical/high findings) |
| `--quick` | - | Quick scan mode - faster but less thorough (affects active checks) |
| `--rate-limiting-testing` | - | Test for missing rate limiting |
| `--registry-exposure` | - | Test for exposed container registries |
| `--sarif` | - | Output SARIF file for CI/CD integration (e.g., results.sarif) |
| `--server` | - | Run FastAPI server |
| `--session-mgmt-testing` | - | Test for session management issues |
| `--show-suppressed` | - | Include suppressed findings in output (marked with suppressed=true) |
| `--skip-global-checks` | - | Skip duplicate global exposure/posture checks in a parallel child shard |
| `--smart` | - | Smart scan - adaptive scanning with staged templates, recursive discovery, and context-aware attacks |
| `--smart-bola-max-endpoints` | - | - |
| `--smtp-security` | - | Enable SMTP security testing (STARTTLS, open relay, banner analysis) |
| `--sqli` | - | Run only SQLi active checks (implies --active) |
| `--sqli-extract-max` | - | - |
| `--ssh-port` | - | SSH port to scan (default 22) |
| `--ssh-testing` | - | Test SSH configuration (password auth detection) |
| `--standard` | - | Standard scan - balanced passive coverage (5-10 min) |
| `--subdomain-quick` | - | Quick subdomain scan using Gungnir only (faster) |
| `--subdomain-sources` | - | Comma-separated subdomain sources: gungnir,subfinder,crtsh (default: all) |
| `--subfinder` | - | Subdomain discovery mode - comprehensive CT log and passive enumeration |
| `--terraform-exposure` | - | Test for exposed Terraform state files |
| `--thorough-params` | - | Test more parameters (100 endpoints x 10 params vs default 50x5) |
| `--threat-intel` | - | Enable threat intelligence checks (IP Reputation, Breach Check, Vendor Risk, Typosquatting, Domain Intel, CT Monitoring, ASN Discovery, Enhanced DNS) |
| `--twofa-bypass-testing` | - | Test for 2FA bypass vulnerabilities |
| `--typosquatting` | - | Detect typosquatting/lookalike domains |
| `--user2-cookies` | - | Session cookies for second user (BOLA comparison) |
| `--user2-header` | - | Authorization header for second user (BOLA comparison) |
| `--user2-login-password` | - | Password for second user form login |
| `--user2-login-username` | - | Username for second user form login |
| `--vendor-risk` | - | Assess third-party/vendor supply chain risk (CDN, analytics, dependencies) |
| `--verified-findings-only` | - | Only keep findings with exploit verification evidence (default for smart scans) |
| `--virustotal-key` | - | VirusTotal API key for enhanced IP reputation (env: VIRUSTOTAL_API_KEY) |
| `--vuln-auth` | - | Enable all auth/access checks (CSRF, IDOR, Rate Limiting, 2FA, Password Reset, Session, Default Creds) |
| `--vuln-injection` | - | Enable all injection checks (Path Traversal, Deserialization) |
| `--vuln-web` | - | Enable all web app checks (File Upload, Open Redirect, Host Header, Business Logic, API Security, Forced Browsing, Cloud SSRF) |
| `--websocket-testing` | - | Test WebSocket endpoints for CSWSH, auth bypass, and other vulnerabilities |
| `--xss` | - | Run only XSS active checks (implies --active) |
| `--zero-rediscovery` | - | - |
| `--zone-transfer-test` | - | Test for DNS zone transfer (AXFR) vulnerability |

### Wrapper Commands, Make Targets, And Release Gates

| Surface | Names |
|---|---|
| `scanner.sh` commands | `agent`, `ai`, `backup`, `build`, `doctor`, `env`, `fleet`, `gungnir`, `help`, `install-deps`, `join`, `logs`, `mcp`, `rebuild`, `reload`, `research`, `reset`, `restart`, `scale`, `scan`, `scan-full`, `scan-smart`, `shell`, `start`, `status`, `stop` |
| Make targets | `dependency-audit`, `dependency-lock`, `e2e`, `e2e-ai-gate`, `e2e-dast`, `e2e-model-intake`, `e2e-model-intake-fixture`, `fleet-acceptance`, `release-gates`, `test`, `upgrade-smoke` |
| Release gates | `test:evidence-provenance`, `test:fleet-current`, `test:hypothesis-proof-promotion`, `test:mcp-read-only`, `test:no-ai-verified`, `test:no-benchmark-fitting`, `test:no-phantom-tools`, `test:planner-no-shell`, `test:planner-risk`, `test:planner-scope`, `test:scanner-auth-quality`, `test:scanner-bounds`, `test:scanner-proof-truth`, `test:scanner-registry-coverage` |

### Runtime Environment-Key Inventory

Only key names and declaring sources are documented; secret values are never read or emitted.

| Environment key | Referenced by |
|---|---|
| `ABUSEIPDB_API_KEY` | `scanner/scanner.py` |
| `AI_API_KEY` | `api/ai_gate_scan.py`, `api/api.py`, `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml`, `scanner/scanner.py` |
| `AI_CLASSIFY_CHAIN_BUDGET_SECONDS` | `docker-compose.release.yml`, `docker-compose.yml`, `scanner/scanner_tools/ai_classifier.py` |
| `AI_CLASSIFY_CIRCUIT_COOLDOWN_SECONDS` | `docker-compose.release.yml`, `docker-compose.yml`, `scanner/scanner_tools/ai_classifier.py` |
| `AI_CLASSIFY_CIRCUIT_ERROR_THRESHOLD` | `docker-compose.release.yml`, `docker-compose.yml`, `scanner/scanner_tools/ai_classifier.py` |
| `AI_CLASSIFY_CIRCUIT_WINDOW_SECONDS` | `docker-compose.release.yml`, `docker-compose.yml`, `scanner/scanner_tools/ai_classifier.py` |
| `AI_CLASSIFY_MAX_FINDINGS_PER_BATCH` | `scanner/scanner_tools/ai_classifier.py` |
| `AI_CLASSIFY_MAX_PROMPT_CHARS` | `scanner/scanner_tools/ai_classifier.py` |
| `AI_CLASSIFY_MIN_SEVERITY` | `api/api.py`, `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml`, `scanner/scanner.py` |
| `AI_CREDENTIAL_ENC_KEY` | `api/secret_store.py` |
| `AI_CREDENTIAL_ENC_KEY_FILE` | `api/secret_store.py` |
| `AI_DEMO_HONEY_PUBLIC_URL` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `AI_DEMO_HONEY_SCANNER_URL` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `AI_DEMO_MODE_ENABLED` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `AI_ESCALATION_MIN_SEVERITY` | `api/api.py`, `api/retest_contract.py`, `api/worker.py` |
| `AI_FALLBACK_MODEL` | `api/api.py`, `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml`, `scanner/scanner.py` |
| `AI_GATE_TRANSCRIPT_RETENTION_DAYS` | `api/ai_gate_scan.py` |
| `AI_GATE_TRUSTED_RECEIPT_KEYS` | `api/ai_gate_scan.py` |
| `AI_GATE_TRUSTED_RECEIPT_KEY_SHA256` | `api/ai_gate_scan.py` |
| `AI_JUDGE_MODEL` | `api/ai_gate_scan.py` |
| `AI_MASK_HOST` | `api/api.py`, `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `AI_MODEL` | `api/ai_gate_scan.py`, `api/api.py`, `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml`, `scanner/scanner.py` |
| `AI_OPS_ROUTER_EXECUTE_ENABLED` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `AI_REASONING_RETRY_MAX_TOKENS` | `scanner/scanner_tools/ai_classifier.py` |
| `AI_SCAN_CLASSIFICATION_ENABLED` | `api/api.py`, `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml`, `scanner/scanner.py` |
| `AI_SETTINGS_KEY` | `api/api.py`, `api/worker.py` |
| `AI_TRANSCRIPT_ALLOW_SENSITIVE` | `api/api.py` |
| `AI_URL` | `api/ai_gate_scan.py`, `api/api.py`, `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml`, `scanner/scanner.py` |
| `AI_VERIFY_ENABLED` | `api/api.py`, `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `AI_VERIFY_MAX_PER_SCAN` | `api/worker.py` |
| `AI_VERIFY_MIN_SEVERITY` | `api/api.py`, `api/retest_contract.py`, `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml`, `scanner/scanner.py` |
| `AI_VERIFY_USE_BROWSER` | `api/worker.py` |
| `APPROVAL_RECEIPTS_REQUIRED_FOR_STATE_CHANGING_ACTIONS` | `api/api.py` |
| `ARTIFACT_CHECKPOINT_INTERVAL_SECONDS` | `api/worker.py` |
| `ARTIFACT_REFERENCED_FILE_MAX_BYTES` | `api/worker.py` |
| `ARTIFACT_REFERENCED_FILE_MAX_COUNT` | `api/worker.py` |
| `ARTIFACT_RETENTION_ATTACHMENT_DAYS` | `docker-compose.release.yml`, `docker-compose.yml` |
| `ARTIFACT_RETENTION_CHECKPOINT_DAYS` | `docker-compose.release.yml`, `docker-compose.yml` |
| `ARTIFACT_RETENTION_DAYS` | `api/artifact_storage.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `ARTIFACT_RETENTION_DIAGNOSTIC_DAYS` | `docker-compose.release.yml`, `docker-compose.yml` |
| `ARTIFACT_RETENTION_RESULT_DAYS` | `docker-compose.release.yml`, `docker-compose.yml` |
| `ARTIFACT_RETENTION_SCREENSHOT_DAYS` | `docker-compose.release.yml`, `docker-compose.yml` |
| `ARTIFACT_RETENTION_SWEEP_SECONDS` | `docker-compose.release.yml`, `docker-compose.yml` |
| `ARTIFACT_S3_PREFIX` | `docker-compose.release.yml`, `docker-compose.yml` |
| `ARTIFACT_STORAGE_BACKEND` | `api/artifact_storage.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `ARTIFACT_STORAGE_REQUIRED` | `api/artifact_storage.py`, `api/broker_worker.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `ASM_DEFAULT_DOMAIN_RATE_PER_HOUR` | `api/asm_inventory.py` |
| `ASM_DEFAULT_ENABLED` | `api/api.py` |
| `ASM_GONE_RETENTION_DAYS` | `api/asm_inventory.py` |
| `ASM_GONE_STREAK_THRESHOLD` | `api/asm_inventory.py` |
| `ASM_REACHABILITY_SWEEP` | `api/asm_inventory.py` |
| `ASM_SCAN_SWEEP_MAX` | `api/worker.py` |
| `ASM_SCHEDULE_RETRY_MINUTES` | `api/api.py` |
| `ASM_SOFT404_DETECT` | `api/asm_inventory.py` |
| `ASM_SOFT404_SIZE_TOL_BYTES` | `api/asm_inventory.py` |
| `ASM_VALIDATE_REACHABILITY` | `api/asm_inventory.py` |
| `AUTOMATION_SETTINGS_KEY` | `api/api.py` |
| `AUTO_FP_MIN_CONFIDENCE` | `api/api.py`, `api/retest_contract.py`, `api/worker.py` |
| `AUTO_FP_ON_RETEST` | `api/api.py`, `api/retest_contract.py`, `api/worker.py` |
| `AUTO_RETEST_MAX_ATTEMPTS` | `api/api.py`, `api/worker.py` |
| `AUTO_RETEST_MAX_PER_SCAN` | `api/api.py`, `api/retest_contract.py`, `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `AUTO_RETEST_MIN_SEVERITY` | `api/api.py`, `api/retest_contract.py`, `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `AUTO_RETEST_ON_SCAN_COMPLETE` | `api/api.py`, `api/retest_contract.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `AUTO_SHARDING_ENABLED` | `api/api.py` |
| `AUTO_SHARDING_MAX_SHARDS` | `api/api.py` |
| `AUTO_SHARDING_MIN_WORKERS` | `api/api.py` |
| `AUTO_SHARDING_STRATEGY` | `api/api.py` |
| `AWS_ACCESS_KEY_ID` | `api/evidence_storage.py` |
| `AWS_ENDPOINT_URL_S3` | `api/evidence_storage.py` |
| `AWS_REGION` | `api/evidence_storage.py` |
| `AWS_SECRET_ACCESS_KEY` | `api/evidence_storage.py` |
| `AWS_SESSION_TOKEN` | `api/evidence_storage.py` |
| `BROKER_INGEST_QUEUE_NAME` | `api/api.py`, `api/worker.py` |
| `BUILD_FINGERPRINT` | `api/worker.py` |
| `COVERAGE_ALLOCATION_DEFAULT` | `api/parallel_scan.py` |
| `DATABASE_URL` | `api/api.py`, `api/gungnir_worker.py`, `api/worker.py`, `scanner/gungnir_worker.py`, `scripts/upgrade_schema_smoke.py` |
| `DEFAULT_ASM_ENABLED` | `api/api.py` |
| `DEFAULT_RESEARCH_PLANNER_MODE` | `api/api.py` |
| `DOMAIN_RATE_REQUEUE_DELAY_SECONDS` | `api/worker.py` |
| `ENV` | `scanner/scanner_tools/remediation_kb.py` |
| `EVIDENCE_INLINE_MAX_BYTES` | `api/evidence_storage.py` |
| `EVIDENCE_RETENTION_PREVIEW_TTL_SECONDS` | `api/api.py` |
| `EVIDENCE_S3_ACCESS_KEY_ID` | `docker-compose.release.yml`, `docker-compose.yml` |
| `EVIDENCE_S3_BUCKET` | `docker-compose.release.yml`, `docker-compose.yml` |
| `EVIDENCE_S3_ENDPOINT_URL` | `docker-compose.release.yml`, `docker-compose.yml` |
| `EVIDENCE_S3_FORCE_PATH_STYLE` | `docker-compose.release.yml`, `docker-compose.yml` |
| `EVIDENCE_S3_REGION` | `docker-compose.release.yml`, `docker-compose.yml` |
| `EVIDENCE_S3_SECRET_ACCESS_KEY` | `docker-compose.release.yml`, `docker-compose.yml` |
| `EVIDENCE_S3_SESSION_TOKEN` | `docker-compose.release.yml`, `docker-compose.yml` |
| `EVIDENCE_S3_TIMEOUT_SECONDS` | `api/evidence_storage.py` |
| `EVIDENCE_STORAGE_BACKEND` | `api/artifact_storage.py`, `api/evidence_storage.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `FINALIZATION_HEARTBEAT_TIMEOUT_MINUTES` | `api/api.py` |
| `FLEET_AGENT_INTERVAL_SECONDS` | `api/fleet_agent.py`, `docker-compose.broker-worker.yml`, `docker-compose.worker.yml` |
| `FLEET_ALLOW_INSECURE_ENROLLMENT` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `FLEET_BROKER_STATE_PATH` | `api/broker_worker.py` |
| `FLEET_CA_CERT_PATH` | `api/api.py` |
| `FLEET_COMPOSE_PROJECT_NAME` | `docker-compose.broker-worker.yml`, `docker-compose.worker.yml` |
| `FLEET_CONNECTION_BUNDLE_JSON` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `FLEET_CONNECTION_BUNDLE_PATH` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `FLEET_CONTROL_PLANE_OVERLAY_URL` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `FLEET_DESIRED_WORKER_COUNT` | `docker-compose.release.yml`, `docker-compose.yml` |
| `FLEET_DRAIN_GRACE_SECONDS` | `api/fleet_agent.py` |
| `FLEET_EDGE_MODE` | `api/api.py` |
| `FLEET_EXPECTED_WORKER_IMAGE_DIGEST` | `docker-compose.broker-worker.yml`, `docker-compose.worker.yml` |
| `FLEET_GATEWAY_BIND_HOST` | `docker-compose.release.yml`, `docker-compose.yml` |
| `FLEET_GATEWAY_PROXY_SECRET` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `FLEET_HEARTBEAT_TIMEOUT_SECONDS` | `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `FLEET_JOIN_RATE_LIMIT_PER_MINUTE` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `FLEET_NODE_ID` | `api/worker.py`, `docker-compose.broker-worker.yml`, `docker-compose.worker.yml` |
| `FLEET_OPERATOR_TOKEN` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml`, `scripts/fleet_acceptance.py` |
| `FLEET_OVERLAY_CIDR` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `FLEET_RECONCILE_MODE` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `FLEET_RESULTS_DIR` | `docker-compose.broker-worker.yml`, `docker-compose.worker.yml` |
| `FLEET_RUNTIME_DIR` | `docker-compose.broker-worker.yml`, `docker-compose.worker.yml` |
| `FLEET_STATE_PATH` | `api/fleet_agent.py` |
| `FLEET_TLS_PORT` | `docker-compose.release.yml`, `docker-compose.yml` |
| `FLEET_WIREGUARD_ENDPOINT` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `FLEET_WIREGUARD_PUBLIC_KEY` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `FLEET_WORKER_CPU_LIMIT` | `docker-compose.broker-worker.yml`, `docker-compose.worker.yml` |
| `FLEET_WORKER_ENV_FILE` | `docker-compose.worker.yml` |
| `FLEET_WORKER_IMAGE` | `docker-compose.broker-worker.yml`, `docker-compose.worker.yml` |
| `FLEET_WORKER_IMAGE_DIGEST` | `api/api.py`, `api/fleet_worker_entrypoint.py`, `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `FLEET_WORKER_MEMORY_LIMIT` | `docker-compose.broker-worker.yml`, `docker-compose.worker.yml` |
| `FULL_COVERAGE_ALLOCATION_DEFAULT` | `api/parallel_scan.py` |
| `GITHUB_TOKEN` | `scanner/scanner.py` |
| `GIT_COMMIT` | `api/api.py`, `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml`, `scanner/scanner.py` |
| `HEARTBEAT_INTERVAL_SECONDS` | `api/worker.py` |
| `HF_TOKEN` | `scanner/scanner_tools/model_intake.py` |
| `HIBP_API_KEY` | `scanner/scanner.py` |
| `HOSTNAME` | `api/broker_worker.py`, `api/worker.py` |
| `HOST_RESULTS_PATH` | `api/api.py` |
| `LOCAL_ENV_FILE` | `api/api.py` |
| `MINIO_BUCKET` | `docker-compose.release.yml`, `docker-compose.yml` |
| `MINIO_PORT` | `docker-compose.release.yml`, `docker-compose.yml` |
| `MINIO_ROOT_PASSWORD` | `docker-compose.release.yml`, `docker-compose.yml` |
| `MINIO_ROOT_USER` | `docker-compose.release.yml`, `docker-compose.yml` |
| `MODEL_INTAKE_ADMISSION_SIGNING_KEY_PEM` | `docker-compose.release.yml`, `docker-compose.worker.yml`, `docker-compose.yml`, `scanner/scanner_tools/model_intake_admission.py` |
| `MODEL_INTAKE_ADMISSION_TRUSTED_PUBLIC_KEYS` | `docker-compose.release.yml`, `docker-compose.yml`, `scanner/scanner_tools/model_intake_admission.py` |
| `MODEL_INTAKE_ALLOWED_HOSTS` | `scanner/scanner_tools/model_intake_acquisition.py` |
| `MODEL_INTAKE_ALLOWED_PORTS` | `scanner/scanner_tools/model_intake_acquisition.py` |
| `MODEL_INTAKE_ALLOW_INSECURE_HTTP` | `scanner/scanner_tools/model_intake_acquisition.py` |
| `MODEL_INTAKE_ALLOW_LOCAL_FILES` | `scanner/scanner_tools/model_intake.py` |
| `MODEL_INTAKE_ALLOW_PRIVATE_NETWORKS` | `scanner/scanner_tools/model_intake_acquisition.py` |
| `MODEL_INTAKE_QUARANTINE_DIR` | `api/api.py`, `scanner/scanner_tools/model_intake.py` |
| `MODEL_INTAKE_SANDBOX_NETWORK_MODE` | `scanner/scanner_tools/model_intake_sandbox.py` |
| `MODEL_INTAKE_SANDBOX_NO_NEW_PRIVILEGES` | `scanner/scanner_tools/model_intake_sandbox.py` |
| `MODEL_INTAKE_SANDBOX_QUEUE_DIR` | `scanner/scanner_tools/model_intake.py` |
| `MODEL_INTAKE_SANDBOX_READ_ONLY` | `scanner/scanner_tools/model_intake_sandbox.py` |
| `MODEL_INTAKE_TRUSTED_KEY_SHA256` | `scanner/scanner_tools/model_intake.py` |
| `MODEL_INTAKE_TRUSTED_SIGNING_KEYS` | `scanner/scanner_tools/model_intake.py` |
| `NUCLEI_TEMPLATES` | `scanner/scanner_tools/nuclei.py` |
| `PARALLEL_SHARD_CONCURRENCY_HARD_MAX` | `api/worker.py` |
| `PARALLEL_SHARD_MAX_PER_PARENT` | `api/worker.py` |
| `PARALLEL_SHARD_REQUEUE_DELAY_SECONDS` | `api/worker.py` |
| `PARALLEL_SHARD_SLOT_TTL_SECONDS` | `api/worker.py` |
| `PARENT_STALE_TIMEOUT_MINUTES` | `api/api.py` |
| `PATH` | `scanner/scanner_tools/model_intake_scanners.py` |
| `PLAYWRIGHT_BROWSERS_PATH` | `api/ai_gate/targets/widget_playwright.py`, `scanner/scanner_tools/form_login.py`, `scanner/scanner_tools/http_scanner.py` |
| `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD` | `scanner/scanner_tools/form_login.py`, `scanner/scanner_tools/http_scanner.py` |
| `POSTGRES_PASSWORD` | `docker-compose.release.yml`, `docker-compose.yml` |
| `POSTGRES_PORT` | `docker-compose.release.yml`, `docker-compose.yml` |
| `PROOF_REQUIRED_FOR_SMART` | `api/api.py`, `api/retest_contract.py`, `api/worker.py`, `scanner/scanner.py` |
| `REDIS_PASSWORD` | `docker-compose.release.yml`, `docker-compose.yml` |
| `REDIS_PORT` | `docker-compose.release.yml`, `docker-compose.yml` |
| `REDIS_URL` | `api/api.py`, `api/gungnir_worker.py`, `api/worker.py`, `scanner/gungnir_worker.py` |
| `RESEARCH_EPISODE_ABANDON_TTL_HOURS` | `api/api.py` |
| `RESULTS_DIR` | `api/api.py`, `api/secret_store.py`, `api/worker.py` |
| `RETEST_AI_BUDGET_SECONDS` | `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `RETEST_AI_CIRCUIT_COOLDOWN_SECONDS` | `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `RETEST_AI_CIRCUIT_ERROR_THRESHOLD` | `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `RETEST_AI_CIRCUIT_KEY` | `api/worker.py` |
| `RETEST_AI_CIRCUIT_WINDOW_SECONDS` | `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `RETEST_INCONCLUSIVE_MAX_REQUEUE` | `api/worker.py` |
| `RETEST_INCONCLUSIVE_RETRY_AFTER_HOURS` | `api/worker.py` |
| `RETEST_MAX_PARALLEL` | `api/worker.py` |
| `RETEST_QUEUE_MAX_RETRIES` | `api/worker.py` |
| `RETEST_QUEUE_NAME` | `api/api.py`, `api/worker.py` |
| `RETEST_REQUEUE_DELAY_SECONDS` | `api/worker.py` |
| `RETEST_RUNNING_STALE_SECONDS` | `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `RETEST_RUNNING_TIMEOUT_MINUTES` | `api/api.py` |
| `RETEST_SLOT_KEY` | `api/worker.py` |
| `RETEST_SLOT_TTL_SECONDS` | `api/worker.py` |
| `RETEST_SLOT_WAIT_MAX_SECONDS` | `api/worker.py` |
| `RETEST_STALE_BATCH_SIZE` | `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `RETEST_STALE_CHECK_INTERVAL_SECONDS` | `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `RETEST_STALE_REQUEUE_LIMIT` | `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `RETEST_WATCHDOG_LOCK_KEY` | `api/worker.py` |
| `RETEST_WATCHDOG_LOCK_SECONDS` | `api/worker.py` |
| `SCANNER_DALFOX_DEEP_DOMXSS` | `scanner/scanner_tools/active_checks.py` |
| `SCANNER_DEBUG_ENDPOINTS` | `scanner/scanner.py` |
| `SCANNER_DEBUG_NOSQL` | `scanner/scanner.py`, `scanner/scanner_tools/active_checks.py` |
| `SCANNER_DEBUG_SQLMAP` | `scanner/scanner.py` |
| `SCANNER_DNS_RESOLVERS` | `scanner/scanner.py` |
| `SCANNER_IMAGE_REPO` | `docker-compose.release.yml` |
| `SCANNER_IMAGE_TAG` | `docker-compose.release.yml` |
| `SCANNER_MAX_CONCURRENT` | `scanner/scanner_tools/common.py` |
| `SCANNER_SUBPROCESS_ARTIFACT_MAX_BYTES` | `scanner/scanner_tools/common.py` |
| `SCANNER_SUBPROCESS_RECEIPT_LIMIT` | `scanner/scanner_tools/common.py` |
| `SCANNER_VERSION` | `api/api.py`, `api/worker.py`, `docker-compose.release.yml`, `docker-compose.yml`, `scanner/scanner.py` |
| `SCAN_CANCEL_POLL_SECONDS` | `api/worker.py` |
| `SCAN_CHECKPOINT_FILE` | `scanner/scanner.py` |
| `SCAN_COOPERATIVE_CANCEL_GRACE_SECONDS` | `api/worker.py` |
| `SCAN_FAULTHANDLER` | `scanner/scanner.py` |
| `SCAN_FORCED_BROWSING_MAX_SECONDS` | `scanner/scanner.py` |
| `SCAN_FORCE_EXIT_ON_SHUTDOWN_TIMEOUT` | `scanner/scanner.py` |
| `SCAN_KILL_GRACE_SECONDS` | `api/worker.py` |
| `SCAN_LOG_TAIL` | `api/worker.py` |
| `SCAN_LOG_TTL_SECONDS` | `api/worker.py` |
| `SCAN_MAX_DURATION_DEFAULT_MINUTES` | `api/worker.py` |
| `SCAN_MAX_DURATION_MINUTES` | `api/worker.py` |
| `SCAN_PHASE4_CANCEL_GRACE` | `scanner/scanner.py` |
| `SCAN_PHASE4_LOGS` | `scanner/scanner.py` |
| `SCAN_PHASE4_MAX_SECONDS` | `scanner/scanner.py` |
| `SCAN_PHASE4_TRACE` | `scanner/scanner.py` |
| `SCAN_SETTINGS_KEY` | `api/api.py` |
| `SCAN_SHUTDOWN_GRACE_SECONDS` | `scanner/scanner.py` |
| `SCAN_VERIFICATION_MAX` | `scanner/scanner.py` |
| `SHAKERSCAN_API_PORT` | `docker-compose.release.yml`, `docker-compose.yml` |
| `SHAKERSCAN_API_URL` | `scripts/shakerscan_mcp.py` |
| `SHAKERSCAN_ASM_DISPATCH_INTERVAL` | `api/api.py` |
| `SHAKERSCAN_BIND_HOST` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `SHAKERSCAN_BROKER_LEASE` | `api/broker_worker.py`, `api/worker.py` |
| `SHAKERSCAN_BROKER_LEASE_SECONDS` | `api/api.py` |
| `SHAKERSCAN_BROKER_MAX_ARTIFACT_BYTES` | `api/api.py` |
| `SHAKERSCAN_BROKER_MAX_RESULT_BYTES` | `api/api.py` |
| `SHAKERSCAN_CANCEL_FILE` | `scanner/scanner_tools/cancellation.py`, `scanner/scanner_tools/common.py` |
| `SHAKERSCAN_CORS_ALLOW_ORIGINS` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `SHAKERSCAN_CORS_ALLOW_ORIGIN_REGEX` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `SHAKERSCAN_CUSTOM_WORDLIST` | `scanner/scanner_tools/discovery.py` |
| `SHAKERSCAN_DATA_BIND_HOST` | `docker-compose.release.yml`, `docker-compose.yml` |
| `SHAKERSCAN_DEBUG_POST_INFER` | `scanner/scanner.py` |
| `SHAKERSCAN_ENABLE_ADAPTIVE_THROTTLE` | `scanner/scanner.py` |
| `SHAKERSCAN_ENFORCE_FLEET_LIMITS` | `api/worker.py` |
| `SHAKERSCAN_FLEET_OPERATOR_TOKEN` | `scripts/fleet_acceptance.py` |
| `SHAKERSCAN_HOST_PLATFORM` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `SHAKERSCAN_MAX_ACTIVE_SCANS` | `api/api.py`, `api/worker.py` |
| `SHAKERSCAN_MAX_WORKERS` | `api/api.py`, `docker-compose.yml` |
| `SHAKERSCAN_MCP_ALLOW_REMOTE_API` | `scripts/shakerscan_mcp.py` |
| `SHAKERSCAN_MCP_TIMEOUT_SECONDS` | `scripts/shakerscan_mcp.py` |
| `SHAKERSCAN_NODE_ID` | `api/artifact_storage.py`, `api/broker_worker.py`, `api/fleet_worker_entrypoint.py`, `api/worker.py` |
| `SHAKERSCAN_NODE_LABELS_JSON` | `api/worker.py` |
| `SHAKERSCAN_PAYLOAD_PACK_MAX` | `scanner/scanner_tools/active_checks.py` |
| `SHAKERSCAN_PER_WORKER_MEM_GB` | `api/api.py`, `docker-compose.yml` |
| `SHAKERSCAN_PLATFORM_MEMORY_RESERVE_GB` | `api/api.py`, `docker-compose.yml` |
| `SHAKERSCAN_PUBLIC_API_URL` | `docker-compose.release.yml`, `docker-compose.yml` |
| `SHAKERSCAN_PUBLIC_HOST` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `SHAKERSCAN_QUEUE_CONSUMER_GROUP` | `api/job_queue.py`, `docker-compose.release.yml`, `docker-compose.worker.yml`, `docker-compose.yml` |
| `SHAKERSCAN_QUEUE_LEASE_HEARTBEAT_FAILURE_LIMIT` | `api/worker.py`, `docker-compose.release.yml`, `docker-compose.worker.yml`, `docker-compose.yml` |
| `SHAKERSCAN_QUEUE_LEASE_HEARTBEAT_SECONDS` | `api/worker.py`, `docker-compose.release.yml`, `docker-compose.worker.yml`, `docker-compose.yml` |
| `SHAKERSCAN_QUEUE_MAX_DELIVERY_ATTEMPTS` | `api/api.py`, `api/worker.py`, `docker-compose.release.yml`, `docker-compose.worker.yml`, `docker-compose.yml` |
| `SHAKERSCAN_QUEUE_ROUTE_MAX` | `api/job_queue.py` |
| `SHAKERSCAN_QUEUE_VISIBILITY_TIMEOUT_SECONDS` | `api/worker.py`, `docker-compose.release.yml`, `docker-compose.worker.yml`, `docker-compose.yml` |
| `SHAKERSCAN_REQUEST_BUDGET_DOMAIN` | `scanner/scanner.py` |
| `SHAKERSCAN_REQUEST_BUDGET_LIMIT` | `scanner/scanner.py` |
| `SHAKERSCAN_REQUEST_BUDGET_MODE` | `api/worker.py`, `scanner/scanner.py` |
| `SHAKERSCAN_REQUEST_BUDGET_RESERVED` | `scanner/scanner.py` |
| `SHAKERSCAN_SCAN_SLOT_MAX_WAIT_SECONDS` | `api/worker.py` |
| `SHAKERSCAN_SCAN_SLOT_TTL_SECONDS` | `api/worker.py` |
| `SHAKERSCAN_STALE_DURATION_GRACE_MIN` | `api/api.py` |
| `SHAKERSCAN_STALE_FAIL_AFTER_SECONDS` | `api/worker.py` |
| `SHAKERSCAN_STREAM_SCANNER_LOGS` | `api/worker.py` |
| `SHAKERSCAN_TRUSTED_REMOTE_TRANSPORT` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `SHAKERSCAN_UI_PORT` | `api/api.py`, `docker-compose.release.yml`, `docker-compose.yml` |
| `SHAKERSCAN_WORKER_FAIL_CLOSED` | `api/worker.py` |
| `SHAKERSCAN_WORKER_IMAGE_DIGEST` | `scanner/scanner_tools/model_intake_scanners.py` |
| `SHAKERSCAN_WORKER_MEM_LIMIT_GB` | `api/api.py` |
| `SMART_BOLA_LANE_MAX_SECONDS` | `scanner/scanner.py` |
| `TESTSSL_BIN` | `scanner/scanner_tools/tls_scanner.py` |
| `UI_IMAGE_REPO` | `docker-compose.release.yml` |
| `VERIFICATION_MIN_SEVERITY` | `api/api.py`, `api/retest_contract.py`, `api/worker.py`, `scanner/scanner.py` |
| `VIRUSTOTAL_API_KEY` | `scanner/scanner.py` |
| `WORKER_ID` | `api/broker_worker.py`, `api/worker.py` |
| `WORKER_IMAGE` | `api/worker.py` |
| `WORKER_PREFLIGHT_ENABLED` | `api/worker.py` |
| `WORKER_PREFLIGHT_REQUIRE_SCANNER` | `api/worker.py` |
| `WORKER_PREFLIGHT_TIMEOUT_SECONDS` | `api/worker.py` |
| `WORKER_QUEUE_BLOCK_SECONDS` | `api/worker.py` |
| `WORKER_REDIS_SOCKET_TIMEOUT_SECONDS` | `api/worker.py` |

### UI Pages

| Route | Source |
|---|---|
| `/ai-gate` | `ui/src/app/ai-gate/page.tsx` |
| `/asm` | `ui/src/app/asm/page.tsx` |
| `/campaigns/{id}` | `ui/src/app/campaigns/[id]/page.tsx` |
| `/campaigns` | `ui/src/app/campaigns/page.tsx` |
| `/deep-hunt/experiment` | `ui/src/app/deep-hunt/experiment/page.tsx` |
| `/deep-hunt/explorer` | `ui/src/app/deep-hunt/explorer/page.tsx` |
| `/deep-hunt/leads` | `ui/src/app/deep-hunt/leads/page.tsx` |
| `/deep-hunt/operator` | `ui/src/app/deep-hunt/operator/page.tsx` |
| `/deep-hunt` | `ui/src/app/deep-hunt/page.tsx` |
| `/deep-hunt/runs/{id}` | `ui/src/app/deep-hunt/runs/[id]/page.tsx` |
| `/docs` | `ui/src/app/docs/page.tsx` |
| `/evidence` | `ui/src/app/evidence/page.tsx` |
| `/exceptions` | `ui/src/app/exceptions/page.tsx` |
| `/exposure` | `ui/src/app/exposure/page.tsx` |
| `/findings/{id}` | `ui/src/app/findings/[id]/page.tsx` |
| `/findings` | `ui/src/app/findings/page.tsx` |
| `/fleet` | `ui/src/app/fleet/page.tsx` |
| `/interactive` | `ui/src/app/interactive/page.tsx` |
| `/model-intake` | `ui/src/app/model-intake/page.tsx` |
| `/` | `ui/src/app/page.tsx` |
| `/scan/new` | `ui/src/app/scan/new/page.tsx` |
| `/scans/{id}` | `ui/src/app/scans/[id]/page.tsx` |
| `/scans` | `ui/src/app/scans/page.tsx` |
| `/schedules` | `ui/src/app/schedules/page.tsx` |
| `/settings/ai-ops-router` | `ui/src/app/settings/ai-ops-router/page.tsx` |
| `/settings/arsenal` | `ui/src/app/settings/arsenal/page.tsx` |
| `/settings` | `ui/src/app/settings/page.tsx` |
| `/settings/policy-profiles` | `ui/src/app/settings/policy-profiles/page.tsx` |
| `/targets/{id}/graph` | `ui/src/app/targets/[id]/graph/page.tsx` |
| `/targets` | `ui/src/app/targets/page.tsx` |
| `/timeline` | `ui/src/app/timeline/page.tsx` |

### Skills, Slash Commands, And Subagents

| Skill | Purpose | Source |
|---|---|---|
| `ai-security-session` | Interactive Testing through ShakerScan's `/session` API. Use when asked to test manually, open an interactive browser session, exercise authentication workflows, or perform BOLA/IDOR endpoint replay. | `skills/ai-security-session/SKILL.md` |
| `content-discovery` | Build target-specific content discovery seeds, path lists, and ShakerScan scan inputs from scan results, JS analysis, framework clues, and exposed docs. Use when asked for content discovery, wordlist generation, ffuf seeds, admin path discovery, hidden file discovery, route discovery, or custom endpoint seeding. | `skills/content-discovery/SKILL.md` |
| `js-analyze` | Analyze JavaScript bundles, frontend routes, browser-captured APIs, libraries, and secrets for a ShakerScan target or completed scan. Use when asked for JS analysis, route analysis, frontend endpoint discovery, library review, source-map hints, or to build `custom_endpoints` for a ShakerScan scan. | `skills/js-analyze/SKILL.md` |
| `research-agent` | Run ShakerScan Deep Hunt: the current coding agent performs free-form, AI-driven exploration and bounded active exploitation through /agent/hunt/* while ShakerScan enforces target scope, approvals, budgets, evidence provenance, and deterministic finding verification. Use for “deep hunt”, “autonomous hunt”, or “investigate autonomously”; do not use for ordinary DAST scans. | `skills/research-agent/SKILL.md` |
| `review-skills` | Review ShakerScan skills, commands, and subagents for broken references, invalid Claude Code configuration, prompt anti-patterns, missing hard gates, missing outputs, and weak operational guidance. Use when asked to audit, review, or quality-check the skill system itself. | `skills/review-skills/SKILL.md` |
| `shakerscan` | Operate ShakerScan. Route scan requests to Web DAST, Deep Hunt requests to the keyless AI investigator, and manual browser work to Interactive Testing; also manage targets, Continuous ASM, findings, AI Gate, Model Intake, evidence, schedules, local workers, and opt-in Linux fleets. | `skills/shakerscan/SKILL.md` |

| Slash command | Title | Purpose | Source |
|---|---|---|---|
| `/ai-gate` | AI Gate | Create/list AI Gate targets and queue AI safety scans. | `.claude/commands/ai-gate.md` |
| `/ai-security-session` | Interactive Testing | Drive an authorized Interactive Testing browser workflow with the compatibility-named `ai-security-session` skill. | `.claude/commands/ai-security-session.md` |
| `/content-discovery` | Content Discovery | Build a high-signal route and file discovery plan for a target using ShakerScan evidence, JS outputs, and framework clues. | `.claude/commands/content-discovery.md` |
| `/deep-hunt` | Deep Hunt | Run an authorized, AI-driven Deep Hunt against the supplied target. | `.claude/commands/deep-hunt.md` |
| `/findings` | List Security Findings | Show security findings from scans. | `.claude/commands/findings.md` |
| `/js-analyze` | JS Analyze | Run JavaScript and frontend attack-surface analysis for a target, completed scan, or supplied JS bundle set. | `.claude/commands/js-analyze.md` |
| `/research` | Deep Hunt compatibility command | Use the `research-agent` skill. | `.claude/commands/research.md` |
| `/review-skills` | Review Skills | Review all ShakerScan skills, commands, and agents for prompt bugs and quality gaps. | `.claude/commands/review-skills.md` |
| `/save-finding` | Save Finding | Save an evidence-backed finding from authorized manual or interactive testing. | `.claude/commands/save-finding.md` |
| `/scan-full` | Full Security Assessment | Run a comprehensive security assessment with the Full profile, including authorized active | `.claude/commands/scan-full.md` |
| `/scan-smart` | Smart Adaptive Scan | Run an intelligent adaptive security scan that adjusts based on findings. | `.claude/commands/scan-smart.md` |
| `/scan` | Scan a target | Run a security scan on the specified target. | `.claude/commands/scan.md` |
| `/status` | Scanner Status | Check the status of ShakerScan. | `.claude/commands/status.md` |
| `/subdomains` | Subdomain Discovery | Discover subdomains for a domain using CT logs and passive sources. | `.claude/commands/subdomains.md` |
| `/workers` | Worker Management | View and scale scanner workers. | `.claude/commands/workers.md` |

| Subagent | Model | Purpose | Source |
|---|---|---|---|
| `content-discovery-agent` | sonnet | Use this agent for high-signal route and file discovery, admin path seeding, API/spec path generation, and producing custom_list and custom_endpoints output for ShakerScan. | `.claude/agents/content-discovery-agent.md` |
| `js-analysis-agent` | sonnet | Use this agent for JavaScript bundle analysis, frontend route discovery, browser-captured API review, library/version review, source-map hints, and ShakerScan custom_endpoints generation. | `.claude/agents/js-analysis-agent.md` |
| `skills-reviewer` | opus | Use PROACTIVELY to review ShakerScan skills, commands, and agents for prompt bugs, bad gates, invalid frontmatter, broken references, or weak output contracts. | `.claude/agents/skills-reviewer.md` |

### Scanner Module Inventory

`access_control_checks.py`, `active_checks.py`, `active_enrichment_policy.py`, `active_prioritization.py`, `adaptive_throttle.py`, `ai_classifier.py`, `api_auth.py`, `api_security.py`, `approval_checks.py`, `asn_discovery.py`, `attack_chains.py`, `attempt_telemetry.py`, `auth_session.py`, `benchmark_summary.py`, `bola_comparison.py`, `brand_protection.py`, `breach_check.py`, `build_fingerprint.py`, `cancellation.py`, `client_side.py`, `common.py`, `completion_status.py`, `compliance_mapper.py`, `coverage_tracker.py`, `credential_check.py`, `critical_checks.py`, `ct_monitor.py`, `data_exposure.py`, `deduplication_engine.py`, `deserialization_tests.py`, `discovery.py`, `dns_enhanced.py`, `dom_xss_analyzer.py`, `domain_intel.py`, `exposure_markers.py`, `file_upload_tests.py`, `finding_correlator.py`, `finding_validator.py`, `focused_scope.py`, `form_login.py`, `github_recon.py`, `google_dorking.py`, `gopher_payloads.py`, `graphql_schema_recovery.py`, `grpc_discovery.py`, `gungnir.py`, `har_discovery.py`, `hash_routes.py`, `health_check.py`, `http_scanner.py`, `hunter_summary.py`, `infrastructure_checks.py`, `injection_extra_checks.py`, `ip_reputation.py`, `logging_checks.py`, `model_intake.py`, `model_intake_acquisition.py`, `model_intake_admission.py`, `model_intake_archives.py`, `model_intake_attestation.py`, `model_intake_evaluation.py`, `model_intake_registry.py`, `model_intake_retention.py`, `model_intake_sandbox.py`, `model_intake_scanners.py`, `network_services.py`, `nmap.py`, `nuclei.py`, `oauth_auth.py`, `oauth_tests.py`, `phase4_checks.py`, `proof_of_exploit.py`, `race_condition_tests.py`, `remediation_kb.py`, `report_gating.py`, `request_meter.py`, `resource_propagation.py`, `sarif_output.py`, `scan_delta.py`, `signal_types.py`, `smtp_scanner.py`, `ssh_scanner.py`, `subdomain_discovery.py`, `subfinder.py`, `tech_discovery.py`, `tls_scanner.py`, `vendor_risk.py`, `verification_engine.py`, `verification_phase.py`, `wayback_discovery.py`, `webhook_checks.py`, `websocket_security.py`

### Durable Storage Inventory

| Table | Declared by |
|---|---|
| `agent_context_packs` | `api/retest_contract.py` |
| `agent_decision_traces` | `api/retest_contract.py` |
| `agent_hunt_runs` | `api/retest_contract.py` |
| `ai_surface_attempts` | `db/init.sql` |
| `ai_surfaces` | `db/init.sql` |
| `ai_target_credentials` | `db/init.sql` |
| `ai_target_principals` | `api/retest_contract.py` |
| `ai_targets` | `db/init.sql` |
| `app_schema_migrations` | `db/init.sql` |
| `app_settings` | `api/retest_contract.py` |
| `application_graph_edges` | `db/init.sql` |
| `application_graph_nodes` | `db/init.sql` |
| `approval_receipts` | `api/retest_contract.py` |
| `asm_endpoint_attempts` | `db/init.sql` |
| `broker_job_leases` | `db/init.sql` |
| `broker_job_results` | `db/init.sql` |
| `campaign_actions` | `api/retest_contract.py` |
| `campaigns` | `api/retest_contract.py` |
| `command_results` | `api/retest_contract.py` |
| `discovery_runs` | `db/init.sql` |
| `evidence_instances` | `api/retest_contract.py` |
| `evidence_objects` | `db/init.sql` |
| `evidence_retention_previews` | `db/init.sql` |
| `export_events` | `db/init.sql` |
| `finding_exceptions` | `db/init.sql` |
| `finding_verifications` | `db/init.sql` |
| `findings` | `db/init.sql` |
| `fleet_node_events` | `db/init.sql` |
| `hypotheses` | `api/retest_contract.py` |
| `model_intake_admission_events` | `db/init.sql` |
| `model_intake_admissions` | `db/init.sql` |
| `model_intake_trust_anchors` | `db/init.sql` |
| `node_credentials` | `db/init.sql` |
| `node_join_tokens` | `db/init.sql` |
| `nodes` | `db/init.sql` |
| `operation_plans` | `api/retest_contract.py` |
| `policy_profiles` | `db/init.sql` |
| `refuter_reviews` | `api/retest_contract.py` |
| `research_decisions` | `api/retest_contract.py` |
| `research_episodes` | `api/retest_contract.py` |
| `research_events` | `api/retest_contract.py` |
| `research_observations` | `api/retest_contract.py` |
| `scan_artifacts` | `db/init.sql` |
| `scan_campaigns` | `db/init.sql` |
| `scans` | `db/init.sql` |
| `schedules` | `db/init.sql` |
| `scope_receipts` | `api/retest_contract.py` |
| `target_credential_profiles` | `api/retest_contract.py` |
| `target_endpoint_expectations` | `api/retest_contract.py` |
| `target_endpoints` | `db/init.sql` |
| `target_invariant_contracts` | `api/retest_contract.py` |
| `target_principal_provisioning_attempts` | `api/retest_contract.py` |
| `target_principals` | `api/retest_contract.py` |
| `targets` | `db/init.sql` |
| `tool_receipts` | `api/retest_contract.py` |

<!-- END GENERATED CAPABILITY INVENTORY -->

---

## 18. Where to go deeper

| Topic | Document |
|-------|----------|
| Agent-facing API how-to (request bodies, examples) | [`CLAUDE.md`](../CLAUDE.md) · [`AGENTS.md`](../AGENTS.md) |
| Getting started, install, product tour | [`README.md`](../README.md) |
| Smart scan budgets, SLOs, release gates | [`SMART_SCAN_POLICY.md`](SMART_SCAN_POLICY.md) |
| OWASP coverage and intentional gaps | [`owasp-coverage-matrix.md`](owasp-coverage-matrix.md) |
| Future product roadmap | [`proposed-next-steps.md`](proposed-next-steps.md) |
| Release readiness and publishing checklist | [`release-readiness.md`](release-readiness.md) |
| AI test workflows + Honey contract | [`AI_TEST_WORKFLOWS.md`](AI_TEST_WORKFLOWS.md) |
| Interactive AI security sessions | [`INTERACTIVE_SESSIONS_GUIDE.md`](INTERACTIVE_SESSIONS_GUIDE.md) |
| DAST execution and Continuous ASM architecture | [`dast-asm-architecture.md`](dast-asm-architecture.md) |
| Multi-node fleet architecture (RFC) | [`multi-node-architecture.md`](multi-node-architecture.md) |
| Multi-node setup and operations | [`multi-node-guide.md`](multi-node-guide.md) |

> Reminder: where any doc and the code disagree, the **code, DB schema, and tests win**. This
> reference is a map, not the territory.
