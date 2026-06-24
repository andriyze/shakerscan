# Juice Shop Crit/High DAST Detection — Gap Analysis & Handoff

> **ARCHIVED (2026-06-23).** Superseded by [proposed-next-steps.md](../proposed-next-steps.md) §1
> (detection recall) and the committed benchmark scorecards in `results/benchmark-runs/`, which now
> machine-track the same misses (`sqli-login`, `nosqli-reviews`). Kept for the per-entry gap detail.

**Goal:** make ShakerScan's DAST engine (universal, not Juice-Shop-tuned) detect ≥70%
of Juice Shop's Critical/High vulnerabilities. Juice Shop is the *benchmark*; every
change must be a generic capability that works on any app with that vuln class.

**Status at handoff:** universal detector + infra improvements shipped and committed
on `docs/functionality-reference`. Confirmed clean-target detection = **4/27 (15%)**;
the realistic ceiling on this 27-entry key is ~20–22/27 (a hard tail needs
capabilities beyond generic black-box DAST). Remaining work is batched below.

Measurement tooling: `/tmp/juice_bench/answer_key.json` (27 entries) + `measure.py`
(route-anchored matching). Protocol: restart Juice Shop (clean DB/oracle) → wipe
target findings (`DELETE FROM findings WHERE target_id=…`) → scan → measure.
See memory `juice-shop-dast-benchmark-protocol`.

---

## Shipped this session (committed)

**Universal detectors**
- DOM-XSS: iframe `javascript:`/`srcdoc` vectors that survive framework HTML
  sanitizers (Angular/React/DOMPurify). `active_checks.hash_route_dom_xss_test`.
- Reflected-XSS: browser-prove *all* reflected contexts (not just script/angular) +
  explicit CVSS so a proven finding isn't capped to medium. `active_checks.smart_xss_test`.
- Exposure: directory-listing → `harvest_listed_files` (parse listed files, fetch,
  classify) + generic encoded-null-byte allowlist bypass (`name%2500.md`, CWE-158);
  serve-index/autoindex markers; `_fetch_url` IncompleteRead robustness; smart scans
  now enable `exposure_infra`; curated dirs always tested. `infrastructure_checks.py`.
- BFLA: content-gated auto-CRUD model-collection probe — fires only when an unauth
  collection leaks PII/credentials/tokens (no FP on public catalogs). `access_control_checks.py`.
- JWT: wire `jwt_comprehensive_test` results (alg:none/weak-secret/alg-confusion)
  into findings — the consumer read non-existent keys so all JWT findings were dropped.

**Infra / correctness (mostly user-requested)**
- Fleet-aware shard concurrency (fixed idle workers; one parent can fill the fleet).
- Coverage dynamic-batch `max_duration` scales with active budget (fixed 9-min shard kills).
- Retest 500 fixed (missing `finding_verifications.campaign_id` column).
- Build label = real commit (provenance) + `build_current` fingerprint-authoritative.
- Runtime-mount test fixed; compose comments corrected; fingerprint covers detector modules.

---

## Confirmed detections (4/27, clean single smart scan)
- `sqli-product-search` — SQLi on `/rest/products/search`.
- `xss-dom-search` — DOM-XSS via the new iframe vector (the headline XSS gap, now closed).
- `bac-user-enumeration-api` — BFLA on `/api/Users` (content-gated).
- `sde-exposed-metrics` — `/metrics` debug endpoint (forced browsing).

---

## Key architectural findings (act on these before more grinding)

1. **Coverage mode loses the crit/high.** Coverage child shards run zero-rediscovery
   (no browser crawl → no DOM-XSS/hash routes) and fragment the *global* posture checks
   (forced-browsing, exposure, dir-listing) across shards. Juice Shop's crit/highs live
   mostly in those global+browser checks, which only a **single smart scan** runs in one
   pass. → For broad real-world coverage, coverage mode must also run global+browser
   checks once (e.g. on the recon/first shard) — today it effectively skips them.
2. **Targets degrade under repeated scanning.** Stored payloads/accounts accumulate and
   cause run-to-run variance. Always restart the lab target before a measurement.
3. **Findings dedup hides re-scan results.** `UNIQUE(target_id, fingerprint)` keeps the
   first scan's id; measure from the scan's own report or wipe findings first.

---

## Per-entry gap analysis (the path to ≥70%)

### Achievable next (batch into ONE deploy + ONE measurement) — ~ +11
| entry | class | what's needed |
|---|---|---|
| sqli-login-bypass | sqli | found intermittently; ensure login POST body SQLi runs in single scan |
| nosqli-order-tracking / review-update / command-dos (3) | nosqli | **NoSQLi tests only hit `base_url` today** — wire `nosql_injection_test*` to discovered GET path-id + JSON-body endpoints |
| sde-confidential-document / ftp-directory-listing / forgotten-backup-nullbyte / encryption-keys / access-logs (5) | exposure | exposure chain now fixed (was a 4-bug chain); validate on clean target — high confidence these now fire |
| xss-reflected-track-result | xss | reflected-XSS browser proof now attempts all contexts; validate |
| bac-basket-bola | bola | needs object-ID harvest + user1/user2 replay on `/rest/basket/{id}` (stateful) |

### Stored XSS (3) — moderate, needs store→render→prove
`xss-stored-product-tampering`, `xss-stored-feedback`, `xss-header-true-client-ip`.
POST/body XSS path only checks the *immediate* response (Juice Shop stores then renders
in the SPA → `in_json` reflection → medium, no proof). Need: inject → re-fetch the
resource → browser-prove against the rendering view. The render URL is app-specific, so
a defensible universal signal = persisted executable payload (iframe/script) round-tripping
unescaped through a GET, optionally browser-proven.

### Hard tail (likely beyond generic black-box DAST) — ~5
`auth-jwt-forged-rsa` (RSA pubkey recovery + HS/RS confusion), `rce-yaml-deserialization`
(auth-gated, crafted payload), `open-redirect-allowlist-bypass` (embedded-allowlisted-URL
bypass; naive payloads return 406), `sde-product-blueprint` (a static `.stl` asset),
`bac-product-tampering` (unauth write/BFLA — non-destructive write checks are Lab/deep
work). These cap the realistic ceiling near 20–22/27.

### Smaller universal wins to verify
`xxe-file-upload` (XML upload), `ssrf-profile-image-url` (URL-valued param), `bac-admin-section`
(hash route — not forced-browsable; needs SPA route check), `auth-jwt-none-alg` (JWT
consumer fixed; verify it fires with the supplied Bearer token).

---

## Recommended next step
One batched deploy: (a) NoSQLi against discovered endpoints, (b) store-then-render
stored-XSS proof, (c) confirm exposure chain + JWT + XXE/SSRF on a **fresh** target,
then a **single** measurement scan. Expected ~15–18/27; reaching 19 also needs
stored-XSS (3) and BOLA (1) to land. Track coverage-mode global-check fragmentation
(finding #1) separately — it matters more for real-world breadth than for this key.
