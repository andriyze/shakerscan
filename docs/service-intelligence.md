# Service Intelligence

**Status:** maintained service-intelligence and Hunt-integration reference.
**Reconciled:** 2026-09-23. This document describes current behavior and known coverage gaps.

## Purpose and operator workflow

Open **Exposure → Services** (`/exposure?lens=services`). Browse matching web targets
and devices, then inspect a listener/application context. The view shows the relationship
from domain/target to address, transport/port, service/product/version, candidate advisories,
public exploit references, investigation activities, and retained evidence.

The four detail tabs are Overview, Weaknesses, Activities, and Evidence/history. Filters,
target-page position and selected service are URL-backed. Search matches **target name or
locator**, not a truncated global service list. Web/AI/model posture scores are deliberately
not reused as service-inventory metrics. A service relationship is not a proven attack path.

“Prepare investigation in Hunt” opens the existing Hunt draft with the owning target and a
server-derived service reference. It does not start a run, attach credentials, approve network
traffic or expand scope. An active planner is still needed. Hunt can read exactly the same
projection using `POST /hunts/{hunt_id}/query` with:

```json
{"kind":"service_intelligence","filter":{"id":"SERVICE_UUID"},"limit":1}
```

The Hunt's stored target—not a caller-supplied target ID—owns that query. Returned labels,
CVE descriptions and references are untrusted evidence data, not planner instructions.

## Implemented

- Read-only `GET /exposure/services`, target pagination and explicit evidence-window limits.
- Web observations from canonical Scan `ports.discover`, `service.fingerprint`, `web.probe`
  and the baseline `http.request` action. Canonical result and content-hashed observation
  manifest validators are reused; malformed, unavailable or over-budget objects produce a warning.
- Existing device service inventory, including inconclusive UDP and `not_observed` states.
  Immutable scan locator and locator-history timestamps determine whether device observations
  are current or historical. Unknown/historical bindings cannot produce a Hunt handoff.
- Stable service-context IDs distinguish owner, observed address, transport, port and positively
  observed application origin. Device contexts also retain their observed locator generation.
  Network-only listeners and positively observed virtual-host contexts are intentionally distinct.
- Nmap method/confidence/tunnel provenance is retained. Port-table names are not product identity.
  A fresh port-only result does not refresh an old product fingerprint.
- Candidate CVEs from the existing hash-pinned, curated device advisory snapshot; the existing
  matcher remains authoritative for matching semantics. A request-local product/CPE index and
  memoization avoid matching the entire snapshot for every repeated listener.
- Explicitly typed `exploit_references` in a pinned advisory snapshot are displayed as research
  links. A vendor advisory URL is never mislabeled as an exploit. No external reference is
  downloaded, imported as a template or executed by this feature.
- Advisory activities for HTTP(S), SSH, database services, SMB, messaging and unknown protocols.
  Available capability metadata comes from the canonical registry. Compatibility is not authority:
  the actual Hunt manifest, target binding, policy, approvals, placement and budgets still decide.
- Exactly scoped active-finding associations and verbatim existing proof/verdict fields. Ambiguous
  origins/backends remain target-scoped. Existing Exposure endpoint relationships are also fixed to
  use owning target plus exact origin/path instead of root domain/path.
- Read-only Hunt query projection, service-ID filtering and snapshot/target-bound pagination cursors.
- Hunt observations from settled `ports.discover`, `service.fingerprint`, `web.probe`,
  `http.request` and `collections.replay_safe` receipts now feed the same projection as Scan
  evidence. The existing reservation store persists those content-hashed receipts atomically with
  action settlement. Reads validate owner, action, receipt, budget, frozen addresses and service
  host before normalizing; they never trust Redis replies, planner notes or result summaries.
  The source Hunt and action remain linked in evidence/history and the UI.

## Deliberate execution boundaries

Supplied-credential validation is distinct from vendor-default and common-password assessment.
The latter two are visible as **not implemented** in this workflow: generic active/network approval
must not authorize password guessing. The device authenticated-active profile is unchanged.
A future credential-assessment capability needs separately bound approval, persistent shared
per-account/per-service attempt budgets, cooldowns, lockout and health stop conditions, secret
redaction, and a deterministic authenticated-identity proof contract.

No new scanner, scan type, independent Hunt engine, vulnerability score or proof predicate is added.
This API does not perform network discovery, login attempts or exploitation on GET or on UI navigation.
Protocol review suggestions with no compatible registered capability remain manual; buttons do not
pretend those capabilities exist.

## Corporate applications and edge appliances

HTTP evidence names common corporate products (mail portals, identity providers, VPN gateways
and application delivery controllers, CI and collaboration servers, administration consoles)
from three passive sources: an exact technology name the HTTP probe reported, an anchored page
title, and a content-discovery hit on a product-specific path whose answer differs from the
host's measured answer for a path that cannot exist. Scan reports list them under
`discovery.corporate_surface` as unconfirmed leads with their basis. A version is used only when
the fingerprint read a plain dotted version; CPE names are derived only for products whose
versions map one-to-one onto the NVD product, so matches (including known-exploited ones) stay
candidates for prioritisation until a deterministic check applies.

## Accuracy and coverage limits

The bundled snapshot is an offline dataset, not complete/live NVD coverage. Zero candidates
means **no match in that snapshot**, not “no vulnerabilities.” Configure the existing
`DEVICE_INTEL_DB_PATH` and `DEVICE_INTEL_DB_SHA256` pair for a reviewed custom snapshot. A missing or
incorrect digest fails closed; its trust status remains visible. This feature never performs a live
CVE, KEV, EPSS or exploit-site query.

### Signed intelligence bundles

Newer data can arrive without a new image as a signed bundle installed under `results/intel`
(`SHAKERSCAN_INTEL_BUNDLE_DIR` inside the containers): `device_advisories.json`, a `manifest.json`
naming its SHA-256, size, `generated_at` and a monotonic `bundle_version`, and `manifest.sig`, an
Ed25519 signature over the manifest. The loader uses the bundle only when the signature verifies
under a key the engine trusts (the vendor keys in `scanner/scanner_tools/intel_bundle.py`, or keys an
operator pins with `SHAKERSCAN_INTEL_TRUSTED_KEYS=<key id>=<base64 public key>`), the snapshot
matches the signed digest, and the bundle is not older than the snapshot built into the image.
Otherwise the built-in snapshot stays in force and the page names the reason (`untrusted_key`,
`bad_signature`, `older_than_builtin`, `version_rollback`, ...). The highest `bundle_version` ever in
force is recorded outside the bundle directory (`results/intel.high-water` and the
`intel_bundle_high_water` table, which API startup copies back to the file), and a lower bundle is
refused. Setting `DEVICE_INTEL_DB_PATH`/`DEVICE_INTEL_DB_SHA256` at all, even to the built-in file,
is an operator pin: it freezes the intelligence and no bundle replaces it. The image sets neither.

`./scanner.sh intel status` shows what is in force; `./scanner.sh intel install <archive, directory
or https URL>` verifies a bundle inside the engine and activates it, refusing a lower
`bundle_version` than the recorded mark (even when the installed bundle no longer verifies; with a
configured database that cannot be reached it refuses) and keeping the previous bundle as
`results/intel.previous`.
Bundles are built and signed with `scripts/intel_bundle.py` (`keygen`, `build`, `verify`); the
private key never belongs in a checkout.

### Rows, verification and Hunt

Each target lists one row per listener product/version (`listener_groups`), ordered by the most
severe candidate or linked finding, then known exploitation; the same listener seen by several
Scans, Hunts or addresses is one row whose observations stay inspectable, an identity is marked
stale once per row, and inconclusive rows with nothing linked are folded by default.

A candidate whose CVE has a check in this release carries `verification`. When the listener is the
target's own origin, **Verify** submits an ordinary Scan with `verify_templates` (the named checks
only, `policy.active_testing` and the `nuclei_active` family, under the target's standing
authorization and budgets). The worker runs each named check or records why it did not:
`intrusive`, `never_requested_path` (the check requests a path Scans never request, such as
`/actuator/heapdump`), `needs_oob_interaction` (Scans run without interactsh), `needs_state_changing_http`,
`exploit_class_needs_exploit_tier` (checks tagged rce, lfi, sqli, deserialization, ssti, xxe,
code-injection, cmdi or ssrf, or with a code/javascript/flow step, need state-changing authority;
admission refuses them up front when the snapshot classes them `safety: exploit`), or
`not_in_template_bundle`; checks that follow redirects run but cannot give a reliable negative
(`needs_redirects`, Scans disable redirects). This selection is recorded on the step's receipt.
The outcome is read back from durable records: `check_matched` links the finding with its own
proof state; `check_not_matched` is reported only when every check for the CVE was requested, ran
in every active-template step, and can give a reliable negative, and is evidence about those checks
only; anything else is `inconclusive` with the reasons. A version match without a run stays a
candidate.

Hunt reads the same rows with `query kind=service_intelligence filter={"view": "candidates"}`: one
row per listener and CVE, known exploited and likely first, with the check that exists and its
verification state.

A version/CPE match is always a candidate in this projection—even if a matcher could promote a
record elsewhere. Confirm product/build, affected component/configuration and distribution backports.
Candidate-local validation is marked `no_linked_validation`; existing active findings are shown
separately. This version does not infer a CVE proof relationship from matching text in a finding title.

Web history covers at most 12 recent supported canonical Scan actions per target, with a 2 MiB/
2,000-observation per-manifest read limit. Each target returns at most 500 service contexts and
300 active finding associations. Each service retains up to 12 evidence/history entries and 30 CVE
candidates. Limits and source failures remain visible. Device history reflects its existing current
service inventory, not a newly materialized all-time service-history database. Missing older entries
or an incomplete scan never resolve a finding or establish clean posture.

Hunt history covers up to 12 recent supported, settled receipts per target, with a 2 MiB /
2,000-observation read budget per receipt. Partial, failed and cancelled actions can retain
positive service evidence without being reported as completed tests. Retries reference the same
canonical action; reads do not create another ledger or duplicate observations. Existing owner /
receipt deletion and retention remove that source from the projection. Device locator changes
remain historical; changed web locators do not silently rebind old Hunt observations. HTTP
fingerprints without a recorded backend address remain explicitly unattributed to an IP.

Older Hunt output without a matching canonical durable receipt is not imported or treated as
verified history. This is a bounded shared read model over persisted evidence, not an unlimited
materialized service-history database. No all-time backfill or new Scan planning behavior is
implied. Raw banners, response bodies, credential values and private manifest paths are not returned.
Application origins strip paths, query strings and fragments and reject embedded credentials.

## API

`GET /exposure/services` accepts `target_kind=all|web|device`, an optional exact `target_id`,
`root_domain`, `search` (target label/locator), `limit` (1–25, default 10) and `offset`.
The response contract is `service-intelligence/v1`. Pagination totals refer to matching **targets**,
including targets with no retained service observations. Domain filtering and finding linkage must
never be used as scope authorization. Registry risk/approval fields are descriptive, not approval receipts.

Hunt queries accept `kind=service_intelligence`, optional `filter.id`, `limit` (1–500) and `cursor`.
A cursor cannot move to another target/filter and is rejected when the evidence snapshot changes.

## Acceptance and current gaps

Focused Python tests cover ownership, exact origins, nonstandard ports, port-only hints, ambiguous
backends, UDP uncertainty, changed device locators, stale identity, private-data projection, advisory
candidate semantics, hash tampering, read-only routing and scoped Hunt pagination. An optional
PostgreSQL test uses only temporary tables when `SERVICE_INTELLIGENCE_TEST_DATABASE_URL` is supplied.
Playwright coverage exercises desktop/mobile browsing, CVE/evidence/activity separation, no writes
on navigation, search/history restoration, and visible source failures.

Run the focused suite:

```sh
python -m pytest -q tests/test_service_intelligence.py tests/test_service_intelligence_routes.py \
  tests/test_service_intelligence_postgres.py tests/test_hunt_service_sources.py \
  tests/test_hunt_service_sources_postgres.py
npm --prefix ui run test:unit
# With the UI running and Chromium installed:
cd ui && npx playwright test tests/browser/service-intelligence.spec.ts
```

Current gaps are intentionally explicit: all-time service-history materialization and legacy backfill; reviewed
CVE-specific verifier bindings and result feedback; live/offline-refresh KEV and EPSS provenance;
additional protocol adapters; separately governed credential assessment; and evidence-backed
consequential attack paths. These are product gaps, not promises implied by a populated service table
or a public exploit reference.
