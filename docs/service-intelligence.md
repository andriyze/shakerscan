# Service Intelligence

**Status:** implemented initial read-only inventory and investigation workflow.
**Reconciled:** 2026-09-17. This document separates shipped behavior from follow-on work.

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

## Accuracy and coverage limits

The bundled snapshot is a small curated dataset, not complete/live NVD coverage. Zero candidates
means **no match in that snapshot**, not “no vulnerabilities.” Configure the existing
`DEVICE_INTEL_DB_PATH` and `DEVICE_INTEL_DB_SHA256` pair for a reviewed custom snapshot. A missing or
incorrect digest fails closed; its trust status remains visible. This feature never performs a live
CVE, KEV, EPSS or exploit-site query.

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

Historical **Hunt-only network outputs** are not backfilled into the Scan observation store. Hunt
can read this feature and launch existing capabilities, but automatic persistence of those legacy
outputs into the same projection remains follow-on work. Raw banners, response bodies, credential
values and private manifest storage paths are not returned. Application origins strip paths, query
strings and fragments and reject embedded credentials.

## API

`GET /exposure/services` accepts `target_kind=all|web|device`, an optional exact `target_id`,
`root_domain`, `search` (target label/locator), `limit` (1–25, default 10) and `offset`.
The response contract is `service-intelligence/v1`. Pagination totals refer to matching **targets**,
including targets with no retained service observations. Domain filtering and finding linkage must
never be used as scope authorization. Registry risk/approval fields are descriptive, not approval receipts.

Hunt queries accept `kind=service_intelligence`, optional `filter.id`, `limit` (1–500) and `cursor`.
A cursor cannot move to another target/filter and is rejected when the evidence snapshot changes.

## Acceptance and remaining work

Focused Python tests cover ownership, exact origins, nonstandard ports, port-only hints, ambiguous
backends, UDP uncertainty, changed device locators, stale identity, private-data projection, advisory
candidate semantics, hash tampering, read-only routing and scoped Hunt pagination. An optional
PostgreSQL test uses only temporary tables when `SERVICE_INTELLIGENCE_TEST_DATABASE_URL` is supplied.
Playwright coverage exercises desktop/mobile browsing, CVE/evidence/activity separation, no writes
on navigation, search/history restoration, and visible source failures.

Run the focused suite:

```sh
python -m pytest -q tests/test_service_intelligence.py tests/test_service_intelligence_routes.py \
  tests/test_service_intelligence_postgres.py
npm --prefix ui run test:unit
# With the UI running and Chromium installed:
cd ui && npx playwright test tests/browser/service-intelligence.spec.ts
```

Follow-on scope: durable cross-Scan/Hunt service-history ingestion; reviewed CVE-specific verifier
bindings and result feedback; live/offline-refresh KEV and EPSS provenance; additional protocol
adapters; separately governed credential assessment; and evidence-backed consequential attack paths.
None of these is implied by a populated service table or a public exploit reference.
