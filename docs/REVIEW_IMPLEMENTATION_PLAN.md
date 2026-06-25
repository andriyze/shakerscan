# Implementation Plan — Roadmap Review (2026-06-25)

The review is accurate (spot-verified: Juice Shop benchmark `artifact_status:
failed_benchmark_scorecard`; no `evidence_objects`/`storage_uri` anywhere; worker
reports but never refuses on submit-time fingerprint; UI `buildPayload` omits
`policy_profile`; receipts verified against self-supplied keys). This sequences the
findings into phases with honest scope. **Bottom line ordering (per the review):
trust the measurements → P0 depth (evidence, graph, recall) → make it usable (UI +
skills).**

## Done this cycle (the two review batches before this one + the freshness item)
- **F1** Model Intake signature + trust-anchor fields are now first-class API request
  inputs → trusted `signature_verified=True` reachable via the API; e2e MI-6 enforced.
- **F2** AI Gate receipt verification gets a trust-root layer (`chain_trusted` requires
  an env-configured anchor; self-signed → consistent-but-untrusted finding).
- **F3/F4** e2e: deterministic local 206 fixture (HF moved to opt-in), AI fixture is
  non-skippable.
- **P3-13** worker fail-closed on build-stale jobs before execution (requeue → fail-closed).
- **P2-11** e2e plan doc corrected: fast gate = integration/hardening; recall = nightly.

## Phase B — Evidence object store (P0-3) — ✅ DONE (complete vertical slice)
Shipped: `evidence_objects` table + migration; `save_findings` writes one hashed,
redaction-profiled, retention-classed object per finding (best-effort, outside the
finding txn so it never rolls the scan back); `GET /findings/{id}/evidence` +
`GET /evidence/{id}`. Live-validated (a real scan wrote 4 objects) + unit tests.
Next phase here: externalize inline content to an object store (file://) for large
blobs + a retention sweeper. Original slice spec below.

A complete vertical slice, not an orphaned table:
1. Schema + migration: `evidence_objects(id, scan_id, finding_id, object_type,
   content_sha256, size_bytes, storage_uri, redaction_profile, retention_class,
   created_at)` in `db/init.sql` + `run_schema_migrations()`.
2. Write path: `save_findings` writes one row per finding's evidence — hash the
   payload, store `storage_uri` (result-file pointer or inline blob ref), stamp
   redaction profile + retention class. Keep embedded `evidence` for back-compat.
3. Read path: `GET /findings/{id}/evidence`, `GET /evidence/{id}`.
4. Care: `save_findings` is fragile (the NUL-byte finalize-hang lived here) — strip
   control bytes, wrap in try/except, never let evidence-object writes fail the scan.

## Phase C — Application graph (P0-2) — biggest
First-class `ApplicationGraph` per target: `graph_nodes` (routes, params, object IDs,
sensitive fields, roles, tenants, workflow states) + `graph_edges` (producer/consumer,
auth boundary). Populate by persisting the in-memory `resource_map`
(access_control_checks.py:2419/2564); consumers = BOLA/IDOR planning reads the durable
graph. Multi-session; improves BOLA recall (feeds Phase D).

## Phase D — Broad DAST recall (P0-1) — open-ended quality
Drive the nightly Juice Shop benchmark to its gates (min_verified_high_critical ≥ 6,
max_unverified_high_ratio ≤ 0.35). Analyze the 5 missed findings → improve detectors;
raise verified ratio (more deterministic proof). Iterative, measured by the benchmark;
benefits from Phase C. NB the focused sidecar is explicitly `not_a_benchmark_scorecard`.

## Phase E — Check registry as execution contract (P1-4)
Add `proof_contract` + `severity_rules` + telemetry schema + permissions to
`CheckFamilySpec`; make SSRF/LFI/RCE/business_logic runnable; drive `build_report`
execution from the registry instead of direct module/task calls. Multi-session.

## Phase F — Close UI + skill gaps (make existing backend usable)
Backend exists; UI/skill don't drive it. Each bounded:
- Model Intake UI: send `policy_profile`; add trusted-key / public-key / signature
  controls; make the "complete" example cryptographic, not `sigstore_verified: true`
  claim-only (P1-6).
- Policy/exception UI + live deployment-decision refresh on the scan page (P1-5).
- AI principals management UI (attacker/victim/admin/service, tenant, credential,
  rotation, principal-pair preview) (P1-7).
- AI surfaces ledger page (sync, attempts, coverage by family, runtime risk,
  transcript retention/purge) (P2-9).
- Findings selection-based bulk retest/status + manual finding + exception-from-finding
  (P2-10); AI widget target + target editing (P2-8); ASM endpoint_filter + prune (P3-12).
- Skills/commands: teach the policy/exception registry, AI principals, surface ledger,
  runtime risk, transcript purge, and strict Model-Intake trust-anchor fields; thicken
  `/ai-gate`.

## Recommended order
Phase B → C → D (the P0 depth the review prioritized) → E, with Phase F interleaved so
no capability stays developer-only for long. Phase B is the cleanest next concrete slice.
