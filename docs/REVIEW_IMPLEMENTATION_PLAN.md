# Implementation Plan — Roadmap Review (2026-06-25)

The review was accurate when written (spot-verified then: Juice Shop benchmark
`artifact_status: failed_benchmark_scorecard`; no `evidence_objects`/`storage_uri`
anywhere; worker reports but never refuses on submit-time fingerprint; UI
`buildPayload` omits `policy_profile`; receipts verified against self-supplied keys).
This document tracks what has since been fixed and what remains. **Bottom line ordering (per the review):
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
- **P1-6** Model Intake UI now sends `policy_profile`, public-key URL/PEM,
  detached signature value, trusted-key PEM, trusted-key SHA-256 fingerprints, and
  signature payload/hash/padding controls instead of leaving the trusted path API-only;
  the complete metadata example no longer asserts claim-only `sigstore_verified: true`.
- **P1-5/P1-6 UI follow-through**: policy profile CRUD is available at
  `/settings/policy-profiles`, saved profiles are selectable from Model Intake, durable
  evidence object content is visible on finding detail, finding exceptions can be created
  and deleted from finding detail, and `/targets/{id}/graph` has node/edge filters plus
  selected-node inspection. Scan detail now refreshes `/scans/{id}/deployment-decision`
  live instead of relying only on embedded scan result state.

## Review corrections (2026-06-25, second review of this cycle)
A follow-up review caught real defects in the first cut — all fixed + validated:
- **worker freshness failed OPEN**: an unknown fingerprint (`None`) was treated as
  safe-to-run. Now only a *provably current* worker runs; unknown ⇒ refuse. Test
  `test_unknown_fingerprint_fails_closed`. Requeue is now time-based (a current
  worker in a mixed fleet takes it in seconds; only a sustained fully-stale window
  fails closed) instead of bounce-count-based.
- **evidence write was INSIDE the finding txn** (the doc claimed outside). Dedented
  to the loop body so it runs after commit — a poisoned txn can't roll the finding back.
- **AI Gate findings had no evidence objects**: `save_ai_findings` now writes
  `ai_gate_evidence` objects (sensitive retention). Live-validated.
- **evidence API 500'd on a non-UUID**: `GET /findings/{id}/evidence` now resolves
  id-or-fingerprint (404 on unknown); `GET /evidence/{id}` 400s on a bad UUID.
- **Model-Intake trusted-key API fields** now accept scalar-or-list (match the scanner).

## Phase B — Evidence object store (P0-3) — ✅ DONE (complete vertical slice)
Shipped: `evidence_objects` table + migration; `save_findings` AND `save_ai_findings`
each write one hashed, redaction-profiled, retention-classed object per finding
(best-effort, AFTER the per-finding txn commits so it can't roll the scan back);
`GET /findings/{id}/evidence` (id-or-fingerprint) + `GET /evidence/{id}`.
Live-validated (DAST + AI findings both get objects) + unit tests.
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

## Phase C — Application graph (P0-2) — ✅ PHASE 1 DONE (write+read; consumer pending)
Shipped: `application_graph_nodes` + `application_graph_edges` tables + migration; a pure
`build_application_graph(result)` transform (route nodes from discovery; object nodes +
produces/consumed_by/auth_boundary edges with the principal pair + sensitive fields from the
BOLA `resource_map`, found recursively); best-effort `persist_application_graph` hooked into
scan finalization; `GET /targets/{id}/graph` (node_type/edge_type filters + summary).
**Live-validated:** a real scan wrote 8 route nodes; the read endpoint returns them. Edge
population (producer/consumer/auth-boundary) is unit-tested on the transform but only emits on a
dual-user BOLA pass — a live dual-user run is the remaining validation. **Phase 2 (consumer):**
BOLA/IDOR planning reads the durable graph instead of rebuilding it per-scan (improves recall,
feeds Phase D); add params/roles/tenants/workflow-state node types.

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
Backend exists; some UI/skill paths still need to drive it. Each bounded:
- Model Intake UI: **done for request wiring** — `policy_profile` and trusted-key /
  public-key / signature controls now submit through the public UI, saved policy profiles
  are selectable, and the complete metadata example no longer asserts claim-only signature
  verification (P1-6).
- Policy profile UI: **done for CRUD** at `/settings/policy-profiles`; exception-from-finding
  and live deployment-decision refresh are also wired on the finding/scan detail pages (P1-5).
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
