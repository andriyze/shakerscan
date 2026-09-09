# Data lifecycle, retention, and portability

**Status:** current implemented safety contract plus remaining roadmap; reconciled 2026-08-29.

The original design plan grew into a point-in-time implementation ledger. It is preserved at
[`archive/data-lifecycle-retention-and-portability-plan.md`](https://github.com/andriyze/shakerscan/blob/ae5a4e231ff2f8f24eeb0abaded1df121cdcf7db/docs/archive/data-lifecycle-retention-and-portability-plan.md).
This document records only the current product boundary and genuinely unfinished work.

## Current behavior

- Scan, Hunt, AI Gate, Model Intake, finding, evidence, and request-archive records retain their
  product-specific ownership and evidence semantics. They are not governed by one generic age query.
- Findings support explicit triage and bounded cleanup. Active findings are not proof merely because
  they remain active, and age alone must not silently resolve them.
- Evidence retention deletion is interactive-only. It requires an immutable target-scoped preview,
  a one-use dangerous approval bound to that preview, locked revalidation, durable execution intent,
  and idempotent retry/finalization.
- Retention schedules are disabled. Destructive cleanup cannot be converted into background
  automation.
- HTTP request archives provide redacted JSON by default. Raw HAR is sensitive and requires explicit
  operator authorization and deployment support.
- Hunt exposes requests-only export separately from its explicit decision record/debrief. Hidden
  chain-of-thought is never an export product.
- Content-addressed evidence and external blobs must not be deleted before durable ownership and
  reference checks succeed.

## Safety invariants

1. Archive/close, content purge, record purge, and “forget” are different operations.
2. A destructive operation starts with a dry-run manifest the user can inspect.
3. Approval binds the exact immutable candidate set and expires with it.
4. Active execution, legal/operational hold, and unresolved ownership block deletion.
5. Database intent is durable before external blob deletion begins.
6. Retry is resumable and idempotent; missing already-deleted blobs do not corrupt finalization.
7. Exports label redaction, completeness, product scope, schema version, and evidence omissions.
8. Import never grants execution authority, proof, credentials, or target authorization.

## Remaining work

- A unified user-facing archive/restore lifecycle across all four product planes.
- Product-aware “Export All / Import All” for disaster recovery and migration, with schema and
  subject-digest validation.
- Legal/operational hold management and policy simulation before any automatic retention is
  reconsidered.
- Storage accounting that distinguishes database rows, content-addressed blobs, quarantine,
  generated reports, and external object stores.

Until those capabilities have public contracts and acceptance tests, do not describe them as
shipped. Backup/restore operations remain documented in `upgrade-and-rollback.md`.


## 2.3.1: target and finding record deletion

Target record deletion is now different from target archive. `POST /targets/{id}/archive`
hides the asset and disables its automatic ASM; it does not cancel existing work or remove
records. `DELETE /targets/{id}` is a permanent database-record operation requiring the preview
and approval below. The Targets page exposes a delete control on each actual target, including
subdomains. It never interprets a root-domain group as recursive ownership of every subdomain.

The Findings page supports selected-record deletion and previewed age cleanup. Finding detail
supports single-record deletion with scan scope. Investigation candidates are not finding rows
and cannot be selected through this surface.

### Explicit API flow

1. Call `POST /data-deletion/preview` with either
   `{"kind":"target","target_id":"<UUID>"}`,
   `{"kind":"findings","finding_ids":["<UUID>"],"scan_id":"<optional UUID>"}`, or
   `{"kind":"findings","older_than_days":90,"status":"resolved","root_domain":"example.invalid"}`.
   The response includes exact IDs, cascade/detach/retain counts, blockers, expiry, a scope receipt,
   and an immutable preview hash. It performs no deletion. The explicit batch limit is 500 findings;
   the per-table inventory limit is 10,000 records. Oversized selections require a narrower preview.
2. Display the preview and retained-data warning to the operator. Only after explicit confirmation,
   call `POST /arsenal/approvals` using its `scope_receipt_id`, `risk_tier: "dangerous"`,
   `action_name: "data.records.delete"`, `approved_by`, `expires_at` equal to the preview expiry,
   confirmations `confirm_authorized`, `confirm_scope_reviewed`, and `confirm_delete_records`,
   and exact `action_context: {"preview_id":"...","preview_hash":"..."}`.
3. Call `POST /data-deletion/execute` with `preview_id`, `preview_hash`, and
   `approval_receipt_id`. Reuse exactly this request after an uncertain network response. A successful
   retry returns the original durable deletion receipt, not a second operation.

Legacy `DELETE /targets/{id}`, `DELETE /findings/{id}`, and destructive `POST /findings/cleanup`
also require the preview and approval; missing preconditions return HTTP 428. A preview for a
batch cannot authorize a singleton route. Changed records, expiry, cross-owner dependencies,
protected evidence, active work, and unresolved restrictive dependencies return HTTP 409.
The complete inventory is revalidated under transaction-scoped writer locks; count updates,
record removal, evidence-index detachment, and the durable result commit atomically. There is
no external storage I/O in that transaction and no scheduled destructive execution.

### What is removed, and what is retained

Target deletion removes the exact target and its owned cascading database records, including
its findings and target-scoped credential profiles. The preview names the affected tables.
Other target IDs survive; child-target parent links are detached. Finding deletion removes only
the selected finding records and their cascading children, then refreshes owner finding counts.

Historical scans/reports, scan artifacts, request archives, exports, backups, and external
content-addressed files are **not erased**. Finding-linked `evidence_objects` are detached before
the finding FK cascade, preserving their storage index instead of silently orphaning blobs.
A report may therefore still contain a historical copy of a deleted finding. Run the dedicated
approved evidence-retention operation first when removing eligible content is also intended.
No suppression/tombstone prevents future discovery or scans from creating new records.

Model Intake targets use their separate product lifecycle. Mixed product ownership and legal or
operational holds block this generic operation. Managed deployments must explicitly enable the
`record_deletion` UI capability and authorize these endpoints at their gateway; this UI flag is
not an API authorization mechanism. Standalone remains a single-user local application.

Acceptance coverage lives in `tests/test_data_lifecycle.py`,
`tests/test_data_lifecycle_postgres.py`, and `ui/tests/browser/data-lifecycle.spec.ts`.
The PostgreSQL test uses only the explicitly named disposable local test database; it must never
be pointed at an existing installation.
