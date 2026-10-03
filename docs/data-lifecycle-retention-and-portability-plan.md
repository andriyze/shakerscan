# Data lifecycle, retention, and portability

**Status:** current implemented safety contract plus remaining roadmap; reconciled 2026-09-09.

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
- HTTP request archives provide redacted JSON by default. HAR is offered masked or raw; raw HAR
  (credentials included) is sensitive, requires explicit operator confirmation in the UI, and can be
  turned off for a deployment with `SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR=0`. The generic evidence API
  never serves unmasked captured traffic.
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
hides the asset, disables automatic ASM, and pauses its recurring schedules in one transaction.
Both scheduler claim paths recheck target activity. Archive does not cancel already admitted
work or remove records. The target deletion dialog offers **Archive target instead** with its
own confirmation, including when erasure is blocked by protected history.
`DELETE /targets/{id}` is a permanent database-record operation requiring the preview
and approval below. The Targets page exposes a delete control on each actual target, including
subdomains, and a **Delete domain** action on each domain group. Deleting a host also deletes the
application services linked to it. Domain deletion selects exactly the targets the Targets list
groups under that domain (multi-part suffixes such as `co.uk` included) plus each host's linked
services; the preview lists every resolved target ID and the approval binds that exact list.

Credentials and request collections offer **Delete permanently** beside Deactivate. Deactivating
is reversible and keeps the encrypted material; permanent deletion uses the same preview and
approval flow and removes every copy (see below).

A single scan (**Delete scan** on its page), Hunt (**Delete** on its run page), AI Gate target
(**Delete permanently** beside Disable; **Show disabled targets** lists disabled ones) and Model
Intake submission (**Delete submission**) are deleted the same way, with what they own and nothing
else of their target.

The Findings page supports selected-record deletion from the selection dock (Select, choose
rows, More, Delete selected findings) and previewed age cleanup (Advanced cleanup). Neither is a
front-line control: bulk triage (`POST /findings/bulk`) is the dock's primary action, and in
managed workspaces both deletion entries require the `record_deletion` and `engine_admin`
capabilities. Finding detail supports single-record deletion with scan scope from the Manage
record block at the end of the page. Investigation candidates are not finding rows and cannot be
selected through this surface.

### Explicit API flow

1. Call `POST /data-deletion/preview` with one of
   `{"kind":"target","target_id":"<UUID>"}`,
   `{"kind":"domain","domain":"example.com"}`,
   `{"kind":"credential_profile","id":"<UUID>"}`,
   `{"kind":"request_collection","id":"<UUID>"}`,
   `{"kind":"scan","id":"<UUID>"}`, `{"kind":"hunt","id":"<UUID>"}`,
   `{"kind":"ai_target","id":"<UUID>"}`, `{"kind":"model_intake_submission","id":"<UUID>"}`,
   `{"kind":"findings","finding_ids":["<UUID>"],"scan_id":"<optional UUID>"}`, or
   `{"kind":"findings","older_than_days":90,"status":"resolved","root_domain":"example.invalid"}`.
   The response includes exact IDs, cascade/detach/retain counts, blockers, expiry, a scope receipt,
   and an immutable preview hash. It performs no deletion. The explicit batch limit is 500 findings,
   a domain may resolve to at most 500 targets, and the per-table inventory limit is 100,000
   records. Oversized selections require a narrower preview.
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
record removal and the durable result commit atomically. There is no external storage I/O in
that transaction and no scheduled destructive execution: files are erased only after the commit,
and their outcome is added to the same durable receipt.
Completed-operation replay validates the stored manifest and approval association without
locking writer tables. Expired pending previews fail before those locks; real deletion still
performs locked revalidation. Run-state blockers follow each subsystem's terminal statuses;
unknown states and resumable states remain blockers.

### What is removed, and what is retained

Target and domain deletion erase everything the target owns: its findings, scans (with their
reports, artifacts, checkpoints, manifests, sealed session state and recorded HTTP traffic),
Hunts (with their actions and traffic), tool receipts of those runs, schedules, endpoints, request
collections, every credential homed on it (including a host's `device` identity), and the saved
login sessions and collection bindings established on it. A host takes its linked application
services. Evidence the deleted rows own or reference is erased once nothing that survives still
points at it, because content-addressed blobs can be shared.

After the database commit, the files those rows named are erased: evidence blobs and scan
artifacts (local or S3), scan checkpoints, and the per-scan result files the worker writes under
`RESULTS_DIR/<host>/`. A result file is erased only when its recorded `scan_id`/`job_id` belongs to
a deleted scan; anything unproven is listed, not deleted. The receipt's `files` block reports how
many files were erased, missing or failed, and `external_files_deleted` is true only when none
failed.

Target and domain deletion also remove the target's authorization scope records, which name its
URL and hosts, and a domain's subdomain-discovery runs.

Finding deletion removes the selected findings, their cascading children and their evidence.

Scan deletion removes the scan and its shard scans, the findings it last observed (a finding a
later scan re-observed belongs to that scan and stays), recorded traffic, artifacts, checkpoints,
saved sessions, budget reservations, evidence and files; a later scan that used it as a baseline
loses only that link. Hunt deletion removes the Hunt with its actions, traffic, saved sessions,
candidates, budget reservations and the findings only it produced. AI target deletion removes its
surfaces, principals, credentials (with their copies in the credential store), findings and AI Gate
scans. Model Intake submission deletion removes its evidence, runner jobs, reviews, admissions and
evidence scan; quarantined model files are removed by the Model Intake quarantine cleanup once no
admission protects them. Only the selected record's own running work blocks these deletions;
work on it that was never started, or that nothing has touched for 15 minutes, is cancelled.

Permanent credential deletion removes the profile, every encrypted version, every grant, its
saved sessions, its assurance history, and the legacy mirrors a later sync would use to re-create
it, and strips its ID from other targets' delegated Hunt authority and from schedules. Permanent
collection deletion removes the document, environments, request index, bindings and selections,
and strips the collection from delegated authority and schedules. A running scan or open Hunt that
still uses the input blocks its deletion. Deactivating a credential revokes its live sessions and
destroys their captured headers at once.

Content-free audit records (approvals, deletion receipts, export events) and exports made before
the deletion are retained. Backups made before the deletion still hold the records: list and
delete them with `shakerscan backup list` and `shakerscan backup delete`. Holds do not
block deletion by default: an open-source install has one operator, and records they own must be
deletable through the approved preview. A deployment that keeps holds sets
`SHAKERSCAN_DELETION_ENFORCE_HOLDS=1`; then an explicit `legal_hold` or `audit` class, or a
`legal_hold`/`operational_hold` flag, blocks erasure. A `sensitive` classification is a content
label, never a hold. Held rows are reported in the preview either way. Evidence already claimed by
a running retention deletion always blocks until that deletion finishes. Use archive to hide
inventory without erasing history.
No suppression/tombstone prevents future discovery or scans from creating new records.

Mixed product ownership and enforced legal or operational holds block this generic operation.
Managed deployments must explicitly enable the
`record_deletion` UI capability (plus `engine_admin` for the Findings list and detail controls)
and authorize these endpoints at their gateway; this UI flag is not an API authorization mechanism. Standalone remains a single-user local application.

Acceptance coverage lives in `tests/test_data_lifecycle.py`,
`tests/test_data_lifecycle_replay.py`, `tests/test_target_archive_admission.py`,
`tests/test_data_lifecycle_postgres.py`, `ui/tests/browser/data-lifecycle.spec.ts`, and
`ui/tests/browser/findings-triage.spec.ts`.
The PostgreSQL test uses only the explicitly named disposable local test database; it must never
be pointed at an existing installation.

Keyed collection uploads have separate real-route acceptance in
`tests/test_collection_atomic_retry_postgres.py`. The maintenance workflow requires that suite
to execute against a dedicated disposable PostgreSQL database without skipped cases. Its app
lifespan is not started, so the tests do not start schedulers, workers, or target traffic.
