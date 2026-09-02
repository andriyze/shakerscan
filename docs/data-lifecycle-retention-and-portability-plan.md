# Data lifecycle, retention, and portability

**Status:** current implemented safety contract plus remaining roadmap; reconciled 2026-08-29.

The original design plan grew into a point-in-time implementation ledger. It is preserved at
[`archive/data-lifecycle-retention-and-portability-plan.md`](archive/data-lifecycle-retention-and-portability-plan.md).
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

