# Internal compatibility boundary

This document describes migration behavior, not an alternate product surface. New clients use one
deterministic Scan and one target-kind-aware Hunt. Their live contracts are `GET /scan/contracts`,
`GET /hunts/contract`, and `/openapi.json`.

Compatibility code may read historical scan-mode names, old finding-source values, retired Hunt
routes, and legacy credential rows so an existing installation can upgrade without losing history.
Those inputs are translated at the API/read boundary only:

- old scan-mode names map to a `fast`, `balanced`, or `thorough` resource ceiling plus explicit
  policy; they cannot select another engine or module registry;
- retired Hunt write routes return `410 Gone`, while bounded historical reads and cancellation stay
  available during the migration window;
- old raw authentication fields remain internal deserialization fields for stored rows and migration.
  Canonical Scan, Hunt, CLI, UI, and MCP requests accept only opaque credential-profile and request-
  collection references;
- legacy plaintext secret rows may be read only long enough to migrate them. Every new secret write
  must produce an `enc:fernet:` value using the configured or auto-generated persistent key, or fail
  closed.

Compatibility models must be explicitly named and must not appear in new public write contracts.
Unknown fields remain rejected at public V2 boundaries. Historical design detail lives under
[`archive/`](archive/README.md).
