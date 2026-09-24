# Shared Hunt investigation state

Use the existing registered asset, run, action, credential and evidence stores. The methodology
library does not create a parallel engagement database or an independently mutable policy object.

## Read before rediscovery

`POST /hunts/{hunt_id}/query` exposes supported retained knowledge such as endpoints, findings,
candidates, principals, hypotheses, receipts, graph context and service intelligence. Follow
`next_cursor` with unchanged filters; page size is not total inventory size. An unavailable or
truncated source is not an empty or complete inventory.

Shared service intelligence includes supported persisted Hunt receipts alongside Scan/device
observations. Keep source action/Hunt/Scan IDs, evidence hashes, observed time and locator context.
Partial positive service observations remain useful without being called completed tests.

## Principal and resource continuity

Use saved references; workers resolve encrypted values. Keep principal, object owner and service
origin explicit when comparing requests. A fresh browser context is not persistent state across
calls. Reproduce necessary read-only steps together when the live browser capability supports it.

Do not silently attach another identity, request collection or address to an existing action.
Use an implemented operator amendment path when advertised; otherwise describe that product gap
and retain the investigation state. Methodology binding does not make such an amendment.

## History and deletion

Retry an identical action using its original idempotency key; a changed action gets a new key.
Read settled accounting rather than inventing usage from elapsed time or a profile ceiling.
Corrections and retests retain provenance. Normal retention/deletion policies apply to stored
observations; a UI summary is not a second owner of protected evidence.

Use `GET /hunts/{hunt_id}/record` for the explicit investigation record. A terminal report includes
completed evidence, unresolved leads, skipped portions and the actual stop reason.
