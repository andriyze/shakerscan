# ADR 0002: Bounded Scan continuation amendments

- Status: accepted
- Date: 2026-08-24
- Scope: deterministic Scan V2

## Context

Scan cannot know every endpoint, request candidate, or verifier action before
discovery. Treating discovery output as permission to create arbitrary later
work would make the effective plan mutable and would let observations expand
the original authority envelope.

## Decision

Scan uses one immutable root plan followed by at most one immutable,
discovery-derived amendment. The root and its continuation allocation are
persisted before the first target packet. Discovery can select work within that
allocation; it cannot create authority.

The durable amendment chain is:

```text
root plan digest
  + continuation-allocation digest
  + discovery-result digest
  + ordered work-manifest digests
  + continuation-plan digest
  -> merged-plan digest and plan version 1
```

Version 0 is the root plan. Version 1 is the merged effective plan. A Scan has
no other writable plan version. Every digest is content addressed and every
record is bound to the same Scan ID, execution-plan digest, and target-binding
digest.

## Authority invariants

The merged plan must satisfy all of these conditions:

```text
merged target authority      == root target authority
merged approval authority    == root approval authority
merged credential authority  <= root credential references
merged collection authority  <= root collection references
merged capability families   <= continuation allocation families
merged aggregate budget      <= continuation allocation ceiling
continuation allocation      <= original Scan budget and policy
```

The amendment may bind exact endpoint, candidate, request-candidate, and
template manifest entries to already authorized action slots. It may not add a
target, origin, address, credential, collection, approval, risk class, budget
dimension, or capability family. Dependencies may refer only to the frozen
root prefix and actions created inside the amendment.

Discovery observations are normalized and stably ordered before their digest
is computed. Reordering equivalent observations must produce the same
manifests and amendment. A content change must change the discovery-result,
manifest, continuation, and merged-plan identities.

## Persistence and execution

The control plane persists the root revision and continuation ceiling in the
same admission transaction as the root action index. After all root actions are
terminal, it derives the amendment only from persisted action results,
observation manifests, and pre-authorized private work-manifest references.

The work manifests, revision record, merged plan header, and appended action
index commit in one database transaction. A crash before that commit leaves
version 0 authoritative. A crash after it reuses version 1; it does not compile
a second amendment. Compare-and-swap on the parent and allocation digests makes
the operation idempotent.

Workers lease actions against one exact plan digest and version. Local, broker,
and parallel placement must reject a result or continuation request for a stale
version. Broker responses carry the exact persisted revision identity rather
than reconstructing authority from public options.

Final reports bind the complete amendment chain. The action and coverage APIs
expose both revision identities and the content-free work-manifest references
so the UI can explain why post-discovery actions exist without exposing private
request values.

## Failure behavior

- Missing or invalid root discovery evidence fails the amendment closed.
- An over-budget, unknown-family, target-changing, or authority-changing
  continuation is rejected before any continued action can be leased.
- Cancellation prevents amendment application and continued scheduling.
- A stale worker may submit neither actions nor results for an earlier version.
- Completed root actions are never replayed merely to rebuild the amendment.
- If amendment persistence is uncertain, no continued traffic starts until the
  control plane resolves the authoritative revision.

## Consequences

- Exact post-discovery actions remain reproducible without requiring endpoint
  knowledge before the first packet.
- Discovery influences selection, never permission.
- Resume can distinguish a root-only Scan from one with an applied amendment.
- Reports, placement, and recovery share one effective-plan identity.
- Supporting another amendment would require a new ADR and schema version; it
  cannot be introduced as an implicit planner loop.

