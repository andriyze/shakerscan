# Hunt AISVS boundary follow-up

This work is stacked on PR #296 at `14f0c649e2ec32f92641bbbaf9aa1c5969552825`.
It assesses changes since `da70141d5d5c8b43ad3b71df64104fc02d1b858f` without
reversing default-on metadata editing, same-asset service reuse, or standing
target authorization. It is an engineering verification profile, not a claim
of AISVS conformance.

## Audit of the three new commits

- `1a58843e`: metadata edits default on with an operator opt-out; the installed
  SSH helper no longer imports HTTP routers; the installer ships the lightweight
  authority dependency; CI starts the stack through the supported launcher and
  requires network capacity to become ready before its deadline.
- `172098e`: removing the metadata confirmation prompt does not permit those
  registry entries to acquire a binary, a network placement or network budget.
- `14f0c64`: synchronizes the hosted installer, tests the launcher-based CI
  startup and canonicalizes the expected address in the DNS-rebinding test.

The source changes address the earlier installer/readiness failures without
turning a missing network worker into a successful readiness result. Metadata
writes still have revision checks and cannot authorize target traffic. Exact
credential sharing, collection revocation and SSH trust remain separate.

## Remaining implementation scope

1. Distinguish operator instructions from Hunt-authored or legacy-unknown text
   across persistence and later Hunt startup. Preserve useful advisory knowledge
   and revision history without automatically promoting it to operator intent.
2. Provide a bounded external-planner access boundary that reuses the canonical
   Hunt API. A planner must not grant itself authority by calling operator routes
   outside its Hunt. Do not pretend a client-supplied role header or a prompt is
   an authentication boundary.
3. Pair adversarial checks with legitimate metadata/capability success cases and
   preserve exact-source CI evidence for this stacked branch.

An unrestricted local coding agent with access to the operator's API, files and
credentials is part of the trusted operator environment. No HTTP wrapper can
isolate it from resources it can reach independently. A protected planner
profile must keep the backend and operator credentials outside that planner's
network/filesystem boundary; local compatibility is not a claim of isolation.

## Standards references

The mappings use the released AISVS 1.0 requirements, not development guidance:

- [C9](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C09-Orchestration-and-Agentic-Action.md): C9.2.5, C9.5.1, C9.5.2, C9.5.3 and C9.5.6.
- [C8](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C08-Memory-Embeddings-and-Vector-Database.md): C8.2.3, applied by analogy to structured target knowledge rather than claiming a vector-store implementation.
- [C5](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C05-Access-Control-and-Identity.md): C5.2.5.
- [C12](https://github.com/OWASP/AISVS/blob/main/1.0/en/0x10-C12-Monitoring-and-Logging.md): C12.5.4.

OWASP AISVS is licensed CC BY-SA 4.0. This document links to its requirements
and records ShakerScan-specific interpretation; it does not vendor their text.

Implementation results and limitations will be recorded with the corresponding
code and regression tests in this PR.
