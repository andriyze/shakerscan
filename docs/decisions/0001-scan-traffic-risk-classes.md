# ADR 0001: Scan traffic risk classes

- Status: accepted
- Date: 2026-08-23
- Amended: 2026-10-07 (read-only exposure checks are passive)
- Scope: deterministic Scan V2

## Decision

Scan uses three independent traffic authorities. A larger resource preset never
changes one authority into another.

### Passive/read-only

Passive means target-bound read-only traffic, not zero traffic. It may use only
GET, HEAD, or OPTIONS through a fixed adapter with runtime destination checks.
It may fingerprint HTTP, inspect DNS/TLS, crawl without form fill, request an
immutable content-discovery wordlist, execute the reviewed passive Nuclei ID
allowlist, run the reviewed exposure checks (`exposure.verify_batch`: GETs of a
fixed seed list and of endpoints discovery already reached, redirects off, no
input varied), and replay explicitly selected safe-read collection requests.

Requesting a fixed sensitive path such as `/.env` is the same traffic as a
wordlist entry; what makes it a verified finding is the file-type proof applied
to the response, not a different kind of request. A request that makes the
target do expensive work rather than read a resource (a JVM heap dump) is never
sent by a passive check, even when discovery reports the route.

Passive execution must disable redirects where the adapter cannot prove every
hop stays in scope, retries that would exceed its reservation, form submission,
browser interaction, payload mutation, public OOB callbacks, arbitrary template
selection, and planner-supplied commands. Every adapter reserves a target-bound
multi-dimensional budget before traffic and reconciles actual use afterward.

### Active

Active permits deterministic security probes that vary inputs or deliberately
exercise a vulnerability hypothesis, such as the reviewed active template pack
and XSS, SQLi, or authorization-differential verification. It requires both the
Scan active-testing policy and a live target-bound approval receipt.

Active authority does not imply permission to use a state-changing HTTP method,
submit a form, use credentials, scan a network, discover subdomains, or contact
an OOB service. Each of those authorities remains independently represented and
validated.

### State changing

State-changing traffic is any POST, PUT, PATCH, DELETE, form submission, or other
request whose declared contract can alter target state. It requires active
testing, a live approval receipt, `allow_state_changing_http`, an immutable
private request reference, and a separately reserved
`state_changing_requests` budget. A zero state-changing ceiling is a hard deny.

Unknown methods, capabilities, template IDs, destinations, or authority records
fail closed.

## Canonical passive graph

Unless a family is explicitly excluded, a normal passive Scan binds and
revalidates target authority, performs HTTP/redirect/security.txt/DNS/TLS
baselines, probes the origin, runs read-only crawl and fixed content discovery,
executes the reviewed passive template manifest, ingests selected collections,
and finalizes only from durable action receipts. Active policy adds active work;
it does not replace this backbone.

Supporting discovery is compiled independently from reportable vulnerability
families. A focused family may therefore receive the read-only prerequisites it
needs without enabling unrelated active work.

## Consequences

- The capability registry is the source of truth for risk, approval, placement,
  budget, parser, and evidence contracts.
- Passive template coverage uses exact reviewed IDs and file digests from the
  pinned image bundle, with an explicit request-cost upper bound.
- UI, API, CLI, and reports must describe persisted action authority rather than
  infer behavior from historical scan-type names.
- Compatibility names such as `quick`, `standard`, and `deep` map to V2 policy
  and budget ceilings. Unsafe or nondeterministic legacy behavior is not
  preserved merely for recall parity.
- Any intentional endpoint- or finding-recall reduction requires an explicit
  recorded product decision and a regression-baseline update.

