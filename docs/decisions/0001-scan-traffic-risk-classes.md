# ADR 0001: Scan traffic risk classes

- Status: accepted
- Date: 2026-08-23
- Amended: 2026-10-07 (read-only exposure checks are passive), 2026-10-10 (the
  fixed GraphQL reads among them), 2026-10-16 (the corporate content-discovery list
  and the opt-in active recon family)
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
The exposure checks' fixed GraphQL reads are the same class: one reviewed
introspection document sent over GET (a GraphQL GET carries only a query
operation, and this one selects only the `__schema` meta field) to fixed
GraphQL paths and to discovered GraphQL routes, and a browser request for fixed
IDE paths. GraphQL documents that exercise a hypothesis (a misspelt field,
repeated aliases) are active (`graphql.verify_batch`), though still GET-only.

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

Content discovery reads one bundled list. With active authority the Scan reads the
common list and then the authored corporate list (mail, identity, VPN gateway and
administration console paths) in the same exact reservation; the traffic stays
read-only GETs, and its larger volume is what active authority buys.

The `recon_active` family is active and explicit: it is in no preset, so no saved
policy or schedule gains it by upgrading, and it needs active testing and a live
approval receipt. It reads only lists the project authored and bundles, measures a
control before reporting anything, meters every question or request against its
reservation, and stops between bounded batches when cancelled:

- Guessing names needs apex authority: the subdomain-discovery authority and an
  operator-declared apex, meaning the bound host is the root itself or its `www` name
  and the root is a registrable domain. The registrable domain of a host bound below
  it (`acme.vendor.example` binds `vendor.example`) is a provider's, so neither
  `dns.enumerate` nor `vhost.discover` is planned, and the bound HTTP executor
  refuses any other Host or SNI for it.
- `dns.enumerate` asks the resolver for `<label>.<apex>` names after a random-label
  wildcard baseline; when that baseline cannot be judged, resolving names are
  withheld and counted. Names are leads recorded like passive discovery (target
  source `dns-enumeration`); nothing is connected to.
- `vhost.discover` requests `/` from the Scan's own frozen origin and address under
  other names below the apex (Host and TLS SNI), against the bound name and random
  never-published names under each apex. It does not apply on a shared edge (a CDN
  or hosting platform named by infrastructure intelligence or the bound name's
  response headers), where the Host header selects other customers' sites. A lead is
  never a route or a target.
- `web.param_discover` sends GETs with random marker values for authored parameter
  names to routes discovery already observed, after a random-name control per route.
  Routes named like actions (the crawler's action words) or carrying token-like
  segments are skipped. A confirmed name feeds the existing candidate pipeline for
  that route.

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

