# Hunt recording, finish proposals and budgets

**Status:** describes how a Hunt records findings, what finishing proposes for reuse and how the
Hunt budget profiles are sized, as of 2.11.1.

## Finding locations

A finding's location is bound to a service the Hunt may name on its own target host:

- An absolute URL must be the inventory's own service, a service that answered one of the cited
  evidence actions, or an origin frozen in the Hunt's context, on the target host.
- A relative path stays on the inventory's own service when that service is among the evidenced
  ones (or nothing is evidenced). Otherwise it takes the single evidenced service on the target
  host, including its scheme and port: `https://example.test` with evidence only from
  `https://example.test:8443/admin` records `/admin` on 8443. Several evidenced services need an
  absolute URL.
- A `host://` asset and a device locator (a bare host name or IP literal, IPv6 with or without
  brackets) are hosts, not services: a relative path takes the single evidenced service on that
  host, a cited device HTTP probe names the service it reached, and a `host://` asset with no
  evidence and one frozen origin resolves a relative path on that origin.
- A finding created without a path follows the same rules. The single evidenced service on the
  target host takes it, with the path its evidence names (the service's root when the evidence
  names several paths): `https://example.test` with evidence only from
  `https://example.test:8443/admin` records `https://example.test:8443/admin`. Among several
  evidenced services the inventory's own takes it when it is one of them, otherwise the one most
  of the evidence came from (a tie goes to the first by scheme, then port). With no evidenced
  service it takes the inventory's own location, or a `host://` asset's or device's first frozen
  origin; a host with neither is refused with a message to cite the service's evidence or give
  an absolute URL. That refusal is an input error: nothing is charged.
- The stored location has one spelling: the scheme and host in lower case, a default port left
  out and the path and query as written. `HTTPS://EXAMPLE.TEST:443/x` is stored as
  `https://example.test/x`. A port outside 1-65535 is refused.
- Malformed frozen origins refuse the write as an input error.

Choosing a location sends no traffic and grants no authority on a service.

## Recording

`findings.create|update|delete` are evidence-linked, Hunt-owned and unverified, and keep their
active-testing and approval checks. They spend no calls, approval-gated calls, wall time or
target traffic: each reserves one unit of `max_candidates`, the record allowance shared with
candidate records, through the shared ledger.

- An unfinished `budget_exhausted` Hunt can still record. Finished, failed and cancelled Hunts are
  closed. Recording never resumes traffic or resets a used budget.
- A full record allowance refuses only that write (a person can raise it). The refusal carries no
  budget state, so it never marks the Hunt `budget_exhausted` or stops its testing.
- A refused write and a repeated creation that returns the existing record spend no unit.
- Creating a finding the Hunt already recorded with the same title and location returns that
  record unchanged, including one with verification history, and says whether newly cited
  evidence was attached (`evidence_attached`); `findings.update` attaches it.
- A Hunt's findings hold at most 64 MiB as stored in UTF-8 (title, description, notes, URL and
  evidence document). A create or update that would pass it is refused with a message naming the
  limit; nothing is written or charged and the Hunt keeps running. The largest finding is about
  40 KB of ASCII text, so about 1,650 of them fit, or about 155 KB of four-byte characters, so
  about 430 fit; typical findings of a few kilobytes fit by the tens of thousands.
- A Hunt's candidate writes stop at 256 MiB of its candidate records as stored in UTF-8 (each
  write's candidate row and observation: title, claim, evidence references, locus and context). A
  create, boundary-draft sighting or correction that would pass it is refused with
  `candidate_bytes_limit` and a message naming the limit; nothing is written or charged and the
  Hunt keeps running. About 1,030 candidates of the
  largest size fit (four-byte characters at every limit, about 260 KB each); a typical candidate
  of a kilobyte or two fits by the hundred thousand.

## Finish proposals

Finishing proposes the Hunt's reusable steps for an operator to review with
`shakerscan knowledge review`. It never writes a saved action, whatever the target delegates, and
the target's metadata opt-out skips it. The outcome is reported in `final_debrief.saved_action`
(`proposed`, `updated`, `unchanged`, `skipped` or `not_saved`) and on the results page.

- Each target has one rolling retained-checks proposal. A later finish updates it in place,
  keeps one copy of each step and the newest 16, leaves out steps a saved action already holds or
  that the operator rejected in the latest rejected retained proposal, and rebases it onto the
  current saved actions. Accepting it saves one saved action as an operator write. Because later
  finishes change it in place, an accept must name the `methodology_sha256` of the text the
  person reviewed (`shakerscan knowledge review` sends it); without it the accept is refused with
  `proposal_review_required`, and a digest of older text with `proposal_text_mismatch`.
- It is not counted against the pending proposals Hunts or operators may file, so a planner keeps
  its whole proposal allowance.
- A finish reads the Hunt's newest 2,000 completed actions in the order they ran.
- A step is proposed only when every input field is on its capability's allowlist (origins,
  paths, read methods, wordlists and a few display options). A step carrying a query value,
  request header or body, browser input, capture, session or credential reference, or an origin
  on another host is left out entirely.
- A path is left out when it has a redaction marker; a character other than letters, digits and
  `/ _ . ~ -` (quotes, `$( )`, `;`, `=`, encoded values); a dot segment; a token-like or
  letter-and-digit code segment; a letters-only capability token (both cases and 12 or more
  letters, or 8 or more not shaped like a camelCase word, such as `ZXhhbXBsZQ`); a word that names
  a credential (token, pin, otp, verify...); or a word that names an action, whether the
  crawler's (log out, delete, reset...), a device or physical control (reboot, firmware, on, off,
  open, disarm, format, move, wake...) or a web state change (apply, checkout, transfer, ban,
  purge, clear, stop, refund, redeem, claim, like, migrate, merge, resend, empty...).
- These rules leave out what they recognise; no word list knows every action a target names. The
  proposal therefore describes its steps as completed steps that can be replayed, which a person
  reviews before accepting, not as read-only.
- The filter reads inputs as the action ledger stores them, after its redaction. Reuse still
  invokes the canonical capabilities under a new Hunt's scope, credentials, approvals and budgets.

A retry of the finish creates no second proposal, and a retention failure keeps the debrief and
reports `not_saved`. The finish takes the target row (KEY SHARE) before the Hunt row, the order
finding writes, operator retractions and decisions use. The planner still has to finish: nothing
finishes a disconnected Hunt automatically.

## Budget profiles

The duration is a Hunt's clock: every call that runs is charged the wall it took against
`max_duration_seconds`, and at least one second. Each call, verification, browser and HTTP limit
covers the whole duration at the most one call can be charged per second of that wall:

- one call, one approval-gated call and one verification per second;
- 32 browser actions per second (a login check is charged its 32 actions conservatively; an
  eight-step `browser.interact` with a one-second timeout is 9);
- 128 HTTP requests per second (a login check's 128 admitted attempts; a browser call is up to 50,
  a collection replay 25, a candidate verification 24). Scanner and network tools run at their own
  rate or delay: Nuclei at 10 requests per second, katana at 5, the headless crawler at 10 of
  egress, Dalfox about 3 and sqlmap about 1.

So a paced investigation reaches the end of its duration before any of these limits:

| Profile | Duration | Calls | HTTP requests | Verifications | Browser actions | Approval-gated calls | Records |
|---|---|---|---|---|---|---|---|
| `fast` | 3,600 s | 3,600 | 460,800 | 3,600 | 115,200 | 3,600 | 3,600 |
| `balanced` | 14,400 s | 14,400 | 1,843,200 | 14,400 | 460,800 | 14,400 | 14,400 |
| `thorough` | 86,400 s | 86,400 | 11,059,200 | 86,400 | 2,764,800 | 86,400 | 86,400 |

These are ceilings, not promised traffic: every call stays paced by its executor. An
`http.request` refused before it sends anything (a scope or approval refusal) is charged the
wall it took, at least a second, not its 15-second hold. A paced Dalfox or sqlmap verification whose own request
log is missing is charged its rate (4 and 2 requests a second) over the seconds it ran plus its
workers' first requests, never less than the proxy saw and never more than its hard bound. Two
charges are not a pace an investigation keeps up and are not covered: a call admitted but refused
before it starts is charged one call and no wall, and a scanner whose traffic the proxy cannot
count and whose launch sets no request rate (headless Dalfox, for one) is charged its hard bound
even when the run ended early.

The approval-gated call ceiling (`max_active_actions`) is the call ceiling, up from 4 / 20 / 80
in 2.11.0: any call can need an approval (a session, a principal, a write), and each such call
still checks its approval receipt, so the count is not what gates it. The safety ceilings keep
their values: TCP ports (100 / 1,200 / 10,000), state-changing requests (4 / 20 / 80), hosts, UDP
ports, out-of-band interactions and device fragility, as do the policy switches and approvals
that turn them on. Records cost no traffic and no wall and get one per call.

`sqli.verify` reserves 900 requests / 540 s and `xss.verify` 1,800 requests / 480 s on every
profile (a device target and a headless `deep_domxss` call keep the registry holds). A call the
remaining budget cannot fund is refused with a budget request a person can grant, never started at
a shorter hold; a call admitted at an older hold runs at the hold it reserved.

## When a limit is used up

Only the duration ends a Hunt. When `max_duration_seconds` is used up, a call that needs wall time
is refused and the Hunt becomes `budget_exhausted` (stop reason
`budget_exhausted:tool_wall_seconds`); it still records findings and candidates, and a person's
raise continues it.

Every other limit, a safety ceiling or a call, traffic or record limit, refuses only the actions
that need more of it. The refusal names the dimension (`error` `budget_exhausted:<dimension>`,
`reason_code` `budget_exhausted`, or `budget_insufficient_for_action` while some is left), the
action waits for a `budget.raise` request the person approves with
`shakerscan approve <request-id>` (or they raise the limit on the Hunt page), and the Hunt keeps
its status: the planner and every action that needs none of that dimension carry on, and once the
limit has room the action's retry with the same key goes through full admission. A
dimension whose permission is off is 0 for the Hunt and is refused with
`budget_dimension_needs_permission`; a raise cannot grant it. The ceiling values are unchanged:

| Used-up ceiling | `fast` / `balanced` / `thorough` | Refused | Hunt status |
|---|---|---|---|
| State-changing requests | 4 / 20 / 80 | `http.request` with a write method, `browser.workflow`, `browser.login_check`, `collections.replay_active`, a mutating `candidate.verify`, any call that reserves writes | keeps running |
| TCP ports | 100 / 1,200 / 10,000 | `ports.discover`, `service.fingerprint`, `service.nse_check`, `tls.inspect`, `ssh.connect` / `ssh.exec`, `device.service.verify`, a device TCP service verification | keeps running |
| Hosts | 50 / 500 / 5,000 | `ports.discover`, `service.fingerprint`, `service.nse_check`, `service.snmp.inspect`, `subdomains.discover`, `ssh.connect` / `ssh.exec` | keeps running |
| UDP ports | 100 / 1,000 / 5,000 | `service.snmp.inspect`, `device.service.verify` and a device UDP service verification | keeps running |
| Out-of-band interactions | 10 / 50 / 200 | calls that reserve out-of-band callbacks | keeps running |
| Device fragility | 20 / 100 / 500 | device probes, scans, service checks and SSH, and on a device Hunt the web and network calls that reserve fragility for their traffic | keeps running |
| Duration | 3,600 / 14,400 / 86,400 s | every call that runs | `budget_exhausted` |

Hosts and TCP ports are counted once per Hunt where the action names them. A network action
whose commands name one address per host reserves only the hosts this Hunt has not attempted.
`ports.discover` with listed ports, a range or a listed profile, `service.fingerprint`,
`service.nse_check` and `tls.inspect` reserve only the ports this Hunt has not attempted, so
fingerprinting or inspecting a port a sweep already reached needs no new allowance. A `top_100` or
`top_1000` sweep does not name its ports and is charged all of them; the open ports it reports
count as attempted. A `tls.inspect` is one port, whatever handshakes it makes. Attempted ports are
remembered in a bounded record; a port it cannot hold is charged again. A mutating
`candidate.verify` reserves 12 state-changing and 24 requests and is charged what its workflow
sent (both runs and the create probe); a verification that reports no count (a device
verification, an error, a browser step) keeps its whole hold.

A Hunt that ended `budget_exhausted` on another dimension under an earlier release keeps that
status and resumes as before once that dimension has room.

At the defaults, logging in, mapping a web application, discovering content, verifying and
recording draw no start warning. A remaining default warning names a safety ceiling and matters
only when the planned work needs that capability (`ports.discover` on `fast`, for example). Start
warnings cost a collection replay by the least it can reserve (one request) and cost a manifest
capability the registry does not know from its manifest entry. The profiles apply to new Hunts;
a running Hunt's limits are raised only by a person: an approved `budget.raise` request or an
amendment on the Hunt page. An agent never amends its own budget.

## Tests

The finding, recording, finish and proposal paths are covered by PostgreSQL tests of the real
schema, API admission and settlement (nonstandard HTTP and HTTPS services, exhausted recording,
the byte bound, repeated creations, terminal-state refusal, the rolling proposal and the planner
proposal allowance, finish idempotence) and by unit tests of the location, retention and ledger
rules. Retention is tested on the output of the ledger's real redaction. The budget test settles
real calls (`http.request` with and without redirects, `candidate.verify`, an eight-step
`browser.interact`, `browser.login_check`, a 25-request replay) against the real ledger on every
profile and requires the duration to refuse first. A used-up ceiling is settled through the real
refusal, ledger and port accounting in unit tests and through API admission in a PostgreSQL test,
which requires the Hunt to stay active and admit a request that needs no port. Completed target
responses in these tests are labelled fixtures; the tests send no target traffic.
