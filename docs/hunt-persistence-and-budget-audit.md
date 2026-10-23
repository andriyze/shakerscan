# Hunt persistence and budget audit

**Status:** describes Hunt finding persistence, recording, finish retention and budget behaviour
as of 2.11.1.

## Nonstandard service ports

The historical finding-save failures compared a finding's port with the inventory locator's
port. A host asset (`host://example.test`) has no HTTP port, so even an absolute finding URL on
its completed HTTP evidence's port 8081 was refused. Relative paths also failed because resolving
them against a `host://` locator produces no usable HTTP origin. An earlier fix accepts a finding
on a service when the same Hunt has successful HTTP evidence from it on that asset.

Two remaining cases are fixed here. Relative paths on HTTP inventory records used the inventory
origin even when all cited evidence was on another service: `https://example.test` plus evidence
from `https://example.test:8443/admin` saved `/admin` against 443. Relative locations now use the
single evidenced service; ambiguous services require an absolute URL. Explicit locations also
recognize same-host origins already frozen in the Hunt context, so incomplete archive capture
does not prevent recording unverified metadata. These changes neither send traffic nor confer
authority on a service.

A device locator (a bare host name or IP literal, IPv6 with or without brackets) is now a host
like a `host://` asset: a relative path takes the single evidenced service on it, and a cited
device HTTP probe names the service it reached. On a URL target a relative path stays on the
inventory's own service whenever that service is among the evidenced ones. A `host://` asset with
no evidence and one frozen origin resolves a relative path as it already accepted the absolute URL.
Malformed frozen origins refuse the write as an input error.

Separately, finding creation used an unconditional insert despite the unique target/fingerprint
constraint. A second creation under a new action key raised a database error. It now returns the
same Hunt's existing record unchanged, including one with verification history, without replacing
its evidence, operator state or verification history, and says whether newly cited evidence was
attached (`findings.update` attaches it).

## Exhausted Hunts and recording

`findings.create|update|delete` used to consume execution calls, active calls and wall time. Both
the API admission guard and finding writer also rejected `budget_exhausted`. A Hunt could gather
evidence, spend its execution allowance, and then be unable to save its conclusions, even though
candidate recording already remained available.

Finding mutations now reserve one unit of the existing `max_candidates` allowance through the
shared durable ledger. They remain evidence-linked, Hunt-owned and unverified, and keep their
existing active-testing and approval checks. Only these registry-declared recording capabilities
gain the unfinished-exhausted exception. Finished, failed and cancelled Hunts remain closed;
recording does not resume traffic or reset any consumed budget. A full allowance refuses only the
write (a person can raise it): the refusal carries no budget state, so it never marks the Hunt
`budget_exhausted` or stops its testing. A refused write and a repeated creation that returns the
existing record spend no unit.

## Verifier reservations and start warnings

Before this release, fast and balanced verifiers reserved the registry floors, a thorough call the
Hunt could not fund stepped down to those floors, and a default profile too small for a
capability produced no start warning, so a Hunt could stop a verification before its verdict
without saying why.

Paced SQLi negative checks had already been measured at roughly 441–475 seconds, above the
300-second floor. Paced XSS checks needed roughly 390–430 seconds, above the 120-second floor.
The longer envelopes (SQLi: 900 requests/540 seconds; XSS: 1,800/480) now apply to all
named profiles, with existing device/headless exceptions retained. New calls do not silently fall
back; old queued reservations and their digests remain executable as originally admitted.

Each profile's call, traffic and verification limits now cover its whole duration at the fastest
pace any executor reserves: 10 requests per second (Nuclei's rate limit and the headless browser's
egress ceiling; katana is held to 5, Dalfox to about 3, sqlmap to about 1, a replay to 25 per
minute, a device to one per second), 0.3 browser actions per second (a nine-step browser action in
30 s), one call per five seconds (the shortest wall any call reserves) and one verification per
60 s (`authz.verify`). So no budget but the duration ends a paced investigation early:

| Profile | Duration | Calls | HTTP requests | Verifications | Browser actions | Approval-gated calls | Records |
|---|---|---|---|---|---|---|---|
| `fast` | 3,600 s | 750 | 40,000 | 60 | 1,200 | 750 | 1,000 |
| `balanced` | 14,400 s | 3,000 | 150,000 | 250 | 4,500 | 3,000 | 5,000 |
| `thorough` | 86,400 s | 18,000 | 900,000 | 1,500 | 26,000 | 18,000 | 20,000 |

The approval-gated call ceiling (`max_active_actions`) rose with the call ceiling, from 4 / 20 / 80
in 2.11.0: any call can need an approval (a session, a principal, a write), and each such call
still checks its approval receipt, so the count is not what gates it. The other authority-dependent
ceilings keep their values: TCP ports, state-changing requests, hosts, UDP ports, out-of-band
interactions and device fragility. Records cost no traffic and get at least one per call. At the
defaults, the standard web workflow (log in, map, discover content, verify, record) draws no start
warning; a remaining default warning names a safety ceiling and matters only when the planned work
needs that capability. Start warnings cost a collection replay by the least it can reserve (one
request) and cost a manifest capability the registry does not know from its manifest entry. These
defaults affect new Hunts only; operator-approved raises remain required beyond a start ceiling.

## Reusable target actions

Completed execution actions were durable, but target recipes were only written when a planner
explicitly invoked `targets.actions.create`. Completion had no retention step. This is separate
from operator instructions and from ordinary execution history.

Finishing now proposes reusable steps for review and never writes a recipe, whatever the target
delegates; the metadata opt-out skips it. Each target has one rolling retained-checks proposal: a
later finish updates it in place, keeps one copy of each step (the newest 16), leaves out steps a
saved action already holds or the operator rejected in the last decided one, and rebases it onto
the current saved actions. It is not counted against the pending proposals Hunts or operators may
file, so it never crowds out a planner's own proposals, and accepting it saves one saved action as
an operator write.

A step is proposed only when every input field is on its capability's allowlist (origins, paths,
read methods, wordlists and a few display options). A step carrying a query value, request header
or body, browser input, capture, session or credential reference, or an origin on another host is
left out entirely, as is a path with a redaction marker, a token-shaped or credential-labelled
segment, or a word that names an action such as log out or delete. The filter reads inputs as the
action ledger stores them, after its redaction, and is tested against that redaction's real output.
Reuse still invokes the canonical capabilities under a new Hunt's scope, credentials, approvals and
budgets.

The finish operation reports its outcome in `final_debrief.saved_action` and the UI. Retries
create no second proposal. An optional retention failure preserves the debrief and reports
`not_saved`. The finish takes the target row (KEY SHARE) before the Hunt row, the order operator
retractions and decisions use. The planner still needs to finish; this change adds no background
planner or automatic completion after disconnection.

## Validation and scope

Regression coverage includes real PostgreSQL schema/migrations, API admission and settlement,
nonstandard HTTP/HTTPS origins, exhausted reporting, creation retries, terminal-state refusal,
saved-action permission modes and finish idempotence. Completed target responses in these tests
are labelled fixtures; the tests send no target traffic. Existing approval, proposal, budget and
reservation tests are retained and exercised. Generated contracts, inventories, installer hashes,
import closure, module-size and documentation gates are checked.

Target-action retention at finish is supplied by the API composition, so the Hunt run service
does not import target persistence. A dispatch test checks that a verifier call the remaining
budget cannot fund starts no worker until an operator amendment raises the limit; the same action
key then runs with the full hold.
