# Hunt persistence and budget audit

**Status:** source audit and focused regression validation; no deployment or target testing.

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

Separately, finding creation used an unconditional insert despite the unique target/fingerprint
constraint. A second creation under a new action key raised a database error. It now returns the
same Hunt's existing record without replacing its evidence, operator state or verification history.

## Exhausted Hunts and recording

`findings.create|update|delete` used to consume execution calls, active calls and wall time. Both
the API admission guard and finding writer also rejected `budget_exhausted`. A Hunt could gather
evidence, spend its execution allowance, and then be unable to save its conclusions, even though
candidate recording already remained available.

Finding mutations now reserve one unit of the existing `max_candidates` allowance through the
shared durable ledger. They remain evidence-linked, Hunt-owned and unverified, and keep their
existing active-testing and approval checks. Only these registry-declared recording capabilities
gain the unfinished-exhausted exception. Finished, failed and cancelled Hunts remain closed;
recording does not resume traffic or reset any consumed budget.

## Verifier reservations and start warnings

Before this release, fast and balanced verifiers reserved the registry floors, a thorough call the
Hunt could not fund stepped down to those floors, and a default profile too small for a
capability produced no start warning, so a Hunt could stop a verification before its verdict
without saying why.

Paced SQLi negative checks had already been measured at roughly 441–475 seconds, above the
300-second floor. Paced XSS checks needed roughly 390–430 seconds, above the 120-second floor.
The existing reviewed envelopes (SQLi: 900 requests/540 seconds; XSS: 1,800/480) now apply to all
named profiles, with existing device/headless exceptions retained. New calls do not silently fall
back; old queued reservations and their digests remain executable as originally admitted.

Startup ceilings now leave room for repeated work: fast 5,000 HTTP requests/80 execution calls,
balanced 20,000/300, thorough 100,000/1,500. Duration and recording allowances grow accordingly.
Authority-dependent network, mutation, device-fragility and OOB ceilings retain their existing
values. These defaults affect new Hunts only. Start warnings use actual executor holds and disclose
impossible default reservations; operator-approved raises remain required beyond a start ceiling.

## Reusable target actions

Completed execution actions were durable, but target recipes were only written when a planner
explicitly invoked `targets.actions.create`. Completion had no retention step. This is separate
from operator instructions and from ordinary execution history.

Finishing now retains up to 16 distinct completed, reusable network steps in one target recipe.
The target's current permissions are read under lock: instruction delegation saves directly,
otherwise the existing review-proposal path applies; metadata opt-out prevents either write.
Bodies, masked material, transient captures and SSH commands are excluded. Session references
become required parameters with no saved session defaults. Reuse still invokes the canonical
capabilities and their new Hunt's scope, credentials, approvals and budgets.

The finish operation reports its retention result in `final_debrief.saved_action` and the UI.
Retries create no duplicate recipe or proposal. An optional retention failure preserves the
debrief and reports `not_saved`. The planner still needs to finish; this change adds no background
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
