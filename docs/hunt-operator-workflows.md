# Hunt operator-workflow improvements

**Status:** feature-frozen integration batch (PR #217). No new features are being added to this
batch. Remaining changes are defect fixes, migration checks, documentation reconciliation and
final-commit acceptance. This batch does not complete the entire original investigation roadmap.

## Goal and frozen scope

Carry explicitly authorized work further without repeated consent prompts or unnecessary restarts.
Preserve operator cancellation, selected identities, target binding, measured usage and the distinction
between useful observations and verified vulnerabilities. A missing executor is a capability gap,
not an authorization problem.

Implemented in this batch:

- Target-specific consent once when absent, reuse of standing authorization, and public Hunt-start
  examples using server budget defaults without copied approval-receipt IDs.
- Safe retirement of leftover `CLAUDE.md` during upgrades and agent-workspace preparation, including
  pre-manifest installations. Preserve local edits under non-loaded backup names and symlink targets.
- A blocking MI-6 trust-anchor gate that requires actual, unwaived passes rather than matching a
  documentation string. Expected optional NSE probes become coverage gaps rather than execution
  errors; genuine failures and measured request accounting remain intact.
- Selectable partial methodologies with separate missing-executor and withheld-permission metadata.
  Web methodology can guide device/network web interfaces. Fresh operator signals take precedence;
  service fields are normalized and previous suggestions are not treated as new observations.
- Methodology bodies and shared core guides use ShakerScan's real API rather than nonexistent schemas,
  fictional adapters or a second approval/budget engine. Existing investigation techniques remain.
  Native service/device methodology is available through the same library and installed kit.
- Shared service intelligence reuses canonical settled Hunt receipts alongside Scan/device evidence,
  with ownership, content identity, observed locator, timestamps, partial-result and deletion handling.
- Operator-requested budget extensions and immediate or deferred resume of unfinished exhausted
  Hunts, with a desktop/mobile editor and durable, revisioned, idempotent amendment history.
- Honest submission-only versus full-investigation guidance, requested-retest guidance and a pinned
  historical link in the 0.8.0 release notes.

## Execution and evidence boundaries

A methodology is knowledge, not an executor or authority grant. Compatible techniques remain useful
when other techniques are unavailable; unexecuted work is a coverage gap, not a clean test or finding.
MQTT, SSH, SMB, SNMP, UPnP and DLNA signals can select native service methodology. Observed web surfaces
can pivot to web methodologies. Arbitrary protocol-message execution is not supplied by those guides.

Shared `service_intelligence` projects persisted observations from `ports.discover`,
`service.fingerprint`, `web.probe`, `http.request` and `collections.replay_safe`. It reuses the existing
atomic settlement store, identity and retention. It does not add network activity or backfill writes
on GET, a duplicate observation database, unlimited all-time materialization or new Scan planning.
Positive observations from partial/interrupted actions remain useful without claiming complete tests.
Unknown backend addresses remain unknown; changed-locator evidence is not silently rebound. Missing,
invalid or truncated sources are explicit and do not erase other usable observations.

The anonymous NSE redirect exception is confined to the same frozen asset under its saved active
network authority. It loads no credentials and does not expand a saved selected-service binding.
Credentialed service selection retains its separate existing checks. HTTP or an invalid certificate
is not itself a reason to abandon explicitly authorized testing.

## Deferred follow-up work (not merge requirements for this frozen batch)

- Executable end-to-end child-result continuation, beyond the corrected planner instructions.
- Multi-step browser workflows and native protocol transports beyond the advertised capabilities.
  Authorized HTTP writes and active collection replay are described in [HTTP workflows](hunt-http-writes.md).
- General mid-run changes to principal slots and request collections; budget amendments do not do this.
  HTTP workflows can explicitly bind a new same-target profile ID/version for a pairing PIN.
- Richer investigation-frontier/freshness handling and optional legacy history reconstruction.
- Credential transport-consequence visibility and broader synthetic transmission acceptance.
- Independent paired efficacy evaluations, patched controls and operator-intervention measurements.

These remain product work, not capabilities implied by passing unit tests. Follow-up changes should
use the existing Hunt runtime and retained knowledge, not a parallel scanner or orchestration engine.

## Stabilization and validation

Use repository generators for manifests and public contracts; never hand-author digests. Validate
installation/migration, the combined methodology and evidence paths, budget/resume concurrency and
cancellation, UI behavior, native tests, and the complete locked Python suite. Report skips separately.
Final merge readiness requires the normal checks on the final commit, including built-stack E2E and
SBOM coverage. A previous batch's green result is not a substitute for final-commit validation.

Scanner dependency installation retries the same package set after refreshing signed APT indexes;
persistent failures still fail the build. Registry access failures must not be concealed by omitting
supporting images, inventing credentials or silently substituting a different image digest.

## Operator budget extensions

Hunt profiles are sized so that no call, verification, browser or HTTP budget runs out before the
profile's duration. Every call that runs is charged at least one second of the duration, and each
limit covers the duration at the most one call can be charged in that second (one call and one
verification; 32 browser actions and 128 requests, a login check's charge):

| Profile | Duration | Calls | HTTP requests | Verifications | Browser actions | Approval-gated calls | Records |
|---|---|---|---|---|---|---|---|
| `fast` | 1 h | 3,600 | 460,800 | 3,600 | 115,200 | 3,600 | 3,600 |
| `balanced` | 4 h | 14,400 | 1,843,200 | 14,400 | 460,800 | 14,400 | 14,400 |
| `thorough` | 24 h | 86,400 | 11,059,200 | 86,400 | 2,764,800 | 86,400 | 86,400 |

These are ceilings, not promised traffic: every call stays paced by its executor. Approval-gated
calls may use the whole call allowance because each one still checks its approval receipt. The
safety ceilings keep their values: TCP ports (100 / 1,200 / 10,000), state-changing requests
(4 / 20 / 80), hosts, UDP ports, out-of-band interactions and device fragility, as do the policy
switches and approvals that turn them on. At the defaults, logging in, mapping a web application
and verifying what it finds needs no budget raise. SQLi and XSS calls reserve their useful paced
execution envelopes on all three profiles; insufficient headroom asks for a budget raise instead of
silently shortening the call. Start warnings use the actual executor reservation.

Evidence-linked finding recording shares `max_candidates` with candidate records and remains
available on an unfinished exhausted Hunt. It does not spend target traffic or execution calls,
and a full allowance or a refused write never stops the Hunt; a refused write spends nothing. A
Hunt's findings hold at most 64 MiB; a write past it is refused and nothing is charged. Finding
locations keep the evidenced service's scheme and port and are stored in one spelling (lower-case
scheme and host, no default port). A relative path stays on the target's own service when that
service is evidenced, and otherwise follows the single evidenced service on the target host; a
device locator or `host://` asset is a host. Use an absolute URL when the evidence spans several
services. Creating a finding the Hunt already recorded with the same title and URL returns the
existing record unchanged, spends nothing, and says whether newly cited evidence was attached
(`findings.update` attaches it).

On finish, the server proposes the Hunt's reusable read-only and verification steps in the
target's one rolling retained-checks proposal for `shakerscan knowledge review`. It never saves
them, even when the target delegates instruction changes, and the metadata opt-out skips it. The
proposal keeps one copy of each step and the newest 16, leaves out steps a saved action already
holds or that you rejected in the latest rejected one, is updated in place by later finishes, and
is not counted against the proposals a Hunt may file. A step is proposed only when every input is
on its capability's allowlist and carries no query value, header, body, browser input, session,
credential or origin on another host, and only when its path names no action (log out, reboot,
firmware, checkout...), credential or code and carries no payload character or dot segment.
Accepting it saves one saved action. The debrief's `saved_action` field reports `proposed`,
`updated`, `unchanged`, `skipped` or `not_saved`. This requires finishing the Hunt; a disconnected
planner does not finish automatically.

The Hunt UI now offers **Extend this Hunt's budget** for unfinished active, awaiting-planner and
budget-exhausted runs. An explicit operator edit sets a new **total**, not a delta. Startup profiles
remain convenient defaults; this endpoint can increase their limits, including total TCP attempts
for full-port work. Actual calls still use their existing per-action limits and batching.

Read the current run's `budget_revision`, `budget`, `budget_used`, and
`budget_amendable_dimensions`. Submit `POST /hunts/{id}/budget-amendments`, for example:

```json
{
  "schema_version": "hunt-budget-amendment/v1",
  "limits": {"max_tcp_ports": 65535},
  "expected_revision": 0,
  "idempotency_key": "operator-port-range-extension-1",
  "operator_confirmed": true,
  "resume": true,
  "reason": "Operator requested all TCP ports on the same authorized asset"
}
```

Use the revision actually returned by the server, and a fresh retry key for each distinct operator
edit. Reuse the same body/key after a lost response; it cannot apply the increase twice. A concurrent
edit returns a revision conflict rather than overwriting another operator's choice. The API accepts
multiple dimensions in one transaction; the UI edits one dimension at a time.

`resume: true` moves an unfinished budget-exhausted run to `awaiting_planner` only when its reported
exhausted dimension has headroom. No action is started automatically. Without resume, exhaustion
remains until deliberately addressed. After extending without resuming, use the existing
`POST /hunts/{id}/resume` or **Resume with current budget**; it checks current headroom without
another increase or resetting usage. Completed, failed, cancelled or finalized exhausted runs
are not reopened. Exhausted unfinished runs remain cancellable, including their owned child jobs.

The existing Hunt row lock serializes amendments with admission/settlement/cancellation. Usage and
outstanding holds never reset; earlier action/reservation objects and the admission snapshot stay
unchanged. The denormalized current policy budget mirrors the new limits, but its permissions and
capability allowlist do not change. Increased device request/fragility ceilings preserve pacing,
health/traffic freezes and all usage; device daily and child-scan limits remain independent. A zero
ceiling can be increased only where the saved policy already permits it; this does not add a
capability originally excluded from the run.

A budget refusal of one action no longer becomes a `failed` row that replays forever. The action is
parked under its key (`awaiting_permission`) with a `budget.raise` permission request; a person's
grant is exactly one amendment of this kind (key `permission:<request id>`, `resume: true`), and the
same key then re-runs full admission. An amendment made here also lets a parked action through on
its next retry. See `docs/hunt-permission-requests.md`.

`GET /hunts/{id}/budget-amendments?after_revision=0&limit=50` pages the durable history, which also
appears in `/record` with explicit truncation. Events retain before/after limits, the usage snapshot,
redacted reason and status transition. Retry-key hashes are internal. Deleting the owning Hunt or
target cascades the event history; this audit table is not a second traffic ledger.

This completes budget-only amendments, not adding principals/collections, clearing device health
pauses, arbitrary protocol execution, or an autonomous child-result driver. Each remains separate
unfinished work above. Budget extensions must reflect a real operator request, never an agent's
silent response to an exhausted allowance.
