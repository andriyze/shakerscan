# Hunt evidence review and continuity

**Status:** Implemented review/integrity tooling on the 2.3.0 integration branch; offline scorer and CI gate only, no live efficacy measurement.

This change builds on the recorded live acceptance in `hunt-authorization-behavior.md`
at `bbaa84c9`, documented by `80abc5d0`. Those two positive leads and the no-lead
control remain acceptance evidence, not a human-productivity study or verified recall gain.

## Retained history versus current assessment

Investigation responses now include `candidate_history`, `candidate_relation`, and
`candidate_matches_latest_attempt`. The compatibility `candidate` field is the most
recent retained association, even when a later attempt is denied or inconclusive.
`historical_only` does not claim that the latest attempt reproduced the lead.
The latest assessment, proof state, and immutable candidate assertions are unchanged.
Propose/read/skip use the same non-executing history projection; none materializes a lead.

Candidate materialization locks the existing proposal row before checking its deterministic
link. The candidate, observation, and link are committed together. Concurrent retry callers
must recheck the link after acquiring that lock. An error writing the link rolls the
candidate and observation back. No new table, proof path, or execution capability is added.

## Review in the existing Hunt page

Opening a saved run at `/hunt?run=<hunt UUID>` displays an investigation review panel
above the operational ledger. It pages existing proposals, reads one selected investigation,
and shows current assessment, retained leads, unresolved questions, attempt/receipt/transaction
references, and supported-request limitations. Refresh is explicit. The panel cannot propose,
approve, execute, or promote anything; these changes do not broaden replay support.

The existing `graph_nodes` query accepts `node_type` and `hunt_id` filters. Its attributes
projection exposes allowlisted UUIDs, digests, and enums for authorization records, not arbitrary
graph attributes or raw request content. Target scoping and cursor/filter binding remain enforced.
Unsupported attributes are marked omitted. This is bounded resume metadata, not a complete target graph.

## Offline human-review measurements

The existing scorer accepts optional `--investigations` (an array of unmodified investigation
GET responses) and `--review` (operator-recorded labels and time). Candidate associations must
link to an executed action in the canonical Hunt record. Example review file:

```json
{
  "hunt_id": "<the exported Hunt UUID>",
  "human_minutes": 12.5,
  "useful_lead_ids": ["<an exported candidate UUID>"],
  "not_useful_lead_ids": [],
  "duplicate_experiments": 0
}
```

These values are operator-recorded, not technical proof. Missing measurements are null, not
zero. Labels must be disjoint and refer to exported candidates. They never increase verified
findings or recall, and a single review cannot demonstrate productivity improvement. Exports
remain operator-trusted; the scorer does not authenticate edited files or execute verification.

Settled conservative full-reservation charges are now reported as upper bounds, separately
from measured traffic. Unknown accounting cannot establish complete exact cost.

## Validation boundary

`Hunt record integrity` runs the focused Python tests, a disposable real PostgreSQL locking
and rollback test, UI unit tests, and a UI build. Set `HUNT_TEST_POSTGRES_DSN` to a disposable
local database to run the PostgreSQL test locally; configured-but-unavailable databases fail
rather than silently skipping. Each test removes only its own random schema.

The database test executes production repository SQL but uses a minimal schema, not the full
migration path. The checks do not run an offensive workload or establish live worker, browser
workflow, multi-model, or paired human-productivity acceptance. The unchanged independent
protocol in `hunt-investigation-evaluation.md` remains the efficacy evaluation requirement.
