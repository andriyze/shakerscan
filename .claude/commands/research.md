# Bounded Research Agent

Use the `research-agent` skill to create or continue a target-bound research episode or Deep Hunt campaign.

**Usage:** `/research <target-id|episode-id|campaign-id> [objective]`

If the first argument is a target ID, create a read-only episode and report its ID. If it is an
episode ID, fetch the current immutable observation and act as the planner for one decision at a time
through `/research/episodes/{id}/decisions`. Use only commands marked `proposable`; preserve the
server-projected experiment template, query-string/path object-ID placement, principals, cleanup, and
proof predicates. Keep all execution inside ShakerScan. Ask before creating a gated episode and
require the necessary target-matching scope and approval receipts.

When the user explicitly asks for Deep Hunt or multi-episode research, launch
`POST /research/campaigns/launch` with bounded duration and episode ceilings. Use
`planner_mode: "agent"` by default. If a readiness scan or linked scan/retest is queued, report its
ID and stop instead of polling.

Use `/settings/research-agent` and `/settings/research-agent/runs/{id}` for user-facing Hunt links.
`/campaigns` is the separate read-only mission-action ledger, not the place to launch or control a
Deep Hunt.
