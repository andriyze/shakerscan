# Bounded Research Agent

Use the `research-agent` skill. ShakerScan has **two autonomous engines**: **Operator** (the
menu-driven research episodes / Deep Hunt campaigns — picks vetted actions, can reach VERIFIED, has
the UI) and **Explorer** (the keyless free-form ReAct hunt — composes its own probes, discovers
net-new SUSPECTED bugs, API-only). Everything below through `/research/*` is Operator; the keyless
`/agent/hunt/*` path is Explorer.

**Usage:** `/research <target-id|episode-id|campaign-id> [objective]`

## Operator (menu-driven research episodes / Deep Hunt campaigns)

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

## Explorer (keyless free-form ReAct hunt)

When the user asks for an **autonomous / keyless deep hunt** to discover net-new bugs, use the
**Explorer** engine instead of Operator: `POST /agent/hunt/{target_id}/session`, then
drive it one turn at a time via `POST /agent/hunt/session/{run_id}/reply` with a fenced
` ```json {"tool_calls":[...]} ``` ` block, ending in a `{"done":true,"findings":[...]}` debrief. See
the `research-agent` skill's "Explorer — Keyless ReAct Deep Hunt" section for the full contract — in
particular, drive only while `status: awaiting_planner` (stop on `completed`/`failed`/`cancelled`),
and debrief findings must cite `evidence_refs` (the `resp_N` refs from `http_request`); prose is not
evidence and is dropped. For an authenticated target, configure managed principals + credential
profiles first, or the hunt runs anonymous-only.

Use `/settings/research-agent` and `/settings/research-agent/runs/{id}` for user-facing Hunt links.
`/campaigns` is the separate read-only mission-action ledger, not the place to launch or control a
Deep Hunt.
