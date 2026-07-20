# Deep Hunt compatibility command

Use the `research-agent` skill.

`/research` is retained as a compatibility command, but the user-facing workflow is **Deep Hunt**.
Do not launch the legacy `/research/campaigns/launch` controller for a Deep Hunt request.

Resolve the authorized target, create a target-bound expiring credential approval, then start:

```http
POST /agent/hunt/{target_id}/session
{
  "objective": "...",
  "mode": "deep_hunt",
  "max_iterations": 12,
  "token_budget": 6000,
  "approval_receipt_id": "..."
}
```

Drive the returned run one planner turn at a time through
`POST /agent/hunt/session/{run_id}/reply`, only while its status is `awaiting_planner`. Findings must
cite real `resp_N` values in `evidence_refs`; prose is not evidence. Stop on `completed`, `failed`,
or `cancelled`.

Use `/settings/research-agent?run={run_id}` as the UI link.
