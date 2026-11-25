# Hunt compatibility command

Use the `research-agent` skill.

`/research` is retained as a compatibility command, but the user-facing workflow is **Hunt**.
The legacy `/research/*` runtime and the `/agent/hunt/*` engine are removed; a Hunt request starts a `/hunts` run.

Resolve the target and check its standing authorization (`GET /targets/{id}/authorization`). When
the Hunt needs active testing and the target has none, ask the person to run `shakerscan targets
authorize <target>` in their own terminal and wait for them; never record an authorization or an
approval receipt yourself. The start resolves the standing authorization itself:

```http
POST /hunts
{
  "target_id": "...",
  "objective": "...",
  "budget_profile": "balanced"
}
```

Drive the returned run from the current coding-agent session through its bounded query, capability,
candidate, verifier, and finish endpoints. Candidates must cite real evidence references; prose is
not evidence. Stop on `completed`, `failed`, `cancelled`, or `budget_exhausted`.

Use `/hunt?run={hunt_id}` as the UI link.
