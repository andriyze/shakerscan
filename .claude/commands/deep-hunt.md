# Deep Hunt

Run an authorized, AI-driven Deep Hunt against the supplied target.

**Usage:** `/deep-hunt <target-url-or-id> [objective]`

Use the `research-agent` skill. Deep Hunt means the keyless `/agent/hunt/*` workflow: autonomous
exploration, bounded active tools, evidence-backed Suspected findings, and deterministic promotion
where supported. It is not a DAST scan and must not use `/research/campaigns/launch`.

Confirm target authorization, create the required target-scoped credential approval, start with
`mode:"deep_hunt"`, and drive each `awaiting_planner` turn from the current coding-agent session.
