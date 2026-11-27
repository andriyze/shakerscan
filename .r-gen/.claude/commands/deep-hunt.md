# Hunt compatibility command

Run an authorized, AI-driven Hunt against the supplied target.

**Usage:** `/deep-hunt <target-url-or-id> [objective]`

Use the `research-agent` skill. Deep Hunt is a compatibility name for the canonical `/hunts/*`
workflow: adaptive exploration, bounded capabilities, evidence-backed candidates, and deterministic
promotion where supported. It is not a DAST scan and must not use either legacy planner engine.

Check the target's standing authorization (`shakerscan api GET /targets/{id}/authorization`). When
active testing is requested and the target has none, ask the person to run `shakerscan targets
authorize <target>` in their own terminal and wait for them: authorizing a target or recording an
approval receipt is the person's decision, never yours. Then start one `/hunts` run, which resolves
that standing authorization itself, and plan through its returned capability manifest.
