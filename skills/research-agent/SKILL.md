---
name: research-agent
description: Compatibility entry point for the unified ShakerScan Hunt workflow. Use only when an older prompt says Deep Hunt or autonomous research; follow the canonical hunt skill and /hunts API.
---

# Deep Hunt compatibility

Deep Hunt is now **Hunt**. Do not start the legacy `/agent/hunt/*` or `/research/*` planners.

Read and follow [`../hunt/SKILL.md`](../hunt/SKILL.md) in full. Translate older wording as follows:

- Deep Hunt, autonomous research, or autonomous hunt → one target-bound `POST /hunts`
- planner turns → capability calls chosen by the current external coding agent
- suspected findings → evidence-backed Hunt candidates
- promotion → the registered deterministic candidate verifier

The runtime remains the sole executor and authority boundary. Never expand target scope, approval,
credentials, request collections, or budgets during the Hunt.
