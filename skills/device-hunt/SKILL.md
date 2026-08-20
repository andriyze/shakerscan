---
name: device-hunt
description: Compatibility entry point for the unified ShakerScan Hunt workflow. Use only when an older prompt says Device Hunt; follow the canonical hunt skill and /hunts API with a device target.
---

# Device Hunt compatibility

Device Hunt is now the device-target form of **Hunt**. Do not start the legacy
`/devices/{id}/agent/session` planner.

Read and follow [`../hunt/SKILL.md`](../hunt/SKILL.md) in full. Start `POST /hunts` with the exact
registered device target ID. Bind request collections only at creation. Secrets remain worker-only,
device fragility limits remain server-owned, and all capability calls must use the canonical Hunt
manifest returned for that run.

The runtime remains the sole executor and authority boundary. Never expand device scope, approval,
credentials, request collections, or budgets during the Hunt.
