# Progressive Hunt methodology selection

Start with the operator's objective and known target evidence. No selected methodology is a valid
starting state; do not load every playbook or make the operator assemble a fixed prerequisite list.

## Evidence-driven routing

Call `POST /hunts/{hunt_id}/skills/suggestions` with concise observed signals such as GraphQL,
JWT, upload, SSH or MQTT. Fresh operator signals take priority over old context. A signal suggests
knowledge; it does not authorize a capability or prove a service was tested.

Read a relevant methodology through `POST /hunts/{hunt_id}/skills/{skill_id}/read`, bind it when
used, and record usage/completion/deferral with real source action IDs. Prerequisites are expanded
by the library. Keep their capability gaps visible rather than making the operator name them all.

## Supported, partial and reference knowledge

Supported and useful partial methodologies are selectable. Missing executors are separate from
permissions withheld by a run, and untested techniques remain explicit. Read reference material
when useful without pretending it is an executable skill. A technique-level limitation must not
hide all the knowledge in a relevant methodology.

Web/interface methods also apply to device or network assets with that surface. Native protocol
observations deserve a protocol methodology; an asset label alone does not invent an HTTP interface.
Select by observed surface and objective while preserving the real asset kind and service binding.

## Compose without shrinking authority

Binding, reading, switching or combining methodologies never grants, removes, narrows or expands
the run's capabilities, scope, approval or budget. Budget metadata is planning guidance, not an
additional per-skill ceiling. Use the running capability contracts, not a list of fictional adapters.

Pick the smallest useful test for a hypothesis, interpret its evidence, and pivot as new facts
arrive. A failed optional technique is not the end of the Hunt. Continue another compatible
technique; report the remaining gap when no implemented path can answer the question.
