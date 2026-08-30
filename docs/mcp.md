# ShakerScan MCP

**Status:** shipped and contract-tested as of 2026-08-25.

ShakerScan includes a fail-closed MCP stdio adapter over the REST Command Arsenal and canonical
Hunt V2. Arsenal tools remain read-only. Hunt tools wrap `/hunts` directly and inherit its exact
target binding, approval, budget, evidence, and proof enforcement; arbitrary shell is never exposed.

Start it from the source/runtime directory:

```bash
./scanner.sh mcp
```

The scanner API must already be available at `http://127.0.0.1:8080`. Override
the origin with `SHAKERSCAN_API_URL`. Non-loopback origins are rejected unless
`SHAKERSCAN_MCP_ALLOW_REMOTE_API=true` is explicitly set.

Example client configuration:

```json
{
  "mcpServers": {
    "shakerscan": {
      "command": "/absolute/path/to/shakerscan/scanner.sh",
      "args": ["mcp"]
    }
  }
}
```

The adapter exposes two deliberately different trust levels:

Read-only Arsenal inspection:

- `shakerscan_targets`
- `shakerscan_asm_gaps`
- `shakerscan_findings`
- `shakerscan_evidence_manifest`
- `shakerscan_timeline`
- `shakerscan_plans`
- `shakerscan_tool_status`

Target-bound Hunt V2 (including state-changing and target-facing operations):

- `shakerscan_hunt_skills` for catalog routing/suggestions and `shakerscan_hunt_skill` for one
  complete methodology plus its deferred techniques
- `shakerscan_hunt_start`, `shakerscan_hunt_get`, and `shakerscan_hunt_query`
- `shakerscan_hunt_capability` for capabilities returned by that Hunt's manifest
- `shakerscan_hunt_candidate`, `shakerscan_hunt_candidate_update`, and `shakerscan_hunt_candidate_delete`
- `shakerscan_hunt_verify`, `shakerscan_hunt_finish`, and `shakerscan_hunt_cancel`

Arsenal tools read `GET /arsenal/commands`, require the mapped command to remain `read_only` risk,
and dispatch through the audited Arsenal endpoint. Hunt discovery reads `GET /hunts/contract` and
generates the start schema from the live authority contract. The MCP boundary uses only the
canonical `goal` name and sends the complete V2 body: schema version, target kind, policy, budgets,
credential references, capability allowlist, request-collection references, and explicit
`skill_ids`. Suggestions are advisory: the planner reads relevant methodology with
`shakerscan_hunt_skill` and chooses supported IDs; MCP never auto-binds them or expands authority.

Before capability execution, the adapter reloads `GET /hunts/{id}`, requires an active or
awaiting-planner run, finds the capability in that Hunt's returned manifest, and validates input
against its published schema. The client may provide an `idempotency_key`; if omitted, the adapter
generates one and returns it as `mcp_idempotency_key` so a retry can reuse the exact action identity.
The runtime still revalidates target binding, approval, budgets, evidence, and proof contracts.
Catalog/contract drift, redirects, oversized responses, unavailable APIs, and unexpected dispatch
results fail closed.

Tool annotations reflect these boundaries: Arsenal inspection and Hunt get/query are read-only;
capability and verification operations are conservatively marked destructive and open-world;
start, candidate create/update/delete, finish, and cancel are state-changing. Candidate updates
cannot change identity or proof-owned fields; deletion expires the candidate while retaining its
immutable audit record. Raw secrets, target-address overrides,
planner argv, and arbitrary shell commands are not representable. Input schemas enforce UUIDs,
enums, required/nested fields, patterns, uniqueness, and numeric bounds before dispatch. The
transport also caps request and response sizes and rejects redirects.
