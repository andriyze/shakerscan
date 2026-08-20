# ShakerScan MCP

**Status:** shipped and contract-tested as of 2026-07-11.

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

The adapter exposes:

- `shakerscan_targets`
- `shakerscan_asm_gaps`
- `shakerscan_findings`
- `shakerscan_evidence_manifest`
- `shakerscan_timeline`
- `shakerscan_plans`
- `shakerscan_tool_status`
- `shakerscan_hunt_start`, `shakerscan_hunt_get`, and `shakerscan_hunt_query`
- `shakerscan_hunt_capability` for capabilities returned by that Hunt's manifest
- `shakerscan_hunt_candidate`, `shakerscan_hunt_verify`, `shakerscan_hunt_finish`, and `shakerscan_hunt_cancel`

Arsenal tools read `GET /arsenal/commands`, require the mapped command to remain `read_only` risk,
and dispatch through the audited Arsenal endpoint. Hunt tools call the canonical `/hunts` API; the
runtime revalidates target binding, the run's capability manifest, approval, budgets, evidence, and
proof contracts. Catalog drift, redirects, oversized responses, unavailable APIs, and unexpected
dispatch results fail closed.

Input schemas enforce UUIDs, enums, required fields, and per-tool numeric bounds before dispatch;
the REST Arsenal validates the command contract again. The transport also caps request and response
sizes and rejects redirects.
