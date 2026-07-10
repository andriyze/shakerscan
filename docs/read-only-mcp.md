# Read-only MCP

ShakerScan includes a fail-closed MCP stdio adapter over the REST Command Arsenal.
It exposes stored product state only and does not expose scan submission, ASM
mutation, retests, replay, policy writes, shell, or arbitrary code execution.

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

For every tool listing and call, the adapter reads `GET /arsenal/commands` and
requires the mapped command to remain `read_only`, `read_only` risk, and `GET`.
Calls then go through `POST /arsenal/execute`, preserving normal command-result
auditing. Catalog drift, redirects, oversized responses, unavailable APIs, and
unexpected dispatch results fail closed.
