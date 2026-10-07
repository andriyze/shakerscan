# ShakerScan MCP

**Status:** shipped and contract-tested as of 2026-08-29.

ShakerScan includes a fail-closed MCP stdio adapter over the REST Command Arsenal and canonical
Hunt V2. Arsenal tools remain read-only. Hunt tools wrap `/hunts` directly and inherit its exact
target binding, approval, budget, evidence, and proof enforcement; arbitrary shell is never exposed.

Start it from the source/runtime directory:

```bash
./scanner.sh mcp
```

The same adapter runs without the engine from the `shakerscan` client
(`pipx install shakerscan`, `uv tool install shakerscan`, or the Homebrew tap; see
[client.md](client.md)):

```bash
shakerscan mcp --url https://scanner.example.com --token-file ./token
```

The scanner API must already be available at `http://127.0.0.1:8080`. Override
the origin with `SHAKERSCAN_API_URL`. Non-loopback origins are rejected unless
`SHAKERSCAN_MCP_ALLOW_REMOTE_API=true` is explicitly set.

Behind an authenticating gateway (for example a self-hosted Enterprise deployment that fronts
the API with service tokens), set `SHAKERSCAN_API_TOKEN` as well: the adapter sends it as
`Authorization: Bearer` on every call. A token is only ever sent over `https://`; the adapter
refuses to start with a token and a plain-http origin, and it never prints the token. The
product CLI (`./scanner.sh hunt ...`, `scripts/v2_cli.py`) honours the same variable with the
same rule.

```bash
SHAKERSCAN_API_URL=https://scanner.example.com \
SHAKERSCAN_MCP_ALLOW_REMOTE_API=true \
SHAKERSCAN_API_TOKEN=<service token> ./scanner.sh mcp
```

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

- `shakerscan_hunt_skills` for catalog metadata and `shakerscan_hunt_skill` for global detail
- `shakerscan_hunt_skill_suggestions`, `shakerscan_hunt_skill_read`,
  `shakerscan_hunt_skill_bind`, `shakerscan_hunt_skill_unbind`, and
  `shakerscan_hunt_skill_usage` for progressive, audited methodology use
- `shakerscan_hunt_start`, `shakerscan_hunt_get`, and `shakerscan_hunt_query`
- `shakerscan_hunt_capability` for capabilities returned by that Hunt's manifest
- `shakerscan_hunt_candidate`, `shakerscan_hunt_candidate_update`, and `shakerscan_hunt_candidate_delete`
- `shakerscan_hunt_verify`, `shakerscan_hunt_finish`, and `shakerscan_hunt_cancel`

Arsenal tools read `GET /arsenal/commands`, require the mapped command to remain `read_only` risk,
and dispatch through the audited Arsenal endpoint. Hunt discovery reads `GET /hunts/contract` and
generates the start schema from the live authority contract. The MCP boundary uses only the
canonical `goal` name and sends the complete V2 body: schema version, target kind, policy, budgets,
credential references, capability allowlist, request-collection references, and optional
`skill_ids`. A run normally starts without one. Adaptive suggestions return at most three compact
records and no bodies; the planner loads exactly one relevant method through the Hunt-specific read
tool before binding it. MCP never auto-binds a methodology or changes authority.

Hunt lifecycle tools (`shakerscan_hunt_start`, `_get`, `_finish`, `_cancel`, `_skill_bind`,
`_skill_unbind`, `_skill_usage`) answer with a compact projection of the Hunt record by default:
identity, status, budget and use, next action, policy, each capability's name, input fields and
budget cost, the last few actions, and counts, plus `mcp_view.omitted` naming what was left out
(the context pack and any field over 4 KB). The full record is 70-150 KB, which agents' tool
output truncates. `view: "full"` returns the record unchanged, and `shakerscan_hunt_get` with
`capability: "<name>"` adds that capability's full manifest entry. Neither argument is sent to
the server.

Before capability execution, the adapter reloads `GET /hunts/{id}`, requires an active or
awaiting-planner run, finds the capability in that Hunt's returned manifest, and validates input
against its published schema. The client may provide an `idempotency_key`; if omitted, the adapter
generates one and returns it as `mcp_idempotency_key` so a retry can reuse the exact action identity.
A capability runs synchronously on the engine and can take minutes (a crawl, content discovery).
When its answer is lost -- the adapter's own request timeout, or a gateway's 502/503/504 -- the
adapter replays the same key and unchanged input, which the engine answers with the action's
current state without starting it again, until the action is final or
`SHAKERSCAN_MCP_ACTION_WAIT_SECONDS` (default 900, at most 3600) passes; only then does it report
the unknown outcome and its recovery identity. `shakerscan hunt call` does the same, bounded by
`SHAKERSCAN_HUNT_ACTION_WAIT_SECONDS`. The adapter classifies by the HTTP status it received, never
by the text of the reason. A definite refusal (a 4xx other than 408, 425 and 429) is never replayed
and reports `outcome: "refused"`: its status and the server's stated reason are in the error message
the agent reads (`error.data` keeps the body). 408, 425 and 429 mean "not now": they report
`outcome: "retry_later"` with any `Retry-After` seconds, and the message names the key to call again
with after waiting.

The capability request may run as long as the server's wall time for it
(`budget_cost.tool_wall_seconds` in the Hunt manifest) plus a margin, never only the adapter's
20-second request timeout. MCP clients usually end a request after 60 seconds, so the adapter never outlives it: a
client that sent a progress token receives progress notifications every 10 seconds while the
action runs (clients that reset their timeout on progress, such as OpenCode, keep waiting); any
other client gets an answer within `SHAKERSCAN_MCP_CALL_SECONDS` (default 45, at most 55). An
action still running then is returned as a normal result with `outcome: "running"` and its
`mcp_idempotency_key`: calling the tool again with the same key and unchanged input collects the
result, because the engine replays the recorded action and never runs it twice.
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
