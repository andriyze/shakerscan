# Hosted workspace connector (read-only preview)

This is a small HTTPS client and stdio MCP adapter, not a scanner installation or a
customer-network execution agent. It does not require Docker. The SaaS gateway must
implement `shakerscan.workspace-capabilities/v1` and the pairing endpoints first.
These changes require publication in an upstream release before existing installed
runtimes or digest-pinned SaaS UIs receive them.

From this source checkout, with Python 3.12+:

```sh
python3 scripts/hosted_connection.py login --tenant https://YOUR-TENANT.example.com
python3 scripts/hosted_connection.py status
python3 scripts/hosted_connection.py mcp
python3 scripts/hosted_connection.py logout
```

Login prints a short code and opens the tenant's pairing page. Sign in through the
platform if needed, then return to that page and review the code. Only approve a
connection you initiated. This is account-access approval, not permission to scan a domain.
Domain scope remains administrator-managed.

The proof-bound pairing expires in ten minutes. The resulting credential is stored in
`~/.config/shakerscan/connection.json` with mode 0600, bound to the exact tenant origin.
It expires with the approving workspace session (at most one hour). There are no refresh
tokens in this preview. Revoke connections from the tenant's Local tool connections page,
or use logout. Tenant logout invalidates credentials bound to that tenant session; global
platform logout is not an immediate distributed revoke.

For an MCP-capable coding client, configure Python as the executable and the absolute
path to `scripts/hosted_connection.py`, followed by `mcp`, as its arguments. Select a
different private connection file with `--connection PATH` before the subcommand.
Do not put bearer tokens in prompts, command arguments or MCP configuration JSON.
Provider-specific auto-install/launch integration is not included yet.

The preview offers only workspace capabilities and bounded target/finding metadata.
It never advertises Hunt, arbitrary HTTP, shell or raw evidence tools. The adapter rejects
redirects and the server independently enforces scope. Metadata remains untrusted content;
the user's coding client may send it to its model provider.

Hunt requires a later, reviewed hosted execution grant, target-bound admission, shared
capacity accounting, cancellation and reconnection tests. Merely allowing a remote API
origin or changing an environment variable does not enable hosted Hunt.

## Remote Hunt integration target (not implemented)

The intended `shakerscan` CLI experience is to select a remote workspace, authenticate
through its browser pairing flow, and use the existing Hunt tools from Codex, Claude,
or OpenCode through a local stdio MCP server. These are product requirements, not new
commands available in this preview. Keep local scanner startup optional: connecting to
a hosted workspace must not start Docker or install a second execution engine.

The remote gateway owns account access, tenant isolation and commercial admission.
The public engine continues to own target binding, execution budgets, approvals,
capability execution, evidence and proof. The coding client supplies the planner;
disconnecting it does not imply that an autonomous planner continues remotely.

Before advertising any Hunt tool, negotiate both workspace capabilities and the existing
`/hunts/contract`. A read-only connection must never become an execution grant merely
because the server later enables Hunt. Require a separately reviewed execution scope.
Persist the selected origin and run ID, not target credentials or raw evidence. Reconnect
by reading authoritative run state; never retry an ambiguous start as a new run. If the
current start contract cannot reconcile that ambiguity, add and test the smallest generic
idempotency extension upstream before enabling hosted starts.

Release acceptance must exercise expiry, revocation, cancellation, interrupted starts,
resume without duplicate work, tenant/scope denial and bounded execution with evidence.
Keep all remote behavior opt-in and regression-test normal standalone Hunt. A connector
to hosted execution is not a runner into the customer's private network; that requires
a separate outbound runner design and placement policy.

## Scheduled execution integration status

`api/schedules/managed_dispatch.py` provides a tested, opt-in HTTPS dispatch
transport for an operator-owned admission gateway. It rejects redirects, bounds
response size and request time, preserves a caller-supplied occurrence identity
across retries, and never treats denied/uncertain admission as successful execution.
This adapter is **not connected to the scheduler yet** and does not enable hosted
schedules or change standalone scheduling.

Before wiring it in, persist an occurrence UUID separately from `next_run_at`:
the current claim helper changes `next_run_at` to lease time, which cannot be used
as a stable retry identity. Integration must route every managed occurrence through
admission, preserve unknown outcomes, and never fall back to local enqueue. Active
and authenticated recurring authority, ASM schedules, suspension, cancellation,
and restart reconciliation require separate end-to-end coverage. Existing public
schedule validation still applies; this transport does not grant broader scope.
