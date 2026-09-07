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
