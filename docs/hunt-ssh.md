# Direct SSH in Hunt

**Status:** Implemented direct exec channels; validation evidence belongs to the exact PR revision.

Hunt's `ssh.exec` sends an authorized remote command directly to a target through
the canonical API, durable reservation, agent-tool worker and Paramiko transport.
It does not run device inventory first. `ssh.connect` remains an authentication-only
check for compatibility; a command session is created lazily by the first `ssh.exec`.

## Use

Select an encrypted SSH profile in the Hunt's SSH identity slot. Grant that profile
`ssh.exec` explicitly in Credentials, including active-capability elevation. Existing
`ssh.connect` permission is not silently upgraded. Reuse the target's standing
network-testing authorization and save its host key or authorize first-contact trust.
These are setup choices, not a confirmation prompt before every delegated command.
Selected SSH access needs active authorization and the exact SSH grant, without
requiring port discovery permission. Discovery tools keep their separate permission.

The Live SSH tab streams stdout/stderr and supports cancellation and saving a
command as a target action. Through MCP, `shakerscan_hunt_ssh_exec` emits progress
notifications; `shakerscan_hunt_ssh_output` polls output and `shakerscan_hunt_ssh_cancel`
cancels one action. Tool calls on the same MCP connection may overlap.
A command that ends without a result is reported `refused` only when it provably did not run:
the request was refused before the stream opened, or the engine recorded no such action. Any
other failure, including an error after output was streamed, is `outcome: "unknown"` with the
action ID to read through `shakerscan_hunt_ssh_output`; the adapter never suggests sending an
uncertain command again.

For log correlation, run a bounded watch through SSH and issue the external check
while it is running. The dedicated agent worker admits at most three leased jobs
at once; Scan workers remain sequential. A device Hunt admits one SSH command and
one external traffic action concurrently, retaining all health and budget checks.
The planner must actively drive the investigation.

```bash
shakerscan api POST /hunts/HUNT_ID/capabilities/ssh.exec \
  '{"idempotency_key":"ssh-inspect-0001","input":{"command":"uname -s","port":22}}'

# Use the returned session_id. An omitted port keeps the session's bound port.
shakerscan api POST /hunts/HUNT_ID/capabilities/ssh.exec \
  '{"idempotency_key":"ssh-inspect-0002","input":{"session_id":"SESSION_ID","command":"pwd","cwd":"/tmp"}}'

shakerscan api --stream --timeout 340 POST /hunts/HUNT_ID/ssh/exec \
  '{"idempotency_key":"ssh-inspect-0003","input":{"session_id":"SESSION_ID","command":"uname -a","timeout_seconds":30}}'

shakerscan api POST /hunts/HUNT_ID/ssh/actions/ACTION_ID/cancel

shakerscan api POST /hunts/HUNT_ID/capabilities/ssh.close \
  '{"idempotency_key":"ssh-close-0001","input":{"session_id":"SESSION_ID"}}'
```

Replace the uppercase IDs with returned UUIDs. Streaming `accepted` events expose
the canonical action ID; `output` events are untrusted cumulative snapshots,
not chunks to append blindly; `result` is the durable action outcome. A dropped
stream requests cancellation. Poll `/hunts/{id}/ssh/actions/{action_id}/output`
for the current bounded output, retained briefly in Redis. Completed canonical
records retain the final output under normal Hunt record retention.

The Live SSH console supports HTTP LAN deployments as well as HTTPS and displays
terminal status and errors alongside any partial stdout/stderr. MCP cancellation
has separate bounded capacity so eight busy execution calls cannot delay a stop
request behind the commands it needs to cancel.

The selected target remains frozen. There is no input for another hostname,
credential value or arbitrary local argv. All target kinds supported by network
Hunt can use SSH; command permission is declared separately from authentication.
A lost session does not cause a new login or a command retry. A new command without
a session ID explicitly opens a new connection. Reusing an idempotency key reads
the original operation rather than repeating a potentially state-changing command.

## Execution behavior

Transports are owned by an agent-tool worker and bound to the Hunt, target digest,
frozen address, port, credential ID/version and pinned host key. Subsequent calls
are routed to that same worker through the existing durable queue. Each command
uses a new exec channel; shell working directory/environment are not persistent.
An optional absolute POSIX `cwd` is quoted before use. No PTY, interactive stdin,
port forwarding or agent forwarding is provided. Commands receive stdin EOF.

Commands default to 30 seconds, with an explicit ceiling of 300 seconds. Setup has
a bounded allowance, and output defaults to 64 KiB with a maximum of 256 KiB across
stdout/stderr. Output limits and timeouts preserve partial results and stop local
IO. Nonzero exit status is a completed remote command result, not a fabricated
vulnerability or scanner failure. Check the returned exit status.

No network connection or authentication is repeated on a reused transport, and no
new host/port budget is reserved for reuse. Time, action and applicable device
fragility budgets still apply. Direct SSH commands do not inherit the unrelated
HTTP/inventory inter-request cooldown; device quotas and operator freezes remain
enforced. A new device connection costs three fragility points; reuse costs one.
Results include authentication/dispatch and command timings; real acceptance
retains first-command, reuse and first-output latency. Idle transports expire
after two minutes; maximum lifetime is 30 minutes. There are at most 32 transports
per worker. Stopped/deleted Hunts and worker shutdown close their sessions. Owner
loss rejects reuse rather than routing it elsewhere.

Grants, identity versions, target binding and host trust are rechecked before each
command and during execution. Known stored identity secrets are withheld across
output chunk boundaries and redacted. Command/cwd text is encrypted in the queued
payload and represented by hashes in audit summaries. Target output can contain
other sensitive information; it remains operator-visible security evidence.

A command runs with the selected remote account's OS and network permissions.
Target binding is not a remote-process sandbox; use appropriately privileged
accounts and grant command execution only for the operator's intended work.

## Cancellation and limitations

Cancellation closes the channel/transport and drains the worker thread before
settlement. That stops ShakerScan's command IO; arbitrary SSH servers may leave
detached remote processes alive. Interrupted commands therefore report
`execution_uncertain` and do not claim confirmed remote process termination.
There is no automatic retry after dispatch or lost acknowledgement.

The optional planner gateway admits these run-scoped endpoints while retaining
its existing deployment-isolation prerequisites. It is not a sandbox for an agent
that can independently reach the unrestricted operator API or its credentials.

`tests/test_target_asset_ssh_runtime_postgres.py` uses real PostgreSQL, Redis,
FastAPI, the production network worker handler, authenticated SSH and real fixture
processes. The fixture is loopback-only and admits test commands explicitly.
Its cancellation cooperation does not prove arbitrary-server process termination.
