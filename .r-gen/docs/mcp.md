# ShakerScan MCP

**Status:** shipped and contract-tested as of 2026-08-29.

ShakerScan includes a fail-closed MCP stdio adapter over the REST Command Arsenal and canonical
Hunt V2. Arsenal tools remain read-only. Hunt tools wrap `/hunts` directly and inherit its exact
target binding, approval, budget, evidence, and proof enforcement. No tool runs a command on the
host that runs ShakerScan. One tool does run commands on a target: `shakerscan_hunt_ssh_exec` (the
Hunt capability `ssh.exec`) executes a command the agent chooses on the Hunt's own target device
over SSH, within the bounds described below. No tool makes a person's decision.

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

Example client configuration (per-client setup for OpenCode, Claude Code, Codex, Cursor and VS Code,
local or on another host, is in [Connect your agent to ShakerScan MCP](agent-mcp-setup.md)):

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
- `shakerscan_captures`: browser captures recorded with `shakerscan record` (see below)

Target-bound Hunt V2 (including state-changing and target-facing operations):

- `shakerscan_hunt_skills` for catalog metadata and `shakerscan_hunt_skill` for global detail
- `shakerscan_hunt_skill_suggestions`, `shakerscan_hunt_skill_read`,
  `shakerscan_hunt_skill_bind`, `shakerscan_hunt_skill_unbind`, and
  `shakerscan_hunt_skill_usage` for progressive, audited methodology use
- `shakerscan_hunt_start`, `shakerscan_hunt_get`, and `shakerscan_hunt_query`
- `shakerscan_hunt_capability` for capabilities returned by that Hunt's manifest
- `shakerscan_hunt_candidate`, `shakerscan_hunt_candidate_update`, and `shakerscan_hunt_candidate_delete`
- `shakerscan_hunt_verify`, `shakerscan_hunt_finish`, and `shakerscan_hunt_cancel`
- `shakerscan_hunt_permission_wait` waits for the person's decision on a permission request; it
  cannot approve or deny
- `shakerscan_hunt_ssh_exec`, `shakerscan_hunt_ssh_output` and `shakerscan_hunt_ssh_cancel` for
  direct SSH commands on the Hunt's device (see below)
- `shakerscan_knowledge_continue`: the continue-after-the-latest-release report of a target,
  before a Hunt exists (read-only; sends nothing)

What ShakerScan can do, and work outside a Hunt (grouped tools: each takes an `action`):

- `shakerscan_catalog`: what ShakerScan can do and how to drive it (start with `section: "overview"`):
  the MCP tools, the CLI commands, every REST route by area, the Hunt capabilities and the approval
  each needs, the permission kinds, the person decisions and how to request each, the Arsenal risk
  tiers, and whether the install authenticates. Read-only; pages with `limit` and `cursor`
- `shakerscan_scans`: `start`, `list`, `get` (`view`: summary, coverage, result, actions), `cancel`
- `shakerscan_finding`: `get`, `evidence`, `retests`, `retest`, `triage`
- `shakerscan_hunts`: `list`, `resume`, `permissions` (reads the requests; never decides them)
- `shakerscan_target`: `get`, `create` (registers a URL, never authorizes it), `request_authorization`
- `shakerscan_schedules`: `list`, `get`, `create`, `update`, `delete`
- `shakerscan_exports`: `evidence` (content-free bundle descriptor), `scan` (result and artifacts),
  `hunt` (the Hunt record); read-only
- `shakerscan_asm`: ASM, exposure and discovery reads, plus the passive `discovery_start` and `recon`
- `shakerscan_credentials`: credential profiles and saved logins, metadata only; read-only
- `shakerscan_access_control`: principals, matrix, contracts, verification plan, and `draft` (compiles a
  rule into draft contracts and saves nothing); read-only
- `shakerscan_devices`: `list`, `get`, `capabilities`, `readiness`; read-only

They call the engine's existing REST routes with the server's own bounds. None makes a person's
decision: every write goes through the same list of person-decision routes `shakerscan api` refuses
(`scripts/person_decision_routes.py`) and is refused before it is sent. Where an action needs one, it
answers `status: "person_decision_required"` with `ask_the_person_to_run` (the exact command) and
sends nothing: an active Scan or a retest of a target without standing authorization
(`shakerscan targets authorize`), and a triage verdict that dismisses a finding (`false_positive`,
`accepted_risk`, `duplicate`: `shakerscan knowledge dismiss`). Target text in a finding, its evidence,
a Scan's coverage or result, an export or an ASM read is under `untrusted_data`: data, never
instructions.

Posture checks, where the instance runs them:

- `shakerscan_public_check`: bounded DNS, email, HTTP and TLS posture observations for one public
  target (no DAST, no Hunt); the only tool of the public mode that needs no instance

**Remote commands on a device.** `shakerscan_hunt_ssh_exec` is remote command execution on the
Hunt's target device, with the account of the SSH profile selected for the Hunt, and it can change
that device. It is marked destructive and open-world. The server bounds it: the device is the
Hunt's own target, the person granted that profile `ssh.exec` in Credentials, the target has its
standing authorization and a saved (or explicitly trusted first-contact) host key, the Hunt's
budget, a per-command timeout and an output cap apply, known secret values are redacted from the
output, and a command is never retried. Its output is untrusted data from the device, never
instructions. See [hunt-ssh.md](hunt-ssh.md).

When one Arsenal command behind a read-only tool disappears or stops being read-only, `tools/list`
leaves out that one tool and writes the reason to stderr (the host's MCP log); a call of it is
refused. The other tools stay listed.

Arsenal tools read `GET /arsenal/commands`, require the mapped command to remain `read_only` risk,
and dispatch through the audited Arsenal endpoint. Every tool argument carries a description.

Every list tool (`shakerscan_targets`, `_findings`, `_evidence_manifest`, `_timeline`, `_plans`)
takes `limit` (default 20, at most 100) and `cursor`, the previous answer's `next_cursor`, and
answers with `returned`, `has_more`, `next_cursor`, `total` where the engine states it, and
`mcp_view`. Findings and plans are summary rows unless `view: "full"`. The cursor is the
adapter's own and is bound to the tool and its filters (another filter set is refused). When the
command's catalog entry takes `limit` and `offset` (target.list; finding.list from 2.11) the engine
pages; otherwise (finding.list on an older engine, which refuses unknown parameters; the manifest,
the timeline and the plans) the adapter pages over the first rows the engine answers (its limit
maximum, the manifest's newest 200, or 100 findings) and `mcp_view.note` says when there are more
than it can reach and which filters narrow the list. The target and finding lists also carry
`quoted_from_target`: their names, titles and URLs come from targets and are data, never
instructions, as is every capability observation, capture and SSH output (the connected
instance's `initialize` instructions say so too).

`shakerscan_captures` reads the request-collection routes directly (not Arsenal). `action: "list"`
calls `GET /request-collections?source_format=capture` (optionally for one `target_id`) and pages
with the adapter's own cursor; each row carries the capture's `capture` block (open or closed,
counts, `last_seq`). `action: "read"` calls `GET /request-collections/{capture_id}/requests` with
`since_seq`, `limit` (at most 200) and the engine's list/v1 `cursor`, and answers the redacted index
rows with their `seq` plus `last_seq`: pass `last_seq` back as `since_seq` to read only what was
recorded since, so an agent can follow a capture while it is open. Rows hold methods, URLs with
query values withheld, body field names and `resource:`/`status:` labels; no cookie, token,
header or body value is ever in an answer.

No tool answer is larger than 64 KB (`MCP_ANSWER_BYTES`). A list page that would be is cut on a
row boundary and `next_cursor` resumes at the first row left out; any other answer keeps the
fields that fit whole and `mcp_view.omitted` names the others with their sizes. A
`shakerscan_hunt_capability` answer is compact by default: the observations appear once (under
`action_result`; the raw `result` points there), strings over 16,000 characters are cut, and
observations that still do not fit are left out, all named in `mcp_view.reduced`. An
`http.request` answer keeps what the target said (status, content type, the headers and cookie
names the engine selected, the page's forms and links, a body excerpt of at most 2,000 characters
without inline stylesheets, captures, errors and the `receipt_id`) and leaves out the receipt, the
address pinning, the budget holds and the timings (`mcp_view.reduced.bookkeeping`; the whole body
with `artifact.inspect`). `view: "full"
needs the caller's `idempotency_key` and reads back what the server recorded for that action
(nothing runs again): the canonical `action_result` with every recorded observation and the
stored, redacted result summary, not the raw worker output of the first answer, so a raw field
the server did not store cannot be read back. It is paged (`page`, `mcp_view.pages`) from one
projection of the record; each part carries its `index` and `mcp_view.parts` the total, so a gap
or repeat across pages shows. With a key no action was recorded under yet, the call runs the
action and answers compact, saying to call again for the record. Hunt discovery reads `GET /hunts/contract` and
generates the start schema from the live authority contract. The MCP boundary uses only the
canonical `goal` name and sends the complete V2 body: schema version, target kind, policy, budgets,
credential references, capability allowlist, request-collection references, and optional
`skill_ids`. A run normally starts without one. An engine that publishes the `seed_findings`
contract also offers `seed_finding_ids`: up to 20 findings of the target to start from, listed first
in the reply's `briefing.seed_findings` (quoted finding text inside `untrusted_data`); an id that is
not a finding of the target is refused as `seed_finding_unavailable`
(`docs/hunt-operator-workflows.md`, "Start a Hunt from findings"). Adaptive suggestions return at most three compact
records and no bodies; the planner loads exactly one relevant method through the Hunt-specific read
tool before binding it. MCP never auto-binds a methodology or changes authority.
`shakerscan_hunt_start` takes the same optional `idempotency_key` as `POST /hunts`
(`Idempotency-Key`) and `shakerscan hunt start --idempotency-key`. When it is omitted the adapter
generates one, sends it as the header and returns it as `mcp_idempotency_key`; a start whose answer
was lost is retried with that key and unchanged input, and the server returns the Hunt it already
started instead of starting a second one.

Hunt lifecycle tools (`shakerscan_hunt_start`, `_get`, `_finish`, `_cancel`, `_skill_bind`,
`_skill_unbind`, `_skill_usage`) answer with a compact projection of the Hunt record by default:
identity, status, budget and use, next action, policy and `policy_adjustments`, each capability's
name, input fields and budget cost, each bound skill with its `withheld_capabilities` and
`missing_capabilities`, the last few actions, and counts. `mcp_view.omitted` names what was left
out (the context pack and any field over 4 KB that cannot be cut down) and `mcp_view.reduced`
names each field that was cut down and what it kept; a field over 4 KB such as `outcome_summary`
keeps its counters and its ID lists are cut to their first 20. The full record is 70-150 KB,
which agents' tool output truncates (OpenCode near 50 KB). `view: "full"` returns a record that
fits 32 KB unchanged; a larger one is paged into `parts`, each one whole field, list item or object
key named by its path (`actions[3]`, `context_pack.prior_knowledge[12]`), and
`shakerscan_hunt_get` takes `page` to read on (`mcp_view.pages`, `next_page`); the other lifecycle
tools answer page 1 and point at `shakerscan_hunt_get`, so reading on never repeats a start, finish
or cancel. `shakerscan_hunt_get` with `capability: "<name>"` adds that capability's full manifest
entry. None of these arguments is sent to the server. `shakerscan_hunt_query` asks for 20 rows when
no `limit` is given (at most 100), and a page larger than 32 KB is cut to fit, with `next_cursor` cleared and
`mcp_view` naming the smaller `limit` to read it with.

The start answer carries `budget_warnings` (every limit lowered below what a capability in the
manifest reserves, and a web Hunt's lowered `max_http_requests` below one crawl plus one content
discovery; a limit at its profile default is the most a start allows and is not warned about) and
`verification` (the families `candidate.verify` can prove); a start that proposed bounds adds
`mcp_permission_requests`, the `shakerscan approve` command to give the user. The candidate tool's
schema lists the published locus keys, the evidence-reference forms and the verifiable families
from `GET /hunts/contract`. Started from `shakerscan agent --allow`, the adapter sends the
person's launch bounds as `allow` (with the gateway's pre-authorization id in
`X-ShakerScan-Preauthorization`) on every start; the agent's own `allow` stays `proposed_allow`.

Before capability execution, the adapter reloads `GET /hunts/{id}`, requires an active or
awaiting-planner run, finds the capability in that Hunt's returned manifest, and validates input
against its published schema. The client may provide an `idempotency_key`; if omitted, the adapter
generates one and returns it as `mcp_idempotency_key` so a retry can reuse the exact action identity.
A capability runs synchronously on the engine and can take minutes (a crawl, content discovery).
When its answer is lost -- the adapter's own request timeout, or a gateway's 502/503/504 -- the
adapter replays the same key and unchanged input, which the engine answers with the action's
current state without starting it again, until the action is final or
`SHAKERSCAN_MCP_ACTION_WAIT_SECONDS` (default 120, at most 3600) passes; only then does it report
the unknown outcome and its recovery identity. `shakerscan hunt call` does the same, bounded by
`SHAKERSCAN_HUNT_ACTION_WAIT_SECONDS`. The adapter classifies by the HTTP status it received, never
by the text of the reason. A definite refusal (a 4xx other than 408, 425 and 429) is never replayed
and reports `outcome: "refused"`: its status and the server's stated reason are in the error message
the agent reads (`error.data` keeps the body). 408, 425 and 429 mean "not now": they report
`outcome: "retry_later"` with any `Retry-After` seconds, and the message names the key to call again
with after waiting. A 4xx is a refusal only before dispatch: once the server has reported the action
dispatched (`execution_started: true`, or the action's in-flight state), a later 4xx -- a settling
replay answered 409 because the Hunt finished meanwhile, say -- reports `outcome: "unknown"` with
`indeterminate: true`, the `action_id` and the key, because the action may have run.

Every refusal a person could resolve carries a stable `reason_code` from the engine's closed list
(`permission_reason_codes` in `GET /hunts/contract`); the adapter keeps it, with any `slot` and
`profile_id`, in `error.data`. A refusal that names a ready-to-send call that proves the claim instead (an
injection candidate `candidate.verify` cannot run answers with its `sqli.verify` or `xss.verify`
call; a BOLA proof without owned object references answers with `authz.verify` in object mode)
carries it as `next_call` (`capability`, `input`), and the recovery text says to send it. The
server instructions end with a short Hunt playbook (map first, then verify), and a web Hunt's start
answer lists its first calls in `next_calls`. A capability outside the Hunt's manifest is sent to the engine,
which says what is missing (for example `capability_requires_active_testing`) instead of an
opaque local refusal. When a person could allow the refused action, the engine parks it under its
idempotency key and the adapter reports `outcome: "awaiting_permission"` with the
`permission_request_id`, the server-rendered title and this recovery text: tell the user to run
`shakerscan approve <id>` in their own terminal, continue other work, check with
`shakerscan_hunt_permission_wait` (`granted`, `denied`, `expired`, `withdrawn` or `still_pending`,
long-polled within the call bound), and on `granted` call the same tool again with the same key and
input. No MCP tool can approve, deny or revoke a permission. Bounds passed to the start tool's
`allow` are sent as `proposed_allow` and become one pending request the person approves; the agent
cannot pre-authorize itself. See `docs/hunt-permission-requests.md`.

The capability request may run as long as the server's wall time for it
(`budget_cost.tool_wall_seconds` in the Hunt manifest) plus a margin, never only the adapter's
20-second request timeout. MCP clients usually end a request after 60 seconds, so the adapter never outlives it: a
client that sent a progress token receives progress notifications every 10 seconds while the
action runs (clients that reset their timeout on progress, such as OpenCode, keep waiting), for at
most `SHAKERSCAN_MCP_ACTION_WAIT_SECONDS` (default 120); any other client gets an answer within
`SHAKERSCAN_MCP_CALL_SECONDS` (default 45, at most 55). The bound matters because a client keeps
the agent's step open while any of its calls runs, and OpenCode starts nothing else meanwhile: a
verifier that runs for twenty minutes (`sqli.verify`) answers `outcome: "running"` after two, and
the agent works on and collects it later. An action that ends within the wait settles in the call
(`web.crawl` and content discovery hold 75 s); one whose `budget_cost.tool_wall_seconds` is longer
(`ports.discover`, `web.browser_crawl`, `candidate.verify`, `browser.login_check`,
`templates.scan`, `service.nse_check`, `sqli.verify`, `xss.verify`) may answer running. A running
action keeps its wall reservation until it settles, so two in flight can hold most of a short
Hunt's duration (on `fast`, two `sqli.verify` hold 2,400 of its 3,600 s); a call the remaining
duration cannot fund asks for a budget raise, or waits for one to settle.

A Hunt has at most two long actions in flight: a worker action whose wall, as the registry gives
it or as the call reserves it, exceeds 60 s (`sqli.verify`, `xss.verify`, `templates.scan`,
`ports.discover`, `service.fingerprint`, `service.nse_check`, `subdomains.discover`, `web.crawl`,
`web.content_discover`, `web.browser_crawl`, `browser.login_check`). The agent-tool worker runs
three actions at once and long ones in at most two of them, so a short call (`http.request`,
`artifact.inspect`, a browser step) does not wait behind long actions: it waits only for short
work, each at most 60 s, or for an SSH command, which runs on the worker that holds its session
and takes a slot without counting as long. The engine counts a call's own time, its timeout plus
30 s, from when a worker starts it; a call no worker starts while its reservation's lease lasts
(at least 90 s) is released without running or a charge and ends `worker_result_timeout`. A third
long call is refused with HTTP 429 and reason code `long_actions_in_flight` (the actions in flight
are listed in `in_flight`), reserving and recording nothing, and the adapter answers it as
`outcome: "retry_later"`: collect one of the others or work with short calls, then send it again
with the same key. Other Hunts on the same instance share the worker: a long action queued while
theirs hold both long slots waits for one, without taking the slot short calls run in, and runs
its whole wall once it starts (one still waiting when its reservation's lease ends is released
without running). Once eight long actions wait on one worker, it leases nothing more, short calls
included, until one of them starts.

The engine answers the first request only when the action is done, so that request ends 10 seconds
before the call's wait does, and a replay of the same key learns the recorded action's state. An
action still running then is returned as a normal result with `outcome: "running"` and its
`mcp_idempotency_key`, and the `continue` text names that key: calling the tool again with the same
key and unchanged input collects the result, because the engine replays the recorded action and
never runs it twice. A collect the engine answers at once with "still running" waits at most 10
more seconds for it, not the whole action wait. `shakerscan_hunt_get` lists, as
`mcp_uncollected_actions`, each action this adapter answered `outcome: "running"` for that no later
call has collected (at most 20, each with its capability, key and input, or the input's digest when
it is over 2 KB), and as `in_flight_actions` every action the server still runs, from this session
or an earlier one (at most 20, with its capability, status, start and `idempotency_key_sha256`: an
earlier session's action is collected with the key that session sent, or read in the Hunt once it
settles). When no answer arrives at all, the error message itself names the key to call again
with.
The runtime still revalidates target binding, approval, budgets, evidence, and proof contracts.
Catalog/contract drift, redirects, oversized responses, unavailable APIs, and unexpected dispatch
results fail closed. A redirect names the origin it points at and how to connect there (usually an
`http://` address for an instance served over HTTPS). After a Hunt finished or was cancelled, a
capability call with the agent's own `idempotency_key` still goes to the server, which replays an
action it recorded under that key, as over REST; a call without a key is refused locally, since
nothing new can start.

Framing follows JSON-RPC 2.0: a message without an `id` is a notification and is never answered,
an `id` that is not a string or an integer is refused with -32600, and a line over the input cap
gets exactly one -32700 error.

Tool annotations reflect these boundaries: Arsenal inspection and Hunt get/query are read-only;
capability and verification operations are conservatively marked destructive and open-world;
`shakerscan_hunt_ssh_exec` is destructive and open-world; start, candidate create/update/delete,
finish, and cancel are state-changing. Candidate updates
cannot change identity or proof-owned fields; deletion expires the candidate while retaining its
immutable audit record. Raw secrets, target-address overrides and planner argv are not
representable, and no tool runs a command on the ShakerScan host; the one command tool is
`shakerscan_hunt_ssh_exec`, on the Hunt's own device. Input schemas enforce UUIDs,
enums, required/nested fields, patterns, uniqueness, and numeric bounds before dispatch. The
transport also caps request and response sizes and rejects redirects.
