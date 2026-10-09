# Hunt permission requests, granted live

**Status:** design note, revised after owner decisions (2026-10-07); E2 and E3 implemented
2026-10-08. PR E1 implemented the attached credential list and `hunt_credential_uses`. PR E2
implements the engine side: closed reason codes, permission requests, grants, pre-authorization,
the `awaiting_permission` action status, the read/decision/revoke routes, the MCP outcome and wait
tool (see "E2 implementation notes" for where it differs). PR E3 implements the terminal side:
`shakerscan approve|deny`, `hunt permissions`, `--allow`, the approver session and the exact
client protocol the gateway's step-up routes must serve ("E3: the terminal approval protocol and
the G1 contract"). The gateway step-up (G1) is not implemented yet; until it is, an Enterprise
approval ends with an exact error and decides nothing. The owner approved the behaviour and the
decisions recorded below; any code follows this note.

## Problem and decision

A Hunt that hits a refusal a person could have allowed stops that line of work. Examples are a
new port, a second identity, a budget ceiling or a state-changing request. PR #337 passes the
agent the refusal text, but the agent usually gives up or misreads it, and the user has no way to
say "yes, do that".

Hunt is driven from the terminal: the `shakerscan` client with OpenCode, Claude Code or Codex
over MCP. **No Hunt step may require the browser.**

**Decision.**
- **Requests.** When a Hunt action is refused for a reason on the allowable list (catalogue
  below), the server records a **permission request** on that Hunt. The request names exactly
  what is needed, in text the server renders.
- **How a request is granted.** Either the request falls inside bounds the person set when the
  Hunt started (**pre-authorization**), or the person approves it in a terminal with step-up
  proof the agent cannot produce (**terminal approval**). The Hunt page may show requests and
  offer Allow, but it is never required.
- **Retry.** After the grant, the agent retries the same action with the same idempotency key.
- **Only the refused action waits.** A pending request never freezes the Hunt; the agent
  continues other work.
- **Hard limits** never become requests.

The design builds on existing mechanisms: budget amendments, standing target authorization,
credential grants, Hunt authority, approval receipts and `hunt_actions` idempotency.

## What exists today (code this builds on)

| Mechanism | Where | Relevance |
|---|---|---|
| Budget amendment `hunt-budget-amendment/v1` | `api/hunt/budget_amendments.py:50-202`; routes `api/hunt/run_router.py:539-549` | Takes absolute `limits`, `expected_revision`, `idempotency_key` (SHA-256 plus a request digest; the same key with a different body gives 409) and `operator_confirmed`. `resume=true` takes a `budget_exhausted` Hunt back to `awaiting_planner` (`:111-118`). It refuses to raise a dimension whose authority is off (`:91-92`). **A budget grant is exactly one amendment.** |
| Budget dimensions | `HuntBudget`, `api/hunt/start_contract.py:80-131` | 13 dimensions. A dimension whose authority is off is set to 0 at start (`:785-806`). |
| `policy_adjustments` | `start_contract.py:431-456, 561`; written once at `api/api.py:13337` | Informational only and not enforced. Grants get their own record instead. |
| Admission refusal codes (#337, commit `ad61b4ca`) | `record_budget_shortage`, `api/hunt/verification_budget.py:31-47`; `result.refusal{stage:"admission"}` in `run_service.py:293-319` | Only `budget_exhausted:<dim>` and `budget_insufficient_for_action:<dim>`. Every other refusal is a free-text `HTTPException` in `api/hunt/interaction_router.py:1686-2176`. |
| MCP refusal reporting (#337) | `scripts/shakerscan_mcp.py:92-157, 950-1013, 1094-1105` | `data.outcome` is `refused`, `retry_later`, `unknown` or `running`, plus `detail` and `mcp_idempotency_key`. There is no reason code, no wait tool and no elicitation (`:1690`). |
| Action idempotency | `interaction_router.py:1614-1684` | The action id is `uuid5(hunt, "hunt-capability:"+key)`, and a stored row replays **whatever its status**. A budget shortage inserts a `failed` row before raising 409 (`:2250-2274`), so **today a retry after a raise replays the refusal**. A policy 403 stores nothing. |
| HTTP `Idempotency-Key` layer | `api/public_api_contract.py:359-387` | Releases the key on 400/401/403/404/405/413/415/422/429. A **409 leaves the key `processing`**; PR E2 fixes this. |
| Standing target authorization | `api/target_authorization.py:148, 213, 319`; `api/targets/router.py:790-829` | An `approval_receipts` row plus a scope receipt. `evaluate_target_scope` refuses private, loopback and metadata ranges (`api/action_scope.py:25-147`). Hunt start applies it via `apply_standing_authorization` (`run_router.py:193`). |
| Runtime destination scope | `api/action_scope.py:561`; frozen `authorized_target_addresses` (`api/api.py:13183`) | A host discovered during a Hunt is recorded with `testing_authorized:false` (`api/hunt/asset_actions.py:80-86`). |
| Credential grants | `api/credential_api.py:772-826`; kind rules `grant_target_kind_error` `:399`, `target_kinds_share_asset` (`api/runtime/models.py:17`), `_validate_kind_placement` (`credential_store.py:254`); active-capability receipt `:64, :806` | Stored in `credential_profile_bindings` (`binding_kind='target'`, soft `revoked_at`). |
| Hunt authority | `api/targets/hunt_authority_router.py`, `hunt_authority.py` | A revisioned document holding SSH host keys, first-contact trust, and profiles a Hunt may *share* to the target. |
| Credentials selected at start | `credential_refs` (`run_router.py:64`; slots `start_contract.py:56-65`), checked at `api/api.py:13104` | Enforced per action at `interaction_router.py:1790-1806`. |
| SSH command authority | `api/capabilities/ssh_commands.py:49-56`; `docs/hunt-ssh.md` | `ssh.exec` must be in the selected profile's `allowed_capabilities`. The device shell-plan confirm (`interaction_router.py:379-600`) is the precedent for exact-command confirmation. |
| Operator-only routes | `api/hunt/planner_gateway.py:28-47` | Budget amendments, shell-plan confirmation and `/approve` are absent from the planner ingress. |
| Hunt UI decisions | `ui/src/lib/huntRunModel.mjs:73-82`, `HuntRunView.tsx:172-187` | The existing "Needs your decision" section. |
| Gateway identity | Enterprise `store.py` (`mfa_verify` with per-counter replay protection `:1055`), `passkeys.py:117` (RP ID = gateway host), `app.py:481-510` | Client tokens belong to **service identities**, not people (`store.py:1610-1624`). A person proves identity only through login, TOTP or a passkey. |

## Data model

**`hunt_permission_requests`**
- `id`, `hunt_run_id`, `kind`, and `reason_code`. Both kinds and reason codes are closed enums.
- `subject_json` holds only server-resolved values: target id; host as IDNA ASCII; port; resolved
  address and scope verdict; profile id, version and home target; slot; capability; dimension
  with current and needed totals; SSH argv. `subject_digest` is SHA-256 of its canonical JSON.
- Blocked action: `action_id`, `capability_name`, `input_digest`.
- `status`, `created_at`, `expires_at` (24 h or the Hunt's duration deadline, whichever is
  earlier).
- Decision fields: `decided_at`, `decided_by` (a person), `decision_via` (`preauthorization`,
  `terminal_stepup`, `approver_session`, `ui_session`, or `local_confirm` on OSS),
  `decision_scope` (`hunt` or `target`), `decision_choice_json`, `grant_id`.
- A partial unique index on `(hunt_run_id, subject_digest) WHERE status='pending'`, so many
  refusals of the same subject make one request.

**`hunt_preauthorizations`** (bounds set at start)
- `id`, `hunt_run_id`, `bounds_json` (parsed grammar below) and its digest.
- `created_by`, the person; `proof`: `stepup`, `launch_stepup` or `local`.
- `created_at`. The bounds are frozen with the Hunt start contract.

**`hunt_permission_grants`**
- `id`, `hunt_run_id`, `request_id`, `preauthorization_id`, `kind`, `subject_json`,
  `subject_digest`, `scope`, `created_by`, `revoked_at`.
- `persisted_ref`: the receipt, binding or Hunt-authority revision written when the grant is
  remembered for the target.
- Bound to versions: a credential grant binds the profile id and version; a target grant binds
  the locator generation.

**`hunt_credential_uses`** and **`hunt_permission_events`** (append-only audit)
- Credential uses: one row per action that resolved a credential. It records the action id,
  slot, profile id and version, and `source`: `selected`, `selected_shared_from:<target>` (a
  credential selected at start that another target shared by grant), `target_own`,
  `shared_from:<target>`, `live_grant:<grant>` or `preauthorized:<preauth>` (the last two in
  E2).
- Events: `requested`, `decided`, `auto_granted`, `used`, `expired`, `withdrawn`, `revoked`,
  each with actor and source.
- Neither table holds secrets, collections or evidence; only ids and digests.

**New `hunt_actions.status` `awaiting_permission`** (constraint in `db/init.sql:1012` and
`api/retest_contract.py:3473-3530`). It freezes the key, capability and input digest and holds
no budget reservation.

## Credentials: one attached list (owner decision)

A Hunt may use every credential **attached to its target**: the target's own credentials and
principals, plus credentials shared to it from other targets through the existing credential
grants. There is no second list.
- **Selection.** Credentials selected at start (`credential_refs`) narrow or point the Hunt to
  specific slots. When none is selected for a slot, the server resolves an attached credential
  that fits the slot. If exactly one fits, it is used; if several fit, the agent must name one.
- **Unattached credential.** Another target's credential that is not shared to this target is a
  `credential.use` request, unless pre-authorization covers it.
  - Grant for this Hunt only: allowed after the same kind rules the credential-grant route
    applies.
  - "Remember": creates the normal credential grant (`grant_profile`,
    `granted_by="permission-request:<id>"`). The credential then joins the single attached list.
- **Never anything else.**
  - A credential never authorizes a destination. Every use is checked against the Hunt's
    authorized set first.
  - Every use is recorded in `hunt_credential_uses` with its source.
- **Wording to align.** The standing-authorization wording changes to "covers the credentials
  attached to this target", so that code and documentation agree. Places to change:
  - the confirmation text in `ui/src/components/targets/TargetAssetDetail.tsx:85`;
  - `ui/src/components/targets/inventory/AuthorizeDialog.tsx`;
  - the `api/target_authorization.py` docstring;
  - `docs/hunt-http-writes.md:55`.

## State machine

```
request:  pending ─(inside pre-authorization bounds)─▶ granted   (instant, decision_via=preauthorization)
             ├─approve (step-up / approver session / UI / OSS confirm)─▶ granted
             ├─deny───▶ denied
             ├─expiry─▶ expired        24 h or the Hunt's duration deadline, whichever is first
             └─Hunt finished/cancelled/failed, or subject stale ─▶ withdrawn

parked action:  awaiting_permission
   retry, request pending          → 409 permission_required (no state change)
   retry, request granted          → same action id re-admitted through full admission
   retry, denied/expired/withdrawn → settles `blocked` (permission_<status>) and replays as such
```

- The Hunt's own status never changes because of a request.
- Other actions keep running, and the Hunt clock does not pause.
- `budget_exhausted` stays the only Hunt-level stop. A `budget.raise` grant clears it through
  `resume=true`.
- `public_hunt_run` exposes `pending_permission_requests`.

## Catalogue of request kinds

The approver is always a person with the operator or admin role. That person proves it at
approval time, or proved it when setting pre-authorization.

| Kind | Raised by (today's refusal) | Grant effect (this Hunt) | Pre-authorization bound | Remember for target |
|---|---|---|---|---|
| `target.authorize` | destination outside `authorized_target_addresses`; another service port (`api/capabilities/http.py:185`); DNS out of scope (`dns.py:168-181`); discovered host (`asset_actions.py:80-86`) | Adds host[:port] to the Hunt's authorized overlay after `evaluate_target_scope` passes | `target.authorize:<patterns>` | Standing authorization via `authorize_target` |
| `credential.use` | unattached credential named, or no attached credential fits a slot (`interaction_router.py:1790-1806`; BOLA/data-exposure verifier) | Uses that profile id and version in that slot, after kind rules pass | `credential.use:<targets>` | Normal credential grant |
| `capability.enable` | not allowed by policy (`:1755`); state-changing HTTP (`:1762`, `:1912`); active replay (`:1768`); network discovery (`network_inputs.py:55`); OOB | Sets the policy flag and sets the zeroed dimension to the shown default | `capability:state-changing\|oob\|tcp-discovery\|active-replay` | No (v1, owner decision) |
| `budget.raise` | `budget_exhausted:<dim>`, `budget_insufficient_for_action:<dim>` (`interaction_router.py:1923, 2209, 2245`) | One amendment: `expected_revision` read under lock, key `permission:<request id>`, `resume=true` | `budget.raise:<N>x` or `budget.raise:<dim>=<max>` | Never |
| `ssh.exec` | the selected SSH profile lacks `ssh.exec` (`ssh_commands.py:49-56`) | This exact argv (by digest) on this host, for this Hunt | Not pre-authorizable in v1 | Add `ssh.exec` to the profile (existing receipt rule) |
| `ssh.host_trust` | unpinned host key with first-contact trust off | Pins the presented fingerprint for this Hunt | `ssh.host_trust:first-contact` | Save to Hunt authority `ssh_host_keys` |

**Hard limits are never requests and no bound covers them:**
- loopback, private, link-local, metadata and reserved destinations, including an IPv6 spelling
  that carries one (NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, IPv4-mapped, 6to4, Teredo);
- the Enterprise "private network targets: refuse" setting;
- an inactive target or a changed locator;
- a Hunt that is not runnable;
- licence state and slots;
- Enterprise feature toggles: Hunt disabled, active autonomous episodes, `arsenal execute=true`,
  network scans off;
- unregistered capabilities;
- anything outside the catalogue.

## Pre-authorization at start

`shakerscan hunt start`, `shakerscan agent`, the MCP start tool and `POST /hunts` accept
repeated bounds:

```
--allow budget.raise:2x                 # each dimension up to 2x its start limit
--allow budget.raise:max_http_requests=5000
--allow credential.use:<target-id|host>,...   # credentials attached to those targets
--allow target.authorize:api.example.com,*.staging.example.com:443
--allow capability:state-changing
--allow ssh.host_trust:first-contact
```

Rules for bounds:
- **Parsing and validation.**
  - Bounds are parsed by the server.
  - Host patterns are IDNA ASCII and must name a registrable domain or a name below one, checked
    against the bundled Public Suffix List including its private section (`api/scope/psl.py`, a
    pinned snapshot, never fetched at runtime). `*`, `*.com`, `*.co.uk`, `*.github.io`,
    `*.herokuapp.com` and `co.uk` are refused ("`*.co.uk` is a public suffix; name a domain you
    control, e.g. `*.example.co.uk`"); `*.example.co.uk` and `*.user.github.io` are accepted. The
    same rule applies to `credential.use` hosts.
  - A pre-authorization stored before this check that names a public suffix is shown as stored,
    with a `refused_bounds` entry explaining why, and covers nothing. It is never reinterpreted
    as a narrower bound.
  - Every host (bounds, destination subjects, credential home hosts, approval screens) is spelled
    by one strict IDNA 2008/UTS #46 canonicalizer (`scanner_tools/host_names.py`), as the HTTP
    client connects: `straße.example` is `xn--strae-oqa.example`, never `strasse.example`. A host
    strict processing refuses (a ZWJ/ZWNJ outside its script, a malformed `xn--` label) is
    refused, not re-encoded with the IDNA 2003 codec. An IP literal is kept in its canonical
    form (`2001:DB8::0001` is `2001:db8::1`), and a numeric spelling that is not canonical
    dotted-decimal IPv4 (`010.000.000.001`, `127.1`, `2852039166`, `0x7f.0.0.1`) is refused for
    targets, scopes and bounds. The target list's SQL compares the same way. Approval text shows
    the canonical ASCII host with its Unicode form beside it.
  - Bounds stored before this (no `host_canonicalization` in `bounds_json`) were parsed with
    IDNA 2003. On load each host bound is re-derived from the strings the person approved: one
    whose IDNA 2003 and 2008 encodings are identical stands; one that differs, or whose source
    cannot be confirmed, is withheld (it covers nothing) and listed under `reapproval_required`.
    The row's other bounds stand, and the withheld bounds are offered back once as a pending
    `preauthorization_reapproval` request the person grants with `shakerscan approve <id>`. The
    offer is made when the Hunt's requests or pre-authorizations are read, so the withheld bounds
    and the request appear together, and once it is granted the old row lists nothing under
    `reapproval_required` and names the new row in `reapproved_by`. A stable bound is matched as
    its whole stored pattern (`[*.]host[:port]`), so it never lends its host to a withheld one.
  - A pending agent proposal recorded under IDNA 2003 that names a host IDNA 2008 spells
    differently is withdrawn when read, and the same `--allow` strings are raised again with their
    IDNA 2008 digest. The old request's `approve_command` and `superseded_by` name the replacement,
    so approving stays one step.
  - Hosts containing a character no URL host may hold (WHATWG forbidden code points such as `%`,
    `@`, `/`, `\`, space, or `*` outside a bound's leading `*.`) and IPv6 zone ids are refused.
  - A bound never covers a hard limit, and kind rules still apply to each credential.
- **When a request falls inside the bounds,** it is created and granted in the same transaction
  (`decision_via=preauthorization`) and audited as pre-authorized by the starting person. The
  action proceeds without a 409.
- **Who sets bounds (Enterprise).** The client and agent hold the same service token, so bounds
  in a request body prove nothing about who set them:
  - `shakerscan agent --allow …` performs one step-up when the person launches it, before any
    agent process exists. The resulting pre-authorization id is passed to the agent's Hunts.
  - `shakerscan hunt start --allow …` asks for step-up unless it names that id.
  - Bounds proposed through the MCP start tool become one pending request that the person
    approves like any other. The MCP tool may also reference or narrow an existing
    pre-authorization id, which never widens it.
- **Local OSS** has no accounts, so bounds are accepted as given, and **pre-authorization is the
  main control** there.

## Terminal approval

`shakerscan approve <request-id> …` or `shakerscan approve --all-pending [--hunt <id>]`:
1. The client fetches the pending requests and prints the **server-rendered** title, effect,
   scope choice and subject. It asks for a scope (`this Hunt` / `remember`) where the kind
   supports one.
2. **Enterprise step-up.** Steps 2 to 4 go through the gateway routes
   (`/_enterprise/approvals/begin|finish`), never the engine decision route directly.
   - `begin` takes the request ids and returns their digests plus a challenge bound to that set.
   - The person names their account and then proves it with one of:
     - **TOTP:** the code is checked by `mfa_verify` against the person's enrolment. It has
       per-counter replay protection and is rate-limited.
     - **Security key:** a FIDO2 USB or NFC key over CTAP2 from the client (python-fido2). The
       RP ID is the gateway host, the challenge covers the request-set digest, and the gateway
       verifies the person's registered credential. User verification (the key's PIN) is
       required, as at login (`passkeys.py:55-68`). Platform authenticators (Touch ID, Windows
       Hello, synced passkeys) are **not** reachable from a pip-installed CLI without a signed
       native helper, so v1 does not offer them.
   - The token alone never approves: it must be a valid connection **and** belong to a person
     with the operator or admin role who passes step-up.
   - **Who may approve whose request (owner decision 8).** Any person with the operator or admin
     role who passes step-up may decide a request raised through any operator token of the same
     instance. The approver is not bound to the token's owner: client tokens belong to service
     identities, not people, so there is no person to bind to. Every decision records the person
     who passed step-up (`decided_by`) and how (`decision_via`), never the token.
3. **Local OSS.** The approval is a plain `y/N` confirmation on the terminal. The trust boundary
   is the host, so any local process that can reach the API could decide. The note and the
   docs say this plainly.
4. The gateway forwards the decision to the engine with `decided_by` set to the person, and
   audits `hunt.permission.decided`.

**Approver session (opt-in, Enterprise).** After a successful step-up the person may choose
`--session 30m`. Where the session lives:
- **In memory only.** The session secret lives only in the memory of the foreground
  `shakerscan approve --watch` process in the person's own terminal. It is never written to
  disk, environment or config, so the agent's shell has no file or variable to read.
- **Server side.** The gateway binds the session to the person, the connection token and a
  30-minute expiry. Every use is audited as `approver_session`, and the person can revoke it.
- While it lasts, the process shows each new request and approves on a keypress.

What this does **not** guarantee on one machine under one OS user:
- A process that can ptrace the approver process (Linux with `ptrace_scope=0`, or root) can read
  its memory.
- An agent that can drive the person's terminal multiplexer (`tmux send-keys`, `screen -X`) can
  type the keypress.

So the guarantee is "no stored secret". The only strong per-approval proof is a step-up code or
key touch the agent never sees. Never type a TOTP code into the agent's chat.

**UI.** The Hunt page shows the requests read-only to every role. It offers Allow and Deny to a
signed-in operator browser session (a person who has already passed login MFA). The UI is never
required.

## Engine API

All routes live under `/hunts`. There is **no create route**: requests come only from
refusals. The planner ingress gets the reads only.

| Route | Notes |
|---|---|
| `GET /hunts/{id}/permission-requests?status=` | Rendered `title`, `explanation`, `effect`, `choices`, `remember_supported`. |
| `GET /hunts/{id}/permission-requests/{rid}?wait_seconds=0..25` | Long-poll; returns as soon as the status changes. |
| `POST /hunts/{id}/permission-requests/{rid}/decision` | Body: `decision`, `scope`, `subject_digest` (must match), `choice`, `idempotency_key`, `decided_by`, `decision_via`. The row is locked `FOR UPDATE`. Replaying the same decision returns 200; a different decision returns 409. In Enterprise the gateway is the only caller. |
| `GET /hunts/{id}/preauthorization`, `GET/POST …/permission-grants`, `POST …/permission-grants/{gid}/revoke` | Read the bounds and grants, and revoke a grant. |

A refusal on the allowable list returns **HTTP 409** with
`detail: {code:"permission_required", permission_request:{id, kind, status, title}, action_id}`.
The idempotency middleware releases the key on this 409.

## MCP and CLI behaviour

**MCP.** `permission_required` maps to `outcome: "awaiting_permission"` with the request id,
title and fixed recovery text:

> *Waiting for the user to allow: {title}. Tell the user to run `shakerscan approve {id}` in
> their own terminal. Continue other work meanwhile. Check with
> `shakerscan_hunt_permission_wait` (it returns `granted`, `denied`, `expired` or
> `still_pending`). On `granted`, call the same tool again with the same idempotency key. On
> `denied` or `expired`, do not retry this action.*

- `shakerscan_hunt_permission_wait` long-polls within the 45 s call limit, with progress
  notifications.
- No MCP tool decides a request.
- A host that declares `elicitation` may get an informational prompt with the same text. Its
  answer is never treated as approval, because an answer through the agent's channel is the
  agent's answer.

**CLI commands.**
- `shakerscan hunt permissions list|show|wait`
- `shakerscan approve` / `shakerscan deny`
- `--allow` on `hunt start` and `agent`
- `hunt call` prints the request and the approve command.

## Idempotent resume

The agent re-sends the same key and the same input. If the request is granted, the parked row is
re-admitted under the same action id through the full admission pipeline: scope, budget
reservation and credential resolution. A grant changes what admission allows but never skips
it. A grant that was revoked or went stale in the meantime produces a fresh request. That
request goes to a person even when the start bounds cover it: once a person revokes a grant,
the bounds stop granting what it covered (see Revocation).

Budget-shortage rows become `awaiting_permission` instead of `failed`, which fixes the
cached-refusal replay. Work that already ran is never re-dispatched.

## Concurrency

- **Several pending requests** are independent. They are deduped by subject; one grant
  unblocks every parked action with that subject, and each action retries under its own key.
- **Cap.** At most 20 requests may be pending per Hunt. Past the cap, the refusal stays plain.
- **After a denial (D46).** The same subject is not asked again in that Hunt for 15 minutes
  (`DENIAL_COOLDOWN`), under any idempotency key: the refusal is `permission_denied`, names the
  denied request and when the subject may be asked again, and raises nothing for the person. The
  cooldown keys on the question, not on every field of the subject: a destination is its scheme,
  host and port, whatever addresses the host resolves to on the next lookup (a CDN or round-robin
  host does not make a fresh question), and a credential is its profile, whichever slot the agent
  names. Another host, port, scheme, dimension, capability or credential is a new question. The
  cooldown also holds back a grant from pre-authorization bounds for that subject, because the
  person's denial is the later decision.
- **Decision races** are prevented by a row lock and a `pending` precondition.
- **Budget grants.** A budget grant re-reads the revision and retries once on 409, because the
  person approved a total, not a delta.
- **Pre-authorization races.** Granting in the refusal transaction is atomic with request
  creation.
- **Hunt ends while a request is pending.** The request is withdrawn in the same transaction. A
  later approval returns "this Hunt has ended; nothing was granted", and "remember" is not
  applied either.
- **Parked action whose request the agent never retried.** It stays parked until the Hunt ends,
  then settles `blocked` with the outcome of its own request (D42): `permission_denied`,
  `permission_expired`, `permission_unused` (granted, never called again) or
  `permission_withdrawn` (still pending when the Hunt ended).

## Security analysis

- **No request from untrusted text.** Requests are created only in server refusal branches,
  from closed enums and server-resolved subjects, and all wording comes from server templates.
  There is no model justification in v1. A target response can at most cause a refusal for a
  host, and that host is shown to the person in plain ASCII with its address and scope verdict.
  SSH argv is shown verbatim and bound by digest.
- **Hard limits come first.** They never produce a request, and no bound covers them.
- **The agent cannot approve.**
  - **Enterprise:** each approval needs TOTP, a security-key touch, or a step-up approver
    session held only in the person's own process. The token alone never approves, and bounds
    in a token-authenticated body need step-up.
  - **OSS local:** the trust boundary is the host. This is stated, not hidden.
- **Grants are narrow.** Every grant covers one subject, there is no "allow all", and a
  credential never authorizes a target.
- **Approval fatigue** is limited by dedupe, the cap, the cooldown after a denial,
  `--all-pending` with a full list, and pre-authorization.
- **Audit.** Every request, decision, automatic grant, credential use and revocation is
  recorded, naming the person and the source.

## M4 fix (reframed)

Today `_execute_hunt_candidate_verification` (`api/hunt/interaction_router.py:4250-4260`) calls
`_verify_suspected_finding_workflow` (`api/api.py:14139`). That goes to
`_agent_verification_workflow_for` (`:13734`; BOLA `user1,user2` at `:13742`; data exposure
`user1` at `:13760`) and then `_arsenal_dispatch_workflow` (`api/arsenal_routes/router.py:8095`).
Both use `_resolve_workflow_principal_contexts` (`api/api.py:16517`), which decrypts the
target's active `target_principals` (`:16559`) without recording which credential was used. It
joins only home profiles (`cp.target_id = p.target_id`), so credentials shared from other
targets are ignored.

Fix (PR E1). Hunt verification keeps using the attached credentials, so no capability is lost.
1. Pass the Hunt context (selected refs, live grants, pre-authorization) down the verification
   chain.
2. Resolve principals from the **attached list**: own profiles plus active
   `credential_profile_bindings` grants. Check active status, version and expiry before
   decrypting. Selected refs narrow the choice (`user1←primary`, `user2←secondary`).
3. Write a `hunt_credential_uses` row for every slot resolved: which credential, from where, and
   for which action.
4. Never decrypt an unattached credential unless a live grant or pre-authorization covers it.
   Otherwise refuse with `credential.use`.
5. Apply the same rule in `_server_materialize_create_ma` (`:18607`) when it is called from a
   Hunt. Callers outside a Hunt are unchanged (owner decision: M4 covers Hunts only).

## Enterprise gateway changes

- **`HUNT_READ`** gains the permission-request, grant and pre-authorization reads for every role
  when Hunt is enabled.
- **The engine decision route is not proxied.** It goes in no allowlist; only the gateway calls
  it.
- **New gateway routes.**
  - `POST /_enterprise/approvals/begin` and `/finish`, for the terminal: a token plus the
    person's TOTP or security-key assertion, with the person's role at least operator. Both are
    rate-limited and lock out like login.
  - `POST /_enterprise/approvals/session` and `DELETE`, for the opt-in 30-minute approver
    session.
  - `POST /_enterprise/preauthorizations`, for start bounds with step-up.
  - A UI Allow from an operator browser session reuses `finish` without a code, since the
    session already passed MFA.
  - Every route sets `decided_by` to the person and writes audit entries
    `hunt.permission.decided` and `hunt.preauthorized`.
- **Licence and toggles.** `allow` needs `can_mutate`; `deny` and `revoke` are always possible.
  Kinds tied to a disabled feature are refused.
- **Hunt start bounds.** A `POST /hunts` body with `allow` bounds must carry a gateway-issued
  pre-authorization id; otherwise the gateway refuses with "pre-authorization needs step-up:
  run shakerscan approve".
- **Review.** Add a `REVIEWED_ENGINE_LINES` entry for the new minor line, regenerate
  `tools/ui_route_inventory.py`, and add dispositions in `tests/enterprise/test_ui_inventory.py`.
- **Capability manifest** gains `hunt_permission_decisions`.

## Migration

- Additive tables, the action-status constraint and the client commands go through the engine
  migration registry and `db/init.sql`, kept in step. There is no backfill.
- Older MCP clients still see a readable `HTTP 409: …` refusal.
- Regenerate the OpenAPI manifest, `publicApi.generated.ts`, surface dispositions,
  `/hunts/contract`, `docs/functionality-reference.md` and the install manifest.

## Test plan

- **Unit tests** (fixtures labelled):
  - every catalogue mapping;
  - hard limits never produce a request and are never covered by a bound;
  - the bound grammar: refused wildcards, IDNA handling;
  - rendered text comes only from templates;
  - a target body that contains request-like text produces nothing.
- **PostgreSQL tests:**
  - the dedupe index;
  - racing decisions;
  - a decision racing Hunt finish or cancel;
  - a budget grant racing an amendment;
  - an automatic grant inside bounds;
  - same-key retry before, during and after a grant, and after a denial;
  - same key with different input gives 409;
  - the budget-shortage resume;
  - the middleware releasing the key on 409.
- **M4 tests:**
  - an unattached principal is never decrypted (spy on `decrypt_secret`);
  - a shared credential resolves through its binding;
  - every use writes a `hunt_credential_uses` row with its source;
  - a rotated profile is refused.
- **Client and MCP tests:**
  - the `awaiting_permission` outcome and the wait tool;
  - no decision tool exists;
  - `approve` renders only server text;
  - the TOTP and security-key paths, using a CTAP2 test authenticator;
  - the approver session leaves nothing on disk or in the environment;
  - MCP start bounds become a pending request.
- **Gateway tests:**
  - a token without step-up is refused;
  - a wrong or replayed TOTP is refused;
  - a viewer is refused;
  - an operator with step-up is allowed;
  - `decided_by` is set to the person;
  - start bounds without a pre-authorization id are refused;
  - the session expires and can be revoked;
  - the inventory dispositions are present.
- **Live acceptance** on the soak host, terminal only, with OpenCode over the client:
  1. The Hunt exhausts `max_http_requests`; `shakerscan approve` with TOTP; the same action
     resumes while other work continued.
  2. A `--allow budget.raise:2x` start auto-grants.
  3. BOLA uses a credential shared from another target, and the use is recorded with its source.
  4. A new port is authorized through pre-authorization.
  5. A denial settles the action `blocked`.
  6. The Hunt is cancelled while a request is pending.
  7. The UI Allow path is checked once, as optional.

## E2 implementation notes

Where the engine (PR E2) differs from, or makes concrete, the design above:

- **Reason codes.** `api/hunt/permission_reasons.py` holds the closed list (`REASON_CODES`,
  published as `permission_reason_codes` in `GET /hunts/contract`). A refusal is a `HuntRefusal`
  whose `detail` is JSON (`error`, `reason_code`, `message`; budget refusals keep the legacy
  `error` string `budget_exhausted:<dim>`). Every recorded refusal leaves a `blocked` action with
  `refusal_stage: admission` and its code (D25/D35); a refusal that a person can allow parks the
  action as `awaiting_permission` instead.
- **Retry of a parked action.** Granted: full admission under the same action id. Pending on an
  active Hunt: admission also runs again, so an action whose refusal no longer applies (a person
  amended the budget directly) goes through; if it still applies it is parked again under the same
  request (409 `permission_required`). Pending on a stopped (`budget_exhausted`) Hunt: 409
  `permission_required` with no change. Denied, expired or withdrawn: `blocked` with
  `permission_<status>`, replayed as such.
- **Kinds raised in E2.** `budget.raise`; `capability.enable` (the grant binds the target's standing
  authorization when the Hunt has none, and is refused with `target_authorization_required`
  otherwise; the bound grammar also takes `capability:active-testing`); `target.authorize` for
  another service port on the Hunt's host and for another host, anonymously only (the host is
  resolved and scope-checked before the request is raised, and every address must be public:
  loopback, private, link-local, metadata and reserved addresses are hard limits even where the
  deployment admits private targets; remember applies to the Hunt's own host only);
  `credential.use` for another target's active credential (a Hunt-only grant is honoured by
  admission, the verifier and `load_for_worker` through the Hunt's live grant, with no binding;
  remember creates the normal credential grant); and `preauthorization` for bounds proposed through
  the MCP start tool. `ssh.exec` and `ssh.host_trust` have their codes but no requests yet: the
  SSH worker re-reads the profile's command grant and meets the host key only at connection time.
  DNS-out-of-scope and discovered-host refusals are not yet wired to `target.authorize`.
- **Request text for another host (D41).** A `target.authorize` request for another host says
  "another host", names the addresses it resolved to and will be pinned to, and offers no
  remember: remember records the standing authorization of the Hunt's own target, so it applies to
  another service on the Hunt's host only.
- **Request text for a credential (D47).** A `credential.use` request names the credential
  (profile name, kind and version) and its home target (name and host), read from those rows when
  the request is raised and kept beside the subject, not in its digest; the ids follow for the
  record. Names are shown as bounded one-line values; no secret is read.
- **A granted destination at dispatch (D39).** A person's live grant and a pre-authorized one are
  the same grant row and the same `policy.granted_destinations` entry, so both run the same way.
  The Hunt's scope receipt names only the Hunt's host, so the worker checks another host on its
  grant instead: the grant is still live (in the policy, its row not revoked), every pinned address
  is public and the host's own scope is not blocked; the Hunt's approval and scope receipts are then
  revalidated for the Hunt's host as for any action, so a revoked authorization still refuses it.
  The same-key retry resolves the host again before admission takes the Hunt lock, and every address
  must still be public (`scope_destination_blocked` otherwise); the connection stays pinned to the
  addresses checked when the request was raised. A refusal at dispatch (authority revoked between
  admission and dispatch) releases the action's hold at once and settles it `blocked` with
  `dispatch_authority_rejected`; it no longer waits about two minutes for stale recovery, during
  which finishing the Hunt was refused. Scanners run only against the Hunt's own host: a scanner
  aimed at another host, granted or not, is refused at admission with `scope_scanner_other_host`,
  before anything is reserved and without a request (reach a granted destination with
  `http.request`).
- **Deadline.** A request expires after 24 h or at `created_at + max_duration_seconds` of the Hunt,
  whichever is first. Past that deadline no request is raised and the refusal stays plain.
- **Start bounds.** `POST /hunts` takes `allow` (a person's bounds) and `proposed_allow` (the MCP
  start tool sends the agent's `allow` argument here). `allow_asserted_by: {person, proof}` names
  who set `allow` (`stepup`, `launch_stepup` or `local`); the gateway sets it after step-up and must
  strip a client-supplied value (G1). Without it the bounds are recorded as `local-operator` /
  `local`. A start that selects another target's credential is admitted only when `allow` covers its
  home target and the kind rules pass; the Hunt-only grant is recorded at start.
- **Routes.** Besides the routes above: `GET /hunts/{id}/permission-events` (the audit). The
  planner ingress delegates the reads only. On OSS the decision and revoke routes are protected by
  the engine's existing API authentication alone: the trust boundary is the host.
- **Revocation.** Revoking takes back exactly what that grant gave. The Hunt's authority
  (its five policy flags, the allowed capabilities and the authorized destinations) is rebuilt
  under the Hunt row lock from its baseline (`hunt_permission_baselines`: the authority before
  its first grant, which cannot be changed) and the grants that are still live. Revoking one grant
  never takes away what the start or another live grant gives, and never restores what a revoked
  grant gave. A grant that is admitted but not yet dispatched is refused at dispatch if its
  authority was revoked in between. A `credential.use` grant stops working at once. A budget
  raise (an amendment) and the pre-authorization bounds cannot be revoked. Revoking never undoes
  a remembered record.
  - **Start bounds.** After a person revokes a grant, the bounds no longer grant what it covered
    for the rest of the Hunt. A later refusal for it is parked as `awaiting_permission` with a
    request that a person allows with `shakerscan approve`. The bounds still grant everything
    else they cover. What is withheld:
    - **Capabilities, by field.** Capability flags overlap: `state-changing` and
      `active-replay` both turn on state-changing HTTP. So the bounds stop granting every flag
      that would turn on a policy field the revoked grant turned on, other than the shared
      `active_testing` base. Revoking `state-changing` withholds `active-replay` too, so the
      revoked write authority cannot come back through another flag. `tcp-discovery` and `oob`
      each withhold only themselves. A grant that turned on only `active_testing` withholds
      only `active-testing`.
    - **Destinations** by scheme, host and port, and **credentials** by profile.
    - **Where it shows.** The request shows `auto_grant_withheld`: the revoked grant, when it was
      revoked and by whom, and the shared fields. `shakerscan approve` and
      `hunt permissions show` print it. The grant list and the `revoked` event show what is
      withheld.
    - **Remaining case.** An `oob` or `tcp-discovery` grant from the bounds still turns
      `active_testing` on after an `active-testing` grant was revoked, because every capability
      flag needs it. It gives back no write, discovery or out-of-band authority that was revoked.
  - **Target authorization is separate.** A capability grant may bind the target's standing
    approval receipt (`approval_receipt_id`, `scope_receipt_id`, `authorization_confirmed`).
    Revoking grants does not undo it: it is a separate decision, withdrawn by revoking the
    target's standing authorization.
  - **Limit.** A Hunt holds at most 64 authorized destinations. A grant past that is refused
    with `destination_limit_reached`, and no destination is dropped.
  - **Upgrade from 2.8.0.** 2.8.0 restored a snapshot of the whole policy on revocation (R1,
    external release audit, 2026-10-09). On startup, every unfinished Hunt with grants and no
    baseline is rebuilt once from its grant rows, each in its own transaction. A Hunt that cannot
    be rebuilt is cancelled exactly as a person's cancel would be, with stop reason
    `permission_authority_unrepaired`. Its withheld private HTTP results are dropped, its scans
    and queued jobs are cancelled, and it is logged by id. Startup continues.
- **MCP.** The `awaiting_permission` outcome and `shakerscan_hunt_permission_wait` ship in E2;
  a capability outside the manifest is sent to the engine, which answers with its code (D31).
- **UI.** The Hunt page lists pending requests read-only with the `shakerscan approve` command;
  Allow and Deny on the page are left to E3/G1.

## E3: the terminal approval protocol and the G1 contract

E3 is client code (`scripts/hunt_approve.py`, vendored into the `shakerscan` client as
`_hunt_approve.py`, and reached through `scripts/v2_cli.py`), so `shakerscan approve` on a pip
client and `./scanner.sh approve` on an engine install run the same protocol.

**Commands.**
- `shakerscan approve <request-id> [--hunt H] [--remember] [--total N]`,
  `shakerscan approve --all-pending [--hunt H]`, `shakerscan deny <request-id> | --all-pending`.
  The request is found among the open Hunts (`active`, `awaiting_planner`, `budget_exhausted`)
  unless `--hunt` names its Hunt. The client prints only the server's `title`, `explanation`,
  `effect`, kind, reason code and expiry. One proof covers every request shown.
- `shakerscan approve --watch [--minutes 30]`: the opt-in approver session (below).
- `shakerscan hunt permissions list [HUNT] [--status S] | show <id> | wait <id> [--seconds N]`:
  JSON with the server-rendered text; `wait` answers `granted`, `denied`, `expired`, `withdrawn`
  or `still_pending`. `shakerscan hunt call` refused with `permission_required` names the request
  and the `shakerscan approve` command.
- `--allow BOUND` (repeatable) on `shakerscan hunt start` and `shakerscan agent`;
  `--propose-allow BOUND` on `hunt start` sends `proposed_allow` (one pending request), as the MCP
  start tool does with its `allow` argument.
- Every command that decides refuses to run without an interactive terminal (stdin a TTY), so a
  command an agent runs in its own tool shell cannot decide or pre-authorize anything.

**Which proof.** A connection with a service token is Enterprise: everything goes through the
gateway's step-up routes and the engine's decision route is never called. A connection without a
token is a local open-source engine: a `y/N` on this terminal, then `POST
/hunts/{id}/permission-requests/{rid}/decision` with `decided_by: local-operator`,
`decision_via: local_confirm` and a fresh `local-approve-<hex>` idempotency key. On OSS any local
process that can reach the API could do the same; the command prints that before asking.

**G1 gateway contract.** All routes take the service token as `Authorization: Bearer`; the token
alone never approves. Every response from these routes, success or refusal, carries a
`schema_version` starting `shakerscan-approval-` (a refusal under FastAPI's `detail`). The client
uses that marker to tell a gateway without these routes (any other answer, such as today's named
403 for an unknown route) apart from a refusal, and then prints an exact error ("this ShakerScan
Enterprise gateway has no terminal approval yet: POST /_enterprise/approvals/begin answered HTTP
403 (…). … needs the gateway's step-up routes (G1). Nothing was approved, denied or
pre-authorized …") and exits 2. There is no fallback.

1. `POST /_enterprise/approvals/begin`
   ```json
   {"schema_version": "shakerscan-approval-begin/v1",
    "purpose": "permission_decision | preauthorization | approver_session",
    "account": "<the sign-in name the person typed>",
    "origin": "https://<gateway public origin>",
    "decisions": [{"hunt_id": "…", "request_id": "…", "subject_digest": "<64 hex>",
                   "decision": "allow | deny", "scope": "hunt | target", "choice": {"total": 1000}}],
    "preauthorization": {"allow": ["budget.raise:2x", "…"], "use": "agent_launch | hunt_start"},
    "session": {"ttl_seconds": 1800}}
   ```
   Exactly one of `decisions`, `preauthorization`, `session`, matching `purpose`. The gateway
   checks the token, that `account` is a person with the operator or admin role (any such person,
   not only the token's owner: owner decision 8), that `origin` is its public URL, and for decisions
   that each request is pending with that `subject_digest` (read from the engine). It answers:
   ```json
   {"schema_version": "shakerscan-approval-challenge/v1", "approval_id": "<opaque>",
    "set_digest": "<64 hex>", "methods": ["totp", "security_key"], "expires_at": "<ISO 8601>",
    "nonce": "<base64url, with security_key>",
    "webauthn": {"challenge": "<base64url>", "rpId": "<gateway host>",
                 "allowCredentials": [{"type": "public-key", "id": "<base64url>"}],
                 "userVerification": "required", "timeout": 120000}}
   ```
   `set_digest` is SHA-256 (hex) of the canonical JSON (`sort_keys`, separators `,` and `:`,
   ASCII) of `{"schema_version": "shakerscan-approval-set/v1", "purpose", "account", "origin"}`
   plus the purpose's part: `decisions` sorted by (`hunt_id`, `request_id`) with exactly the six
   keys above; `preauthorization` with `allow` sorted and de-duplicated and `use`; or `session`
   with `ttl_seconds`. The client computes the same digest and refuses a challenge that differs.
   `methods` lists only what the person has enrolled. The WebAuthn `challenge` is
   `base64url(SHA-256(base64url_decode(nonce) || bytes.fromhex(set_digest)))`; the client checks
   it before asking the key, so a key touch signs exactly this set.
2. `POST /_enterprise/approvals/finish`
   ```json
   {"schema_version": "shakerscan-approval-finish/v1", "approval_id": "…", "set_digest": "…",
    "proof": {"method": "totp", "code": "123456"}}
   ```
   or `{"method": "security_key", "credential": {"id", "rawId", "type": "public-key",
   "response": {"clientDataJSON", "authenticatorData", "signature", "userHandle"}}}` (base64url;
   the shape `py_webauthn` verifies at sign-in, origin = the gateway's public URL, user
   verification required), or `{"method": "approver_session", "session_id", "session_secret"}`.
   TOTP goes through `mfa_verify` (per-counter replay protection); both routes are rate-limited
   and lock out like login. An approval id is single-use and expires (five minutes suggested).
   It answers `{"schema_version": "shakerscan-approval-result/v1", "approval_id", "decided_by":
   "<person>", "decision_via": "terminal_stepup | approver_session"}` plus, by purpose:
   - `results`: one `{"hunt_id", "request_id", "http_status", "request": <engine request> |
     "error": <engine detail>}` per decision. The gateway makes each decision itself with
     `POST /hunts/{hunt_id}/permission-requests/{request_id}/decision` and the body
     `{decision, scope, subject_digest, choice, "idempotency_key": "approval:<approval_id>:<request_id>",
     "decided_by": "<person>", "decision_via": "terminal_stepup" | "approver_session"}`; any
     `decided_by` a client sent is ignored. It audits `hunt.permission.decided`. `allow` needs the
     licence's `can_mutate`; `deny` is always possible.
   - `preauthorization`: `{"id", "allow", "use", "proof": "stepup" | "launch_stepup",
     "expires_at"}`, bound to the person and the token (suggested lifetime: `agent_launch` until
     the token's working day ends, at most 12 h; `hunt_start` 10 minutes, one use). Audits
     `hunt.preauthorized`.
   - `session`: `{"session_id", "session_secret", "expires_at"}` for at most 30 minutes, bound to
     the person and the token, revocable. Audits each use as `approver_session`.
3. `POST /_enterprise/approvals/session/revoke` `{"schema_version":
   "shakerscan-approval-session-revoke/v1", "session_id", "session_secret"}` answers
   `{"schema_version": "shakerscan-approval-session/v1", "session_id", "revoked": true}`.
4. **Hunt start with bounds.** `POST /hunts` with a non-empty `allow` must carry the header
   `X-ShakerScan-Preauthorization: <id>`. The gateway checks that the id is live, belongs to this
   token, and that every string in `allow` is in its `allow`; it then sets `allow_asserted_by:
   {"person": "<person>", "proof": "launch_stepup" | "stepup"}`, removes the header, and forwards.
   Without the header it refuses 403 with `{"schema_version": "shakerscan-approval-error/v1",
   "error": "preauthorization_stepup_required", "message": "pre-authorization needs step-up: run
   shakerscan approve"}`. It always removes a client-sent `allow_asserted_by`; `proposed_allow`
   passes through unchanged (it becomes a pending request).
5. **Never proxied:** the engine's decision and revoke routes stay out of every token allowlist.
   The read routes (`permission-requests`, `permission-grants`, `preauthorization`,
   `permission-events`) join `HUNT_READ`.

Refusals use `{"detail": {"schema_version": "shakerscan-approval-error/v1", "error": "<code>",
"message": "<text>"}}`; the client prints the code and message. Suggested codes:
`stepup_failed`, `stepup_locked` (429), `role_insufficient`, `account_unknown`,
`origin_mismatch`, `approval_unknown`, `approval_expired`, `approval_set_changed` (409),
`session_invalid`, `preauthorization_invalid`, `feature_disabled`, `licence_read_only`.

**`--allow` at launch.** `shakerscan agent --allow BOUND…` validates the `<kind>:<value>` shape
locally (the engine parses the grammar) and checks that the agent it will start is on `PATH`
before anything else (D44: a launch that cannot start asks for no step-up and mints no
pre-authorization). On Enterprise it then runs one `preauthorization` step-up
(`use: agent_launch`) before any agent process exists; a gateway without G1 gets the exact error
and no agent starts. The agent's environment, and its MCP registrations (`.mcp.json` `env`,
`opencode.json` `environment`, `codex mcp add --env`), then carry `SHAKERSCAN_HUNT_ALLOW` (the
bounds, JSON) and `SHAKERSCAN_PREAUTHORIZATION_ID`; the MCP start tool and `hunt start` send them
as `allow` and the header on every Hunt. The id is not a secret on its own (the gateway binds it to
the token, the person and the bounds and lets nothing widen it); it is rewritten, or removed, on
every `shakerscan agent` launch. On an open-source engine the bounds are the local operator's and
are sent as given. `hunt start --allow` steps up itself (`use: hunt_start`) unless
`--preauthorization ID` names one or the launch environment carries one; without a terminal it
refuses and suggests `--propose-allow`.

**The approver session, honestly.** `approve --watch` asks for one step-up (`approver_session`),
then shows each new request and decides it on a keypress (`a`, `r` to remember where supported,
`d`, `s`, `q`). The session secret lives only in that foreground process's memory: never on disk,
in the environment or in config, never printed, wiped when the session ends, which also revokes it
at the gateway. It does not protect against a process that can read the approver's memory (ptrace
with `ptrace_scope=0`, or root), nor against an agent that can type into the person's terminal
(`tmux send-keys`, `screen -X`); Python may also keep copies of the string the client cannot wipe.
The guarantee is "no stored secret" and a bounded, revocable, audited window. The strong
per-approval proof is a step-up code or key touch the agent never sees. On OSS `--watch` is the
same loop, and each keypress is the confirmation.

**Security keys.** CTAP2 over USB or NFC through python-fido2 when it is installed beside the
client (`pipx inject shakerscan fido2`); without it the client says so and offers `--method totp`.
Platform authenticators are not reachable from a pip-installed command.

## PR split

**Engine**
- **E1:** credential use recording and the attached-list rule. This is the M4 fix plus the
  standing-authorization wording.
- **E2:** permission requests and pre-authorization:
  - tables, events and the `awaiting_permission` status;
  - the `permission_required` refusal and the middleware 409 fix;
  - the read and decision routes;
  - every catalogue kind, start bounds, and remember-for-target;
  - read-only Hunt page cards with optional Allow.
- **E3:** the terminal approve flow in the client and MCP:
  - `approve`/`deny`, `--allow`, and `hunt permissions`;
  - TOTP and CTAP2 step-up against the gateway, and the in-memory approver session;
  - the MCP outcome and wait tool;
  - docs.

**Gateway**
- **G1:** the step-up approval routes (TOTP or security key bound to the person), the approver
  session, start pre-authorization, role rules (operator or admin), audit, licence and toggle
  rules, allowlists, inventory and tests, to the contract in "E3: the terminal approval protocol
  and the G1 contract". The routes differ from the earlier sketch in "Enterprise gateway changes":
  pre-authorization and the approver session are `purpose`s of `begin`/`finish` rather than
  routes of their own, the session is revoked with `POST …/session/revoke`, and start bounds carry
  the pre-authorization id in the `X-ShakerScan-Preauthorization` header.

## Owner decisions recorded

1. **Terminal-first.** No Hunt step requires the browser. Approval is by pre-authorization or by
   terminal step-up; the UI is optional.
2. **One credential list.** A Hunt may use all credentials attached to its target (own plus
   shared). An unattached credential becomes a request; "remember" creates the normal grant.
3. **M4 reframed.** Every credential use is recorded with its source. Never use an unattached
   credential without a live grant or pre-authorization. The fix applies to Hunts only.
4. **Expiry.** A pending request expires after 24 h or at the Hunt's duration deadline,
   whichever is first. The Hunt clock does not pause.
5. **Capability flags.** No "remember" for capability flags in v1.
6. **No model justification** on requests in v1.
7. **A pending request never freezes the Hunt.**
8. **Any operator may approve (2026-10-08).** Any person with the operator or admin role who passes
   step-up may approve or deny a request raised through any operator token; the gateway does not
   require the approver to own the token (tokens belong to service identities). Kept after the
   OpenCode acceptance raised it (observation O2); the decision is audited with the person's name.

## Remaining questions

- **OIDC-only people.** They have no gateway TOTP or security key. Should they enrol a gateway
  security key for step-up, or should step-up use the provider's device-code flow (which needs a
  second device's browser, not this one)?
- **Platform authenticators.** Should a signed native helper be built later so that Touch ID or
  Windows Hello can stand in for a USB security key?
