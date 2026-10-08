# Hunt permission requests, granted live

**Status:** design note, revised after owner decisions (2026-10-07). PR E1 implements the
attached credential list and `hunt_credential_uses`; the rest is not implemented yet. The owner
approved the behaviour and the decisions recorded below; any code follows this note.

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
  slot, profile id and version, and `source`: `selected`, `target_own`,
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
- loopback, private, link-local, metadata and reserved destinations;
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
  - Host patterns are IDNA ASCII and must contain a registrable domain, so `*` and `*.com` are
    refused.
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
it. A grant that was revoked or went stale in the meantime produces a fresh request.

Budget-shortage rows become `awaiting_permission` instead of `failed`, which fixes the
cached-refusal replay. Work that already ran is never re-dispatched.

## Concurrency

- **Several pending requests** are independent. They are deduped by subject; one grant
  unblocks every parked action with that subject, and each action retries under its own key.
- **Cap.** At most 20 requests may be pending per Hunt. Past the cap, the refusal stays plain.
- **Decision races** are prevented by a row lock and a `pending` precondition.
- **Budget grants.** A budget grant re-reads the revision and retries once on 409, because the
  person approved a total, not a delta.
- **Pre-authorization races.** Granting in the refusal transaction is atomic with request
  creation.
- **Hunt ends while a request is pending.** The request is withdrawn in the same transaction. A
  later approval returns "this Hunt has ended; nothing was granted", and "remember" is not
  applied either.
- **Parked action whose request the agent never retried.** It stays parked until the Hunt ends,
  then settles `blocked`.

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
- **Approval fatigue** is limited by dedupe, the cap, `--all-pending` with a full list, and
  pre-authorization.
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
  rules, allowlists, inventory and tests.

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

## Remaining questions

- **OIDC-only people.** They have no gateway TOTP or security key. Should they enrol a gateway
  security key for step-up, or should step-up use the provider's device-code flow (which needs a
  second device's browser, not this one)?
- **Platform authenticators.** Should a signed native helper be built later so that Touch ID or
  Windows Hello can stand in for a USB security key?
