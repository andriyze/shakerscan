# Hunt permission requests, granted live

**Status:** design note for owner review, 2026-10-07. Nothing here is implemented. The
behaviour is approved in principle; this note fixes the details before any code is written.

## Problem and decision

A Hunt that hits a refusal a person could have allowed (a new port, a second identity, a
budget ceiling, a state-changing request) stops that line of work. The agent usually gives up
or misdiagnoses the refusal, even though PR #337 now passes it the refusal text. The user has no
way to say "yes, do that" from where the Hunt is running.

**Decision.** When a Hunt action is refused for a reason on the allowable list (catalogue below),
the server records a **permission request** on that Hunt. The request names exactly what is
needed, in text the server renders. The refused action is parked under its idempotency key. A
person with the operator role or higher allows or denies the request in the Hunt page, or from
the CLI where the installation permits it. When the request is allowed, the server records a
**grant**, and the agent retries the same action with the same idempotency key. The Hunt
continues from where it stopped. Agents and models can trigger requests (only by being refused)
but can never decide them. Hard limits never become requests.

Everything is built on existing mechanisms rather than parallel copies: budget amendments,
standing target authorization, credential grants, Hunt authority, approval receipts and
`hunt_actions` idempotency.

## What exists today (code this builds on)

| Mechanism | Where | Relevance |
|---|---|---|
| Budget amendment `hunt-budget-amendment/v1` | `api/hunt/budget_amendments.py:50-202`, routes `api/hunt/run_router.py:539-549` | Takes absolute `limits`, `expected_revision`, `idempotency_key` (SHA-256 plus request digest; a different body under the same key gives 409) and `operator_confirmed`. `resume=true` moves a `budget_exhausted` Hunt back to `awaiting_planner` (`:111-118`). Refuses to raise a dimension whose authority is off (`:91-92`). **A budget grant is exactly one amendment.** |
| Budget dimensions | `HuntBudget`, `api/hunt/start_contract.py:80-131` | 13 dimensions, from `max_duration_seconds` to `max_oob_interactions`. Dimensions whose authority is off are set to 0 at start (`:785-806`). |
| `policy_adjustments` | `start_contract.py:431-456, 561, 785-806`; written once at `api/api.py:13337` | Informational list of what the server resolved at start. It is not enforced. Grants do **not** append to it; they get their own record (below). |
| Admission refusal codes (#337, commit `ad61b4ca`) | `record_budget_shortage`, `api/hunt/verification_budget.py:31-47`; shown as `result.refusal{stage:"admission"}` in `run_service.py:293-319` | The only machine codes are `budget_exhausted:<dim>` and `budget_insufficient_for_action:<dim>`. Every other refusal is a free-text `HTTPException` in `api/hunt/interaction_router.py` (`:1686-2176`). |
| MCP refusal reporting (#337) | `scripts/shakerscan_mcp.py:92-157, 950-1013, 1094-1105` | JSON-RPC error with `data.outcome` (`refused`/`retry_later`/`unknown`/`running`), `detail`, `mcp_idempotency_key`, `recovery`. No machine reason code, no wait tool, no elicitation; `initialize` advertises only `tools` (`:1690`). |
| Action idempotency | `interaction_router.py:1614-1684` | The action id is `uuid5(hunt, "hunt-capability:"+key)`. A stored row replays **whatever its status**. Budget shortages insert a `failed` row before raising 409 (`:2250-2274`), so **a retry after a raise replays the refusal today**. Policy 403s roll back and store nothing. |
| HTTP `Idempotency-Key` layer | `api/public_api_contract.py:359-387` | Releases the key on 400/401/403/404/405/413/415/422/429. **409 is in neither list**, so the key stays `processing` (latent bug; fixed in PR E2). |
| Standing target authorization | `api/target_authorization.py:148, 213, 319`; routes `api/targets/router.py:790-829` | `approval_receipts` row (`target.authorization`) plus a scope receipt. `evaluate_target_scope` refuses private, loopback and metadata ranges (`api/action_scope.py:25-147`). Hunt start copies it in through `apply_standing_authorization` (`run_router.py:193`). |
| Runtime destination scope | `evaluate_runtime_destination_scope`, `api/action_scope.py:561`; frozen `authorized_target_addresses` (`api/api.py:13183`) | Discovered hosts are recorded with `testing_authorized:false` (`api/hunt/asset_actions.py:80-86`). |
| Credential grants | `api/credential_api.py:772-826`, `CredentialGrantCreate` `:142`; kind rules `grant_target_kind_error` `:399`, `target_kinds_share_asset` (`api/runtime/models.py:17`), `_validate_kind_placement` (`credential_store.py:254`), active-capability receipt check (`:64, :806`) | Table `credential_profile_bindings` (`binding_kind='target'`, `granted_by`, soft `revoked_at`). |
| Hunt authority | `api/targets/hunt_authority_router.py:18-56`, `hunt_authority.py:18-84`; UI `ui/src/components/targets/TargetHuntPermissions.tsx` | Revisioned document in `targets.metadata_json.hunt_authority`. Today `credential_profile_ids` lists profiles a Hunt may **share** to the target (one-time delegation for `credentials.grant`), not profiles a Hunt may **use**. It also holds SSH host keys and first-contact trust. |
| Credentials selected at start | `credential_refs` (`run_router.py:64`, slots in `start_contract.py:56-65`), validated in `api/api.py:13104`, frozen in `context_pack` (`:13180, 13235`) | Enforced per action by `select_hunt_*_principal_reference` (`interaction_router.py:1790-1806`). |
| SSH command authority | `api/capabilities/ssh_commands.py:49-56`; `docs/hunt-ssh.md` | `ssh.exec` must be in the selected SSH profile's `allowed_capabilities`. The exact-command precedent is the device shell plan confirm (`interaction_router.py:379-600`; digest, expiry, receipt, statuses proposed/queued/expired). |
| Operator-only routes kept from the planner | `api/hunt/planner_gateway.py:28-47` | Budget amendments, shell-plan confirmation and `/approve` are deliberately absent from the leased planner ingress. |
| Hunt UI decisions | `ui/src/lib/huntRunModel.mjs:73-82`, `HuntRunView.tsx:172-187` | The "Needs your decision" section already lists shell plans and budget exhaustion. |
| Audit | `hunt_actions`, `hunt_budget_amendments`, `hunt_skill_events`, coverage events | There is no generic Hunt audit table. OSS has no RBAC (`docs/lan-access.md:80`). The engine records the actor only from the gateway-supplied `shakerscan.operator_identity` (`hunt_authority_router.py:56`). |

## Data model

Two new tables and one new action status. Grants that are remembered for a target are written
to the existing stores, not to a new one.

**`hunt_permission_requests`**
- Identity: `id`, `hunt_run_id`, `kind` (closed enum, see catalogue), `reason_code` (closed enum).
- `subject_json`: only server-resolved values (target id, host as IDNA ASCII, port, resolved
  address and scope verdict, profile id/version/home target, slot, capability, dimension,
  current/needed totals, SSH command argv). `subject_digest` is SHA-256 of its canonical JSON.
- The blocked action: `action_id`, `capability_name`, `input_digest`.
- `status`, `created_at`, `expires_at`, `decided_at`, `decided_by`, `decision_scope`
  (`hunt`|`target`), `decision_choice_json` (for example the profile id or new limit picked),
  `grant_id`.
- A partial unique index on `(hunt_run_id, subject_digest) WHERE status='pending'` dedupes
  requests: ten refusals for the same port make one request.

**`hunt_permission_grants`**
- `id`, `hunt_run_id`, `request_id`, `kind`, `subject_json`, `subject_digest`, `scope`,
  `created_by`, `created_at`, `revoked_at`, `revoked_by`.
- `persisted_ref`, set for target scope: the receipt id, binding id or Hunt-authority revision
  written.
- A Hunt-scope grant dies with the Hunt.
- A grant is bound to versions. A credential grant binds the profile id **and** version, so a
  rotated or deactivated profile needs a new request. A target grant binds the target locator
  generation.

**`hunt_permission_events`** (append-only audit): `requested`, `decided`, `used`, `expired`,
`withdrawn`, `revoked`. Each event names the actor and the **source** of the authority used:
`selected`, `target_authority`, `granted_from_target:<id>`, or `live_grant:<grant id>`. Each
`hunt_actions.result_summary` also gains `authority_sources[]`.

**New `hunt_actions.status` `awaiting_permission`** (check constraint in `db/init.sql:1012` and
`api/retest_contract.py:3473-3530`). The parked row freezes the key, capability and input
digest, so the agent cannot reuse the key with different input (409, as today). It holds
**no** budget reservation.

**Hunt authority gains `usable_credentials: [{profile_id, slot}]`.** This field is distinct from
the existing share-delegation `credential_profile_ids`. Each entry must reference a profile that
is bound to the target, either at home or through an active credential grant.

## State machine

```
request:  pending ──allow──▶ granted ──(grant revoked)──▶ (grant ends; request stays granted)
             │ ├──deny────▶ denied
             │ ├──expiry───▶ expired      (default min(24h, Hunt duration deadline))
             │ └──Hunt finished/cancelled/failed ─▶ withdrawn  (same transaction as the status change)
             └── subject no longer applicable (target locator changed, profile revoked) ─▶ withdrawn

parked action (hunt_actions):  awaiting_permission
   retry, request pending         → 409 permission_required (same request, no state change)
   retry, request granted         → row re-admitted under the same action id; normal pipeline
   retry, denied/expired/withdrawn → row settles `blocked` (reason permission_<status>); replays from then on
```

The Hunt's own status does not change. Other actions keep running while a request is pending.
`budget_exhausted` stays the one Hunt-level stop. The budget grant clears it through
amendment `resume=true`. `public_hunt_run` exposes `pending_permission_requests` (a count and the
newest five).

## Catalogue of request kinds

Approver for every kind: a person with the operator or admin role, in a signed-in session in
Enterprise. A kind is "remember" capable only where an existing target-level store exists.

| Kind | Raised by (today's refusal) | Grant effect (Hunt scope) | "Remember for target" |
|---|---|---|---|
| `target.authorize` | destination outside `authorized_target_addresses`; another service port needs active testing (`api/capabilities/http.py:185`); DNS outside scope (`dns.py:168-181`); discovered host not authorized (`asset_actions.py:80-86`) | Adds host[:port] to this Hunt's authorized overlay, after `evaluate_target_scope` passes at decision time | Records standing authorization through `authorize_target` (`target_authorization.py:319`); a new host first becomes a target |
| `credential.use` | no or invalid credential for slot (`interaction_router.py:1790-1806`); BOLA/data-exposure verifier missing a slot (after the M4 fix) | The user picks from a server-computed eligible list: the target's own profiles, its grants, and other targets' profiles passing all grant kind rules. Bound to slot, profile id and version | Credential grant to the target (`grant_profile`, `granted_by="permission-request:<id>"`) when the profile is foreign, plus an entry in `usable_credentials` |
| `capability.enable` | not allowed by Hunt policy (`:1755`); state-changing HTTP (`:1762`, `:1912`); active replay (`:1768`); network discovery (`network_inputs.py:55`); OOB | Sets the policy flag for this Hunt and sets the zeroed dimension to a value the user picks (default shown). Needs the Hunt's active receipt; if that is missing, a `target.authorize` request is raised first | Not in v1 (no target-level policy store; open question 3) |
| `budget.raise` | `budget_exhausted:<dim>`, `budget_insufficient_for_action:<dim>` (`verification_budget.py:31-47`, `interaction_router.py:1923, 2209, 2245`) | One budget amendment: `expected_revision` read under lock at decision, `idempotency_key="permission:"+request_id`, `resume=true`, `operator_confirmed=true` | Never |
| `ssh.exec` | selected SSH profile lacks `ssh.exec` (`ssh_commands.py:49-56`) | Allows this exact argv (digest) on this host for this Hunt; the request shows the command verbatim, labelled as proposed by the agent | Adds `ssh.exec` to the profile's `allowed_capabilities` (existing receipt rule) |
| `ssh.host_trust` | unpinned host key with first-contact trust off | Pins the presented fingerprint for this Hunt | Saves it to `ssh_host_keys` in Hunt authority |

**Never a request (hard limits):**
- loopback, private, link-local, cloud-metadata and reserved destinations (`action_scope.py:25-147`);
- the Enterprise "private network targets: refuse" setting;
- inactive target or changed locator (`:1710-1712`);
- Hunt not runnable (`:1686`);
- licence state and slots;
- Enterprise feature toggles: Hunt disabled, active autonomous episodes, `/arsenal/execute` with `execute=true`, network scans off;
- capabilities the deployment does not register;
- anything not in the catalogue.

These keep today's plain refusal text.

**Credential rule (owner point 5).** The effective credential set for a slot is the start
selection ∪ the target's `usable_credentials` ∪ live `credential.use` grants for this Hunt.
Nothing else is ever used.
- If a Hunt-authority entry fits a refused slot, the server uses it with no request and records
  source `target_authority`, or `granted_from_target:<home>` when the profile came from another
  target through a credential grant.
- A credential never authorizes a destination. Every use is checked against the Hunt's
  authorized set first, so a credential grant cannot widen scope.

## API

All routes are under the canonical `/hunts` surface. None of them is added to the planner-lease
ingress. There is **no create route**: requests come only from refusals.

| Route | Who | Notes |
|---|---|---|
| `GET /hunts/{id}/permission-requests?status=` | anyone who can read the Hunt | Includes server-rendered `title`, `explanation`, `effect`, `choices`, `remember_supported`. |
| `GET /hunts/{id}/permission-requests/{rid}?wait_seconds=0..25` | as above | Long-poll: returns at once on any status change, otherwise after `wait_seconds`. |
| `POST /hunts/{id}/permission-requests/{rid}/decision` | operator+ person | Body: `decision` (`allow`/`deny`), `scope` (`hunt`/`target`), `subject_digest` (must match; protects against stale views), `choice` (kind-specific: `profile_id`, `limit`, `budget`), `idempotency_key`, `operator_confirmed:true`, `note` (≤500 chars, redacted). Row `FOR UPDATE`; replaying the same decision returns 200, a conflicting one 409 with the current state. |
| `GET /hunts/{id}/permission-grants` | read | Active and revoked grants with their uses. |
| `POST /hunts/{id}/permission-grants/{gid}/revoke` | operator+ person | Stops future uses; in-flight actions finish. |

The refusal response for an allowable reason is **HTTP 409** with
`detail: {code: "permission_required", permission_request: {id, kind, status, title, hunt_url}, action_id}`.
The idempotency middleware is changed so that a 409 releases the key, like a 422.

## MCP and CLI

**MCP adapter.**
- Maps `permission_required` to `outcome: "awaiting_permission"`, with `permission_request_id`,
  the server `title`, `hunt_url`, and fixed recovery text: *"Waiting for the user to allow: {title}.
  Tell the user, then call `shakerscan_hunt_permission_wait`. When it returns `granted`, call the
  same tool again with the same idempotency key. If it returns `denied` or `expired`, do not retry
  this action."*
- New tool `shakerscan_hunt_permission_wait(hunt_id, request_id)` long-polls within the 45 s call
  limit and sends progress notifications. It returns the status, or `still_pending` so the agent
  calls it again.
- No MCP tool decides a request.
- MCP hosts that declare the `elicitation` capability may later receive an informational
  `elicitation/create` that shows the title and the Hunt page link. It never carries an Allow
  button, because an answer through the agent's channel is the agent's answer.
- Assertions and tokens are never put in the link.

**CLI.**
- `shakerscan hunt permissions list|show|wait <hunt>` everywhere.
- `approve|deny <hunt> <request> [--remember]` only where the caller is a person: OSS local, and
  Enterprise only if open question 1 allows it.
- `hunt call` prints the request and the Hunt page link on `permission_required`.

## UI

The existing **"Needs your decision"** section of `HuntRunView.tsx` gains one card per pending
request (`pendingDecisions()` merges them). Example card:

> **Allow this Hunt to use the credential "Staging admin" (belongs to api.example.com)?**
> Blocked step: authorization proof needs a second identity (slot: secondary). The Hunt is
> waiting for this step; other work continues.
> ◉ Only this Hunt ○ Also future Hunts on shop.example.com
> [Allow] [Deny]
> *Requested by ShakerScan after it refused the step. The agent cannot approve requests.*

Card rules:
- A `target.authorize` card shows the host as ASCII, the resolved address, and whether it shares
  the target's registrable domain.
- An `ssh.exec` card shows the argv in monospace, under "command proposed by the agent".
- Viewers see the card without buttons: "An operator must decide."

Other placements:
- A badge counts pending requests in the Hunt list.
- The timeline shows `awaiting_permission` actions and later uses with their authority source.
- Target detail (`TargetHuntPermissions.tsx`) gains a "Credentials Hunts may use" list, kept
  separate from "may share".

## Idempotent resume

The agent re-sends the **same** key and input. The server recognises the parked row.
1. If the request is granted, the server re-runs the full admission (scope, budget reservation,
   credential selection) inside a normal transaction and moves the row from
   `awaiting_permission` to `reserved`.
2. A grant changes what admission allows, but never skips it. A grant that has been revoked or
   gone stale in the meantime leads to a fresh request.
3. Budget-shortage rows also become `awaiting_permission`, no longer `failed`, which fixes the
   cached-refusal replay.
4. Work that already ran is never re-dispatched; this keeps `require_resume_headroom`
   semantics.

## Concurrency

- **Several pending requests** are independent. They are deduped by subject, and one grant
  unblocks every parked action with that subject; each action retries under its own key.
- The number of pending requests per Hunt is capped (proposal: 20). Past the cap, a refusal
  stays plain with "too many pending permission requests".
- **Decision races** are prevented by a row lock and the `pending` precondition.
- A **budget grant racing another amendment** uses the amendment's `expected_revision`. On 409
  the decision is retried once with the fresh revision, because the user approved the new
  total, not the delta.
- **The Hunt ends while a request is pending:** the request is withdrawn in the same
  transaction. A later decision returns 409 "this Hunt has ended; nothing was granted", and
  "remember" is not applied either. The user edits target permissions directly instead.
- **A grant arrives while the agent has moved on:** the parked action stays parked until the
  Hunt ends, then settles `blocked`.
- **Duration budget:** it keeps counting while a request waits (see open question 4).

## Security analysis

- **No request from untrusted text.** Requests are created only inside server refusal branches,
  from the closed `kind`/`reason_code` enums and server-resolved `subject` fields. Titles and
  explanations are rendered from server templates, never from agent or target text. The model
  cannot add a justification in v1.
- **Target-derived strings.** Hosts are rendered as IDNA ASCII, with the resolved address and
  the scope verdict next to them. SSH argv is shown verbatim and bound by digest. A redirect or
  response body can at most cause a refusal for a host the user then sees in plain form.
- **Hard limits are checked first.** A private or metadata destination never produces a request.
- **The agent cannot approve.**
  - Enterprise: the decision routes accept only a signed-in **browser session** with operator or
    admin role. Service tokens are refused; the client and agent hold service tokens.
  - Planner-lease ingress: the decision routes are not exposed.
  - OSS local (no login, `docs/lan-access.md:80`): the trust boundary is the host. Any process
    that can reach the API can decide, so `operator_confirmed` plus `subject_digest` only prevent
    accidents. The OSS docs must say this plainly.
- **Narrow grants.** Each grant is one subject. There is no "allow all", and a credential grant
  never authorizes a target.
- **Fatigue.** Requests are deduped and capped, and every card states its effect and scope.
- **Audit.** Every request, decision, use and revocation is an event naming the actor and the
  source. Secrets, collections and evidence are never logged: subjects hold ids and digests only.

## M4 fix

Today `_execute_hunt_candidate_verification` (`api/hunt/interaction_router.py:4250-4260`) calls
`_verify_suspected_finding_workflow` (`api/api.py:14139`). That reaches
`_agent_verification_workflow_for` (`:13734`; BOLA resolves `user1,user2` at `:13742`,
data exposure `user1` at `:13760`) and then `_arsenal_dispatch_workflow`
(`api/arsenal_routes/router.py:8095`). Both call `_resolve_workflow_principal_contexts`
(`api/api.py:16517`), which decrypts **every active `target_principals` row** of the target
(`:16559`). The Hunt's `credential_refs` never reach this chain. The resolver also joins only
home-target profiles (`cp.target_id = p.target_id`), so granted credentials cannot be used.

Fix (PR E1):
1. Pass the run's frozen `credential_refs`, plus the live `credential.use` grants once E3 lands,
   down the verification chain.
2. Add a Hunt resolver in the style of `resolve_hunt_authz_principals`
   (`api/hunt/authz_credentials.py:24`). It maps `user1←primary` and `user2←secondary`, reads
   only profile ids in the effective set through `credential_profile_bindings` (home or active
   grant), and checks version, active status and expiry before it decrypts.
3. Use this resolver at both resolution points, and in `_server_materialize_create_ma`
   (`:18607`) when it is called from a Hunt.
4. When a slot is missing, return 422 with the finding left suspected; after E3 this becomes a
   `credential.use` request.
5. Callers outside a Hunt keep today's resolver; that is out of scope here and noted as follow-up.

## Enterprise gateway changes

All in `src/shakerscan_saas/enterprise/policy.py` and `app.py`:
- Add `GET /hunts/{ID}/permission-(?:requests|grants)` and `.../permission-requests/{ID}` to
  `HUNT_READ`, for every role when Hunt is enabled.
- Add `POST .../permission-requests/{ID}/decision` and `.../permission-grants/{ID}/revoke` to
  `HUNT_WRITE`, with a new app-side guard. Requests with `user["auth"]!="session"` are refused
  with "permission decisions need a signed-in person" (the same pattern as the admin session rule
  in `authenticate`, `app.py:500`). Origin is required as for every session mutation.
- Rewrite `decided_by` to `authorizing_identity(user)`, in the same way as `approved_by` in
  `ensure_target_authorization` (`app.py:1607`). Audit `hunt.permission.decided` with the request
  kind and scope.
- Licence: allow decisions only when `can_mutate`; `deny` and `revoke` stay possible, like
  `can_cancel`.
- Feature toggles: when a toggle is off, the gateway refuses `allow` decisions for the kinds that
  toggle covers.
- A long-poll `wait_seconds` must stay under `upstream_timeout_seconds`, or the route joins
  `long_running`.
- Review: this is a new engine minor line, so it gets a `REVIEWED_ENGINE_LINES` entry with
  history notes. Regenerate `tools/ui_route_inventory.py` against it and add dispositions in
  `tests/enterprise/test_ui_inventory.py` (the decision is `hunt:operator-session`). Add tests in
  `test_hunt_preview.py`.
- Add a capability-manifest feature `hunt_permission_decisions`, so the UI hides the buttons for
  viewers and token-only contexts.

## Migration

- Additive tables, the action-status constraint update and the Hunt-authority field are
  introduced through the engine's migration registry; `db/init.sql` and the PostgreSQL migration
  are kept in step.
- Older Hunt-authority documents read `usable_credentials` as empty. Existing Hunts have no
  requests, and nothing is backfilled.
- Old MCP clients still see a readable refusal (`HTTP 409: …` with the title, as in #337).
  Upgrading the client adds waiting.
- Regenerate the public OpenAPI manifest, `publicApi.generated.ts`, the surface dispositions,
  `/hunts/contract`, `docs/functionality-reference.md` and the install manifest.

## Test plan

**Unit tests** (fixtures labelled):
- refusal → kind/reason mapping for every catalogue row;
- hard limits never create a request (private, metadata, changed locator, unregistered
  capability);
- every rendered string comes from templates; a target body containing request-looking text
  produces nothing.

**PostgreSQL tests:**
- dedupe index;
- concurrent decisions;
- a decision racing Hunt finish or cancel;
- a budget grant racing an amendment;
- same-key retry before, during and after a grant, and after a denial;
- same key with different input gives 409;
- a budget-shortage replay now resumes;
- the 409 key release in the middleware.

**M4 tests:**
- an unselected principal is never decrypted (spy on `decrypt_secret`);
- a granted foreign profile resolves through its binding;
- a rotated profile is refused.

**MCP adapter tests:**
- `awaiting_permission` outcome;
- the wait tool times out and then resolves;
- there is no decision tool.

**UI unit and browser tests:** click Allow and Deny on a real Hunt page, the remember option,
and the viewer view.

**Gateway tests:**
- a service token is refused on the decision route;
- a viewer is refused;
- an operator session is allowed with origin;
- `decided_by` is rewritten;
- the inventory dispositions are present.

**Live acceptance** on the soak host, through the UI, with OpenCode over the client:
1. A Hunt exhausts `max_http_requests`; the user allows a raise; the same action resumes.
2. BOLA uses another target's credential granted live.
3. A new port is authorized for the Hunt.
4. A denied request settles `blocked`.
5. A Hunt is cancelled while a request is pending.

## PR split

**Engine:**
- **E1:** M4 selection-aware verification resolver (standalone; ships first).
- **E2:** tables, events, the `awaiting_permission` action status, the `permission_required`
  refusal, the middleware 409 fix, read and decision routes, and the `budget.raise` and
  `capability.enable` kinds.
- **E3:** `credential.use` (including other targets' credentials, kind rules and
  `usable_credentials`), `target.authorize`, `ssh.exec` and `ssh.host_trust`, and remember-for-target.
- **E4:** Hunt page cards, the target-detail list, MCP outcome and wait tool, CLI, docs and
  contract regeneration.

**Gateway:**
- **G1:** after the engine line is published: allowlists, the session-only decision guard,
  `decided_by` rewrite, licence and toggle rules, audit, manifest feature, inventory and tests.

## Open questions for the owner

1. **Can the CLI approve in Enterprise?** The CLI and agents hold the same service tokens. The
   recommendation is browser-only decisions in Enterprise v1; the CLI lists, waits and prints the
   link. The alternative is a person-bound, short-lived "approver" token type that is never
   written to an agent workspace.
2. **Pending-request expiry:** 24 h, or the end of the Hunt's duration budget, whichever comes
   first?
3. **Remember for capability flags:** should "remember" exist for `capability.enable`
   (state-changing HTTP, OOB, TCP discovery)? That would need a new target-level default in Hunt
   authority. Proposal: not in v1.
4. **Duration budget while waiting:** should `max_duration_seconds` pause while a request is
   pending? Proposal: no, it keeps counting, and the request card shows the time remaining.
5. **Foreign credential, Hunt scope only:** may it be used without creating a credential grant
   (binding) on the target? Proposal: yes, since the same kind rules are checked; "remember"
   creates the binding.
6. **Agent justification:** should a model-written note be shown at all (collapsed, labelled
   untrusted), or nothing in v1? Proposal: nothing.
7. **M4 outside Hunt:** should the same selection rule apply to non-Hunt autonomous verification,
   or is that a separate change?
