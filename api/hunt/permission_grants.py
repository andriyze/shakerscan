"""Grant effects, decisions and revocations for Hunt permission requests.

A grant reuses the mechanism that already owns its authority; it never adds a parallel one:

* ``budget.raise`` is exactly one ``hunt-budget-amendment/v1``: total limits, the revision read
  under the Hunt row lock, key ``permission:<request id>``, ``resume=true`` when the Hunt stopped
  on this dimension. There is no "remember" for budget.
* ``capability.enable`` turns the policy flag on for this Hunt only, adds the capability to the
  persisted allowlist the workers re-read, and sets a zeroed dimension to the profile default
  through one amendment. It needs the target's standing authorization. No "remember" (v1).
* ``target.authorize`` adds the destination to the Hunt's authorized overlay
  (``policy.granted_destinations``), which ``resolve_hunt_http_origin`` honours at admission and
  in the worker. Remember on the Hunt's own host records the standing target authorization.
* ``credential.use`` lets this Hunt use exactly one profile version after the same kind rules a
  credential grant applies, without creating a binding. Remember creates the normal credential
  grant (``granted_by="permission-request:<id>"``), which joins the one attached list.

A grant changes what admission allows; it never skips admission. Decisions lock the Hunt row and
then the request row, require the pending state and the exact subject digest, and are
replay-safe: the same decision again returns the recorded one, a different one is refused.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Awaitable
import uuid

from fastapi import HTTPException

from .budget_amendments import HuntBudgetAmendmentRequest, amendable_dimensions, apply_budget_amendment
from .permission_bounds import CAPABILITY_FLAGS, BoundError, Bounds, legacy_host_changes, parse_bounds
from .permission_reasons import (
    KIND_BUDGET_RAISE,
    KIND_CAPABILITY_ENABLE,
    KIND_CREDENTIAL_USE,
    KIND_PREAUTHORIZATION,
    KIND_TARGET_AUTHORIZE,
)
from .permission_store import (
    covering_preauthorization,
    hunt_bounds,
    load_request,
    reconcile_host_encoding,
    public_grant,
    public_request,
    record_event,
    record_preauthorization,
    render,
)
from .start_contract import HUNT_BUDGET_PROFILES, ZEROABLE_HUNT_BUDGET_DIMENSIONS

# Ledger dimension (what admission reserves) -> the budget limit that bounds it.
LEDGER_TO_BUDGET = {
    "agent_actions": "max_capability_calls",
    "active_actions": "max_active_actions",
    "http_requests": "max_http_requests",
    "tcp_ports_attempted": "max_tcp_ports",
    "browser_actions": "max_browser_actions",
    "state_changing_requests": "max_state_changing_requests",
    "tool_wall_seconds": "max_duration_seconds",
    "device_fragility_points": "max_device_fragility_points",
    "hosts_attempted": "max_hosts",
    "udp_ports_attempted": "max_udp_ports",
    "oob_interactions": "max_oob_interactions",
    "verifications": "max_verifications",
    "candidates": "max_candidates",
}
FINISHED_STATUSES = frozenset({"completed", "cancelled", "failed"})


class GrantRefused(HTTPException):
    """The person's decision cannot be applied; nothing was granted."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(status_code=status_code, detail={"error": code, "message": message})


def _json(value: Any, default: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return default
    return default if value is None else dict(value) if isinstance(value, Mapping) else value


def hunt_finished(run: Mapping[str, Any]) -> bool:
    return str(run.get("status") or "") in FINISHED_STATUSES or run.get("completed_at") is not None


async def _standing_authorization(conn: Any, target_id: Any) -> Mapping[str, Any] | None:
    try:
        from target_authorization import current_target_authorization
    except ModuleNotFoundError:
        from api.target_authorization import current_target_authorization
    return await current_target_authorization(conn, target_id)


# Replaceable by tests (labelled doubles) and kept to one seam.
standing_authorization: Callable[[Any, Any], Awaitable[Mapping[str, Any] | None]] = _standing_authorization


async def _lock_run(conn: Any, hunt_id: Any) -> dict[str, Any]:
    row = await conn.fetchrow("SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE", uuid.UUID(str(hunt_id)))
    if row is None:
        raise HTTPException(404, "Hunt not found")
    return dict(row)


async def _write_policy(conn: Any, run: dict[str, Any], policy: Mapping[str, Any]) -> None:
    context = _json(run.get("context_pack"), {})
    context["allowed_capabilities"] = list(policy.get("allowed_capabilities") or [])
    await conn.execute(
        """UPDATE hunt_runs SET policy_json=$2::jsonb, context_pack=$3::jsonb,
                  approval_receipt_id=COALESCE(approval_receipt_id, $4::uuid), updated_at=NOW()
           WHERE id=$1""",
        run["id"], json.dumps(policy), json.dumps(context, default=str),
        uuid.UUID(str(policy["approval_receipt_id"])) if policy.get("approval_receipt_id") else None,
    )
    run["policy_json"], run["context_pack"] = json.dumps(policy), json.dumps(context, default=str)


async def _ensure_receipt(conn: Any, run: Mapping[str, Any], policy: dict[str, Any]) -> bool:
    """Bind the target's standing authorization to a Hunt that started without one."""
    if policy.get("approval_receipt_id"):
        return False
    target_id = run.get("target_id") or run.get("device_target_id")
    standing = await standing_authorization(conn, target_id)
    if not standing or not standing.get("approval_receipt_id"):
        raise GrantRefused(409, "target_authorization_required", (
            "This target has no standing authorization, which this permission needs. Authorize "
            f"the target once (POST /targets/{target_id}/authorization), then allow this request again."
        ))
    policy["approval_receipt_id"] = str(standing["approval_receipt_id"])
    policy["scope_receipt_id"] = str(standing.get("scope_receipt_id") or "") or None
    policy["authorization_confirmed"] = True
    return True


def _start_limit(run: Mapping[str, Any], dimension: str) -> int:
    context = _json(run.get("context_pack"), {})
    started = (context.get("hunt_start_contract") or {}).get("resolved_budget") or {}
    budget = _json(run.get("budget_json"), {})
    return int(started.get(dimension) or budget.get(dimension) or 0)


async def _amend(
    conn: Any, run: Mapping[str, Any], *, request_id: Any, limits: Mapping[str, int],
    actor: str, suffix: str = "",
) -> dict[str, Any] | None:
    """One budget amendment under the Hunt lock; retried once if the revision moved."""
    if not limits:
        return None
    for attempt in range(2):
        current = dict(await conn.fetchrow("SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE", run["id"]))
        budget = _json(current.get("budget_json"), {})
        wanted = {key: int(value) for key, value in limits.items() if int(value) > int(budget.get(key) or 0)}
        if not wanted:
            return None
        stop = str(current.get("stop_reason") or "")
        resume = current.get("status") == "budget_exhausted" and stop.startswith("budget_exhausted:") and (
            LEDGER_TO_BUDGET.get(stop.removeprefix("budget_exhausted:")) in wanted
        )
        try:
            return await apply_budget_amendment(conn, current["id"], HuntBudgetAmendmentRequest(
                limits=wanted, expected_revision=int(current.get("budget_revision") or 0),
                idempotency_key=f"permission:{request_id}{suffix}", operator_confirmed=True,
                resume=resume, reason=f"Permission request {request_id} granted by {actor}"[:500],
            ))
        except HTTPException as exc:
            if exc.status_code == 409 and attempt == 0 and isinstance(exc.detail, Mapping):
                continue
            raise
    return None


async def _apply_budget(conn, run, request, choice, actor) -> dict[str, Any]:
    subject = _json(request["subject_json"], {})
    display = _json(request.get("display_json"), {})
    dimension = str(subject["dimension"])
    if dimension not in amendable_dimensions(run):
        raise GrantRefused(409, "budget_dimension_needs_permission",
                           f"{dimension} needs a permission this Hunt does not have; a budget raise cannot grant it.")
    needed = int(display.get("needed_total") or 0)
    total = int(choice.get("total") or display.get("proposed_total") or needed)
    if total < needed:
        raise GrantRefused(422, "budget_total_too_small",
                           f"The refused action needs a total of at least {needed} {dimension}.")
    amendment = await _amend(conn, run, request_id=request["id"], limits={dimension: total}, actor=actor)
    return {"dimension": dimension, "total": total,
            "amendment_id": (amendment or {}).get("amendment", {}).get("amendment_id")}


async def _apply_capability(conn, run, request, actor) -> dict[str, Any]:
    subject = _json(request["subject_json"], {})
    policy = _json(run.get("policy_json"), {})
    before = {key: policy.get(key) for key in (
        "active_testing", "allow_state_changing_http", "allow_oob_interactions", "network_discovery",
        "mutation_allowed", "approval_receipt_id", "scope_receipt_id", "authorization_confirmed",
    )}
    receipt_bound = await _ensure_receipt(conn, run, policy)
    flag = str(subject.get("flag") or "")
    for field in CAPABILITY_FLAGS.get(flag, ()):
        policy[field] = True
    if policy.get("allow_state_changing_http"):
        policy["mutation_allowed"] = True
    capability = str(subject["capability"])
    allowed = list(policy.get("allowed_capabilities") or [])
    added = capability not in allowed
    if added:
        allowed.append(capability)
    policy["allowed_capabilities"] = allowed
    await _write_policy(conn, run, policy)
    profile = HUNT_BUDGET_PROFILES.get(str(run.get("budget_profile") or "balanced"), HUNT_BUDGET_PROFILES["balanced"])
    budget = _json(run.get("budget_json"), {})
    permitted = set(amendable_dimensions({**run, "policy_json": policy}))
    raises = {
        key: int(getattr(profile, key)) for key in sorted(ZEROABLE_HUNT_BUDGET_DIMENSIONS)
        if key in permitted and int(budget.get(key) or 0) == 0 and int(getattr(profile, key)) > 0
    }
    amendment = await _amend(conn, run, request_id=request["id"], limits=raises, actor=actor, suffix=":dimensions")
    return {"policy_before": before, "flag": flag, "capability": capability, "capability_added": added,
            "receipt_bound": receipt_bound, "dimensions_set": raises,
            "amendment_id": (amendment or {}).get("amendment", {}).get("amendment_id")}


async def _apply_target(conn, run, request, actor) -> dict[str, Any]:
    subject = _json(request["subject_json"], {})
    policy = _json(run.get("policy_json"), {})
    destinations = [dict(item) for item in policy.get("granted_destinations") or () if isinstance(item, Mapping)]
    entry = {key: subject.get(key) for key in ("host", "port", "scheme", "origin", "addresses", "same_host")}
    entry["request_id"] = str(request["id"])
    if not any(item.get("origin") == entry["origin"] for item in destinations):
        destinations.append(entry)
    policy["granted_destinations"] = destinations[-64:]
    await _write_policy(conn, run, policy)
    return {"destination": entry}


async def _apply_credential(conn, run, request) -> dict[str, Any]:
    subject = _json(request["subject_json"], {})
    from .permission_subjects import credential_kind_error
    error = await credential_kind_error(conn, run, subject)
    if error:
        raise GrantRefused(409, "credential_kind_unsupported", error)
    return {"profile_id": subject["profile_id"], "profile_version": subject["profile_version"],
            "slot": subject.get("slot")}


async def _remember(conn, run, request, actor) -> str | None:
    kind = request["kind"]
    subject = _json(request["subject_json"], {})
    target_id = run.get("target_id") or run.get("device_target_id")
    if kind == KIND_TARGET_AUTHORIZE:
        if not subject.get("same_host"):
            raise GrantRefused(422, "remember_not_supported",
                               "Remember applies to the Hunt's own host; another host is a separate target.")
        try:
            from target_authorization import TargetAuthorizationError, authorize_target
        except ModuleNotFoundError:
            from api.target_authorization import TargetAuthorizationError, authorize_target
        try:
            standing = await authorize_target(conn, target_id, approved_by=actor)
        except TargetAuthorizationError as exc:
            raise GrantRefused(409, "target_authorization_refused", str(exc)) from exc
        return f"approval_receipt:{standing.get('approval_receipt_id')}"
    if kind == KIND_CREDENTIAL_USE:
        try:
            from runtime.credential_store import CredentialStoreError, PostgresCredentialProfileStore
        except ModuleNotFoundError:
            from api.runtime.credential_store import CredentialStoreError, PostgresCredentialProfileStore
        try:
            await PostgresCredentialProfileStore().grant_profile(
                conn, profile_id=subject["profile_id"], target_kind=str(run["target_kind"]),
                target_id=target_id, granted_by=f"permission-request:{request['id']}",
                now=datetime.now(timezone.utc),
            )
        except CredentialStoreError as exc:
            raise GrantRefused(409, "credential_grant_refused", str(exc)) from exc
        return f"credential_grant:{subject['profile_id']}:{target_id}"
    raise GrantRefused(422, "remember_not_supported", f"{kind} cannot be remembered for the target.")


async def apply_grant(
    conn: Any, *, run: dict[str, Any], request: Mapping[str, Any], scope: str,
    choice: Mapping[str, Any], actor: str, via: str, preauthorization_id: Any = None,
) -> dict[str, Any]:
    """Apply one grant inside the caller's transaction (Hunt row locked); return its row."""
    kind = request["kind"]
    persisted_ref = None
    if scope == "target":
        persisted_ref = await _remember(conn, run, request, actor)
    if kind == KIND_BUDGET_RAISE:
        effect = await _apply_budget(conn, run, request, choice, actor)
    elif kind == KIND_CAPABILITY_ENABLE:
        effect = await _apply_capability(conn, run, request, actor)
    elif kind == KIND_TARGET_AUTHORIZE:
        effect = await _apply_target(conn, run, request, actor)
    elif kind == KIND_CREDENTIAL_USE:
        effect = await _apply_credential(conn, run, request)
    elif kind == KIND_PREAUTHORIZATION:
        subject = _json(request["subject_json"], {})
        bounds = _approvable_proposal(subject)
        stored = await record_preauthorization(
            conn, hunt_id=run["id"], bounds=bounds, created_by=actor, proof="request_approval",
            source_request_id=request["id"],
        )
        effect = {"preauthorization_id": str(stored["id"]), "bounds_digest": bounds.digest()}
    else:
        raise GrantRefused(422, "kind_not_grantable", f"{kind} requests cannot be granted in this release.")
    row = await conn.fetchrow(
        """INSERT INTO hunt_permission_grants
               (hunt_run_id, request_id, preauthorization_id, kind, subject_json, subject_digest,
                scope, effect_json, persisted_ref, created_by)
           VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8::jsonb,$9,$10) RETURNING *""",
        run["id"], request["id"],
        uuid.UUID(str(preauthorization_id)) if preauthorization_id else None,
        kind, json.dumps(_json(request["subject_json"], {}), sort_keys=True), request["subject_digest"],
        scope, json.dumps(effect, sort_keys=True, default=str), persisted_ref, str(actor)[:200],
    )
    await conn.execute(
        """UPDATE hunt_permission_requests
           SET status='granted', decided_at=NOW(), decided_by=$2, decision_via=$3,
               decision_scope=$4, decision_choice_json=$5::jsonb, grant_id=$6
           WHERE id=$1""",
        request["id"], str(actor)[:200], via, scope, json.dumps(dict(choice), sort_keys=True), row["id"],
    )
    return dict(row)


# ---------------------------------------------------------------------------------------------
# Pre-authorization.

def _approvable_proposal(subject: Mapping[str, Any]) -> Bounds:
    """The bounds an agent's proposal grants, refused when they are not the bounds it digested.

    A proposal raised before hosts were spelled with IDNA 2008/UTS #46 carries a digest of its
    IDNA 2003 parse. When a host it names is spelled differently now (``straße.example`` was
    ``strasse.example``), granting it would authorize another host than the one recorded, so the
    person is asked to approve a new proposal instead; nothing is reinterpreted silently.
    """
    allow = [str(item) for item in subject.get("allow") or ()]
    try:
        bounds = parse_bounds(allow)
    except BoundError as exc:
        raise GrantRefused(409, "preauthorization_reapproval_required", (
            f"These proposed bounds cannot be granted: {exc}. Start the Hunt again with bounds "
            "that spell the intended hosts."
        )) from exc
    if subject.get("bounds_digest") != bounds.digest():
        changed = legacy_host_changes(allow)
        if changed:
            # Normally replaced before a person sees it (``supersede_legacy_proposals`` runs when
            # the request is read); this is the backstop, and reading it again does the replacing.
            raise GrantRefused(409, "preauthorization_reapproval_required", " ".join(
                item.finding() for item in changed
            ) + " This proposal names other hosts than the ones it was recorded for, so it was not "
                "granted. Run shakerscan approve with this request id again: it is replaced by the "
                "same bounds for the hosts they name, which you approve in one step.")
    return bounds


def _covers(bounds: Bounds, request: Mapping[str, Any], run: Mapping[str, Any]) -> dict[str, Any] | None:
    """The grant choice when ``bounds`` cover this request, else None."""
    kind = request["kind"]
    subject = _json(request["subject_json"], {})
    display = _json(request.get("display_json"), {})
    if kind == KIND_BUDGET_RAISE:
        dimension = str(subject.get("dimension"))
        total = bounds.covers_budget(
            dimension=dimension, start_limit=_start_limit(run, dimension),
            needed_total=int(display.get("needed_total") or 0),
        )
        return {"total": total} if total else None
    if kind == KIND_CREDENTIAL_USE:
        ok = bounds.covers_credential(home_target_id=str(subject.get("home_target_id")),
                                      home_host=subject.get("home_host"))
        return {} if ok else None
    if kind == KIND_TARGET_AUTHORIZE:
        return {} if bounds.covers_target(host=str(subject.get("host")), port=subject.get("port")) else None
    if kind == KIND_CAPABILITY_ENABLE:
        flag = str(subject.get("flag") or "")
        return {} if flag and bounds.covers_capability(flag) else None
    return None


async def try_preauthorized_grant(conn: Any, run: dict[str, Any], request: Mapping[str, Any]) -> dict[str, Any] | None:
    """Grant a pending request inside the start bounds, in the caller's transaction."""
    if request["kind"] == KIND_PREAUTHORIZATION or request["status"] != "pending":
        return None
    # Legacy (IDNA 2003) host bounds that no longer match are offered back to the person, and
    # legacy proposals are replaced, before coverage is read.
    await reconcile_host_encoding(conn, run)
    _bounds, rows = await hunt_bounds(conn, run["id"])
    choices: dict[str, Any] = {}

    def predicate(bounds: Bounds) -> bool:
        choice = _covers(bounds, request, run)
        if choice is not None:
            choices["value"] = choice
        return choice is not None

    preauth = covering_preauthorization(rows, predicate)
    if preauth is None:
        return None
    try:
        # A savepoint: a grant that cannot be applied leaves nothing behind, and the request
        # stays pending for a person.
        async with conn.transaction():
            grant = await apply_grant(
                conn, run=run, request=request, scope="hunt", choice=choices["value"],
                actor=str(preauth["created_by"]), via="preauthorization", preauthorization_id=preauth["id"],
            )
    except HTTPException:
        return None
    await record_event(
        conn, hunt_id=run["id"], request_id=request["id"], grant_id=grant["id"],
        action_id=request.get("action_id"), event="auto_granted", actor=str(preauth["created_by"]),
        source="preauthorization", detail={"preauthorization_id": str(preauth["id"])},
    )
    return grant


# ---------------------------------------------------------------------------------------------
# Decisions and revocation (person only: never reachable through the planner or MCP).

def _key_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


async def withdraw_request(conn: Any, hunt_id: Any, request_id: Any, *, actor: str, source: str) -> None:
    updated = await conn.fetchrow(
        """UPDATE hunt_permission_requests SET status='withdrawn', decided_at=NOW()
           WHERE id=$1 AND status='pending' RETURNING id""",
        uuid.UUID(str(request_id)),
    )
    if updated is not None:
        await record_event(conn, hunt_id=hunt_id, request_id=request_id, event="withdrawn",
                           actor=actor, source=source)


async def decide(conn: Any, hunt_id: Any, request_id: Any, body: Mapping[str, Any]) -> dict[str, Any]:
    """Apply a person's decision. The caller opens the transaction."""
    from .permission_store import expire_due
    run = await _lock_run(conn, hunt_id)
    await expire_due(conn, run["id"])
    request = await load_request(conn, run["id"], request_id, for_update=True)
    if request is None:
        raise HTTPException(404, "Permission request not found in this Hunt")
    decision, scope = str(body["decision"]), str(body.get("scope") or "hunt")
    choice = dict(body.get("choice") or {})
    key = _key_digest(str(body["idempotency_key"]))
    if request["status"] != "pending":
        same = (
            request.get("decision_key_sha256") == key
            or (request["status"] == ("granted" if decision == "allow" else "denied")
                and (decision == "deny" or request.get("decision_scope") == scope))
        )
        if same and request["status"] in {"granted", "denied"}:
            return {"replayed": True, "request": public_request(request)}
        replaced = _json(request.get("display_json"), {})
        if request["status"] == "withdrawn" and replaced.get("superseded_reason"):
            message = (
                f"{replaced['superseded_reason']} This proposal was replaced"
                + (f" by request {replaced['superseded_by']}: run shakerscan approve "
                   f"{replaced['superseded_by']}." if replaced.get("superseded_by") else
                   " and cannot be granted; start the Hunt again with bounds that spell the host.")
            )
        elif request["status"] == "withdrawn":
            message = "This Hunt has ended; nothing was granted."
        else:
            message = f"This request is already {request['status']}; the decision was not applied."
        raise HTTPException(409, {
            "error": f"permission_{request['status']}",
            "message": message,
            "request": public_request(request),
        })
    if str(body.get("subject_digest") or "") != request["subject_digest"]:
        raise HTTPException(409, {
            "error": "permission_subject_changed",
            "message": "The request you reviewed no longer matches; fetch it again before deciding.",
        })
    actor = str(body.get("decided_by") or "local-operator")[:200]
    via = str(body.get("decision_via") or "local_confirm")
    if hunt_finished(run):
        await withdraw_request(conn, run["id"], request["id"], actor=actor, source="hunt_ended")
        raise HTTPException(409, {"error": "permission_withdrawn",
                                  "message": "This Hunt has ended; nothing was granted, and nothing was remembered."})
    if decision == "deny":
        await conn.execute(
            """UPDATE hunt_permission_requests
               SET status='denied', decided_at=NOW(), decided_by=$2, decision_via=$3,
                   decision_scope=$4, decision_key_sha256=$5 WHERE id=$1""",
            request["id"], actor, via, scope, key,
        )
        grant = None
    else:
        rendered = render(request["kind"], _json(request["subject_json"], {}), _json(request.get("display_json"), {}))
        if scope not in rendered["scopes"]:
            raise HTTPException(422, {"error": "remember_not_supported",
                                      "message": f"{request['kind']} supports only: {', '.join(rendered['scopes'])}."})
        grant = await apply_grant(conn, run=run, request=request, scope=scope, choice=choice,
                                  actor=actor, via=via)
        await conn.execute("UPDATE hunt_permission_requests SET decision_key_sha256=$2 WHERE id=$1",
                           request["id"], key)
    await record_event(
        conn, hunt_id=run["id"], request_id=request["id"], grant_id=grant["id"] if grant else None,
        event="decided", actor=actor, source=via,
        detail={"decision": decision, "scope": scope, "subject_digest": request["subject_digest"]},
    )
    current = await load_request(conn, run["id"], request["id"])
    return {"replayed": False, "request": public_request(current),
            **({"grant": public_grant(grant)} if grant else {})}


async def revoke_grant(conn: Any, hunt_id: Any, grant_id: Any, *, revoked_by: str) -> dict[str, Any]:
    """Revoke a live grant for the rest of this Hunt. A remembered record is not undone here."""
    run = await _lock_run(conn, hunt_id)
    row = await conn.fetchrow(
        "SELECT * FROM hunt_permission_grants WHERE id=$1 AND hunt_run_id=$2 FOR UPDATE",
        uuid.UUID(str(grant_id)), run["id"],
    )
    if row is None:
        raise HTTPException(404, "Permission grant not found in this Hunt")
    grant = dict(row)
    if grant["revoked_at"] is not None:
        return {"replayed": True, "grant": public_grant(grant)}
    if grant["kind"] in {KIND_BUDGET_RAISE, KIND_PREAUTHORIZATION}:
        raise HTTPException(409, {"error": "grant_not_revocable", "message": (
            "A budget raise is an amendment in the Hunt's history and pre-authorization bounds are "
            "frozen with the start; neither is revoked."
        )})
    effect = _json(grant["effect_json"], {})
    policy = _json(run.get("policy_json"), {})
    if grant["kind"] == KIND_TARGET_AUTHORIZE:
        origin = (effect.get("destination") or {}).get("origin")
        policy["granted_destinations"] = [
            item for item in policy.get("granted_destinations") or () if item.get("origin") != origin
        ]
        await _write_policy(conn, run, policy)
    elif grant["kind"] == KIND_CAPABILITY_ENABLE:
        for key, value in (effect.get("policy_before") or {}).items():
            if key in {"approval_receipt_id", "scope_receipt_id", "authorization_confirmed"}:
                continue
            policy[key] = value
        if effect.get("capability_added"):
            policy["allowed_capabilities"] = [
                name for name in policy.get("allowed_capabilities") or () if name != effect.get("capability")
            ]
        await _write_policy(conn, run, policy)
    updated = await conn.fetchrow(
        "UPDATE hunt_permission_grants SET revoked_at=NOW(), revoked_by=$2 WHERE id=$1 RETURNING *",
        grant["id"], str(revoked_by)[:200] or "local-operator",
    )
    await record_event(conn, hunt_id=run["id"], request_id=grant["request_id"], grant_id=grant["id"],
                       event="revoked", actor=str(revoked_by)[:200] or "local-operator", source="revoke")
    return {"replayed": False, "grant": public_grant(updated)}


# How a parked action the agent never retried settles when its Hunt ends, by the outcome of the
# request it waited for (D42: a denied or expired request used to read "withdrawn").
PARKED_ENDINGS: Mapping[str, tuple[str, str]] = {
    "denied": ("permission_denied", "The person denied the permission this action waited for; it did not run."),
    "expired": ("permission_expired",
                "The permission request expired before anyone decided it; the action did not run."),
    "granted": ("permission_unused", "The permission was granted, but the action was not called again "
                "before the Hunt ended; it did not run."),
    "withdrawn": ("permission_withdrawn", "The Hunt ended before this permission was granted."),
}


async def settle_for_ended_hunt(conn: Any, hunt_id: Any, *, actor: str, source: str) -> None:
    """Withdraw pending requests and settle parked actions blocked, in the finishing transaction.

    A request past its expiry ends ``expired``, not withdrawn, and each parked action is labelled
    by the outcome of its own request.
    """
    from .permission_store import expire_due

    hunt_uuid = uuid.UUID(str(hunt_id))
    await expire_due(conn, hunt_uuid)
    rows = await conn.fetch(
        """UPDATE hunt_permission_requests SET status='withdrawn', decided_at=NOW()
           WHERE hunt_run_id=$1 AND status='pending' RETURNING id""",
        hunt_uuid,
    )
    for row in rows:
        await record_event(conn, hunt_id=hunt_uuid, request_id=row["id"], event="withdrawn",
                           actor=actor, source=source)
    # Every pending request was just withdrawn, so a parked action's request is granted,
    # denied, expired or withdrawn; an action whose request is gone reads as withdrawn.
    await conn.execute(
        """WITH ending AS (
               SELECT * FROM jsonb_to_recordset($2::jsonb) AS e(status text, code text, message text)
           )
           UPDATE hunt_actions a
           SET status='blocked', completed_at=NOW(),
               result_summary=COALESCE(a.result_summary, '{}'::jsonb) || COALESCE((
               SELECT jsonb_build_object('error', e.code, 'reason_code', e.code, 'message', e.message)
               FROM ending e
               WHERE e.status = COALESCE((
                   SELECT r.status FROM hunt_permission_requests r
                   WHERE r.hunt_run_id=a.hunt_run_id
                     AND r.id::text = a.result_summary->>'permission_request_id'
               ), 'withdrawn')), '{}'::jsonb)
           WHERE a.hunt_run_id=$1 AND a.status='awaiting_permission'""",
        hunt_uuid, json.dumps([
            {"status": status, "code": code, "message": message}
            for status, (code, message) in PARKED_ENDINGS.items()
        ]),
    )

__all__ = [
    "GrantRefused", "LEDGER_TO_BUDGET", "PARKED_ENDINGS", "apply_grant", "decide", "hunt_finished", "revoke_grant",
    "settle_for_ended_hunt", "standing_authorization", "try_preauthorized_grant", "withdraw_request",
]
