"""What a Hunt worker re-checks at dispatch for a destination a person authorized, and how a
refused dispatch settles (D39).

A ``target.authorize`` grant adds another host to the Hunt's authorized destinations
(``policy.granted_destinations``), pinned to the addresses that were resolved and scope-checked
when the request was raised. The Hunt's scope receipt names only the Hunt's own host, so checking
the granted host against it refused every live grant at dispatch (``scope_invalid``) once the Hunt
had a receipt bound; a Hunt without one skipped the check, which is why the pre-authorized path
looked healthy live. At dispatch a granted destination is therefore checked on its own authority
and the Hunt's on its own:

* the grant is still live: it is in the Hunt's policy with the same pinned addresses, and its row
  is not revoked;
* the destination still passes the hard limits: every pinned address is public (loopback,
  private, link-local, metadata and reserved addresses never are, whatever the deployment admits
  for registered targets) and the host's own scope evaluation is not blocked;
* the Hunt's approval and scope receipts are revalidated for the Hunt's host as for any other
  action, so a revoked, expired or replaced authorization still refuses it.

A pre-authorized grant and a person's live grant are the same grant row and the same policy entry,
so both are honoured identically.

A refusal at dispatch happens before the worker starts the reservation. It used to leave the
action and its hold ``reserved`` until stale recovery (about two minutes), which refused finishing
the Hunt meanwhile. ``settle_rejected_dispatch`` now releases the hold at once, under the Hunt row
lock and only while the reservation is still ``reserved`` (the durable proof that nothing started),
and settles the action ``blocked`` with ``dispatch_authority_rejected``.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
import json
import logging
from typing import Any
import urllib.parse
import uuid

try:
    from capabilities.http import granted_destination, resolve_hunt_http_origin
    from capabilities.network import CapabilityInputError
    from capabilities.replay import require_hunt_replay_authority
    from runtime.budgets import BUDGET_DIMENSIONS
    from runtime.hunt_http_contract import (
        HttpAuthorityWithdrawn,
        require_http_request_authority,
    )
    from runtime.models import TargetBinding
    from runtime.reservation_store import PostgresBudgetReservationStore
except ModuleNotFoundError:
    from ..capabilities.http import granted_destination, resolve_hunt_http_origin
    from ..capabilities.network import CapabilityInputError
    from ..capabilities.replay import require_hunt_replay_authority
    from ..runtime.budgets import BUDGET_DIMENSIONS
    from ..runtime.hunt_http_contract import (
        HttpAuthorityWithdrawn,
        require_http_request_authority,
    )
    from ..runtime.models import TargetBinding
    from ..runtime.reservation_store import PostgresBudgetReservationStore

from .permission_reasons import HuntRefusal

DISPATCH_REJECTED = "dispatch_authority_rejected"
logger = logging.getLogger(__name__)


class HuntDispatchRejected(CapabilityInputError):
    """The worker refused an admitted Hunt action before any traffic: its authority changed."""


class GrantedDestinationRecheck(HuntRefusal):
    """Admission met a granted destination before resolving it again: leave the Hunt lock,
    resolve (``granted_destination_recheck``) and admit again. Never answered to a caller."""

    def __init__(self, origin: Any) -> None:
        super().__init__("scope_destination_blocked", "the authorized destination is resolved again")
        self.recheck_origin = origin


def _json(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return dict(value) if isinstance(value, Mapping) else {}


def public_address(value: Any) -> bool:
    """A globally routable unicast address: the only kind a granted destination may use.

    The scope guard's classifier (``action_scope.public_unicast_address``), so a NAT64, mapped,
    6to4 or Teredo spelling of a private or metadata address, and the cloud platform-service
    addresses ``is_global`` accepts (168.63.129.16), are refused here as they are for targets.
    """
    try:
        from action_scope import public_unicast_address
    except ModuleNotFoundError:
        from ..action_scope import public_unicast_address
    return public_unicast_address(value)


def destination_hard_limit(granted: Mapping[str, Any], environment: str) -> str | None:
    """Why a granted destination may not be reached now, or None."""
    addresses = [str(item) for item in granted.get("addresses") or () if str(item)]
    if not addresses or not all(public_address(item) for item in addresses):
        return "it no longer resolves only to public addresses"
    try:
        from action_scope import evaluate_scope, receipt_to_dict
    except ModuleNotFoundError:
        from ..action_scope import evaluate_scope, receipt_to_dict
    url = f"{granted.get('scheme')}://{granted.get('host')}:{granted.get('port')}"
    receipt = receipt_to_dict(evaluate_scope(url, allowed_hosts=[str(granted.get("host"))], environment=environment))
    if receipt.get("verdict") == "blocked":
        return "its scope is blocked: " + ", ".join(str(item) for item in receipt.get("blocked_by") or ())
    return None


async def granted_destination_recheck(pool: Any, hunt_id: Any, origin: Any) -> str | None:
    """Before admission takes the Hunt lock: why a granted destination may not be admitted now.

    The retry of an action a person allowed resolves the destination again: every address must
    still be public, or the call is refused as a hard limit (``scope_destination_blocked``). The
    connection itself stays pinned to the addresses checked when the request was raised, so a
    later answer can never move it.
    """
    if origin is None:
        return None
    from . import permission_subjects

    async with pool.acquire() as conn:
        run = await conn.fetchrow("SELECT policy_json, context_pack FROM hunt_runs WHERE id=$1", uuid.UUID(str(hunt_id)))
    if run is None:
        return None
    granted = granted_destination(_json(run["policy_json"]), origin)
    if granted is None or granted.get("same_host"):
        return None
    environment = str((_json(run["context_pack"]).get("target") or {}).get("environment") or "production")
    host = str(granted.get("host"))
    try:
        addresses = [str(item) for item in await permission_subjects.resolve_destination_addresses(
            f"{granted.get('scheme')}://{host}:{granted.get('port')}", environment,
        )]
    except Exception:  # noqa: BLE001 - an unresolvable destination is a hard limit
        addresses = []
    reason = destination_hard_limit({**granted, "addresses": addresses}, environment)
    if reason is None:
        return None
    return (f"{host} cannot be reached: {reason}. Private, loopback, link-local, metadata and reserved "
            "destinations are never allowed, whoever authorized the host.")


EXECUTABLE_HUNT_STATUSES = frozenset({"active", "awaiting_planner", "budget_exhausted"})


def require_dispatchable(
    run: Mapping[str, Any], capability_name: str, label: str, *, requires_active_approval: bool = False,
) -> dict[str, Any]:
    """The Hunt's current policy, if this queued action may still run; otherwise a dispatch
    refusal, which settles the action blocked and releases its hold at once.

    Admission accepted the action; between then and the worker the Hunt may have ended or been
    cancelled, or the grant that put the capability on its allowlist (or gave it active approval)
    may have been revoked. Those are refusals of withdrawn authority, not worker faults, and
    used to strand the hold until stale recovery (R1 review).
    """
    status = str(run.get("status") or "")
    if status not in EXECUTABLE_HUNT_STATUSES:
        raise HuntDispatchRejected(
            f"Hunt action authority rejected at dispatch: the Hunt is {status} and no longer executable"
        )
    policy = _json(run.get("policy_json"))
    if capability_name not in {str(item) for item in policy.get("allowed_capabilities") or ()}:
        raise HuntDispatchRejected(
            f"Hunt action authority rejected at dispatch: {label} capability is outside the persisted Hunt allowlist"
        )
    if requires_active_approval and not (policy.get("active_testing") and policy.get("approval_receipt_id")):
        raise HuntDispatchRejected(
            f"Hunt action authority rejected at dispatch: {label} capability no longer has active approval"
        )
    return policy


def dispatch_replay_authority(capability_name: str, policy: Mapping[str, Any], *, replay_policy: str | None) -> bool:
    """``require_hunt_replay_authority`` at dispatch, on the Hunt's current policy, plus the
    persisted allowlist: a replay whose authority was withdrawn after admission (its
    ``active-replay`` or state-changing grant revoked) is a dispatch refusal, read as blocked."""
    try:
        active = require_hunt_replay_authority(capability_name, policy, replay_policy=replay_policy)
    except ValueError as exc:
        raise HuntDispatchRejected(f"Hunt action authority rejected at dispatch: {exc}") from exc
    if capability_name not in {str(item) for item in policy.get("allowed_capabilities") or ()}:
        raise HuntDispatchRejected(
            "Hunt action authority rejected at dispatch: replay capability is outside the persisted Hunt allowlist"
        )
    return active


def dispatch_http_request_authority(
    capability_input: Mapping[str, Any], policy: Mapping[str, Any], *, requested_budget: Mapping[str, Any],
) -> bool:
    """``require_http_request_authority`` at dispatch, on the Hunt's current policy: a write
    admission accepted whose authority was withdrawn since (its grant revoked, R1) is a dispatch
    refusal that releases the hold at once, not a worker fault left to stale recovery."""
    try:
        return require_http_request_authority(capability_input, policy, requested_budget=requested_budget)
    except HttpAuthorityWithdrawn as exc:
        raise HuntDispatchRejected(f"Hunt action authority rejected at dispatch: {exc}") from exc


def dispatch_http_target(target: TargetBinding, origin: Any, policy: Mapping[str, Any]) -> TargetBinding:
    """``resolve_hunt_http_origin`` at dispatch: an origin admission accepted and the worker no
    longer can (a grant revoked in between) is a dispatch refusal, not a worker fault."""
    try:
        return resolve_hunt_http_origin(target, origin, policy)
    except ValueError as exc:
        raise HuntDispatchRejected(f"Hunt action authority rejected at dispatch: {exc}") from exc


async def dispatch_scope_binding(
    conn: Any, *, run: Mapping[str, Any], target: TargetBinding, target_url: str,
) -> TargetBinding:
    """The binding the Hunt's own receipts are revalidated against at dispatch.

    The Hunt's host, and another service on it, is checked as it is. A granted destination is
    re-checked on its grant and the hard limits (module docstring) and then checked as the Hunt's
    host, because its authority for that host is the grant, not the Hunt's scope receipt. Any
    other host is returned unchanged, and the receipt check refuses it as before.
    """
    registered = (urllib.parse.urlsplit(str(target_url or "")).hostname or "").lower().rstrip(".")
    host = str(target.canonical_host or "").lower().rstrip(".")
    if not registered or host == registered:
        return target
    policy = _json(run.get("policy_json"))
    # The grant is for one origin (scheme, host and port) and the addresses pinned with it; the
    # binding a granted origin produces names exactly that origin (``granted_destination_target``).
    match = granted_destination(policy, target.allowed_origins[0]) if len(target.allowed_origins) == 1 else None
    granted = dict(match) if (
        match is not None and not match.get("same_host") and str(match.get("host") or "") == host
        and tuple(str(address) for address in match.get("addresses") or ()) == tuple(target.allowed_addresses)
    ) else None
    if granted is None:
        return target
    live = await conn.fetchval(
        """SELECT revoked_at IS NULL FROM hunt_permission_grants
           WHERE hunt_run_id=$1 AND request_id=$2 AND kind='target.authorize'""",
        uuid.UUID(str(run["id"])), uuid.UUID(str(granted.get("request_id"))),
    )
    if not live:
        raise HuntDispatchRejected(
            f"Hunt action authority rejected at dispatch: the grant for {host} is no longer live"
        )
    context = _json(run.get("context_pack"))
    environment = str((context.get("target") or {}).get("environment") or "production")
    reason = destination_hard_limit(granted, environment)
    if reason:
        raise HuntDispatchRejected(f"Hunt action authority rejected at dispatch: {host} {reason}")
    return replace(target, canonical_host=registered)


async def settle_rejected_dispatch(
    pool: Any, job_data: Mapping[str, Any], exc: BaseException, *, job_id: str, store: Any = None,
) -> dict[str, Any]:
    """Release a refused dispatch's hold and settle its action ``blocked``, in one transaction.

    Nothing is changed unless the reservation and the action are still ``reserved`` and match
    the job exactly; the result then says the budget was settled (released), so the API records
    the refusal instead of leaving the lease to the sweeper.

    It runs inside the worker's ``except HuntDispatchRejected`` handler, so it never raises: if
    the settlement itself fails (the database is unreachable, the row changed shape), the job
    still gets the contract result, unsettled, and stale recovery releases the lease as before.
    """
    message = str(exc)[:240]
    result: dict[str, Any] = {
        "job_id": job_id, "status": "failed", "error": f"contract:{message}",
        "durable_budget_settled": False,
    }
    try:
        return await _settle_rejected_dispatch(pool, job_data, message, result, store)
    except Exception as failure:  # noqa: BLE001 - never leave the job without a result
        logger.warning("Hunt dispatch refusal could not be settled at once (%s); stale recovery releases it",
                       type(failure).__name__)
        return result


async def settle_rejected_replay_dispatch(
    pool: Any, job_data: Mapping[str, Any], exc: BaseException, *, job_id: str, store: Any = None,
) -> dict[str, Any]:
    """``settle_rejected_dispatch`` for a request-collection replay job, whose worker creates its
    own hold: a refusal before that hold exists has nothing to release, and the action is
    settled ``blocked`` with the same dispatch-refusal summary. Never raises."""
    store = store if store is not None else PostgresBudgetReservationStore()
    data = {**dict(job_data), "budget_reservation_id": job_data.get("reservation_id")}
    result = await settle_rejected_dispatch(pool, data, exc, job_id=job_id, store=store)
    if result.get("durable_budget_settled"):
        return result
    message = str(exc)[:240]
    try:
        hunt_id = uuid.UUID(str(job_data.get("hunt_id") or ""))
        action_id = uuid.UUID(str(job_data.get("action_id") or ""))
        reservation_id = str(uuid.UUID(str(job_data.get("reservation_id") or "")))
        async with pool.acquire() as conn, conn.transaction():
            if await store.load(conn, reservation_id, for_update=True) is not None:
                return result  # a hold exists and was not settled above: leave it to its own path
            blocked = {
                "job_id": job_id, "status": "blocked", "ok": False, "error": DISPATCH_REJECTED,
                "reason_code": DISPATCH_REJECTED, "message": message, "refusal_stage": "dispatch",
                "execution_started": False, "durable_budget_settled": True, "reservation_id": None,
                "budget_consumed": {},
            }
            updated = await conn.execute(
                """UPDATE hunt_actions SET status='blocked', completed_at=NOW(), result_summary=$3::jsonb
                   WHERE id=$1 AND hunt_run_id=$2 AND status IN ('reserved','running')""",
                action_id, hunt_id, json.dumps({key: value for key, value in blocked.items() if key != "job_id"}),
            )
            return blocked if str(updated).endswith(" 1") else result
    except Exception as failure:  # noqa: BLE001 - never leave the job without a result
        logger.warning("Hunt replay dispatch refusal could not be settled (%s)", type(failure).__name__)
        return result


async def _settle_rejected_dispatch(
    pool: Any, job_data: Mapping[str, Any], message: str, result: dict[str, Any], store: Any = None,
) -> dict[str, Any]:
    try:
        hunt_id = uuid.UUID(str(job_data.get("hunt_id") or ""))
        action_id = uuid.UUID(str(job_data.get("action_id") or ""))
        reservation_id = str(uuid.UUID(str(job_data.get("budget_reservation_id") or "")))
    except ValueError:
        return result
    store = store if store is not None else PostgresBudgetReservationStore()
    async with pool.acquire() as conn:
        async with conn.transaction():
            run = await conn.fetchrow(
                "SELECT id, budget_used_json FROM hunt_runs WHERE id=$1 FOR UPDATE", hunt_id,
            )
            stored = await store.load(conn, reservation_id, for_update=True)
            action = await conn.fetchrow(
                "SELECT status FROM hunt_actions WHERE id=$1 AND hunt_run_id=$2 FOR UPDATE",
                action_id, hunt_id,
            )
            if (
                run is None or stored is None or action is None
                or stored.action_id != str(action_id)
                or stored.record.owner_kind != "hunt" or stored.record.owner_id != str(hunt_id)
                or stored.action_digest != str(job_data.get("action_digest") or "").lower()
                or stored.record.status != "reserved" or str(action["status"]) != "reserved"
            ):
                return result
            released = stored.record.release(proof_not_started=True, reason=DISPATCH_REJECTED)
            used = _json(run["budget_used_json"])
            reconciled = released.reconcile_consumed(
                {name: int(used.get(name) or 0) for name in BUDGET_DIMENSIONS}
            )
            await store.persist_terminal(
                conn, previous=stored, terminal=released, ledger_after_settlement=reconciled, receipt=None,
            )
            used.update(reconciled)
            await conn.execute(
                "UPDATE hunt_runs SET budget_used_json=$2, updated_at=NOW() WHERE id=$1",
                hunt_id, json.dumps(used),
            )
            result = {
                **result,
                "status": "blocked", "ok": False, "error": DISPATCH_REJECTED, "reason_code": DISPATCH_REJECTED,
                "message": message, "refusal_stage": "dispatch", "execution_started": False,
                "durable_budget_settled": True, "reservation_id": reservation_id,
                "budget_reservation_id": reservation_id, "budget_reservation_state": released.status,
                "receipt_id": None, "budget_consumed": dict(released.actual),
                "used_after_reconciliation": dict(reconciled),
            }
            await conn.execute(
                """UPDATE hunt_actions SET status='blocked', completed_at=NOW(), result_summary=$3::jsonb
                   WHERE id=$1 AND hunt_run_id=$2 AND status='reserved'""",
                action_id, hunt_id, json.dumps({key: value for key, value in result.items() if key != "job_id"}),
            )
    return result


__all__ = [
    "DISPATCH_REJECTED",
    "EXECUTABLE_HUNT_STATUSES",
    "GrantedDestinationRecheck",
    "HuntDispatchRejected",
    "destination_hard_limit",
    "dispatch_http_request_authority",
    "dispatch_http_target",
    "dispatch_replay_authority",
    "dispatch_scope_binding",
    "granted_destination_recheck",
    "public_address",
    "require_dispatchable",
    "settle_rejected_dispatch",
    "settle_rejected_replay_dispatch",
]
