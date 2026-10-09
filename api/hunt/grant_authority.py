"""A Hunt's effective authority: its starting policy plus every grant that is still live.

Capability and destination grants change ``policy_json``, which admission, the HTTP authority
helper and the workers read. The policy a grant produces is never undone by restoring what the
policy looked like before that grant: other grants may have been applied or revoked since, so
such a snapshot is not an inverse (R1, external release audit, 2026-10-09). Instead, every grant
and every revocation rebuilds the authority fields from two sources, under the Hunt row lock:

* the **baseline**: the Hunt's authority before its first grant, recorded once in
  ``hunt_permission_baselines`` (a trigger refuses changes), and
* the **live grants**: ``hunt_permission_grants`` rows with ``revoked_at IS NULL``, in the order
  they were granted. Each grant turns on only the fields it names (``fields_enabled``), adds only
  its capability, and authorizes only its own destination.

A field is on when the baseline has it or a live grant turns it on, so revoking one grant never
removes another live grant's authority and never brings back a revoked grant's. Budget
amendments and the target's approval receipt are separate sources with their own semantics and
are not touched here.

Hunts that were granted something before the baseline table existed (2.8.0) have no baseline
row; it is reconstructed once, deterministically, from their grant rows (``reconstruct_baseline``)
and then recorded, and ``repair_grant_authority`` does that for every unfinished Hunt at startup.
"""
from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from .permission_bounds import CAPABILITY_FLAGS
from .permission_reasons import KIND_CAPABILITY_ENABLE, KIND_TARGET_AUTHORIZE

logger = logging.getLogger(__name__)

# The policy fields a capability grant can turn on. mutation_allowed follows
# allow_state_changing_http, as it does at Hunt start.
AUTHORITY_FLAGS: tuple[str, ...] = (
    "active_testing", "allow_state_changing_http", "allow_oob_interactions", "network_discovery",
    "mutation_allowed",
)
POLICY_GRANT_KINDS = (KIND_CAPABILITY_ENABLE, KIND_TARGET_AUTHORIZE)
MAX_GRANTED_DESTINATIONS = 64
BASELINE_SCHEMA_VERSION = "hunt-permission-baseline/v1"
_FINISHED = ("completed", "cancelled", "failed")


def _json(value: Any, default: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return default
    if value is None:
        return default
    return dict(value) if isinstance(value, Mapping) else value


def _destinations(policy: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [dict(item) for item in policy.get("granted_destinations") or () if isinstance(item, Mapping)]


def grant_fields(grant: Mapping[str, Any]) -> tuple[str, ...]:
    """The policy fields one capability grant turns on.

    Recorded on the grant since R1 (``fields_enabled``); a 2.8.0 grant names only its flag, and
    the flag's fields are read from the same table that granted them.
    """
    effect = _json(grant.get("effect_json"), {})
    recorded = effect.get("fields_enabled")
    if isinstance(recorded, list):
        return tuple(str(field) for field in recorded if str(field) in AUTHORITY_FLAGS)
    flag = str(effect.get("flag") or _json(grant.get("subject_json"), {}).get("flag") or "")
    return tuple(CAPABILITY_FLAGS.get(flag, ()))


def baseline_from_policy(policy: Mapping[str, Any]) -> dict[str, Any]:
    """The baseline of a Hunt that has no grant yet: its current authority, as it is."""
    return {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "flags": {key: policy.get(key) is True for key in AUTHORITY_FLAGS},
        "allowed_capabilities": [str(name) for name in policy.get("allowed_capabilities") or ()],
        "granted_destinations": _destinations(policy),
    }


def reconstruct_baseline(policy: Mapping[str, Any], grants: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """The baseline of a Hunt granted something before baselines were recorded (2.8.0).

    Only grants changed these fields after start, so:

    * the flags are the ``policy_before`` the Hunt's first capability grant recorded under the
      row lock (nothing had changed them before it), or the current flags without such a grant;
    * the capabilities are the current list without every capability a grant ever added (a
      capability a grant added was not in the list then, and revocation removed only those);
    * the destinations are the current ones without any a destination grant added.
    """
    ordered = sorted(grants, key=lambda row: (str(row.get("created_at") or ""), str(row.get("id") or "")))
    capability_grants = [row for row in ordered if row.get("kind") == KIND_CAPABILITY_ENABLE]
    baseline = baseline_from_policy(policy)
    first = next((
        _json(row.get("effect_json"), {}).get("policy_before") for row in capability_grants
        if isinstance(_json(row.get("effect_json"), {}).get("policy_before"), Mapping)
    ), None)
    if first is not None:
        baseline["flags"] = {key: first.get(key) is True for key in AUTHORITY_FLAGS}
    added = {
        str(_json(row.get("effect_json"), {}).get("capability")) for row in capability_grants
        if _json(row.get("effect_json"), {}).get("capability_added")
    }
    baseline["allowed_capabilities"] = [name for name in baseline["allowed_capabilities"] if name not in added]
    granted_requests = {str(row.get("request_id")) for row in ordered if row.get("kind") == KIND_TARGET_AUTHORIZE}
    baseline["granted_destinations"] = [
        item for item in baseline["granted_destinations"] if str(item.get("request_id")) not in granted_requests
    ]
    return baseline


def effective_policy(
    policy: Mapping[str, Any], baseline: Mapping[str, Any], live_grants: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """``policy`` with its authority fields rebuilt from ``baseline`` and ``live_grants`` (in
    grant order). Every other field, including the approval receipt, is kept as it is."""
    flags = {key: bool((baseline.get("flags") or {}).get(key)) for key in AUTHORITY_FLAGS}
    capabilities = [str(name) for name in baseline.get("allowed_capabilities") or ()]
    destinations = [dict(item) for item in baseline.get("granted_destinations") or () if isinstance(item, Mapping)]
    for grant in live_grants:
        effect = _json(grant.get("effect_json"), {})
        if grant.get("kind") == KIND_CAPABILITY_ENABLE:
            for field in grant_fields(grant):
                flags[field] = True
            capability = str(effect.get("capability") or _json(grant.get("subject_json"), {}).get("capability") or "")
            if capability and capability not in capabilities:
                capabilities.append(capability)
        elif grant.get("kind") == KIND_TARGET_AUTHORIZE:
            entry = effect.get("destination")
            if isinstance(entry, Mapping) and not any(item.get("origin") == entry.get("origin") for item in destinations):
                destinations.append(dict(entry))
    if flags["allow_state_changing_http"]:
        flags["mutation_allowed"] = True
    result = dict(policy)
    result.update(flags)
    result["allowed_capabilities"] = capabilities
    result["granted_destinations"] = destinations[-MAX_GRANTED_DESTINATIONS:]
    return result


def authority_diff(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    """What a rebuild changed, for the audit event: field and capability names and origins only."""
    old_caps, new_caps = list(before.get("allowed_capabilities") or ()), list(after.get("allowed_capabilities") or ())
    old_origins = [str(item.get("origin")) for item in _destinations(before)]
    new_origins = [str(item.get("origin")) for item in _destinations(after)]
    return {
        "flags_on": [key for key in AUTHORITY_FLAGS if after.get(key) is True and before.get(key) is not True],
        "flags_off": [key for key in AUTHORITY_FLAGS if before.get(key) is True and after.get(key) is not True],
        "capabilities_added": [name for name in new_caps if name not in old_caps],
        "capabilities_removed": [name for name in old_caps if name not in new_caps],
        "destinations_added": [origin for origin in new_origins if origin not in old_origins],
        "destinations_removed": [origin for origin in old_origins if origin not in new_origins],
    }


async def _grant_rows(conn: Any, hunt_id: Any, *, live_only: bool) -> list[dict[str, Any]]:
    rows = await conn.fetch(
        """SELECT id, request_id, kind, subject_json, effect_json, created_at, revoked_at
           FROM hunt_permission_grants WHERE hunt_run_id=$1 AND kind = ANY($2::text[])"""
        + (" AND revoked_at IS NULL" if live_only else "") + " ORDER BY created_at, id",
        uuid.UUID(str(hunt_id)), list(POLICY_GRANT_KINDS),
    )
    return [dict(row) for row in rows]


async def hunt_baseline(conn: Any, run: Mapping[str, Any]) -> dict[str, Any]:
    """The Hunt's recorded baseline; recorded now (caller holds the Hunt row lock) if missing."""
    hunt_id = uuid.UUID(str(run["id"]))
    stored = await conn.fetchval("SELECT policy_json FROM hunt_permission_baselines WHERE hunt_run_id=$1", hunt_id)
    if stored is not None:
        return _json(stored, {})
    policy = _json(run.get("policy_json"), {})
    history = await _grant_rows(conn, hunt_id, live_only=False)
    baseline = reconstruct_baseline(policy, history) if history else baseline_from_policy(policy)
    await conn.execute(
        """INSERT INTO hunt_permission_baselines(hunt_run_id, policy_json, source)
           VALUES($1, $2::jsonb, $3) ON CONFLICT (hunt_run_id) DO NOTHING""",
        hunt_id, json.dumps(baseline, sort_keys=True, default=str), "reconstructed" if history else "first_grant",
    )
    return baseline


async def rebuild_authority(
    conn: Any, run: Mapping[str, Any], *, pending: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """The policy ``run`` must hold now: the baseline plus every live grant, then ``pending`` (a
    grant being applied in this transaction, not yet inserted). The caller holds the Hunt row
    lock, so no grant can be applied or revoked between this read and the caller's write."""
    baseline = await hunt_baseline(conn, run)
    live = await _grant_rows(conn, run["id"], live_only=True)
    return effective_policy(_json(run.get("policy_json"), {}), baseline, [*live, *pending])


async def repair_grant_authority(conn: Any) -> list[str]:
    """Rebuild the authority of every unfinished Hunt granted something before baselines existed.

    Idempotent: a Hunt is repaired once, when its baseline is recorded. Returns the Hunts whose
    stored policy changed (a 2.8.0 revocation had left authority that no live grant holds, or
    removed authority one still held).
    """
    candidates = await conn.fetch(
        """SELECT DISTINCT g.hunt_run_id FROM hunt_permission_grants g
           JOIN hunt_runs r ON r.id = g.hunt_run_id
           WHERE g.kind = ANY($1::text[]) AND r.completed_at IS NULL AND r.status <> ALL($2::text[])
             AND NOT EXISTS (SELECT 1 FROM hunt_permission_baselines b WHERE b.hunt_run_id = g.hunt_run_id)""",
        list(POLICY_GRANT_KINDS), list(_FINISHED),
    )
    changed: list[str] = []
    for candidate in candidates:
        async with conn.transaction():
            row = await conn.fetchrow("SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE", candidate["hunt_run_id"])
            if row is None:
                continue
            run = dict(row)
            before = _json(run.get("policy_json"), {})
            after = await rebuild_authority(conn, run)
            if after == before:
                continue
            context = _json(run.get("context_pack"), {})
            context["allowed_capabilities"] = list(after.get("allowed_capabilities") or [])
            await conn.execute(
                "UPDATE hunt_runs SET policy_json=$2::jsonb, context_pack=$3::jsonb, updated_at=NOW() WHERE id=$1",
                run["id"], json.dumps(after), json.dumps(context, default=str),
            )
            changed.append(str(run["id"]))
            logger.warning("Hunt %s: permission authority rebuilt from its live grants (%s)",
                           run["id"], json.dumps(authority_diff(before, after), sort_keys=True))
    return changed


__all__ = [
    "AUTHORITY_FLAGS", "authority_diff", "baseline_from_policy", "effective_policy", "grant_fields",
    "hunt_baseline", "rebuild_authority", "reconstruct_baseline", "repair_grant_authority",
]
