"""Hunt start: credential references, start bounds, and the permissions they record.

Credential references must name credentials attached to the target (the one attached list). A
reference to another target's credential is admitted only when the person's own start bounds
(``allow: credential.use:<targets>``) cover its home target and the credential-grant kind rules
pass; the Hunt then records a pre-authorized ``credential.use`` request and grant for it in the
start transaction, and no binding is created.

``allow`` bounds are recorded as the starting person's (``allow_asserted_by``, which the
Enterprise gateway sets after step-up; ``local`` on OSS). ``proposed_allow`` bounds, which the MCP
start tool sends for the agent, become one pending ``preauthorization`` request: the agent cannot
pre-authorize itself.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
import uuid

from fastapi import HTTPException

from .credential_uses import CREDENTIAL_NOT_ATTACHED, HuntCredentialRefusal, unattached_reference_refusal
from .permission_bounds import parse_bounds
from .permission_reasons import KIND_CREDENTIAL_USE, KIND_PREAUTHORIZATION
from .permission_store import pending_summary, raise_request, record_preauthorization
from .permission_subjects import credential_kind_error
from .start_contract import HuntStartContract

try:
    from runtime.credential_refs import CredentialReferenceError, validate_generic_credential_references
    from runtime.credential_store import CredentialStoreError
except ModuleNotFoundError:
    from ..runtime.credential_refs import CredentialReferenceError, validate_generic_credential_references
    from ..runtime.credential_store import CredentialStoreError


def _reference_code(message: str) -> str | None:
    """The reason code for a start-time credential reference refusal (D36)."""
    if message.endswith("is inactive or expired"):
        return "credential_inactive"
    if message.endswith("is unavailable or bound to another target"):
        return CREDENTIAL_NOT_ATTACHED
    if "target kind does not match" in message or " is incompatible with " in message:
        return "credential_kind_unsupported"
    return None


def _owner(contract: HuntStartContract) -> tuple[str, str]:
    assertion = contract.allow_asserted_by or {}
    return str(assertion.get("person") or "local-operator"), str(assertion.get("proof") or "local")


async def _preauthorized_profile(
    conn: Any, store: Any, contract: HuntStartContract, target_id: uuid.UUID, profile_id: str,
) -> tuple[Any, str | None] | None:
    """Another target's credential the person's start bounds cover (with its home host), or None."""
    if not contract.allow:
        return None
    bounds = parse_bounds(contract.allow)
    if not bounds.credential_targets:
        return None
    try:
        profile = await store.get_profile(conn, profile_id=profile_id)
    except CredentialStoreError:
        return None
    home = await conn.fetchrow("SELECT url FROM targets WHERE id=$1", uuid.UUID(str(profile.target_id)))
    import urllib.parse
    home_host = urllib.parse.urlsplit(str((home or {}).get("url") or "")).hostname if home else None
    if not bounds.covers_credential(home_target_id=str(profile.target_id), home_host=home_host):
        return None
    subject = {"profile_id": profile.profile_id, "profile_version": profile.current_version}
    run = {"target_kind": contract.target_kind}
    if await credential_kind_error(conn, run, subject):
        return None
    return profile, home_host


async def validate_start_credentials(
    conn: Any, contract: HuntStartContract, target_id: uuid.UUID, store: Any,
) -> tuple[list[dict[str, Any]], list[Any]]:
    """The credential rows a Hunt starts with, and the pre-authorized foreign profiles among them."""
    if not contract.credential_refs:
        return [], []
    profiles = list(await store.list_profiles(
        conn, target_kind=contract.target_kind, target_id=target_id, include_inactive=True,
    ))
    preauthorized: list[Any] = []
    while (refusal := unattached_reference_refusal(contract.credential_refs, profiles)) is not None:
        covered = await _preauthorized_profile(conn, store, contract, target_id, str(refusal.profile_id or ""))
        if covered is None:
            raise HTTPException(status_code=422, detail=refusal.public_detail())
        profiles.append(covered[0])
        preauthorized.append(covered)
    try:
        generic, _missing = validate_generic_credential_references(
            contract.credential_refs, profiles, target_kind=contract.target_kind,
        )
    except CredentialReferenceError as exc:
        code = _reference_code(str(exc))
        if code is None:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        detail = HuntCredentialRefusal(code, str(exc)).public_detail() if code != "credential_inactive" else {
            "error": "hunt_credential_refused", "reason_code": code, "message": str(exc),
        }
        raise HTTPException(status_code=422, detail=detail) from exc
    return generic, preauthorized


async def record_start_permissions(
    conn: Any, run: Mapping[str, Any], contract: HuntStartContract, preauthorized: Sequence[Any],
) -> dict[str, Any]:
    """Record start bounds, the agent's proposal, and pre-authorized credential grants.

    Returns what the start response adds: the requests still pending for a person (the agent's
    proposed bounds), so the planner can tell the person which ``shakerscan approve`` to run.
    """
    if not (contract.allow or contract.proposed_allow or preauthorized):
        return {}
    from .permission_grants import try_preauthorized_grant

    person, proof = _owner(contract)
    async with conn.transaction():
        run = dict(await conn.fetchrow("SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE", run["id"]))
        if contract.allow:
            await record_preauthorization(
                conn, hunt_id=run["id"], bounds=parse_bounds(contract.allow), created_by=person, proof=proof,
            )
        for profile, home_host in preauthorized:
            request, _created = await raise_request(
                conn, run=run, kind=KIND_CREDENTIAL_USE, reason_code=CREDENTIAL_NOT_ATTACHED,
                subject={
                    "profile_id": profile.profile_id, "profile_version": profile.current_version,
                    "home_target_id": str(profile.target_id), "home_host": home_host,
                    "slot": profile.principal_slot,
                    "consuming_target_id": str(run.get("target_id") or run.get("device_target_id")),
                },
                actor=person, source="hunt_start",
            )
            if request is not None:
                await try_preauthorized_grant(conn, run, request)
        if contract.proposed_allow:
            bounds = parse_bounds(contract.proposed_allow)
            await raise_request(
                conn, run=run, kind=KIND_PREAUTHORIZATION, reason_code="preauthorization_proposed",
                subject={"allow": list(contract.proposed_allow), "bounds_digest": bounds.digest()},
                actor="agent", source="proposed_allow",
            )
    return {"pending_permission_requests": await pending_summary(conn, run["id"])}


__all__ = ["record_start_permissions", "validate_start_credentials"]
