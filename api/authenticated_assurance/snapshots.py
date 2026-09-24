"""Immutable, reviewed assessment metadata; never a credential or permission grant.

``ScanProfileSnapshot`` and ``bound_snapshot`` live in ``snapshot_binding`` and are
re-exported here: they are part of this module's public surface for every caller.
"""

from datetime import datetime, timezone
from copy import deepcopy
from typing import Literal
from uuid import UUID

from pydantic import Field

from .evaluation import current_assurance
from .snapshot_binding import ScanProfileSnapshot, bound_snapshot
from .models import MetadataModel, ProfileConfiguration, ValidationRecord, exact_origin
from .store import AssuranceStore, ProfileConflict


class ScanProfileSelection(MetadataModel):
    profile_id: UUID
    revision: int = Field(gt=0, strict=True)
    reviewed: Literal[True]


def attach_scan_snapshots(credential_refs: list[dict], snapshots: list[dict]) -> list[dict]:
    """Attach server-created snapshots without mutating the admitted references."""
    parsed = [ScanProfileSnapshot.model_validate(value) for value in snapshots]
    if (not 1 <= len(parsed) <= 2 or len({value.profile_id for value in parsed}) != len(parsed) or
            len(credential_refs) != len(parsed) or
            {str(value.profile_id) for value in parsed} != {str(ref.get("profile_id")) for ref in credential_refs}):
        raise ProfileConflict("invalid_profile_selection")
    refs = deepcopy(credential_refs)
    for ref in refs:
        pinned = next(value for value in parsed if str(value.profile_id) == str(ref.get("profile_id")))
        ref["authenticated_profile_snapshot"] = pinned.model_dump(mode="json")
        bound_snapshot(ref)
    return refs


def snapshot_authority_current(pinned: ScanProfileSnapshot, profile: dict | None, target_id: str) -> bool:
    """Metadata authority only; a current profile does not prove application health."""
    if not profile or str(pinned.target_id) != str(target_id):
        return False
    config = ProfileConfiguration.model_validate(profile["configuration"])
    return bool(
        config.target_id == pinned.target_id and config.credential_reference == pinned.profile_id and
        profile["current_profile_revision"] == pinned.revision and
        profile["configuration_digest"] == pinned.configuration_digest and
        config.digest(pinned.credential_version, pinned.credential_record_version) == pinned.configuration_digest and
        profile["current_lifecycle_state"] == "ready" and profile["target_active"] and
        profile["credential_active"] and (profile["credential_expires_at"] is None or
            profile["credential_expires_at"] > datetime.now(timezone.utc)) and
        profile["current_version"] == pinned.credential_version and
        profile["current_record_version"] == pinned.credential_record_version and
        tuple(config.credential_destinations) == pinned.credential_destinations and
        exact_origin(profile["current_target_url"]) in pinned.credential_destinations
    )


def snapshot_for_scan(profile: dict, selection: ScanProfileSelection, credential_ref: dict, *,
                      target_id: UUID, target_url: str, now: datetime, generation: UUID) -> ScanProfileSnapshot:
    config = ProfileConfiguration.model_validate(profile["configuration"])
    if (config.target_id != target_id or selection.profile_id != config.credential_reference or
            str(credential_ref.get("profile_id")) != str(selection.profile_id)):
        raise ProfileConflict("credential_target_mismatch")
    if profile["revision"] != selection.revision or profile["current_profile_revision"] != selection.revision:
        raise ProfileConflict("profile_changed")
    if config.lifecycle_state != "ready" or profile["current_lifecycle_state"] != "ready":
        raise ProfileConflict("profile_disabled")
    if not profile["target_active"] or config.credential_destinations != [exact_origin(target_url)] or exact_origin(profile["current_target_url"]) != exact_origin(target_url):
        raise ProfileConflict("destination_rejected")
    if (credential_ref.get("profile_version") != profile["credential_version"] or
            credential_ref.get("credential_record_version") != profile["credential_record_version"]):
        raise ProfileConflict("credential_changed")
    record = ValidationRecord.model_validate(profile["validation"]) if profile["validation"] else None
    state = current_assurance(record, revision=selection.revision, credential_version=profile["current_version"],
        credential_record_version=profile["current_record_version"], configuration_digest=profile["configuration_digest"],
        now=now, process_generation=generation, credential_active=profile["credential_active"],
        credential_expires_at=profile["credential_expires_at"], lifecycle_state=config.lifecycle_state)
    if state["state"] != "valid":
        raise ProfileConflict(state["reason_code"])
    if not record.evidence_reference:
        raise ProfileConflict("validation_unavailable")
    return ScanProfileSnapshot(profile_id=selection.profile_id, revision=selection.revision, target_id=target_id,
        credential_version=record.credential_version, credential_record_version=record.credential_record_version,
        configuration_digest=record.configuration_digest, display_name=config.display_name,
        environment_label=config.environment_label, declared_role=config.declared_role,
        credential_destinations=tuple(config.credential_destinations), setup_validation_id=record.validation_id,
        setup_evidence_reference=record.evidence_reference, setup_validated_at=record.checked_at,
        setup_valid_until=min(record.valid_until, profile["credential_expires_at"]) if profile["credential_expires_at"] else record.valid_until,
        process_generation=generation)


async def pin_scan_profiles(conn, selections: list[ScanProfileSelection], credential_refs: list[dict], *,
                            target_id: UUID, target_url: str, now: datetime, generation: UUID) -> list[dict]:
    """Pin assurance and credential metadata under the caller's admission transaction.

    The credential row lock is mandatory: without it, a concurrent credential rotation
    can commit between reading the canonical credential reference and creating the
    assessment snapshot. A missing credential row is therefore an admission failure.
    """
    ids = [selection.profile_id for selection in selections]
    if not 1 <= len(ids) <= 2 or len(set(ids)) != len(ids):
        raise ProfileConflict("invalid_profile_selection")
    if {str(value) for value in ids} != {str(ref.get("profile_id")) for ref in credential_refs}:
        raise ProfileConflict("credential_target_mismatch")
    snapshots = []
    for selection in sorted(selections, key=lambda value: str(value.profile_id)):
        locked = await conn.fetchrow("SELECT id FROM credential_profiles WHERE id=$1 FOR UPDATE", selection.profile_id)
        if not locked:
            raise ProfileConflict("credential_changed")
        profile = await AssuranceStore().get(conn, selection.profile_id, revision=selection.revision)
        if not profile:
            raise ProfileConflict("authenticated_profile_not_found")
        ref = next(value for value in credential_refs if str(value["profile_id"]) == str(selection.profile_id))
        snapshots.append(snapshot_for_scan(profile, selection, ref, target_id=target_id,
            target_url=target_url, now=now, generation=generation).model_dump(mode="json"))
    return snapshots
