"""The reviewed snapshot carried by a credential reference, and its binding check.

Extracted from ``snapshots`` so that ``evaluation`` can validate a pinned snapshot
without importing ``snapshots``, which imports ``evaluation`` for current_assurance.
That pair was an import cycle; this module depends only on models and store.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from .models import MetadataModel
from .store import ProfileConflict


class ScanProfileSnapshot(MetadataModel):
    schema_version: Literal["authenticated-scan-snapshot/v1"] = "authenticated-scan-snapshot/v1"
    profile_id: UUID
    revision: int = Field(gt=0, strict=True)
    target_id: UUID
    credential_version: int = Field(gt=0, strict=True)
    credential_record_version: int = Field(gt=0, strict=True)
    configuration_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    display_name: str
    environment_label: str
    declared_role: str | None
    credential_destinations: tuple[str, ...]
    setup_validation_id: UUID
    setup_evidence_reference: UUID
    setup_validated_at: datetime
    setup_valid_until: datetime
    process_generation: UUID
    # Setup evidence cannot assert the state of work that has not happened yet.
    assessment_authentication_state: Literal["unknown"] = "unknown"
    continuous_authentication_proven: Literal[False] = False
    secret_values_visible: Literal[False] = False


def bound_snapshot(credential_ref: dict) -> ScanProfileSnapshot | None:
    """Validate the optional reviewed metadata carried by the canonical credential ref."""
    if "authenticated_profile_snapshot" not in credential_ref:
        return None
    pinned = ScanProfileSnapshot.model_validate(credential_ref["authenticated_profile_snapshot"])
    if (str(pinned.profile_id) != str(credential_ref.get("profile_id")) or
            type(credential_ref.get("profile_version")) is not int or
            type(credential_ref.get("credential_record_version")) is not int or
            pinned.credential_version != credential_ref.get("profile_version") or
            pinned.credential_record_version != credential_ref.get("credential_record_version")):
        raise ProfileConflict("credential_changed")
    return pinned
