"""Versioned metadata contracts. No secret or arbitrary execution fields."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = "authenticated-scan-profile/v1"
ASSURANCE_VERSION = "authentication-assurance/v1"
AuthenticationState = Literal["valid", "invalid", "expired", "unknown", "revoked", "unsupported"]
ReasonCode = Literal[
    "identity_confirmed", "expected_identity_missing", "unexpected_identity",
    "unexpected_role", "login_redirect", "destination_rejected", "credential_expired",
    "credential_revoked", "credential_changed", "profile_changed", "profile_disabled",
    "validation_timeout", "validation_unavailable", "validation_not_supported",
    "validation_stale", "application_error", "access_denied", "invalid_response",
    "legacy_unverified", "not_validated", "process_restarted", "authentication_gap",
    "approval_unavailable", "validation_cancelled", "worker_unavailable",
    "insecure_transport_not_approved",
    "validation_pending",
]


def exact_origin(value: str) -> str:
    """Origin equality includes scheme and effective port; reject ambiguous URLs."""
    if any(ord(c) <= 32 for c in value) or "\\" in value:
        raise ValueError("invalid credential destination")
    try:
        parsed = urlsplit(value)
        port = parsed.port
        host = (parsed.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid credential destination") from exc
    if parsed.scheme not in {"https", "http"} or not host or parsed.username is not None or parsed.password is not None:
        raise ValueError("credential destination must be an HTTP(S) origin without user information")
    display = f"[{host}]" if ":" in host else host
    if port is not None and port != (443 if parsed.scheme == "https" else 80):
        display += f":{port}"
    return f"{parsed.scheme}://{display}"


class MetadataModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class ValidationPolicy(MetadataModel):
    # Owner-reviewed path, never a whole URL, query string, script, or login flow.
    path: str = Field(min_length=1, max_length=512)
    identity_field: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
    expected_identity: str = Field(min_length=1, max_length=120)
    role_field: str | None = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
    expected_role: str | None = Field(default=None, min_length=1, max_length=120)
    freshness_seconds: int = Field(default=300, ge=30, le=900, strict=True)
    timeout_seconds: int = Field(default=5, ge=1, le=10, strict=True)
    owner_confirmed_read_only: Literal[True]

    @field_validator("path")
    @classmethod
    def read_only_path(cls, value: str) -> str:
        if (not value.startswith("/") or value.startswith("//") or
                any(c in value for c in "?#\\%") or any(ord(c) <= 32 for c in value) or
                any(segment in {".", ".."} for segment in value.split("/"))):
            raise ValueError("health path must be an absolute path without query, fragment, or escapes")
        return value

    @model_validator(mode="after")
    def role_pair(self):
        if (self.role_field is None) != (self.expected_role is None):
            raise ValueError("role field and expected role must be configured together")
        if self.role_field == self.identity_field:
            raise ValueError("identity and role fields must differ")
        return self


class ProfileConfiguration(MetadataModel):
    schema_version: Literal["authenticated-scan-profile/v1"] = SCHEMA_VERSION
    target_id: UUID
    credential_reference: UUID
    display_name: str = Field(min_length=1, max_length=120)
    environment_label: str = Field(min_length=1, max_length=80)
    declared_role: str | None = Field(default=None, max_length=120)
    # One reviewed origin in v1. IdP cross-origin sign-in remains unsupported.
    credential_destinations: list[str] = Field(min_length=1, max_length=1)
    validation_policy: ValidationPolicy
    lifecycle_state: Literal["draft", "ready", "disabled", "archived"] = "draft"

    @field_validator("credential_destinations")
    @classmethod
    def origins(cls, values: list[str]) -> list[str]:
        result = []
        for value in values:
            parsed = urlsplit(value)
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                raise ValueError("credential destination must contain only an origin")
            result.append(exact_origin(value))
        return result

    @field_validator("display_name", "environment_label", "declared_role")
    @classmethod
    def labels(cls, value: str | None) -> str | None:
        if value is not None and (not value.strip() or any(ord(c) < 32 for c in value)):
            raise ValueError("metadata labels must be nonempty printable text")
        return value.strip() if value is not None else None

    def digest(self, credential_version: int, credential_record_version: int) -> str:
        payload = {**self.model_dump(mode="json"), "credential_version": credential_version,
                   "credential_record_version": credential_record_version}
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class ProfileWrite(MetadataModel):
    configuration: ProfileConfiguration
    expected_revision: int = Field(ge=0, strict=True)
    reviewed: Literal[True]


class ValidationRequest(MetadataModel):
    expected_revision: int = Field(gt=0, strict=True)
    approval_receipt_id: UUID
    reviewed: Literal[True]
    allow_insecure_transport: bool = False


class ValidationRecord(MetadataModel):
    schema_version: Literal["authentication-assurance/v1"] = ASSURANCE_VERSION
    validation_id: UUID
    request_id: UUID | None = None
    profile_id: UUID
    revision: int = Field(gt=0, strict=True)
    credential_version: int = Field(gt=0, strict=True)
    credential_record_version: int = Field(gt=0, strict=True)
    configuration_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    state: AuthenticationState
    reason_code: ReasonCode
    checked_at: datetime
    valid_until: datetime | None = None
    # A match bit, not the application-provided identity or response content.
    identity_matched: bool = False
    role_matched: bool | None = None
    evidence_reference: UUID | None = None
    process_generation: UUID

    @model_validator(mode="after")
    def truthful_validity(self):
        if self.checked_at.tzinfo is None or (self.valid_until and self.valid_until.tzinfo is None):
            raise ValueError("validation timestamps must have timezones")
        if self.state == "valid":
            if (self.reason_code != "identity_confirmed" or not self.identity_matched or
                    self.role_matched is False or not self.valid_until or self.valid_until <= self.checked_at):
                raise ValueError("valid assurance requires positive identity evidence and a freshness horizon")
        elif self.valid_until is not None or self.identity_matched or self.role_matched is not None:
            raise ValueError("unconfirmed assurance cannot carry positive identity evidence")
        return self
