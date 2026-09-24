"""Deterministic evaluation of bounded, worker-private health responses.

This module does not dispatch network work, resolve credentials, or grant authority.
Only a server-owned caller may supply an observation after normal runtime checks.
Response bytes and application-provided strings never enter its output.
"""

from datetime import datetime, timedelta
import json
from typing import Any, Mapping, Sequence
from uuid import UUID, uuid4

from .models import ProfileConfiguration, ValidationRecord, exact_origin

MAX_HEALTH_RESPONSE_BYTES = 16_384
_HEALTH_STATES = frozenset({"valid", "invalid", "unknown", "expired", "revoked"})
_HEALTH_REASON_CODES = frozenset({
    "identity_confirmed", "validation_unavailable", "validation_timeout",
    "destination_rejected", "login_redirect", "expected_identity_missing",
    "unexpected_identity", "unexpected_role", "access_denied", "application_error",
    "invalid_response", "credential_expired", "credential_revoked", "profile_disabled",
    "profile_changed", "credential_changed", "process_restarted", "validation_stale",
})


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate health response field")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise ValueError("non-JSON health response constant")


def evaluate_health_response(
    configuration: ProfileConfiguration, *, revision: int, credential_version: int,
    credential_record_version: int,
    checked_at: datetime, process_generation: UUID, status_code: int | None = None,
    body: bytes = b"", content_type: str = "", response_url: str | None = None,
    location: str | None = None, timed_out: bool = False, credential_expired: bool = False,
) -> ValidationRecord:
    """A 200 page or a 403 must never imply accepted or expired identity."""
    state, reason = "unknown", "validation_unavailable"
    identity_matched, role_matched = False, None
    if credential_expired:
        state, reason = "expired", "credential_expired"
    elif timed_out:
        reason = "validation_timeout"
    elif response_url is not None:
        expected_url = configuration.credential_destinations[0] + configuration.validation_policy.path
        try:
            destination_ok = exact_origin(response_url) in configuration.credential_destinations
        except ValueError:
            destination_ok = False
        if not destination_ok or response_url != expected_url:
            reason = "destination_rejected"
        elif status_code is not None and 300 <= status_code < 400:
            reason = "login_redirect"
            if location and not location.startswith("/"):
                try:
                    if exact_origin(location) not in configuration.credential_destinations:
                        reason = "destination_rejected"
                except ValueError:
                    reason = "destination_rejected"
            elif location and location.startswith("//"):
                reason = "destination_rejected"
        elif status_code == 401:
            state, reason = "invalid", "expected_identity_missing"
        elif status_code == 403:
            reason = "access_denied"
        elif status_code is not None and status_code >= 500:
            reason = "application_error"
        elif status_code == 200:
            reason = "invalid_response"
            if content_type.split(";", 1)[0].strip().lower() == "application/json" and len(body) <= MAX_HEALTH_RESPONSE_BYTES:
                try:
                    document = json.loads(body, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
                except (ValueError, UnicodeError, RecursionError):
                    document = None
                if isinstance(document, dict):
                    policy = configuration.validation_policy
                    actual = document.get(policy.identity_field)
                    if actual is None or actual == "":
                        state, reason = "invalid", "expected_identity_missing"
                    elif not isinstance(actual, str) or actual != policy.expected_identity:
                        state, reason = "invalid", "unexpected_identity"
                    elif policy.role_field and document.get(policy.role_field) != policy.expected_role:
                        state, reason = "invalid", "unexpected_role"
                    else:
                        state, reason = "valid", "identity_confirmed"
                        identity_matched = True
                        role_matched = True if policy.role_field else None
    return ValidationRecord(
        validation_id=uuid4(), profile_id=configuration.credential_reference,
        revision=revision, credential_version=credential_version,
        credential_record_version=credential_record_version,
        configuration_digest=configuration.digest(credential_version, credential_record_version), state=state,
        reason_code=reason, checked_at=checked_at,
        valid_until=checked_at + timedelta(seconds=configuration.validation_policy.freshness_seconds) if state == "valid" else None,
        identity_matched=identity_matched, role_matched=role_matched,
        process_generation=process_generation,
    )


def current_assurance(
    record: ValidationRecord | None, *, revision: int, credential_version: int,
    credential_record_version: int,
    configuration_digest: str, now: datetime, process_generation: UUID,
    credential_active: bool = True, credential_expires_at: datetime | None = None,
    lifecycle_state: str = "draft", destination_active: bool = True,
) -> dict[str, Any]:
    """Live metadata overrides stale validity, including after a process restart."""
    state, reason = "unknown", "not_validated"
    if not credential_active:
        state, reason = "revoked", "credential_revoked"
    elif credential_expires_at and credential_expires_at <= now:
        state, reason = "expired", "credential_expired"
    elif lifecycle_state in {"disabled", "archived"}:
        state, reason = "revoked", "profile_disabled"
    elif not destination_active:
        reason = "destination_rejected"
    elif record:
        if record.revision != revision or record.configuration_digest != configuration_digest:
            reason = "profile_changed"
        elif (record.credential_version != credential_version or
              record.credential_record_version != credential_record_version):
            reason = "credential_changed"
        elif record.process_generation != process_generation:
            reason = "process_restarted"
        elif record.checked_at > now:
            reason = "invalid_response"
        elif record.state == "valid" and (not record.valid_until or record.valid_until <= now):
            reason = "validation_stale"
        else:
            state, reason = record.state, record.reason_code
    return {
        "state": state, "reason_code": reason,
        "last_checked_at": record.checked_at.isoformat() if record else None,
        "last_validated_at": record.checked_at.isoformat() if record and record.state == "valid" else None,
        "continuous_authentication_proven": False,
        "secret_values_visible": False,
    }


def _authentication_requested(options: Mapping[str, Any]) -> bool:
    references = options.get("credential_profile_refs")
    if isinstance(references, list) and references:
        return True
    if options.get("managed_credential_profiles"):
        return True
    legacy_keys = (
        "auth_header", "auth_headers_json", "auth_cookies", "auth_token", "auth_user",
        "auth_scenario_json", "login_url", "login_username", "login_password",
        "login_extra_fields", "auto_auth", "disposable_login_credentials",
        "oauth_client_id", "oauth_client_secret", "oauth_token_url", "oauth_scope",
        "oauth_username", "oauth_password", "user2_cookies", "user2_header",
        "user2_login_url", "user2_login_username", "user2_login_password",
    )
    return any(options.get(key) not in (None, "", [], {}, False) for key in legacy_keys)


def scan_authentication_summary(
    options: Mapping[str, Any], *, interrupted_action_count: int = 0,
    health_observations: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Project frozen profile metadata and bounded Scan health samples conservatively."""
    references = options.get("credential_profile_refs") or []
    profiles = []
    for item in references if isinstance(references, list) else []:
        if not isinstance(item, Mapping):
            continue
        try:
            profile_id = str(UUID(str(item.get("profile_id") or item.get("id"))))
        except (TypeError, ValueError):
            continue
        version = item.get("profile_version", item.get("version"))
        public = {"credential_reference": profile_id,
                  "credential_version": version if type(version) is int and version > 0 else None}
        if "authenticated_profile_snapshot" in item:
            from .snapshot_binding import bound_snapshot
            try:
                snapshot = bound_snapshot(dict(item))
                if snapshot is not None:
                    public["assessment_snapshot"] = snapshot.model_dump(mode="json")
            except (ValueError, TypeError, AttributeError):
                pass
        profiles.append(public)

    timeline = []
    valid_count = 0
    uncertain_count = 0
    for raw in health_observations:
        if not isinstance(raw, Mapping) or raw.get("kind") != "authentication_health":
            continue
        record = raw.get("record")
        if not isinstance(record, Mapping):
            continue
        try:
            profile_id = str(UUID(str(record.get("profile_id"))))
        except (TypeError, ValueError):
            continue
        raw_state = record.get("state")
        raw_reason = record.get("reason_code")
        state = raw_state if isinstance(raw_state, str) and raw_state in _HEALTH_STATES else "unknown"
        reason = raw_reason if isinstance(raw_reason, str) and raw_reason in _HEALTH_REASON_CODES else "invalid_response"
        identity_matched = record.get("identity_matched") is True
        # Positive evidence is accepted only when all positive fields agree. A malformed
        # or forged historical receipt can therefore degrade assurance but never improve it.
        if state == "valid" and (reason != "identity_confirmed" or not identity_matched):
            state, reason, identity_matched = "unknown", "invalid_response", False
        if state == "valid":
            valid_count += 1
        else:
            uncertain_count += 1
        timeline.append({
            "credential_reference": profile_id,
            "state": state,
            "reason_code": reason,
            "checked_at": record.get("checked_at") if isinstance(record.get("checked_at"), str) else None,
            "valid_until": record.get("valid_until") if isinstance(record.get("valid_until"), str) else None,
            "identity_matched": identity_matched,
            "role_matched": record.get("role_matched") if type(record.get("role_matched")) is bool else None,
        })
    timeline.sort(key=lambda row: str(row.get("checked_at") or ""))

    interrupted = max(0, interrupted_action_count) if type(interrupted_action_count) is int else 0
    requested = bool(interrupted or _authentication_requested(options) or profiles or timeline)
    sampled = bool(timeline)
    gap = bool(interrupted or uncertain_count)
    if gap:
        state, reason, coverage = "unknown", "authentication_gap", "partial"
    elif sampled and valid_count:
        state, reason, coverage = "valid", "sampled_identity_confirmed", "sampled"
    elif any("assessment_snapshot" in profile for profile in profiles):
        state, reason, coverage = "unknown", "not_validated", "unverified"
    elif requested:
        state, reason, coverage = "unknown", "legacy_unverified", "unverified"
    else:
        state, reason, coverage = "unknown", "not_validated", "not_requested"

    limitations = []
    if interrupted:
        limitations.append("Credential authority became unavailable; affected actions were interrupted or blocked.")
    if sampled:
        limitations.append("Identity health was sampled at bounded points; continuous authentication is not proven.")
    elif requested:
        limitations.append("No recorded identity health timeline; credential use does not establish accepted identity.")
    return {
        "schema_version": "authentication-assurance/v1",
        "authentication_requested": requested,
        "state": state,
        "reason_code": reason,
        "profiles": profiles,
        "coverage": coverage,
        "health_sample_count": len(timeline),
        "valid_health_sample_count": valid_count,
        "uncertain_health_sample_count": uncertain_count,
        "health_timeline": timeline,
        "interrupted_action_count": interrupted,
        "continuous_authentication_proven": False,
        "finding_evidence_preserved": True,
        "limitations": limitations,
        "secret_values_visible": False,
    }
