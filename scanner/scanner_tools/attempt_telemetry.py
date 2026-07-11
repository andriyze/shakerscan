"""Versioned, conservative normalization for scanner attempt telemetry."""

from __future__ import annotations

from typing import Any


ENDPOINT_ATTEMPT_SCHEMA_V1 = "active_endpoint_attempt_v1"
MASS_ASSIGNMENT_ATTEMPT_SCHEMA_V1 = "mass_assignment_attempt_v1"
JWT_PROBE_ATTEMPT_SCHEMA_V1 = "jwt_probe_attempt_v1"

DECLARED_ENDPOINT_ATTEMPT_SCHEMAS = frozenset({ENDPOINT_ATTEMPT_SCHEMA_V1})
DECLARED_REGISTRY_TELEMETRY_SCHEMAS = frozenset({
    ENDPOINT_ATTEMPT_SCHEMA_V1,
    MASS_ASSIGNMENT_ATTEMPT_SCHEMA_V1,
    JWT_PROBE_ATTEMPT_SCHEMA_V1,
})

ATTEMPT_STATUSES = frozenset({
    "started",
    "completed",
    "partial",
    "skipped",
    "blocked",
    "cancelled",
    "failed",
})


def _nonnegative_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def normalize_endpoint_attempt(
    attempt: Any,
    *,
    schema_version: str | None,
) -> dict[str, Any] | None:
    """Return a bounded v1 endpoint attempt, or reject an undeclared schema."""
    if schema_version not in DECLARED_ENDPOINT_ATTEMPT_SCHEMAS or not isinstance(attempt, dict):
        return None
    custom_endpoint = str(attempt.get("custom_endpoint") or "").strip()
    if not custom_endpoint:
        return None

    normalized = dict(attempt)
    normalized["schema_version"] = schema_version
    normalized["custom_endpoint"] = custom_endpoint[:4096]
    normalized["method"] = str(attempt.get("method") or "GET").upper()[:16]
    normalized["url"] = str(attempt.get("url") or "")[:4096] or None
    normalized["family"] = str(attempt.get("family") or "unknown").strip().lower()[:64]
    normalized["param_count"] = _nonnegative_int(attempt.get("param_count"))
    normalized["attempted_params_count"] = _nonnegative_int(attempt.get("attempted_params_count"))
    normalized["completed_params_count"] = min(
        normalized["attempted_params_count"],
        _nonnegative_int(attempt.get("completed_params_count")),
    )

    status = str(attempt.get("status") or "partial").strip().lower()
    if status not in ATTEMPT_STATUSES:
        status = "partial"
    if status == "completed" and (
        normalized["completed_params_count"] < normalized["attempted_params_count"]
        or attempt.get("error_summary")
        or attempt.get("budget_exhausted")
        or attempt.get("cancelled")
    ):
        status = "partial"
    normalized["status"] = status

    error_summary = attempt.get("error_summary")
    normalized["error_summary"] = str(error_summary)[:500] if error_summary else None
    normalized["skip_reason"] = str(attempt.get("skip_reason") or "")[:200] or None
    normalized["budget_exhausted_reason"] = (
        str(attempt.get("budget_exhausted_reason") or "")[:200] or None
    )
    normalized["cancelled"] = bool(
        attempt.get("cancelled")
        or status == "cancelled"
        or normalized["skip_reason"] == "cancelled"
        or normalized["budget_exhausted_reason"] == "cancelled"
    )
    normalized["proof_observed"] = bool(
        attempt.get("proof_observed")
        or attempt.get("proof_type")
        or attempt.get("proof_types")
    )
    return normalized


def endpoint_attempt_schema_from_report(report: Any) -> str | None:
    if not isinstance(report, dict):
        return None
    active = report.get("active_checks")
    if not isinstance(active, dict):
        return None
    version = str(active.get("endpoint_attempt_schema_version") or "").strip()
    return version if version in DECLARED_ENDPOINT_ATTEMPT_SCHEMAS else None


def normalize_registry_attempt_telemetry(
    telemetry: Any,
    *,
    expected_schema: str | None,
) -> dict[str, Any] | None:
    """Validate common receipt facts without treating unknown schemas as success."""
    if (
        expected_schema not in DECLARED_REGISTRY_TELEMETRY_SCHEMAS
        or not isinstance(telemetry, dict)
        or telemetry.get("schema_version") != expected_schema
    ):
        return None
    normalized = dict(telemetry)
    normalized["status"] = str(telemetry.get("status") or "partial").strip().lower()
    for key in (
        "endpoint_count",
        "method_count",
        "parameter_count",
        "attempted_count",
        "completed_count",
        "finding_count",
    ):
        normalized[key] = _nonnegative_int(telemetry.get(key))
    normalized["skip_reason"] = str(telemetry.get("skip_reason") or "")[:200] or None
    normalized["error_summary"] = str(telemetry.get("error_summary") or "")[:500] or None
    normalized["budget_exhausted_reason"] = (
        str(telemetry.get("budget_exhausted_reason") or "")[:200] or None
    )
    normalized["cancelled"] = bool(telemetry.get("cancelled"))
    normalized["proof_observed"] = bool(telemetry.get("proof_observed"))
    if normalized["status"] == "completed" and (
        normalized["completed_count"] < normalized["attempted_count"]
        or normalized["cancelled"]
        or normalized["error_summary"]
        or normalized["budget_exhausted_reason"]
    ):
        normalized["status"] = "partial"
    return normalized
