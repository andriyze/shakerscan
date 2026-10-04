"""Scan-time proof may refresh a persisted row only on the same service."""
from typing import Any, Callable

try:
    from finding_service_identity import finding_provenance_key
except ModuleNotFoundError:
    from scanner.finding_service_identity import finding_provenance_key

from .finding_identity import finding_identity_keys


def scan_result_verification_overrides(
    result: dict[str, Any] | None, fields_for: Callable,
) -> dict[tuple, dict[str, Any]]:
    if not isinstance(result, dict):
        return {}
    overrides = {}
    for finding in result.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        fields = fields_for(finding)
        if fields:
            for fingerprint in finding_identity_keys(finding):
                overrides[(fingerprint, finding_provenance_key(finding))] = fields
    return overrides


def matching_verification_override(overrides: dict, finding: dict) -> dict:
    return overrides.get((str(finding.get("fingerprint") or ""), finding_provenance_key(finding))) or {}
