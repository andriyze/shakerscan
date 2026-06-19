"""Helpers for preserving finding triage metadata in persisted evidence."""

from __future__ import annotations

import re
from typing import Any


TRIAGE_EVIDENCE_KEY = "triage"
TRIAGE_FIELDS_FROM_FINDING = (
    "precision_policy",
    "verification_reason",
    "suspected",
    "needs_verification",
    "verified",
    "confidence",
    "confidence_tier",
)

_REDACT_SENSITIVE_KEY_RE = re.compile(
    r"^(authorization|cookie|set[-_]?cookie|proxy-authorization|"
    r"x[-_]api[-_]?key|x[-_]auth[-_]token|api[-_]?key|"
    r"auth_header|auth_headers_json|auth_cookies|"
    r"user2_header|user2_cookies|login_password|password)$",
    re.IGNORECASE,
)
_REDACT_AUTH_VALUE_RE = re.compile(
    r"(Bearer\s+[A-Za-z0-9._~+/-]{8,}=*"
    r"|eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,})"
)


def redact_finding_evidence(value: Any) -> Any:
    """Strip live auth material from finding evidence before DB persistence."""
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, nested in value.items():
            if (
                isinstance(key, str)
                and _REDACT_SENSITIVE_KEY_RE.match(key)
                and nested not in (None, "", {}, [])
            ):
                out[key] = "[REDACTED]"
            else:
                out[key] = redact_finding_evidence(nested)
        return out
    if isinstance(value, list):
        return [redact_finding_evidence(item) for item in value]
    if isinstance(value, str):
        return _REDACT_AUTH_VALUE_RE.sub("[REDACTED]", value)
    return value


def build_evidence_with_triage(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Embed precision/verification fields into the evidence JSONB payload.

    These fields live at the top level of the in-memory finding dict but the
    `findings` table only persists `evidence`. Folding them under
    `evidence.triage` carries downgrade reasoning to the UI without a schema
    migration.
    """
    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        base: dict[str, Any] = dict(evidence)
    elif evidence is None:
        base = {}
    else:
        base = {"raw": evidence}

    triage: dict[str, Any] = {}
    for key in TRIAGE_FIELDS_FROM_FINDING:
        if key not in finding:
            continue
        value = finding[key]
        if value is None:
            continue
        triage[key] = value

    if not triage and not base:
        return None
    if triage:
        base[TRIAGE_EVIDENCE_KEY] = triage
    return base or None
