"""Helpers for preserving finding triage metadata in persisted evidence."""

from __future__ import annotations

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
