"""Provenance gate for autonomous-agent findings.

Ported from T3MP3ST ``src/evidence/gate.ts`` (``gateLiveFinding``) and the
``EvidenceVault`` self-verification stripping (``src/evidence/index.ts:116-149``).

This is the **SUSPECTED-tier bar**: a finding is surfaced only if it is backed by
*real tool output* (``request``/``response``/``command``/``log``/``file``/``output``),
never by prose. A critical/high finding asserted with zero evidence of any kind is a
blocked overclaim. This bar is intentionally *weaker* than the VERIFIED tier
(``family_proof`` re-execution) — it buys "creativity without false trust". The model
picks the predicate and supplies the evidence; the server never lets the model itself
stamp a finding verified (see :func:`strip_self_verification`).

Kept dependency-free (stdlib only) so it is host-testable and importable flat in the
container (``import agent_provenance``).
"""
from __future__ import annotations

import time
from typing import Any

# Evidence "kinds" that count as genuine tool output — T:src/evidence/gate.ts:18.
TOOL_EVIDENCE_KINDS: frozenset[str] = frozenset(
    {"output", "command", "response", "request", "log", "file"}
)

# Columns/keys a caller (especially the model) must never be able to self-assert. The
# first two mirror T3MP3ST's EvidenceVault; the rest are OUR verified-tier signals, so a
# model debrief can never inject a promoted verdict — only the server moat may.
_GATE_OWNED_KEYS: tuple[str, ...] = (
    "verified_at",
    "verify_gate",
    "verified",
    "provenance",
    "last_verification_verdict",
    "last_verification_status",
    "last_verification_confidence",
    "promotable",
)


def _evidence_items(finding: dict[str, Any]) -> list[dict[str, Any]]:
    ev = finding.get("evidence")
    if isinstance(ev, list):
        return [e for e in ev if isinstance(e, dict)]
    return []


def gate_live_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Port of ``gateLiveFinding``.

    Returns ``{passed, provenance, reasons, checked_at}``. ``provenance`` is a 3-level
    ladder ``none < context < tool``. A finding *passes* (is suspected-worthy) only if it
    carries at least one tool-output evidence item with non-empty content.
    """
    evidence = _evidence_items(finding)
    tool_ev = [
        e
        for e in evidence
        if str(e.get("type", "")).strip() in TOOL_EVIDENCE_KINDS
        and str(e.get("content", "")).strip()
    ]

    reasons: list[str] = []
    if not tool_ev:  # RULE 1 — prose is not evidence
        reasons.append(
            "no tool-output evidence: a surfaced finding requires real tool output "
            "(request/response/command/log/file/output), not prose"
        )
    severity = str(finding.get("severity", "")).strip().lower()
    if severity in ("critical", "high") and not evidence:  # RULE 2 — overclaim
        reasons.append(f"{severity} severity asserted with zero evidence")

    provenance = "tool" if tool_ev else ("context" if evidence else "none")
    return {
        "passed": not reasons,
        "provenance": provenance,
        "reasons": reasons,
        "checked_at": int(time.time() * 1000),
    }


def strip_self_verification(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``payload`` with gate-owned verification fields removed.

    Verification state is gate-/moat-owned. A caller may update finding metadata,
    evidence, remediation, etc., but can never self-stamp a finding as verified. Port of
    ``EvidenceVault.updateFinding`` sanitization (T:src/evidence/index.ts:116-128),
    widened to also strip ShakerScan's promoted-verdict columns.
    """
    if not isinstance(payload, dict):
        return {}
    out = dict(payload)
    for key in _GATE_OWNED_KEYS:
        out.pop(key, None)
    return out
