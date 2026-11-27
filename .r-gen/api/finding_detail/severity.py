"""The "why this severity" line and the stored-versus-current rule comparison.

Recompute policy: a stored finding keeps the severity it was persisted with. The read path never
rewrites the row (no migration, no startup backfill, no table lock); it states the current rule
next to the stored value, and the next Scan that observes the finding persists the current rule.
"""

from __future__ import annotations

from typing import Any, Mapping

try:
    from scan.severity_calibration import PRODUCER_REASONS, SEVERITY_BASIS_SCHEMA, current_rule_severity
except ModuleNotFoundError:  # package import in host-side tests
    from ..scan.severity_calibration import PRODUCER_REASONS, SEVERITY_BASIS_SCHEMA, current_rule_severity

from .common import record, text

_PROOF_NOTE = "Severity rates the impact if the issue is real; the proof state says whether it is proven."

POLICY = (
    "Stored findings keep the severity they were recorded with; the next Scan that observes this "
    "finding records the current rule."
)


def severity_section(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    stored = text(finding.get("severity"), 20).lower() or "info"
    basis = record(evidence.get("severity_basis"))
    out: dict[str, Any] = {"severity": stored, "policy": POLICY}
    if basis.get("schema") == SEVERITY_BASIS_SCHEMA:
        out.update({
            "reason": text(basis.get("reason"), 1200),
            "rule": text(basis.get("rule"), 120),
            "source": "recorded",
        })
        producer = text(basis.get("producer_severity"), 20)
        if producer and producer != stored:
            out["producer_severity"] = producer
    current = None
    try:
        current = current_rule_severity({**finding, "evidence": dict(evidence)})
    except Exception:  # a malformed historical row must not break the page
        current = None
    if current and current.get("severity") and current.get("severity") != stored:
        out["current_rule"] = {
            "severity": text(current.get("severity"), 20),
            "reason": text(current.get("reason"), 1200),
        }
    if not out.get("reason") and current:
        out.update({"reason": text(current.get("reason"), 1200), "rule": text(current.get("rule"), 120), "source": "current_rule"})
    if not out.get("reason"):
        reason = PRODUCER_REASONS.get(text(finding.get("tool"), 80))
        out.update({"reason": reason, "source": "producer"} if reason else {"source": "producer"})
    out["proof_note"] = _PROOF_NOTE
    return out


__all__ = ["POLICY", "severity_section"]
