"""Shared XSS execution evidence; proof is independent of impact assessment."""

from typing import Any


def apply_xss_execution_evidence(
    finding: dict[str, Any], *, location: Any, parameter: Any,
    signal: str, verifier: Any, dom_marker_executed: Any = None,
) -> None:
    finding["evidence"].setdefault("cvss", {
        "status": "not_assessed",
        "basis": "Execution proof alone does not establish privileges or confidentiality/integrity impact",
        "required_context": ["attacker_privileges", "victim_context", "confidentiality_impact", "integrity_impact"],
    })
    finding["evidence"]["execution_sink"] = {
        "location": str(location or "") or None,
        "parameter": str(parameter or "") or None,
        "signal": signal,
        "verifier": str(verifier or "") or None,
        "dom_marker_executed": dom_marker_executed,
    }
