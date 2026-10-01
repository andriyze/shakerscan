"""Fix guidance for a finding, from the scanner's remediation knowledge base.

A finding the exposure prover classified (evidence.exposure_class) maps to guidance by class.
Anything else falls back to the knowledge base's title keywords, and says so: that match is a
best guess, not a classification.
"""

from __future__ import annotations

import json
import re
from typing import Any

try:
    from scanner_tools.remediation_kb import get_remediation_for_exposure_class, get_remediation_for_finding
except ImportError:  # host-side tests add api/ only; the runtime image has scanner_tools on /app
    import os
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scanner"))
    from scanner_tools.remediation_kb import get_remediation_for_exposure_class, get_remediation_for_finding


def _evidence(finding: dict[str, Any]) -> dict[str, Any]:
    value = finding.get("evidence")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


# "CORS allows credentialed cross-origin reads: /api/openapi.json" is about CORS; the path after
# the colon names where, and matching words in it gave the OpenAPI guidance.
_TRAILING_LOCATION = re.compile(r":\s+(?:/|https?://)\S*.*$")


def _title_subject(title: Any) -> str:
    return _TRAILING_LOCATION.sub("", str(title or "")).strip()


def finding_remediation(finding: dict[str, Any]) -> dict[str, Any] | None:
    """The guidance to show for ``finding``, or None when the knowledge base has none."""
    exposure_class = str(_evidence(finding).get("exposure_class") or "")
    entry = get_remediation_for_exposure_class(exposure_class) if exposure_class else None
    matched_by = "exposure_class"
    if entry is None:
        entry = get_remediation_for_finding({"title": _title_subject(finding.get("title")), "tool": finding.get("tool")})
        matched_by = "title"
    if not entry:
        return None
    examples = entry.get("code_examples") or {}
    return {
        "title": entry.get("title"),
        "description": entry.get("description"),
        "impact": entry.get("business_impact"),
        "steps": [str(step) for step in entry.get("remediation_steps") or []],
        "code_examples": [{"label": str(label), "code": str(code)} for label, code in examples.items()],
        "verification": entry.get("verification"),
        "references": [str(link) for link in entry.get("documentation_links") or []],
        "effort": entry.get("effort"),
        "matched_by": matched_by,
    }
