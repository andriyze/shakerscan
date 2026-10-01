"""Fix guidance for a finding, from the scanner's remediation knowledge base.

The knowledge base matches by the exposure prover's class, then by the finding's type (the check
that produced it, a fixed catalog title, or the header it names), then by title keywords. The
response says which (``matched_by``): a keyword match is general guidance for that kind of issue.
"""

from __future__ import annotations

from typing import Any

try:
    from scanner_tools.remediation_kb import match_remediation
except ImportError:  # host-side tests add api/ only; the runtime image has scanner_tools on /app
    import os
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scanner"))
    from scanner_tools.remediation_kb import match_remediation


def finding_remediation(finding: dict[str, Any]) -> dict[str, Any] | None:
    """The guidance to show for ``finding``, or None when the knowledge base has none."""
    matched = match_remediation(finding)
    if not matched:
        return None
    entry, matched_by = matched
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
