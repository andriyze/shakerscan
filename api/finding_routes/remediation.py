"""Fix guidance for a finding, from the scanner's remediation knowledge base.

The knowledge base matches by the exposure prover's class, then by the finding's type (the check
that produced it, a nuclei template id, a fixed catalog title, or the header it names), then by
title keywords. When none of those matches, the check's own remediation text kept in evidence is
the floor. The response says which (``matched_by``): a keyword match is general guidance for that
kind of issue, and ``producer`` is the text the check itself wrote.
"""

from __future__ import annotations

import json
import re
import shlex
from typing import Any
import urllib.parse

try:
    from scanner_tools.remediation_kb import match_remediation
except ImportError:  # host-side tests add api/ only; the runtime image has scanner_tools on /app
    import os
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scanner"))
    from scanner_tools.remediation_kb import match_remediation


_PLACEHOLDER_URL = re.compile(r"https?://example\.com(?P<path>/[^\s'\"|]*)?")
_PLACEHOLDER_HOST = re.compile(r"(?<![\w.-])example\.com\b")


def _finding_location(finding: dict[str, Any]) -> tuple[str, str, str]:
    """(url, origin, host) this finding is about, from its own fields; empty when unknown."""
    evidence = finding.get("evidence")
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except ValueError:
            evidence = {}
    evidence = evidence if isinstance(evidence, dict) else {}
    for candidate in (evidence.get("request_url"), evidence.get("matched_at"), finding.get("url"),
                      evidence.get("origin"), finding.get("target_url")):
        try:
            parsed = urllib.parse.urlsplit(str(candidate or ""))
        except ValueError:
            continue
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            origin = f"{parsed.scheme}://{parsed.netloc}"
            return urllib.parse.urlunsplit(parsed._replace(fragment="")), origin, parsed.hostname
    return "", "", ""


def localize_command(command: Any, finding: dict[str, Any]) -> str | None:
    """A knowledge-base check command rewritten for this finding's own URL, origin and host.

    The knowledge base writes ``https://example.com/<path>``; copied as is it checks nothing. A
    placeholder with a path becomes the finding's URL (the path the finding is about), one without
    a path becomes its origin, and a bare host (``dig``) its host. Values are shell-quoted.
    """
    if not isinstance(command, str) or not command:
        return None
    url, origin, host = _finding_location(finding)
    if not url:
        return command

    def replace(match: re.Match[str]) -> str:
        return shlex.quote(url if match.group("path") else origin)

    localized = _PLACEHOLDER_URL.sub(replace, command)
    return _PLACEHOLDER_HOST.sub(lambda _m: shlex.quote(host), localized)


def finding_remediation(finding: dict[str, Any]) -> dict[str, Any] | None:
    """The guidance to show for ``finding``, or None when neither the knowledge base nor the check has any."""
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
        "verification": localize_command(entry.get("verification"), finding),
        "references": [str(link) for link in entry.get("documentation_links") or []],
        "effort": entry.get("effort"),
        "matched_by": matched_by,
    }
