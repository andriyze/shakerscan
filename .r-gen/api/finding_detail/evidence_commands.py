"""Commands in a finding's stored evidence, as a finding read serves them.

A finding keeps the evidence it was stored with, and a release before every target-chosen value
went through ``shell_word`` wrote its commands with the URL or host as typed. The finding page
offers ``verify_commands`` for copying, so a stored row could hand a person a command that runs
what the target chose. On read:

- ``verify_commands`` of an exposed file are rebuilt from the evidence's own URL and path (the
  way retest rows rebuild their replay commands from their inputs);
- ``verify_commands`` without those inputs, and a ``reproduction`` that does not have exactly the
  shape the scanner writes now, are moved to ``verify_commands_as_recorded`` and
  ``reproduction_as_recorded``: shown as recorded text, never offered for copying.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Any, MutableMapping

try:
    from scanner_tools.copy_commands import exposed_file_verify_commands, is_current_reproduction
except ModuleNotFoundError:  # package import in host-side tests
    from scanner.scanner_tools.copy_commands import exposed_file_verify_commands, is_current_reproduction


def _origin(url: str) -> str:
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return ""
    return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else ""


def _current_verify_commands(finding: MutableMapping[str, Any], evidence: dict[str, Any]) -> list[str] | None:
    url = evidence.get("url")
    if str(finding.get("tool") or "").lower() != "exposed_files" or not isinstance(url, str) or not url.strip():
        return None
    base_url = str(finding.get("target_url") or "").strip() or _origin(url)
    return exposed_file_verify_commands(url, str(evidence.get("path") or ""), base_url)


def current_evidence_commands(finding: MutableMapping[str, Any]) -> None:
    """Replace ``finding["evidence"]``'s stored commands with what a read may offer (see module)."""
    raw = finding.get("evidence")
    was_text = isinstance(raw, str)
    if was_text:
        try:
            evidence = json.loads(raw)
        except (TypeError, ValueError):
            return
    else:
        evidence = raw
    if not isinstance(evidence, dict):
        return
    evidence = dict(evidence)
    changed = False
    stored = evidence.get("verify_commands")
    if stored is not None:
        rebuilt = _current_verify_commands(finding, evidence)
        if rebuilt is not None:
            changed = changed or rebuilt != stored
            evidence["verify_commands"] = rebuilt
        else:
            evidence["verify_commands_as_recorded"] = evidence.pop("verify_commands")
            changed = True
    reproduction = evidence.get("reproduction")
    if reproduction is not None and not is_current_reproduction(reproduction):
        evidence["reproduction_as_recorded"] = evidence.pop("reproduction")
        changed = True
    if changed:
        finding["evidence"] = json.dumps(evidence) if was_text else evidence
