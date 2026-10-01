"""The fingerprint a persisted finding row is keyed by.

Persistence keys a target's finding rows by this value, but a scan report keeps its findings
without it. A reader that must match a report row to its persisted row -- the deployment gate,
whose policy exceptions name the persisted row -- recomputes it here rather than comparing
display strings or relying on ``findings.scan_id``, which a later scan overwrites.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

try:
    from findings import templated_finding_identity
except ModuleNotFoundError as exc:  # package layout in host-side tests
    if exc.name != "findings":
        raise
    from scanner.findings import templated_finding_identity


def canonical_finding_fingerprint(finding: Mapping[str, Any]) -> str:
    """Endpoint findings get a templated, id/payload-insensitive identity; others keep the
    scanner ID, else a hash of title, tool, URL and CWE."""
    try:
        templated = templated_finding_identity(dict(finding))
    except Exception:
        templated = None
    if templated:
        return "t:" + hashlib.sha256(templated.encode()).hexdigest()[:16]
    return _untemplated_fingerprint(finding)


def _untemplated_fingerprint(finding: Mapping[str, Any]) -> str:
    """The identity every finding had before endpoint findings were templated: the scanner ID,
    else a hash of title, tool, URL and CWE. Rows persisted then still carry it."""
    scanner_id = finding.get("id", "")
    if scanner_id:
        return scanner_id
    key_string = "|".join(str(finding.get(field, "")) for field in ("title", "tool", "url", "cwe"))
    return hashlib.sha256(key_string.encode()).hexdigest()[:16]


def finding_identity_keys(finding: Mapping[str, Any]) -> tuple[str, ...]:
    """Every fingerprint a persisted row for this report finding can carry.

    The canonical fingerprint first; then, for an endpoint finding, the untemplated one its row
    was keyed by before endpoint identities were templated. A reader matching report findings to
    stored rows checks both, so neither a current row nor an older one is missed.
    """
    canonical = canonical_finding_fingerprint(finding)
    untemplated = _untemplated_fingerprint(finding)
    return (canonical,) if canonical == untemplated else (canonical, untemplated)


__all__ = ["canonical_finding_fingerprint", "finding_identity_keys"]
