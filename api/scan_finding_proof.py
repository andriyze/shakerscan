"""One proof vocabulary on the scan detail, the same one the findings API serves.

A scan report keeps the scanner's scan-time words (``proof_state: exploited`` or ``candidate``)
while ``GET /findings`` serves the canonical projection (``verified``, ``suspected``,
``unverified``) from ``finding_proof_fields``. The scan page read the report's words against the
canonical vocabulary and showed ten proven critical exposures as "0 proven, need verification".
The scan detail now carries the canonical projection on both its report findings and its persisted
rows; the scanner's own word stays available as ``scan_time_proof_state``.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable

try:
    from finding_service_identity import finding_provenance_key
except ModuleNotFoundError:
    from scanner.finding_service_identity import finding_provenance_key

ProofProjector = Callable[[dict[str, Any]], dict[str, Any]]
# Every fingerprint a persisted row for a report finding can carry (finding_identity_keys).
IdentityKeys = Callable[[dict[str, Any]], Iterable[str]]

_PROOF_KEYS = ("proof_state", "is_verified", "is_suspected")
# Read for the projection only; never returned on the scan detail.
_PROJECTION_INPUTS = ("evidence", "latest_retest_mode")

# The scan detail's persisted findings, with what the projection needs: the stored evidence
# and the latest retest's mode, selected exactly as the findings routes select them.
SCAN_DETAIL_FINDINGS_SQL = """
    SELECT f.id, f.fingerprint, f.title, f.severity, f.cvss_score, f.status, f.tool, f.url,
           f.first_seen_at, f.last_seen_at,
           f.last_verification_status, f.last_verification_verdict, f.last_verification_confidence,
           f.evidence,
           CASE WHEN latest_retest.verdict IS NOT NULL THEN latest_retest.verification_mode END
               AS latest_retest_mode
    FROM findings f
    LEFT JOIN LATERAL (
        SELECT verdict, verification_mode
        FROM finding_verifications
        WHERE finding_id = f.id
        ORDER BY created_at DESC, id DESC
        LIMIT 1
    ) latest_retest ON TRUE
    WHERE f.scan_id = $1
    ORDER BY
        CASE f.severity
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 4
            ELSE 5
        END
"""


def project_scan_finding_proof(
    report: Any,
    persisted_rows: list[dict[str, Any]],
    *,
    project: ProofProjector,
    identities: IdentityKeys,
) -> list[dict[str, Any]]:
    """Attach the canonical proof projection to ``report["findings"]`` and the persisted rows.

    Report findings are projected from their own scan-time evidence. A persisted row is
    projected from its stored evidence and latest retest (exactly as ``GET /findings`` does)
    and is also verified when the report finding it fingerprints to is verified, so a proof
    from this run and a proof from a deterministic retest both count and neither downgrades
    the other.

    A report finding names its row by the identity persistence stores it under: the canonical
    (templated) fingerprint, or the older untemplated one for a row stored before that.
    Matching by any other key misses the row and lets its weaker stored projection win.
    """
    report_findings = report.get("findings") if isinstance(report, dict) else None
    verified_fingerprints: set[tuple] = set()
    for finding in report_findings if isinstance(report_findings, list) else []:
        if not isinstance(finding, dict):
            continue
        keys = identities(finding)
        projection = project(finding)
        if "proof_state" in finding and "scan_time_proof_state" not in finding:
            finding["scan_time_proof_state"] = finding["proof_state"]
        finding.update({name: projection[name] for name in _PROOF_KEYS})
        if projection["is_verified"]:
            verified_fingerprints.update((key, finding_provenance_key(finding)) for key in keys if key)

    for row in persisted_rows:
        projection = project(row)
        if not projection["is_verified"] and (str(row.get("fingerprint") or ""), finding_provenance_key(row)) in verified_fingerprints:
            projection = {"proof_state": "verified", "is_verified": True, "is_suspected": False}
        row.update({name: projection[name] for name in _PROOF_KEYS})
        for name in _PROJECTION_INPUTS:
            row.pop(name, None)
    return persisted_rows
