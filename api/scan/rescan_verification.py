"""A later Scan that ran the same passive check on the same URL and did not see a finding again.

An open sensitive-exposure or missing-header finding is re-checked by every Scan of its target that
runs the same check. When such a Scan read the finding's own URL (the exposure probe's read of the
recorded file, the baseline request that lacked the header), got an answer the check could judge,
and the check no longer matched, that Scan is the proof the finding was fixed: one completed
verification is recorded for it (``verification_mode`` ``scan_rescan``, verdict ``likely_fixed``,
the Scan and its coverage record as proof), as a retest that proved it fixed is recorded.

The engine never changes a finding's status here; whoever closes findings on a ``likely_fixed``
verification (the Enterprise gateway's retest-to-close) closes it. A Scan that sees the finding
again keeps it open as before (``save_findings``).

Not evidence, so nothing is recorded:

* the Scan did not read the finding's URL (another scope, a slice its wall cut off, a probe that
  timed out), or got no answer or a service's answer (408, 429, 502-504) there;
* the read still matched the finding's exposure class (it is reported again, or the soft-404 rule
  set it aside: either way not fixed);
* the baseline answered outside 200-399 (an error page is not the page the header was missing on),
  or as another principal than the finding's own observation;
* a finding the check cannot be repeated for exactly (``proof_retest`` gives no request: a binary
  signature, a GraphQL read, a masked value), or a family other than exposures and baseline or
  template missing headers.
"""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence
import uuid

try:
    from proof_retest import EXPOSURE_RETEST_CHECK, HEADER_RETEST_CHECK, PASSIVE_RETEST_CHECK_TYPES, proof_retest_request
except ModuleNotFoundError:  # package import in host-side tests
    from ..proof_retest import EXPOSURE_RETEST_CHECK, HEADER_RETEST_CHECK, PASSIVE_RETEST_CHECK_TYPES, proof_retest_request

VERIFICATION_MODE = "scan_rescan"
_TOOLS = ("shakerscan_exposure_probe", "http_baseline", "nuclei")
_UNAVAILABLE = frozenset({408, 429, 502, 503, 504})


def _json(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str) and value:
        try:
            parsed = json.loads(value)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def rescan_verdict(
    finding: Mapping[str, Any], coverage: Mapping[str, Any],
) -> dict[str, Any] | None:
    """The proof a Scan's ``check_coverage`` gives that this open finding is fixed, or None."""
    request, _gap = proof_retest_request(finding)
    if request is None or request.capability not in PASSIVE_RETEST_CHECK_TYPES:
        return None
    if request.capability == EXPOSURE_RETEST_CHECK:
        read = next((
            row for row in coverage.get("exposure") or ()
            if isinstance(row, Mapping) and row.get("url") == request.url
        ), None)
        status = read.get("response_status") if read else None
        if read is None or type(status) is not int or status in _UNAVAILABLE:
            return None
        if read.get("exposure_class") == request.expected:
            return None
        return {
            "check": request.capability, "request": f"GET {request.url}", "response_status": status,
            "expected_exposure_class": request.expected, "exposure_class": read.get("exposure_class"),
            "reason": "The Scan's exposure check read the same URL and no longer matched the exposure.",
        }
    if request.capability == HEADER_RETEST_CHECK:
        evidence = _json(finding.get("evidence"))
        principal = str(_json(evidence.get("observed_response")).get("principal") or "anonymous")
        line = f"GET {request.url}"
        seen = next((
            row for row in coverage.get("baseline_headers") or ()
            if isinstance(row, Mapping) and row.get("request_line") == line
            and str(row.get("principal") or "anonymous") == principal
        ), None)
        status = seen.get("response_status") if seen else None
        if seen is None or type(status) is not int or not 200 <= status < 400:
            return None
        if request.expected not in set(seen.get("present_headers") or ()):
            return None
        return {
            "check": request.capability, "request": line, "response_status": status,
            "header": request.expected, "header_present": True,
            "reason": "The Scan's baseline request to the same page now answered with the header.",
        }
    return None


def rescan_verdicts(
    findings: Sequence[Mapping[str, Any]], coverage: Mapping[str, Any],
) -> list[tuple[Mapping[str, Any], dict[str, Any]]]:
    """``(finding, proof)`` for each open finding the Scan's coverage shows fixed."""
    if not isinstance(coverage, Mapping) or coverage.get("schema_version") != "scan-check-coverage/v1":
        return []
    found = []
    for finding in findings:
        proof = rescan_verdict(finding, coverage)
        if proof is not None:
            found.append((finding, proof))
    return found


async def record_rescan_verifications(
    conn: Any, *, scan_id: str, target_id: str, report: Mapping[str, Any],
) -> int:
    """Record one ``scan_rescan`` verification per open finding of the target that this Scan's
    coverage shows fixed and that this Scan did not report again. Idempotent per Scan and finding.
    Never changes a finding's status. Returns how many were recorded."""
    coverage = report.get("check_coverage") if isinstance(report, Mapping) else None
    if not isinstance(coverage, Mapping):
        return 0
    scan_uuid, target_uuid = uuid.UUID(str(scan_id)), uuid.UUID(str(target_id))
    rows = await conn.fetch(
        """SELECT f.id, f.tool, f.url, f.evidence, f.title, f.severity, f.scan_id,
                  t.url AS target_url
           FROM findings f JOIN targets t ON t.id = f.target_id
           WHERE f.target_id = $1 AND f.status = 'active' AND f.tool = ANY($2::text[])
             AND f.scan_id IS DISTINCT FROM $3
             AND NOT EXISTS (
                 SELECT 1 FROM finding_verifications v
                 WHERE v.finding_id = f.id AND v.scan_id = $3 AND v.verification_mode = $4
             )""",
        target_uuid, list(_TOOLS), scan_uuid, VERIFICATION_MODE,
    )
    recorded = 0
    for finding, proof in rescan_verdicts([dict(row) for row in rows], coverage):
        request, _gap = proof_retest_request(finding)
        proof = {**proof, "scan_id": str(scan_uuid), "evidence_type": "scan_rescan_not_reproduced"}
        async with conn.transaction():
            verification_id = await conn.fetchval(
                """INSERT INTO finding_verifications (
                       finding_id, scan_id, target_id, requested_by, status, result_status,
                       verdict, verdict_reason, finding_type, target_url, original_url, method,
                       proof, artifacts, confidence, attempts_exhausted, message,
                       verification_mode, started_at, completed_at, updated_at
                   ) VALUES (
                       $1, $2, $3, 'scan', 'completed', 'likely_fixed', 'likely_fixed', $4, $5, $6,
                       $7, 'GET', $8::jsonb, $9::jsonb, 0.9, TRUE, $4, $10, NOW(), NOW(), NOW()
                   ) RETURNING id""",
                finding["id"], scan_uuid, target_uuid, proof["reason"],
                PASSIVE_RETEST_CHECK_TYPES[request.capability],
                str(finding.get("target_url") or request.url), request.url,
                json.dumps(proof), json.dumps({"check": request.capability, "source_scan_id": str(scan_uuid)}),
                VERIFICATION_MODE,
            )
            await conn.execute(
                """UPDATE findings SET last_verification_status = 'completed',
                       last_verification_verdict = 'likely_fixed',
                       last_verification_confidence = 0.9, last_verified_at = NOW(),
                       updated_at = NOW()
                   WHERE id = $1""",
                finding["id"],
            )
        recorded += 1 if verification_id else 0
    return recorded


async def verify_fixed_after_scan(
    pool: Any, *, scan_id: str, target_id: str, report: Mapping[str, Any], label: str = "",
) -> int:
    """The worker's call after a Scan's findings are saved: ``record_rescan_verifications`` in
    its own connection, logged, never raising (it never decides the Scan)."""
    try:
        async with pool.acquire() as conn:
            recorded = await record_rescan_verifications(
                conn, scan_id=scan_id, target_id=target_id, report=report,
            )
    except Exception as exc:  # noqa: BLE001
        print(f"[{label}] rescan verification error: {type(exc).__name__}: {exc}", flush=True)
        return 0
    if recorded:
        print(f"[{label}] {recorded} open finding(s) not seen again on a re-checked URL: "
              "verified fixed by this scan", flush=True)
    return recorded


__all__ = [
    "VERIFICATION_MODE", "record_rescan_verifications", "rescan_verdict", "rescan_verdicts",
    "verify_fixed_after_scan",
]
