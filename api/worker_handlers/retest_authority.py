"""A finding retest's authorization while it runs, as the worker applies it.

``process_finding_retest_job`` opens the watch (``open_retest_authority``) around both tiers of
the replay and, when the retest is stopped, records it with ``settle_retest_authority_stop``.
The watch itself is the device and AI run machinery (``scan.running_scan_authority``); what the
retest is bound to is ``scan.retest_authority``.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from typing import Any, Awaitable, Callable

try:
    from scan.authority_deadline import AUTHORITY_UNVERIFIED_AFTER_SECONDS, UNVERIFIED
    from scan.retest_authority import (
        admitted_authority_json,
        legacy_admitted_authority,
        parse_admitted_authority,
        retest_authority_stop_message,
    )
    from scan.running_scan_authority import ScanAuthorityStopped
    from retest_contract import settle_retest_subject_error
except ModuleNotFoundError:  # package import in host-side tests
    from ..scan.authority_deadline import AUTHORITY_UNVERIFIED_AFTER_SECONDS, UNVERIFIED
    from ..scan.retest_authority import (
        admitted_authority_json,
        legacy_admitted_authority,
        parse_admitted_authority,
        retest_authority_stop_message,
    )
    from ..scan.running_scan_authority import ScanAuthorityStopped
    from ..retest_contract import settle_retest_subject_error

STOP_REASONS = frozenset({"authorization_withdrawn", "authorization_unverified"})


def _get(row: Any, key: str) -> Any:
    try:
        return row[key]
    except (KeyError, TypeError, IndexError):
        return row.get(key) if hasattr(row, "get") else None


async def open_retest_authority(
    pool: Any, verification: Any, job_data: dict[str, Any], *,
    watch: Callable[..., Awaitable[Any]], record_event: Callable[[str], Any] | None,
) -> Any:
    """The running authority for one retest (``watch`` is ``running_retest_authority``).

    A retest admitted by this engine is bound to what it was admitted with
    (``finding_verifications.admitted_authority``). One queued by an earlier engine has no
    record: it is bound to the target's current authorization and the approval receipt its queue
    message named, the binding is kept on the row, and it is refused (``ScanAuthorityStopped``)
    when the target had an authorization when it was queued and has none now.
    """
    admitted = parse_admitted_authority(_get(verification, "admitted_authority"))
    if admitted is None:
        async def legacy() -> tuple[dict[str, Any], str | None]:
            async with pool.acquire() as conn:
                return await legacy_admitted_authority(
                    conn, target_id=_get(verification, "target_id"), queued_at=_get(verification, "created_at"),
                    approval_receipt_id=job_data.get("approval_receipt_id"))
        try:
            # Bounded and fail-closed like the check before any run: unknown is unverified.
            admitted, refusal = await asyncio.wait_for(legacy(), timeout=AUTHORITY_UNVERIFIED_AFTER_SECONDS)
        except Exception:
            raise ScanAuthorityStopped(UNVERIFIED, before_start=True, subject="Retest") from None
        if refusal is not None:
            raise ScanAuthorityStopped(refusal, before_start=True, subject="Retest")
        # Kept on the row, so a requeue (whose message names no approval) stays bound to it.
        async with pool.acquire() as conn:
            await conn.execute(
                """UPDATE finding_verifications SET admitted_authority=COALESCE(admitted_authority, $2::jsonb)
                    WHERE id=$1""", _get(verification, "id"), admitted_authority_json(admitted))
    return await watch(
        pool, admitted=admitted, record_event=record_event,
        # The URL the replay is sent to (run_finding_retest replays original_url first).
        destination=str(_get(verification, "original_url") or _get(verification, "target_url") or ""))


async def settle_retest_authority_stop(
    pool: Any, verification: Any, stop: dict[str, Any], *, attempt: int, mode: str,
    finish_campaign: Callable[..., Awaitable[Any]],
) -> None:
    """Record a retest stopped by its authorization: failed, no verdict, the stop named.

    Nothing the partial run observed is kept as a verdict: the finding records an attempted
    verification with verdict ``error`` (never fixed, still vulnerable or false positive), and a
    candidate is settled inconclusive, never refuted or verified. A fresh connection is used:
    the job's own may have been cancelled mid-query by the stop.
    """
    message = retest_authority_stop_message(stop)
    artifacts = {"authority_stop": stop, "started_at": str(_get(verification, "started_at") or ""),
                 "completed_at": datetime.now(timezone.utc).isoformat()}
    async with pool.acquire() as conn:
        subject = await conn.fetchrow(
            """UPDATE finding_verifications
                  SET status='failed', result_status='error', verdict='error', verdict_reason=$2,
                      proof=NULL, artifacts=$3::jsonb, confidence=NULL, attempt_count=$4,
                      attempts_exhausted=TRUE, retry_class='authorization', retryable=FALSE,
                      message=$2, error_message=$5, completed_at=NOW(), verification_mode=$6,
                      updated_at=NOW()
                WHERE id=$1
            RETURNING finding_id, candidate_id, campaign_id""",
            _get(verification, "id"), message, json.dumps(artifacts), attempt,
            f"{stop['stop_reason']}:{stop['reason_code']}", "ai_driven" if mode == "ai" else "deterministic")
        await settle_retest_subject_error(
            conn, subject, verification_id=_get(verification, "id"), error=str(stop["stop_reason"]))
        campaign_id = _get(subject, "campaign_id") if subject else None
        await finish_campaign(conn, str(campaign_id) if campaign_id else None, status="failed")


def retest_stop_status(stop: dict[str, Any], *, attempt: int) -> dict[str, str]:
    """The retest job status a stopped retest publishes."""
    return {
        "status": "failed", "result_status": "error", "verdict": "error",
        "stop_reason": str(stop["stop_reason"]), "reason_code": str(stop["reason_code"]),
        "retry_class": "authorization", "retryable": "false", "attempt": str(attempt),
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }


def ai_replay_authority_stop(result: dict[str, Any], error: str | None) -> tuple[dict[str, Any], str] | None:
    """``(stop, verdict reason)`` for an AI Gate replay stopped by its authorization, else None.

    A partial replay that did not reproduce the finding is not a fix (``running_scan_authority``).
    """
    metadata = result.get("scan_metadata") if isinstance(result.get("scan_metadata"), dict) else {}
    stop = metadata.get("authority_stop") if isinstance(metadata.get("authority_stop"), dict) else None
    if stop is None and metadata.get("stop_reason") not in STOP_REASONS:
        return None
    stop = {**(stop or {}), "stop_reason": metadata.get("stop_reason") or (stop or {}).get("stop_reason")}
    reason = retest_authority_stop_message({
        "reason_code": stop.get("reason_code"),
        # ScanAuthorityStopped names a refusal before any traffic in its error text.
        "before_start": "stopped before it started" in str(error or result.get("error") or ""),
    })
    return stop, reason


async def scan_stopped_by_authority(conn: Any, scan_id: Any) -> bool:
    """Whether a Scan's report names an authorization stop (its automatic retests are not queued)."""
    stop = await conn.fetchval(
        "SELECT result->'scan_metadata'->>'stop_reason' FROM scans WHERE id = $1::uuid", str(scan_id))
    return stop in STOP_REASONS
