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
    from scan.running_scan_authority import ScanAuthorityStopped, retest_authority_receipts
    from retest_contract import infer_retest_inputs, settle_retest_subject_error
    from action_scope import receipt_scope_covers_host, url_host_for_scope
except ModuleNotFoundError:  # package import in host-side tests
    from ..scan.authority_deadline import AUTHORITY_UNVERIFIED_AFTER_SECONDS, UNVERIFIED
    from ..scan.retest_authority import (
        admitted_authority_json,
        legacy_admitted_authority,
        parse_admitted_authority,
        retest_authority_stop_message,
    )
    from ..scan.running_scan_authority import ScanAuthorityStopped, retest_authority_receipts
    from ..retest_contract import infer_retest_inputs, settle_retest_subject_error
    from ..action_scope import receipt_scope_covers_host, url_host_for_scope

STOP_REASONS = frozenset({"authorization_withdrawn", "authorization_unverified"})


def _get(row: Any, key: str) -> Any:
    try:
        return row[key]
    except (KeyError, TypeError, IndexError):
        return row.get(key) if hasattr(row, "get") else None


def retest_destination(verification: Any) -> str:
    """The URL a retest replays first, as ``run_finding_retest`` derives it."""
    inputs = infer_retest_inputs(dict(verification))
    return str(inputs.get("original_url") or inputs.get("target_url") or "")


async def _destination_allowed(pool: Any, admitted: dict[str, Any]) -> Callable[[str], bool] | None:
    """The hosts the replay may reach: the scope of the receipt that admitted its destination.

    Scope receipts are immutable, so it is read once; the running check covers the receipt.
    """
    receipts = retest_authority_receipts(admitted)
    if not receipts:
        return None
    covering = admitted.get("destination_receipt_id") or str(receipts[-1][0])
    async with pool.acquire() as conn:
        scope = await conn.fetchrow(
            """SELECT s.verdict, s.normalized_scope, s.allowed_hosts, s.allowed_root_domains
                 FROM approval_receipts a JOIN scope_receipts s ON s.id = a.scope_receipt_id
                WHERE a.id = $1::uuid""", str(covering))
    scope = dict(scope) if scope is not None and str(scope["verdict"] or "") != "blocked" else None

    def allowed(url: str) -> bool:
        host = url_host_for_scope(url)
        return bool(scope is not None and host and receipt_scope_covers_host(host, scope))
    return allowed


async def open_retest_authority(
    pool: Any, verification: Any, job_data: dict[str, Any], *,
    watch: Callable[..., Awaitable[Any]], record_event: Callable[[str], Any] | None,
) -> "RetestWatch":
    """The watch for one retest's replay (``watch`` builds its ``running_retest_authority``).

    A retest admitted by this engine is bound to what it was admitted with
    (``finding_verifications.admitted_authority``). One queued by an earlier engine has no
    record: it is bound to the target's current authorization and the approval its queue message
    (or its operation record) named, the binding is kept on the row, and it is refused
    (``ScanAuthorityStopped``) when an authorization the target had when it was queued has gone,
    or when its replay destination is not covered. The destination rule refuses traffic, and
    redirect hops, outside the scope that admitted the destination.
    """
    destination = retest_destination(verification)
    admitted = parse_admitted_authority(_get(verification, "admitted_authority"))
    if admitted is None:
        async def legacy() -> tuple[dict[str, Any], str | None]:
            async with pool.acquire() as conn:
                return await legacy_admitted_authority(
                    conn, target_id=_get(verification, "target_id"), queued_at=_get(verification, "created_at"),
                    approval_receipt_id=job_data.get("approval_receipt_id"), destination=destination,
                    verification_id=_get(verification, "id"))
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
    authority = await watch(pool, admitted=admitted, record_event=record_event, destination=destination)
    try:
        allowed = await asyncio.wait_for(_destination_allowed(pool, admitted),
                                         timeout=AUTHORITY_UNVERIFIED_AFTER_SECONDS)
    except Exception:
        raise ScanAuthorityStopped(UNVERIFIED, before_start=True, subject="Retest") from None
    return RetestWatch(authority, allowed)


class RetestWatch:
    """``async with`` around a retest's replay: its running authority, and the destination
    guard (``scanner_tools.destination_guard``) that refuses traffic and redirect hops off the
    scope that admitted the destination. ``refused`` lists the hosts refused."""

    def __init__(self, authority: Any, allowed: Callable[[str], bool] | None) -> None:
        from scanner_tools.destination_guard import destination_guard

        self.authority = authority
        self._scope = destination_guard(allowed)
        self._guard: Any = None

    @property
    def reason(self) -> str | None:
        return self.authority.reason

    @property
    def refused(self) -> list[str]:
        return list(self._guard.refused) if self._guard is not None else []

    @property
    def incidents(self) -> list[str]:
        return list(self._guard.incidents) if self._guard is not None else []

    async def __aenter__(self) -> "RetestWatch":
        self._guard = self._scope.__enter__()
        try:
            await self.authority.__aenter__()
        except BaseException:
            self._scope.__exit__(None, None, None)
            raise
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        try:
            return await self.authority.__aexit__(*exc)
        finally:
            self._scope.__exit__(None, None, None)


def cut_short_by_destination(result: dict[str, Any], watch: Any) -> dict[str, Any]:
    """A replay that had requests or redirects refused is inconclusive unless it proved the
    finding (proof from allowed traffic stands): it shows neither a fix nor a false positive.
    Failures of the browser egress proxy are kept on the artifacts (host and error class)."""
    refused, incidents = list(getattr(watch, "refused", []) or []), list(getattr(watch, "incidents", []) or [])
    if incidents:
        artifacts = result.get("artifacts") if isinstance(result.get("artifacts"), dict) else {}
        result = {**result, "artifacts": {**artifacts, "destination_guard_incidents": incidents}}
    if not refused or str(result.get("verdict") or "") == "exploited":
        return result
    reason = ("The replay was redirected or sent outside the approved scope and those requests were "
              "refused; no verdict.")
    artifacts = result.get("artifacts") if isinstance(result.get("artifacts"), dict) else {}
    return {**result, "status": "completed", "result_status": "inconclusive", "verdict": "inconclusive",
            "verdict_reason": reason, "message": reason, "confidence": None, "retryable": False,
            "artifacts": {**artifacts, "refused_destinations": sorted(set(refused))}}


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
    for delay in SETTLE_RETRY_DELAYS:
        try:
            await _settle_once(pool, verification, stop, attempt=attempt, mode=mode, finish_campaign=finish_campaign)
            return
        except Exception:
            # The database may be the reason for the stop; the stop is also published on the
            # retest job (``retest_stop_status``) so the stale-retest reaper settles it rather
            # than requeueing it, if every attempt here fails.
            if delay is None:
                raise
            await asyncio.sleep(delay)


SETTLE_RETRY_DELAYS = (1.0, 2.0, 4.0, None)


async def _settle_once(
    pool: Any, verification: Any, stop: dict[str, Any], *, attempt: int, mode: str,
    finish_campaign: Callable[..., Awaitable[Any]],
) -> None:
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
        "authority_stop": json.dumps(stop, sort_keys=True),
    }


def published_stop(job_status: Any) -> dict[str, Any] | None:
    """The stop a retest published on its job status before settling it (``retest_stop_status``)."""
    if not isinstance(job_status, dict):
        return None
    raw = job_status.get("authority_stop") or job_status.get(b"authority_stop")
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    try:
        stop = json.loads(raw) if raw else None
    except (TypeError, ValueError):
        return None
    if not isinstance(stop, dict) or stop.get("stop_reason") not in STOP_REASONS or not stop.get("reason_code"):
        return None
    return stop


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


async def record_retest_stop(
    pool: Any, redis: Any, job_key: str, verification: Any, stop: dict[str, Any], *, attempt: int,
    mode: str, finish_campaign: Callable[..., Awaitable[Any]],
) -> None:
    """Publish the stop on the retest job first, then settle it on the row (with retries)."""
    try:
        redis.hset(job_key, mapping=retest_stop_status(stop, attempt=attempt))
        redis.expire(job_key, 86400)
    except Exception:
        pass  # the row is the record; the job status only lets the reaper finish a failed settle
    await settle_retest_authority_stop(pool, verification, stop, attempt=attempt, mode=mode,
                                       finish_campaign=finish_campaign)


async def settle_published_stop(
    pool: Any, redis: Any, row: Any, *, finish_campaign: Callable[..., Awaitable[Any]],
) -> bool:
    """For the stale-retest reaper: settle a retest that published an authorization stop but
    whose settle failed (``record_retest_stop``), instead of requeueing it. True when settled."""
    job_id = str(_get(row, "job_id") or "")
    try:
        stop = published_stop(redis.hgetall(f"retest_job:{job_id}")) if job_id else None
    except Exception:
        stop = None
    if stop is None:
        return False
    await settle_retest_authority_stop(pool, row, stop, attempt=max(1, int(_get(row, "attempt_count") or 1)),
                                       mode="", finish_campaign=finish_campaign)
    return True
