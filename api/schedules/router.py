"""Recurring scan schedule routes.

Extracted verbatim from the api.py monolith. Owns create/read/update/delete for
recurring daily and weekly normal scans and typed ASM coverage waves, including
next-run calculation and the fail-closed handling of retired evidence-retention
schedules.

The database pool is supplied by the composition root through
``configure_schedule_router``.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import random
import socket
from typing import Any, Callable, Optional
import urllib.parse
import uuid
from zoneinfo import ZoneInfo

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

try:
    from api_utils import LEGACY_SCAN_WRITE_FIELDS, _optional_uuid, _record_map, _uuid_or_400, utc_now, utc_now_iso
    from scan.contracts import raw_scan_authentication_keys, resolve_scan_contract
    from serialization import _decode_json_value, row_to_dict
except ModuleNotFoundError:  # package import in host-side tests
    from ..api_utils import LEGACY_SCAN_WRITE_FIELDS, _optional_uuid, _record_map, _uuid_or_400, utc_now, utc_now_iso
    from ..scan.contracts import raw_scan_authentication_keys, resolve_scan_contract
    from ..serialization import _decode_json_value, row_to_dict


router = APIRouter()

_pool_provider: Callable[[], Any] | None = None


def configure_schedule_router(pool_provider: Callable[[], Any]) -> None:
    """Bind the application database pool without importing the app module."""
    global _pool_provider
    _pool_provider = pool_provider


def _pool():
    pool = _pool_provider() if _pool_provider is not None else None
    if pool is None:
        raise HTTPException(status_code=503, detail="database pool is not ready")
    return pool

def _schedule_options_dict(value: Any) -> dict[str, Any]:
    decoded = _decode_json_value(value) or {}
    return decoded if isinstance(decoded, dict) else {}


def _normalize_schedule_kind(
    schedule_kind: Any = None,
    scan_options: Any = None,
    *,
    allow_legacy: bool = True,
) -> str:
    requested = str(schedule_kind or "").strip().lower()
    options = _schedule_options_dict(scan_options)
    legacy = str(options.get("kind") or "").strip().lower()

    if requested in ("", "scan", "normal"):
        requested = "normal_scan"
    if legacy in ("scan", "normal"):
        legacy = "normal_scan"

    if requested not in VALID_SCHEDULE_KINDS:
        raise ValueError(f"schedule_kind must be one of: {', '.join(sorted(VALID_SCHEDULE_KINDS))}")

    if allow_legacy and legacy:
        if legacy not in VALID_SCHEDULE_KINDS:
            raise ValueError(f"scan_options.kind must be one of: {', '.join(sorted(VALID_SCHEDULE_KINDS))}")
        if schedule_kind is not None and legacy != requested:
            raise ValueError("schedule_kind conflicts with scan_options.kind")
        return legacy

    return requested


def _schedule_kind_from_row(row: Any) -> str:
    data = _record_map(row)
    return _normalize_schedule_kind(
        data.get("schedule_kind"),
        data.get("scan_options"),
        allow_legacy=True,
    )


def calculate_next_run(frequency: str, day_of_week: int | None, time_of_day: str, timezone: str, jitter_minutes: int = 0) -> datetime:
    """Calculate the next UTC datetime for a scheduled run.

    Args:
        frequency: 'daily' or 'weekly'
        day_of_week: 0-6 (Monday-Sunday) for weekly schedules
        time_of_day: 'HH:MM' format
        timezone: IANA timezone string (e.g. 'UTC', 'America/New_York')
        jitter_minutes: Random jitter range (±minutes) to avoid thundering herd

    Returns:
        UTC datetime for the next scheduled run
    """
    try:
        tz = ZoneInfo(timezone)
    except (KeyError, Exception):
        tz = ZoneInfo('UTC')

    now_utc = utc_now()
    now_local = now_utc.replace(tzinfo=ZoneInfo('UTC')).astimezone(tz)

    hour, minute = 2, 0
    try:
        parts = time_of_day.split(':')
        hour, minute = int(parts[0]), int(parts[1])
    except (ValueError, IndexError):
        pass

    # Start with today at the specified time
    candidate = now_local.replace(hour=hour, minute=minute, second=0, microsecond=0)

    if frequency == 'weekly' and day_of_week is not None:
        # day_of_week: 0=Monday, 6=Sunday (Python weekday convention)
        current_weekday = now_local.weekday()
        days_ahead = day_of_week - current_weekday
        if days_ahead < 0 or (days_ahead == 0 and candidate <= now_local):
            days_ahead += 7
        candidate = candidate + timedelta(days=days_ahead)
    else:
        # Daily: if today's time has passed, schedule for tomorrow
        if candidate <= now_local:
            candidate = candidate + timedelta(days=1)

    # Apply jitter
    if jitter_minutes > 0:
        jitter = random.randint(-jitter_minutes, jitter_minutes)
        candidate = candidate + timedelta(minutes=jitter)

    # Convert to UTC
    return candidate.astimezone(ZoneInfo('UTC')).replace(tzinfo=None)


def _refuse_raw_schedule_authentication(scan_options: dict) -> None:
    """Refuse raw authentication in schedule options, as the direct Scan route does.

    An unvalidated options dict let a schedule carry the exact fields `POST /scans` refuses --
    bearer headers, cookies, login passwords, OAuth secrets, legacy managed profile references --
    and persist them verbatim in JSONB, outside the encrypted credential store and outside the
    approval and action-plan authority the canonical path enforces. This runs for every schedule
    kind, before any per-kind branch, because ASM waves carry scan options too.
    """
    raw_keys = raw_scan_authentication_keys(scan_options)
    if raw_keys:
        raise HTTPException(
            status_code=422,
            detail=(
                "scheduled Scans reject raw authentication ("
                + ", ".join(raw_keys)
                + "); create an encrypted credential profile and pass "
                "credential_profile_ids with a target-bound approval receipt"
            ),
        )


class ScheduleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str = Field(min_length=1)
    name: Optional[str] = None
    frequency: str  # daily, weekly
    day_of_week: Optional[int] = None  # 0-6 (Monday-Sunday)
    time_of_day: str = '02:00'  # HH:MM
    timezone: str = 'UTC'
    schedule_kind: str = 'normal_scan'
    scan_options: Optional[dict] = None
    jitter_minutes: int = Field(default=30, ge=0, le=1440)


class ScheduleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = None
    frequency: Optional[str] = None
    day_of_week: Optional[int] = None
    time_of_day: Optional[str] = None
    timezone: Optional[str] = None
    schedule_kind: Optional[str] = None
    scan_options: Optional[dict] = None
    jitter_minutes: Optional[int] = Field(default=None, ge=0, le=1440)
    is_active: Optional[bool] = None


class ScheduleTargetSafetyError(ValueError):
    """A recurring job cannot safely bind the target destination."""

    retryable = False


class ScheduleTargetResolutionError(ScheduleTargetSafetyError):
    """A recurring target could not be resolved due to a transient failure."""

    retryable = True


async def handle_schedule_target_failure(
    pool: Any,
    *,
    schedule_id: Any,
    error: ScheduleTargetSafetyError,
    now: datetime,
    retry_minutes: int = 15,
) -> None:
    """Persist a retry for resolver outages or disable an unsafe destination."""
    retry_at = (
        now + timedelta(minutes=max(1, int(retry_minutes)))
        if isinstance(error, ScheduleTargetResolutionError) else None
    )
    async with pool.acquire() as conn:
        if retry_at is not None:
            # A due row was read before DNS resolution began. The operator may
            # pause it while that lookup is in flight, so a transient failure
            # may postpone only a schedule that is still active; it must never
            # turn a later pause back into an active recurring job.
            await conn.execute(
                """UPDATE schedules
                   SET next_run_at=$1, updated_at=NOW()
                   WHERE id=$2 AND is_active=true""",
                retry_at, schedule_id,
            )
        else:
            await conn.execute(
                """UPDATE schedules
                   SET is_active=false, next_run_at=NULL, updated_at=NOW()
                   WHERE id=$1""",
                schedule_id,
            )
    disposition = "Retrying" if retry_at is not None else "Disabled"
    print(
        f"[scheduler] {disposition} schedule {str(schedule_id)[:8]}: {error}",
        flush=True,
    )


async def _default_schedule_resolver(host: str, port: int) -> list[Any]:
    loop = asyncio.get_running_loop()
    return await loop.getaddrinfo(
        host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM,
    )


async def validate_schedule_target_destination(
    url: str,
    *,
    resolver: Callable[[str, int], Any] | None = None,
) -> tuple[str, ...]:
    """Resolve a recurring target and require every destination to be public.

    Validation is repeated at dispatch because a hostname that was public when the
    schedule was saved may later resolve to a private or metadata address.
    """
    try:
        parsed = urllib.parse.urlsplit(str(url or "").strip())
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        if parsed.scheme.lower() not in {"http", "https"} or not host:
            raise ValueError
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except (TypeError, ValueError) as exc:
        raise ScheduleTargetSafetyError(
            "Scheduled targets must use a valid HTTP(S) URL."
        ) from exc

    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise ScheduleTargetSafetyError(
            "Scheduled targets must not resolve to a local or internal destination."
        )

    addresses: set[str] = set()
    try:
        addresses.add(str(ipaddress.ip_address(host)))
    except ValueError:
        try:
            records = await asyncio.wait_for(
                (resolver or _default_schedule_resolver)(host, port), timeout=5.0,
            )
        except (asyncio.TimeoutError, OSError, socket.gaierror) as exc:
            raise ScheduleTargetResolutionError(
                "Scheduled target DNS resolution failed."
            ) from exc
        for record in records or ():
            raw = record
            if isinstance(record, (tuple, list)) and len(record) >= 5:
                sockaddr = record[4]
                raw = sockaddr[0] if isinstance(sockaddr, (tuple, list)) else sockaddr
            try:
                addresses.add(str(ipaddress.ip_address(str(raw).split("%", 1)[0])))
            except ValueError:
                continue

    if not addresses:
        raise ScheduleTargetResolutionError(
            "Scheduled target did not resolve to a usable IP address."
        )
    unsafe = sorted(
        address for address in addresses if not ipaddress.ip_address(address).is_global
    )
    if unsafe:
        raise ScheduleTargetSafetyError(
            "Scheduled targets must not resolve to private, loopback, link-local, "
            "reserved, or metadata addresses."
        )
    return tuple(sorted(addresses, key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value)))))


async def _schedule_health_map_for_schedules(
    conn,
    schedules: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    candidates = [
        schedule
        for schedule in schedules
        if schedule.get("is_active", True)
        and _schedule_kind_from_row(schedule) == "normal_scan"
        and schedule.get("target_id")
    ]
    if not candidates:
        return {}

    target_ids: list[uuid.UUID] = []
    seen_target_ids: set[str] = set()
    for schedule in candidates:
        target_id = str(schedule.get("target_id"))
        if target_id in seen_target_ids:
            continue
        try:
            target_ids.append(uuid.UUID(target_id))
            seen_target_ids.add(target_id)
        except (TypeError, ValueError):
            continue
    if not target_ids:
        return {}

    recent_failures = await conn.fetch(
        """
        SELECT id, target_id, target_url, scan_type, error_message, created_at, completed_at
        FROM scans
        WHERE status = 'failed'
          AND target_id = ANY($1::uuid[])
          AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
          AND (scan_role IS NULL OR scan_role <> 'shard')
        ORDER BY created_at DESC
        LIMIT 500
        """,
        target_ids,
        SCHEDULE_HEALTH_LOOKBACK_DAYS,
    )

    failures_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in recent_failures:
        failure = row_to_dict(row)
        key = (str(failure.get("target_id")), str(failure.get("scan_type") or "quick"))
        failures_by_key.setdefault(key, []).append(failure)

    # Recovery detection: a schedule that has produced a non-failed terminal run more
    # recently than its failures has RECOVERED and must not be flagged. Without this, a
    # single outage keeps a green-since schedule marked "needs attention" for the whole
    # 14-day window.
    last_success_rows = await conn.fetch(
        """
        SELECT target_id, COALESCE(scan_type, 'quick') AS scan_type, MAX(created_at) AS last_success
        FROM scans
        WHERE status IN ('completed', 'partial', 'degraded')
          AND target_id = ANY($1::uuid[])
          AND (scan_role IS NULL OR scan_role <> 'shard')
        GROUP BY target_id, COALESCE(scan_type, 'quick')
        """,
        target_ids,
    )
    last_success_by_key: dict[tuple[str, str], Any] = {}
    for row in last_success_rows:
        record = row_to_dict(row)
        last_success_by_key[(str(record.get("target_id")), str(record.get("scan_type") or "quick"))] = record.get("last_success")

    health_by_schedule_id: dict[str, dict[str, Any]] = {}
    for schedule in candidates:
        key = (str(schedule.get("target_id")), str(schedule.get("scan_type") or "quick"))
        failures = failures_by_key.get(key, [])
        last_success = last_success_by_key.get(key)
        if last_success is not None:
            failures = [
                failure for failure in failures
                if failure.get("created_at") is not None and failure["created_at"] > last_success
            ]
        health = _schedule_health_from_failures(schedule, failures)
        if health and health.get("status") in {"attention", "warning"}:
            health_by_schedule_id[str(schedule.get("id"))] = health
    return health_by_schedule_id


@router.get("/schedules")
async def list_schedules(
    target_id: Optional[str] = None,
    is_active: Optional[bool] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    """List scan schedules."""
    async with _pool().acquire() as conn:
        query = """
            SELECT s.*, t.url as target_url, t.name as target_name
            FROM schedules s
            JOIN targets t ON s.target_id = t.id
            WHERE 1=1
        """
        params = []
        param_idx = 1

        if target_id:
            query += f" AND s.target_id = ${param_idx}"
            params.append(uuid.UUID(target_id))
            param_idx += 1

        if is_active is not None:
            query += f" AND s.is_active = ${param_idx}"
            params.append(is_active)
            param_idx += 1

        query += f" ORDER BY s.created_at DESC LIMIT ${param_idx} OFFSET ${param_idx + 1}"
        params.extend([limit, offset])

        rows = await conn.fetch(query, *params)
        schedules = [row_to_dict(r) for r in rows]
        try:
            health_map = await _schedule_health_map_for_schedules(conn, schedules)
            for schedule in schedules:
                health = health_map.get(str(schedule.get("id")))
                if health:
                    schedule["schedule_health"] = health
        except Exception:
            pass

    return {
        'schedules': schedules,
        'total': len(rows)
    }


@router.post("/schedules")
async def create_schedule(request: ScheduleCreate):
    """Create a new scan schedule."""
    try:
        kind_input = request.schedule_kind if "schedule_kind" in request.model_fields_set else None
        schedule_kind = _normalize_schedule_kind(kind_input, request.scan_options, allow_legacy=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    scan_options = _schedule_options_dict(request.scan_options)
    scan_options.pop("kind", None)
    if schedule_kind == "evidence_retention_sweep":
        raise HTTPException(
            status_code=400,
            detail=(
                "Scheduled evidence retention is no longer supported. "
                "Use Evidence cleanup to review and approve an exact target-scoped preview."
            ),
        )

    # Validate frequency
    if request.frequency not in ('daily', 'weekly'):
        raise HTTPException(status_code=400, detail="Frequency must be 'daily' or 'weekly'")

    # Validate time_of_day format
    try:
        parts = request.time_of_day.split(':')
        h, m = int(parts[0]), int(parts[1])
        if not (0 <= h <= 23 and 0 <= m <= 59):
            raise ValueError
    except (ValueError, IndexError):
        raise HTTPException(status_code=400, detail="time_of_day must be in HH:MM format (00:00 - 23:59)")

    # Validate day_of_week for weekly
    if request.frequency == 'weekly':
        if request.day_of_week is None:
            raise HTTPException(status_code=400, detail="day_of_week is required for weekly schedules (0=Monday, 6=Sunday)")
        if not (0 <= request.day_of_week <= 6):
            raise HTTPException(status_code=400, detail="day_of_week must be 0-6 (Monday-Sunday)")

    _refuse_raw_schedule_authentication(scan_options)

    if schedule_kind == "normal_scan":
        legacy_fields = sorted(LEGACY_SCAN_WRITE_FIELDS.intersection(scan_options))
        if legacy_fields:
            raise HTTPException(
                status_code=422,
                detail=(
                    "canonical Scan schedules reject legacy option authority: "
                    + ", ".join(legacy_fields)
                ),
            )
        try:
            resolve_scan_contract(
                budget_profile=scan_options.get("budget_profile"),
                policy=scan_options.get("policy"),
                advanced=scan_options.get("advanced"),
                approval_receipt_id=scan_options.get("approval_receipt_id"),
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    # Validate timezone
    try:
        ZoneInfo(request.timezone)
    except (KeyError, Exception):
        raise HTTPException(status_code=400, detail=f"Invalid timezone: {request.timezone}")

    async with _pool().acquire() as conn:
        # Verify target exists
        target_uuid = _uuid_or_400(request.target_id, "target id")
        target = await conn.fetchrow("SELECT id, url FROM targets WHERE id = $1", target_uuid)
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        try:
            await validate_schedule_target_destination(str(target["url"]))
        except ScheduleTargetSafetyError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        next_run = calculate_next_run(
            request.frequency,
            request.day_of_week,
            request.time_of_day,
            request.timezone,
            request.jitter_minutes
        )

        schedule_id = await conn.fetchval("""
            INSERT INTO schedules (
                target_id, name, frequency, day_of_week, time_of_day,
                timezone, jitter_minutes, schedule_kind, scan_type, scan_options,
                is_active, next_run_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true, $11)
            RETURNING id
        """,
            target_uuid,
            request.name,
            request.frequency,
            request.day_of_week,
            request.time_of_day,
            request.timezone,
            request.jitter_minutes,
            schedule_kind,
            "scan",
            json.dumps(scan_options),
            next_run
        )

    return {
        'id': str(schedule_id),
        'target_url': target['url'],
        'next_run_at': next_run.isoformat(),
        'status': 'created'
    }


@router.get("/schedules/{schedule_id}")
async def get_schedule(schedule_id: str):
    """Get schedule details."""
    async with _pool().acquire() as conn:
        schedule = await conn.fetchrow("""
            SELECT s.*, t.url as target_url, t.name as target_name
            FROM schedules s
            JOIN targets t ON s.target_id = t.id
            WHERE s.id = $1
        """, uuid.UUID(schedule_id))

        if not schedule:
            raise HTTPException(status_code=404, detail="Schedule not found")

    return row_to_dict(schedule)


@router.patch("/schedules/{schedule_id}")
async def update_schedule(schedule_id: str, request: ScheduleUpdate):
    """Update a schedule."""
    async with _pool().acquire() as conn:
        # Get existing schedule to check timing field changes
        existing = await conn.fetchrow(
            """SELECT s.*, t.url AS target_url
               FROM schedules s JOIN targets t ON t.id=s.target_id
               WHERE s.id=$1""",
            uuid.UUID(schedule_id),
        )
        if not existing:
            raise HTTPException(status_code=404, detail="Schedule not found")
        try:
            await validate_schedule_target_destination(str(existing["target_url"]))
        except ScheduleTargetSafetyError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        updates = []
        params = []
        param_idx = 1
        timing_changed = False

        if request.name is not None:
            updates.append(f"name = ${param_idx}")
            params.append(request.name)
            param_idx += 1

        if request.frequency is not None:
            if request.frequency not in ('daily', 'weekly'):
                raise HTTPException(status_code=400, detail="Frequency must be 'daily' or 'weekly'")
            updates.append(f"frequency = ${param_idx}")
            params.append(request.frequency)
            param_idx += 1
            timing_changed = True

        if request.day_of_week is not None:
            if not (0 <= request.day_of_week <= 6):
                raise HTTPException(status_code=400, detail="day_of_week must be 0-6")
            updates.append(f"day_of_week = ${param_idx}")
            params.append(request.day_of_week)
            param_idx += 1
            timing_changed = True

        if request.time_of_day is not None:
            try:
                parts = request.time_of_day.split(':')
                h, m = int(parts[0]), int(parts[1])
                if not (0 <= h <= 23 and 0 <= m <= 59):
                    raise ValueError
            except (ValueError, IndexError):
                raise HTTPException(status_code=400, detail="time_of_day must be HH:MM")
            updates.append(f"time_of_day = ${param_idx}")
            params.append(request.time_of_day)
            param_idx += 1
            timing_changed = True

        if request.timezone is not None:
            try:
                ZoneInfo(request.timezone)
            except (KeyError, Exception):
                raise HTTPException(status_code=400, detail=f"Invalid timezone: {request.timezone}")
            updates.append(f"timezone = ${param_idx}")
            params.append(request.timezone)
            param_idx += 1
            timing_changed = True

        explicit_kind_update = request.schedule_kind is not None
        legacy_kind_update = (
            request.scan_options is not None
            and isinstance(request.scan_options, dict)
            and "kind" in request.scan_options
        )
        normalized_schedule_kind: str | None = None
        if explicit_kind_update or legacy_kind_update:
            try:
                normalized_schedule_kind = _normalize_schedule_kind(
                    request.schedule_kind if explicit_kind_update else None,
                    request.scan_options if request.scan_options is not None else {},
                    allow_legacy=True,
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            if normalized_schedule_kind == "evidence_retention_sweep":
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Scheduled evidence retention is no longer supported. "
                        "Choose a scan or ASM schedule, or use Evidence cleanup interactively."
                    ),
                )
            updates.append(f"schedule_kind = ${param_idx}")
            params.append(normalized_schedule_kind)
            param_idx += 1

        effective_schedule_kind = normalized_schedule_kind or _schedule_kind_from_row(existing)

        if request.scan_options is not None:
            scan_options = _schedule_options_dict(request.scan_options)
            scan_options.pop("kind", None)
            _refuse_raw_schedule_authentication(scan_options)
            if effective_schedule_kind == "evidence_retention_sweep":
                raise HTTPException(
                    status_code=409,
                    detail="Legacy evidence retention schedules must be migrated to a scan or ASM schedule.",
                )
            if effective_schedule_kind == "normal_scan":
                legacy_fields = sorted(LEGACY_SCAN_WRITE_FIELDS.intersection(scan_options))
                if legacy_fields:
                    raise HTTPException(
                        status_code=422,
                        detail=(
                            "canonical Scan schedules reject legacy option authority: "
                            + ", ".join(legacy_fields)
                        ),
                    )
                try:
                    resolve_scan_contract(
                        budget_profile=scan_options.get("budget_profile"),
                        policy=scan_options.get("policy"),
                        advanced=scan_options.get("advanced"),
                        approval_receipt_id=scan_options.get("approval_receipt_id"),
                    )
                except ValueError as exc:
                    raise HTTPException(status_code=422, detail=str(exc)) from exc
            updates.append(f"scan_options = ${param_idx}")
            params.append(json.dumps(scan_options))
            param_idx += 1
        elif explicit_kind_update:
            existing_options = _schedule_options_dict(existing["scan_options"])
            existing_options.pop("kind", None)
            if (
                _schedule_kind_from_row(existing) == "evidence_retention_sweep"
                and effective_schedule_kind != "evidence_retention_sweep"
            ):
                for legacy_key in (
                    "dry_run",
                    "older_than_days",
                    "retention_class",
                    "limit",
                    "delete_local_files",
                    "approval_receipt_id",
                    "preview_id",
                    "target_id",
                ):
                    existing_options.pop(legacy_key, None)
            if existing_options != _schedule_options_dict(existing["scan_options"]):
                updates.append(f"scan_options = ${param_idx}")
                params.append(json.dumps(existing_options))
                param_idx += 1

        if request.jitter_minutes is not None:
            updates.append(f"jitter_minutes = ${param_idx}")
            params.append(request.jitter_minutes)
            param_idx += 1
            timing_changed = True

        if request.is_active is not None:
            if request.is_active and effective_schedule_kind == "evidence_retention_sweep":
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "Legacy evidence retention schedules cannot be enabled. "
                        "Migrate this schedule to a scan or ASM schedule, or delete it."
                    ),
                )
            updates.append(f"is_active = ${param_idx}")
            params.append(request.is_active)
            param_idx += 1
            if request.is_active:
                timing_changed = True
            else:
                updates.append("next_run_at = NULL")

        if not updates:
            raise HTTPException(status_code=400, detail="No updates provided")

        # Recalculate next_run_at if timing fields changed
        if timing_changed and request.is_active is not False:
            freq = request.frequency or existing['frequency']
            dow = request.day_of_week if request.day_of_week is not None else existing['day_of_week']
            tod = request.time_of_day or existing['time_of_day'] or '02:00'
            tz = request.timezone or existing['timezone'] or 'UTC'
            jitter = request.jitter_minutes if request.jitter_minutes is not None else (existing['jitter_minutes'] or 0)
            next_run = calculate_next_run(freq, dow, tod, tz, jitter)
            updates.append(f"next_run_at = ${param_idx}")
            params.append(next_run)
            param_idx += 1

        updates.append("updated_at = NOW()")
        params.append(uuid.UUID(schedule_id))

        query = f"UPDATE schedules SET {', '.join(updates)} WHERE id = ${param_idx} RETURNING id"
        result = await conn.fetchval(query, *params)

        if not result:
            raise HTTPException(status_code=404, detail="Schedule not found")

    return {'id': schedule_id, 'status': 'updated'}


@router.delete("/schedules/{schedule_id}")
async def delete_schedule(schedule_id: str):
    """Delete a schedule."""
    async with _pool().acquire() as conn:
        result = await conn.execute(
            "DELETE FROM schedules WHERE id = $1", uuid.UUID(schedule_id)
        )
        if result == "DELETE 0":
            raise HTTPException(status_code=404, detail="Schedule not found")

    return {'id': schedule_id, 'status': 'deleted'}
VALID_SCHEDULE_KINDS = {"normal_scan", "asm_improve", "evidence_retention_sweep"}


SCHEDULE_HEALTH_LOOKBACK_DAYS = 14


def _schedule_health_from_failures(
    schedule: dict[str, Any],
    failures: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if not failures:
        return None

    latest = failures[0]
    latest_kind = _schedule_failure_kind(latest.get("error_message"))
    timeout_count = sum(
        1
        for failure in failures
        if _schedule_failure_kind(failure.get("error_message")) in {"duration_timeout", "heartbeat_timeout"}
    )
    recent_failed_count = len(failures)
    scan_type = str(schedule.get("scan_type") or "quick")
    schedule_kind = _schedule_kind_from_row(schedule)

    status = "attention" if recent_failed_count >= 2 or latest_kind in {"duration_timeout", "heartbeat_timeout"} else "warning"
    if latest_kind in {"duration_timeout", "heartbeat_timeout"}:
        reason = "repeated_timeout" if timeout_count >= 2 else latest_kind
    elif recent_failed_count >= 2:
        reason = "repeated_failure"
    else:
        reason = latest_kind

    suggested_scan_type = None
    recommendation = "Review the latest failed scan before the next scheduled run."
    if schedule_kind == "normal_scan" and scan_type == "quick" and reason in {"repeated_timeout", "duration_timeout", "heartbeat_timeout"}:
        suggested_scan_type = "standard"
        recommendation = "Pause this schedule or switch it to standard after confirming the production scan budget."
    elif reason in {"repeated_timeout", "duration_timeout", "heartbeat_timeout"}:
        recommendation = "Pause this schedule or increase the schedule budget after confirming authorization."
    elif reason == "target_unreachable":
        recommendation = "Pause this schedule until the target resolves and passes pre-scan validation."

    latest_failed_scan_id = latest.get("id")
    return {
        "status": status,
        "reason": reason,
        "failure_kind": latest_kind,
        "recent_failed_count": recent_failed_count,
        "timeout_failed_count": timeout_count,
        "lookback_days": SCHEDULE_HEALTH_LOOKBACK_DAYS,
        "latest_failed_scan_id": str(latest_failed_scan_id) if latest_failed_scan_id else None,
        "latest_failed_at": latest.get("created_at") or latest.get("completed_at"),
        "latest_error": _first_error_line(latest.get("error_message")),
        "recommendation": recommendation,
        "suggested_scan_type": suggested_scan_type,
    }
def _schedule_failure_kind(error_message: Any) -> str:
    text = str(error_message or "").lower()
    if "exceeded max duration" in text:
        return "duration_timeout"
    if "no heartbeat" in text:
        return "heartbeat_timeout"
    if "target unreachable" in text or "dns resolution failed" in text or "cannot resolve hostname" in text:
        return "target_unreachable"
    if "queue enqueue" in text or "redis" in text:
        return "queue_failure"
    return "failed"


def _first_error_line(error_message: Any) -> str:
    text = str(error_message or "Scan failed before producing a clean result.").strip()
    return text.split("\n", 1)[0][:300]
