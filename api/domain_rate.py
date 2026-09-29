"""Per-root-domain hourly test ledger shared by Continuous ASM and background Scans.

What the quota means
--------------------
``max_requests_per_hour_per_domain`` (a historical name; the default comes from
``ASM_DEFAULT_DOMAIN_RATE_PER_HOUR`` and is 1000) caps **endpoints tested per rolling hour across
every target that shares a root domain**. The unit is always endpoints: an ASM batch holds the
endpoints it claimed, a Scan holds the active endpoints its immutable plan may test.
HTTP request budgets are a different unit and are never reserved against this quota.

Which work it governs
---------------------
* **Background work** is governed: Continuous ASM endpoint batches (dispatcher, scheduled "ASM
  improve" waves and manually queued ASM test batches, all of which use the ASM pacing the target
  was configured with), ASM recon Scans, and scheduled Scans (``admission_origin=schedule``), plus
  the parallel children of those Scans. Nobody watches this work start, so it may wait for
  headroom. A wait is visible (``current_phase=waiting_for_domain_rate`` plus the ``domain_rate``
  object with an estimated resume time). A Scan's immutable plan cannot be lowered at runtime, so
  a background Scan holds its full immutable endpoint plan or waits. A plan larger than the
  configured hourly cap fails with an actionable reason; only
  an ASM batch can be reduced, by releasing claimed endpoints back to the inventory, and that
  reduction is recorded on the Scan (``domain_rate.reduction``) and in its report metadata.
* **Operator work** is never delayed or shrunk by the quota: Scans an operator submits through
  ``POST /scans`` or ``POST /targets/{id}/scan`` (UI, API, client, MCP and Hunt-dispatched Scans all
  use that admission), their parallel children and device web children. They are explicit,
  authorized and already bounded by their budget profile and the engine's per-host request pacing.
  They still *count*: their planned endpoints are held while they run and their tested endpoints
  are recorded when they finish, so background work on the same root domain backs off. (Finding
  retests never passed through this quota and remain outside it.)

The ledger
----------
Two Redis keys per root domain: a sorted set of entry expiries and a hash of entry units. Entry
``h:<id>`` is an in-flight hold (expires ``HOLD_TTL_SECONDS`` after it was taken, so an abandoned
reservation frees itself); entry ``c:<id>`` is consumption that is *not* already visible in the
database window (``target_endpoints.last_tested_at`` within the hour, which ASM stamps itself) and
expires one window after the work finished. Settling a hold is idempotent per entry id: the unused
remainder is released and the used part is recorded once. Every entry expires on its own, so a
busy domain decays continuously; the keys' own TTL only garbage-collects them after the last entry.
All mutation happens in Lua using the Redis server clock, which keeps the API dispatcher, local
workers and broker leases on one atomic ledger regardless of host clock skew.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import logging
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, Mapping

logger = logging.getLogger(__name__)

WINDOW_SECONDS = 3600
HOLD_TTL_SECONDS = 3600
SETTLED_TTL_SECONDS = 86400
WORK_OPERATOR = "operator"
WORK_BACKGROUND = "background"
ADMISSION_ORIGIN_KEY = "admission_origin"
ORIGIN_SCHEDULE = "schedule"
WAITING_PHASE = "waiting_for_domain_rate"
BACKGROUND_ORIGINS = frozenset({ORIGIN_SCHEDULE})
BACKGROUND_KINDS = frozenset({"asm_batch", "asm_recon"})
_LEDGER_PREFIX = "domain_rate:v2"

_PRUNE = """
local now_parts = redis.call('TIME')
local now = tonumber(now_parts[1]) * 1000 + math.floor(tonumber(now_parts[2]) / 1000)
local expired = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', now)
for _, member in ipairs(expired) do redis.call('HDEL', KEYS[2], member) end
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
local function total_units()
  local used = 0
  for _, value in ipairs(redis.call('HVALS', KEYS[2])) do used = used + (tonumber(value) or 0) end
  return used
end
local function keep_keys()
  local last = redis.call('ZRANGE', KEYS[1], -1, -1, 'WITHSCORES')
  if last[2] then
    local at = math.floor(tonumber(last[2])) + 1000
    redis.call('PEXPIREAT', KEYS[1], at)
    redis.call('PEXPIREAT', KEYS[2], at)
  else
    redis.call('DEL', KEYS[1], KEYS[2])
  end
end
"""

# ARGV: entry id, requested units, headroom (cap minus the database window), hold ttl ms,
# all_or_nothing flag, enforce flag. Returns {units now held by the entry, ledger units after}.
RESERVE_LUA = "-- shakerscan:domain_rate:reserve" + _PRUNE + """
local hold = 'h:' .. ARGV[1]
local requested = tonumber(ARGV[2]) or 0
local headroom = tonumber(ARGV[3]) or 0
local enforce = ARGV[6] ~= '0'
local used = total_units()
local existing = tonumber(redis.call('HGET', KEYS[2], hold) or '0') or 0
local total = existing
if requested > existing then
  local need = requested - existing
  local grant = need
  if enforce then
    local free = headroom - used
    if free < 0 then free = 0 end
    if grant > free then grant = free end
    if ARGV[5] == '1' and grant < need then grant = 0 end
  end
  total = existing + grant
end
if total > 0 then
  redis.call('HSET', KEYS[2], hold, total)
  redis.call('ZADD', KEYS[1], now + tonumber(ARGV[4]), hold)
end
keep_keys()
return {total, used - existing + total}
"""

# ARGV: entry id, consumed units (-1 = unknown: keep what was held), window ms,
# settled-marker ttl ms, final-execution flag. A zero-unit marker prevents a late duplicate settlement from
# restarting the rolling window after its consumption entry has expired.
# Returns {units the hold had, units recorded as consumption}.
SETTLE_LUA = "-- shakerscan:domain_rate:settle" + _PRUNE + """
local hold = 'h:' .. ARGV[1]
local done = 'd:' .. ARGV[1]
local used = 'c:' .. ARGV[1]
if redis.call('HEXISTS', KEYS[2], done) == 1 then
  return {0, tonumber(redis.call('HGET', KEYS[2], used) or '0') or 0}
end
local held = tonumber(redis.call('HGET', KEYS[2], hold) or '0') or 0
local consumed = tonumber(ARGV[2]) or -1
if consumed < 0 then consumed = held end
redis.call('HDEL', KEYS[2], hold)
redis.call('ZREM', KEYS[1], hold)
if consumed > 0 then
  redis.call('HSET', KEYS[2], used, consumed)
  redis.call('ZADD', KEYS[1], now + tonumber(ARGV[3]), used)
end
if ARGV[5] == '1' then
  redis.call('HSET', KEYS[2], done, 0)
  redis.call('ZADD', KEYS[1], now + tonumber(ARGV[4]), done)
end
keep_keys()
return {held, consumed}
"""

# Returns {server now ms, ledger units, {expiry ms, units, ...}} for status and resume estimates.
USAGE_LUA = "-- shakerscan:domain_rate:usage" + _PRUNE + """
local entries = redis.call('ZRANGE', KEYS[1], 0, -1, 'WITHSCORES')
local schedule = {}
for index = 1, #entries, 2 do
  table.insert(schedule, math.floor(tonumber(entries[index + 1])))
  table.insert(schedule, tonumber(redis.call('HGET', KEYS[2], entries[index]) or '0') or 0)
end
keep_keys()
return {now, total_units(), schedule}
"""


def ledger_keys(root_domain: str) -> tuple[str, str]:
    normalized = str(root_domain or "").strip().lower()
    digest = hashlib.sha256(normalized.encode("utf-8", "replace")).hexdigest()[:16]
    return f"{_LEDGER_PREFIX}:{digest}:expiry", f"{_LEDGER_PREFIX}:{digest}:units"


def _int(value: Any) -> int:
    if isinstance(value, bytes):
        value = value.decode("ascii", "replace")
    try:
        return int(float(value or 0))
    except (TypeError, ValueError):
        return 0


def work_class(options: Mapping[str, Any] | None) -> str:
    """Classify work from durable Scan options (see module docstring)."""
    opts = options if isinstance(options, Mapping) else {}
    if str(opts.get("run_kind") or "") in BACKGROUND_KINDS:
        return WORK_BACKGROUND
    if str(opts.get(ADMISSION_ORIGIN_KEY) or "") in BACKGROUND_ORIGINS:
        return WORK_BACKGROUND
    return WORK_OPERATOR


def planned_endpoints(
    options: Mapping[str, Any] | None,
    *,
    prepare: Callable[[Mapping[str, Any]], Any],
    is_dast: Callable[[Mapping[str, Any]], bool],
) -> int:
    """Active endpoints a canonical Scan plan may test (the quota unit), never HTTP requests."""
    opts = options or {}
    if not is_dast(opts):
        return 0
    _normalized, admission = prepare(opts)
    if admission.plan is None:
        return 0
    maximum = max(0, int(admission.plan.budget.max_endpoints))
    known = opts.get("custom_endpoints")
    known_count = len(known) if isinstance(known, list) else 0
    if known_count > 0:
        return min(known_count, maximum)
    return maximum if admission.plan.policy.active_testing else 0


def reserve(
    redis_client: Any,
    root_domain: str,
    *,
    entry_id: str,
    requested: int,
    headroom: int,
    enforce: bool = True,
    all_or_nothing: bool = False,
    hold_ttl_seconds: int = HOLD_TTL_SECONDS,
) -> tuple[int, int | None]:
    """Hold up to ``requested`` units for ``entry_id``; returns (units held, ledger units).

    ``enforce=False`` records operator work without admission control. A Redis failure fails
    closed for enforced work (nothing held) and open for operator work (it runs unrecorded).
    """
    requested = max(0, int(requested or 0))
    if requested <= 0 or not root_domain:
        return 0, None
    try:
        held, ledger = redis_client.eval(
            RESERVE_LUA, 2, *ledger_keys(root_domain),
            str(entry_id), requested, max(0, int(headroom or 0)),
            max(60, int(hold_ttl_seconds)) * 1000,
            "1" if all_or_nothing else "0", "1" if enforce else "0",
        )
        return max(0, _int(held)), max(0, _int(ledger))
    except Exception as exc:
        logger.warning("domain rate reservation failed for %s: %s", root_domain, exc)
        print(f"[domain-rate] reservation failed for {root_domain}: {exc}", flush=True)
        return (0 if enforce else requested), None


def settle(
    redis_client: Any,
    root_domain: str,
    *,
    entry_id: str,
    consumed: int | None,
    window_seconds: int = WINDOW_SECONDS,
    finalized: bool = True,
) -> tuple[int, int] | None:
    """Release a hold, recording ``consumed`` units (``None`` = unknown: keep what was held)."""
    if not root_domain or not entry_id:
        return None
    try:
        held, recorded = redis_client.eval(
            SETTLE_LUA, 2, *ledger_keys(root_domain), str(entry_id),
            -1 if consumed is None else max(0, int(consumed)), int(window_seconds) * 1000,
            SETTLED_TTL_SECONDS * 1000, "1" if finalized else "0",
        )
        return _int(held), _int(recorded)
    except Exception as exc:
        logger.warning("domain rate settlement failed for %s: %s", root_domain, exc)
        print(f"[domain-rate] settlement failed for {root_domain} ({entry_id}): {exc}", flush=True)
        return None


def ledger_state(redis_client: Any, root_domain: str) -> tuple[int, int, list[tuple[int, int]]]:
    """(server now ms, ledger units, [(expiry ms, units)]) with expired entries pruned."""
    if not root_domain:
        return 0, 0, []
    try:
        now_ms, total, flat = redis_client.eval(USAGE_LUA, 2, *ledger_keys(root_domain))
    except Exception as exc:
        logger.warning("domain rate usage read failed for %s: %s", root_domain, exc)
        return 0, 0, []
    flat = list(flat or [])
    return _int(now_ms), max(0, _int(total)), [
        (_int(flat[i]), _int(flat[i + 1])) for i in range(0, len(flat) - 1, 2)
    ]


def usage(redis_client: Any, root_domain: str) -> int:
    return ledger_state(redis_client, root_domain)[1]


def admit(
    redis_client: Any,
    *,
    root_domain: str,
    cap: int,
    db_used: int,
    entry_id: str | None,
    amount: int,
    work: str,
    all_or_nothing: bool = False,
) -> dict[str, Any]:
    """Admission decision for ``amount`` endpoint units of ``work`` against the domain ledger."""
    entry = str(entry_id or uuid.uuid4())
    base = {
        "root_domain": root_domain, "cap": cap, "used": int(db_used or 0), "requested": amount,
        "entry_id": entry, "work_class": work, "enforced": work != WORK_OPERATOR,
        "all_or_nothing": bool(all_or_nothing),
    }
    headroom = max(0, int(cap) - int(db_used or 0))
    # An immutable Scan plan must hold every endpoint it may execute. A smaller token
    # would admit a 10,000-endpoint plan against a 1,000-endpoint hourly cap.
    token = amount
    if all_or_nothing and work != WORK_OPERATOR and amount > cap:
        return {**base, "granted": 0, "held": 0, "limited": True,
                "reserved": usage(redis_client, root_domain), "reason": "plan_exceeds_domain_cap",
                "unadmittable": True}
    held, ledger = reserve(
        redis_client, root_domain, entry_id=entry, requested=token, headroom=headroom,
        enforce=work != WORK_OPERATOR, all_or_nothing=all_or_nothing,
    )
    if work == WORK_OPERATOR:
        return {**base, "granted": amount, "limited": False, "held": held,
                "reserved": ledger, "reason": "operator_recorded"}
    granted = (amount if held >= token else 0) if all_or_nothing else min(amount, held)
    return {
        **base, "granted": granted, "held": held, "limited": granted < amount,
        "reserved": ledger if ledger is not None else usage(redis_client, root_domain),
        "reason": "reserved" if granted >= amount else "domain_rate_limited",
    }


async def resume_estimate(conn: Any, redis_client: Any, decision: Mapping[str, Any]) -> str | None:
    """Earliest time the domain frees enough units for the smallest admissible grant.

    Holds are counted until their own expiry although running work usually settles them sooner,
    so this is an estimate ("about"), never a promise.
    """
    root_domain = str(decision.get("root_domain") or "")
    cap = int(decision.get("cap") or 0)
    if not root_domain or cap <= 0:
        return None
    now_ms, ledger_units, schedule = ledger_state(redis_client, root_domain)
    releases = list(schedule)
    rows = await conn.fetch(
        """
        SELECT EXTRACT(EPOCH FROM te.last_tested_at + ($2 || ' seconds')::interval) * 1000 AS frees_at,
               count(*) AS units
        FROM target_endpoints te JOIN targets t ON t.id = te.target_id
        WHERE t.root_domain = $1
          AND te.last_tested_at >= NOW() - ($2 || ' seconds')::interval
        GROUP BY 1
        """,
        root_domain, str(WINDOW_SECONDS),
    )
    db_used = 0
    for row in rows or ():
        units = _int(row["units"])
        db_used += units
        releases.append((_int(row["frees_at"]), units))
    requested = int(decision.get("requested") or 0)
    needed = min(requested, cap) if decision.get("all_or_nothing") else min(1, requested)
    excess = db_used + ledger_units + needed - cap
    if excess <= 0:
        return _iso(now_ms) if now_ms else None
    freed = 0
    for frees_at, units in sorted(releases):
        freed += units
        if freed >= excess:
            return _iso(max(frees_at, now_ms))
    return None


def _iso(epoch_ms: int) -> str:
    return datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def waiting_record(decision: Mapping[str, Any], *, wait_cycles: int, since: str | None) -> dict[str, Any]:
    """Durable ``scans.domain_rate_json`` for work parked behind the quota."""
    root = str(decision.get("root_domain") or "")
    return {
        "schema": "domain_rate/v1",
        "state": "waiting",
        "work_class": str(decision.get("work_class") or WORK_BACKGROUND),
        "root_domain": root,
        "cap_per_hour": int(decision.get("cap") or 0),
        "tested_last_hour": int(decision.get("used") or 0),
        "in_flight_or_recorded": int(decision.get("reserved") or 0),
        "requested": int(decision.get("requested") or 0),
        "resume_estimate": decision.get("resume_at"),
        "wait_cycles": int(wait_cycles),
        "waiting_since": since,
        "reason": (
            f"Waiting for {root or 'this domain'}'s hourly test budget: "
            f"{int(decision.get('cap') or 0)} endpoints per hour across its targets are in use "
            "by background testing or recent Scans."
        ),
    }


def wait_cycles(redis_client: Any, job_data: Mapping[str, Any], job_id: str) -> int:
    if isinstance(job_data.get("_canonical_queue_payload"), Mapping):
        previous = redis_client.hget(f"job:{job_id}", "domain_rate_wait_cycles")
    else:
        previous = job_data.get("domain_rate_wait_cycles")
    return _int(previous) + 1


async def record_wait(conn: Any, redis_client: Any, job_data: Mapping[str, Any], *,
                      job_id: str, scan_id: str, rate: Mapping[str, Any], status: str,
                      from_statuses: tuple[str, ...]) -> str:
    """Park a Scan with a durable quota reason and estimated resume time."""
    since = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    record = waiting_record(rate, wait_cycles=wait_cycles(redis_client, job_data, job_id),
                            since=since)
    return await conn.execute(
        """UPDATE scans
           SET status=$2, current_phase=$3, started_at=NULL,
               progress=LEAST(COALESCE(progress, 0), 5),
               domain_rate_json=$4::jsonb || jsonb_build_object('waiting_since', COALESCE(
                   CASE WHEN domain_rate_json->>'state' = 'waiting'
                        THEN domain_rate_json->>'waiting_since' END, $5))
           WHERE id=$1 AND status = ANY($6::text[])""",
        uuid.UUID(str(scan_id)), status, WAITING_PHASE, json.dumps(record),
        record["waiting_since"], list(from_statuses),
    )


def unadmittable_record(decision: Mapping[str, Any]) -> dict[str, Any]:
    """Explain an immutable background plan larger than its configured hourly cap."""
    root = str(decision.get("root_domain") or "this domain")
    cap = int(decision.get("cap") or 0)
    requested = int(decision.get("requested") or 0)
    return {
        "schema": "domain_rate/v1", "state": "blocked", "work_class": WORK_BACKGROUND,
        "root_domain": root, "cap_per_hour": cap, "requested": requested,
        "reason": (
            f"Background Scan plan allows {requested} endpoints, exceeding {root}'s "
            f"{cap}-endpoint hourly test budget. Lower the Scan's max_endpoints limit "
            "or increase the domain budget before scheduling it again."
        ),
    }


async def fail_oversized_scan(pool: Any, redis_client: Any, *, job_id: str,
                              scan_id: str, decision: Mapping[str, Any]) -> None:
    record = unadmittable_record(decision)
    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE scans SET status='failed', progress=100,
                      current_phase='domain_rate_plan_exceeds_cap', error_message=$2,
                      domain_rate_json=$3::jsonb, completed_at=NOW()
               WHERE id=$1 AND status IN ('pending','queued','running')""",
            uuid.UUID(str(scan_id)), record["reason"], json.dumps(record),
        )
    redis_client.hset(f"job:{job_id}", mapping={
        "status": "failed", "current_phase": "domain_rate_plan_exceeds_cap",
        "error_message": record["reason"], "progress": "100",
    })
    redis_client.expire(f"job:{job_id}", 86400)


async def track_dispatch_hold(pool: Any, job_data: Mapping[str, Any]) -> None:
    """Register an API-dispatcher hold before any worker early return can strand it."""
    hold_id, target_id = job_data.get("domain_rate_hold_id"), job_data.get("target_id")
    if not hold_id or not target_id:
        return
    async with pool.acquire() as conn:
        root = await conn.fetchval("SELECT root_domain FROM targets WHERE id=$1",
                                   uuid.UUID(str(target_id)))
    if root:
        track(str(root).strip().lower(), str(hold_id))


def admitted_record(decision: Mapping[str, Any], reduction: Mapping[str, Any] | None = None) -> dict[str, Any]:
    work = str(decision.get("work_class") or WORK_BACKGROUND)
    record = {
        "schema": "domain_rate/v1",
        "state": "reduced" if reduction else "admitted",
        "work_class": work,
        "root_domain": str(decision.get("root_domain") or ""),
        "cap_per_hour": int(decision.get("cap") or 0),
        "requested": int(decision.get("requested") or 0),
        "granted": int(decision.get("granted") or 0),
        "reason": (
            "Operator-initiated Scan: never delayed or reduced by the hourly test budget; its "
            "endpoints count toward the domain so background testing backs off."
            if work == WORK_OPERATOR else "Admitted within the domain's hourly test budget."
        ),
    }
    if reduction:
        record["reduction"] = dict(reduction)
        record["reason"] = str(reduction.get("reason") or record["reason"])
    return record


def reduction_record(decision: Mapping[str, Any]) -> dict[str, Any]:
    """Why an ASM batch tests fewer claimed endpoints than it was queued with.

    Only endpoint batches can be reduced honestly (unclaimed endpoints are released back to the
    inventory). A Scan's immutable plan cannot be lowered at runtime, so background Scans are
    admitted whole or wait.
    """
    granted, requested = int(decision.get("granted") or 0), int(decision.get("requested") or 0)
    root = str(decision.get("root_domain") or "")
    return {
        "dimension": "claimed_endpoints",
        "requested": requested,
        "granted": granted,
        "root_domain": root,
        "cap_per_hour": int(decision.get("cap") or 0),
        "reason": (
            f"Background ASM batch reduced to {granted} of {requested} endpoints by "
            f"{root or 'the domain'}'s hourly test budget ({int(decision.get('cap') or 0)} "
            "endpoints per hour across its targets); the rest return to the inventory."
        ),
    }


def annotate_result(result: dict[str, Any], reduction: Mapping[str, Any] | None) -> None:
    """Carry a quota reduction into the report metadata and its coverage reasons."""
    if not isinstance(reduction, Mapping) or not reduction:
        return
    metadata = result.get("scan_metadata") if isinstance(result.get("scan_metadata"), dict) else {}
    metadata["domain_rate_reduction"] = dict(reduction)
    result["scan_metadata"] = metadata
    coverage = result.get("coverage") if isinstance(result.get("coverage"), dict) else None
    if coverage is not None:
        reasons = list(coverage.get("reasons") or [])
        if reduction.get("reason") and reduction["reason"] not in reasons:
            reasons.append(str(reduction["reason"]))
        coverage["reasons"] = reasons


def tested_endpoints(result: Mapping[str, Any] | None) -> int | None:
    """Endpoints a finished Scan actively tested; ``None`` when the report cannot say."""
    report = result if isinstance(result, Mapping) else {}
    coverage = report.get("coverage") if isinstance(report.get("coverage"), Mapping) else None
    if coverage is None:
        return None
    execution = coverage.get("active_execution")
    if execution is None:
        return 0
    if not isinstance(execution, Mapping):
        return None
    return max(0, _int(execution.get("endpoints_tested")))


def public_view(raw: Any, *, status: str | None) -> dict[str, Any] | None:
    """The ``domain_rate`` object on Scan responses; a stale wait is not shown as current."""
    import json

    if isinstance(raw, (str, bytes)):
        try:
            raw = json.loads(raw)
        except ValueError:
            return None
    if not isinstance(raw, dict) or not raw:
        return None
    view = dict(raw)
    if view.get("state") == "waiting" and str(status or "") not in {"pending", "queued"}:
        view["state"] = "waited"
    return view


# Settlement: the worker opens one scope per job; reservations register in it and are settled when
# the job returns, raises or is cancelled. Work that never started execution releases its hold;
# work that ran without a measurement keeps what it held (unknown outcomes retain capacity).
_SCOPE: contextvars.ContextVar[list[dict[str, Any]] | None] = contextvars.ContextVar(
    "domain_rate_settlements", default=None,
)


@contextmanager
def settlement_scope(redis_factory: Callable[[], Any]) -> Iterator[None]:
    token = _SCOPE.set([])
    try:
        yield
    finally:
        pending = _SCOPE.get() or []
        _SCOPE.reset(token)
        if pending:
            client = redis_factory()
            for item in pending:
                consumed = item["consumed"]
                if not item["executing"]:
                    consumed = 0
                settle(client, item["root_domain"], entry_id=item["entry_id"],
                       consumed=consumed, finalized=bool(item["executing"]))


def track(root_domain: str, entry_id: str, *, executing: bool = False) -> None:
    scope = _SCOPE.get()
    if scope is None or not root_domain or not entry_id:
        return
    for item in scope:
        if item["entry_id"] == entry_id:
            item["executing"] = item["executing"] or executing
            return
    scope.append({"root_domain": root_domain, "entry_id": entry_id,
                  "executing": executing, "consumed": None})


def mark_executing(entry_id: str) -> None:
    for item in _SCOPE.get() or ():
        if item["entry_id"] == entry_id:
            item["executing"] = True


def measure(entry_id: str, consumed: int | None) -> None:
    """Record units consumed that the database window does not already count."""
    for item in _SCOPE.get() or ():
        if item["entry_id"] == entry_id:
            item["executing"] = True
            item["consumed"] = None if consumed is None else max(0, int(consumed))
