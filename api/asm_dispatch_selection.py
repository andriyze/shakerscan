"""Which Continuous ASM targets one dispatcher tick evaluates, and their counts in a few queries (2.11).

The dispatcher used to evaluate every ASM target on every tick: four COUNT queries each and an
unconditional JSONB rewrite of the target row (about 50k queries and 10k row writes a minute at 10k
targets). A tick now evaluates only the targets that are due, at most
``ASM_DISPATCH_TARGETS_PER_TICK`` of them, with their counts loaded in one query per kind, and the
caller rewrites the stored decision only when it changed.

A target is due when it was never evaluated by this process, when its ASM configuration or its last
recon/test stamps changed, or when the time its last decision named has come. Decisions that can
change at any moment (an active Scan finishing, a per-domain rate window, a dispatch just made)
are re-evaluated on the next tick; every other decision at the latest after
``ASM_RECHECK_MAX_SECONDS``, so an approval or endpoint change is picked up within that bound.
The schedule lives in the dispatcher's own process (its loop leader); a new leader starts by
evaluating everything once.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from typing import Any, Iterable, Mapping


def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, "") or default))
    except ValueError:
        return default


ASM_DISPATCH_TARGETS_PER_TICK = _int_env("ASM_DISPATCH_TARGETS_PER_TICK", 200)
ASM_RECHECK_MAX_SECONDS = _int_env("ASM_RECHECK_MAX_SECONDS", 300)
# Decisions whose inputs change without any stored stamp changing: evaluate again next tick.
RECHECK_NEXT_TICK = frozenset({"active_scan", "domain_rate_cap", "rate_or_daily_cap"})

FINGERPRINT_SQL = """
    SELECT id, md5(concat_ws('|', asm_config::text, asm_last_test_at::text, asm_last_recon_at::text)) AS fingerprint
    FROM targets
    WHERE asm_enabled = true AND is_active = true
"""

DETAIL_SQL = """
    SELECT id, url, root_domain, asm_config, asm_last_test_at, asm_last_recon_at,
           metadata_json->'asm_last_decision' AS last_decision
    FROM targets
    WHERE id = ANY($1::uuid[]) AND asm_enabled = true AND is_active = true
"""

ACTIVE_SQL = """
    SELECT target_id, COUNT(*) AS n FROM scans
    WHERE target_id = ANY($1::uuid[]) AND status IN ('pending', 'queued', 'running')
    GROUP BY target_id
"""

# The same predicate as asm_inventory.claimable_count, for many targets at once.
CLAIMABLE_SQL = """
    SELECT te.target_id, COUNT(*) AS n
    FROM target_endpoints te
    JOIN unnest($1::uuid[], $2::text[]) AS p(target_id, stale_days) ON te.target_id = p.target_id
    WHERE te.test_status IN ('untested', 'stale')
       OR (te.test_status = 'tested' AND te.last_tested_at < NOW() - (p.stale_days || ' days')::interval)
    GROUP BY te.target_id
"""

# asm_inventory.tested_recently_count(hours=24), for many targets at once.
TESTED_TODAY_SQL = """
    SELECT target_id, COUNT(*) AS n FROM target_endpoints
    WHERE target_id = ANY($1::uuid[]) AND last_tested_at >= NOW() - ('24' || ' hours')::interval
    GROUP BY target_id
"""

# asm_inventory.domain_tested_recently_count(hours=1), for many root domains at once.
DOMAIN_SQL = """
    SELECT t.root_domain, COUNT(*) AS n
    FROM target_endpoints te
    JOIN targets t ON t.id = te.target_id
    WHERE t.root_domain = ANY($1::text[])
      AND te.last_tested_at >= NOW() - ('1' || ' hours')::interval
    GROUP BY t.root_domain
"""


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return _aware(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return None


def decode_json(value: Any) -> Any:
    if isinstance(value, (str, bytes)):
        try:
            return json.loads(value)
        except ValueError:
            return None
    return value


class AsmDueSchedule:
    """target id -> (when it is next due, fingerprint of the stamps it was evaluated with)."""

    def __init__(self) -> None:
        self._due: dict[str, tuple[datetime, str]] = {}

    def select(self, rows: Iterable[Mapping[str, Any]], *, now: datetime, limit: int) -> list[str]:
        """The due target ids, most overdue first (never evaluated, or changed, before all)."""
        now = _aware(now)
        current = {str(row["id"]): str(row["fingerprint"] or "") for row in rows}
        for target_id in [tid for tid in self._due if tid not in current]:
            self._due.pop(target_id, None)  # disabled, deactivated or deleted
        epoch = datetime.min.replace(tzinfo=timezone.utc)
        due: list[tuple[datetime, str]] = []
        for target_id, fingerprint in current.items():
            entry = self._due.get(target_id)
            if entry is None or entry[1] != fingerprint:
                due.append((epoch, target_id))
            elif entry[0] <= now:
                due.append((entry[0], target_id))
        due.sort()
        return [target_id for _when, target_id in due[: max(1, int(limit))]]

    def schedule(
        self,
        target_id: str,
        fingerprint: str,
        decision: Mapping[str, Any] | None,
        *,
        now: datetime,
        dispatched: bool = False,
    ) -> datetime:
        """Record when the target is next due after this evaluation."""
        now = _aware(now)
        ceiling = now + timedelta(seconds=ASM_RECHECK_MAX_SECONDS)
        blocked_by = str((decision or {}).get("blocked_by") or "")
        dispatched = dispatched or str((decision or {}).get("action") or "") in {"recon", "test"}
        if dispatched or not decision or blocked_by in RECHECK_NEXT_TICK:
            due = now
        else:
            eligible = _parse_time((decision or {}).get("next_eligible_at"))
            due = min(eligible, ceiling) if eligible is not None else ceiling
            due = max(due, now)
        self._due[str(target_id)] = (due, str(fingerprint or ""))
        return due

    def forget(self, target_id: str) -> None:
        self._due.pop(str(target_id), None)


async def load_due_targets(
    conn: Any, schedule: AsmDueSchedule, *, now: datetime, limit: int = ASM_DISPATCH_TARGETS_PER_TICK,
) -> list[dict[str, Any]]:
    """Full rows (with a ``fingerprint``) of the targets due this tick."""
    fingerprints = await conn.fetch(FINGERPRINT_SQL)
    due_ids = schedule.select(fingerprints, now=now, limit=limit)
    if not due_ids:
        return []
    by_id = {str(row["id"]): str(row["fingerprint"] or "") for row in fingerprints}
    rows = await conn.fetch(DETAIL_SQL, [_uuid(target_id) for target_id in due_ids])
    order = {target_id: index for index, target_id in enumerate(due_ids)}
    out = []
    for row in rows:
        item = dict(row)
        item["fingerprint"] = by_id.get(str(row["id"]), "")
        out.append(item)
    out.sort(key=lambda item: order.get(str(item["id"]), len(order)))
    return out


def _uuid(value: Any) -> Any:
    import uuid

    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


async def load_counts(
    conn: Any, targets: list[Mapping[str, Any]], *, stale_days: Mapping[str, int],
) -> dict[str, Any]:
    """{"active": {id: n}, "claimable": {id: n}, "tested_today": {id: n}, "domain_used": {root: n}}."""
    ids = [_uuid(target["id"]) for target in targets]
    if not ids:
        return {"active": {}, "claimable": {}, "tested_today": {}, "domain_used": {}}
    active = await conn.fetch(ACTIVE_SQL, ids)
    claimable = await conn.fetch(
        CLAIMABLE_SQL, ids, [str(int(stale_days.get(str(target_id), 30))) for target_id in ids])
    tested = await conn.fetch(TESTED_TODAY_SQL, ids)
    roots = sorted({str(target["root_domain"]) for target in targets if target.get("root_domain")})
    domains = await conn.fetch(DOMAIN_SQL, roots) if roots else []
    return {
        "active": {str(row["target_id"]): int(row["n"]) for row in active},
        "claimable": {str(row["target_id"]): int(row["n"]) for row in claimable},
        "tested_today": {str(row["target_id"]): int(row["n"]) for row in tested},
        "domain_used": {str(row["root_domain"]): int(row["n"]) for row in domains},
    }


def same_decision(previous: Any, current: Mapping[str, Any]) -> bool:
    """True when the stored decision equals the new one apart from when it was recorded."""
    previous = decode_json(previous)
    if not isinstance(previous, dict):
        return False
    current = json.loads(json.dumps(dict(current), default=str))  # compare as stored (JSON values)
    strip = lambda value: {key: item for key, item in value.items() if key != "recorded_at"}  # noqa: E731
    return strip(previous) == strip(current)


__all__ = [
    "ASM_DISPATCH_TARGETS_PER_TICK",
    "ASM_RECHECK_MAX_SECONDS",
    "AsmDueSchedule",
    "decode_json",
    "load_counts",
    "load_due_targets",
    "same_decision",
]
