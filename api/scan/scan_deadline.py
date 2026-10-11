"""The Scan's own time limit (``max_duration_seconds``), enforced by the worker that runs it.

Before this, nothing in the V2 action path read ``max_duration_seconds``: an overlong Scan ran
until the control plane's stale-scan sweep found it about 50 % past its limit and marked it
``failed`` with no findings, because the V2 worker writes no legacy checkpoint for the sweep to
recover. The limit is now the worker's to keep, the way a withdrawn authorization is
(``action_authority_guard``):

* Work stops at ``deadline_at``: the Scan's start plus ``max_duration_seconds``, less a small
  reserve so that finalizing the report also fits inside the limit.
* An action still running at the deadline is interrupted through the same action-local signal
  its adapter already checks (``action_interruption``). What it observed before the stop is
  kept and its receipt is ``partial`` with reason ``scan_time_limit``. An adapter that has not
  stopped ``stop_grace_seconds`` later is cancelled; what it did is unknown, so it fails and
  keeps its full reservation.
* An action that has not started by the deadline is not started: it settles ``timed_out`` with
  reason ``scan_time_limit`` and nothing charged. No further continuation round is compiled.
* ``finalize.report`` always runs; it sends no target traffic. The report keeps every finding
  confirmed before the stop, its coverage is ``partial`` and it names the stop.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
import sys
import time
from typing import Any, Callable, Mapping
import uuid

from .capability_result import CapabilityResultReason


SCAN_TIME_LIMIT = CapabilityResultReason.SCAN_TIME_LIMIT.value
# Finalizing reads settled receipts and sends no traffic; it takes seconds. The reserve keeps
# that, and the wind-down of an interrupted action, inside the configured limit.
FINALIZATION_RESERVE_FRACTION = 0.05
FINALIZATION_RESERVE_FLOOR_SECONDS = 15.0
FINALIZATION_RESERVE_CEILING_SECONDS = 120.0
# How long an action stopped at the deadline may take to wind down through its own stop
# checks before it is cancelled outright.
TIME_LIMIT_STOP_GRACE_SECONDS = 15.0
FINALIZER_ACTION_ID = "finalize.report"


def finalization_reserve_seconds(max_duration_seconds: int | float) -> float:
    """Seconds held back from the work deadline for the stop and the report."""
    limit = max(0.0, float(max_duration_seconds))
    reserve = min(
        FINALIZATION_RESERVE_CEILING_SECONDS,
        max(FINALIZATION_RESERVE_FLOOR_SECONDS, limit * FINALIZATION_RESERVE_FRACTION),
    )
    # A very short limit still leaves most of it for work.
    return min(reserve, limit / 4.0)


def _epoch(value: Any) -> float | None:
    if isinstance(value, datetime):
        moment = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return moment.timestamp()
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
        return float(value)
    return None


@dataclass
class ScanDeadline:
    """When the Scan's work must stop, and what the stop did."""

    started_at: float
    max_duration_seconds: int
    clock: Callable[[], float] = time.time
    stop_grace_seconds: float = TIME_LIMIT_STOP_GRACE_SECONDS
    reached_at: str | None = None
    interrupted_actions: list[str] = field(default_factory=list)
    not_run_actions: list[str] = field(default_factory=list)
    # Continuation rounds that were not compiled because the limit had passed.
    refused_rounds: int = 0

    @classmethod
    def for_scan(
        cls,
        *,
        started_at: Any,
        max_duration_seconds: Any,
        clock: Callable[[], float] = time.time,
    ) -> "ScanDeadline | None":
        """The deadline of a Scan that started at ``started_at``; ``None`` without a limit."""
        try:
            limit = int(max_duration_seconds)
        except (TypeError, ValueError):
            return None
        if limit <= 0:
            return None
        start = _epoch(started_at)
        if start is None:
            start = clock()
        return cls(started_at=start, max_duration_seconds=limit, clock=clock)

    @property
    def deadline_at(self) -> float:
        return (
            self.started_at
            + self.max_duration_seconds
            - finalization_reserve_seconds(self.max_duration_seconds)
        )

    def remaining_seconds(self) -> float:
        return self.deadline_at - self.clock()

    def reached(self) -> bool:
        if self.remaining_seconds() > 0:
            return False
        self._mark()
        return True

    def _mark(self) -> None:
        if self.reached_at is None:
            self.reached_at = datetime.now(timezone.utc).isoformat()

    def record_interrupted(self, action_id: str) -> None:
        self._mark()
        if action_id not in self.interrupted_actions:
            self.interrupted_actions.append(action_id)

    def record_not_run(self, action_id: str) -> None:
        self._mark()
        if action_id not in self.not_run_actions:
            self.not_run_actions.append(action_id)

    def record_refused_round(self) -> None:
        """A further work round was not compiled because the limit had passed."""
        self._mark()
        self.refused_rounds += 1

    @property
    def stopped(self) -> bool:
        return bool(self.interrupted_actions or self.not_run_actions or self.refused_rounds)

    def annotate(self, report: dict[str, Any]) -> dict[str, Any]:
        """Record on the Scan report that it stopped at its time limit.

        Findings confirmed before the stop are kept; coverage is ``partial`` (a worse status,
        failed or cancelled, is kept), and the grade is marked unreliable.
        """
        if not self.stopped:
            return report
        stop = {
            "reason_code": SCAN_TIME_LIMIT,
            "max_duration_seconds": self.max_duration_seconds,
            "started_at": datetime.fromtimestamp(self.started_at, timezone.utc).isoformat(),
            "work_deadline_at": datetime.fromtimestamp(self.deadline_at, timezone.utc).isoformat(),
            "observed_at": self.reached_at,
            "interrupted_actions": list(self.interrupted_actions),
            "not_run_actions": list(self.not_run_actions),
            "continuation_rounds_not_run": self.refused_rounds,
            "message": (
                "The scan stopped at its time limit; findings confirmed before the stop are "
                "kept and coverage is incomplete"
            ),
        }
        coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else {}
        reasons = [str(item) for item in coverage.get("reasons") or () if str(item).strip()]
        status = str(coverage.get("status") or "").strip().lower()
        status = "partial" if status in {"", "complete", "completed"} else status
        report["coverage"] = {
            **coverage,
            "status": status,
            "reasons": [*reasons, *([] if SCAN_TIME_LIMIT in reasons else [SCAN_TIME_LIMIT])],
        }
        metadata = report.get("scan_metadata") if isinstance(report.get("scan_metadata"), dict) else {}
        reliability = [
            str(item) for item in metadata.get("grade_reliability_reasons") or () if str(item).strip()
        ]
        report["scan_metadata"] = {
            **metadata,
            "status": status,
            # Stopped at the limit is never complete, even when coverage is already worse.
            "partial": True,
            "grade_reliable": False,
            "grade_reliability_reasons": [
                *reliability, *([] if SCAN_TIME_LIMIT in reliability else [SCAN_TIME_LIMIT]),
            ],
            "stopped_at_time_limit": True,
            "time_limit_stop": stop,
        }
        return report


async def load_scan_deadline(
    pool: Any, *, scan_id: str, options: Mapping[str, Any], max_duration_seconds: Any,
    own_max_duration_seconds: Any = None,
) -> ScanDeadline | None:
    """The time limit this execution must keep.

    A Scan keeps its own limit from its own start. A shard keeps whichever ends first: its
    parent Scan's limit (``max_duration_seconds``) from the parent's start, or its own
    (``own_max_duration_seconds``, a shard budget may be smaller) from its own start. A start
    that cannot be read is measured from now, never unlimited.
    """
    authority = options.get("_v2_worker_authority")
    root_id = (
        str(authority.get("parent_scan_id") or "") if isinstance(authority, Mapping) else ""
    ) or str(scan_id)
    starts: dict[str, Any] = {}
    try:
        async with pool.acquire() as conn:
            for candidate in dict.fromkeys((root_id, str(scan_id))):
                starts[candidate] = await conn.fetchval(
                    "SELECT started_at FROM scans WHERE id=$1", uuid.UUID(candidate),
                )
    except Exception as exc:
        print(f"[scan] scan {str(scan_id)[:8]} start time unavailable ({type(exc).__name__}); "
              "its time limit runs from now", file=sys.stderr, flush=True)
    own_start = starts.get(str(scan_id))
    candidates = [
        ScanDeadline.for_scan(
            started_at=starts.get(root_id) or own_start, max_duration_seconds=max_duration_seconds,
        ),
    ]
    if root_id != str(scan_id) and own_max_duration_seconds is not None:
        candidates.append(ScanDeadline.for_scan(
            started_at=own_start, max_duration_seconds=own_max_duration_seconds,
        ))
    found = [item for item in candidates if item is not None]
    return min(found, key=lambda item: item.deadline_at) if found else None


def _limit(value: Any) -> int | None:
    try:
        limit = int(value)
    except (TypeError, ValueError):
        return None
    return limit if limit > 0 else None


def node_scan_deadline(
    options: Mapping[str, Any], *, clock: Callable[[], float] = time.time,
) -> ScanDeadline | None:
    """The time limit a fleet node keeps, measured from when it starts the Scan.

    A node has no database to read the Scan's start from; it starts the work as soon as it
    leases it, so its own start is the nearest it can measure. A shard keeps the smaller of the
    Scan's limit and its own.
    """
    limits: list[int] = []
    plan = options.get("scan_execution_plan")
    budget = plan.get("budget") if isinstance(plan, Mapping) else None
    if isinstance(budget, Mapping) and _limit(budget.get("max_duration_seconds")):
        limits.append(int(budget["max_duration_seconds"]))
    shard = options.get("canonical_shard_authority")
    sub_budget = shard.get("sub_budget") if isinstance(shard, Mapping) else None
    if isinstance(sub_budget, Mapping) and _limit(sub_budget.get("max_duration_seconds")):
        limits.append(int(sub_budget["max_duration_seconds"]))
    if not limits:
        return None
    return ScanDeadline.for_scan(started_at=clock(), max_duration_seconds=min(limits), clock=clock)


__all__ = [
    "FINALIZER_ACTION_ID",
    "SCAN_TIME_LIMIT",
    "ScanDeadline",
    "TIME_LIMIT_STOP_GRACE_SECONDS",
    "finalization_reserve_seconds",
    "load_scan_deadline",
    "node_scan_deadline",
]
