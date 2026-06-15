"""Parallel scan orchestration: plan a parent scan into independent shards.

A parallel scan splits one logical scan of a single target across the worker
fleet (see docs/parallel-scan-architecture.md). The flow is a scatter-gather:

    POST /scans {parallel:true}
        -> parent scan row (scan_role='parent')
        -> scan_plan job
             -> N child scan rows (scan_role='shard') + N scan_shard jobs
        -> each shard runs run_scan() with a focused option override
        -> last shard to finish enqueues a scan_merge job
        -> scan_merge aggregates child results into the parent report

This module is the *planner*: it is pure logic (no I/O) so it can be unit
tested. Given the parent scan options it returns a ParallelPlan whose shards
each carry a full child-options dict (parent options + a focused override).

Two strategies:

  - ``scope``: partition an explicit ``custom_endpoints`` list across shards.
    Each shard tests only its slice with a trimmed discovery budget. This is a
    real division of work (genuine speed-up) and is the best fit for API
    targets where the endpoints are known up front.

  - ``family``: split active testing by capability using the scanner's focused
    flags (``--sqli`` / ``--xss``). One broad shard covers full breadth at the
    parent budget; additional shards run deeper, higher-budget SQLi- and
    XSS-focused passes. This buys *depth* (more coverage / larger budget in the
    same wall-clock), not raw speed, because discovery repeats per shard. The
    raw-speed "discover once, slice endpoints" path requires the scanner
    carve-out documented as a follow-up in the architecture doc.

``auto`` resolves to ``scope`` when >=2 custom endpoints are present, else
``family``.
"""

from __future__ import annotations

import copy
import json
import uuid
from dataclasses import dataclass, field
from typing import Any

# Job ``type`` values routed by the worker's process_job().
PLAN_JOB_TYPE = "scan_plan"
SHARD_JOB_TYPE = "scan_shard"
MERGE_JOB_TYPE = "scan_merge"

# Statuses that mean a scan row will not change on its own.
TERMINAL_STATUSES = ("completed", "failed", "cancelled")

# Option keys that control orchestration itself. They must never be propagated
# into a child shard's options or a shard would try to fan out recursively.
PARALLEL_OPTION_KEYS = ("parallel", "shards", "shard_strategy")

# Scan types that actually run active injection testing. ``family`` sharding is
# only meaningful for these; for passive types it degrades to a single shard.
ACTIVE_SCAN_TYPES = frozenset({"full", "aggressive", "smart"})

VALID_STRATEGIES = frozenset({"auto", "scope", "family"})

# Hard ceiling on shards regardless of request, so a stray ``shards: 999`` can't
# flood the queue. The worker fleet cap (POST /workers, 1-20) bounds throughput
# anyway; this just bounds the row/queue explosion per scan.
MAX_SHARDS = 12

# ``family`` strategy can express at most these distinct, non-overlapping shards
# with the focused flags the scanner exposes today.
FAMILY_SHARD_LABELS = ("broad", "sqli", "xss")


@dataclass
class ShardSpec:
    """One unit of fan-out work: a focused child scan."""

    index: int
    label: str
    options: dict[str, Any]


@dataclass
class ParallelPlan:
    """Result of planning. ``shards`` may be length 1 (caller should then fall
    back to a normal standalone scan rather than orchestrating)."""

    strategy: str
    shards: list[ShardSpec] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def shard_count(self) -> int:
        return len(self.shards)

    @property
    def is_parallel(self) -> bool:
        return len(self.shards) >= 2


def _base_child_options(parent_options: dict[str, Any]) -> dict[str, Any]:
    """Copy parent options minus the orchestration keys."""
    child = copy.deepcopy(parent_options or {})
    for key in PARALLEL_OPTION_KEYS:
        child.pop(key, None)
    return child


def _merge_custom_budget(options: dict[str, Any], overrides: dict[str, Any]) -> None:
    """Merge ``overrides`` into ``options['custom_budget']`` in place."""
    budget = dict(options.get("custom_budget") or {})
    budget.update(overrides)
    options["custom_budget"] = budget


def _coerce_shard_request(requested_shards: Any, worker_count: int) -> int:
    """Resolve the requested shard count to a concrete integer.

    ``"auto"``/None scales to the available worker fleet (so fan-out matches
    capacity), bounded to a sensible default range.
    """
    if isinstance(requested_shards, bool):  # bool is an int subclass; reject it
        requested_shards = None
    if isinstance(requested_shards, int) and requested_shards > 0:
        return min(requested_shards, MAX_SHARDS)
    if isinstance(requested_shards, str) and requested_shards.strip().isdigit():
        return min(max(1, int(requested_shards.strip())), MAX_SHARDS)
    # auto: one shard per available worker, clamped to [2, 4] for a balanced
    # default that does not monopolise the fleet.
    auto = max(2, min(4, int(worker_count or 0) or 3))
    return auto


def _partition_round_robin(items: list[Any], n: int) -> list[list[Any]]:
    """Split ``items`` into ``n`` round-robin buckets (balanced sizes)."""
    buckets: list[list[Any]] = [[] for _ in range(n)]
    for i, item in enumerate(items):
        buckets[i % n].append(item)
    return [b for b in buckets if b]


def _normalize_endpoint_list(endpoints: Any) -> list[str]:
    """Return non-empty, de-duplicated endpoint strings preserving order."""
    if not isinstance(endpoints, list):
        return []

    normalized: list[str] = []
    seen: set[str] = set()
    for endpoint in endpoints:
        if not isinstance(endpoint, str):
            continue
        value = endpoint.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return normalized


def _plan_scope(
    parent_options: dict[str, Any],
    endpoints: list[str],
    requested: int,
    notes: list[str],
) -> list[ShardSpec]:
    n = min(requested, len(endpoints))
    if n < 2:
        notes.append(
            f"scope strategy needs >=2 endpoints to fan out; got {len(endpoints)} "
            "- falling back to a single shard"
        )
    buckets = _partition_round_robin(list(endpoints), max(1, n))
    if len(buckets) < n:
        notes.append(f"scope shards reduced to {len(buckets)} (fewer endpoints than requested)")
    shards: list[ShardSpec] = []
    for i, slice_eps in enumerate(buckets):
        opts = _base_child_options(parent_options)
        opts["custom_endpoints"] = slice_eps
        # Endpoints are explicit, so a deep site crawl per shard is wasted work.
        # Trim discovery breadth while leaving active-testing budget intact.
        _merge_custom_budget(opts, {"max_urls": 150, "browser_max_pages": 5})
        shards.append(ShardSpec(index=i, label=f"scope[{i}]", options=opts))
    return shards


def _plan_family(
    parent_options: dict[str, Any],
    scan_type: str,
    requested: int,
    notes: list[str],
) -> list[ShardSpec]:
    if scan_type not in ACTIVE_SCAN_TYPES:
        notes.append(
            f"family strategy is only meaningful for active scan types "
            f"({', '.join(sorted(ACTIVE_SCAN_TYPES))}); '{scan_type}' is passive "
            "- running a single broad shard"
        )
        broad = _base_child_options(parent_options)
        return [ShardSpec(index=0, label="broad", options=broad)]

    # broad: full breadth at the parent budget (all active families).
    broad = _base_child_options(parent_options)

    # sqli: focused, deeper. Disable XSS so the scanner enters focused mode and
    # limits active modules to SQLi; bump depth/budget.
    sqli = _base_child_options(parent_options)
    sqli.update({"sqli": True, "xss": False, "no_early_stop": True, "thorough_params": True})
    if (sqli.get("budget_profile") or "balanced") in ("fast", "balanced"):
        sqli["budget_profile"] = "thorough"

    xss = _base_child_options(parent_options)
    xss.update({"xss": True, "sqli": False, "no_early_stop": True, "thorough_params": True})
    if (xss.get("budget_profile") or "balanced") in ("fast", "balanced"):
        xss["budget_profile"] = "thorough"

    ordered = [
        ShardSpec(index=0, label="broad", options=broad),
        ShardSpec(index=1, label="sqli", options=sqli),
        ShardSpec(index=2, label="xss", options=xss),
    ]

    n = min(requested, len(FAMILY_SHARD_LABELS))
    if requested > len(FAMILY_SHARD_LABELS):
        notes.append(
            f"family strategy caps at {len(FAMILY_SHARD_LABELS)} shards "
            f"(broad/sqli/xss); requested {requested}"
        )
    selected = ordered[:n]
    for i, shard in enumerate(selected):  # reindex contiguously
        shard.index = i
    return selected


def plan_shards(
    parent_options: dict[str, Any],
    *,
    scan_type: str,
    requested_shards: Any = "auto",
    strategy: str = "auto",
    worker_count: int = 0,
) -> ParallelPlan:
    """Build a ParallelPlan from parent scan options.

    Args:
        parent_options: the parent scan's options dict (as submitted).
        scan_type: resolved scan type (quick/standard/deep/full/aggressive/smart).
        requested_shards: int, numeric string, or "auto".
        strategy: "auto" | "scope" | "family".
        worker_count: current worker fleet size (used to auto-scale shards).
    """
    notes: list[str] = []
    strategy = (strategy or "auto").strip().lower()
    if strategy not in VALID_STRATEGIES:
        notes.append(f"unknown strategy '{strategy}', defaulting to auto")
        strategy = "auto"

    scan_type = (scan_type or "standard").strip().lower()
    endpoints = _normalize_endpoint_list(parent_options.get("custom_endpoints"))

    resolved = strategy
    if strategy == "auto":
        resolved = "scope" if len(endpoints) >= 2 else "family"

    requested = _coerce_shard_request(requested_shards, worker_count)

    if resolved == "scope":
        if len(endpoints) < 2:
            notes.append("no endpoint list to partition; switching to family strategy")
            resolved = "family"
        else:
            shards = _plan_scope(parent_options, endpoints, requested, notes)
            return ParallelPlan(strategy="scope", shards=shards, notes=notes)

    shards = _plan_family(parent_options, scan_type, requested, notes)
    return ParallelPlan(strategy="family", shards=shards, notes=notes)


# ---------------------------------------------------------------------------
# Orchestration helpers (Redis keys + merge reconciliation)
# ---------------------------------------------------------------------------

def shards_remaining_key(parent_id: str) -> str:
    return f"scan:{parent_id}:shards:remaining"


def merge_guard_key(parent_id: str) -> str:
    return f"scan:{parent_id}:merge:enqueued"


def merge_job(parent_id: str) -> dict[str, Any]:
    """Build the scan_merge job payload for a parent scan."""
    return {"type": MERGE_JOB_TYPE, "parent_scan_id": parent_id}


async def reconcile_parallel_parent(conn, parent_id: str, redis_client, queue_name: str) -> bool:
    """Enqueue the merge job once all of a parent's shards are terminal.

    Safe to call repeatedly and from multiple processes: the actual enqueue is
    guarded by a Redis SET NX so the merge runs exactly once. Returns True iff
    this call enqueued the merge.
    """
    pid = uuid.UUID(parent_id)
    parent_status = await conn.fetchval("SELECT status FROM scans WHERE id = $1", pid)
    if parent_status == "cancelled":
        try:
            redis_client.set(merge_guard_key(parent_id), "cancelled", nx=True, ex=86400)
        except Exception:
            pass
        return False
    total = await conn.fetchval(
        "SELECT count(*) FROM scans WHERE parent_scan_id = $1", pid
    )
    if not total:
        return False
    non_terminal = await conn.fetchval(
        """
        SELECT count(*) FROM scans
        WHERE parent_scan_id = $1 AND status NOT IN ('completed', 'failed', 'cancelled')
        """,
        pid,
    )
    if non_terminal:
        return False
    # All shards terminal — enqueue merge exactly once.
    if redis_client.set(merge_guard_key(parent_id), "1", nx=True, ex=86400):
        redis_client.rpush(queue_name, json.dumps(merge_job(parent_id)))
        return True
    return False
