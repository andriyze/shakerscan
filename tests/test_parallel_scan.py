"""Tests for parallel scan planning and merge reconciliation.

Covers the pure planner logic (api/parallel_scan.py) and the merge-enqueue
barrier reconciliation using lightweight fakes for the DB connection and Redis.
"""

import asyncio
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import parallel_scan  # noqa: E402
from parallel_scan import plan_shards, reconcile_parallel_parent  # noqa: E402


# ---------------------------------------------------------------------------
# Planner: family strategy
# ---------------------------------------------------------------------------

def test_family_default_produces_broad_sqli_xss():
    plan = plan_shards({"scan_type": "smart"}, scan_type="smart",
                       requested_shards="auto", strategy="family", worker_count=4)
    assert plan.strategy == "family"
    labels = [s.label for s in plan.shards]
    assert labels == ["broad", "sqli", "xss"]


def test_family_focused_flags_and_budget_bump():
    plan = plan_shards({"scan_type": "smart", "budget_profile": "balanced"},
                       scan_type="smart", strategy="family", requested_shards=3)
    by_label = {s.label: s.options for s in plan.shards}
    # broad keeps full breadth: neither focused flag forced on
    assert not by_label["broad"].get("sqli")
    assert not by_label["broad"].get("xss")
    # sqli shard is focused on SQLi and deepened
    assert by_label["sqli"]["sqli"] is True
    assert by_label["sqli"]["xss"] is False
    assert by_label["sqli"]["no_early_stop"] is True
    assert by_label["sqli"]["budget_profile"] == "thorough"
    # xss shard is focused on XSS
    assert by_label["xss"]["xss"] is True
    assert by_label["xss"]["sqli"] is False


def test_family_respects_higher_explicit_budget():
    plan = plan_shards({"scan_type": "smart", "budget_profile": "exhaustive"},
                       scan_type="smart", strategy="family", requested_shards=2)
    by_label = {s.label: s.options for s in plan.shards}
    # exhaustive is already deeper than thorough; do not downgrade it
    assert by_label["sqli"]["budget_profile"] == "exhaustive"


def test_family_caps_at_three_with_note():
    plan = plan_shards({"scan_type": "aggressive"}, scan_type="aggressive",
                       strategy="family", requested_shards=9)
    assert plan.shard_count == 3
    assert any("caps at 3" in n for n in plan.notes)


def test_family_passive_scan_degrades_to_single_shard():
    plan = plan_shards({"scan_type": "standard"}, scan_type="standard",
                       strategy="family", requested_shards=3)
    assert plan.shard_count == 1
    assert plan.is_parallel is False
    assert any("passive" in n for n in plan.notes)


def test_requested_shards_can_reduce_below_three():
    plan = plan_shards({"scan_type": "smart"}, scan_type="smart",
                       strategy="family", requested_shards=2)
    assert [s.label for s in plan.shards] == ["broad", "sqli"]
    # indices are contiguous
    assert [s.index for s in plan.shards] == [0, 1]


# ---------------------------------------------------------------------------
# Planner: scope strategy
# ---------------------------------------------------------------------------

def test_scope_partitions_endpoints_round_robin():
    eps = [f"GET /api/x{i}?id=1" for i in range(7)]
    plan = plan_shards({"scan_type": "smart", "custom_endpoints": eps},
                       scan_type="smart", strategy="scope", requested_shards=3)
    assert plan.strategy == "scope"
    assert plan.shard_count == 3
    # every endpoint assigned exactly once, no overlap
    assigned = [e for s in plan.shards for e in s.options["custom_endpoints"]]
    assert sorted(assigned) == sorted(eps)
    assert len(assigned) == len(eps)


def test_scope_trims_discovery_budget():
    eps = [f"GET /api/x{i}?id=1" for i in range(4)]
    plan = plan_shards({"scan_type": "smart", "custom_endpoints": eps},
                       scan_type="smart", strategy="scope", requested_shards=2)
    for s in plan.shards:
        assert s.options["custom_budget"]["max_urls"] == 150
        assert s.options["custom_budget"]["browser_max_pages"] == 5


def test_scope_more_shards_than_endpoints_reduces():
    eps = ["GET /a?id=1", "GET /b?id=2"]
    plan = plan_shards({"scan_type": "smart", "custom_endpoints": eps},
                       scan_type="smart", strategy="scope", requested_shards=5)
    assert plan.shard_count == 2


def test_auto_picks_scope_when_endpoints_present():
    eps = ["GET /a?id=1", "GET /b?id=2", "GET /c?id=3"]
    plan = plan_shards({"scan_type": "smart", "custom_endpoints": eps},
                       scan_type="smart", strategy="auto", requested_shards=3)
    assert plan.strategy == "scope"


def test_auto_picks_family_without_endpoints():
    plan = plan_shards({"scan_type": "smart"}, scan_type="smart",
                       strategy="auto", requested_shards=3)
    assert plan.strategy == "family"


def test_scope_falls_back_to_family_with_one_endpoint():
    plan = plan_shards({"scan_type": "smart", "custom_endpoints": ["GET /a?id=1"]},
                       scan_type="smart", strategy="scope", requested_shards=3)
    assert plan.strategy == "family"


# ---------------------------------------------------------------------------
# Planner: invariants
# ---------------------------------------------------------------------------

def test_orchestration_keys_never_leak_into_child_options():
    parent = {"scan_type": "smart", "parallel": True, "shards": 3, "shard_strategy": "family"}
    plan = plan_shards(parent, scan_type="smart", strategy="family", requested_shards=3)
    for shard in plan.shards:
        for key in parallel_scan.PARALLEL_OPTION_KEYS:
            assert key not in shard.options


def test_child_options_are_independent_copies():
    parent = {"scan_type": "smart", "custom_budget": {"max_urls": 999}}
    plan = plan_shards(parent, scan_type="smart", strategy="family", requested_shards=3)
    plan.shards[1].options["custom_budget"]["max_urls"] = 1
    # mutating one shard must not bleed into another or the parent
    assert parent["custom_budget"]["max_urls"] == 999
    assert plan.shards[0].options.get("custom_budget", {}).get("max_urls") != 1


def test_shards_request_coercion_rejects_bool():
    # bool is an int subclass; True must not be read as "1 shard"
    plan = plan_shards({"scan_type": "smart"}, scan_type="smart",
                       strategy="family", requested_shards=True, worker_count=4)
    assert plan.shard_count >= 2


def test_unknown_strategy_defaults_to_auto():
    plan = plan_shards({"scan_type": "smart"}, scan_type="smart",
                       strategy="banana", requested_shards=3)
    assert any("unknown strategy" in n for n in plan.notes)
    assert plan.strategy in ("family", "scope")


def test_max_shards_ceiling():
    eps = [f"GET /x{i}?id=1" for i in range(50)]
    plan = plan_shards({"scan_type": "smart", "custom_endpoints": eps},
                       scan_type="smart", strategy="scope", requested_shards=999)
    assert plan.shard_count <= parallel_scan.MAX_SHARDS


# ---------------------------------------------------------------------------
# Merge reconciliation (barrier -> enqueue merge exactly once)
# ---------------------------------------------------------------------------

class _FakeConn:
    """Minimal asyncpg-conn stand-in for reconcile_parallel_parent."""

    def __init__(self, total, non_terminal):
        self._total = total
        self._non_terminal = non_terminal

    async def fetchval(self, query, *args):
        if "NOT IN" in query:
            return self._non_terminal
        return self._total


class _FakeRedis:
    def __init__(self):
        self.store = {}
        self.pushed = []

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return False
        self.store[key] = value
        return True

    def rpush(self, key, value):
        self.pushed.append((key, value))
        return len(self.pushed)


def _run(coro):
    return asyncio.run(coro)


def test_reconcile_enqueues_merge_when_all_terminal():
    pid = str(uuid.uuid4())
    conn = _FakeConn(total=3, non_terminal=0)
    r = _FakeRedis()
    enqueued = _run(reconcile_parallel_parent(conn, pid, r, "scan_jobs"))
    assert enqueued is True
    assert len(r.pushed) == 1
    queue, payload = r.pushed[0]
    assert queue == "scan_jobs"
    assert parallel_scan.MERGE_JOB_TYPE in payload
    assert pid in payload


def test_reconcile_waits_while_shards_pending():
    pid = str(uuid.uuid4())
    conn = _FakeConn(total=3, non_terminal=1)
    r = _FakeRedis()
    enqueued = _run(reconcile_parallel_parent(conn, pid, r, "scan_jobs"))
    assert enqueued is False
    assert r.pushed == []


def test_reconcile_enqueues_merge_only_once():
    pid = str(uuid.uuid4())
    conn = _FakeConn(total=2, non_terminal=0)
    r = _FakeRedis()
    first = _run(reconcile_parallel_parent(conn, pid, r, "scan_jobs"))
    second = _run(reconcile_parallel_parent(conn, pid, r, "scan_jobs"))
    assert first is True
    assert second is False  # SET NX guard blocks the second enqueue
    assert len(r.pushed) == 1


def test_reconcile_noop_when_no_children():
    pid = str(uuid.uuid4())
    conn = _FakeConn(total=0, non_terminal=0)
    r = _FakeRedis()
    enqueued = _run(reconcile_parallel_parent(conn, pid, r, "scan_jobs"))
    assert enqueued is False
    assert r.pushed == []
