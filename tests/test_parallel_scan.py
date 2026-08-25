"""Tests for parallel scan planning and merge reconciliation.

Covers the pure planner logic (api/parallel_scan.py) and the merge-enqueue
barrier reconciliation using lightweight fakes for the DB connection and Redis.
"""

import asyncio
import json
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import parallel_scan  # noqa: E402
from parallel_scan import plan_shards, reconcile_parallel_parent  # noqa: E402


ACTIVE = {
    "scan_policy": {"active_testing": True, "include_families": []},
    "active": True,
    "budget_profile": "balanced",
    "resolved_scan_budget": {
        "max_http_requests": 5000,
        "max_endpoints": 500,
        "max_browser_actions": 100,
        "max_tool_wall_seconds": 900,
    },
    "resolved_budget": {
        "request_max": 5000,
        "max_urls": 500,
        "browser_max_pages": 100,
        "phase4_max_seconds": 900,
        "active_max_endpoints": 500,
        "active_max_seconds": 900,
    },
}
PASSIVE = {
    **ACTIVE,
    "scan_policy": {"active_testing": False, "include_families": []},
    "active": False,
}


def test_auth_costing_recognizes_managed_profiles_and_auth_flows():
    assert parallel_scan._options_have_auth({
        "managed_credential_profiles": [{"auth_state": "user1", "profile_id": "p1"}],
    }) is True
    assert parallel_scan._options_have_auth({"auto_auth": True}) is True
    assert parallel_scan._options_have_auth({"auth_scenario_json": "{}"}) is True
    assert parallel_scan._options_have_auth({}) is False


# ---------------------------------------------------------------------------
# Planner: family strategy
# ---------------------------------------------------------------------------

def test_family_default_produces_broad_sqli_xss():
    plan = plan_shards({**ACTIVE},
                       requested_shards="auto", strategy="family", worker_count=4)
    assert plan.strategy == "family"
    labels = [s.label for s in plan.shards]
    assert labels == ["broad", "sqli", "xss"]


def test_family_specialization_uses_canonical_family_scope_only():
    plan = plan_shards({**ACTIVE, "budget_profile": "balanced"}, strategy="family", requested_shards=3)
    by_label = {s.label: s.options for s in plan.shards}
    assert by_label["broad"]["coverage_attempt_family"] == "all"
    assert by_label["sqli"]["coverage_attempt_family"] == "sqli"
    assert by_label["sqli"]["no_early_stop"] is True
    assert by_label["xss"]["coverage_attempt_family"] == "xss"
    assert all(
        not {"sqli", "xss", "check_family", "asm_check_family"}.intersection(options)
        for options in by_label.values()
    )


def test_family_preserves_parent_budget_profile():
    plan = plan_shards({**ACTIVE, "budget_profile": "exhaustive"}, strategy="family", requested_shards=2)
    by_label = {s.label: s.options for s in plan.shards}
    assert by_label["sqli"]["budget_profile"] == "exhaustive"


def test_family_caps_at_three_with_note():
    plan = plan_shards({**ACTIVE},
                       strategy="family", requested_shards=9)
    assert plan.shard_count == 3
    assert any("caps at 3" in n for n in plan.notes)


def test_family_passive_scan_degrades_to_single_shard():
    plan = plan_shards({**PASSIVE},
                       strategy="family", requested_shards=3)
    assert plan.shard_count == 1
    assert plan.is_parallel is False
    assert any("passive" in n for n in plan.notes)


def test_requested_shards_can_reduce_below_three():
    plan = plan_shards({**ACTIVE},
                       strategy="family", requested_shards=2)
    assert [s.label for s in plan.shards] == ["broad", "sqli"]
    # indices are contiguous
    assert [s.index for s in plan.shards] == [0, 1]


# ---------------------------------------------------------------------------
# Planner: scope strategy
# ---------------------------------------------------------------------------

def test_scope_partitions_endpoints_round_robin():
    eps = [f"GET /api/x{i}?id=1" for i in range(7)]
    plan = plan_shards({**ACTIVE, "custom_endpoints": eps}, strategy="scope", requested_shards=3)
    assert plan.strategy == "scope"
    assert plan.shard_count == 3
    # every endpoint assigned exactly once, no overlap
    assigned = [e for s in plan.shards for e in s.options["custom_endpoints"]]
    assert sorted(assigned) == sorted(eps)
    assert len(assigned) == len(eps)


def test_scope_ignores_duplicate_empty_and_non_string_endpoints():
    eps = [" GET /a?id=1 ", "", "GET /b?id=2", "GET /a?id=1", None, 7]
    plan = plan_shards({**ACTIVE, "custom_endpoints": eps}, strategy="scope", requested_shards=3)
    assert plan.strategy == "scope"
    assert plan.shard_count == 2
    assigned = [e for s in plan.shards for e in s.options["custom_endpoints"]]
    assert assigned == ["GET /a?id=1", "GET /b?id=2"]


def test_scope_trims_discovery_budget():
    eps = [f"GET /api/x{i}?id=1" for i in range(4)]
    plan = plan_shards({**ACTIVE, "custom_endpoints": eps}, strategy="scope", requested_shards=2)
    for s in plan.shards:
        assert s.options["custom_budget"]["max_duration_minutes"] == 8
        assert s.options["custom_budget"]["max_urls"] == 150
        assert s.options["custom_budget"]["browser_max_pages"] == 5
        assert s.options["custom_budget"]["nuclei_max_targets"] == 120
        assert s.options["custom_budget"]["phase4_max_seconds"] == 20
        assert s.options["custom_budget"]["active_max_seconds"] == 90
        assert s.options["custom_budget"]["active_max_endpoints"] == 2
        assert s.options["custom_budget"]["active_params_per_endpoint"] == 2
        assert s.options["custom_budget"]["smart_bola_max_endpoints"] == 2


def test_scope_partitions_parent_request_budget_without_multiplication():
    eps = [f"GET /api/x{i}" for i in range(6)]
    parent_request_max = 500
    parent_options = {
        **PASSIVE,
        "custom_endpoints": eps,
        "custom_budget": {"request_max": parent_request_max},
    }

    plan = plan_shards(
        parent_options,
        strategy="scope",
        requested_shards=6,
    )

    child_limits = [shard.options["custom_budget"]["request_max"] for shard in plan.shards]
    assert len(child_limits) == 6
    assert all(limit > 0 for limit in child_limits)
    assert sum(child_limits) == parent_request_max
    assert all(shard.options["resolved_budget"]["request_max"] == limit
               for shard, limit in zip(plan.shards, child_limits))
    assert any("without exceeding parent request_max" in note for note in plan.notes)


def test_scope_request_budget_smaller_than_requested_fanout_reduces_shards():
    eps = [f"GET /api/x{i}" for i in range(6)]
    plan = plan_shards(
        {
            **PASSIVE,
            "custom_endpoints": eps,
            "custom_budget": {"request_max": 3},
        },
        strategy="scope",
        requested_shards=6,
    )

    assert plan.shard_count == 3
    assert sum(shard.options["custom_budget"]["request_max"] for shard in plan.shards) == 3
    assigned = [endpoint for shard in plan.shards for endpoint in shard.options["custom_endpoints"]]
    assert sorted(assigned) == sorted(eps)


def test_scope_preserves_explicit_custom_budget_caps():
    eps = ["GET /a?id=1", "GET /b?id=2"]
    plan = plan_shards(
        {
            **ACTIVE,
            "custom_endpoints": eps,
            "custom_budget": {
                "max_urls": 25,
                "active_max_seconds": 30,
                "smart_bola_max_endpoints": 1,
            },
        },
        strategy="scope",
        requested_shards=2,
    )
    for s in plan.shards:
        assert s.options["custom_budget"]["max_urls"] == 25
        assert s.options["custom_budget"]["active_max_seconds"] == 30
        assert s.options["custom_budget"]["smart_bola_max_endpoints"] == 1


def test_scope_more_shards_than_endpoints_reduces():
    eps = ["GET /a?id=1", "GET /b?id=2"]
    plan = plan_shards({**ACTIVE, "custom_endpoints": eps}, strategy="scope", requested_shards=5)
    assert plan.shard_count == 2


def test_auto_picks_scope_when_endpoints_present():
    eps = ["GET /a?id=1", "GET /b?id=2", "GET /c?id=3"]
    plan = plan_shards({**ACTIVE, "custom_endpoints": eps}, strategy="auto", requested_shards=3)
    assert plan.strategy == "scope"


def test_auto_picks_family_without_endpoints():
    plan = plan_shards({**ACTIVE},
                       strategy="auto", requested_shards=3)
    assert plan.strategy == "family"


def test_scope_falls_back_to_family_with_one_endpoint():
    plan = plan_shards({**ACTIVE, "custom_endpoints": ["GET /a?id=1"]}, strategy="scope", requested_shards=3)
    assert plan.strategy == "family"


def test_scope_keeps_bola_producer_and_consumer_on_one_shard():
    # A collection (producer of resource ids) and its /{id} consumer must land on
    # the SAME shard, or the cross-principal BOLA differential can't harvest an id
    # from the producer response and replay it as the second principal.
    eps = [
        "GET /workshop/api/shop/orders",
        "GET /workshop/api/shop/orders/1",
        "GET /identity/api/v2/vehicle/vehicles",
        "GET /identity/api/v2/vehicle/5/location",
        "POST /community/api/v2/coupon/validate-coupon json:{\"coupon_code\":\"x\"}",
    ]
    plan = plan_shards(
        {
            **ACTIVE,
            "custom_endpoints": eps,
            "exploit_depth": True,
            "auth_header": "Bearer t",
            "user2_header": "Bearer u",
        },
        strategy="scope",
        requested_shards=5,
    )
    assert plan.strategy == "scope"

    def shard_of(ep):
        return next(i for i, s in enumerate(plan.shards) if ep in s.options["custom_endpoints"])

    # producer + consumer co-located for both resource families
    assert shard_of("GET /workshop/api/shop/orders") == shard_of("GET /workshop/api/shop/orders/1")
    assert shard_of("GET /identity/api/v2/vehicle/vehicles") == shard_of(
        "GET /identity/api/v2/vehicle/5/location"
    )
    # every endpoint still assigned exactly once
    assigned = [e for s in plan.shards for e in s.options["custom_endpoints"]]
    assert sorted(assigned) == sorted(eps)


def test_scope_heavy_shards_get_more_wallclock_and_active_budget():
    # exploit_depth (or auth) shards need real wall-clock or they hit the reaper.
    eps = ["GET /api/a", "GET /api/b"]
    plan = plan_shards(
        {**ACTIVE, "custom_endpoints": eps, "exploit_depth": True},
        strategy="scope",
        requested_shards=2,
    )
    for s in plan.shards:
        b = s.options["custom_budget"]
        # 1 endpoint/shard heavy: floor of 20 min (vs light 6) + 300s active (vs 60)
        assert b["max_duration_minutes"] == 20
        assert b["active_max_seconds"] == 300
        assert b["phase4_max_seconds"] == 180
        assert b["active_params_per_endpoint"] == 4


def test_scope_auth_alone_marks_shard_heavy():
    eps = ["GET /api/a", "GET /api/b"]
    plan = plan_shards(
        {**ACTIVE, "custom_endpoints": eps, "auth_header": "Bearer t"},
        strategy="scope",
        requested_shards=2,
    )
    assert all(s.options["custom_budget"]["max_duration_minutes"] == 20 for s in plan.shards)


def test_scope_light_shards_keep_raw_speed_budget():
    # No auth / no exploit_depth => unchanged raw-speed budget (regression guard).
    eps = ["GET /api/a", "GET /api/b"]
    plan = plan_shards(
        {**ACTIVE, "custom_endpoints": eps},
        strategy="scope",
        requested_shards=2,
    )
    for s in plan.shards:
        b = s.options["custom_budget"]
        assert b["max_duration_minutes"] == 6  # 4 + 2*1
        assert b["active_max_seconds"] == 90
        assert b["phase4_max_seconds"] == 20


# ---------------------------------------------------------------------------
# Planner: invariants
# ---------------------------------------------------------------------------

def test_orchestration_keys_never_leak_into_child_options():
    parent = {**ACTIVE, "parallel": True, "shards": 3, "shard_strategy": "family"}
    plan = plan_shards(parent, strategy="family", requested_shards=3)
    for shard in plan.shards:
        for key in parallel_scan.PARALLEL_OPTION_KEYS:
            assert key not in shard.options


def test_child_options_are_independent_copies():
    parent = {**ACTIVE, "custom_budget": {"max_urls": 999}}
    plan = plan_shards(parent, strategy="family", requested_shards=3)
    plan.shards[1].options["custom_budget"]["max_urls"] = 1
    # mutating one shard must not bleed into another or the parent
    assert parent["custom_budget"]["max_urls"] == 999
    assert plan.shards[0].options.get("custom_budget", {}).get("max_urls") != 1


def test_shards_request_coercion_rejects_bool():
    # bool is an int subclass; True must not be read as "1 shard"
    plan = plan_shards({**ACTIVE},
                       strategy="family", requested_shards=True, worker_count=4)
    assert plan.shard_count >= 2


def test_unknown_strategy_defaults_to_auto():
    plan = plan_shards({**ACTIVE},
                       strategy="banana", requested_shards=3)
    assert any("unknown strategy" in n for n in plan.notes)
    assert plan.strategy in ("family", "scope")


def test_max_shards_ceiling():
    eps = [f"GET /x{i}?id=1" for i in range(50)]
    plan = plan_shards({**ACTIVE, "custom_endpoints": eps}, strategy="scope", requested_shards=999)
    assert plan.shard_count <= parallel_scan.MAX_SHARDS


# ---------------------------------------------------------------------------
# Merge reconciliation (barrier -> enqueue merge exactly once)
# ---------------------------------------------------------------------------

class _FakeConn:
    """Minimal asyncpg-conn stand-in for reconcile_parallel_parent."""

    def __init__(self, total, non_terminal, parent_status="running", *, expected=None, fanout_complete=True):
        self._total = total
        self._non_terminal = non_terminal
        self._parent_status = parent_status
        self._expected = total if expected is None else expected
        self._fanout_complete = fanout_complete

    async def fetchrow(self, query, *args):
        return {
            "status": self._parent_status,
            "shard_count": self._expected,
            "options": {
                parallel_scan.PARALLEL_FANOUT_COMPLETE_KEY: self._fanout_complete,
                parallel_scan.PARALLEL_EXPECTED_SHARDS_KEY: self._expected,
            },
        }

    async def fetchval(self, query, *args):
        if "SELECT status" in query:
            return self._parent_status
        if "NOT IN" in query:
            return self._non_terminal
        return self._total


class _FakeRedis:
    def __init__(self):
        self.store = {}
        self.pushed = []
        self.calls = []

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return False
        self.store[key] = value
        return True

    def rpush(self, key, value):
        self.pushed.append((key, value))
        self.calls.append(("rpush", key, value))
        return len(self.pushed)

    def lpush(self, key, value):
        self.pushed.insert(0, (key, value))
        self.calls.append(("lpush", key, value))
        return len(self.pushed)

    def eval(self, _script, numkeys, guard_key, queue_name, guard_value, _ttl, payload):
        assert numkeys == 2
        self.calls.append(("eval", guard_key, queue_name))
        if guard_key in self.store:
            return 0
        self.store[guard_key] = guard_value
        self.lpush(queue_name, payload)
        return 1


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
    assert json.loads(payload)["placement"] == {"node_scope": "local"}
    assert r.calls[0][0] == "eval"
    assert r.calls[1][0] == "lpush"


def test_reconcile_waits_while_shards_pending():
    pid = str(uuid.uuid4())
    conn = _FakeConn(total=3, non_terminal=1)
    r = _FakeRedis()
    enqueued = _run(reconcile_parallel_parent(conn, pid, r, "scan_jobs"))
    assert enqueued is False
    assert r.pushed == []


def test_reconcile_waits_until_fanout_is_complete():
    pid = str(uuid.uuid4())
    conn = _FakeConn(total=1, non_terminal=0, expected=3, fanout_complete=False)
    r = _FakeRedis()
    assert _run(reconcile_parallel_parent(conn, pid, r, "scan_jobs")) is False
    assert r.pushed == []


def test_reconcile_requires_exact_expected_child_count():
    pid = str(uuid.uuid4())
    conn = _FakeConn(total=1, non_terminal=0, expected=3, fanout_complete=True)
    r = _FakeRedis()
    assert _run(reconcile_parallel_parent(conn, pid, r, "scan_jobs")) is False
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


def test_reconcile_skips_cancelled_parent():
    pid = str(uuid.uuid4())
    conn = _FakeConn(total=3, non_terminal=0, parent_status="cancelled")
    r = _FakeRedis()
    enqueued = _run(reconcile_parallel_parent(conn, pid, r, "scan_jobs"))
    assert enqueued is False
    assert r.pushed == []
    assert r.store[parallel_scan.merge_guard_key(pid)] == "cancelled"


def test_canonical_parallel_planning_uses_active_policy_without_a_scan_mode():
    options = {**ACTIVE}

    assert parallel_scan.resolve_auto_strategy(options, "auto") == "coverage"
    plan = parallel_scan.plan_shards(
        options,
        requested_shards=3,
        strategy="family",
        worker_count=3,
    )

    assert plan.is_parallel is True
    assert [shard.label for shard in plan.shards] == ["broad", "sqli", "xss"]
    assert all("scan_type" not in shard.options for shard in plan.shards)
