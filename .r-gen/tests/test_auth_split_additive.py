"""Additive auth-state testing: authenticating must ADD an anonymous baseline,
never REPLACE it, and must keep user1+user2 together so cross-user BOLA still
runs. Pins the two-way auth_split plan and the BOLA-preserving expansion.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

import parallel_scan as ps  # noqa: E402


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


def _states(plan):
    return sorted(str(s.options.get("auth_state")) for s in plan.shards)


def test_auth_split_primary_only_is_two_way_additive():
    plan = ps.plan_shards(
        {**ACTIVE, "parallel": True, "auth_header": "Bearer u1"}, strategy="auth_split")
    assert plan.is_parallel is True
    assert len(plan.shards) == 2
    assert _states(plan) == ["anonymous", "user1"]
    authed = next(s for s in plan.shards if s.options.get("auth_state") == "user1")
    anon = next(s for s in plan.shards if s.options.get("auth_state") == "anonymous")
    # authed keeps creds; anonymous strips them
    assert authed.options.get("auth_header") == "Bearer u1"
    assert not anon.options.get("auth_header")


def test_auth_split_keeps_user1_and_user2_together_for_bola():
    # The BOLA trap: a per-identity {anon,user1,user2} split leaves no shard with
    # BOTH user1 and user2 creds, silently killing cross-user BOLA. The two-way
    # split must keep them together in the full-context authed shard.
    plan = ps.plan_shards(
        {**ACTIVE, "parallel": True,
         "auth_header": "Bearer u1", "user2_header": "Bearer u2"}, strategy="auth_split")
    assert len(plan.shards) == 2
    assert _states(plan) == ["anonymous", "user1"]
    authed = next(s for s in plan.shards if s.options.get("auth_state") == "user1")
    # BOTH principals present in one shard -> check_bola can run.
    assert authed.options.get("auth_header") == "Bearer u1"
    assert authed.options.get("user2_header") == "Bearer u2"
    anon = next(s for s in plan.shards if s.options.get("auth_state") == "anonymous")
    assert not anon.options.get("auth_header")
    assert not anon.options.get("user2_header")


def test_auth_split_no_creds_degrades_to_single_scan():
    plan = ps.plan_shards(
        {**ACTIVE, "parallel": True}, strategy="auth_split")
    assert plan.is_parallel is False
    assert len(plan.shards) == 1


def test_auth_split_is_self_contained_not_shared_expansion():
    # auth_split does its OWN two-way split; the shared _expand_auth_states keeps
    # its intentional per-identity cross-product for coverage's per-principal
    # endpoint coverage (unchanged). Guards against accidentally coupling them.
    base = [ps.ShardSpec(0, "base", {**ACTIVE,
                                     "auth_header": "u1", "user2_header": "u2"})]
    opts = {"auth_state_shards": True, "auth_header": "u1", "user2_header": "u2"}
    out = ps._expand_auth_states(base, opts, [])
    # shared expansion stays 3-way (anon/user1/user2) — coverage relies on it
    assert len(out) == 3
    assert sorted(str(s.options.get("auth_state")) for s in out) == \
        ["anonymous", "user1", "user2"]


def test_available_auth_states_reports_all_three():
    assert ps.available_auth_states({"auth_header": "u1", "user2_header": "u2"}) == \
        ["anonymous", "user1", "user2"]
