import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools.discovery import (  # noqa: E402
    _limit_api_probe_candidates,
    _plan_api_base_probe_budget,
    calculate_adaptive_depth,
)


def test_smart_discovery_uses_conservative_depth_without_signals():
    depth, paths_per_level = calculate_adaptive_depth({}, base_depth=3)

    assert depth == 2
    assert paths_per_level == 8


def test_smart_discovery_expands_when_sql_signals_exist():
    depth, paths_per_level = calculate_adaptive_depth({"sql_errors": True}, base_depth=3)

    assert depth > 2
    assert paths_per_level > 8


def test_api_probe_candidate_limit_applies_after_common_paths_are_merged():
    candidates = _limit_api_probe_candidates(["/search", "/api/users", "/search"], api_probe_limit=1)

    assert candidates == ["/search"]


def test_api_probe_candidate_limit_zero_disables_probing():
    candidates = _limit_api_probe_candidates(["/search", "/api/users"], api_probe_limit=0)

    assert candidates == []


def test_api_base_probe_budget_respects_small_limits():
    plan = _plan_api_base_probe_budget({"/api/", "/api/v1/", "/rest/"}, api_probe_limit=2)

    assert sum(limit for _, limit in plan) == 2
    assert len(plan) == 2
    assert all(limit == 1 for _, limit in plan)
