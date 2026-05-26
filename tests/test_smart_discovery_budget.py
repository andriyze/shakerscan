import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools.discovery import (  # noqa: E402
    _limit_api_probe_candidates,
    _limit_recursive_directories,
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


def test_recursive_directory_limit_prioritizes_api_and_sensitive_paths():
    directories = [
        "/static/",
        "/marketing/",
        "/api/users/",
        "/docs/",
        "/admin/",
        "/rest/products/",
        "/images/",
    ]

    limited = _limit_recursive_directories(directories, max_bases=3)

    assert limited == ["/api/users/", "/rest/products/", "/admin/"]


def test_recursive_directory_limit_zero_disables_fuzzing_bases():
    assert _limit_recursive_directories(["/api/", "/admin/"], max_bases=0) == []
