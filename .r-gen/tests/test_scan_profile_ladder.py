from api.scan.contracts import BUDGET_PROFILES, resolve_scan_contract


def test_scan_profile_ladder_restores_depth_without_unreachable_tool_time():
    expected = {
        "fast": (1_800, 5_000),
        "balanced": (3_600, 20_000),
        "thorough": (10_800, 60_000),
        "deep": (21_600, 150_000),
    }

    assert set(BUDGET_PROFILES) == set(expected)
    for name, (wall, requests) in expected.items():
        profile = BUDGET_PROFILES[name]
        assert profile.max_duration_seconds == wall
        assert profile.max_http_requests == requests
        assert profile.max_tool_wall_seconds <= profile.max_duration_seconds


def test_deep_is_a_canonical_opt_in_profile_and_advanced_limits_only_lower_it():
    contract = resolve_scan_contract(
        budget_profile="deep",
        policy={"preset": "passive"},
        advanced={"max_duration_seconds": 3_600, "max_http_requests": 20_000},
    )

    assert contract.budget_profile == "deep"
    assert contract.budget.max_duration_seconds == 3_600
    assert contract.budget.max_http_requests == 20_000
