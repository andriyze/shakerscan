from scanner.constants import (
    resolve_bola_deadline_seconds,
    resolve_phase4_max_seconds,
    resolve_scan_budget,
)


def test_resolve_scan_budget_applies_profile_defaults():
    fast = resolve_scan_budget("smart", "fast")
    thorough = resolve_scan_budget("smart", "thorough")

    assert fast["budget_profile"] == "fast"
    assert thorough["budget_profile"] == "thorough"
    assert thorough["max_urls"] > fast["max_urls"]
    assert thorough["active_max_endpoints"] > fast["active_max_endpoints"]
    assert thorough["nuclei_early_stop"] is False


def test_resolve_scan_budget_accepts_safe_custom_overrides():
    budget = resolve_scan_budget(
        "smart",
        "balanced",
        {
            "max_urls": "2500",
            "active_max_seconds": 1800,
            "nuclei_early_stop": "false",
            "max_findings_per_family": -1,
            "ignored": 123,
        },
    )

    assert budget["max_urls"] == 2500
    assert budget["active_max_seconds"] == 1800
    assert budget["nuclei_early_stop"] is False
    assert budget["max_findings_per_family"] is None
    assert "ignored" not in budget


def test_resolve_scan_budget_accepts_parameter_discovery_overrides():
    budget = resolve_scan_budget(
        "smart",
        "balanced",
        {"param_discovery_url_limit": 4, "param_discovery_max_params": 6},
    )

    assert budget["param_discovery_url_limit"] == 4
    assert budget["param_discovery_max_params"] == 6


def test_resolve_scan_budget_accepts_phase4_override():
    budget = resolve_scan_budget("smart", "balanced", {"phase4_max_seconds": 45})

    assert budget["phase4_max_seconds"] == 45


def test_phase4_budget_is_capped_for_active_smart_scans():
    budget = {"active_max_seconds": 180}

    phase4_max = resolve_phase4_max_seconds(
        budget,
        smart_mode=True,
        active_checks=True,
        default_seconds=360,
    )

    assert phase4_max == 60


def test_phase4_budget_uses_explicit_lower_override():
    budget = {"active_max_seconds": 180, "phase4_max_seconds": 30}

    phase4_max = resolve_phase4_max_seconds(
        budget,
        smart_mode=True,
        active_checks=True,
        default_seconds=360,
    )

    assert phase4_max == 30


def test_bola_deadline_keeps_profile_floor_without_custom_budget():
    assert resolve_bola_deadline_seconds({"active_max_seconds": 90}, None) == 300


def test_bola_deadline_honors_explicit_custom_budget():
    assert (
        resolve_bola_deadline_seconds(
            {"active_max_seconds": 90},
            {"active_max_seconds": 90},
        )
        == 90
    )


def test_custom_budget_cannot_disable_watchdog_timeout():
    budget = resolve_scan_budget("standard", "balanced", {"max_duration_minutes": 0})

    assert budget["max_duration_minutes"] == 1


def test_custom_budget_is_capped_to_generous_ceiling():
    # custom_budget is intentionally allowed to exceed the exhaustive PROFILE so
    # operators can dial in huge on-demand budgets; it is capped at the generous
    # SCAN_BUDGET_CEILINGS, not the per-scan-type exhaustive default.
    from scanner.constants import SCAN_BUDGET_CEILINGS

    budget = resolve_scan_budget("quick", "balanced", {"max_urls": 10**9, "active_max_endpoints": 10**9})

    assert budget["max_urls"] == SCAN_BUDGET_CEILINGS["max_urls"]
    assert budget["active_max_endpoints"] == SCAN_BUDGET_CEILINGS["active_max_endpoints"]
    # A value within the ceiling but above the exhaustive profile is honored.
    big = resolve_scan_budget("smart", "balanced", {"active_max_endpoints": 2000})
    assert big["active_max_endpoints"] == 2000  # exhaustive profile default is only 300


def test_invalid_budget_profile_falls_back_to_balanced():
    budget = resolve_scan_budget("standard", "whatever")

    assert budget["budget_profile"] == "balanced"
    assert budget["scan_type"] == "standard"
