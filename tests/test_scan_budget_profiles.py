from scanner.constants import resolve_scan_budget


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


def test_custom_budget_cannot_disable_watchdog_timeout():
    budget = resolve_scan_budget("standard", "balanced", {"max_duration_minutes": 0})

    assert budget["max_duration_minutes"] == 1


def test_custom_budget_is_capped_to_scan_type_exhaustive_profile():
    budget = resolve_scan_budget("quick", "balanced", {"max_urls": 999999, "max_duration_minutes": 999999})

    assert budget["max_urls"] == 400
    assert budget["max_duration_minutes"] == 45


def test_invalid_budget_profile_falls_back_to_balanced():
    budget = resolve_scan_budget("standard", "whatever")

    assert budget["budget_profile"] == "balanced"
    assert budget["scan_type"] == "standard"
