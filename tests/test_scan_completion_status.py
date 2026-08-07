from scanner.scanner_tools.completion_status import build_scan_completion_status


def test_completion_status_detects_budget_in_multi_entry_sqlmap_skip_list():
    # When sqlmap_skipped is a list with one budget entry and one
    # non-budget entry (e.g. "no_candidates"), the joined-string heuristic
    # previously could miss budget-classification. Each entry must be
    # classified individually.
    status = build_scan_completion_status(
        coverage_status="complete",
        active_block={
            "sqlmap_skipped": [
                {"skip_reason": "no_candidates_found"},
                {"skip_reason": "primary_family_budget_exhausted"},
            ],
        },
    )

    assert status["budget_exhausted"] is True
    assert status["budget_exhausted_at"] == "active_enrichment"


def test_completion_status_surfaces_post_active_budget_skips():
    status = build_scan_completion_status(
        coverage_status="complete",
        active_block={
            "post_active_enrichment_skipped": "primary_family_budget_exhausted",
            "active_endpoint_budget": 5,
            "active_endpoints_discovered": 42,
            "active_endpoints_selected": 5,
            "active_endpoint_budget_capped": True,
            "sqlmap_skipped": [{"reason": "primary_family_budget_exhausted", "url": "https://example.test/search"}],
            "nosql_skipped": "primary_family_budget_exhausted",
            "dom_xss_skipped": "primary_family_budget_exhausted",
            "smart_bola_skipped": "primary_family_budget_exhausted",
        },
    )

    assert status["complete"] is False
    assert status["limited"] is True
    assert status["budget_exhausted"] is True
    assert status["budget_exhausted_at"] == "active_enrichment"
    assert status["capped_lists"]["active_endpoints"]["discovered"] == 42
    assert status["capped_lists"]["active_endpoints"]["selected"] == 5
    assert {entry["module"] for entry in status["skipped_modules"]} >= {
        "sqlmap",
        "nosql_injection",
        "dom_xss",
        "bola_idor",
    }


def test_completion_status_marks_clean_complete_scan():
    status = build_scan_completion_status(
        coverage_status="complete",
        checks_skipped=[],
        active_block={},
        discovery_summary={},
    )

    assert status["complete"] is True
    assert status["limited"] is False
    assert status["budget_exhausted"] is False
    assert status["skipped_modules"] == []
    assert status["capped_lists"] == {}


def test_completion_status_degrades_enforced_request_budget_stop():
    status = build_scan_completion_status(
        coverage_status="complete",
        request_budget={
            "mode": "enforce",
            "rejected_requests": 1,
            "budget_exhausted": True,
        },
    )

    assert status["complete"] is False
    assert status["limited"] is True
    assert status["budget_exhausted"] is True
    assert status["budget_exhausted_at"] == "request_budget"


def test_completion_status_does_not_call_unmetered_tool_block_a_budget_exhaustion():
    status = build_scan_completion_status(
        coverage_status="complete",
        request_budget={
            "mode": "enforce",
            "rejected_requests": 4,
            "unmetered_tool_invocations": 4,
            "budget_exhausted": False,
            "remaining_requests": 368,
        },
    )

    assert status["complete"] is True
    assert status["limited"] is True
    assert status["budget_exhausted"] is False
    assert status["budget_exhausted_at"] is None


def test_completion_status_records_config_skips_without_budget_failure():
    status = build_scan_completion_status(
        coverage_status="complete",
        checks_skipped=[
            {
                "check": "nuclei",
                "reason": "Nuclei disabled by focused active mode",
                "impact": "Template findings were not tested",
                "configured": True,
            }
        ],
    )

    assert status["complete"] is True
    assert status["limited"] is True
    assert status["budget_exhausted"] is False
    assert status["skipped_modules"][0]["module"] == "nuclei"
    assert status["skipped_modules"][0]["configured"] is True


def test_completion_status_marks_active_endpoint_cap_as_incomplete():
    status = build_scan_completion_status(
        coverage_status="complete",
        active_block={
            "active_endpoint_budget": 10,
            "active_endpoints_discovered": 25,
            "active_endpoints_selected": 10,
            "active_endpoint_budget_capped": True,
        },
    )

    assert status["complete"] is False
    assert status["limited"] is True
    assert status["budget_exhausted"] is True
    assert status["budget_exhausted_at"] == "active_endpoint_selection"


def test_completion_status_bounds_family_attempts_to_selected_endpoints():
    status = build_scan_completion_status(
        coverage_status="complete",
        active_block={
            "active_endpoint_budget": 50,
            "active_endpoints_discovered": 1083,
            "active_endpoints_selected": 50,
            "active_endpoint_budget_capped": True,
            "smart_total_endpoints_tested": 72,
        },
    )

    active_cap = status["capped_lists"]["active_endpoints"]
    assert active_cap["discovered"] == 1083
    assert active_cap["selected"] == 50
    assert active_cap["tested"] == 50
    assert active_cap["family_endpoint_attempts"] == 72
    assert active_cap["tested_note"].startswith("bounded_by_selected_endpoints")


def test_completion_status_includes_active_endpoint_distributions():
    status = build_scan_completion_status(
        coverage_status="complete",
        active_block={
            "active_endpoint_budget": 3,
            "active_endpoints_discovered": 10,
            "active_endpoints_selected": 3,
            "active_endpoint_budget_capped": True,
            "active_endpoints_discovered_by_source": {
                "har_discovery": 5,
                "openapi": 4,
                "options": 1,
            },
            "active_endpoints_selected_by_source": {
                "har_discovery": 2,
                "openapi": 1,
            },
            "active_endpoints_discovered_by_method": {
                "GET": 6,
                "POST": 4,
            },
            "active_endpoints_selected_by_method": {
                "GET": 1,
                "POST": 2,
            },
        },
    )

    active_cap = status["capped_lists"]["active_endpoints"]
    assert active_cap["discovered_by_source"] == {
        "har_discovery": 5,
        "openapi": 4,
        "options": 1,
    }
    assert active_cap["selected_by_source"] == {
        "har_discovery": 2,
        "openapi": 1,
    }
    assert active_cap["discovered_by_method"] == {
        "GET": 6,
        "POST": 4,
    }
    assert active_cap["selected_by_method"] == {
        "GET": 1,
        "POST": 2,
    }


def test_completion_status_records_discovery_url_caps():
    status = build_scan_completion_status(
        coverage_status="complete",
        discovery_summary={
            "url_budget_caps": [
                {
                    "reason": "JSON link following",
                    "discovered": 250,
                    "selected": 100,
                    "budget": 100,
                    "capped": True,
                }
            ]
        },
    )

    assert status["complete"] is False
    assert status["limited"] is True
    assert status["budget_exhausted"] is True
    assert status["budget_exhausted_at"] == "discovery"
    assert status["capped_lists"]["urls"] == {
        "discovered": 250,
        "selected": 100,
        "budget": 100,
        "capped": True,
        "reasons": ["JSON link following"],
    }
