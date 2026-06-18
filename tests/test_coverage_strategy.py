"""Tests for coverage strategy, exploit-depth, auth-state sharding, and the
recon endpoint harvester (api/parallel_scan.py)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import parallel_scan as p  # noqa: E402


# --------------------------- exploit-depth ---------------------------

def test_exploit_depth_applied_to_all_shards():
    plan = p.plan_shards({"scan_type": "smart", "exploit_depth": True},
                         scan_type="smart", strategy="family", requested_shards=3)
    assert plan.shards
    for s in plan.shards:
        assert s.options.get("no_early_stop") is True
        cb = s.options.get("custom_budget") or {}
        assert cb.get("sqli_extract_max") == 8
        assert cb.get("oob_max_findings") == 8
        assert "max_findings_per_family" in cb  # None -> unlimited downstream


def test_exploit_depth_off_by_default():
    plan = p.plan_shards({"scan_type": "smart"}, scan_type="smart", strategy="family", requested_shards=2)
    assert all(not (s.options.get("custom_budget") or {}).get("sqli_extract_max") for s in plan.shards)


def test_auto_strategy_resolves_active_scan_to_coverage_in_plan_worker():
    assert p.resolve_auto_strategy({"scan_type": "smart"}, "smart", "auto") == "coverage"
    assert p.resolve_auto_strategy({"scan_type": "full"}, "full", "auto") == "coverage"


def test_auto_strategy_resolves_explicit_endpoints_to_scope():
    assert (
        p.resolve_auto_strategy(
            {"scan_type": "smart", "custom_endpoints": ["GET /a?id=1", "POST /b json:{\"id\":1}"]},
            "smart",
            "auto",
        )
        == "scope"
    )


def test_auto_strategy_honors_explicit_family():
    assert p.resolve_auto_strategy({"scan_type": "smart"}, "smart", "family") == "family"


def test_coverage_recon_budget_skips_heavy_active_and_nuclei_work():
    budget = p.RECON_DISCOVERY_BUDGET
    assert budget["active_max_endpoints"] == 1
    assert budget["active_max_seconds"] == 0
    assert budget["api_probe_limit"] == 250
    assert budget["param_discovery_url_limit"] == 0
    assert budget["nuclei_max_targets"] == 0
    assert budget["phase4_max_seconds"] == 0
    assert budget["max_duration_minutes"] <= 10


# --------------------------- coverage partition ---------------------------

def test_coverage_partitions_all_endpoints_disjoint():
    eps = [f"GET /api/x{i}?id=1" for i in range(320)]
    plan = p.plan_coverage_shards({"scan_type": "smart"}, eps, per_shard_cap=150)
    assert plan.strategy == "coverage"
    assert plan.shard_count == 3  # ceil(320/150)
    union = [e for s in plan.shards for e in s.options["custom_endpoints"]]
    assert sorted(union) == sorted(eps)          # every endpoint covered
    assert len(union) == len(set(union)) == 320  # disjoint, no dup
    for s in plan.shards:
        cb = s.options["custom_budget"]
        resolved = s.options["resolved_budget"]
        assert cb["active_max_endpoints"] == len(s.options["custom_endpoints"])
        assert cb["api_probe_limit"] == 0
        assert cb["param_discovery_url_limit"] == 0
        assert cb["active_max_seconds"] == max(300, 8 * len(s.options["custom_endpoints"]))
        assert resolved["api_probe_limit"] == 0
        assert resolved["param_discovery_url_limit"] == 0
        assert resolved["browser_max_pages"] == 0
        assert resolved["active_max_endpoints"] == len(s.options["custom_endpoints"])
        assert s.options["focused_endpoints_only"] is True
        assert s.options["zero_rediscovery"] is True
        assert s.options["no_early_stop"] is True
        assert cb["nuclei_max_targets"] == 0


def test_coverage_runs_global_checks_once_per_plan():
    eps = [f"GET /api/x{i}?id=1" for i in range(320)]
    plan = p.plan_coverage_shards({"scan_type": "smart"}, eps, per_shard_cap=150)

    assert [s.options.get("skip_global_checks") for s in plan.shards] == [False, True, True]
    assert [s.options["custom_budget"].get("nuclei_max_targets") for s in plan.shards] == [0, 0, 0]
    assert [s.options["resolved_budget"].get("nuclei_max_targets") for s in plan.shards] == [0, 0, 0]
    assert any("zero-rediscovery shards skip" in n for n in plan.notes)


def test_exhaustive_coverage_shards_get_deeper_active_budget():
    eps = [f"GET /api/x{i}?id=1" for i in range(300)]
    plan = p.plan_coverage_shards(
        {"scan_type": "smart", "budget_profile": "exhaustive", "exploit_depth": True},
        eps,
        per_shard_cap=150,
    )

    assert plan.shard_count == 2
    assert all(s.options["custom_budget"]["active_max_seconds"] == 2250 for s in plan.shards)
    assert all(s.options["resolved_budget"]["active_max_seconds"] == 2250 for s in plan.shards)


def test_finding_merge_key_collapses_repeated_passive_shard_findings():
    first = {
        "tool": "http_methods",
        "title": "Risky HTTP methods advertised: DELETE, PUT (6 endpoints)",
        "severity": "info",
        "url": "http://host.docker.internal:3001",
        "evidence": {"shard": 1},
    }
    second = {
        **first,
        "evidence": {"shard": 2, "methods": ["DELETE", "PUT"]},
    }
    distinct_url = {
        **first,
        "url": "http://host.docker.internal:3001/api",
    }

    assert p.finding_merge_key(first) == p.finding_merge_key(second)
    assert p.finding_merge_key(first) != p.finding_merge_key(distinct_url)


def test_coverage_caps_shards_without_dropping_endpoints():
    eps = [f"GET /a{i}?x=1" for i in range(5000)]
    plan = p.plan_coverage_shards({"scan_type": "smart"}, eps, per_shard_cap=150, max_shards=12)
    assert plan.shard_count == 12
    union = [e for s in plan.shards for e in s.options["custom_endpoints"]]
    assert sorted(union) == sorted(eps)
    assert any("preserve endpoint coverage" in n for n in plan.notes)


def test_coverage_single_endpoint_falls_back_to_one_shard():
    plan = p.plan_coverage_shards({"scan_type": "smart"}, ["GET /only?x=1"])
    assert plan.shard_count == 1
    assert plan.is_parallel is False
    shard = plan.shards[0]
    assert shard.options["custom_endpoints"] == ["GET /only?x=1"]
    assert shard.options["focused_endpoints_only"] is True
    assert shard.options["zero_rediscovery"] is True
    assert shard.options["custom_budget"]["nuclei_max_targets"] == 0
    assert shard.options["custom_budget"]["phase4_max_seconds"] == 0
    assert shard.options["resolved_budget"]["active_max_endpoints"] == 1
    assert any("zero-rediscovery shards skip" in n for n in plan.notes)


def test_coverage_family_multiplies_endpoint_buckets_by_family_lanes():
    eps = [f"GET /api/x{i}?id=1" for i in range(10)]
    plan = p.plan_coverage_family_shards(
        {"scan_type": "smart", "coverage_max_shards": 6},
        eps,
        per_shard_cap=5,
    )

    assert plan.strategy == "coverage_family"
    assert plan.shard_count == 6
    assert [s.label for s in plan.shards] == [
        "coverage[0]:broad",
        "coverage[0]:sqli",
        "coverage[0]:xss",
        "coverage[1]:broad",
        "coverage[1]:sqli",
        "coverage[1]:xss",
    ]
    lane_counts = {"broad": 0, "sqli": 0, "xss": 0}
    endpoint_appearances = []
    for shard in plan.shards:
        endpoint_appearances.extend(shard.options["custom_endpoints"])
        assert shard.options["focused_endpoints_only"] is True
        assert shard.options["zero_rediscovery"] is True
        assert shard.options["custom_budget"]["nuclei_max_targets"] == 0
        assert shard.options["custom_budget"]["phase4_max_seconds"] == 0
        if shard.label.endswith(":sqli"):
            lane_counts["sqli"] += 1
            assert shard.options["coverage_attempt_family"] == "sqli"
            assert shard.options["coverage_family_aware"] is True
            assert shard.options["asm_check_family"] == "sqli"
            assert shard.options["sqli"] is True
            assert shard.options["xss"] is False
        elif shard.label.endswith(":xss"):
            lane_counts["xss"] += 1
            assert shard.options["coverage_attempt_family"] == "xss"
            assert shard.options["coverage_family_aware"] is True
            assert shard.options["asm_check_family"] == "xss"
            assert shard.options["xss"] is True
            assert shard.options["sqli"] is False
        else:
            lane_counts["broad"] += 1
            assert shard.options["coverage_attempt_family"] == "all"
            assert shard.options["coverage_family_aware"] is True
            assert "asm_check_family" not in shard.options
    assert lane_counts == {"broad": 2, "sqli": 2, "xss": 2}
    assert sorted(set(endpoint_appearances)) == sorted(eps)
    assert len(endpoint_appearances) == len(eps) * 3
    assert [s.options.get("skip_global_checks") for s in plan.shards] == [False, True, True, True, True, True]
    assert any("coverage_allocation=dynamic" in n for n in plan.notes)


def test_coverage_family_total_shard_cap_limits_family_lanes():
    eps = [f"GET /api/x{i}?id=1" for i in range(10)]
    plan = p.plan_coverage_family_shards({"scan_type": "smart", "shards": 2}, eps, per_shard_cap=5)

    assert plan.shard_count == 2
    assert [s.label for s in plan.shards] == ["coverage[0]:broad", "coverage[0]:sqli"]
    assert any("dropped xss" in n for n in plan.notes)


def test_coverage_family_respects_explicit_high_risk_focus():
    eps = [f"GET /api/orders/{i}" for i in range(12)]
    plan = p.plan_coverage_family_shards(
        {
            "scan_type": "smart",
            "check_family": "bola",
            "asm_check_family": "bola",
            "exploit_depth": True,
            "coverage_max_shards": 6,
        },
        eps,
        per_shard_cap=5,
    )

    assert plan.strategy == "coverage_family"
    assert [s.label for s in plan.shards] == [
        "coverage[0]:bola",
        "coverage[1]:bola",
        "coverage[2]:bola",
    ]
    assert {s.options["coverage_attempt_family"] for s in plan.shards} == {"bola"}
    assert {s.options["asm_check_family"] for s in plan.shards} == {"bola"}
    assert all(s.options["sqli"] is False and s.options["xss"] is False for s in plan.shards)
    endpoint_appearances = [e for shard in plan.shards for e in shard.options["custom_endpoints"]]
    assert sorted(endpoint_appearances) == sorted(eps)


# --------------------------- harvest ---------------------------

def test_harvest_prefers_params_and_dedups():
    # discovery is a TOP-LEVEL report section (matches real scanner output).
    recon = {"discovery": {
        "browser_api_endpoints": [{"method": "GET", "url": "http://h:3001/rest/products/1"}],
        "har_discovery": {"endpoints": ["/api/Feedbacks/1?q=x", "/rest/products/1"]},  # dup of browser (path)
        "js_bundle_analysis": {"api_endpoints": ["/api/Users/1?id=1"]},
        "katana_sample": ["/rest/products/search?q=a"],
    }}
    eps = p.harvest_endpoints(recon)
    # params-bearing endpoints come first
    assert eps[0].endswith("?q=x") or "?" in eps[0]
    assert sum(1 for e in eps if "?" in e) == 3
    # /rest/products/1 deduped to a single entry
    assert sum(1 for e in eps if e == "GET /rest/products/1") == 1


def test_harvest_empty_result_is_safe():
    assert p.harvest_endpoints({}) == []
    assert p.harvest_endpoints({"result": {"discovery": {}}}) == []


def test_harvest_keeps_worklist_priority_and_appends_discovery_routes():
    # The scanner emits shaped active worklist entries, but that list can be
    # narrower than the discovered API surface. Keep worklist priority while
    # appending discovery routes so resource producers are not dropped.
    recon = {
        "active_checks": {"active_worklist": ["GET /a?x=1", "POST /b form:k=1", "GET /c"]},
        "discovery": {"katana_sample": ["/should/be/used", "/c"]},
    }
    eps = p.harvest_endpoints(recon)
    assert eps == ["GET /a?x=1", "POST /b form:k=1", "GET /c", "GET /should/be/used"]


def test_harvest_appends_crapi_resource_producers_when_active_worklist_is_narrow():
    recon = {
        "active_checks": {
            "active_worklist": [
                "POST /api/shop/apply_coupon json:{\"code\":\"TEST123\",\"id\":1}",
                "POST /merchant/contact_mechanic json:{\"email\":\"test@example.com\"}",
            ]
        },
        "discovery": {
            "js_bundle_analysis": {
                "api_endpoints": [
                    "http://crapi.test/workshop/api/shop/orders/all",
                    "http://crapi.test/workshop/api/shop/orders/<orderId>",
                ],
            },
            "katana_sample": [
                "http://crapi.test/identity/api/v2/vehicle/vehicles?vehicle_id=1",
            ],
        },
    }

    eps = p.harvest_endpoints(recon)

    assert eps[:2] == [
        "POST /api/shop/apply_coupon json:{\"code\":\"TEST123\",\"id\":1}",
        "POST /merchant/contact_mechanic json:{\"email\":\"test@example.com\"}",
    ]
    assert "GET /workshop/api/shop/orders/all" in eps
    assert "GET /workshop/api/shop/orders/<orderId>" in eps
    assert "GET /identity/api/v2/vehicle/vehicles?vehicle_id=1" in eps


def test_harvest_filters_static_asset_worklist_entries():
    recon = {
        "active_checks": {
            "active_worklist": [
                "GET /assets/public/images/logo.png?image_id=1&id=1",
                "POST /assets/public/images/logo.png json:{\"id\":1}",
                "PATCH /static/app.js json:{\"id\":1}",
                "GET /api/users?id=1",
                "POST /rest/login json:{\"email\":1}",
            ]
        }
    }

    assert p.harvest_endpoints(recon) == [
        "GET /api/users?id=1",
        "POST /rest/login json:{\"email\":1}",
    ]


def test_harvest_default_keeps_large_worklist():
    worklist = [f"GET /e{i}?id=1" for i in range(3000)]
    eps = p.harvest_endpoints({"active_checks": {"active_worklist": worklist}})
    assert eps == worklist


def test_coverage_per_shard_cap_option_controls_shard_count():
    eps = [f"GET /e{i}?id=1" for i in range(390)]
    few = p.plan_coverage_shards({"scan_type": "smart"}, eps)  # active-mix default cap 50
    many = p.plan_coverage_shards({"scan_type": "smart", "coverage_per_shard_cap": 50}, eps)
    explicit_large = p.plan_coverage_shards({"scan_type": "smart", "coverage_per_shard_cap": 150}, eps)
    assert few.shard_count == 8
    assert many.shard_count == 8
    assert explicit_large.shard_count == 3
    # still covers every endpoint, disjoint
    union = [e for s in many.shards for e in s.options["custom_endpoints"]]
    assert sorted(union) == sorted(eps)


def test_coverage_default_cap_is_smaller_for_broad_active_mix():
    assert p._default_coverage_per_shard_cap({"scan_type": "smart"}) == 50
    assert p._coverage_dynamic_batch_size({"scan_type": "smart"}) == 50
    assert p._default_coverage_per_shard_cap({"scan_type": "smart", "exploit_depth": True}) == 35
    assert p._coverage_dynamic_batch_size({"scan_type": "smart", "coverage_dynamic_batch_size": 90}) == 90


def test_coverage_default_cap_keeps_focused_family_lanes_larger():
    assert p._default_coverage_per_shard_cap({"scan_type": "smart", "asm_check_family": "sqli"}) == 150


def test_coverage_honors_explicit_shards_cap():
    # 1800 endpoints auto-size to 36 broad active shards (cap 50); an explicit
    # shards=3 must cap the fan-out to 3 without dropping any endpoint.
    eps = [f"GET /e{i}?id=1" for i in range(1800)]
    auto = p.plan_coverage_shards({"scan_type": "smart"}, eps)
    capped = p.plan_coverage_shards({"scan_type": "smart", "shards": 3}, eps)
    assert auto.shard_count == 36
    assert capped.shard_count == 3  # explicit request honored as a hard cap
    union = [e for s in capped.shards for e in s.options["custom_endpoints"]]
    assert sorted(union) == sorted(eps)  # every endpoint still covered
    # string form also honored
    assert p.plan_coverage_shards({"scan_type": "smart", "shards": "4"}, eps).shard_count == 4
    # an explicit request LARGER than auto-size doesn't inflate beyond need
    assert p.plan_coverage_shards({"scan_type": "smart", "shards": 50}, eps).shard_count == 36


def test_coverage_auth_state_expansion_preserves_all_endpoints_per_state():
    eps = [f"GET /e{i}?id=1" for i in range(1800)]
    plan = p.plan_coverage_shards(
        {
            "scan_type": "smart",
            "auth_state_shards": True,
            "auth_header": "Bearer u1",
            "user2_header": "Bearer u2",
        },
        eps,
        per_shard_cap=100,
    )

    assert plan.shard_count == 54  # 18 coverage buckets x anon/user1/user2
    for state in ("anonymous", "user1", "user2"):
        state_eps = [
            endpoint
            for shard in plan.shards
            if shard.options.get("auth_state") == state
            for endpoint in shard.options["custom_endpoints"]
        ]
        assert sorted(state_eps) == sorted(eps)
        state_shards = [s for s in plan.shards if s.options.get("auth_state") == state]
        assert sum(1 for s in state_shards if not s.options.get("skip_global_checks")) == 1


def test_aggregate_coverage_uses_assigned_endpoint_union_for_coverage_strategy():
    merged = p.aggregate_shard_coverage(
        "coverage",
        [
            {
                "status": "completed",
                "options": {"custom_endpoints": ["GET /a?id=1", "GET /b?id=1"]},
                "smart_coverage": {
                    "endpoints": {"discovered": 200, "tested": 2, "coverage": 0.01},
                    "discovery_sources": ["active_worklist"],
                },
            },
            {
                "status": "failed",
                "options": {"custom_endpoints": ["GET /c?id=1"]},
                "smart_coverage": {},
            },
        ],
    )

    assert merged["endpoints"] == {
        "discovered": 3,
        "tested": 2,
        "coverage": 0.667,
        "basis": "assigned_custom_endpoints",
    }
    assert merged["aggregated_from_shards"] == 2
    assert merged["coverage_reports_from_shards"] == 1
    assert merged["discovery_sources"] == ["active_worklist"]


def test_aggregate_coverage_tracks_auth_attempts_separately():
    endpoints = ["GET /profile?id=1", "POST /orders body:id=1"]
    merged = p.aggregate_shard_coverage(
        "coverage",
        [
            {
                "status": "completed",
                "options": {"auth_state": "anonymous", "custom_endpoints": endpoints},
                "smart_coverage": {"auth_states_tested": ["anonymous"]},
            },
            {
                "status": "completed",
                "options": {"auth_state": "user1", "custom_endpoints": endpoints},
                "smart_coverage": {"auth_states_tested": ["user1"]},
            },
            {
                "status": "failed",
                "options": {"auth_state": "user2", "custom_endpoints": endpoints},
                "smart_coverage": {},
            },
        ],
    )

    assert merged["endpoints"]["discovered"] == 2
    assert merged["endpoints"]["tested"] == 2
    assert merged["endpoints"]["coverage"] == 1.0
    assert merged["endpoints"]["basis"] == "assigned_custom_endpoints"
    assert merged["endpoints"]["auth_attempts_assigned"] == 6
    assert merged["endpoints"]["auth_attempts_completed"] == 4
    assert merged["endpoints"]["auth_attempt_coverage"] == 0.667
    assert merged["auth_states_tested"] == ["anonymous", "user1"]


def test_aggregate_coverage_tracks_family_attempts_separately():
    merged = p.aggregate_shard_coverage(
        "coverage_family",
        [
            {"status": "completed", "options": {"custom_endpoints": ["GET /a?x=1"]}, "smart_coverage": {}},
            {
                "status": "completed",
                "options": {"custom_endpoints": ["GET /a?x=1"], "asm_check_family": "sqli"},
                "smart_coverage": {},
            },
            {
                "status": "failed",
                "options": {"custom_endpoints": ["GET /a?x=1"], "asm_check_family": "xss"},
                "smart_coverage": {},
            },
        ],
    )

    assert merged["endpoints"]["discovered"] == 1
    assert merged["endpoints"]["tested"] == 1
    assert merged["endpoints"]["coverage"] == 1.0
    assert merged["endpoints"]["family_attempts_assigned"] == 3
    assert merged["endpoints"]["family_attempts_completed"] == 2
    assert merged["endpoints"]["family_attempt_coverage"] == 0.667


def test_aggregate_coverage_uses_completed_shard_auth_state_options():
    endpoints = ["GET /profile?id=1"]
    merged = p.aggregate_shard_coverage(
        "coverage",
        [
            {
                "status": "completed",
                "options": {"auth_state": "user2", "custom_endpoints": endpoints},
                "smart_coverage": {},
            },
        ],
    )

    assert merged["auth_states_tested"] == ["user2"]


# --------------------------- auth-state ---------------------------

def test_available_auth_states():
    assert p.available_auth_states({}) == ["anonymous"]
    assert p.available_auth_states({"auth_header": "Bearer x"}) == ["anonymous", "user1"]
    assert p.available_auth_states({"auth_header": "x", "user2_header": "y"}) == ["anonymous", "user1", "user2"]


def test_apply_auth_state_scopes_credentials():
    opts = {"auth_header": "Bearer u1", "user2_header": "Bearer u2", "user2_cookies": "c2"}
    anon = p._apply_auth_state(opts, "anonymous")
    assert "auth_header" not in anon and "user2_header" not in anon and anon["auth_state"] == "anonymous"
    u1 = p._apply_auth_state(opts, "user1")
    assert u1["auth_header"] == "Bearer u1" and "user2_header" not in u1
    u2 = p._apply_auth_state(opts, "user2")
    assert u2["auth_header"] == "Bearer u2" and "user2_header" not in u2


def test_user2_does_not_inherit_primary_credentials():
    # Only user2_cookies provided (no user2_header) alongside a primary header.
    # The user2 shard must NOT inherit the primary auth_header (BOLA correctness).
    opts = {"auth_header": "Bearer u1", "user2_cookies": "sess=u2"}
    u2 = p._apply_auth_state(opts, "user2")
    assert u2.get("auth_cookies") == "sess=u2"
    assert "auth_header" not in u2          # no fallback to primary header
    assert "user2_cookies" not in u2
    # Symmetric: only user2_header + primary cookies -> no primary cookie leak.
    opts2 = {"auth_cookies": "sess=u1", "user2_header": "Bearer u2"}
    u2b = p._apply_auth_state(opts2, "user2")
    assert u2b.get("auth_header") == "Bearer u2"
    assert "auth_cookies" not in u2b


def test_auth_state_expansion_multiplies_shards():
    plan = p.plan_shards(
        {"scan_type": "smart", "auth_state_shards": True, "auth_header": "x", "user2_header": "y"},
        scan_type="smart", strategy="family", requested_shards=3,
    )
    # 3 families x 3 auth states = 9 shards
    assert plan.shard_count == 9
    labels = [s.label for s in plan.shards]
    assert "broad:anonymous" in labels and "sqli:user2" in labels


def test_auth_state_noop_without_credentials():
    plan = p.plan_shards({"scan_type": "smart", "auth_state_shards": True},
                         scan_type="smart", strategy="family", requested_shards=3)
    assert plan.shard_count == 3  # no creds -> no expansion
    assert any("no credentials" in n for n in plan.notes)


def test_coverage_allocation_mode_defaults_to_dynamic(monkeypatch):
    monkeypatch.delenv("COVERAGE_ALLOCATION_DEFAULT", raising=False)
    monkeypatch.delenv("FULL_COVERAGE_ALLOCATION_DEFAULT", raising=False)

    assert p.coverage_allocation_mode({}) == "dynamic"


def test_coverage_allocation_mode_accepts_dynamic_aliases(monkeypatch):
    monkeypatch.setenv("COVERAGE_ALLOCATION_DEFAULT", "static")

    assert p.coverage_allocation_mode({"coverage_allocation": "dynamic"}) == "dynamic"
    assert p.coverage_allocation_mode({"coverage_allocation": "pull"}) == "dynamic"
    assert p.coverage_allocation_mode({"dynamic_coverage_allocation": True}) == "dynamic"
    assert p.coverage_allocation_mode({"coverage_allocation": "static"}) == "static"


def test_coverage_allocation_mode_env_can_restore_static_default(monkeypatch):
    monkeypatch.setenv("COVERAGE_ALLOCATION_DEFAULT", "static")

    assert p.coverage_allocation_mode({}) == "static"
    assert p.coverage_allocation_mode({"dynamic_coverage_allocation": False}) == "static"


def test_dynamic_coverage_plan_uses_pull_workers_without_static_slices():
    notes: list[str] = []
    plan = p.plan_dynamic_coverage_shards(
        {"scan_type": "smart", "coverage_dynamic_batch_size": 25},
        endpoint_count=100,
        auth_state_count=2,
        notes=notes,
    )

    assert plan.strategy == "coverage"
    assert plan.shard_count == 8
    assert any("dynamic campaign allocation" in n for n in plan.notes)
    for shard in plan.shards:
        assert shard.options["coverage_dynamic_worker"] is True
        assert shard.options["coverage_dynamic_campaign_only"] is True
        assert shard.options["coverage_dynamic_batch_size"] == 25
        assert shard.options["coverage_stale_days"] == 0
        assert shard.options["zero_rediscovery"] is True
        assert shard.options["focused_endpoints_only"] is True
        assert "custom_endpoints" not in shard.options
        assert shard.options["custom_budget"]["nuclei_max_targets"] == 0
        assert shard.options["custom_budget"]["phase4_max_seconds"] == 0


def test_dynamic_coverage_family_plan_uses_family_pull_lanes():
    plan = p.plan_dynamic_coverage_family_shards(
        {"scan_type": "smart", "coverage_dynamic_batch_size": 25, "coverage_dynamic_max_batches": 12},
        endpoint_count=100,
        auth_state_count=1,
    )

    assert plan.strategy == "coverage_family"
    assert plan.shard_count == 12
    assert [s.label for s in plan.shards[:3]] == [
        "coverage-dynamic[0]:broad",
        "coverage-dynamic[0]:sqli",
        "coverage-dynamic[0]:xss",
    ]
    assert {s.options["coverage_attempt_family"] for s in plan.shards} == {"all", "sqli", "xss"}
    assert all(s.options["coverage_dynamic_worker"] is True for s in plan.shards)
    assert all(s.options["coverage_family_aware"] is True for s in plan.shards)
    assert all("custom_endpoints" not in s.options for s in plan.shards)
    assert all(s.options["custom_budget"]["phase4_max_seconds"] == 0 for s in plan.shards)
    sqli = next(s for s in plan.shards if s.label.endswith(":sqli"))
    xss = next(s for s in plan.shards if s.label.endswith(":xss"))
    broad = next(s for s in plan.shards if s.label.endswith(":broad"))
    assert sqli.options["asm_check_family"] == "sqli"
    assert xss.options["asm_check_family"] == "xss"
    assert "asm_check_family" not in broad.options


def test_dynamic_coverage_family_respects_explicit_focus():
    plan = p.plan_dynamic_coverage_family_shards(
        {
            "scan_type": "smart",
            "check_family": "bola",
            "asm_check_family": "bola",
            "exploit_depth": True,
            "coverage_dynamic_batch_size": 25,
            "coverage_dynamic_max_batches": 12,
        },
        endpoint_count=100,
        auth_state_count=1,
    )

    assert plan.strategy == "coverage_family"
    assert plan.shard_count == 4
    assert [s.label for s in plan.shards] == [
        "coverage-dynamic[0]:bola",
        "coverage-dynamic[1]:bola",
        "coverage-dynamic[2]:bola",
        "coverage-dynamic[3]:bola",
    ]
    assert {s.options["coverage_attempt_family"] for s in plan.shards} == {"bola"}
    assert {s.options["asm_check_family"] for s in plan.shards} == {"bola"}
    assert all(s.options["coverage_family_aware"] is True for s in plan.shards)
    assert all(s.options["sqli"] is False and s.options["xss"] is False for s in plan.shards)
