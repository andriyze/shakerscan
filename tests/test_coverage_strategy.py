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


def test_coverage_recon_budget_skips_heavy_active_and_nuclei_work():
    budget = p.RECON_DISCOVERY_BUDGET
    assert budget["active_max_endpoints"] == 1
    assert budget["active_max_seconds"] == 0
    assert budget["param_discovery_url_limit"] == 0
    assert budget["nuclei_max_targets"] == 0
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
        assert cb["active_max_endpoints"] == len(s.options["custom_endpoints"])
        assert s.options["no_early_stop"] is True


def test_coverage_runs_global_checks_once_per_plan():
    eps = [f"GET /api/x{i}?id=1" for i in range(320)]
    plan = p.plan_coverage_shards({"scan_type": "smart"}, eps, per_shard_cap=150)

    assert [s.options.get("skip_global_checks") for s in plan.shards] == [False, True, True]


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


def test_harvest_prefers_full_worklist_over_samples():
    # The scanner emits the FULL worklist at report['active_checks']['active_worklist'];
    # harvest must use it (not the lossy discovery samples) for true coverage.
    recon = {
        "active_checks": {"active_worklist": ["GET /a?x=1", "POST /b form:k=1", "GET /c"]},
        "discovery": {"katana_sample": ["/should/not/be/used"]},
    }
    eps = p.harvest_endpoints(recon)
    assert eps == ["GET /a?x=1", "POST /b form:k=1", "GET /c"]


def test_harvest_default_keeps_large_worklist():
    worklist = [f"GET /e{i}?id=1" for i in range(3000)]
    eps = p.harvest_endpoints({"active_checks": {"active_worklist": worklist}})
    assert eps == worklist


def test_coverage_per_shard_cap_option_controls_shard_count():
    eps = [f"GET /e{i}?id=1" for i in range(390)]
    few = p.plan_coverage_shards({"scan_type": "smart"}, eps)  # default cap 150
    many = p.plan_coverage_shards({"scan_type": "smart", "coverage_per_shard_cap": 50}, eps)
    assert few.shard_count == 3
    assert many.shard_count == 8  # smaller cap -> more shards
    # still covers every endpoint, disjoint
    union = [e for s in many.shards for e in s.options["custom_endpoints"]]
    assert sorted(union) == sorted(eps)


def test_coverage_honors_explicit_shards_cap():
    # 1800 endpoints would auto-size to ~12 shards (cap 150); an explicit
    # shards=3 must cap the fan-out to 3 without dropping any endpoint.
    eps = [f"GET /e{i}?id=1" for i in range(1800)]
    auto = p.plan_coverage_shards({"scan_type": "smart"}, eps)
    capped = p.plan_coverage_shards({"scan_type": "smart", "shards": 3}, eps)
    assert auto.shard_count == 12
    assert capped.shard_count == 3  # explicit request honored as a hard cap
    union = [e for s in capped.shards for e in s.options["custom_endpoints"]]
    assert sorted(union) == sorted(eps)  # every endpoint still covered
    # string form also honored
    assert p.plan_coverage_shards({"scan_type": "smart", "shards": "4"}, eps).shard_count == 4
    # an explicit request LARGER than auto-size doesn't inflate beyond need
    assert p.plan_coverage_shards({"scan_type": "smart", "shards": 50}, eps).shard_count == 12


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
