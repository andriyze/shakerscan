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


def test_coverage_caps_shards_and_notes_partial():
    eps = [f"GET /a{i}?x=1" for i in range(5000)]
    plan = p.plan_coverage_shards({"scan_type": "smart"}, eps, per_shard_cap=150, max_shards=12)
    assert plan.shard_count == 12
    assert any("partial" in n for n in plan.notes)


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


def test_coverage_per_shard_cap_option_controls_shard_count():
    eps = [f"GET /e{i}?id=1" for i in range(390)]
    few = p.plan_coverage_shards({"scan_type": "smart"}, eps)  # default cap 150
    many = p.plan_coverage_shards({"scan_type": "smart", "coverage_per_shard_cap": 50}, eps)
    assert few.shard_count == 3
    assert many.shard_count == 8  # smaller cap -> more shards
    # still covers every endpoint, disjoint
    union = [e for s in many.shards for e in s.options["custom_endpoints"]]
    assert sorted(union) == sorted(eps)


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
