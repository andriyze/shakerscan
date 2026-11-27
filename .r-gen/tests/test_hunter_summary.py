import json
import os
import sys


_SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))
if _SCANNER_DIR not in sys.path:
    sys.path.insert(0, _SCANNER_DIR)

from scanner_tools.hunter_summary import build_hunter_summary  # noqa: E402


def _report():
    return {
        "active_checks": {
            "active_endpoints_discovered_by_source": {"har": 50, "browser": 10},
            "endpoint_attempts": [
                {"family": "sqli", "auth_state": "anonymous", "status": "completed", "attempted_params_count": 3},
                {"family": "bola", "auth_state": "user2", "status": "completed"},
            ],
        },
        "findings": [
            {"type": "SQLi", "tool": "smart_sqli", "severity": "critical", "verified": True},
            {"type": "smart_authz", "tool": "smart_authz", "severity": "high", "title": "BOLA", "verified": True},
            {"type": "X", "tool": "x", "severity": "high", "title": "unproven high"},  # proof gap
        ],
        "smart_coverage": {
            "endpoints": {"discovered": 120, "tested": 80},
            "parameters": {"tested": 200},
            "auth_states_tested": ["user1", "user2"],
        },
    }


def test_hunter_summary_authenticated_two_principals():
    s = build_hunter_summary(_report(), options={"auth_header": "Bearer x", "user2_header": "Bearer y"})
    assert s["discovery_sources"] == {"browser": 10, "har": 50}
    assert s["confirmed_high_critical"] == 2
    assert s["app_graph_stats"]["endpoints_discovered"] == 120
    assert s["app_graph_stats"]["principals_available"] == {"primary": True, "second": True}
    # both principals present -> nothing blocked
    assert s["blocked_hypotheses"] == []
    # the unproven high is a proof gap, the two verified findings are not
    assert len(s["proof_gaps"]) == 1
    assert any("proof depth" in c for c in s["next_recommended_campaigns"])


def test_hunter_summary_blocks_missing_principals():
    report = {"smart_coverage": {"endpoints": {"discovered": 8}, "auth_states_tested": ["anonymous"]}}
    s = build_hunter_summary(report, options={})  # no creds at all
    fams = {b["family"] for b in s["blocked_hypotheses"]}
    assert fams == {"authz", "bola"}  # auth-required families recorded as blocked, not tested anon
    assert s["app_graph_stats"]["principals_available"] == {"primary": False, "second": False}
    txt = " ".join(s["next_recommended_campaigns"])
    assert "primary credentials" in txt and "second principal" in txt
    # under-discovered surface (<=40 endpoints, no observed source) is flagged
    assert "under-discovered" in txt


def test_hunter_summary_redacts_credentials():
    s = build_hunter_summary(_report(), options={"auth_header": "Bearer SUPERSECRETTOKEN123",
                                                 "user2_cookies": "session=SECRETCOOKIE"})
    blob = json.dumps(s)
    assert "SUPERSECRETTOKEN123" not in blob
    assert "SECRETCOOKIE" not in blob
    # only booleans are exposed for principals
    assert s["app_graph_stats"]["principals_available"]["primary"] is True


def test_hunter_summary_emitted_with_zero_findings():
    # acceptance: emit a summary even when nothing is confirmed
    s = build_hunter_summary({"smart_coverage": {"endpoints": {"discovered": 3}}}, options={})
    assert s["confirmed_high_critical"] == 0
    assert s["findings_confirmed"] == {}
    assert isinstance(s["next_recommended_campaigns"], list) and s["next_recommended_campaigns"]
