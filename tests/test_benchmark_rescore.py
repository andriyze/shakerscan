"""Benchmark two-user run + post-retest re-score (docs proposed-next-steps §6).

The verified-H/C lift from the deterministic auto-retest happens AFTER the scan
finishes, but the scorecard historically read at scan-finish. These pin the
re-score's verdict->verified mapping, the retest-settle wait, and the §10 fleet
gate that the runner now enforces.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import benchmark_targets as b  # noqa: E402


def test_retest_proof_counts_as_verified():
    f = b._norm_live_finding(
        {"title": "BOLA", "severity": "high", "verified": False,
         "last_verification_verdict": "exploited"}
    )
    assert f["verified"] is True


def test_scan_time_verified_preserved():
    f = b._norm_live_finding(
        {"title": "SQLi", "severity": "critical", "verified": True,
         "last_verification_verdict": None}
    )
    assert f["verified"] is True


def test_inconclusive_retest_is_not_verified():
    for verdict in ("inconclusive", "error", "likely_vulnerable", None, ""):
        f = b._norm_live_finding(
            {"title": "lead", "severity": "high", "verified": False,
             "last_verification_verdict": verdict}
        )
        assert f["verified"] is False, verdict


def test_live_finding_preserves_browser_proof_evidence():
    proof = {"proven": True, "technique": "headless_xss_dialog"}
    finding = b._norm_live_finding({
        "title": "Reflected XSS",
        "severity": "high",
        "evidence": {"browser_proof": proof},
    })

    assert b._has_browser_proof(finding) is True


def test_post_retest_merge_preserves_scan_time_browser_proof():
    proof = {"proven": True, "technique": "headless_xss_dialog"}
    scan_finding = {
        "title": "DOM XSS in Hash Route",
        "tool": "hash_route_dom_xss",
        "url": "https://example.test/#/search?q=payload",
        "severity": "high",
        "verified": True,
        "browser_proof": proof,
        "evidence": {"payload": "redacted-marker"},
    }
    live_finding = b._norm_live_finding({
        "title": scan_finding["title"],
        "tool": scan_finding["tool"],
        "url": scan_finding["url"],
        "severity": "high",
        "last_verification_verdict": "exploited",
        "evidence": {"triage": {"verified": True}},
    })

    merged = b._post_retest_findings([scan_finding], [live_finding])

    assert len(merged) == 1
    assert merged[0]["verified"] is True
    assert merged[0]["browser_proof"] == proof
    assert merged[0]["evidence"]["payload"] == "redacted-marker"
    assert merged[0]["evidence"]["triage"]["verified"] is True
    assert b._has_browser_proof(merged[0]) is True


def test_verified_family_gate_is_independent_of_expectation_severity():
    fixture = {
        "name": "unit",
        "expected": [{
            "id": "critical-sqli",
            "family": "sqli",
            "route": "/api/search",
            "min_severity": "critical",
            "proof": "verified",
        }],
        "gates": {"require_verified_sqli": True},
    }
    card = b.collect_scorecard({
        "findings": [{
            "title": "SQL Injection",
            "url": "https://example.test/api/search",
            "severity": "high",
            "verified": True,
        }],
    }, fixture)

    assert card["expected_found"] == []
    gate = next(g for g in b.apply_gates(card, fixture) if g["gate"] == "require_verified_sqli")
    assert gate["pass"] is True


def test_browser_gate_requires_explicit_successful_browser_proof():
    fixture = {"name": "unit", "expected": [], "gates": {"require_browser_proven_xss": True}}
    base = {
        "title": "Reflected XSS",
        "url": "https://example.test/search",
        "severity": "high",
        "verified": True,
    }

    unproven = b.collect_scorecard({"findings": [base]}, fixture)
    failed = next(g for g in b.apply_gates(unproven, fixture) if g["gate"] == "require_browser_proven_xss")
    assert failed["pass"] is False

    proven = b.collect_scorecard({
        "findings": [{**base, "browser_proof": {"proven": True}}],
    }, fixture)
    passed = next(g for g in b.apply_gates(proven, fixture) if g["gate"] == "require_browser_proven_xss")
    assert passed["pass"] is True


def test_fleet_gate_blocks_mixed_fleet(monkeypatch):
    monkeypatch.setattr(b, "_get", lambda *a, **k: {
        "fleet_uniform": False, "count": 16, "current_count": 5,
        "stale_count": 11, "pending_count": 0, "distinct_fingerprints": ["a", "b"],
    })
    uniform, summary = b.check_fleet("http://x")
    assert uniform is False
    assert summary["stale"] == 11


def test_fleet_gate_allows_uniform_fleet(monkeypatch):
    monkeypatch.setattr(b, "_get", lambda *a, **k: {
        "fleet_uniform": True, "count": 16, "current_count": 16,
        "stale_count": 0, "pending_count": 0, "distinct_fingerprints": ["a"],
    })
    uniform, summary = b.check_fleet("http://x")
    assert uniform is True
    assert summary["stale"] == 0


def test_apply_gates_fails_report_trust_signals():
    card = {
        "verified_high_critical": 10,
        "false_positive_risk": 0,
        "expected_found": [],
        "report_invariant_violations": ["findings_count mismatch"],
        "grade_reliable": False,
        "active_execution_failed": True,
        "report_degraded": True,
        "retest_settled": False,
    }

    gates = b.apply_gates(card, {"gates": {}})
    failed = {g["gate"] for g in gates if not g["pass"]}

    assert "report_invariants_clean" in failed
    assert "grade_reliable" in failed
    assert "active_execution_ok" in failed
    assert "report_not_degraded" in failed
    assert "retest_settled" in failed


def test_benchmark_artifact_metadata_is_explicit_about_pass_fail():
    failed = b.artifact_metadata(False)
    passed = b.artifact_metadata(True)

    assert failed["artifact_type"] == "benchmark_scorecard_run"
    assert failed["artifact_status"] == "failed_benchmark_scorecard"
    assert passed["artifact_status"] == "passed_benchmark_scorecard"
    assert "not a success claim" in failed["artifact_note"]


def test_scorecard_emits_benchmark_miss_followups_for_supported_families():
    card = b.collect_scorecard(
        {"findings": []},
        {
            "name": "unit",
            "target_url": "https://bench.example.test",
            "expected": [
                {
                    "id": "sqli-login",
                    "family": "sqli",
                    "route": "/rest/user/login",
                    "min_severity": "critical",
                    "proof": "verified",
                },
                {
                    "id": "xss-dom",
                    "family": "xss",
                    "route": "#/search",
                    "min_severity": "high",
                    "proof": "browser",
                },
                {
                    "id": "exposed-file",
                    "family": "sensitive_exposure",
                    "route": "/ftp",
                    "min_severity": "high",
                    "proof": "deterministic",
                },
            ],
        },
    )

    followups = {item["expectation_id"]: item for item in card["benchmark_followups"]}
    assert followups["sqli-login"]["status"] == "ready"
    assert followups["sqli-login"]["next_test_action"]["command"] == "scan.focused_family"
    assert followups["sqli-login"]["next_test_action"]["parameters"]["check_family"] == "sqli"
    assert followups["sqli-login"]["next_test_action"]["parameters"]["target"] == "https://bench.example.test"
    assert "post_body_params" in followups["sqli-login"]["operator_hints"]
    assert followups["xss-dom"]["next_test_action"]["parameters"]["check_family"] == "xss"
    assert "browser_proof_required" in followups["xss-dom"]["operator_hints"]
    assert followups["exposed-file"]["status"] == "detector_gap"
    assert followups["exposed-file"]["next_test_action"] is None


def test_scorecard_blocks_bola_followup_until_second_principal_observed():
    card = b.collect_scorecard(
        {"findings": [], "smart_coverage": {"auth_states_tested": ["user1"]}},
        {
            "name": "crapi-unit",
            "target_url": "https://crapi.example.test",
            "auth": {
                "user1_login": {"url": "/login"},
                "user2_login": {"url": "/login"},
                "requires_two_users": True,
            },
            "expected": [
                {
                    "id": "bola-orders",
                    "family": "bola",
                    "route": "/workshop/api/shop/orders",
                    "min_severity": "high",
                    "proof": "verified",
                },
            ],
        },
    )

    followup = card["benchmark_followups"][0]
    assert followup["status"] == "blocked"
    assert followup["next_test_action"] is None
    assert "missing_second_principal" in followup["blocked_by"]
    assert followup["blocked_action_template"]["command"] == "scan.focused_family"
    assert followup["blocked_action_template"]["parameters"]["check_family"] == "bola"
    assert followup["blocked_action_template"]["parameters"]["exploit_depth"] is True


def test_scorecard_includes_body_completion_diagnostics():
    card = b.collect_scorecard(
        {
            "findings": [],
            "active_checks": {
                "endpoint_attempts": [
                    {
                        "family": "nosql",
                        "method": "POST",
                        "param_location": "body",
                        "attempted_params_count": 2,
                        "completed_params_count": 2,
                        "status": "completed",
                        "validation_fields_added": ["email"],
                    }
                ],
            },
        },
        {"name": "unit", "expected": []},
    )

    diagnostics = card["body_completion_diagnostics"]
    assert diagnostics["body_attempts"] == 1
    assert diagnostics["parameter_completion_ratio"] == 1.0
    assert diagnostics["families"]["nosqli"]["response_guided_completion_attempts"] == 1


def test_benchmark_hypothesis_seed_payload_is_content_free_and_traceable():
    card = {
        "target": "juice_shop",
        "phase": "post_retest",
        "scan_id": "scan-1",
        "benchmark_followups": [
            {
                "expectation_id": "sqli-login",
                "family": "sqli",
                "route": "/rest/user/login",
                "next_test_action": {"command": "scan.focused_family"},
            }
        ],
    }

    payload = b.benchmark_hypothesis_seed_payload(
        card,
        target_id="target-1",
        created_by="pytest",
    )

    assert payload["target_id"] == "target-1"
    assert payload["benchmark"] == "juice_shop"
    assert payload["scorecard_id"] == "juice_shop:post_retest"
    assert payload["scorecard_scan_id"] == "scan-1"
    assert payload["followups"] == card["benchmark_followups"]
    assert payload["created_by"] == "pytest"


def test_seed_benchmark_hypotheses_skips_empty_followup_list(monkeypatch):
    called = {"post": False}

    def fake_post(*_args, **_kwargs):
        called["post"] = True
        return {}

    monkeypatch.setattr(b, "_post", fake_post)
    result = b.seed_benchmark_hypotheses("http://api.test", {"benchmark_followups": []})

    assert called["post"] is False
    assert result["submitted"] is False
    assert result["reason"] == "no_benchmark_followups"
    assert result["execution_enabled"] is False
    assert result["findings_created"] == 0
    assert result["queued_scans"] == 0


def test_seed_benchmark_hypotheses_posts_followups(monkeypatch):
    captured = {}

    def fake_post(url, body, timeout=30):
        captured["url"] = url
        captured["body"] = body
        captured["timeout"] = timeout
        return {
            "created_or_endorsed": 1,
            "skipped_count": 0,
            "execution_enabled": False,
            "findings_created": 0,
            "queued_scans": 0,
        }

    monkeypatch.setattr(b, "_post", fake_post)
    result = b.seed_benchmark_hypotheses(
        "http://api.test",
        {
            "target": "crapi",
            "phase": "scan_finish",
            "scan_id": "scan-2",
            "benchmark_followups": [{"expectation_id": "bola-orders", "family": "bola"}],
        },
        target_id="target-2",
        created_by="pytest",
    )

    assert result["submitted"] is True
    assert captured["url"] == "http://api.test/arsenal/hypotheses/from-benchmark"
    assert captured["body"]["target_id"] == "target-2"
    assert captured["body"]["benchmark"] == "crapi"
    assert captured["body"]["scorecard_id"] == "crapi:scan_finish"
    assert captured["body"]["followups"][0]["expectation_id"] == "bola-orders"
    assert result["response"]["created_or_endorsed"] == 1


def test_parse_target_id_overrides_requires_name_uuid_shape():
    assert b.parse_target_id_overrides(["juice_shop=target-1", "crapi=target-2"]) == {
        "juice_shop": "target-1",
        "crapi": "target-2",
    }
    try:
        b.parse_target_id_overrides(["missing-separator"])
    except ValueError as exc:
        assert "NAME=UUID" in str(exc)
    else:
        raise AssertionError("expected invalid override to raise")


def test_retest_settle_returns_true_when_drained(monkeypatch):
    monkeypatch.setattr(b, "_get", lambda *a, **k: {
        "retest_pending": 0, "retest_queued": 0, "retest_running": 0,
    })
    assert b.wait_for_retest_settle("http://x", timeout=5) is True


def test_retest_settle_counts_all_retest_lanes(monkeypatch):
    # If any retest lane is busy, it is not settled — verify the sum is used.
    seen = {"calls": 0}

    def fake_get(*a, **k):
        seen["calls"] += 1
        # busy once, then drained
        if seen["calls"] == 1:
            return {"retest_pending": 0, "retest_queued": 2, "retest_running": 0}
        return {"retest_pending": 0, "retest_queued": 0, "retest_running": 0}

    monkeypatch.setattr(b, "_get", fake_get)
    monkeypatch.setattr(b.time, "sleep", lambda *_: None)
    assert b.wait_for_retest_settle("http://x", timeout=60, poll=0) is True
    assert seen["calls"] >= 2
