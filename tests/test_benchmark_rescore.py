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
