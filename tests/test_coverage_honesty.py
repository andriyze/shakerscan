"""Coverage-number honesty (docs proposed-next-steps §11).

Headline ASM coverage must use ONE labeled denominator (testable = total − gone)
so `tested / denominator` reproduces the displayed coverage — instead of three
different "untested" numbers and a `total` inflated by retired/phantom rows.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import asm_inventory as a  # noqa: E402


def _rows(statuses):
    # A "completed" status only counts as tested with explicit endpoint telemetry.
    return [
        {
            "status": s,
            "scanner_telemetry_json": {
                "per_endpoint_telemetry": True,
                "endpoint_attempt": {"schema_version": "active_endpoint_attempt_v1"},
            },
            "attempted_params_count": 1,
            "completed_params_count": 1,
        }
        for s in statuses
    ]


def test_attempt_coverage_exposes_single_labeled_denominator():
    rows = _rows(["completed", "completed", "partial", "auth_missing"])
    # 10 testable endpoints assigned, 4 attempted, 2 completed.
    s = a.attempt_coverage_from_rows(rows, total=10, basis="latest")
    assert s["denominator"] == 10
    assert s["denominator_label"]  # labeled, not blank
    assert s["tested"] == 2
    # tested / denominator reproduces the displayed coverage.
    assert s["coverage"] == round(s["tested"] / s["denominator"], 3)
    assert s["untested"] == 10 - 4  # total − attempted


def test_coverage_denominator_never_uses_inflated_total():
    # 50 raw rows but only 5 testable (rest retired/gone) — coverage must be on 5,
    # not 50, so a heavily-retired surface doesn't read as near-zero coverage.
    rows = _rows(["completed"] * 5)
    s = a.attempt_coverage_from_rows(rows, total=5, basis="latest")
    assert s["coverage"] == 1.0  # 5/5, not 5/50
    assert s["denominator"] == 5


def test_zero_testable_is_zero_coverage_not_crash():
    s = a.attempt_coverage_from_rows([], total=0, basis="latest")
    assert s["coverage"] == 0.0
    assert s["denominator"] == 0
    assert s["tested"] == 0


def test_coverage_label_passthrough():
    s = a.attempt_coverage_from_rows(_rows(["completed"]), total=4, basis="latest",
                                     coverage_denominator="assigned_auth_scoped_endpoints")
    assert s["coverage_denominator"] == "assigned_auth_scoped_endpoints"
    assert s["denominator_label"] == "assigned_auth_scoped_endpoints"
