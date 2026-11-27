"""Active-execution honesty gate (docs proposed-next-steps §4).

A smart/full scan that requested active checks but tested ZERO endpoints must not
earn a reliable headline grade — UNLESS discovery genuinely found no injectable
surface. These pin assess_scan_completeness's active-execution classification.
"""

import importlib.util
import os
import sys

_SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))
if _SCANNER_DIR not in sys.path:
    sys.path.insert(0, _SCANNER_DIR)

# Load scanner/scanner.py under a unique name (other tests cache a `scanner`
# package in sys.modules that lacks these symbols).
_spec = importlib.util.spec_from_file_location(
    "scanner_main_for_active_honesty", os.path.join(_SCANNER_DIR, "scanner.py")
)
scanner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scanner)

assess = scanner.assess_scan_completeness


def _report(active_checks: dict) -> dict:
    return {"active_checks": active_checks}


def test_surface_found_zero_tested_is_execution_failure():
    # Discovery found 12 injectable endpoints; the active lane tested none.
    r = assess(
        _report({
            "active_endpoints_discovered": 12,
            "active_endpoints_selected": 12,
            "active_worklist_total": 12,
            "smart_total_endpoints_tested": 0,
            "endpoint_attempts_total": 0,
        }),
        active_checks_requested=True,
    )
    assert r["active_execution_failed"] is True
    assert r["active_execution"]["execution_failed"] is True
    assert r["active_execution"]["injectable_surface_found"] is True
    # Hard grade-reliability failure regardless of other modules.
    assert r["grade_reliable"] is False
    # status downgraded away from a clean "complete".
    assert r["status"] != "complete"
    assert any("active lane tested zero" in i for i in r["issues"])


def test_no_surface_zero_tested_is_acceptable():
    # Discovery found no parameterized/injectable surface — nothing to test.
    r = assess(
        _report({
            "active_endpoints_discovered": 0,
            "active_endpoints_selected": 0,
            "active_worklist_total": 0,
            "smart_total_endpoints_tested": 0,
            "endpoint_attempts_total": 0,
        }),
        active_checks_requested=True,
    )
    assert r["active_execution_failed"] is False
    assert r["active_execution"]["zero_attempts"] is True
    assert r["active_execution"]["execution_failed"] is False
    # Not an active-execution failure (grade reliability decided by required modules).
    assert any("no parameterized/injectable" in i for i in r["issues"])


def test_endpoints_actually_tested_is_not_a_failure():
    r = assess(
        _report({
            "active_endpoints_discovered": 5,
            "active_endpoints_selected": 5,
            "smart_total_endpoints_tested": 5,
            "get_endpoints_tested": 5,
            "endpoint_attempts_total": 5,
        }),
        active_checks_requested=True,
    )
    assert r["active_execution_failed"] is False
    assert r["active_execution"]["endpoints_tested"] >= 5
    assert r["modules"]["active_checks"]["completed"] is True


def test_active_not_requested_has_no_active_execution_marker():
    r = assess({}, active_checks_requested=False)
    assert r.get("active_execution") is None
    assert r["active_execution_failed"] is False


def test_public_only_scan_does_not_flag_active_failure():
    # In public-only mode active checks are intentionally skipped, not failed.
    r = assess(
        _report({"active_endpoints_discovered": 9, "smart_total_endpoints_tested": 0}),
        active_checks_requested=True,
        public_only=True,
    )
    assert r["active_execution_failed"] is False
    assert r.get("active_execution") is None
