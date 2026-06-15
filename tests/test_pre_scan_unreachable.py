"""Regression: an unreachable target must produce a FAILED scan, not a graded
"completed" one.

When pre-scan validation can't reach the target, build_report returns early with
a diagnostic report. The worker decides completed-vs-failed solely on
``result["error"]`` (api/worker.py: ``error = result.get('error')``). If that
key is absent, an unreachable target is persisted as ``completed`` with a
misleading placeholder grade (e.g. ``78 C*``). This test pins the contract that
the pre-scan-fail path sets ``report["error"]`` so the worker marks it failed.
"""

import asyncio
import importlib.util
import os
import sys

# scanner.py is a script-style module that does `from scanner_tools... import`,
# so scanner/ must be on sys.path for those top-level imports to resolve.
_SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))
if _SCANNER_DIR not in sys.path:
    sys.path.insert(0, _SCANNER_DIR)

# Import the health_check module the same way build_report does (top-level
# `scanner_tools.health_check`) so monkeypatching it affects build_report's
# inner `from scanner_tools.health_check import pre_scan_validation`.
import scanner_tools.health_check as health_check  # noqa: E402

# Load scanner/scanner.py under a UNIQUE name to avoid colliding with the
# `scanner` package other tests cache in sys.modules (which has no build_report).
_spec = importlib.util.spec_from_file_location(
    "shaker_scanner_main_under_test", os.path.join(_SCANNER_DIR, "scanner.py")
)
scanner_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scanner_mod)


def _make_fake_pre_scan(warnings):
    async def fake_pre_scan_validation(target):
        return {
            "can_proceed": False,
            "warnings": warnings,
            "connectivity": {"details": {"http_status": 0, "ip_addresses": []}},
        }
    return fake_pre_scan_validation


def test_unreachable_target_sets_error(monkeypatch):
    monkeypatch.setattr(
        health_check,
        "pre_scan_validation",
        _make_fake_pre_scan(["Port 9 is not reachable", "Neither port 9, 443 nor 80 is reachable"]),
    )
    report = asyncio.run(scanner_mod.build_report("http://192.0.2.1"))

    # The worker keys failed-vs-completed off this field.
    assert report.get("error"), "unreachable target must set report['error'] so the worker marks the scan failed"
    assert "unreachable" in report["error"].lower()
    assert "Port 9 is not reachable" in report["error"]
    # Still a well-formed diagnostic report (no findings, pre-scan http source).
    assert report.get("findings") == []
    assert (report.get("http") or {}).get("source") == "pre_scan"


def test_unreachable_target_with_no_warnings_still_sets_error(monkeypatch):
    monkeypatch.setattr(health_check, "pre_scan_validation", _make_fake_pre_scan([]))
    report = asyncio.run(scanner_mod.build_report("http://192.0.2.1"))
    assert report.get("error") == "Target unreachable during pre-scan validation"
