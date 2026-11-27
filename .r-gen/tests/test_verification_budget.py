"""Regression tests for the scan-time verification budget (max_findings).

These guard the fix for scans hanging/being-reaped at finalize: the verification
phase must (a) bound how many findings get expensive proof at scan time, and
(b) spend that budget only on findings that actually attempt a proof — not noisy
untyped high/criticals. Offline-safe: max_findings=0 defers every eligible finding
before any network proof is attempted.
"""
import asyncio
import os
import sys

SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))
sys.path.insert(0, SCANNER_DIR)
from scanner_tools.verification_phase import verify_high_severity_findings  # noqa: E402
sys.path.pop(0)


def _run(findings, **kw):
    return asyncio.run(verify_high_severity_findings(findings, include_summary=True, **kw))


def test_budget_zero_defers_all_eligible_without_proof():
    # max_findings=0 => every eligible typed finding is deferred (suspected +
    # needs_verification) before any expensive/network proof runs.
    findings = [
        {"type": "sqli", "severity": "critical", "title": "SQLi A", "url": "http://t/a"},
        {"type": "sqli", "severity": "high", "title": "SQLi B", "url": "http://t/b"},
        {"type": "xss", "severity": "high", "title": "XSS C", "url": "http://t/c"},
        {"type": "info_leak", "severity": "low", "title": "low D"},  # below threshold
    ]
    out, summary = _run(findings, min_severity="high", max_findings=0)
    by_title = {f.get("title"): f for f in out}
    for t in ("SQLi A", "SQLi B", "XSS C"):
        assert by_title[t].get("verification_reason") == "scan_verification_budget_exhausted"
        assert by_title[t].get("needs_verification") is True
        assert not by_title[t].get("verified")
    # Below-threshold finding passes through untouched.
    assert "verification_reason" not in by_title["low D"]
    assert len(out) == 4  # nothing dropped


def test_untyped_finding_does_not_consume_budget():
    # A high finding with no recognizable type/prover must NOT consume the budget
    # (so it can't starve real SQLi/XSS/BOLA proofs). With max_findings=0 it should
    # fall through (no budget gate) rather than being marked budget-exhausted.
    findings = [
        {"type": "nonsense_unprovable", "severity": "critical", "title": "noise"},
    ]
    out, _ = _run(findings, min_severity="high", max_findings=0)
    assert out[0].get("verification_reason") != "scan_verification_budget_exhausted"
