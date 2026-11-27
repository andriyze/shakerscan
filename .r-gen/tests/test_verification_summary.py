"""Verification Depth D: summarize_verification calibration regression tests."""
import os
import sys

SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))
sys.path.insert(0, SCANNER_DIR)
from findings import summarize_verification  # noqa: E402
sys.path.pop(0)


def test_proven_finding_lands_in_verified_tier_regardless_of_capped_score():
    # A deterministically-proven finding whose confidence was capped into the 'high'
    # band must still count as verified-tier (proof beats the heuristic cap).
    findings = [
        {"severity": "critical", "verified": True, "confidence_tier": "high"},
        {"severity": "high", "verified": True, "confidence_tier": "medium"},
    ]
    s = summarize_verification(findings)
    assert s["verified"] == 2
    assert s["by_confidence_tier"].get("verified") == 2
    assert s["unproven_high"] == 0 and s["unproven_critical"] == 0


def test_unproven_high_is_suspected_not_verified():
    findings = [
        {"severity": "high", "confidence_tier": "high"},          # no verified flag
        {"severity": "critical", "confidence_tier": "medium"},    # no verified flag
    ]
    s = summarize_verification(findings)
    assert s["verified"] == 0
    assert s["suspected"] == 2
    assert s["unproven_high"] == 1 and s["unproven_critical"] == 1
    # not promoted into the verified tier
    assert s["by_confidence_tier"].get("verified") is None
