"""
Regression tests for proof-gated report filtering.
"""

import os
import sys


SCANNER_DIR = os.path.join(os.path.dirname(__file__), "..", "scanner")
sys.path.insert(0, SCANNER_DIR)

from scanner_tools import finding_validator, report_gating  # noqa: E402

sys.path.pop(0)


def test_finding_has_verification_evidence_rejects_generic_nested_validation_flags():
    finding = {
        "title": "HSTS header missing",
        "validation": {"verified": True, "confidence": 0.6},
    }

    assert report_gating.finding_has_verification_evidence(finding) is False


def test_finding_has_verification_evidence_accepts_nested_validation_proof():
    finding = {
        "title": "Confirmed SQL injection",
        "validation": {"verified": True, "evidence_level": "confirmed_exploit", "confidence": 0.9},
    }

    assert report_gating.finding_has_verification_evidence(finding) is True


def test_finding_has_verification_evidence_rejects_failed_browser_proof():
    finding = {
        "title": "Potential XSS",
        "verified": True,
        "browser_proof": {"proven": False, "attempted": True},
    }

    assert report_gating.finding_has_verification_evidence(finding) is False


def test_finding_has_verification_evidence_accepts_proven_browser_proof():
    finding = {
        "title": "Confirmed XSS",
        "browser_proof": {"proven": True, "confidence": 0.99},
    }

    assert report_gating.finding_has_verification_evidence(finding) is True


def test_finding_has_verification_evidence_accepts_poe_result():
    finding = {
        "title": "Potential SQL injection",
        "poe_result": {"proven": True, "attempted": True},
    }

    assert report_gating.finding_has_verification_evidence(finding) is True


def test_finding_has_verification_evidence_rejects_unverified_finding():
    finding = {
        "title": "Potential issue",
        "validation": {"verified": False},
        "verification_verdict": "inconclusive",
    }

    assert report_gating.finding_has_verification_evidence(finding) is False


def test_validate_exposed_file_uses_high_confidence_metadata_when_body_redacted():
    finding = {
        "title": "Exposed file: .env (confidence: high)",
        "evidence": {
            "path": ".env",
            "confidence": "high",
            "has_html": False,
            "markers": ["dotenv_format", "credential_like"],
            "preview_first_line": "DB_NAME=crapi",
        },
    }

    result = finding_validator.validate_exposed_file(finding, response_body=None, response_headers=None)

    assert result.verified is True
    assert result.confidence >= 0.8
    assert "High-confidence exposed file" in (result.reason or "")


def test_validate_exposed_file_uses_medium_confidence_sensitive_markers():
    finding = {
        "title": "Exposed file: .env (confidence: medium)",
        "evidence": {
            "path": ".env",
            "confidence": "medium",
            "has_html": False,
            "markers": ["dotenv_format"],
            "preview_first_line": "FEATURE_FLAG=true",
        },
    }

    result = finding_validator.validate_exposed_file(finding, response_body=None, response_headers=None)

    assert result.verified is True
    assert result.confidence == 0.75
    assert "Medium-confidence exposed file" in (result.reason or "")


def test_validate_exposed_file_without_body_stays_unverified_for_weak_signal():
    finding = {
        "title": "Exposed file: robots.txt (confidence: low)",
        "evidence": {
            "path": "robots.txt",
            "confidence": "low",
            "has_html": False,
            "markers": [],
        },
    }

    result = finding_validator.validate_exposed_file(finding, response_body=None, response_headers=None)

    assert result.verified is False
    assert result.confidence <= 0.4
