"""
Tests for worker.py helpers that fold precision/verification triage fields into
the persisted evidence JSONB and canonicalize JSON for signature comparison.
"""

import os
import sys
import types


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *args, **kwargs: None))

import worker  # noqa: E402


def test_build_evidence_with_triage_merges_top_level_fields():
    finding = {
        "title": "Reflected XSS",
        "evidence": {"url": "https://example.test/search", "param": "q"},
        "precision_policy": {
            "original_severity": "high",
            "confidence_capped": True,
            "confidence_cap_reason": "vendor_or_framework_static_sink",
        },
        "verification_reason": "DOM XSS static lead without payload execution",
        "suspected": True,
        "needs_verification": True,
        "verified": False,
        "confidence": 0.34,
        "confidence_tier": "uncertain",
    }

    out = worker._build_evidence_with_triage(finding)

    assert out is not None
    # Underlying evidence is preserved
    assert out["url"] == "https://example.test/search"
    assert out["param"] == "q"
    # Triage envelope is attached
    triage = out["triage"]
    assert triage["suspected"] is True
    assert triage["needs_verification"] is True
    assert triage["verified"] is False
    assert triage["verification_reason"].startswith("DOM XSS")
    assert triage["precision_policy"]["confidence_cap_reason"] == "vendor_or_framework_static_sink"


def test_build_evidence_with_triage_handles_missing_evidence():
    finding = {
        "title": "Missing-evidence finding",
        "verified": True,
        "confidence": 0.91,
    }

    out = worker._build_evidence_with_triage(finding)

    assert out is not None
    assert out["triage"]["verified"] is True
    assert out["triage"]["confidence"] == 0.91


def test_build_evidence_with_triage_returns_none_when_no_data():
    finding = {"title": "Nothing"}

    assert worker._build_evidence_with_triage(finding) is None


def test_build_evidence_with_triage_skips_none_triage_fields():
    finding = {
        "evidence": {"url": "https://x.test"},
        "precision_policy": None,
        "verification_reason": None,
    }

    out = worker._build_evidence_with_triage(finding)

    assert out == {"url": "https://x.test"}


def test_canonicalize_jsonish_normalizes_key_order():
    # asyncpg returns JSONB as a string with unpredictable key order; the
    # in-memory finding is a dict. Both should canonicalize identically.
    db_repr = '{"b": 2, "a": 1}'
    local_repr = '{"a": 1, "b": 2}'

    assert worker._canonicalize_jsonish(db_repr) == worker._canonicalize_jsonish(local_repr)


def test_canonicalize_jsonish_handles_none():
    assert worker._canonicalize_jsonish(None) is None


def test_canonicalize_jsonish_non_json_string_passthrough():
    # A non-JSON string should fall through without raising.
    assert worker._canonicalize_jsonish("plain text") == "plain text"
