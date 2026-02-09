"""
Tests for AI classification provenance tracking (provider vs heuristic fallback).
"""

import asyncio
import os
import sys
from typing import Any


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import ai_classifier  # noqa: E402


def _sample_findings() -> list[dict[str, Any]]:
    return [
        {"id": "f1", "title": "Finding one", "severity": "high", "tool": "dalfox", "evidence": {}},
        {"id": "f2", "title": "Finding two", "severity": "medium", "tool": "nuclei", "evidence": {}},
        {"id": "f3", "title": "Finding three", "severity": "low", "tool": "custom_tool", "evidence": {}},
    ]


def test_classification_meta_tracks_provider_and_fallback_ids():
    async def fake_call_ai_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        return (
            {
                "findings": [
                    {"finding_id": "f1", "verdict": "true_positive", "confidence": 0.9, "rationale": "ok"},
                    {"finding_id": "f2", "verdict": "false_positive", "confidence": 0.7, "rationale": "ok"},
                ],
                "_provider_meta": {"model_used": "mock-model"},
            },
            None,
            12,
        )

    original = ai_classifier.call_ai_provider
    ai_classifier.call_ai_provider = fake_call_ai_provider
    try:
        results, error, _latency, meta = asyncio.run(
            ai_classifier.classify_findings_batch(
                findings=_sample_findings(),
                scan_context={},
                ai_url="https://mock.provider/v1/chat/completions",
                ai_api_key="sk-mock",
                model="mock-model",
                mask_host="example.com",
            )
        )
    finally:
        ai_classifier.call_ai_provider = original

    assert error is not None  # missing verdict for f3 should report partial error
    assert meta is not None
    assert meta["provider_used"] is True
    assert set(meta["provider_finding_ids"]) == {"f1", "f2"}
    assert set(meta["fallback_finding_ids"]) == {"f3"}
    assert results["f1"].classification_source == "provider"
    assert results["f2"].classification_source == "provider"
    assert results["f3"].classification_source == "heuristic_fallback"


def test_classification_meta_all_fallback_when_provider_unavailable():
    async def fake_call_ai_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        return None, "provider down", 5

    original = ai_classifier.call_ai_provider
    ai_classifier.call_ai_provider = fake_call_ai_provider
    try:
        results, error, _latency, meta = asyncio.run(
            ai_classifier.classify_findings_batch(
                findings=_sample_findings(),
                scan_context={},
                ai_url="https://mock.provider/v1/chat/completions",
                ai_api_key="sk-mock",
                model="mock-model",
                mask_host="example.com",
            )
        )
    finally:
        ai_classifier.call_ai_provider = original

    assert error is not None
    assert meta is not None
    assert meta["provider_used"] is False
    assert meta["provider_finding_ids"] == []
    assert set(meta["fallback_finding_ids"]) == {"f1", "f2", "f3"}
    assert all(v.classification_source == "heuristic_fallback" for v in results.values())
