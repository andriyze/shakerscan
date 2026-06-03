"""
Tests for AI classification provenance tracking (provider vs heuristic fallback).
"""

import asyncio
import json
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


def test_parse_classification_accepts_provider_id_alias():
    response = {
        "findings": [
            {"id": "f-alias", "verdict": "true_positive", "confidence": 0.91, "rationale": "ok"}
        ]
    }

    parsed = ai_classifier._parse_ai_classification_results(response)
    assert "f-alias" in parsed
    assert parsed["f-alias"].verdict == "true_positive"
    assert parsed["f-alias"].classification_source == "provider"


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


def test_classification_splits_failed_chunks_before_fallback():
    async def fake_call_ai_provider(*args, **kwargs):  # noqa: ANN002, ANN003
        user_prompt = (args[3] if len(args) > 3 else kwargs.get("messages", []))[1]["content"]
        payload = json.loads(user_prompt)
        finding_ids = [str(item.get("finding_id") or item.get("id")) for item in payload.get("findings", [])]
        if len(finding_ids) > 1:
            return None, "Network error: ClientConnectionError: Connection closed", 5
        fid = finding_ids[0]
        return (
            {
                "findings": [
                    {"finding_id": fid, "verdict": "true_positive", "confidence": 0.8, "rationale": "ok"}
                ],
                "_provider_meta": {"model_used": "mock-model"},
            },
            None,
            10,
        )

    original = ai_classifier.call_ai_provider
    ai_classifier.call_ai_provider = fake_call_ai_provider
    try:
        results, error, _latency, meta = asyncio.run(
            ai_classifier.classify_findings_batch(
                findings=[
                    {"id": "f1", "title": "A", "severity": "high", "tool": "dalfox", "evidence": {}},
                    {"id": "f2", "title": "B", "severity": "medium", "tool": "nuclei", "evidence": {}},
                ],
                scan_context={},
                ai_url="https://mock.provider/v1/chat/completions",
                ai_api_key="sk-mock",
                model="mock-model",
                mask_host="example.com",
            )
        )
    finally:
        ai_classifier.call_ai_provider = original

    assert meta is not None
    assert meta["provider_used"] is True
    assert set(meta["provider_finding_ids"]) == {"f1", "f2"}
    assert set(meta["fallback_finding_ids"]) == set()
    assert error is not None  # includes split retry warning
    assert results["f1"].classification_source == "provider"
    assert results["f2"].classification_source == "provider"


def test_response_ai_enhancement_surfaces_top_level_provider_metadata():
    async def fake_validate_finding_with_response(*args, **kwargs):  # noqa: ANN002, ANN003
        return ai_classifier.ResponseValidationResult(
            verdict="false_positive",
            confidence=0.93,
            reasoning="Response is a generic HTML shell, not an exposed admin resource.",
            evidence="<html>Loading...</html>",
        )

    original_validate = ai_classifier.validate_finding_with_response
    original_should_use = ai_classifier.should_use_ai_validation
    ai_classifier.validate_finding_with_response = fake_validate_finding_with_response
    ai_classifier.should_use_ai_validation = lambda *args, **kwargs: True  # noqa: ARG005
    try:
        finding = asyncio.run(
            ai_classifier.enhance_finding_with_ai(
                finding={
                    "id": "f-stage3",
                    "tool": "forced_browsing",
                    "title": "Accessible Sensitive File: /admin",
                    "severity": "high",
                    "confidence": 0.8,
                },
                response_body="<html>Loading...</html>",
                response_headers={"content-type": "text/html"},
                ai_url="https://mock.provider/v1/chat/completions",
                ai_api_key="sk-mock",
                model="mock-model",
            )
        )
    finally:
        ai_classifier.validate_finding_with_response = original_validate
        ai_classifier.should_use_ai_validation = original_should_use

    assert finding["ai_verdict"] == "false_positive"
    assert finding["ai_confidence"] == 0.93
    assert finding["ai_confidence_percent"] == 93
    assert finding["ai_classification_source"] == "provider"
    assert finding["ai_rationale"].startswith("Response is a generic")
    assert finding["ai_validation"]["classification_source"] == "provider"
    assert finding["filter_reason"].startswith("AI FP detection")
