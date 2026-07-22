"""
Unit tests for SPA catch-all detection hardening.
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import common


def test_spa_detection_high_confidence_sets_flag(monkeypatch: pytest.MonkeyPatch):
    async def fake_fetch(_url: str, timeout: int = 10, max_bytes: int = common.MAX_SIMPLE_FETCH_BYTES):
        _ = timeout, max_bytes
        return (
            200,
            "<!doctype html><html><head><title>App</title></head>"
            "<body><div id=\"root\"></div><script src=\"/assets/app.js\"></script></body></html>",
            "text/html; charset=utf-8",
        )

    monkeypatch.setattr(common, "_fetch_url_simple", fake_fetch)

    result = asyncio.run(common.detect_spa_catch_all("https://example.com"))

    assert result["is_spa_catch_all"] is True
    assert result["confidence"] == "high"
    assert result["evidence"]["html_shell"] is True
    assert result["evidence"]["has_spa_indicators"] is True


def test_spa_detection_medium_confidence_does_not_set_flag(monkeypatch: pytest.MonkeyPatch):
    async def fake_fetch(_url: str, timeout: int = 10, max_bytes: int = common.MAX_SIMPLE_FETCH_BYTES):
        _ = timeout, max_bytes
        return (
            200,
            "<!doctype html><html><head><title>Login</title></head>"
            "<body><h1>Please sign in</h1></body></html>",
            "text/html",
        )

    monkeypatch.setattr(common, "_fetch_url_simple", fake_fetch)

    result = asyncio.run(common.detect_spa_catch_all("https://example.com"))

    assert result["is_spa_catch_all"] is False
    assert result["confidence"] == "medium"
    assert result["evidence"]["all_paths_200"] is True
    assert result["evidence"]["content_identical"] is True
    assert result["evidence"]["html_shell"] is True
    assert result["evidence"]["has_spa_indicators"] is False


def test_spa_detection_non_html_does_not_set_flag(monkeypatch: pytest.MonkeyPatch):
    async def fake_fetch(_url: str, timeout: int = 10, max_bytes: int = common.MAX_SIMPLE_FETCH_BYTES):
        _ = timeout, max_bytes
        return (200, '{"error":"not found"}', "application/json")

    monkeypatch.setattr(common, "_fetch_url_simple", fake_fetch)

    result = asyncio.run(common.detect_spa_catch_all("https://example.com"))

    assert result["is_spa_catch_all"] is False
    assert result["confidence"] == "low"
    assert result["evidence"]["all_paths_200"] is True
    assert result["evidence"]["content_identical"] is True
    assert result["evidence"]["html_shell"] is False


# ---------------------------------------------------------------------------
# Forced browsing under an SPA catch-all: must NOT skip everything — a
# content-validated exposure (e.g. /metrics) has to still surface.
# ---------------------------------------------------------------------------

from scanner_tools import access_control_checks as acc  # noqa: E402


def test_forced_browsing_under_spa_runs_content_validated_categories(monkeypatch):
    async def fake_spa(url, timeout=10):
        return {"is_spa_catch_all": True, "evidence": {"html_shell": True}}

    async def fake_homepage_hash(url, timeout=10):
        return "spahash"

    tested_paths = []

    async def fake_test_single_path(base_url, path, timeout=10, homepage_hash=None, max_body_bytes=0):
        tested_paths.append(path)
        # Simulate the real content-validation outcome: /metrics serves a real
        # Prometheus body (validated high); every other path is the SPA shell,
        # rejected by content validation and downgraded to info.
        if path.rstrip("/") == "/metrics":
            return {"path": path, "url": base_url + path, "status_code": 200,
                    "category": "debug_dev", "severity": "high", "accessible": True,
                    "protected": False, "redirects": False,
                    "content_type": "text/plain; version=0.0.4"}
        return {"path": path, "url": base_url + path, "status_code": 200,
                "category": "debug_dev", "severity": "info", "accessible": False,
                "protected": False, "redirects": False,
                "false_positive_detected": True, "content_validation_failed": True}

    monkeypatch.setattr(acc, "detect_spa_catch_all", fake_spa)
    monkeypatch.setattr(acc, "fetch_homepage_hash", fake_homepage_hash)
    monkeypatch.setattr(acc, "test_single_path", fake_test_single_path)

    res = asyncio.run(acc.check_forced_browsing("http://spa.test", max_total_time=30))

    # Did NOT early-return empty:
    assert res["spa_detected"] is True
    assert res["paths_tested"] > 0
    assert tested_paths, "forced browsing skipped all paths under SPA"
    # Only content-validated categories are tested under SPA:
    for cat in res["categories_tested"]:
        assert cat in acc.CATEGORY_CONTENT_VALIDATORS, f"non-validated category {cat} tested under SPA"
    # /metrics surfaced as a validated high; shell paths did not:
    highs = [f for f in res["findings"] if f.get("accessible") and f.get("severity") == "high"]
    assert any(f["path"].rstrip("/") == "/metrics" for f in highs), "validated /metrics exposure lost under SPA"
