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
