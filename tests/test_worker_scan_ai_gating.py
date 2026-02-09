"""
Tests for scan-time AI command/env gating in worker.run_scan.
"""

import asyncio
import os
import sys
import types



sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace())
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *args, **kwargs: None))

import worker  # noqa: E402


class _FakeProcess:
    def __init__(self, stdout_payload: bytes, stderr_payload: bytes = b""):
        self.stdout = asyncio.StreamReader()
        self.stdout.feed_data(stdout_payload)
        self.stdout.feed_eof()

        self.stderr = asyncio.StreamReader()
        if stderr_payload:
            self.stderr.feed_data(stderr_payload)
        self.stderr.feed_eof()
        self.returncode = 0

    async def wait(self):
        return self.returncode


def test_run_scan_disables_scan_ai_when_classification_disabled(monkeypatch):
    captured = {}

    async def _fake_create_subprocess_exec(*cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["env"] = dict(kwargs.get("env") or {})
        return _FakeProcess(b'{"ok": true, "findings": []}')

    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", _fake_create_subprocess_exec)
    monkeypatch.setattr(
        worker,
        "_load_runtime_ai_settings",
        lambda: {
            "ai_url": "https://ai.example/v1/chat/completions",
            "ai_api_key": "secret",
            "ai_model": "model-a",
            "ai_model_fallback": "model-b",
            "ai_mask_host": "masked.example",
            "ai_scan_classification_enabled": False,
            "ai_classify_min_severity": "medium",
            "ai_verify_min_severity": "medium",
        },
    )

    result = asyncio.run(worker.run_scan("https://example.com", {"scan_type": "smart"}))
    cmd = captured["cmd"]
    env = captured["env"]

    assert result.get("ok") is True
    assert "--ai" not in cmd
    assert env["AI_SCAN_CLASSIFICATION_ENABLED"] == "false"
    assert env["AI_CLASSIFY_MIN_SEVERITY"] == "medium"
    assert env["AI_VERIFY_MIN_SEVERITY"] == "medium"


def test_run_scan_enables_scan_ai_when_classification_enabled(monkeypatch):
    captured = {}

    async def _fake_create_subprocess_exec(*cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["env"] = dict(kwargs.get("env") or {})
        return _FakeProcess(b'{"ok": true, "findings": []}')

    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", _fake_create_subprocess_exec)
    monkeypatch.setattr(
        worker,
        "_load_runtime_ai_settings",
        lambda: {
            "ai_url": "https://ai.example/v1/chat/completions",
            "ai_api_key": "secret",
            "ai_model": "model-a",
            "ai_model_fallback": "model-b",
            "ai_mask_host": "masked.example",
            "ai_scan_classification_enabled": False,
            "ai_classify_min_severity": "high",
            "ai_verify_min_severity": "high",
        },
    )

    options = {
        "scan_type": "smart",
        "ai_scan_classification_enabled": True,
        "ai_classify_min_severity": "low",
        "ai_verify_min_severity": "critical",
    }

    result = asyncio.run(worker.run_scan("https://example.com", options))
    cmd = captured["cmd"]
    env = captured["env"]

    assert result.get("ok") is True
    assert "--ai" in cmd
    assert "--ai-url" in cmd
    assert "--ai-api-key" in cmd
    assert "--model" in cmd
    assert env["AI_SCAN_CLASSIFICATION_ENABLED"] == "true"
    assert env["AI_CLASSIFY_MIN_SEVERITY"] == "low"
    assert env["AI_VERIFY_MIN_SEVERITY"] == "critical"
