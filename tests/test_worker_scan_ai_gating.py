"""
Tests for scan-time AI command/env gating in worker.run_scan.
"""

import asyncio
import os
import sys
import types
from datetime import datetime, timezone



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


class _FakeCredentialPool:
    async def fetchrow(self, query, target_id):
        return {
            "auth_kind": "bearer",
            "header_name": None,
            "secret_value": "runtime-target-secret",
            "metadata_json": {},
        }

    async def fetch(self, query, target_id):
        return []


class _FakePrincipalPool(_FakeCredentialPool):
    async def fetch(self, query, target_id):
        return [
            {
                "id": "00000000-0000-0000-0000-000000000010",
                "label": "tenant-a-user",
                "role": "attacker",
                "tenant_id": "tenant-a",
                "auth_kind": "bearer",
                "header_name": None,
                "secret_value": "principal-runtime-secret",
                "metadata_json": {"purpose": "cross-tenant"},
            }
        ]


class _FakeFinalizeConnection:
    def __init__(self):
        self.executions = []

    async def execute(self, query, *args):
        self.executions.append((query, args))


class _FakeFinalizePool:
    def __init__(self):
        self.conn = _FakeFinalizeConnection()

    def acquire(self):
        return self

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


def test_hydrate_ai_gate_options_loads_secrets_only_in_worker(monkeypatch):
    target_id = "00000000-0000-0000-0000-000000000001"
    monkeypatch.setattr(worker, "db_pool", _FakeCredentialPool())
    monkeypatch.setattr(
        worker,
        "_load_runtime_ai_settings",
        lambda: {
            "ai_url": "https://ai.example/v1/chat/completions",
            "ai_api_key": "runtime-ai-key",
            "ai_model": "model-a",
            "ai_model_fallback": "",
        },
    )

    options = {
        "run_kind": "ai_api",
        "ai_target_id": target_id,
        "ai_target": {
            "id": target_id,
            "endpoint_url": "https://example.test/chat",
            "credential_ref": {"ai_target_id": target_id, "configured": True},
        },
    }

    hydrated = asyncio.run(worker._hydrate_ai_gate_options(options))

    assert hydrated["ai_target"]["credential"]["secret"] == "runtime-target-secret"
    assert "credential_ref" not in hydrated["ai_target"]
    assert hydrated["ai_api_key"] == "runtime-ai-key"


def test_hydrate_ai_gate_options_loads_principal_credentials_in_worker(monkeypatch):
    target_id = "00000000-0000-0000-0000-000000000001"
    monkeypatch.setattr(worker, "db_pool", _FakePrincipalPool())
    monkeypatch.setattr(worker, "_load_runtime_ai_settings", lambda: {})

    options = {
        "run_kind": "ai_rag",
        "ai_target_id": target_id,
        "ai_target": {
            "id": target_id,
            "endpoint_url": "https://example.test/rag",
            "credential_ref": {"ai_target_id": target_id, "configured": True},
            "principal_refs": [
                {
                    "id": "00000000-0000-0000-0000-000000000010",
                    "label": "tenant-a-user",
                    "role": "attacker",
                    "credential_configured": True,
                }
            ],
        },
    }

    hydrated = asyncio.run(worker._hydrate_ai_gate_options(options))

    assert hydrated["ai_target"]["principals"][0]["credential"]["secret"] == "principal-runtime-secret"
    assert hydrated["ai_target"]["principals"][0]["role"] == "attacker"
    assert "principal_refs" not in hydrated["ai_target"]


def test_finalize_ai_finding_retest_marks_reproduced_finding(monkeypatch):
    pool = _FakeFinalizePool()
    monkeypatch.setattr(worker, "db_pool", pool)
    verification_id = "00000000-0000-0000-0000-000000000002"
    finding_id = "00000000-0000-0000-0000-000000000003"

    asyncio.run(worker.finalize_ai_finding_retest(
        options={
            "ai_finding_retest": {
                "verification_id": verification_id,
                "finding_id": finding_id,
                "mode": "same_probe",
                "probe_id": "smoke.prompt-leakage",
                "probe_family": "prompt_leakage",
            }
        },
        result={
            "findings": [
                {
                    "confidence": 0.93,
                    "evidence": {"probe_id": "smoke.prompt-leakage", "probe_family": "prompt_leakage"},
                }
            ],
            "ai_gate": {"errors": [], "transcripts": [], "decision": {"decision": "block"}},
        },
        scan_id="00000000-0000-0000-0000-000000000004",
        completed_at=datetime.now(timezone.utc),
        error=None,
    ))

    verification_update = pool.conn.executions[0][1]
    finding_update = pool.conn.executions[1][1]
    assert verification_update[0] == "completed"
    assert verification_update[1] == "still_vulnerable"
    assert verification_update[2] == "exploited"
    assert finding_update[1] == "exploited"


def test_run_scan_rejects_invalid_explicit_scan_type():
    try:
        asyncio.run(worker.run_scan("https://example.com", {"scan_type": "standard-ish"}))
    except ValueError as exc:
        assert "scan_type must be one of" in str(exc)
    else:
        raise AssertionError("invalid scan_type should be rejected before scanner subprocess starts")


def test_run_scan_maps_explicit_standard_to_standard_flag(monkeypatch):
    captured = {}

    async def _fake_create_subprocess_exec(*cmd, **kwargs):
        captured["cmd"] = list(cmd)
        return _FakeProcess(b'{"ok": true, "findings": []}')

    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", _fake_create_subprocess_exec)
    monkeypatch.setattr(worker, "_load_runtime_ai_settings", lambda: {})

    result = asyncio.run(worker.run_scan("https://example.com", {"scan_type": "standard"}))

    assert result.get("ok") is True
    assert "--standard" in captured["cmd"]
    assert "--quick" not in captured["cmd"]


def test_run_scan_maps_active_worklist_budget_flag(monkeypatch):
    captured = {}

    async def _fake_create_subprocess_exec(*cmd, **kwargs):
        captured["cmd"] = list(cmd)
        return _FakeProcess(b'{"ok": true, "findings": []}')

    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", _fake_create_subprocess_exec)
    monkeypatch.setattr(worker, "_load_runtime_ai_settings", lambda: {})

    result = asyncio.run(worker.run_scan(
        "https://example.com",
        {"scan_type": "smart", "custom_budget": {"active_worklist_max": 50000}},
    ))

    assert result.get("ok") is True
    assert "--budget-active-worklist-max" in captured["cmd"]
    assert captured["cmd"][captured["cmd"].index("--budget-active-worklist-max") + 1] == "50000"


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


def test_run_scan_null_classification_option_uses_runtime_setting(monkeypatch):
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
            "ai_scan_classification_enabled": True,
            "ai_classify_min_severity": "medium",
            "ai_verify_min_severity": "medium",
        },
    )

    # Simulates persisted scan options that include the key with null value.
    options = {
        "scan_type": "smart",
        "ai_scan_classification_enabled": None,
    }

    result = asyncio.run(worker.run_scan("https://example.com", options))
    cmd = captured["cmd"]
    env = captured["env"]

    assert result.get("ok") is True
    assert "--ai" in cmd
    assert env["AI_SCAN_CLASSIFICATION_ENABLED"] == "true"
    assert env["AI_CLASSIFY_MIN_SEVERITY"] == "medium"
