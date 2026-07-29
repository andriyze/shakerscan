import json
import os
import time

from scanner.scanner_tools import model_intake_providers as providers


def test_provider_registry_keeps_scanners_out_of_execution_and_policy_classes(tmp_path, monkeypatch):
    heartbeat = tmp_path / "heartbeat.json"
    heartbeat.write_text("{}")
    os.utime(heartbeat, (time.time(), time.time()))
    monkeypatch.setenv("MODEL_INTAKE_SANDBOX_QUEUE_DIR", str(tmp_path))
    monkeypatch.setenv(
        "MODEL_INTAKE_SANDBOX_RUNTIME_ADAPTERS_JSON",
        json.dumps({".safetensors": {"argv": ["/runtime/check", "{artifact}"]}}),
    )

    readiness = providers.provider_readiness()
    by_id = {item["id"]: item for item in readiness["providers"]}

    assert by_id["isolated-sandbox-service"]["ready"] is True
    assert by_id["isolated-sandbox-service"]["kind"] == "execution_provider"
    assert by_id["embedding-security-evaluator"]["runner_included"] is False
    assert by_id["embedded-admission-policy"]["kind"] == "policy_provider"
    assert by_id["opa-policy"]["status"] == "NOT_IMPLEMENTED"
    assert by_id["core-report-exporter"]["kind"] == "report_provider"


def test_sandbox_provider_is_explicit_when_runtime_adapter_is_absent(tmp_path, monkeypatch):
    heartbeat = tmp_path / "heartbeat.json"
    heartbeat.write_text("{}")
    monkeypatch.setenv("MODEL_INTAKE_SANDBOX_QUEUE_DIR", str(tmp_path))
    monkeypatch.delenv("MODEL_INTAKE_SANDBOX_RUNTIME_ADAPTERS_JSON", raising=False)

    result = providers.SandboxExecutionProvider().readiness()

    assert result["ready"] is True
    assert result["runtime_adapter_extensions"] == []
    assert "known-answer" in result["limitation"]
