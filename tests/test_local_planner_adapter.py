import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import local_planner_adapter as adapter  # noqa: E402


def test_safe_agent_env_strips_provider_and_secret_variables(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "secret")
    monkeypatch.setenv("CODEX_HOME", "/secret-home")
    monkeypatch.setenv("SAFE_VISIBLE", "yes")

    env, count = adapter.safe_agent_env()

    assert "OPENAI_API_KEY" not in env
    assert "CODEX_HOME" not in env
    assert env["SAFE_VISIBLE"] == "yes"
    assert count >= 2


def test_build_prompt_redacts_secret_shaped_context():
    prompt = adapter.build_prompt(
        "inspect",
        {
            "context_hash": "a" * 64,
            "allowed_commands": ["target.get"],
            "authorization": "Bearer top-secret-token",
            "notes": "password=hunter2 and eyJaaaaaa.bbbbbb.cccccc",
        },
        [{"name": "target.get", "status": "read_only", "risk_tier": "read_only"}],
    )

    assert "top-secret-token" not in prompt
    assert "hunter2" not in prompt
    assert "eyJaaaaaa.bbbbbb.cccccc" not in prompt
    assert prompt.count("[REDACTED") >= 3


def test_run_codex_is_bounded_and_disables_execution_features(monkeypatch, tmp_path):
    binary = tmp_path / "codex"
    binary.write_text("binary", encoding="utf-8")
    binary.chmod(0o755)
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[1:] == ["--version"]:
            return type("Proc", (), {"returncode": 0, "stdout": "codex-cli 1.2.3\n", "stderr": ""})()
        output_path = Path(argv[argv.index("--output-last-message") + 1])
        output_path.write_text('{"objective":"inspect"}', encoding="utf-8")
        return type("Proc", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(adapter.subprocess, "run", fake_run)
    raw, metadata = adapter.run_codex("bounded prompt", timeout_seconds=999, binary=str(binary))

    argv, kwargs = calls[-1]
    assert raw == '{"objective":"inspect"}'
    assert argv[1:4] == ["exec", "--sandbox", "read-only"]
    for feature in adapter.DISABLED_CODEX_FEATURES:
        index = argv.index(feature)
        assert argv[index - 1] == "--disable"
    assert kwargs["timeout"] == adapter.MAX_TIMEOUT_SECONDS
    assert kwargs["cwd"].startswith("/tmp/") or "shakerscan-planner-" in kwargs["cwd"]
    assert metadata["planner_execution_enabled"] is False
    assert metadata["retry_count"] == 0
    assert metadata["fingerprint"]


def test_current_scorecard_requires_fixture_and_planner_fingerprints(tmp_path):
    fixtures = tmp_path / "fixtures.json"
    fixtures.write_text(json.dumps([{
        "id": "fixture-1",
        "context_pack": {"context_hash": "a" * 64},
        "expected": {"max_risk_tier": "read_only"},
        "gold_plan": {},
    }]), encoding="utf-8")
    scorecard = tmp_path / "scorecard.json"
    identity = {"fingerprint": "planner-fingerprint"}
    payload = {
        "schema_version": adapter.SCORECARD_VERSION,
        "agent": "codex",
        "planner_fingerprint": "planner-fingerprint",
        "adapter_version": adapter.ADAPTER_VERSION,
        "fixture_sha256": adapter.file_sha256(fixtures),
        "passed": True,
        "report": {"passed": True, "passed_count": 1, "fixture_count": 1, "results": [{"fixture_id": "fixture-1", "passed": True}]},
    }
    scorecard.write_text(json.dumps(payload), encoding="utf-8")

    assert adapter.require_current_scorecard(scorecard, fixtures, identity)["passed"] is True

    payload["planner_fingerprint"] = "stale"
    scorecard.write_text(json.dumps(payload), encoding="utf-8")
    try:
        adapter.require_current_scorecard(scorecard, fixtures, identity)
    except adapter.AdapterError as exc:
        assert "planner_fingerprint" in str(exc)
    else:
        raise AssertionError("stale planner scorecard should fail closed")


def test_plan_posts_only_parse_then_dry_run_persistence(monkeypatch, tmp_path):
    fixtures = tmp_path / "fixtures.json"
    fixtures.write_text(json.dumps([{
        "id": "fixture-1",
        "context_pack": {"context_hash": "a" * 64},
        "expected": {"max_risk_tier": "read_only"},
        "gold_plan": {},
    }]), encoding="utf-8")
    scorecard = tmp_path / "scorecard.json"
    identity = {"agent": "codex", "version": "1", "fingerprint": "fp", "binary_path": "/codex", "adapter_version": adapter.ADAPTER_VERSION}
    scorecard.write_text(json.dumps({
        "schema_version": adapter.SCORECARD_VERSION, "agent": "codex",
        "planner_fingerprint": "fp", "adapter_version": adapter.ADAPTER_VERSION,
        "fixture_sha256": adapter.file_sha256(fixtures), "passed": True,
        "report": {"passed": True, "passed_count": 1, "fixture_count": 1, "results": [{"fixture_id": "fixture-1", "passed": True}]},
    }), encoding="utf-8")
    monkeypatch.setattr(adapter, "codex_identity", lambda binary=None: identity)
    monkeypatch.setattr(adapter, "run_codex", lambda *args, **kwargs: ('{"objective":"inspect"}', {**identity, "planner_execution_enabled": False}))
    calls = []

    def fake_api(base_url, path, *, method="GET", payload=None):
        calls.append((method, path, payload))
        if path.startswith("/arsenal/context-packs"):
            return {"context_packs": [{"id": "ctx", "context_pack": {"context_hash": "a" * 64, "allowed_commands": ["target.get"]}}]}
        if path == "/arsenal/commands":
            return {"commands": [{"name": "target.get", "status": "read_only", "risk_tier": "read_only"}]}
        if path == "/agents/local/plan/parse":
            return {"accepted": True, "context_hash": "a" * 64, "operation_plan": {"objective": "inspect", "planner": {}, "context_hash": "a" * 64, "target_scope": {}, "risk_tier": "read_only", "actions": []}}
        if path == "/arsenal/plans":
            return {"operation_plan": {"id": "plan-id", **payload}}
        raise AssertionError(path)

    monkeypatch.setattr(adapter, "api_json", fake_api)
    result = adapter.plan("http://api", "ctx", "inspect", fixtures, scorecard, timeout_seconds=30)

    assert result["accepted"] is True
    writes = [(method, path) for method, path, _ in calls if method == "POST"]
    assert writes == [("POST", "/agents/local/plan/parse"), ("POST", "/arsenal/plans")]
    assert all("execute" not in path for _, path in writes)
    persisted_payload = calls[-1][2]
    assert persisted_payload["planner"]["eval_passed"] is True
    assert persisted_payload["planner"]["planner_execution_enabled"] is False
