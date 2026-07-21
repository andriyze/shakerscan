import json
import sys
from pathlib import Path

import pytest


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


def test_planner_error_excerpt_drops_prompt_preview():
    stderr = "session banner\nINPUT: sensitive target observation\nERROR: schema is invalid\ncaused by: allOf unsupported"

    excerpt = adapter._planner_error_excerpt(stderr)

    assert excerpt == "ERROR: schema is invalid caused by: allOf unsupported"
    assert "sensitive target" not in excerpt


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


def test_operation_plan_schema_uses_closed_responses_compatible_envelopes():
    schema = adapter.operation_plan_schema()

    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == set(schema["required"])
    for key in ("planner", "target_scope", "budget", "constraints"):
        assert schema["properties"][key]["type"] == "string"
    action = schema["properties"]["actions"]["items"]
    assert action["additionalProperties"] is False
    assert set(action["properties"]) == set(action["required"])
    assert action["properties"]["parameters"]["type"] == "string"


def test_operation_plan_envelopes_decode_before_api_validation():
    plan = {
        "planner": '{"kind":"local_agent","agent":"codex"}',
        "target_scope": '{"target_id":"target-1"}',
        "budget": '{"requests":10}',
        "constraints": '{"blocked_by":[]}',
        "actions": [{"parameters": '{"check_family":"xss"}'}],
    }

    adapter._decode_local_operation_plan_envelopes(plan)

    assert plan["planner"]["agent"] == "codex"
    assert plan["target_scope"] == {"target_id": "target-1"}
    assert plan["budget"] == {"requests": 10}
    assert plan["actions"][0]["parameters"] == {"check_family": "xss"}


def test_operation_plan_envelopes_reject_non_object_json():
    with pytest.raises(adapter.AdapterError, match="budget must encode a JSON object"):
        adapter._decode_local_operation_plan_envelopes({"budget": "[]"})


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


def test_research_prompt_filters_blocked_commands_and_redacts_target_data():
    prompt = adapter.build_research_prompt({
        "id": "obs-1",
        "context_hash": "a" * 64,
        "observation_pack": {
            "objective": "inspect",
            "authorization": "Bearer secret-value",
            "proposable_commands": [
                {"name": "asm.gaps", "proposable": True},
                {"name": "asm.test", "proposable": False, "blocked_by": ["approval_receipt_missing"]},
            ],
        },
    })

    assert "secret-value" not in prompt
    assert '"name":"asm.gaps"' in prompt
    assert '"name":"asm.test"' not in prompt
    assert "one JSON object" in prompt


def test_research_decision_schema_has_no_execution_or_receipt_fields():
    schema = adapter.research_decision_schema({
        "id": "obs-1",
        "context_hash": "a" * 64,
        "observation_pack": {
            "proposable_commands": [
                {"name": "finding.get", "proposable": True},
                {"name": "finding.retest", "proposable": False},
                {"name": "asm.gaps", "proposable": True},
            ],
        },
    })
    properties = schema["properties"]

    assert schema["additionalProperties"] is False
    assert "execute" not in properties
    assert "approval_receipt_id" not in properties
    assert "scope_receipt_id" not in properties
    assert properties["decision"]["enum"] == ["execute_action", "request_input", "stop"]
    assert properties["observation_id"] == {"type": "string", "const": "obs-1"}
    assert properties["context_hash"] == {"type": "string", "const": "a" * 64}
    assert properties["action"]["properties"]["command"]["enum"] == ["", "asm.gaps", "finding.get"]
    assert properties["action"]["properties"]["parameters"]["type"] == "string"
    assert "allOf" not in schema
    assert properties["expected_signal"]["type"] == ["string", "null"]
    assert properties["falsifier"]["type"] == ["string", "null"]


def test_research_decision_schema_without_commands_allows_only_terminal_decisions():
    schema = adapter.research_decision_schema({
        "id": "obs-empty",
        "context_hash": "b" * 64,
        "observation_pack": {"proposable_commands": []},
    })

    assert schema["properties"]["decision"]["enum"] == ["request_input", "stop"]
    assert schema["properties"]["action"]["properties"]["command"]["enum"] == [""]


def test_local_research_parameter_envelope_decodes_nested_json_object():
    decision = {"action": {"command": "scan.focused_family", "parameters": '{"check_family":"xss","options":{"depth":2}}'}}

    adapter._decode_local_research_parameters(decision)

    assert decision["action"]["parameters"] == {
        "check_family": "xss",
        "options": {"depth": 2},
    }


def test_local_research_parameter_envelope_rejects_non_object_json():
    decision = {"action": {"command": "asm.gaps", "parameters": "[]"}}

    with pytest.raises(adapter.AdapterError, match="JSON object"):
        adapter._decode_local_research_parameters(decision)


def test_run_codex_research_rejects_execute_action_without_signal(monkeypatch):
    observation = {
        "id": "obs-1",
        "context_hash": "a" * 64,
        "observation_pack": {
            "proposable_commands": [{"name": "asm.gaps", "proposable": True}],
        },
    }
    candidate = {
        "decision_version": adapter.RESEARCH_DECISION_VERSION,
        "decision": "execute_action",
        "observation_id": "obs-1",
        "context_hash": "a" * 64,
        "hypothesis_id": None,
        "action": {"command": "asm.gaps", "parameters": "{}"},
        "expected_signal": "",
        "falsifier": "no gap remains",
        "reason": "inspect",
        "confidence": 0.8,
        "requested_input": None,
        "stop_reason": None,
    }
    monkeypatch.setattr(adapter, "_run_codex_structured", lambda *args, **kwargs: (
        json.dumps(candidate),
        {"prompt_bytes": 100, "output_bytes": 100},
    ))

    try:
        adapter.run_codex_research_decision(observation, timeout_seconds=30)
    except adapter.AdapterError as exc:
        assert "expected_signal" in str(exc)
    else:
        raise AssertionError("an execute action without an expected signal must fail locally")


@pytest.mark.parametrize(
    ("decision_type", "requested_input", "stop_reason", "error"),
    [
        ("request_input", "", None, "missing requested_input"),
        ("request_input", "Provide a second authenticated principal.", "also stop", "must not include stop_reason"),
        ("stop", None, "too short", "missing stop_reason"),
        ("stop", "provide credentials", "No useful bounded action remains for this target.", "must not include requested_input"),
    ],
)
def test_local_research_terminal_decisions_require_their_semantic_fields(
    decision_type, requested_input, stop_reason, error,
):
    observation = {
        "id": "obs-1",
        "context_hash": "a" * 64,
        "observation_pack": {"proposable_commands": []},
    }
    decision = {
        "decision": decision_type,
        "observation_id": "obs-1",
        "context_hash": "a" * 64,
        "action": {"command": "", "parameters": {}},
        "expected_signal": None,
        "falsifier": None,
        "requested_input": requested_input,
        "stop_reason": stop_reason,
    }

    with pytest.raises(adapter.AdapterError, match=error):
        adapter._validate_local_research_decision(decision, observation)


def test_research_episode_runner_submits_one_decision_at_a_time(monkeypatch):
    calls = []
    states = [
        {
            "episode": {"id": "episode-1", "status": "awaiting_planner", "terminal": False},
            "current_observation": {"id": "obs-1", "context_hash": "a" * 64, "observation_pack": {}},
        },
        {
            "episode": {"id": "episode-1", "status": "completed", "terminal": True},
            "current_observation": {"id": "obs-2", "context_hash": "b" * 64, "observation_pack": {}},
        },
    ]

    monkeypatch.setattr(adapter, "codex_identity", lambda binary=None: {
        "agent": "codex", "version": "1", "fingerprint": "fp",
        "binary_path": "/codex", "adapter_version": adapter.ADAPTER_VERSION,
    })
    monkeypatch.setattr(adapter, "run_codex_research_decision", lambda *args, **kwargs: ({
        "decision_version": adapter.RESEARCH_DECISION_VERSION,
        "decision": "stop",
        "observation_id": "obs-1",
        "context_hash": "a" * 64,
        "hypothesis_id": None,
        "action": {"command": "", "parameters": {}},
        "expected_signal": None,
        "falsifier": None,
        "reason": "done",
        "confidence": 1,
        "requested_input": None,
        "stop_reason": "objective_complete",
    }, {
        "estimated_model_tokens": 100, "sandbox": "read-only", "tools_disabled": [],
        "workdir_isolated": True, "provider_api_keys_stripped": True,
        "model_tokens_metering": "estimated",
    }))

    def fake_api(base_url, path, *, method="GET", payload=None):
        calls.append((method, path, payload))
        if method == "GET":
            return states.pop(0) if len(states) > 1 else states[0]
        assert path == "/research/episodes/episode-1/decisions"
        return {"accepted": True, "decision_id": "decision-1", "episode": {"status": "completed"}}

    monkeypatch.setattr(adapter, "api_json", fake_api)
    result = adapter.run_research_episode("http://api", "episode-1", max_decisions=5, timeout_seconds=30)

    writes = [call for call in calls if call[0] == "POST"]
    assert len(writes) == 1
    assert writes[0][2]["execute"] is True
    assert writes[0][2]["model_tokens_used"] == 100
    assert result["decision_count"] == 1


def test_research_episode_runner_rejects_server_autopilot_before_planning(monkeypatch):
    calls = []

    monkeypatch.setattr(adapter, "codex_identity", lambda binary=None: {
        "agent": "codex", "version": "1", "fingerprint": "fp",
        "binary_path": "/codex", "adapter_version": adapter.ADAPTER_VERSION,
    })

    def fail_if_planned(*_args, **_kwargs):
        raise AssertionError("local Codex must not plan while server autopilot is enabled")

    def fake_api(base_url, path, *, method="GET", payload=None):
        calls.append((method, path, payload))
        return {
            "episode": {
                "id": "episode-1",
                "status": "awaiting_planner",
                "terminal": False,
                "autopilot_enabled": True,
            },
            "current_observation": {
                "id": "obs-1",
                "context_hash": "a" * 64,
                "observation_pack": {},
            },
        }

    monkeypatch.setattr(adapter, "run_codex_research_decision", fail_if_planned)
    monkeypatch.setattr(adapter, "api_json", fake_api)

    with pytest.raises(adapter.AdapterError, match="server autopilot is enabled"):
        adapter.run_research_episode(
            "http://api", "episode-1", max_decisions=5, timeout_seconds=30
        )

    assert calls == [("GET", "/research/episodes/episode-1", None)]


def test_research_episode_runner_returns_dispatched_scan_without_polling(monkeypatch):
    calls = []
    observation = {
        "id": "obs-1",
        "context_hash": "a" * 64,
        "observation_pack": {
            "proposable_commands": [{"name": "scan.focused_family", "proposable": True}],
        },
    }
    decision = {
        "decision_version": adapter.RESEARCH_DECISION_VERSION,
        "decision": "execute_action",
        "observation_id": "obs-1",
        "context_hash": "a" * 64,
        "hypothesis_id": None,
        "action": {"command": "scan.focused_family", "parameters": {"check_family": "xss"}},
        "expected_signal": "The focused scan records a repeatable XSS signal.",
        "falsifier": "The focused scan completes without a repeatable XSS signal.",
        "reason": "Test the highest-priority family.",
        "confidence": 0.8,
        "requested_input": None,
        "stop_reason": None,
    }
    monkeypatch.setattr(adapter, "codex_identity", lambda binary=None: {
        "agent": "codex", "version": "1", "fingerprint": "fp",
        "binary_path": "/codex", "adapter_version": adapter.ADAPTER_VERSION,
    })
    monkeypatch.setattr(adapter, "run_codex_research_decision", lambda *args, **kwargs: (
        decision,
        {
            "estimated_model_tokens": 100, "sandbox": "read-only", "tools_disabled": [],
            "workdir_isolated": True, "provider_api_keys_stripped": True,
            "model_tokens_metering": "estimated",
        },
    ))

    def fake_api(base_url, path, *, method="GET", payload=None):
        calls.append((method, path, payload))
        if method == "GET":
            return {
                "episode": {"id": "episode-1", "status": "awaiting_planner", "terminal": False},
                "current_observation": observation,
            }
        return {
            "accepted": True,
            "dispatched": True,
            "decision_id": "decision-1",
            "episode": {"id": "episode-1", "status": "awaiting_planner", "terminal": False},
            "current_observation": {"id": "obs-2", "observation_pack": {}},
            "decisions": [{
                "id": "decision-1",
                "policy_result": {
                    "observation_summary": {
                        "result": {"scan_id": "scan-1", "job_id": "job-1", "status": "queued"},
                        "operation_id": "command-result-1",
                        "command_result": {
                            "id": "command-result-1", "scan_id": "scan-1", "status": "queued",
                            "next_action": "/scans/scan-1",
                        },
                    },
                },
            }],
        }

    monkeypatch.setattr(adapter, "api_json", fake_api)
    result = adapter.run_research_episode("http://api", "episode-1", max_decisions=5, timeout_seconds=30)

    assert [(method, path) for method, path, _ in calls] == [
        ("GET", "/research/episodes/episode-1"),
        ("POST", "/research/episodes/episode-1/decisions"),
    ]
    assert result["awaiting_linked_work"] is True
    assert result["linked_work"] == {
        "kind": "scan",
        "command": "scan.focused_family",
        "status": "queued",
        "scan_id": "scan-1",
        "retest_id": None,
        "finding_id": None,
        "job_id": "job-1",
        "command_result_id": "command-result-1",
        "ui_path": "/scans/scan-1",
    }


def test_research_episode_runner_returns_dispatched_retest_from_observation(monkeypatch):
    calls = []
    observation = {
        "id": "obs-1",
        "context_hash": "a" * 64,
        "observation_pack": {
            "proposable_commands": [{"name": "finding.retest", "proposable": True}],
        },
    }
    decision = {
        "decision_version": adapter.RESEARCH_DECISION_VERSION,
        "decision": "execute_action",
        "observation_id": "obs-1",
        "context_hash": "a" * 64,
        "hypothesis_id": None,
        "action": {"command": "finding.retest", "parameters": {"finding_id": "finding-1"}},
        "expected_signal": "The replay reproduces the recorded anomaly.",
        "falsifier": "The replay behaves like the control request.",
        "reason": "Refresh finding proof.",
        "confidence": 0.8,
        "requested_input": None,
        "stop_reason": None,
    }
    monkeypatch.setattr(adapter, "codex_identity", lambda binary=None: {
        "agent": "codex", "version": "1", "fingerprint": "fp",
        "binary_path": "/codex", "adapter_version": adapter.ADAPTER_VERSION,
    })
    monkeypatch.setattr(adapter, "run_codex_research_decision", lambda *args, **kwargs: (
        decision,
        {
            "estimated_model_tokens": 100, "sandbox": "read-only", "tools_disabled": [],
            "workdir_isolated": True, "provider_api_keys_stripped": True,
            "model_tokens_metering": "estimated",
        },
    ))

    def fake_api(base_url, path, *, method="GET", payload=None):
        calls.append((method, path, payload))
        if method == "GET":
            return {
                "episode": {"id": "episode-1", "status": "awaiting_planner", "terminal": False},
                "current_observation": observation,
            }
        return {
            "accepted": True,
            "dispatched": True,
            "decision_id": "decision-1",
            "episode": {"id": "episode-1", "status": "awaiting_planner", "terminal": False},
            "current_observation": {
                "id": "obs-2",
                "observation_pack": {
                    "previous_observation": {
                        "result": {
                            "retest_id": "retest-1", "job_id": "job-1",
                            "finding_id": "finding-1", "status": "queued",
                        },
                        "operation_id": "command-result-1",
                    },
                },
            },
            "decisions": [],
        }

    monkeypatch.setattr(adapter, "api_json", fake_api)
    result = adapter.run_research_episode("http://api", "episode-1", max_decisions=5, timeout_seconds=30)

    assert len(calls) == 2
    assert result["linked_work"]["kind"] == "finding_retest"
    assert result["linked_work"]["retest_id"] == "retest-1"
    assert result["linked_work"]["finding_id"] == "finding-1"
    assert result["linked_work"]["ui_path"] == "/findings/finding-1"


def test_research_episode_runner_settles_async_work_before_planning(monkeypatch):
    calls = []
    monkeypatch.setattr(adapter, "codex_identity", lambda binary=None: {
        "agent": "codex", "version": "1", "fingerprint": "fp",
        "binary_path": "/codex", "adapter_version": adapter.ADAPTER_VERSION,
    })
    monkeypatch.setattr(
        adapter,
        "run_codex_research_decision",
        lambda *args, **kwargs: pytest.fail("planner must not run while linked work is unsettled"),
    )

    def fake_api(base_url, path, *, method="GET", payload=None):
        calls.append((method, path))
        if method == "GET":
            return {
                "episode": {
                    "id": "episode-1", "status": "awaiting_observation",
                    "terminal": False, "autopilot_enabled": False,
                }
            }
        assert path == "/research/episodes/episode-1/settle"
        return {
            "settled": False,
            "episode": {"id": "episode-1", "status": "awaiting_observation", "terminal": False},
            "waiting_on": [{
                "kind": "scan", "id": "scan-1", "status": "running",
                "ui_path": "/scans/scan-1",
            }],
        }

    monkeypatch.setattr(adapter, "api_json", fake_api)
    result = adapter.run_research_episode(
        "http://api", "episode-1", max_decisions=3, timeout_seconds=30,
    )

    assert calls == [
        ("GET", "/research/episodes/episode-1"),
        ("POST", "/research/episodes/episode-1/settle"),
    ]
    assert result["decision_count"] == 0
    assert result["awaiting_linked_work"] is True
    assert result["linked_work"]["id"] == "scan-1"


def test_research_cli_projection_omits_full_observation_pack():
    projected = adapter._research_cli_projection({
        "ok": True,
        "episode_id": "episode-1",
        "decision_count": 1,
        "decisions": [{"command": "asm.gaps"}],
        "awaiting_linked_work": False,
        "linked_work": None,
        "episode": {
            "status": "awaiting_planner", "terminal": False,
            "remaining_budget": {"steps": 3},
        },
        "current_observation": {
            "id": "obs-2", "sequence": 2, "context_hash": "a" * 64,
            "observation_pack": {
                "current_surface": {"huge": "x" * 100_000},
                "previous_observation": {"command": "asm.gaps", "dispatched": True},
            },
        },
        "planner": {"agent": "codex"},
    })

    assert projected["ui_path"] == "/deep-hunt?episode_id=episode-1"
    assert projected["current_observation"]["previous_result"]["command"] == "asm.gaps"
    assert "observation_pack" not in json.dumps(projected)
    assert len(json.dumps(projected)) < 5000
