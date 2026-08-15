import os
import sys

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "api"))

import device_agent  # noqa: E402


def test_device_agent_contract_has_only_bounded_device_tools():
    names = {tool["name"] for tool in device_agent.tool_schemas()}
    assert names == device_agent.CALLABLE_TOOL_NAMES
    assert "shell(" not in device_agent.render_contract().lower()
    assert "queue_device_scan" in device_agent.render_contract()
    assert "devref_1" in device_agent.render_contract()


def test_device_agent_tool_validation_cannot_change_target_or_safety_profile():
    with pytest.raises(ValueError, match="unsupported arguments"):
        device_agent.validate_tool_call({
            "name": "queue_device_scan",
            "arguments": {
                "coverage_profile": "inventory",
                "reason": "baseline",
                "target": "other-device.test",
                "safety_profile": "lab_invasive",
            },
        })
    name, args = device_agent.validate_tool_call({
        "name": "queue_device_scan",
        "arguments": {"coverage_profile": "posture", "reason": "check all TCP"},
    })
    assert name == "queue_device_scan"
    assert args["coverage_profile"] == "posture"
    assert args["include_web_dast"] is True


def test_device_agent_reply_parser_requires_real_evidence_refs_for_leads():
    tools = device_agent.interpret_reply('```json\n{"tool_calls":[{"name":"inspect_device","arguments":{}}]}\n```')
    assert tools["kind"] == "tool_calls"
    done = device_agent.interpret_reply('''```json
    {"done":true,"summary":"reviewed","leads":[
      {"title":"Supported","rationale":"service evidence","evidence_refs":["devref_2"]},
      {"title":"Unsupported","rationale":"guess","evidence_refs":[]}
    ],"next_actions":["retest after firmware update"]}
    ```''')
    assert done["kind"] == "done"
    assert [lead["title"] for lead in done["result"]["leads"]] == ["Supported"]


def test_device_agent_state_fixes_safety_and_budgets():
    state = device_agent.seed_state(objective="Review the TV", safety_profile="safe_remote", max_turns=8)
    assert state["safety_profile"] == "safe_remote"
    assert state["max_turns"] == 8
    assert state["actions_used"] == 0
    assert state["scans_queued"] == 0


def test_device_agent_api_and_schema_preserve_the_device_boundary():
    api_source = open(os.path.join(ROOT, "api", "api.py"), encoding="utf-8").read()
    migration_source = open(os.path.join(ROOT, "api", "retest_contract.py"), encoding="utf-8").read()
    assert '@app.post("/devices/{device_id}/agent/session")' in api_source
    assert '@app.post("/device-agent/session/{run_id}/reply")' in api_source
    assert "DeviceAgentSessionStartRequest" in api_source
    assert '"target_fixed": True' in api_source
    assert '"safety_profile_fixed": True' in api_source
    assert "CREATE TABLE IF NOT EXISTS device_agent_runs" in migration_source
    assert "device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE" in migration_source
