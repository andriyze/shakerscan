import os
import sys
import json
import hashlib

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
    assert state["fragility_budget"] == device_agent.MAX_FRAGILITY_PER_SESSION
    assert state["traffic_frozen"] is False


def test_device_agent_depth_tools_are_read_only_and_scan_costs_are_profiled():
    for name in ("diff_scans", "recall_hypotheses", "query_policy", "resolve_intel", "lookup_protocol_playbook"):
        assert name in device_agent.CALLABLE_TOOL_NAMES
    assert device_agent.tool_fragility_cost("diff_scans", {}) == 0
    assert device_agent.tool_fragility_cost("queue_device_scan", {"coverage_profile": "inventory"}) == 5
    assert device_agent.tool_fragility_cost("queue_device_scan", {"coverage_profile": "thorough", "include_web_dast": True}) == 22
    assert device_agent.tool_fragility_cost("verify_service_state", {"transport": "tcp"}) == 3
    assert device_agent.tool_fragility_cost("verify_service_state", {"transport": "udp"}) == 6
    name, args = device_agent.validate_tool_call({"name": "diff_scans", "arguments": {}})
    assert name == "diff_scans" and args == {"scan_a": None, "scan_b": None}
    name, args = device_agent.validate_tool_call({"name": "verify_service_state", "arguments": {
        "transport": "tcp", "port": 8443, "expected_state": "closed", "reason": "admin listener should be absent",
    }})
    assert name == "verify_service_state" and args["port"] == 8443


def test_device_agent_local_intel_has_no_runtime_egress(tmp_path, monkeypatch):
    store = tmp_path / "device-intel.json"
    store.write_text(json.dumps({"advisories": [{
        "cpe": "cpe:/o:vendor:device:1.0",
        "cve": "CVE-TEST-0001",
        "title": "Fixture advisory",
        "severity": "high",
    }]}))
    monkeypatch.setenv("DEVICE_INTEL_DB_PATH", str(store))
    monkeypatch.setenv("DEVICE_INTEL_DB_SHA256", hashlib.sha256(store.read_bytes()).hexdigest())
    result = device_agent.resolve_local_intel(cpe="cpe:/o:vendor:device:1.0", product=None, version=None)
    assert result["runtime_egress"] is False
    assert result["candidates"][0]["advisory_id"] == "CVE-TEST-0001"
    monkeypatch.setenv("DEVICE_INTEL_DB_SHA256", "0" * 64)
    rejected = device_agent.resolve_local_intel(cpe="cpe:/o:vendor:device:1.0", product=None, version=None)
    assert rejected["status"] == "integrity_mismatch"
    assert rejected["candidates"] == []


def test_protocol_playbook_never_infers_unknown_service_from_port_alone():
    known = device_agent.lookup_protocol_playbook("ssdp", 1900)
    assert known["status"] == "available"
    unknown = device_agent.lookup_protocol_playbook("mystery", 80)
    assert unknown["status"] == "not_found"
    assert "do not infer" in unknown["guidance"].lower()


def test_device_agent_api_and_schema_preserve_the_device_boundary():
    api_source = open(os.path.join(ROOT, "api", "api.py"), encoding="utf-8").read()
    migration_source = open(os.path.join(ROOT, "api", "retest_contract.py"), encoding="utf-8").read()
    assert '@app.post("/devices/{device_id}/agent/session")' in api_source
    assert '@app.post("/device-agent/session/{run_id}/reply")' in api_source
    assert "DeviceAgentSessionStartRequest" in api_source
    assert '"target_fixed": True' in api_source
    assert '"safety_profile_fixed": True' in api_source
    assert "CREATE TABLE IF NOT EXISTS device_agent_runs" in migration_source
    assert "CREATE TABLE IF NOT EXISTS device_agent_actions" in migration_source
    assert "_build_device_agent_context_pack" in api_source
    assert "_diff_device_scan_snapshots" in api_source
    assert "device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE" in migration_source
