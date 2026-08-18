import os
import sys
import json
import hashlib

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "api"))
sys.path.insert(0, os.path.join(ROOT, "scanner"))

import device_agent  # noqa: E402
import family_proof  # noqa: E402
from scanner_tools.device_web import (  # noqa: E402
    paired_reverse_request,
    strip_credential_headers,
)


def test_device_agent_contract_has_only_bounded_device_tools():
    names = {tool["name"] for tool in device_agent.tool_schemas()}
    assert names == device_agent.CALLABLE_TOOL_NAMES
    assert "propose_ssh_shell" in device_agent.render_contract()
    assert "local-host shell" in device_agent.render_contract().lower()
    assert "separate user confirmation" in device_agent.render_contract().lower()
    assert "queue_device_scan" in device_agent.render_contract()
    assert "separately labeled inconclusive observations" in device_agent.render_contract()
    assert "locus.state_path" in device_agent.render_contract()
    assert "locus.cleanup_request_id" in device_agent.render_contract()
    assert "HTTP success alone is never proof" in device_agent.render_contract()
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


def test_device_agent_debrief_preserves_typed_candidate_fields():
    reply = '''{
      "done": true,
      "summary": "done",
      "leads": [{
        "title": "Unexpected Telnet",
        "family": "service_exposure",
        "severity": "high",
        "rationale": "Confirmed service conflicts with policy",
        "locus": {"transport": "tcp", "port": 23},
        "evidence_refs": ["devref_3"],
        "verifier_contract_id": "device.service_exposure"
      }]
    }'''

    result = device_agent.interpret_reply(reply)
    lead = result["result"]["leads"][0]

    assert lead["family"] == "service_exposure"
    assert lead["severity"] == "high"
    assert lead["locus"] == {"transport": "tcp", "port": 23}
    assert lead["verifier_contract_id"] == "device.service_exposure"


def test_device_agent_state_fixes_safety_and_budgets():
    state = device_agent.seed_state(objective="Review the TV", safety_profile="safe_remote", max_turns=8)
    assert state["safety_profile"] == "safe_remote"
    assert state["max_turns"] == 8
    assert state["actions_used"] == 0
    assert state["scans_queued"] == 0
    assert state["fragility_budget"] == device_agent.MAX_FRAGILITY_PER_SESSION
    assert state["traffic_frozen"] is False


def test_device_agent_depth_tools_are_read_only_and_scan_costs_are_profiled():
    for name in ("inspect_capabilities", "diff_scans", "recall_hypotheses", "query_policy", "resolve_intel", "lookup_protocol_playbook"):
        assert name in device_agent.CALLABLE_TOOL_NAMES
    assert device_agent.tool_fragility_cost("diff_scans", {}) == 0
    assert device_agent.tool_fragility_cost("queue_device_scan", {"coverage_profile": "inventory"}) == 5
    assert device_agent.tool_fragility_cost("queue_device_scan", {"coverage_profile": "thorough", "include_web_dast": True}) == 22
    assert device_agent.tool_fragility_cost("queue_device_scan", {"coverage_profile": "inventory", "capability_ids": ["ssh-authenticated-host-review"]}) == 11
    assert device_agent.tool_fragility_cost("verify_service_state", {"transport": "tcp"}) == 3
    assert device_agent.tool_fragility_cost("verify_service_state", {"transport": "udp"}) == 6
    assert device_agent.tool_fragility_cost("verify_candidate", {}) == 3
    name, args = device_agent.validate_tool_call({"name": "diff_scans", "arguments": {}})
    assert name == "diff_scans" and args == {"scan_a": None, "scan_b": None}
    name, args = device_agent.validate_tool_call({"name": "verify_service_state", "arguments": {
        "transport": "tcp", "port": 8443, "expected_state": "closed", "reason": "admin listener should be absent",
    }})
    assert name == "verify_service_state" and args["port"] == 8443
    name, args = device_agent.validate_tool_call({"name": "queue_device_scan", "arguments": {
        "coverage_profile": "inventory", "reason": "correlate listeners", "capability_ids": ["ssh-authenticated-host-review"],
    }})
    assert name == "queue_device_scan" and args["capability_ids"] == ["ssh-authenticated-host-review"]
    with pytest.raises(ValueError, match="capability_ids"):
        device_agent.validate_tool_call({"name": "queue_device_scan", "arguments": {
            "coverage_profile": "inventory", "reason": "unsafe", "capability_ids": ["arbitrary-shell"],
        }})
    name, args = device_agent.validate_tool_call({"name": "propose_ssh_shell", "arguments": {
        "port": 2222,
        "commands": ["id", "uname -a"],
        "purpose": "Inspect runtime identity",
        "risk_summary": "Read-only identity commands",
    }})
    assert name == "propose_ssh_shell"
    assert args["commands"] == ["id", "uname -a"]
    assert args["timeout_seconds"] == 20
    with pytest.raises(ValueError, match="unsupported arguments"):
        device_agent.validate_tool_call({"name": "propose_ssh_shell", "arguments": {
            "port": 22, "commands": ["id"], "purpose": "x", "risk_summary": "x", "target": "other-host",
        }})
    candidate_id = "4ae842d5-7250-4b0f-9942-c4a204d7ca6d"
    name, args = device_agent.validate_tool_call({"name": "verify_candidate", "arguments": {
        "candidate_id": candidate_id, "reason": "confirm policy-conflicting exposure",
    }})
    assert name == "verify_candidate" and args["candidate_id"] == candidate_id
    with pytest.raises(ValueError, match="unsupported arguments"):
        device_agent.validate_tool_call({"name": "verify_candidate", "arguments": {
            "candidate_id": candidate_id, "reason": "escape", "port": 23,
        }})


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


def test_device_agent_uses_bundled_intel_when_env_is_unset(monkeypatch):
    monkeypatch.delenv("DEVICE_INTEL_DB_PATH", raising=False)
    monkeypatch.delenv("DEVICE_INTEL_DB_SHA256", raising=False)
    result = device_agent.resolve_local_intel(
        cpe="cpe:2.3:a:embedthis:goahead:3.6.4:*:*:*:*:*:*:*",
        product=None,
        version=None,
    )
    assert result["status"] == "available"
    assert result["snapshot_sha256"] == device_agent.BUNDLED_SNAPSHOT_SHA256
    assert result["candidates"][0]["advisory_id"] == "CVE-2017-17562"
    assert result["candidates"][0]["promotable"] is True


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
    assert '@app.post("/device-agent/session/{run_id}/shell-plans/{plan_id}/confirm")' in api_source
    assert "confirm_exact_commands" in api_source
    assert "confirm_remote_device_effects" in api_source
    assert "_DEVICE_AGENT_APPROVED_SHELL_PLAN" in api_source
    assert "DeviceAgentSessionStartRequest" in api_source
    assert '"target_fixed": True' in api_source
    assert '"safety_profile_fixed": True' in api_source
    assert "CREATE TABLE IF NOT EXISTS device_agent_runs" in migration_source
    assert "CREATE TABLE IF NOT EXISTS device_agent_actions" in migration_source
    assert "_build_device_agent_context_pack" in api_source
    assert "_diff_device_scan_snapshots" in api_source
    assert "device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE" in migration_source


def test_device_http_request_tool_is_registered_readonly_and_session_capped():
    tools = {tool["name"]: tool for tool in device_agent.tool_schemas()}
    assert "device_http_request" in tools
    assert "device_http_request" in device_agent.CALLABLE_TOOL_NAMES
    assert device_agent.TOOL_TIERS["device_http_request"] == 0
    assert device_agent.DEVICE_HTTP_REQUEST_SESSION_LIMIT == 40
    assert device_agent.tool_fragility_cost("device_http_request", {}) == 1
    assert "device_http_request" in device_agent.render_contract()
    schema = tools["device_http_request"]["parameters"]
    assert schema["required"] == ["path"]
    assert schema["properties"]["method"]["enum"] == ["GET", "HEAD"]
    assert set(schema["properties"]) == {"path", "method", "origin_port"}


def test_device_http_request_path_and_method_validation_blocks_target_escape():
    name, args = device_agent.validate_tool_call({
        "name": "device_http_request",
        "arguments": {"path": "/api/status?verbose=1"},
    })
    assert name == "device_http_request"
    assert args == {"path": "/api/status?verbose=1", "method": "GET", "origin_port": None}
    name, args = device_agent.validate_tool_call({
        "name": "device_http_request",
        "arguments": {"path": "/", "method": "HEAD", "origin_port": 3001},
    })
    assert args["method"] == "HEAD" and args["origin_port"] == 3001
    for bad_path in [
        "http://tv.example.test/api",
        "https://evil.test",
        "//skip-pinning",
        "relative/path",
        "/api/\r\nHost: other",
        "/a\x00b",
    ]:
        with pytest.raises(ValueError):
            device_agent.validate_tool_call({"name": "device_http_request", "arguments": {"path": bad_path}})
    for bad_method in ["POST", "PUT", "DELETE", "post"]:
        with pytest.raises(ValueError, match="GET or HEAD"):
            device_agent.validate_tool_call({
                "name": "device_http_request",
                "arguments": {"path": "/", "method": bad_method},
            })
    with pytest.raises(ValueError, match="unsupported arguments"):
        device_agent.validate_tool_call({
            "name": "device_http_request",
            "arguments": {"path": "/", "host": "other.test"},
        })
    with pytest.raises(ValueError, match="origin_port"):
        device_agent.validate_tool_call({
            "name": "device_http_request",
            "arguments": {"path": "/", "origin_port": 70000},
        })


def test_device_http_request_server_side_budgets_are_enforced_in_the_executor():
    api_source = open(os.path.join(ROOT, "api", "api.py"), encoding="utf-8").read()
    assert "DEVICE_HTTP_REQUEST_SESSION_LIMIT" in api_source
    assert "device_http_requests_used" in api_source
    assert "observe_only cannot send device HTTP requests" in api_source
    assert "DEVICE_HTTP_REQUEST_MIN_INTERVAL_SECONDS" in api_source
    assert "_device_request_pinned_http(" in api_source
    assert "_device_confirmed_web_origins" in api_source
    assert "origin_port does not match a confirmed-open web origin" in api_source
    state = device_agent.seed_state(objective="probe web", safety_profile="safe_remote", max_turns=4)
    assert state["device_http_requests_used"] == 0


def test_control_authorization_preconditions_list_exactly_what_is_missing():
    state = device_agent.seed_state(objective="tv", safety_profile="safe_remote", max_turns=4)
    gaps = device_agent.control_authorization_precondition_gaps(state)
    assert "authenticated_active_safety_required" in gaps
    assert "bound_request_replay_not_confirmed" in gaps
    assert "no_bound_confirmed_request_collection" in gaps
    assert "state_changing_replay_not_authorized" in gaps
    assert "exact_collection_id_required" in gaps
    assert "exact_request_id_required" in gaps
    assert "exact_cleanup_request_id_required" in gaps
    ready = device_agent.seed_state(objective="tv", safety_profile="authenticated_active", max_turns=4)
    ready["device_request_collections"] = [{"collection_id": "c1", "state_changing_request_count": 2}]
    ready["confirm_request_replay"] = True
    ready["allow_state_changing_requests"] = True
    exact_locus = {"collection_id": "c1", "request_id": "req1", "cleanup_request_id": "req2"}
    assert device_agent.control_authorization_precondition_gaps(ready, exact_locus) == []
    assert device_agent.control_authorization_precondition_gaps(
        ready, {"collection_id": "other", "request_id": "req1", "cleanup_request_id": "req2"}
    ) == [
        "no_bound_confirmed_request_collection"
    ]
    read_only_collection = dict(ready)
    read_only_collection["device_request_collections"] = [{"collection_id": "c1", "state_changing_request_count": 0}]
    assert device_agent.control_authorization_precondition_gaps(read_only_collection, exact_locus) == [
        "no_state_changing_request_in_bound_collection"
    ]


def test_control_replay_verdict_classifies_unauthenticated_control():
    for rejected in (401, 403, 404):
        assert device_agent.control_replay_verdict(rejected) == "unauthorized_rejected"
    for accepted in (200, 201, 204):
        assert device_agent.control_replay_verdict(accepted) == "unauthenticated_control_accepted"
    assert device_agent.control_replay_verdict(500) == "inconclusive"
    assert device_agent.control_replay_verdict(0) == "inconclusive"


def test_control_state_transition_requires_an_observable_effect_and_exact_restoration():
    before = {"status": 200, "body": b'{"power":"off"}'}
    unchanged = {"status": 200, "body": b'{"power":"off"}'}
    changed = {"status": 200, "body": b'{"power":"on"}'}

    no_effect = device_agent.control_state_transition(before, unchanged)
    assert no_effect["comparable"] is True
    assert no_effect["changed"] is False

    effect = device_agent.control_state_transition(before, changed)
    assert effect["changed"] is True
    assert effect["before"]["body_sha256"] != effect["after"]["body_sha256"]

    truncated = device_agent.control_state_transition(
        {**before, "truncated": True}, changed,
    )
    assert truncated["comparable"] is False
    assert truncated["changed"] is False

    restored = device_agent.control_state_transition(before, unchanged)
    assert restored["comparable"] is True and restored["changed"] is False

    no_effect_proof = family_proof.evaluate_family_proof("device_control_authorization", {
        "exact_bound_request": True,
        "before_state": True,
        "underprivileged_effect": False,
        "after_state": False,
        "cleanup_or_safe_residue": False,
        "state_unchanged": True,
        "reexecuted_at_handoff": True,
    })
    assert no_effect_proof["verdict"] == "refuted"
    assert no_effect_proof["promotable"] is False


def test_device_web_credential_stripping_and_paired_reverse_request_helpers():
    stripped = strip_credential_headers({
        "Authorization": "Bearer secret",
        "Cookie": "session=secret",
        "X-API-Key": "secret",
        "Content-Type": "application/json",
    })
    assert stripped == {"Content-Type": "application/json"}
    requests = [
        {"id": "on", "method": "POST", "name": "Power On", "url": "https://tv.example.test/api/power/on"},
        {"id": "read", "method": "GET", "name": "Status", "url": "https://tv.example.test/api/status"},
        {"id": "off", "method": "POST", "name": "Power Off", "url": "https://tv.example.test/api/power/off"},
    ]
    assert paired_reverse_request(requests, "on")["id"] == "off"
    assert paired_reverse_request(requests, "read") is None
    assert paired_reverse_request(requests, "missing") is None
    delete_pair = [
        {"id": "create", "method": "POST", "url": "https://tv.example.test/api/presets"},
        {"id": "remove", "method": "DELETE", "url": "https://tv.example.test/api/presets"},
    ]
    assert paired_reverse_request(delete_pair, "create") is None
    # Name substrings and cross-origin lookalikes are not exact cleanup bindings.
    loose_name_pair = [
        {"id": "start", "method": "POST", "name": "Start diagnostics", "url": "https://tv.example.test/api/run"},
        {"id": "stop", "method": "POST", "name": "Stop diagnostics", "url": "https://tv.example.test/api/other"},
    ]
    assert paired_reverse_request(loose_name_pair, "start") is None
    cross_origin = [
        {"id": "on", "method": "POST", "url": "https://tv.example.test/api/power/on"},
        {"id": "off", "method": "POST", "url": "https://other.example.test/api/power/off"},
    ]
    assert paired_reverse_request(cross_origin, "on") is None
