from tests.api_sources import (
    api_tree_source, definition_source, route_is_declared, route_source,
)
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
    assert result["status"] == "available" and result["source"] in {"builtin", "external_bundle"}
    if result["source"] == "builtin":
        assert result["snapshot_sha256"] == device_agent.device_advisories.BUNDLED_SNAPSHOT_SHA256
    assert result["candidates"][0]["advisory_id"] == "CVE-2017-17562"
    assert result["candidates"][0]["advisory_match_complete"] is True
    assert result["candidates"][0]["promotable"] is False
    assert result["candidates"][0]["identity_evidence_tier"] == "network_service_fingerprint"


def test_device_agent_uses_an_installed_verified_bundle_like_exposure(tmp_path, monkeypatch):
    import base64
    from tests.test_intel_bundle import _seed, _write_bundle

    advisories = device_agent.device_advisories
    intel_bundle = advisories._bundle_module()   # the module object the loader uses
    seed = _seed()
    public = intel_bundle.public_key_for(seed)
    monkeypatch.setitem(intel_bundle.TRUSTED_BUNDLE_KEYS, intel_bundle.key_id_for(public),
                        base64.b64encode(public).decode())
    monkeypatch.delenv(intel_bundle.TRUSTED_KEYS_ENV, raising=False)
    monkeypatch.setenv(intel_bundle.BUNDLE_DIR_ENV, str(tmp_path / "intel"))
    monkeypatch.delenv("DEVICE_INTEL_DB_PATH", raising=False)
    monkeypatch.delenv("DEVICE_INTEL_DB_SHA256", raising=False)
    monkeypatch.setattr(intel_bundle, "_PROCESS_HIGH_WATER", {})
    monkeypatch.setattr(advisories, "_SNAPSHOT_CACHE", {})
    _write_bundle(str(tmp_path / "intel"), seed, version=3)
    result = device_agent.resolve_local_intel(
        cpe="cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*", product=None, version=None)
    assert (result["status"], result["source"]) == ("available", "external_bundle")
    assert [row["advisory_id"] for row in result["candidates"]] == ["CVE-2099-0001"]   # bundle-only
    # An operator pin still freezes the intelligence: the bundle never replaces it.
    store = tmp_path / "pinned.json"
    store.write_text(json.dumps({"advisories": []}))
    monkeypatch.setenv("DEVICE_INTEL_DB_PATH", str(store))
    monkeypatch.setenv("DEVICE_INTEL_DB_SHA256", hashlib.sha256(store.read_bytes()).hexdigest())
    pinned = device_agent.resolve_local_intel(
        cpe="cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*", product=None, version=None)
    assert (pinned["source"], pinned["candidates"]) == ("operator_pinned", [])


def test_protocol_playbook_never_infers_unknown_service_from_port_alone():
    known = device_agent.lookup_protocol_playbook("ssdp", 1900)
    assert known["status"] == "available"
    unknown = device_agent.lookup_protocol_playbook("mystery", 80)
    assert unknown["status"] == "not_found"
    assert "do not infer" in unknown["guidance"].lower()



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

    volatile_before = {"status": 200, "body": b'{"power":"off","counter":1}'}
    volatile_after = {"status": 200, "body": b'{"power":"off","counter":2}'}
    selected = device_agent.control_state_transition(
        volatile_before, volatile_after, json_pointer="/power",
    )
    assert selected["comparable"] is True and selected["changed"] is False


def test_control_cleanup_adapters_restore_only_one_bound_mutation_field():
    query = device_agent.derive_control_cleanup_request({
        "method": "POST", "url": "https://tv.test/api/power?state=on&source=app",
        "headers": {}, "body": b"",
    }, {
        "cleanup_adapter": "restore_query_parameter", "mutation_field": "state",
    }, "off")
    assert query["url"] == "https://tv.test/api/power?state=off&source=app"

    json_request = device_agent.derive_control_cleanup_request({
        "method": "PUT", "url": "https://tv.test/api/power",
        "headers": {"Content-Type": "application/json"},
        "body": b'{"power":"on","source":"app"}',
    }, {
        "cleanup_adapter": "restore_json_field", "mutation_field": "power",
    }, "off")
    assert json.loads(json_request["body"]) == {"power": "off", "source": "app"}

    form = device_agent.derive_control_cleanup_request({
        "method": "POST", "url": "/api/power", "headers": {},
        "body": b"enabled=true&source=app",
    }, {
        "cleanup_adapter": "restore_form_field", "mutation_field": "enabled",
    }, False)
    assert form["body"] == b"enabled=false&source=app"

    with pytest.raises(ValueError, match="must_exist_once"):
        device_agent.derive_control_cleanup_request({
            "method": "POST", "url": "/api/power?state=on&state=off", "body": b"",
        }, {
            "cleanup_adapter": "restore_query_parameter", "mutation_field": "state",
        }, "off")

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


def test_device_http_attempts_are_charged_before_success_is_known():
    state = {}

    assert device_agent.reserve_device_http_attempt(state, now_monotonic=10.0) == 1
    assert state["device_http_requests_used"] == 1
    with pytest.raises(device_agent.DeviceHttpAttemptRejected) as spaced:
        device_agent.reserve_device_http_attempt(state, now_monotonic=10.5)
    assert spaced.value.status_code == 429
    assert state["device_http_requests_used"] == 1

    state["device_http_requests_used"] = device_agent.DEVICE_HTTP_REQUEST_SESSION_LIMIT
    with pytest.raises(device_agent.DeviceHttpAttemptRejected) as exhausted:
        device_agent.reserve_device_http_attempt(state, now_monotonic=12.0)
    assert exhausted.value.status_code == 409

def _device_state(*, objective: str, safety_profile: str, max_turns: int) -> dict:
    """A device execution state as the tests need it: counters at zero, nothing recorded."""
    return {
        "objective": objective, "safety_profile": safety_profile, "max_turns": max_turns,
        "turns": 0, "actions_used": 0, "scans_queued": 0, "device_http_requests_used": 0,
        "fragility_budget": device_agent.MAX_FRAGILITY_PER_SESSION, "fragility_used": 0,
        "traffic_frozen": False, "next_evidence_ref": 1, "evidence": {}, "notes": [], "events": [],
    }


def test_device_http_request_server_side_budgets_are_enforced_in_the_executor():
    api_source = api_tree_source()
    assert "device_http_requests_used" in api_source
    assert "observe_only cannot send device HTTP requests" in api_source
    assert "reserve_device_http_attempt" in api_source
    assert "_device_request_pinned_http(" in api_source
    assert "_device_confirmed_web_origins" in api_source
    # A port the operator names is reached directly: a device locator cannot carry a port, so
    # demanding a discovery scan first made a known service unreachable and unsayable. The
    # origin is still built from the bound device's own locator, never from planner input.
    assert "_device_operator_named_web_origin" in api_source
    assert "port directly with origin_port" in api_source


def test_control_authorization_preconditions_list_exactly_what_is_missing():
    state = _device_state(objective="tv", safety_profile="safe_remote", max_turns=4)
    gaps = device_agent.control_authorization_precondition_gaps(state)
    assert "authenticated_active_safety_required" in gaps
    assert "bound_request_replay_not_confirmed" in gaps
    assert "no_bound_confirmed_request_collection" in gaps
    assert "state_changing_replay_not_authorized" in gaps
    assert "exact_collection_id_required" in gaps
    assert "exact_request_id_required" in gaps
    assert "exact_cleanup_request_id_required" in gaps
    ready = _device_state(objective="tv", safety_profile="authenticated_active", max_turns=4)
    ready["device_request_collections"] = [{"collection_id": "c1", "state_changing_request_count": 2}]
    ready["confirm_request_replay"] = True
    ready["allow_state_changing_requests"] = True
    exact_locus = {"collection_id": "c1", "request_id": "req1", "cleanup_request_id": "req2"}
    assert device_agent.control_authorization_precondition_gaps(ready, exact_locus) == []
    derived_locus = {
        "collection_id": "c1", "request_id": "req1",
        "cleanup_adapter": "restore_query_parameter",
        "mutation_field": "state", "state_json_pointer": "/power",
    }
    assert device_agent.control_authorization_precondition_gaps(ready, derived_locus) == []
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
