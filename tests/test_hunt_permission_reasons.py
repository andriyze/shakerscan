"""Closed reason codes for Hunt refusals, and which ones may become permission requests.

Unit tests with labelled doubles (no database). The real-PostgreSQL behaviour of requests,
grants and admission is in tests/test_hunt_permission_requests_postgres.py.

Covers the retest defects: D25/D35 (refusals recorded), D31 (which capability permission is
missing), D32 (which approval), D34 (machine-readable code), D36 (codes on every credential
path), D37 (attached but not allowed is not "missing"), and the walls catalogue W1-W43 from the
2026-10-08 plan runs (main732, maincec).
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from api.capabilities.inline import _blocked_error
from api.hunt.credential_uses import HuntCredentialRefusal, action_credential_references
from api.hunt.permission_reasons import (
    PERMISSION_KINDS, REASON_CODES, REQUESTABLE_KINDS, HuntRefusal, reason_kind, refusal_summary,
)
from api.hunt.permission_store import render
from api.hunt.permission_subjects import (
    approval_required_refusal, capability_refusal, destination_refusal, preflight_reason_code,
)
from api.hunt.run_service import public_hunt_action
from api.hunt.start_contract import HuntStartContractError, normalize_hunt_start_payload
from api.hunt.start_permissions import _reference_code
from api.runtime.models import TargetBinding

TARGET = TargetBinding(
    target_id="target-1", target_kind="web", canonical_host="app.example.test",
    allowed_origins=("https://app.example.test",), allowed_addresses=("203.0.113.10",),
)

# Hard limits: never a request, whatever the bounds.
HARD = (
    "hunt_not_runnable", "target_not_found", "target_inactive", "target_locator_changed",
    "capability_unregistered", "capability_target_kind_mismatch", "capability_requires_credentials",
    "scope_destination_blocked", "scope_credential_other_host", "scope_origin_invalid", "scope_scanner_other_host",
    "credential_inactive", "credential_version_changed", "budget_dimension_needs_permission",
)


def _run(policy=None, kind="web"):
    return {"target_kind": kind, "policy_json": json.dumps(policy or {
        "active_testing": False, "allow_state_changing_http": False, "network_discovery": False,
        "allow_oob_interactions": False, "credential_access": False,
    })}


def test_the_reason_codes_and_kinds_are_closed_and_hard_limits_have_no_kind():
    assert len(REASON_CODES) == len(set(REASON_CODES))
    assert set(PERMISSION_KINDS) == {
        "target.authorize", "credential.use", "capability.enable", "budget.raise", "ssh.exec",
        "ssh.host_trust", "preauthorization",
    }
    for code in HARD:
        assert reason_kind(code) is None, code
    # SSH kinds keep their codes but are not raised as requests in this release.
    assert reason_kind("ssh_exec_not_allowed") is None and "ssh.exec" not in REQUESTABLE_KINDS
    with pytest.raises(ValueError):
        HuntRefusal("anything_the_agent_says", "free text")


@pytest.mark.parametrize(("name", "policy", "code", "flag"), [
    ("xss.verify", None, "capability_requires_active_testing", "active-testing"),
    ("collections.replay_active", {"active_testing": True}, "capability_requires_state_changing_http",
     "state-changing"),
    ("ports.discover", {"active_testing": True}, "capability_requires_network_discovery", "tcp-discovery"),
    ("templates.scan", None, "capability_requires_active_testing", "active-testing"),
])
def test_a_withheld_capability_names_the_permission_it_needs(name, policy, code, flag):
    """D31: one opaque refusal for every withheld capability."""
    refusal = capability_refusal(_run(policy), name)
    assert refusal.reason_code == code and refusal.kind == "capability.enable"
    assert refusal.subject == {"capability": name, "flag": flag}
    assert "Capability is not allowed by this Hunt" not in refusal.message


def test_capabilities_no_grant_can_lift_are_hard():
    assert capability_refusal(_run(), "shell.exec").reason_code == "capability_unregistered"
    assert capability_refusal(_run(), "device.inspect").reason_code == "capability_target_kind_mismatch"
    assert capability_refusal(_run(), "auth.session.establish").reason_code == "capability_requires_credentials"
    for name in ("shell.exec", "device.inspect", "auth.session.establish"):
        assert capability_refusal(_run(), name).kind is None


def test_destinations_another_port_another_host_and_never_a_credential_off_target():
    port = destination_refusal(TARGET, "https://app.example.test:8443", {}, principal_slot="anonymous")
    assert port.reason_code == "scope_other_service_port" and port.kind == "target.authorize"
    assert port.subject["same_host"] is True and port.subject["port"] == 8443
    host = destination_refusal(TARGET, "https://api.example.test", {}, principal_slot="anonymous")
    assert host.reason_code == "scope_other_host" and host.kind == "target.authorize"
    credential = destination_refusal(TARGET, "https://api.example.test", {}, principal_slot="primary")
    assert credential.reason_code == "scope_credential_other_host" and credential.kind is None
    invalid = destination_refusal(TARGET, "https://user@app.example.test/path", {}, principal_slot="anonymous")
    assert invalid.reason_code == "scope_origin_invalid"


def test_an_approval_refusal_says_which_approval_and_why():
    """D32: "Approval receipt is required" without saying which."""
    refusal = approval_required_refusal(
        "browser.navigate", principal_slot="anonymous", uses_session=True, writes_http=False,
        forges_identity=False, uses_direct_origin=False, uses_service_origin=False,
    )
    assert refusal.reason_code == "approval_receipt_required"
    assert "session_ref" in refusal.message and "standing authorization" in refusal.message


def test_a_coded_refusal_is_json_and_its_record_keeps_the_code():
    """D34: the server stored the code inside a Python repr string."""
    refusal = HuntRefusal("credential_version_changed", "rotated", extra={"slot": "primary"})
    assert refusal.detail == {"error": "credential_version_changed", "reason_code": "credential_version_changed",
                              "message": "rotated", "slot": "primary"}
    detail = HuntCredentialRefusal("credential_version_changed", "rotated", slot="user1").public_detail()
    assert _blocked_error(SimpleNamespace(detail=detail)) == "credential_version_changed"
    summary = refusal_summary(refusal)
    action = public_hunt_action({
        "id": "6f2b4f1e-0000-4000-8000-000000000001", "capability_name": "http.request", "status": "blocked",
        "input_summary": {}, "result_summary": json.dumps(summary), "receipt_id": None,
    })["result"]
    assert action["reason_code"] == "credential_version_changed"
    assert action["refusal"]["stage"] == "admission" and action["execution_started"] is False


def test_an_ambiguous_or_ungranted_principal_is_refused_at_admission_with_a_code():
    """D36b: two selected profiles for one slot failed after admission, charged, in free text."""
    ref = {"source": "credential_profiles", "principal_slot": "primary", "profile_id":
           "11111111-1111-4111-8111-111111111111", "profile_version": 1, "allowed_capabilities": ["http.request"]}
    two = {"credential_refs": [ref, {**ref, "profile_id": "22222222-2222-4222-8222-222222222222"}]}
    with pytest.raises(HuntCredentialRefusal) as ambiguous:
        action_credential_references("http.request", {"as_principal": "primary"}, two)
    assert ambiguous.value.code == "credential_ambiguous_for_slot"
    ungranted = {"credential_refs": [{**ref, "allowed_capabilities": ["authz.verify"]}]}
    with pytest.raises(HuntCredentialRefusal) as missing_capability:
        action_credential_references("http.request", {"as_principal": "primary"}, ungranted)
    assert missing_capability.value.code == "credential_capability_not_granted"
    with pytest.raises(HuntCredentialRefusal) as missing:
        action_credential_references("http.request", {"as_principal": "secondary"}, ungranted)
    assert missing.value.code == "credential_missing_for_slot"


def test_start_refusals_carry_codes():
    """D36a/c and W11, W42, W43: start refusals a person can resolve are coded."""
    assert _reference_code("secondary_credential_profile_id is inactive or expired") == "credential_inactive"
    with pytest.raises(HuntStartContractError) as distinct:
        normalize_hunt_start_payload({"target_id": "t", "target_kind": "web", "policy": {}, "credential_refs": {
            "web_credential_profile_id": "p1", "primary_credential_profile_id": "p1"}})
    assert distinct.value.code == "credentials_not_distinct"
    with pytest.raises(HuntStartContractError) as ceiling:
        normalize_hunt_start_payload({"target_id": "t", "target_kind": "web", "policy": {},
                                      "budget_profile": "fast", "budgets": {"max_http_requests": 999_999}})
    assert ceiling.value.code == "budget_above_profile_ceiling"
    with pytest.raises(HuntStartContractError) as direct:
        normalize_hunt_start_payload({"target_id": "t", "target_kind": "web", "policy": {
            "allow_direct_origin": True, "authorization_confirmed": True, "approval_receipt_id": "a"}})
    assert direct.value.code == "direct_origin_address_required"
    with pytest.raises(HuntStartContractError) as bound:
        normalize_hunt_start_payload({"target_id": "t", "target_kind": "web", "policy": {},
                                      "allow": ["target.authorize:*.com"]})
    assert bound.value.code == "preauthorization_bound_invalid"


def test_request_text_comes_only_from_server_templates():
    """No model justification: a subject value is shown as a value, never as instructions."""
    rendered = render("target.authorize", {
        "host": "evil.example", "port": 443, "scheme": "https", "origin": "https://evil.example:443",
        "scope_verdict": "allowed", "same_host": False, "addresses": ["93.184.216.34"],
    }, {})
    assert rendered["title"] == "Authorize evil.example:443 for this Hunt"
    assert set(rendered) == {"title", "explanation", "effect", "remember_supported", "choices", "scopes"}
    assert render("capability.enable", {"capability": "xss.verify", "flag": "active-testing"}, {})[
        "remember_supported"] is False
    assert render("budget.raise", {"dimension": "max_http_requests", "limit": 5}, {})["scopes"] == ["hunt"]


# ---------------------------------------------------------------------------------------------
# W1-W43: every wall from the 2026-10-08 plan runs, with its code or why it has none.

CODED = "coded"
DISPOSITIONS = {
    "agent_input": "an agent input error; the request is fixed by the agent, not a person",
    "not_a_refusal": "not a refusal",
    "gateway": "an Enterprise gateway route decision, by design",
    "client_validation": "the MCP adapter validates the argument against the server contract",
}
WALLS = {
    "W1": (CODED, "scope_other_host"), "W2": (CODED, "scope_other_service_port"),
    "W3": (CODED, "target_not_found"), "W4": (CODED, "target_not_found"),
    "W5": (CODED, "credential_not_attached"), "W6": ("not_a_refusal", None),
    "W7": (CODED, "principal_anonymous_only"), "W8": (CODED, "state_changing_http_not_allowed"),
    "W9": (CODED, "capability_requires_active_testing"), "W10": ("not_a_refusal", None),
    "W11": (CODED, "capability_unregistered"), "W12": (CODED, "collection_not_bound"),
    "W13": (CODED, "approval_receipt_required"), "W14": (CODED, "budget_exhausted"),
    "W15": (CODED, "budget_resume_without_headroom"), "W16": (CODED, "budget_dimension_needs_permission"),
    "W17": ("agent_input", None), "W18": ("agent_input", None), "W19": ("client_validation", None),
    "W20": (CODED, "verification_route_unresolved"), "W21": (CODED, "verification_family_unsupported"),
    "W22": (CODED, "verification_method_unsupported"), "W23": ("not_a_refusal", None),
    "W24": ("agent_input", None), "W25": (CODED, "hunt_not_runnable"),
    "W26": (CODED, "idempotency_key_reused"), "W27": ("agent_input", None), "W28": ("agent_input", None),
    "W29": ("agent_input", None), "W30": ("gateway", None), "W31": ("client_validation", None),
    "W32": (CODED, "credential_inactive"), "W33": (CODED, "credentials_not_distinct"),
    "W34": (CODED, "credential_not_attached"), "W35": (CODED, "credential_version_changed"),
    "W36": (CODED, "credential_version_changed"), "W37": (CODED, "credential_capability_not_granted"),
    "W38": (CODED, "credential_missing_for_slot"), "W39": (CODED, "credential_capability_not_granted"),
    "W40": (CODED, "credential_ambiguous_for_slot"), "W41": (CODED, "credential_ambiguous_for_slot"),
    "W42": (CODED, "budget_above_profile_ceiling"), "W43": (CODED, "direct_origin_address_required"),
}
# The walls a person could allow live, and the request each one raises.
GRANTABLE = {
    "W1": "target.authorize", "W2": "target.authorize", "W8": "capability.enable",
    "W9": "capability.enable", "W14": "budget.raise", "W34": "credential.use",
}


def test_every_wall_has_a_closed_code_or_a_stated_reason_for_none():
    assert sorted(WALLS, key=lambda key: int(key[1:])) == [f"W{index}" for index in range(1, 44)]
    for wall, (kind, code) in WALLS.items():
        if kind == CODED:
            assert code in REASON_CODES, wall
        else:
            assert kind in DISPOSITIONS and code is None, wall
    for wall, permission in GRANTABLE.items():
        assert REASON_CODES[WALLS[wall][1]].kind == permission, wall
    # W12 (collection binding) is the operator's route; W16 needs a new Hunt: neither is a request.
    assert reason_kind("collection_not_bound") is None and reason_kind("budget_dimension_needs_permission") is None


def test_the_preflight_and_resume_walls_are_coded_where_they_are_raised():
    assert preflight_reason_code("verification_route_unresolved") == "verification_route_unresolved"
    assert preflight_reason_code("verification bridge supports ['bola'], not 'ai'") == "verification_family_unsupported"
    assert preflight_reason_code(
        "mass_assignment verification requires an explicitly evidenced POST create operation"
    ) == "verification_method_unsupported"


def test_the_start_contract_publishes_the_codes_and_the_bound_grammar():
    from api.hunt.start_contract import hunt_start_public_contract

    contract = hunt_start_public_contract()
    assert contract["permission_reason_codes"] == sorted(REASON_CODES)
    assert "budget.raise:<N>x" in contract["allow_bounds"]["grammar"]


def test_the_planner_ingress_reads_permission_requests_but_never_decides_them():
    from api.hunt.planner_gateway import route_allowed

    hunt = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    request = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    assert route_allowed("GET", f"/hunts/{hunt}/permission-requests", hunt)
    assert route_allowed("GET", f"/hunts/{hunt}/permission-requests/{request}", hunt)
    assert route_allowed("GET", f"/hunts/{hunt}/permission-grants", hunt)
    assert not route_allowed("POST", f"/hunts/{hunt}/permission-requests/{request}/decision", hunt)
    assert not route_allowed("POST", f"/hunts/{hunt}/permission-grants/{request}/revoke", hunt)
    assert not route_allowed("POST", f"/hunts/{hunt}/permission-requests", hunt)  # no create route


def test_d37_attached_credentials_without_the_verifier_capability_are_not_missing(monkeypatch):
    from api.hunt import verification_credentials as module
    from tests.test_hunt_credential_attachment import (
        OWN_ALICE, FixtureStore, _profile, _scope,
    )

    store = FixtureStore([_profile(OWN_ALICE, slot="primary", capabilities=("http.request",))])

    class Conn:
        async def fetch(self, query, *args):
            return []

    with pytest.raises(HuntCredentialRefusal) as refused:
        asyncio.run(module._select(Conn(), _scope(), ["user1"], store))
    assert refused.value.code == "credential_capability_not_granted"
    assert "attach" not in refused.value.public_detail()


def test_the_hunt_postgres_workflow_runs_the_permission_tests():
    from pathlib import Path

    workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/hunt-record-integrity.yml").read_text()
    assert "tests/test_hunt_permission_requests_postgres.py" in workflow
    assert "tests/test_hunt_refusal_retry_postgres.py" in workflow
    assert "tests/test_public_retry_conflict_postgres.py" in workflow


@pytest.mark.parametrize("name", ["shell.exec", "made.up"])
def test_an_unregistered_capability_is_refused_with_its_code_and_no_request(monkeypatch, name):
    """D45: it reached MCP as 404 "'unknown capability: shell.exec'" (a Python repr) with no
    reason_code. It is a hard limit: a coded refusal from the closed list, never a request."""
    from api.hunt import interaction_router as router

    async def executable(*_args):  # labelled double: the Hunt exists and is active
        return None

    monkeypatch.setattr(router, "_require_executable_hunt_or_recorded_action", executable)
    with pytest.raises(HuntRefusal) as refused:
        asyncio.run(router.execute_hunt_capability(
            "00000000-0000-4000-8000-000000000001", name,
            router.HuntCapabilityRequest(idempotency_key="unknown-capability-0001", input={}),
        ))
    detail = refused.value.detail
    assert refused.value.status_code == 404
    assert detail["reason_code"] == "capability_unregistered" and detail["error"] == "capability_unregistered"
    assert detail["message"].startswith(f"{name} is not a registered Hunt capability")
    assert "'unknown capability" not in detail["message"], "no Python repr"
    assert refused.value.kind is None and refused.value.recorded is False
