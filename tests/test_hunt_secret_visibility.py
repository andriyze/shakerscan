"""2.11 discovered secrets: who may let a Hunt's agent see values, and the secret.try rules.

* ``secret_visibility`` is a person's choice at Hunt start, off by default, recorded with who set
  it; the MCP start tool (the agent) never sends it, and the product CLI refuses to send it to a
  connected instance whose gateway cannot record the person's step-up for it.
* ``secret.try`` is a closed permission kind that no start bound covers.
* The deny rules and destination keys are pure functions (no network).
"""
from __future__ import annotations

from pathlib import Path
import sys
import types

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "api"), str(ROOT / "scanner"), str(ROOT / "scripts"), str(ROOT)]

from hunt import secret_try  # noqa: E402
from hunt.permission_bounds import parse_bounds  # noqa: E402
from hunt.permission_grants import _covers  # noqa: E402
from hunt.permission_reasons import KIND_SECRET_TRY, PERMISSION_KINDS, REQUESTABLE_KINDS, reason_kind  # noqa: E402
from hunt.start_contract import (  # noqa: E402
    HuntStartContractError, hunt_start_public_contract, normalize_hunt_start_payload,
)

START = {
    "schema_version": "hunt-start/v2", "target_id": "t-1", "target_kind": "web", "goal": "g",
    "budget_profile": "fast", "policy": {"active_testing": False},
}


def _persisted(contract):
    return contract.persisted_policy(
        approval_validated=False, credential_access=False, approval_receipt_id=None,
        scope_receipt_id=None, budget=contract.resolved_budget_object, allowed_capabilities=[],
    )


def test_by_default_a_hunt_never_lets_the_agent_see_values():
    contract = normalize_hunt_start_payload(dict(START))
    assert contract.secret_values_visible is False
    policy = _persisted(contract)
    assert policy["secret_values_visible"] is False and policy["secret_visibility_set_by"] is None
    assert contract.public_dict()["secret_values_visible"] is False


def test_the_person_who_starts_the_hunt_may_allow_it_and_is_recorded():
    contract = normalize_hunt_start_payload({
        **START, "secret_visibility": "agent_may_see",
        "allow_asserted_by": {"person": "alice@example.test", "proof": "stepup"},
    })
    policy = _persisted(contract)
    assert policy["secret_values_visible"] is True
    assert policy["secret_visibility_set_by"] == "alice@example.test"
    assert policy["secret_visibility_proof"] == "stepup"
    assert contract.public_dict()["secret_visibility"] == "agent_may_see"
    local = _persisted(normalize_hunt_start_payload({**START, "secret_visibility": "agent_may_see"}))
    assert local["secret_visibility_set_by"] == "local-operator" and local["secret_visibility_proof"] == "local"
    with pytest.raises(HuntStartContractError):
        normalize_hunt_start_payload({**START, "secret_visibility": "always"})
    advertised = hunt_start_public_contract()["secret_visibility"]
    assert advertised["default"] == "withheld" and "agent_may_see" in advertised["values"]


def test_the_agent_cannot_set_it_through_the_mcp_start_tool():
    from tests.test_mcp_refusal_reasons import HUNT, mcp
    contract = {
        "schema_version": "hunt-start/v2", "target_kinds": ["web"], "policy_fields": ["active_testing"],
        "credential_ref_fields": [], "budget_profiles": {"fast": {"max_http_requests": 500}},
        "budget_dimensions": [{"name": "max_http_requests", "minimum": 1}], "limits": {"allow": 32},
        "allow_bounds": {"grammar": ["budget.raise:<N>x"]},
    }
    assert "secret_visibility" not in mcp._hunt_start_tool(contract).properties
    sent = []

    class Client(mcp.ArsenalClient):
        def hunt_contract(self):
            return contract

        def request_json(self, method, path, payload=None):
            sent.append((method, path, payload))
            return {"hunt_id": HUNT, "status": "active", "capabilities": []}

    try:
        Client("http://127.0.0.1:8080").call_tool("shakerscan_hunt_start", {
            **START, "secret_visibility": "agent_may_see",
        })
    except Exception:  # noqa: BLE001 - refusing the field outright is as good as dropping it
        pass
    assert all("secret_visibility" not in (payload or {}) for _method, _path, payload in sent)


def test_the_cli_sends_it_for_the_operator_and_refuses_it_unproven_on_a_connected_instance(monkeypatch):
    import v2_cli
    from tests.test_hunt_approve import Client, _parse

    monkeypatch.delenv("SHAKERSCAN_HUNT_ALLOW", raising=False)
    monkeypatch.delenv("SHAKERSCAN_PREAUTHORIZATION_ID", raising=False)
    contract = {"schema_version": "hunt-start/v2", "target_kinds": ["web"], "budget_profiles": {"balanced": {}},
                "budget_dimensions": []}
    local = Client({("GET", "/hunts/contract"): contract, ("POST", "/hunts"): lambda payload: {"hunt_id": "h"}})
    v2_cli._run_hunt(_parse("hunt", "start", "--target-id", "t-1", "--target-kind", "web",
                            "--agent-may-see-secrets"), local)
    assert local.sent[-1][2]["secret_visibility"] == "agent_may_see"
    v2_cli._run_hunt(_parse("hunt", "start", "--target-id", "t-1", "--target-kind", "web"), local)
    assert "secret_visibility" not in local.sent[-1][2]
    connected = Client({("GET", "/hunts/contract"): contract, ("POST", "/hunts"): lambda payload: {"hunt_id": "h"}},
                       token="token-1")
    monkeypatch.setattr(v2_cli.sys, "stdin", types.SimpleNamespace(isatty=lambda: True, readline=lambda: "a\n"))
    with pytest.raises(v2_cli.CliError) as refused:
        v2_cli._run_hunt(_parse("hunt", "start", "--target-id", "t-1", "--target-kind", "web",
                                "--agent-may-see-secrets"), connected)
    assert "No Hunt was started" in str(refused.value)
    assert ("POST", "/hunts") not in [(method, path) for method, path, *_ in connected.sent]


def test_a_secret_try_is_a_person_only_permission_no_start_bound_covers():
    assert KIND_SECRET_TRY in PERMISSION_KINDS and KIND_SECRET_TRY in REQUESTABLE_KINDS
    assert reason_kind("secret_other_target") == KIND_SECRET_TRY
    assert reason_kind("secret_try_attempts_exhausted") == KIND_SECRET_TRY
    assert reason_kind("secret_try_rate_limited") is None
    assert reason_kind("secret_try_destination_denied") is None
    everything = parse_bounds([
        "budget.raise:10x", "target.authorize:*.example.test", "credential.use:app.example.test",
        "capability:state-changing", "capability:active-testing",
    ])
    request = {"kind": KIND_SECRET_TRY, "status": "pending", "subject_json": {
        "secret_id": "00000000-0000-4000-8000-000000000001", "origin": "https://app.example.test:443",
        "host": "app.example.test", "path": "/login", "method": "POST"}}
    assert _covers(everything, request, {"budget_profile": "fast"}) is None


def test_destinations_are_keyed_canonically_and_denied_logins_resist_respelling(monkeypatch):
    monkeypatch.delenv("SHAKERSCAN_SECRET_TRY_DENY", raising=False)
    assert secret_try.destination_of({"path": "/login", "method": "post"}, "https://APP.example.test/base") == {
        "origin": "https://app.example.test:443", "host": "app.example.test", "path": "/login", "method": "POST"}
    assert secret_try.destination_of({"origin": "http://app.example.test:8080", "path": "x"}, None)["origin"] == (
        "http://app.example.test:8080")
    assert secret_try.destination_of({"path": "/"}, "ftp://app.example.test") is None
    for path in ("/hub", "/hub/", "/hub/login", "/Hub/Login", "/%68ub/login", "/%2568ub/login",
                 "/a/../hub/login", "//hub//login", "/hub/login?next=/"):
        assert secret_try.denied_destination("honey.shakerscan.com", path), path
        assert secret_try.denied_destination("HONEY.shakerscan.com.", path), path
    for path in ("/", "/hubs", "/login", "/api/hub"):
        assert not secret_try.denied_destination("honey.shakerscan.com", path), path
    monkeypatch.setenv("SHAKERSCAN_SECRET_TRY_DENY", "sso.example.test/, app.example.test/auth")
    assert secret_try.denied_destination("sso.example.test", "/anything")
    assert secret_try.denied_destination("app.example.test", "/auth/login")
    assert not secret_try.denied_destination("app.example.test", "/login")


def test_the_person_reads_names_and_ids_never_a_value():
    subject = {"secret_id": "00000000-0000-4000-8000-000000000001", "found_on_target_id": "t-s",
               "consuming_target_id": "t-t", "origin": "https://app.example.test:443",
               "host": "app.example.test", "path": "/login", "method": "POST"}
    title, explanation, effect = secret_try.render_secret_try(
        subject, {"secret_kind": "password", "secret_label": "DB_PASSWORD", "secret_length": 18,
                  "found_on_name": "staging"}, lambda value, limit=80: str(value or "")[:limit])
    assert "staging" in title and "POST https://app.example.test:443/login" in title
    assert "DB_PASSWORD" in explanation and "never shown" in explanation
    assert str(secret_try.DEFAULT_ATTEMPTS) in effect and "cannot be remembered" in effect
