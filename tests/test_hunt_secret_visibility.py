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
    with pytest.raises(HuntStartContractError):
        normalize_hunt_start_payload({**START, "secret_visibility": "always"})
    advertised = hunt_start_public_contract()["secret_visibility"]
    assert advertised["default"] == "withheld" and "agent_may_see" in advertised["values"]


def test_without_a_person_assertion_the_engine_refuses_it(monkeypatch):
    # A token holder (an agent with the service token included) cannot just ask for it.
    for assertion in (None, {"person": "", "proof": "stepup"}, {"person": "x", "proof": "agent"}):
        payload = {**START, "secret_visibility": "agent_may_see"}
        if assertion is not None:
            payload["allow_asserted_by"] = assertion
        with pytest.raises(HuntStartContractError) as refused:
            normalize_hunt_start_payload(payload)
        assert refused.value.code in {"secret_visibility_unasserted", "preauthorization_bound_invalid"}
    local = {**START, "secret_visibility": "agent_may_see",
             "allow_asserted_by": {"person": "operator-at-host", "proof": "local"}}
    # A loopback-only install: the local operator's assertion stands, recorded exactly.
    monkeypatch.setenv("SHAKERSCAN_BIND_HOST", "127.0.0.1")
    monkeypatch.delenv("SHAKERSCAN_PUBLIC_HOST", raising=False)
    policy = _persisted(normalize_hunt_start_payload(local))
    assert policy["secret_visibility_set_by"] == "operator-at-host" and policy["secret_visibility_proof"] == "local"
    # Published beyond loopback: a "local" assertion proves nothing; a step-up proof is needed.
    for bind, public in (("0.0.0.0", ""), ("127.0.0.1", "scanner.example.test"), ("100.64.0.5", "")):
        monkeypatch.setenv("SHAKERSCAN_BIND_HOST", bind)
        monkeypatch.setenv("SHAKERSCAN_PUBLIC_HOST", public)
        with pytest.raises(HuntStartContractError) as remote:
            normalize_hunt_start_payload(local)
        assert remote.value.code == "secret_visibility_unasserted"
        stepped = {**local, "allow_asserted_by": {"person": "alice@example.test", "proof": "stepup"}}
        assert _persisted(normalize_hunt_start_payload(stepped))["secret_visibility_set_by"] == "alice@example.test"


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
            "allow_asserted_by": {"person": "someone", "proof": "local"},
        })
    except Exception:  # noqa: BLE001 - refusing the field outright is as good as dropping it
        pass
    assert all("secret_visibility" not in (payload or {}) and "allow_asserted_by" not in (payload or {})
               for _method, _path, payload in sent)


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
    assert local.sent[-1][2]["allow_asserted_by"]["proof"] == "local"
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
    # Never truncated: a path the request may carry but the try cannot name exactly is no destination.
    long_path = "/" + "a" * secret_try.MAX_PATH_CHARS
    assert secret_try.destination_of({"path": long_path}, "https://app.example.test") is None
    assert secret_try.destination_of({"path": long_path[:secret_try.MAX_PATH_CHARS]}, "https://app.example.test")
    for path in ("/hub", "/hub/", "/hub/login", "/Hub/Login", "/%68ub/login", "/%2568ub/login",
                 "/a/../hub/login", "//hub//login", "/hub/login?next=/"):
        assert secret_try.denied_destination("honey.shakerscan.com", path), path
        assert secret_try.denied_destination("HONEY.shakerscan.com.", path), path
    for path in ("/hub;jsessionid=1/login", "/hub/login;x=y", "/%2Fhub/login", "/static/..;/hub/login"):
        assert secret_try.denied_destination("honey.shakerscan.com", path), path
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


def test_a_denied_login_is_recognised_by_the_address_a_request_is_pinned_to(monkeypatch):
    import asyncio
    monkeypatch.delenv("SHAKERSCAN_SECRET_TRY_DENY", raising=False)
    monkeypatch.setattr(secret_try, "_RESOLVED", {})
    # Labelled double: the denied host's addresses, without DNS.
    monkeypatch.setattr(secret_try, "resolve_denied_host",
                        lambda host: frozenset({"198.51.100.7"}) if host == "honey.shakerscan.com" else frozenset())
    alias = ("alias.example.test", "/hub/login")
    assert asyncio.run(secret_try.denied_destination_resolved(*alias, ("198.51.100.7",)))
    assert asyncio.run(secret_try.denied_destination_resolved("alias.example.test", "/hub;a=b/login", ("198.51.100.7",)))
    assert not asyncio.run(secret_try.denied_destination_resolved("alias.example.test", "/login", ("198.51.100.7",)))
    assert not asyncio.run(secret_try.denied_destination_resolved(*alias, ("203.0.113.9",)))


def test_a_request_carrying_a_discovered_secret_follows_no_redirect_even_on_its_own_origin(monkeypatch):
    """A same-origin 302 to the denied hub login: the secret-bearing request is sent once and the
    redirect is not followed (httpx MockTransport; no network)."""
    import asyncio
    import httpx
    from capabilities import http_workflow
    from runtime.models import TargetBinding

    seen = []

    def handler(request):
        seen.append((request.url.path, request.headers.get("x-api-key")))
        if request.url.path == "/account":
            return httpx.Response(302, headers={"location": "/hub/login"})
        return httpx.Response(200)

    class MockClient(httpx.AsyncClient):
        def __init__(self, **kwargs):
            kwargs.pop("transport", None)
            super().__init__(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", MockClient)
    target = TargetBinding(
        target_id="t-1", target_kind="web", canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",), allowed_addresses=("203.0.113.10",),
        allowed_root_domains=("example.test",), scope_receipt_id="scope-1",
    )
    inputs = {"method": "GET", "path": "/account", "follow_redirects": True, "request_bindings": [
        {"secret_ref": "secret://00000000-0000-4000-8000-000000000001", "header": "X-Api-Key"}]}

    async def exchange(conn, *, values, trusted_headers, capture_state, **_):
        # Labelled double for the store: the resolved value goes into the bound header.
        capture_state.bound_values.append("synthetic-key-0001")
        wire = {key: value for key, value in values.items() if key != "request_bindings"}
        return wire, {**trusted_headers, "X-Api-Key": "synthetic-key-0001"}, capture_state

    monkeypatch.setattr(http_workflow, "prepare_http_exchange", exchange)

    class Conn:
        async def fetchrow(self, *_args):
            return {"status": "active", "completed_at": None}

    class Pool:
        def acquire(self):
            pool_conn = Conn()

            class Context:
                async def __aenter__(self):
                    return pool_conn

                async def __aexit__(self, *_):
                    return False
            return Context()

    async def revalidate(_conn):
        return None

    async def run():
        execute, _exchange, _ = await http_workflow.prepare_http_operation(
            pool=Pool(), run={"id": "00000000-0000-4000-8000-0000000000aa"}, context={},
            policy={"active_testing": True}, action_id="00000000-0000-4000-8000-0000000000ab",
            target=target, target_url="https://app.example.test", inputs=inputs, trusted_headers={},
            principal_slot="anonymous", requested_budget={"http_requests": 5, "active_actions": 1}, timeout_seconds=5,
            recorder=lambda _captured: None, revalidate=revalidate,
        )
        return await execute()

    result = asyncio.run(run())
    assert seen == [("/account", "synthetic-key-0001")]
    assert result.get("hops_followed", 0) == 0
