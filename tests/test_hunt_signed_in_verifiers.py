"""Hunt scanners and verifiers signed in, verifier body inputs, and the sqli.verify proof.

Unit level: the planner contract, admission's refusals, the sqlmap/dalfox argv for a body
input, the exact proof request, the proof step over a labelled transport double, and the
materialized finding. The database paths are in test_hunt_signed_in_verifiers_postgres.py.
"""
from __future__ import annotations

import asyncio
import json
import uuid

import pytest

from api import agent_tools
from api.hunt import scanner_sqli_proof
from api.hunt.deterministic_findings import _sqli_finding_records, materialize_verified_hunt_findings
from api.hunt.permission_reasons import HuntRefusal
from api.hunt.scanner_identity import scanner_admission, scanner_identity_refusal
from api.runtime.capability_registry import CAPABILITY_REGISTRY, CapabilityInputContractError
from api.runtime.models import TargetBinding
from api.runtime.request_replay_executor import ReplayTransportResult

ORIGIN = "https://app.example.test"
LOGIN_BODY = {
    "path": "/login", "method": "POST", "body_field_names": ["username", "password"],
    "injection_field": "username",
}
ACTIVE = {"active_testing": True, "allow_state_changing_http": False}
STATE_CHANGING = {"active_testing": True, "allow_state_changing_http": True}


# --- The planner contract -----------------------------------------------------------------------

@pytest.mark.parametrize("name", ["sqli.verify", "xss.verify"])
def test_verifiers_accept_a_body_field_as_the_tested_input(name):
    values = CAPABILITY_REGISTRY.validate_hunt_input(name, {**LOGIN_BODY, "as_principal": "primary"})
    assert values["injection_field"] == "username"
    properties = CAPABILITY_REGISTRY.require(name).planner_contract()["input_schema"]["properties"]
    assert {"method", "body_field_names", "injection_field", "content_type", "session_ref",
            "as_principal"} <= set(properties)


@pytest.mark.parametrize("values,message", [
    ({"path": "/login", "method": "POST", "body_field_names": ["username"]}, "injection_field"),
    ({**LOGIN_BODY, "injection_field": "email"}, "one of body_field_names"),
    ({**LOGIN_BODY, "body_field_names": ["username", "username"]}, "distinct"),
    ({**LOGIN_BODY, "method": "GET"}, "not an allowed value"),
    ({**LOGIN_BODY, "body_field_names": ["user.name"]}, "invalid format"),
    ({"path": "/item?id=1", "as_principal": "primary",
      "session_ref": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, "not both"),
])
def test_a_body_input_must_name_its_field_and_one_identity(values, message):
    with pytest.raises(CapabilityInputContractError, match=message):
        CAPABILITY_REGISTRY.validate_hunt_input("sqli.verify", values)


def test_a_body_input_is_not_a_deep_dom_xss_check_nor_a_crawl_input():
    with pytest.raises(CapabilityInputContractError, match="deep_domxss"):
        CAPABILITY_REGISTRY.validate_hunt_input("xss.verify", {**LOGIN_BODY, "deep_domxss": True})
    with pytest.raises(CapabilityInputContractError, match="unsupported fields"):
        CAPABILITY_REGISTRY.validate_hunt_input("web.crawl", {"method": "POST"})


def test_the_signed_in_scanners_advertise_a_session_and_the_browser_crawl_no_identity():
    for name in ("web.crawl", "web.content_discover", "templates.scan", "xss.verify", "sqli.verify"):
        properties = CAPABILITY_REGISTRY.require(name).planner_contract()["input_schema"]["properties"]
        assert {"as_principal", "session_ref"} <= set(properties), name
    browser = CAPABILITY_REGISTRY.require("web.browser_crawl").planner_contract()["input_schema"]
    assert set(browser["properties"]) == {"origin"}
    with pytest.raises(CapabilityInputContractError, match="unsupported fields: as_principal"):
        CAPABILITY_REGISTRY.validate_hunt_input("web.browser_crawl", {"as_principal": "primary"})
    # The Scan's own input contract is unchanged.
    CAPABILITY_REGISTRY.validate_input("web.browser_crawl", {"as_principal": "primary"})


# --- Admission ----------------------------------------------------------------------------------

def test_admission_runs_signed_in_scanners_as_their_principal():
    assert scanner_admission("sqli.verify", {"path": "/item?id=1", "as_principal": "primary"}, ACTIVE) == "primary"
    assert scanner_admission("web.crawl", {"as_principal": "secondary"}, ACTIVE) == "secondary"
    session = {"session_ref": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
    assert scanner_admission("templates.scan", session, ACTIVE) == "anonymous"
    assert scanner_identity_refusal("xss.verify", {"path": "/search?q=x", **session}) is None


@pytest.mark.parametrize("name,values", [
    ("web.browser_crawl", {"as_principal": "primary"}),
    ("xss.verify", {"path": "/search?q=x", "deep_domxss": True, "as_principal": "primary"}),
    ("xss.verify", {"path": "/#/search?q=x", "session_ref": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}),
])
def test_a_capability_that_cannot_carry_the_session_refuses_it_and_says_why(name, values):
    with pytest.raises(HuntRefusal) as refused:
        scanner_admission(name, values, ACTIVE)
    assert refused.value.reason_code == "principal_anonymous_only"
    assert "without a session" in refused.value.message or "cannot carry" in refused.value.message


def test_a_body_test_needs_the_state_changing_permission_and_raises_a_request():
    with pytest.raises(HuntRefusal) as refused:
        scanner_admission("sqli.verify", LOGIN_BODY, ACTIVE)
    assert refused.value.reason_code == "state_changing_http_not_allowed"
    assert refused.value.subject == {"capability": "sqli.verify", "flag": "state-changing"}
    assert "own hold" in refused.value.message
    assert scanner_admission("sqli.verify", LOGIN_BODY, STATE_CHANGING) == "anonymous"


def test_scanner_principals_are_recorded_as_credential_uses():
    from api.hunt.credential_uses import action_credential_references

    profile = str(uuid.uuid4())
    context = {"credential_refs": [{
        "source": "credential_profiles", "principal_slot": "primary", "profile_id": profile,
        "profile_version": 2, "allowed_capabilities": ["http.request", "sqli.verify"],
    }]}
    assert action_credential_references("sqli.verify", {"as_principal": "primary"}, context) == [
        ("primary", {"profile_id": profile, "principal_slot": "primary", "profile_version": 2})]
    from api.hunt.credential_uses import HuntCredentialRefusal
    with pytest.raises(HuntCredentialRefusal) as refused:
        action_credential_references("xss.verify", {"as_principal": "primary"}, context)
    assert refused.value.code == "credential_capability_not_granted"


# --- The tool argv ------------------------------------------------------------------------------

def _plan(name, tool, values, *, headers=None):
    options = agent_tools.canonical_hunt_scanner_options(name, values)
    hold = agent_tools.canonical_hunt_scanner_budget(name, budget_profile="balanced")
    return agent_tools.build_enforced_scanner_plan(
        tool, f"{ORIGIN}{values['path']}", options, reserved_budget=hold,
        pinned_address="203.0.113.10", pinned_proxy_url="socks5://127.0.0.1:41000",
        trusted_headers=headers,
        runtime_paths={"sqlmap_output_dir": "/tmp/fixture-sqlmap", "scratch_dir": "/tmp/fixture"},
    )


def test_a_body_sqli_verify_hands_sqlmap_the_body_and_the_session():
    argv = list(_plan("sqli.verify", "sqlmap", {**LOGIN_BODY, "as_principal": "primary"},
                      headers={"Cookie": "sid=fixture"}).argv)
    assert argv[argv.index("--data") + 1] == "username=shakerscan&password=shakerscan"
    assert argv[argv.index("-p") + 1] == "username,password"
    assert argv[argv.index("--headers") + 1] == "Cookie: sid=fixture"


def test_a_json_body_xss_verify_hands_dalfox_the_body():
    argv = list(_plan("xss.verify", "dalfox", {
        **LOGIN_BODY, "content_type": "application/json", "path": "/api/login",
    }, headers={"Authorization": "Bearer fixture"}).argv)
    assert argv[argv.index("-X") + 1] == "POST"
    assert json.loads(argv[argv.index("-d") + 1]) == {"password": "shakerscan", "username": "shakerscan"}
    assert "Authorization: Bearer fixture" in argv


# --- The proof ----------------------------------------------------------------------------------

def _target():
    return TargetBinding(
        target_id=str(uuid.uuid4()), target_kind="web", canonical_host="app.example.test",
        allowed_origins=(ORIGIN,), allowed_addresses=("203.0.113.10",),
        allowed_root_domains=("example.test",), environment="test", scope_receipt_id="scope",
    )


def test_the_proof_request_is_the_request_sqlmap_was_given():
    request, candidate = scanner_sqli_proof.proof_request(
        f"{ORIGIN}/login?next=/", LOGIN_BODY, "username", headers={"Cookie": "sid=1"}, action_id="a")
    assert (request.method, request.url, request.body) == (
        "POST", f"{ORIGIN}/login?next=/", b"username=shakerscan&password=shakerscan")
    assert ("Cookie", "sid=1") in request.headers and request.has_sensitive_material
    assert candidate["request_class"] == "safe_authentication"
    request, candidate = scanner_sqli_proof.proof_request(
        f"{ORIGIN}/item?id=1", {"path": "/item?id=1"}, "id", headers={}, action_id="a")
    assert (request.method, candidate["request_class"], request.auth_type) == ("GET", "safe_read", "none")
    assert scanner_sqli_proof.proof_request(
        f"{ORIGIN}/item?id=1", {"path": "/item?id=1"}, "name", headers={}, action_id="a") is None


class _ErrorOnQuote:
    """Labelled double: the pinned transport. A quote in ``id`` answers with a database error."""

    sent: list = []

    async def send(self, request, *, target, timeout_seconds, follow_redirects):
        type(self).sent.append(request)
        body = b"SQLITE_ERROR: unrecognized token" if "%27" in request.url else b"<p>item</p>"
        return ReplayTransportResult(
            status_code=500 if "%27" in request.url else 200, connected_address="203.0.113.10",
            final_url=request.url, response_headers={}, response_body=body, elapsed_ms=5,
        )


def _prove(monkeypatch, observations, *, actual, reserved=None):
    archived = []

    async def archive(_conn, collected, *_args):
        archived.extend(collected)

    class Pool:
        def acquire(self):
            class Conn:
                async def __aenter__(self): return object()
                async def __aexit__(self, *_): return False
            return Conn()

    _ErrorOnQuote.sent = []
    monkeypatch.setattr(scanner_sqli_proof, "PinnedAiohttpReplayTransport", _ErrorOnQuote)
    monkeypatch.setattr(scanner_sqli_proof.http_archive, "archive_hunt_capture", archive)

    async def beat():
        return None

    proofs, used = asyncio.run(scanner_sqli_proof.prove_hunt_sqli_signal(
        pool=Pool(), results_dir="/tmp", run={"id": str(uuid.uuid4()), "target_id": str(uuid.uuid4())},
        action_id=uuid.uuid4(), target=_target(), execution_target=f"{ORIGIN}/item?id=1",
        values={"path": "/item?id=1", "as_principal": "primary"}, observations=observations,
        reserved=reserved or {"http_requests": 1_800, "tool_wall_seconds": 1_200}, actual=actual,
        headers={"Cookie": "sid=fixture"}, principal_slot="primary", heartbeat=beat, cancelled=lambda: False,
    ))
    return proofs, used, archived


def test_a_sqlmap_signal_is_proved_signed_in_inside_the_actions_own_hold(monkeypatch):
    proofs, used, archived = _prove(monkeypatch, [
        {"kind": "sqli_finding", "param": "id", "method": "GET", "proof_state": "candidate"},
    ], actual={"http_requests": 120, "tool_wall_seconds": 90})
    (proof,) = proofs
    assert (proof["kind"], proof["proof_state"], proof["proof_contract"]) == (
        "sqli_proof", "verified", "sqli_error_differential/v2")
    assert proof["field_path"] == "id" and proof["repetitions"] == 2
    assert used["http_requests"] == 4 and "state_changing_requests" not in used
    assert all(("Cookie", "sid=fixture") in request.headers for request in _ErrorOnQuote.sent)
    assert len(archived) == 4 and {call.principal_slot for call in archived} == {"primary"}


def test_no_signal_no_proof_and_an_exhausted_hold_proves_nothing(monkeypatch):
    assert _prove(monkeypatch, [{"kind": "sqli_dbms_fingerprint", "message": "x"}],
                  actual={"http_requests": 10})[:2] == ([], {})
    proofs, used, _archived = _prove(monkeypatch, [{"kind": "sqli_finding", "param": "id"}],
                                     actual={"http_requests": 1_798, "tool_wall_seconds": 100})
    assert proofs[0]["not_proven_reason"] == "proof_unfunded" and used == {}
    assert _ErrorOnQuote.sent == []


# --- The finding --------------------------------------------------------------------------------

VERIFIED = {
    "kind": "sqli_proof", "origin": ORIGIN, "canonical_path": "/item", "method": "GET",
    "field_path": "id", "request_class": "safe_read", "proof_state": "verified",
    "finding_verdict": "verified", "proof_contract": "sqli_error_differential/v2",
    "technique": "error_based_repeated", "repetitions": 2, "response_pairs": [],
    "database_error_signatures": ["sqlite"], "secret_values_visible": False,
}


def test_only_a_verified_proof_on_an_admitted_origin_becomes_a_finding():
    hunt, action, receipt = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    (record,) = _sqli_finding_records(hunt, action, ORIGIN, "sqli.verify", receipt, [
        VERIFIED,
        {"kind": "sqli_finding", "param": "id", "proof_state": "candidate"},
        {**VERIFIED, "proof_state": "not_proven", "finding_verdict": "not_proven"},
        {**VERIFIED, "repetitions": 1},
        {**VERIFIED, "origin": "https://other.example.test"},
    ])
    assert (record["cwe"], record["severity"], record["title"]) == (
        "CWE-89", "critical", "Verified SQL injection")
    assert record["url"] == f"{ORIGIN}/item" and record["evidence"]["param"] == "id"
    assert record["evidence"]["tool_receipt_id"] == str(receipt)
    assert not _sqli_finding_records(hunt, action, ORIGIN, "sqli.verify", receipt, [
        {"kind": "sqli_finding", "param": "id"}])


def test_a_signed_in_proof_is_recorded_with_its_principal():
    class DB:
        def __init__(self): self.evidence = self.severity = None
        async def fetchrow(self, query, *args): return None
        async def fetchval(self, query, *args):
            self.evidence, self.severity = json.loads(args[4]), args[9]
            return uuid.uuid4()
        async def execute(self, *args): pass

    db = DB()
    ids = asyncio.run(materialize_verified_hunt_findings(
        db, uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), ORIGIN, "sqli.verify", uuid.uuid4(),
        {"path": "/item?id=1", "as_principal": "primary"}, [VERIFIED],
        evidence_principals=("primary",),
    ))
    assert len(ids) == 1 and db.severity == "critical"
    assert db.evidence["evidence_principals"] == ["primary"]
    assert db.evidence["proof_contract"] == "sqli_error_differential/v2"


def test_a_retest_does_not_judge_a_finding_proved_signed_in():
    from api.worker_handlers.retest_identity import (
        candidate_evidence_was_signed_in, retest_identity_unresolved,
    )

    verification = {"finding_id": str(uuid.uuid4()), "evidence": {"evidence_principals": ["primary"]}}
    assert candidate_evidence_was_signed_in(verification)
    assert retest_identity_unresolved(verification)
    assert not candidate_evidence_was_signed_in({"finding_id": "f", "evidence": {"param": "id"}})


def test_a_hunt_body_verifier_is_not_charged_to_the_state_changing_ceiling():
    from api.capabilities.scanner import ScannerExecutionAdapter

    spec = CAPABILITY_REGISTRY.require("sqli.verify")
    arguments = dict(
        specification=spec, process_runner=None, redacted_execution={},
        requested_budget={"http_requests": 1_800, "tool_wall_seconds": 1_200},
        process_payload={"scanner_options": LOGIN_BODY},
    )
    # A Scan body attempt reserves its mutations; the guard stays for every other caller.
    with pytest.raises(ValueError, match="state-changing reservation"):
        ScannerExecutionAdapter(**arguments)
    ScannerExecutionAdapter(**arguments, mutations_in_request_hold=True)


def test_the_worker_releases_a_call_whose_body_permission_or_session_route_went_away():
    from api.hunt.dispatch_authority import HuntDispatchRejected
    from api.hunt.scanner_identity import ANONYMOUS, resolve_scanner_identity

    def resolve(values, policy):
        return asyncio.run(resolve_scanner_identity(
            object(), context={}, target=_target(), policy=policy, approval_receipt_id=None,
            hunt_id=uuid.uuid4(), capability_name="xss.verify" if "deep_domxss" in values else "sqli.verify",
            values=values, execution_target=f"{ORIGIN}/login", session_store=None,
        ))

    # Revoked after admission: nothing is resolved or sent, and the hold is released.
    with pytest.raises(HuntDispatchRejected, match="state-changing permission"):
        resolve(LOGIN_BODY, ACTIVE)
    with pytest.raises(HuntDispatchRejected, match="pinned browser"):
        resolve({"path": "/s?q=1", "deep_domxss": True, "as_principal": "primary"}, ACTIVE)
    assert resolve(LOGIN_BODY, STATE_CHANGING) is ANONYMOUS
