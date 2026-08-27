from __future__ import annotations

import asyncio
import json
import urllib.parse

from api.capabilities.nosqli_verify import NoSQLiVerifyAdapter
from api.check_registry import get_check_family
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from api.runtime.models import TargetBinding
from api.runtime.request_replay_executor import ReplayTransportResult
from api.scan.contracts import SCAN_V2_FAMILY_NAMES, public_scan_contract
from scanner.scanner_tools.request_replay import ReplayAuthorization, build_replay_plan


def _target() -> TargetBinding:
    return TargetBinding(
        target_id="10000000-0000-4000-8000-000000000001",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
        scope_receipt_id="10000000-0000-4000-8000-000000000002",
    )


def _request(*, method: str = "GET", url: str, body: str = "", content_type: str = ""):
    headers = {"Content-Type": content_type} if content_type else {}
    return build_replay_plan(
        ({
            "id": "exact-request",
            "method": method,
            "url": url,
            "headers": headers,
            "body": body,
            "body_mode": content_type or "none",
            "has_sensitive_material": bool(body),
        },),
        allowed_origins=_target().allowed_origins,
        authorization=ReplayAuthorization(
            active_testing=True,
            allow_state_changing_http=True,
            approval_receipt_id="approval-1",
        ),
    ).requests[0]


def _run(request, candidate, transport):
    adapter = NoSQLiVerifyAdapter(
        specification=CAPABILITY_REGISTRY.require("nosqli.verify_batch"),
        target=_target(),
        request=request,
        candidate=candidate,
        transport=transport,
        requested_budget={"http_requests": 20, "tool_wall_seconds": 20},
    )
    return asyncio.run(adapter.execute(
        heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False,
    ))


def _result(status, body, headers=None):
    return ReplayTransportResult(
        status_code=status, connected_address="192.0.2.10",
        final_url="https://app.example.test/x",
        response_headers=headers or {"Content-Type": "application/json"},
        response_body=body, elapsed_ms=10,
    )


class OperatorInterpretedTransport:
    """A store that interprets ``field[$ne]`` returns a different result set."""

    async def send(self, request, **_kwargs):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(request.url).query)
        if any("[$ne]" in key for key in query):
            return _result(200, b'{"results":[{"id":1},{"id":2}]}')
        return _result(200, b'{"results":[]}')


class LiteralOperatorTransport:
    """A store that treats ``field[$ne]`` as a literal key: no differential."""

    async def send(self, request, **_kwargs):
        return _result(200, b'{"results":[]}')


class AuthBypassTransport:
    async def send(self, request, **_kwargs):
        document = json.loads(request.body.decode("utf-8"))
        password = document.get("password")
        if isinstance(password, dict) and "$ne" in password:
            return _result(
                200, b'{"authentication":{"token":"eyJ.session.grant"}}',
                {"Content-Type": "application/json", "Set-Cookie": "sid=abc"},
            )
        return _result(401, b'{"error":"invalid credentials"}')


def test_operator_set_differential_promotes_repeatably():
    result = _run(
        _request(url="https://app.example.test/rest/products/search?q=apple"),
        {
            "candidate_id": "a" * 64, "method": "GET",
            "parameter_name": "q", "request_class": "safe_read",
        },
        OperatorInterpretedTransport(),
    )
    proof = result.observations[0]
    assert proof["proof_state"] == "verified"
    assert proof["proof_contract"] == "nosqli_operator_differential/v1"
    assert proof["technique"] == "operator_set_differential_repeated"
    assert proof["repetitions"] == 2
    assert len(proof["response_pairs"]) == 2


def test_literal_operator_store_is_never_promoted():
    result = _run(
        _request(url="https://app.example.test/rest/products/search?q=apple"),
        {
            "candidate_id": "b" * 64, "method": "GET",
            "parameter_name": "q", "request_class": "safe_read",
        },
        LiteralOperatorTransport(),
    )
    proof = result.observations[0]
    assert proof["proof_state"] == "not_proven"
    assert proof["proof_contract"] is None


def test_json_body_operator_authentication_bypass_is_critical_class():
    result = _run(
        _request(
            method="POST", url="https://app.example.test/rest/user/login",
            body=json.dumps({"email": "a@b.test", "password": "guess"}),
            content_type="application/json",
        ),
        {
            "candidate_id": "c" * 64, "method": "POST",
            "field_path": "password", "request_class": "safe_authentication",
            "request_ref_id": "exact-request",
        },
        AuthBypassTransport(),
    )
    proof = result.observations[0]
    assert proof["proof_state"] == "verified"
    assert proof["technique"] == "operator_auth_bypass_repeated"
    assert proof["session_state_discarded"] is True
    assert proof["secret_values_visible"] is False


def test_nosqli_is_a_registered_canonical_family():
    assert "nosqli" in SCAN_V2_FAMILY_NAMES
    assert get_check_family("nosqli").is_active is True
    assert get_check_family("mongo_injection").name == "nosqli"  # alias
    spec = CAPABILITY_REGISTRY.require("nosqli.verify_batch")
    assert spec.required_approval == "active_testing"
    assert "nosqli_proof" in spec.evidence_contract
    families = {item["name"] for item in public_scan_contract()["families"]}
    assert "nosqli" in families


def test_compiler_emits_query_and_request_nosqli_batches():
    from api.scan.action_plan import ScanActionPlanCompiler
    from tests.test_scan_action_compiler import _execution, _target as _compiler_target

    plan = ScanActionPlanCompiler().compile(
        scan_id="60000000-0000-4000-8000-000000000001",
        execution_plan=_execution(include=("nosqli",), active=True),
        target_binding=_compiler_target(), action_scope="full",
    )
    exposure = next(
        action for action in plan.actions
        if action.capability_name == "nosqli.verify_batch"
    )
    assert list(exposure.placement["eligible_backends"]) == ["local"]


def test_finalizer_promotes_only_repeated_nosqli_operator_proof():
    from api.scan.action_plan import ScanActionPlan
    from api.scan.finalizer import finalize_scan_report
    from tests.test_scan_finalizer import _result_with_observation_count
    from tests.test_scan_orchestrator import SCAN_ID, _action

    verify = _action("verify.nosqli", 0, capability_name="nosqli.verify_batch")
    final = _action("finalize.report", 1, dependencies=(verify.action_id,))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(verify, final),
    )
    results = {verify.action_id: _result_with_observation_count(verify, 2)}
    observations = {verify.action_id: (
        {
            "kind": "nosqli_proof", "candidate_id": "nosqli-1",
            "method": "POST", "field_path": "password",
            "request_class": "safe_authentication",
            "proof_state": "verified", "finding_verdict": "verified",
            "proof_contract": "nosqli_operator_differential/v1",
            "technique": "operator_auth_bypass_repeated",
            "operator": "$ne", "repetitions": 2,
            "response_pairs": [{"literal_status": 401, "operator_status": 200}],
            "session_state_discarded": True,
        },
        {
            "kind": "nosqli_proof", "candidate_id": "nosqli-2",
            "proof_state": "not_proven", "finding_verdict": "not_proven",
            "proof_contract": None, "repetitions": 2,
        },
    )}

    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results=results, observations=observations,
    )

    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["tool"] == "shakerscan_nosqli_verify"
    assert finding["severity"] == "critical"
    assert finding["cwe"] == "CWE-943"
    assert finding["verified"] is True
    assert finding["evidence"]["canonical_capability"] == "nosqli.verify_batch"


class ErroringOperatorTransport:
    """A SQL-backed store that raises when handed an operator object."""

    async def send(self, request, **_kwargs):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(request.url).query)
        if any("[$ne]" in key for key in query):
            return _result(500, b'{"error":"Internal Server Error"}')
        return _result(200, b'{"results":[]}')


def test_a_server_error_on_the_operator_payload_is_never_proof():
    """A 500 proves the operator was rejected, not interpreted.

    A SQL-backed endpoint handed ``key[$ne]=<sentinel>`` raises where the
    literal answers 200. That is a stable, repeatable difference, so a
    fingerprint-only differential promoted it to a verified NoSQL injection --
    a false positive at the highest trust tier this scanner has.
    """
    result = _run(
        _request(url="https://app.example.test/api/Challenges/?key=nftMintChallenge"),
        {
            "candidate_id": "b" * 64, "method": "GET",
            "parameter_name": "key", "request_class": "safe_read",
        },
        ErroringOperatorTransport(),
    )
    proof = result.observations[0]
    assert proof["proof_state"] == "not_proven"
    assert proof["finding_verdict"] == "not_proven"
