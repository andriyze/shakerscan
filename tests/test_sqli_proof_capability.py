from __future__ import annotations

import asyncio
import json
import urllib.parse

import pytest

from api.capabilities.sqli_proof import SQLiProofAdapter
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from api.runtime.models import TargetBinding
from api.runtime.request_replay_executor import ReplayTransportResult
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
    adapter = SQLiProofAdapter(
        specification=CAPABILITY_REGISTRY.require("sqli.prove_batch"),
        target=_target(),
        request=request,
        candidate=candidate,
        transport=transport,
        requested_budget={
            "http_requests": 20,
            "state_changing_requests": 20 if request.method == "POST" else 0,
            "tool_wall_seconds": 20,
        },
    )
    return asyncio.run(adapter.execute(
        heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False,
    ))


class ErrorDifferentialTransport:
    async def send(self, request, **_kwargs):
        value = urllib.parse.parse_qs(
            urllib.parse.urlsplit(request.url).query,
        ).get("q", [""])[0]
        body = (
            b"You have an error in your SQL syntax near input"
            if value.endswith("'") else b'{"products":[]}'
        )
        return ReplayTransportResult(
            status_code=200, connected_address="192.0.2.10",
            final_url=request.url, response_headers={"Content-Type": "application/json"},
            response_body=body, elapsed_ms=10,
        )


def test_error_differential_requires_two_matching_reproductions():
    result = _run(
        _request(url="https://app.example.test/search?q=apple"),
        {
            "candidate_id": "a" * 64, "method": "GET",
            "parameter_name": "q", "request_class": "safe_read",
        },
        ErrorDifferentialTransport(),
    )
    proof = result.observations[0]
    assert result.status == "success"
    assert proof["proof_state"] == "verified"
    assert proof["proof_contract"] == "sqli_error_differential/v2"
    assert proof["repetitions"] == 2
    assert len(proof["response_pairs"]) == 2


class AuthenticationTransport:
    async def send(self, request, **_kwargs):
        document = json.loads(request.body)
        bypass = "OR 1=1" in document["email"]
        return ReplayTransportResult(
            status_code=200 if bypass else 401,
            connected_address="192.0.2.10", final_url=request.url,
            response_headers={"Content-Type": "application/json"},
            response_body=(
                b'{"authentication":{"token":"worker-secret"}}'
                if bypass else b'{"error":"invalid credentials"}'
            ), elapsed_ms=15,
        )


def test_safe_authentication_proof_detects_json_identity_without_leaking_it():
    result = _run(
        _request(
            method="POST", url="https://app.example.test/login",
            body='{"email":"nobody@example.test","password":"invalid"}',
            content_type="application/json",
        ),
        {
            "candidate_id": "b" * 64, "request_ref_id": "exact-request",
            "method": "POST", "field_path": "email",
            "request_class": "safe_authentication",
        },
        AuthenticationTransport(),
    )
    proof = result.observations[0]
    assert proof["proof_state"] == "verified"
    assert proof["proof_contract"] == "sqli_authentication_bypass/v1"
    assert proof["session_state_discarded"] is True
    assert "worker-secret" not in json.dumps(result.__dict__, default=str)


@pytest.mark.parametrize(("status", "token"), [(200, False), (403, False), (500, True)])
def test_authentication_challenge_cookies_and_failed_token_responses_are_not_proof(status, token):
    class ChallengeTransport:
        async def send(self, request, **_kwargs):
            injected = "OR 1=1" in json.loads(request.body)["email"]
            return ReplayTransportResult(
                status_code=status if injected else 401,
                connected_address="192.0.2.10", final_url=request.url,
                response_headers={
                    "Content-Type": "application/json",
                    **({"Set-Cookie": "challenge=challenge-secret"} if injected else {}),
                },
                response_body=(
                    b'{"authentication":{"token":"challenge-secret"}}' if injected and token
                    else b'{"challenge":"complete verification"}' if injected
                    else b'{"error":"invalid credentials"}'
                ), elapsed_ms=10,
            )

    result = _run(
        _request(
            method="POST", url="https://app.example.test/login",
            body='{"email":"nobody@example.test","password":"invalid"}',
            content_type="application/json",
        ),
        {"candidate_id": "c" * 64, "method": "POST", "field_path": "email",
         "request_class": "safe_authentication"},
        ChallengeTransport(),
    )
    assert result.observations[0]["proof_state"] == "not_proven"
    assert result.observations[0]["proof_contract"] is None
    assert result.actual_budget["http_requests"] == 8
    assert "challenge-secret" not in json.dumps(result.observations)



def _run_with_budget(request, candidate, transport, *, http_requests, through_executor=False):
    budget = {
        "http_requests": http_requests,
        "state_changing_requests": http_requests if request.method == "POST" else 0,
        "tool_wall_seconds": 20,
    }
    spec = CAPABILITY_REGISTRY.require("sqli.prove_batch")
    adapter = SQLiProofAdapter(
        specification=spec, target=_target(), request=request,
        candidate=candidate, transport=transport, requested_budget=budget,
    )
    if through_executor:
        from api.hunt.capability_executor import (
            CapabilityExecutionContext, CapabilityExecutor,
        )
        return asyncio.run(CapabilityExecutor().execute(
            CapabilityExecutionContext(
                specification=spec, target=_target(), requested_budget=budget,
                adapter_managed_cancellation=True,
            ),
            adapter, heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False,
        ))
    return asyncio.run(adapter.execute(
        heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False,
    ))


def _q(request):
    return urllib.parse.parse_qs(urllib.parse.urlsplit(request.url).query).get("q", [""])[0]


def _json_result(body: bytes):
    return ReplayTransportResult(
        status_code=200, connected_address="192.0.2.10", final_url="",
        response_headers={"Content-Type": "application/json"},
        response_body=body, elapsed_ms=10,
    )


class EchoTransport:
    """Reflects the parameter straight back; nothing ever reaches a database."""

    async def send(self, request, **_kwargs):
        value = _q(request)
        return _json_result(json.dumps({"q": value}).encode())


def test_echo_endpoint_reflecting_payload_is_not_proven():
    result = _run_with_budget(
        _request(url="https://app.example.test/search?q=apple"),
        {"candidate_id": "e" * 64, "method": "GET",
         "parameter_name": "q", "request_class": "safe_read"},
        EchoTransport(), http_requests=20,
    )
    proof = result.observations[0]
    assert proof["proof_state"] == "not_proven"
    assert proof["proof_contract"] is None


class BooleanBlindTransport:
    """A genuine boolean differential: TRUE reproduces the baseline, FALSE does not.

    The payload itself is never reflected -- it goes into the query -- so after
    reflection stripping TRUE still equals the baseline and FALSE still differs.
    """

    def __init__(self):
        self.sent = 0

    async def send(self, request, **_kwargs):
        self.sent += 1
        value = _q(request)
        if "1'='1" in value:
            body = b'{"products":["apple"]}'       # TRUE condition: baseline rows
        elif "1'='2" in value:
            body = b'{"products":[]}'              # FALSE condition: no rows
        else:
            body = b'{"products":["apple"]}'       # control + error payload, no SQL error
        return _json_result(body)


def test_boolean_differential_true_matches_baseline_false_differs_is_verified():
    transport = BooleanBlindTransport()
    result = _run_with_budget(
        _request(url="https://app.example.test/search?q=apple"),
        {"candidate_id": "f" * 64, "method": "GET",
         "parameter_name": "q", "request_class": "safe_read"},
        transport, http_requests=20,
    )
    proof = result.observations[0]
    assert proof["proof_state"] == "verified"
    assert proof["proof_contract"] == "sqli_boolean_differential/v1"


class ReflectingBooleanTransport:
    """Reflects the payload AND carries a genuine, post-normalization difference."""

    async def send(self, request, **_kwargs):
        value = _q(request)
        if "1'='1" in value:
            rows = 2
        elif "1'='2" in value:
            rows = 0
        else:
            rows = 2
        return _json_result(json.dumps({"q": value, "rows": rows}).encode())


def test_boolean_reflection_with_a_real_difference_still_verifies():
    result = _run_with_budget(
        _request(url="https://app.example.test/search?q=apple"),
        {"candidate_id": "9" * 64, "method": "GET",
         "parameter_name": "q", "request_class": "safe_read"},
        ReflectingBooleanTransport(), http_requests=20,
    )
    proof = result.observations[0]
    assert proof["proof_state"] == "verified"
    assert proof["proof_contract"] == "sqli_boolean_differential/v1"


class NoSignalTransport:
    """Never an error, never a differential: the oracle must find nothing."""

    def __init__(self):
        self.sent = 0

    async def send(self, request, **_kwargs):
        self.sent += 1
        return _json_result(b'{"ok":true}')


def test_proof_never_sends_more_requests_than_reserved():
    # Reservation of exactly four funds only the error stage. Before the budget
    # gate, the boolean stage fired anyway and sent four more (eight total), which
    # the executor then rejected as an over-reservation -- yet those requests had
    # already been sent. The adapter must stop at its reservation.
    transport = NoSignalTransport()
    result = _run_with_budget(
        _request(url="https://app.example.test/search?q=apple"),
        {"candidate_id": "4" * 64, "method": "GET",
         "parameter_name": "q", "request_class": "safe_read"},
        transport, http_requests=4,
    )
    assert transport.sent == 4
    assert result.actual_budget["http_requests"] == 4
    assert result.observations[0]["proof_state"] == "not_proven"

    # And through the executor the honest result is a clean not_proven, never a
    # budget-contract failure.
    transport = NoSignalTransport()
    executed = _run_with_budget(
        _request(url="https://app.example.test/search?q=apple"),
        {"candidate_id": "4" * 64, "method": "GET",
         "parameter_name": "q", "request_class": "safe_read"},
        transport, http_requests=4, through_executor=True,
    )
    assert transport.sent == 4
    assert executed.status in {"success", "partial"}
    assert executed.actual_budget["http_requests"] <= 4
    assert "adapter_budget_contract_violation" not in " ".join(executed.errors)


def test_sqlite_error_constants_are_recognised_signatures():
    """SQLITE_ERROR is what SQLite itself emits.

    The separator was not optional, so the pattern matched
    ``sqlite3_exception`` but missed ``SQLITE_ERROR``. An error-based injection
    that reproduced its 200/500 differential twice, byte-identically, was still
    withheld for want of a database signature.
    """
    from api.capabilities.sqli_proof import _SQL_ERROR_PATTERNS

    def matched(text):
        return any(pattern.search(text) for pattern in _SQL_ERROR_PATTERNS)

    for body in (
        'SQLITE_ERROR: near "\'%\'": syntax error',
        "sqlite3_exception",
        "SQLiteError: bad query",
        "sqlite error",
    ):
        assert matched(body), body

    for benign in (
        "a benign sentence about sql lite products",
        "SQLITE_CONSTRAINT",
        "no database words here",
    ):
        assert not matched(benign), benign
