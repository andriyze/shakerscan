from __future__ import annotations

import asyncio
import json
import urllib.parse

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
        requested_budget={"http_requests": 20, "tool_wall_seconds": 20},
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

