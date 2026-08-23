from __future__ import annotations

import asyncio
import json
import urllib.parse

from api.capabilities.request_mutation import (
    RequestMutationVerificationAdapter,
    mutate_private_request,
)
from api.hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from api.runtime.models import TargetBinding
from api.runtime.request_replay_executor import ReplayTransportResult
from scanner.scanner_tools.request_replay import ReplayAuthorization, build_replay_plan


def _target() -> TargetBinding:
    return TargetBinding(
        target_id="10000000-0000-4000-8000-000000000001",
        target_kind="api",
        canonical_host="api.example.test",
        allowed_origins=("https://api.example.test",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
        scope_receipt_id="10000000-0000-4000-8000-000000000002",
    )


def _request(*, body: str, content_type: str):
    return build_replay_plan(
        ({
            "id": "create-order",
            "method": "POST",
            "url": "https://api.example.test/orders?tenant=worker-secret",
            "headers": {
                "Content-Type": content_type,
                "Authorization": "Bearer worker-secret",
            },
            "body": body,
            "body_mode": content_type,
            "has_sensitive_material": True,
        },),
        allowed_origins=_target().allowed_origins,
        authorization=ReplayAuthorization(
            active_testing=True,
            allow_state_changing_http=True,
            approval_receipt_id="approval-1",
        ),
    ).requests[0]


def _candidate():
    return {
        "candidate_id": "a" * 64,
        "request_ref_id": "create-order",
        "method": "POST",
        "family_hints": ("xss", "sqli"),
    }


def test_json_and_form_mutations_preserve_exact_request_outside_one_field():
    json_request = _request(
        body='{"sku":"worker-secret","comment":"hello"}',
        content_type="application/json",
    )
    changed, field, marker, encoding = mutate_private_request(
        json_request, family="xss", candidate_id="a" * 64,
    )
    document = json.loads(changed.body)
    assert (field, encoding) == ("comment", "json")
    assert document == {"comment": marker, "sku": "worker-secret"}
    assert changed.url == json_request.url
    assert changed.headers == json_request.headers

    form_request = _request(
        body="product=worker-secret&id=7",
        content_type="application/x-www-form-urlencoded",
    )
    changed, field, _marker, encoding = mutate_private_request(
        form_request, family="sqli", candidate_id="b" * 64,
    )
    assert (field, encoding) == ("id", "form")
    assert urllib.parse.parse_qsl(changed.body.decode()) == [
        ("product", "worker-secret"), ("id", "7'"),
    ]


class ReflectingTransport:
    def __init__(self):
        self.requests = []

    async def send(self, request, **_kwargs):
        self.requests.append(request)
        return ReplayTransportResult(
            status_code=200,
            connected_address="192.0.2.10",
            final_url=request.url,
            response_headers={"Content-Type": "text/plain"},
            response_body=request.body if len(self.requests) == 2 else b"control",
        )


def test_xss_request_verifier_emits_value_free_differential_evidence():
    request = _request(
        body='{"comment":"worker-secret","sku":"A-1"}',
        content_type="application/json",
    )
    transport = ReflectingTransport()
    spec = CAPABILITY_REGISTRY.require("xss.request_verify")
    budget = dict(spec.budget_cost)
    adapter = RequestMutationVerificationAdapter(
        specification=spec,
        target=_target(),
        request=request,
        candidate=_candidate(),
        transport=transport,
        requested_budget=budget,
    )
    result = asyncio.run(CapabilityExecutor().execute(
        CapabilityExecutionContext(
            specification=spec,
            target=_target(),
            requested_budget=budget,
            adapter_managed_cancellation=True,
        ),
        adapter,
        heartbeat=lambda: asyncio.sleep(0),
        cancelled=lambda: False,
    ))

    assert result.status == "success"
    assert result.actual_budget["http_requests"] == 2
    assert result.actual_budget["state_changing_requests"] == 2
    assert result.observations[0]["proof_status"] == "reflected_candidate_only"
    public = json.dumps({
        "observations": result.observations,
        "execution": result.redacted_execution,
    }, sort_keys=True)
    assert "worker-secret" not in public
    assert "Bearer" not in public
    assert len(transport.requests) == 2


class SqlErrorTransport(ReflectingTransport):
    async def send(self, request, **_kwargs):
        self.requests.append(request)
        body = (
            b"You have an error in your SQL syntax"
            if len(self.requests) == 2 else b"normal response"
        )
        return ReplayTransportResult(
            status_code=500 if len(self.requests) == 2 else 200,
            connected_address="192.0.2.10",
            final_url=request.url,
            response_body=body,
        )


def test_sqli_request_verifier_uses_error_differential_without_extraction():
    request = _request(
        body="id=7&note=worker-secret",
        content_type="application/x-www-form-urlencoded",
    )
    transport = SqlErrorTransport()
    spec = CAPABILITY_REGISTRY.require("sqli.request_verify")
    budget = dict(spec.budget_cost)
    adapter = RequestMutationVerificationAdapter(
        specification=spec,
        target=_target(),
        request=request,
        candidate=_candidate(),
        transport=transport,
        requested_budget=budget,
    )
    result = asyncio.run(CapabilityExecutor().execute(
        CapabilityExecutionContext(
            specification=spec,
            target=_target(),
            requested_budget=budget,
            adapter_managed_cancellation=True,
        ),
        adapter,
        heartbeat=lambda: asyncio.sleep(0),
        cancelled=lambda: False,
    ))

    assert result.status == "success"
    assert result.observations[0]["proof_status"] == "db_error_candidate_only"
    assert result.observations[0]["finding_verdict"] == "suspected"
