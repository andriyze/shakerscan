from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from runtime.models import TargetBinding
from runtime.request_replay_executor import (
    ReplayExecutionError,
    ReplayTransportResult,
    execute_replay_plan,
)
from scanner_tools.request_replay import ReplayAuthorization, build_replay_plan


class Clock:
    def __init__(self):
        self.value = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        self.value += timedelta(milliseconds=10)
        return self.value


class FakeTransport:
    def __init__(self, results=None, error=None):
        self.results = list(results or [])
        self.error = error
        self.calls = []

    async def send(self, request, *, target, timeout_seconds, follow_redirects):
        self.calls.append({
            "request": request,
            "target": target,
            "timeout_seconds": timeout_seconds,
            "follow_redirects": follow_redirects,
        })
        if self.error:
            raise self.error
        return self.results.pop(0)


class HangingTransport(FakeTransport):
    async def send(self, request, *, target, timeout_seconds, follow_redirects):
        self.calls.append({"request": request, "target": target})
        await asyncio.sleep(60)
        raise AssertionError("worker deadline did not interrupt the transport")


def _target(address="192.0.2.10"):
    return TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="api.example.test",
        allowed_origins=("https://api.example.test",),
        allowed_addresses=(address,),
        scope_receipt_id="scope-1",
    )


def _request(method="GET", request_id="request-1"):
    return {
        "id": request_id,
        "method": method,
        "url": "https://api.example.test/orders/1?token=wire-secret",
        "headers": {
            "Authorization": "Bearer header-secret",
            "Cookie": "session=cookie-secret",
            "Content-Type": "application/json",
        },
        "body": b'{"password":"body-secret"}',
        "body_mode": "application/json",
        "auth_type": "captured",
        "has_sensitive_material": True,
        "unresolved_variables": [],
        "error": None,
    }


def _plan(requests=None, *, active=False):
    return build_replay_plan(
        requests or [_request()],
        allowed_origins=["https://api.example.test"],
        authorization=(
            ReplayAuthorization(
                active_testing=True,
                allow_state_changing_http=True,
                approval_receipt_id="approval-1",
            )
            if active else ReplayAuthorization()
        ),
    )


def _result(**overrides):
    values = {
        "status_code": 200,
        "connected_address": "192.0.2.10",
        "final_url": "https://api.example.test/orders/1?token=response-secret",
        "response_headers": {"Content-Type": "application/json", "Set-Cookie": "secret"},
        "response_body": b'{"secret":"response-body"}',
        "elapsed_ms": 12,
    }
    values.update(overrides)
    return ReplayTransportResult(**values)


@pytest.mark.asyncio
async def test_exact_wire_request_executes_with_reservation_and_redacted_receipt():
    plan = _plan()
    transport = FakeTransport([_result()])
    states = []
    settlements = []

    async def state(record, ledger):
        states.append((record.status, dict(ledger)))

    async def settle(record, receipt, ledger):
        settlements.append((record, receipt, dict(ledger)))

    outcome = await execute_replay_plan(
        plan,
        target=_target(),
        owner_kind="scan",
        owner_id="scan-1",
        worker_id="worker-1",
        limits={"http_requests": 10},
        consumed={"http_requests": 2},
        transport=transport,
        reservation_id="reservation-1",
        receipt_id="receipt-1",
        clock=Clock(),
        on_reservation=state,
        on_settlement=settle,
        receipt_context={
            "principal_profile_ref": "profile-1",
            "principal_profile_version": 3,
            "principal_slot": "primary",
        },
    )

    assert [item[0] for item in states] == ["requested", "reserved", "running"]
    assert transport.calls[0]["follow_redirects"] is False
    wire = transport.calls[0]["request"].wire_dict()
    assert wire["headers"]["Authorization"] == "Bearer header-secret"
    assert wire["headers"]["Cookie"] == "session=cookie-secret"
    assert wire["body"] == b'{"password":"body-secret"}'

    assert outcome.status == "succeeded"
    assert outcome.reservation.status == "committed"
    assert outcome.ledger_consumed == {"http_requests": 3}
    assert settlements[0][0].execution_receipt_hash == settlements[0][1].receipt_hash
    public = repr(outcome.receipt.public_dict())
    for secret in (
        "wire-secret", "header-secret", "cookie-secret", "body-secret",
        "response-secret", "response-body",
    ):
        assert secret not in public
    observation = outcome.receipt.observations[0]
    assert outcome.receipt.redacted_execution["principal_profile_ref"] == "profile-1"
    assert outcome.receipt.redacted_execution["principal_profile_version"] == 3
    assert outcome.receipt.redacted_execution["principal_slot"] == "primary"
    assert observation["response_header_names"] == ["Content-Type", "Set-Cookie"]
    assert observation["response_body_size"] == len(b'{"secret":"response-body"}')
    assert len(observation["response_body_sha256"]) == 64


@pytest.mark.asyncio
async def test_partial_timeout_is_measured_and_committed_without_refund_of_attempt():
    requests = [_request(request_id="request-1"), _request(request_id="request-2")]
    plan = _plan(requests)
    transport = FakeTransport([
        _result(),
        _result(status_code=None, error_code="timeout", timed_out=True, response_body=b""),
    ])
    outcome = await execute_replay_plan(
        plan,
        target=_target(),
        owner_kind="scan",
        owner_id="scan-1",
        worker_id="worker-1",
        limits={"http_requests": 10},
        consumed={"http_requests": 0},
        transport=transport,
        clock=Clock(),
    )

    assert outcome.status == "partial"
    assert outcome.reservation.status == "committed"
    assert outcome.receipt.partial is True and outcome.receipt.timed_out is True
    assert outcome.receipt.budget_consumed == {"http_requests": 2}
    assert outcome.ledger_consumed == {"http_requests": 2}


@pytest.mark.asyncio
async def test_cancellation_before_first_request_settles_without_target_traffic():
    transport = FakeTransport([_result()])
    settlements = []

    async def settle(record, receipt, ledger):
        settlements.append((record, receipt, dict(ledger)))

    outcome = await execute_replay_plan(
        _plan(),
        target=_target(),
        owner_kind="hunt",
        owner_id="hunt-1",
        worker_id="worker-1",
        limits={"http_requests": 10},
        consumed={"http_requests": 0},
        transport=transport,
        clock=Clock(),
        cancelled=lambda: True,
        on_settlement=settle,
    )

    assert transport.calls == []
    assert outcome.status == "cancelled"
    assert outcome.reservation.status == "failed"
    assert outcome.reservation.actual == {"http_requests": 0}
    assert outcome.ledger_consumed == {"http_requests": 0}
    assert outcome.receipt.status == "cancelled"
    assert outcome.receipt.partial is False
    assert outcome.receipt.errors == ("execution_cancelled",)
    assert settlements[0][1].receipt_hash == outcome.receipt.receipt_hash


@pytest.mark.asyncio
async def test_cancellation_between_requests_never_sends_the_next_request():
    plan = _plan([
        _request(request_id="request-1"),
        _request(request_id="request-2"),
    ])
    transport = FakeTransport([_result(), _result()])

    outcome = await execute_replay_plan(
        plan,
        target=_target(),
        owner_kind="hunt",
        owner_id="hunt-1",
        worker_id="worker-1",
        limits={"http_requests": 10},
        consumed={"http_requests": 0},
        transport=transport,
        clock=Clock(),
        cancelled=lambda: len(transport.calls) >= 1,
    )

    assert len(transport.calls) == 1
    assert outcome.status == "cancelled"
    assert outcome.reservation.actual == {"http_requests": 1}
    assert outcome.ledger_consumed == {"http_requests": 1}
    assert outcome.receipt.status == "cancelled"
    assert outcome.receipt.partial is True
    assert len(outcome.receipt.observations) == 1


@pytest.mark.asyncio
async def test_preconnect_timeout_preserves_timeout_status_without_scope_false_positive():
    transport = FakeTransport([_result(
        status_code=None,
        connected_address=None,
        error_code="connect_timeout",
        timed_out=True,
        response_headers={},
        response_body=b"",
    )])
    outcome = await execute_replay_plan(
        _plan(), target=_target(), owner_kind="scan", owner_id="scan-1",
        worker_id="worker-1", limits={"http_requests": 10},
        consumed={"http_requests": 0}, transport=transport, clock=Clock(),
    )
    assert outcome.status == "partial"
    assert outcome.reservation.status == "committed"
    assert outcome.receipt.timed_out is True
    assert outcome.receipt.observations[0]["connected_address"] is None


@pytest.mark.asyncio
async def test_worker_owned_deadline_interrupts_hanging_transport_and_charges_attempt():
    outcome = await execute_replay_plan(
        _plan(), target=_target(), owner_kind="scan", owner_id="scan-1",
        worker_id="worker-1", limits={"http_requests": 10},
        consumed={"http_requests": 0}, transport=HangingTransport(),
        timeout_seconds=0.1, clock=Clock(),
    )
    assert outcome.status == "partial"
    assert outcome.receipt.timed_out is True
    assert outcome.receipt.errors == ("request-1:worker_timeout",)
    assert outcome.ledger_consumed == {"http_requests": 1}


@pytest.mark.asyncio
async def test_transport_scope_escape_fails_closed_and_charges_attempted_request():
    transport = FakeTransport([_result(connected_address="192.0.2.99")])
    outcome = await execute_replay_plan(
        _plan(),
        target=_target(),
        owner_kind="scan",
        owner_id="scan-1",
        worker_id="worker-1",
        limits={"http_requests": 10},
        consumed={"http_requests": 0},
        transport=transport,
        clock=Clock(),
    )

    assert outcome.status == "partial"
    assert outcome.reservation.status == "failed"
    assert outcome.reservation.actual == {"http_requests": 1}
    assert outcome.ledger_consumed == {"http_requests": 1}
    assert outcome.receipt.budget_reservation_state == "failed"
    assert any("replayexecutionerror" in item for item in outcome.receipt.errors)


@pytest.mark.asyncio
async def test_transport_url_userinfo_is_rejected_without_leaking_credentials():
    transport = FakeTransport([_result(
        final_url="https://user:password-secret@api.example.test/orders/1",
    )])
    outcome = await execute_replay_plan(
        _plan(), target=_target(), owner_kind="scan", owner_id="scan-1",
        worker_id="worker-1", limits={"http_requests": 10},
        consumed={"http_requests": 0}, transport=transport, clock=Clock(),
    )
    assert outcome.reservation.status == "failed"
    assert "password-secret" not in repr(outcome.receipt.public_dict())
    assert any("replayexecutionerror" in item for item in outcome.receipt.errors)


@pytest.mark.asyncio
async def test_transport_exception_settles_failed_receipt_and_never_leaks_exception_text():
    transport = FakeTransport(error=RuntimeError("Bearer raw-exception-secret"))
    outcome = await execute_replay_plan(
        _plan(),
        target=_target(),
        owner_kind="hunt",
        owner_id="hunt-1",
        worker_id="worker-1",
        limits={"http_requests": 10},
        consumed={"http_requests": 0},
        transport=transport,
        clock=Clock(),
    )

    assert outcome.reservation.status == "failed"
    assert outcome.receipt.hunt_id == "hunt-1"
    assert "raw-exception-secret" not in repr(outcome.receipt.public_dict())
    assert outcome.ledger_consumed == {"http_requests": 1}


@pytest.mark.asyncio
async def test_budget_exhaustion_prevents_any_wire_execution():
    transport = FakeTransport([_result()])
    with pytest.raises(Exception, match="budget exhausted"):
        await execute_replay_plan(
            _plan(),
            target=_target(),
            owner_kind="scan",
            owner_id="scan-1",
            worker_id="worker-1",
            limits={"http_requests": 2},
            consumed={"http_requests": 2},
            transport=transport,
            clock=Clock(),
        )
    assert transport.calls == []


@pytest.mark.asyncio
async def test_invalid_principal_receipt_context_fails_before_wire_execution():
    transport = FakeTransport([_result()])
    with pytest.raises(ReplayExecutionError, match="receipt profile binding"):
        await execute_replay_plan(
            _plan(), target=_target(), owner_kind="scan", owner_id="scan-1",
            worker_id="worker-1", limits={"http_requests": 10},
            consumed={"http_requests": 0}, transport=transport,
            receipt_context={
                "principal_profile_ref": "",
                "principal_profile_version": 1,
                "principal_slot": "primary",
            },
        )
    assert transport.calls == []


@pytest.mark.asyncio
async def test_state_changing_replay_reserves_and_settles_typed_mutation_budget():
    plan = _plan([_request(method="POST")], active=True)
    outcome = await execute_replay_plan(
        plan,
        target=_target(),
        owner_kind="scan",
        owner_id="scan-1",
        worker_id="worker-1",
        limits={"http_requests": 10, "state_changing_requests": 2},
        consumed={"http_requests": 0, "state_changing_requests": 0},
        transport=FakeTransport([_result(status_code=201)]),
        clock=Clock(),
    )

    assert outcome.receipt.approval_receipt_id == "approval-1"
    assert outcome.receipt.budget_consumed == {
        "http_requests": 1,
        "state_changing_requests": 1,
    }
    assert outcome.ledger_consumed == {
        "http_requests": 1,
        "state_changing_requests": 1,
    }


def test_canonical_action_can_bind_the_public_replay_adapter_identity():
    outcome = asyncio.run(execute_replay_plan(
        _plan(),
        target=_target(),
        owner_kind="scan",
        owner_id="scan-1",
        worker_id="worker-1",
        limits={"http_requests": 10},
        consumed={"http_requests": 0},
        transport=FakeTransport([_result()]),
        receipt_capability_name="collections.replay_safe",
        receipt_adapter_name="collections.replay",
        receipt_adapter_version="1",
        clock=Clock(),
    ))

    assert outcome.receipt.capability_name == "collections.replay_safe"
    assert outcome.receipt.adapter_name == "collections.replay"
    assert outcome.receipt.adapter_version == "1"


def test_replay_receipt_preserves_content_free_source_authority_provenance():
    context = {
        "collection_id": "10000000-0000-4000-8000-000000000001",
        "selection_id": "20000000-0000-4000-8000-000000000002",
        "selection_digest": "a" * 64,
        "collection_payload_digest": "b" * 64,
        "environment_digest": "c" * 64,
        "target_binding_digest": "d" * 64,
        "request_manifest_digest": "e" * 64,
        "principal_binding_digest": "f" * 64,
        "principal_profile_ref": "30000000-0000-4000-8000-000000000003",
        "principal_profile_version": 4,
        "principal_slot": "primary",
    }
    outcome = asyncio.run(execute_replay_plan(
        _plan(),
        target=_target(),
        owner_kind="scan",
        owner_id="scan-1",
        worker_id="worker-1",
        limits={"http_requests": 10},
        consumed={"http_requests": 0},
        transport=FakeTransport([_result()]),
        receipt_context=context,
        clock=Clock(),
    ))

    assert {
        name: outcome.receipt.redacted_execution[name]
        for name in context
    } == context
    rendered = repr(outcome.receipt.public_dict())
    assert "header-secret" not in rendered
    assert "body-secret" not in rendered


def test_executor_requires_bounded_transport_results():
    with pytest.raises(ReplayExecutionError, match="capture limit"):
        ReplayTransportResult(
            status_code=200,
            connected_address="192.0.2.10",
            final_url="https://api.example.test/",
            response_body=b"x" * (2 * 1024 * 1024 + 1),
        )
    with pytest.raises(ReplayExecutionError, match="line breaks"):
        ReplayTransportResult(
            status_code=200,
            connected_address="192.0.2.10",
            final_url="https://api.example.test/",
            response_headers={"X-Test": "ok\r\nInjected: yes"},
        )
