from __future__ import annotations

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
from scanner_tools.request_replay import build_replay_plan


class Clock:
    def __init__(self):
        self.value = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        self.value += timedelta(seconds=1)
        return self.value


class Transport:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    async def send(self, request, *, target, timeout_seconds, follow_redirects):
        self.calls.append((request.request_id, timeout_seconds, follow_redirects))
        return self.results.pop(0)


def _target():
    return TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="api.example.test",
        allowed_origins=("https://api.example.test",),
        allowed_addresses=("192.0.2.10",),
        scope_receipt_id="scope-1",
    )


def _plan(count=2):
    rows = []
    for index in range(count):
        rows.append({
            "id": f"request-{index + 1}",
            "method": "GET",
            "url": f"https://api.example.test/items/{index + 1}",
            "headers": {},
            "body": "",
            "unresolved_variables": [],
            "error": None,
        })
    return build_replay_plan(rows, allowed_origins=["https://api.example.test"])


def _result(final_url="https://api.example.test/items/1"):
    return ReplayTransportResult(
        status_code=200,
        connected_address="192.0.2.10",
        final_url=final_url,
        response_headers={"Content-Type": "application/json"},
        response_body=b"{}",
        elapsed_ms=5,
    )


@pytest.mark.asyncio
async def test_durable_mode_requires_both_persistence_boundaries_before_wire_execution():
    transport = Transport([_result()])
    with pytest.raises(ReplayExecutionError, match="durable replay requires"):
        await execute_replay_plan(
            _plan(1),
            target=_target(),
            owner_kind="scan",
            owner_id="scan-1",
            worker_id="worker-1",
            limits={"http_requests": 10},
            consumed={"http_requests": 0},
            transport=transport,
            require_durable_persistence=True,
        )
    assert transport.calls == []


@pytest.mark.asyncio
async def test_replay_heartbeats_persist_between_requests_and_settles_as_owner():
    secret = "AbCdEf0123456789AbCdEf0123456789"
    transport = Transport([
        _result(f"https://api.example.test/reset/{secret}?token=wire-secret"),
        _result("https://api.example.test/items/2"),
    ])
    transitions = []
    settlements = []

    async def persist(record, ledger):
        transitions.append((record.status, record.version, record.lease_expires_at, dict(ledger)))

    async def settle(record, receipt, ledger):
        settlements.append((record, receipt, dict(ledger)))

    outcome = await execute_replay_plan(
        _plan(2),
        target=_target(),
        owner_kind="hunt",
        owner_id="hunt-1",
        worker_id="worker-1",
        limits={"http_requests": 10},
        consumed={"http_requests": 0},
        transport=transport,
        timeout_seconds=0.1,
        lease_seconds=1,
        clock=Clock(),
        on_reservation=persist,
        on_settlement=settle,
        require_durable_persistence=True,
    )

    assert [(status, version) for status, version, _lease, _ledger in transitions] == [
        ("requested", 1),
        ("reserved", 2),
        ("running", 3),
        ("running", 4),
    ]
    assert transitions[1][2] is not None
    assert transitions[2][2] is not None
    assert transitions[3][2] > transitions[2][2]
    assert outcome.status == "succeeded"
    assert outcome.reservation.status == "committed"
    assert settlements[0][0].worker_id == "worker-1"
    public = repr(outcome.receipt.public_dict())
    assert secret not in public
    assert "wire-secret" not in public
    assert "/reset/<redacted>" in public


@pytest.mark.asyncio
async def test_effective_lease_covers_one_maximum_wire_attempt():
    transitions = []

    async def persist(record, ledger):
        transitions.append(record)

    async def settle(record, receipt, ledger):
        return None

    await execute_replay_plan(
        _plan(1),
        target=_target(),
        owner_kind="scan",
        owner_id="scan-1",
        worker_id="worker-1",
        limits={"http_requests": 10},
        consumed={"http_requests": 0},
        transport=Transport([_result()]),
        timeout_seconds=45,
        lease_seconds=1,
        clock=Clock(),
        on_reservation=persist,
        on_settlement=settle,
        require_durable_persistence=True,
    )

    reserved = transitions[1]
    assert reserved.lease_expires_at is not None
    assert (reserved.lease_expires_at - reserved.updated_at).total_seconds() >= 51
