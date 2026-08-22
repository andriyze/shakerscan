from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from runtime.budget_reservations import (
    DurableBudgetReservation,
    ReservationTransitionError,
)
from scanner_tools.request_replay import (
    ReplayAuthorization,
    ReplayPlan,
    build_replay_plan,
)


NOW = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)


def _plan() -> ReplayPlan:
    return build_replay_plan(
        [
            {
                "id": "read-1",
                "method": "GET",
                "url": (
                    "https://api.example.test/reset/"
                    "AbCdEf0123456789AbCdEf0123456789?token=wire-secret-value"
                ),
                "headers": {},
                "body": "",
                "unresolved_variables": [],
                "error": None,
            },
            {
                "id": "write-1",
                "method": "POST",
                "url": "https://api.example.test/orders",
                "headers": {"Content-Type": "application/json"},
                "body": "{\"sku\":\"A-1\"}",
                "unresolved_variables": [],
                "error": None,
            },
        ],
        allowed_origins=["https://api.example.test"],
        authorization=ReplayAuthorization(
            active_testing=True,
            allow_state_changing_http=True,
            approval_receipt_id="approval-1",
        ),
    )


def test_replay_plan_owns_typed_budget_and_secret_free_url_representation():
    plan = _plan()
    assert plan.estimated_budget == {
        "http_requests": 2,
        "state_changing_requests": 1,
    }
    public = repr(plan.public_dict())
    assert "AbCdEf0123456789AbCdEf0123456789" not in public
    assert "wire-secret-value" not in public
    assert "/reset/<redacted>" in public


def test_reserve_against_applies_hold_before_execution():
    requested = DurableBudgetReservation.request(
        owner_kind="hunt",
        owner_id="hunt-1",
        capability_name="collections.replay",
        amounts=_plan().estimated_budget,
        now=NOW,
        reservation_id="reservation-1",
    )
    reserved, ledger = requested.reserve_against(
        limits={"http_requests": 10, "state_changing_requests": 2},
        consumed={"http_requests": 1, "state_changing_requests": 0},
        now=NOW,
        lease_seconds=10,
    )
    assert reserved.status == "reserved"
    assert ledger == {"http_requests": 3, "state_changing_requests": 1}


def test_only_live_owning_worker_can_commit_running_reservation():
    requested = DurableBudgetReservation.request(
        owner_kind="hunt",
        owner_id="hunt-1",
        capability_name="collections.replay",
        amounts={"http_requests": 1},
        now=NOW,
    )
    reserved, _ledger = requested.reserve_against(
        limits={"http_requests": 10},
        consumed={"http_requests": 0},
        now=NOW,
        lease_seconds=10,
    )
    running = reserved.start(
        worker_id="worker-1",
        now=NOW + timedelta(seconds=1),
        lease_seconds=10,
    )

    with pytest.raises(ReservationTransitionError, match="owning worker"):
        running.commit(
            actual={"http_requests": 1},
            execution_receipt_hash="a" * 64,
            now=NOW + timedelta(seconds=2),
            worker_id="worker-2",
        )
    with pytest.raises(ReservationTransitionError, match="expired before commit"):
        running.commit(
            actual={"http_requests": 1},
            execution_receipt_hash="a" * 64,
            now=NOW + timedelta(seconds=12),
            worker_id="worker-1",
        )

    committed = running.commit(
        actual={"http_requests": 1},
        execution_receipt_hash="a" * 64,
        now=NOW + timedelta(seconds=2),
        worker_id="worker-1",
    )
    assert committed.status == "committed"
