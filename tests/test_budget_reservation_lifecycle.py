from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from runtime.budget_reservations import (
    DurableBudgetReservation,
    ReservationTransitionError,
)


NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
RECEIPT_HASH = "a" * 64


def _requested():
    return DurableBudgetReservation.request(
        owner_kind="hunt",
        owner_id="hunt-1",
        capability_name="web.crawl",
        amounts={"http_requests": 10, "tool_wall_seconds": 20},
        reservation_id="reservation-1",
        now=NOW,
    )


def test_full_lifecycle_reconciles_actual_usage_and_versions_every_transition():
    requested = _requested()
    reserved = requested.reserve(now=NOW, lease_seconds=30)
    running = reserved.start(worker_id="worker-1", now=NOW + timedelta(seconds=1))
    committed = running.commit(
        actual={"http_requests": 4, "tool_wall_seconds": 8},
        execution_receipt_hash=RECEIPT_HASH,
        now=NOW + timedelta(seconds=5),
    )

    assert [requested.status, reserved.status, running.status, committed.status] == [
        "requested", "reserved", "running", "committed"
    ]
    assert [requested.version, reserved.version, running.version, committed.version] == [1, 2, 3, 4]
    assert committed.reconcile_consumed(
        {"http_requests": 10, "tool_wall_seconds": 20}
    ) == {"http_requests": 4, "tool_wall_seconds": 8}
    assert committed.execution_uncertain is False
    assert len(committed.state_digest) == 64


def test_running_reservation_cannot_be_refunded_without_execution_receipt():
    running = _requested().reserve(now=NOW).start(
        worker_id="worker-1", now=NOW + timedelta(seconds=1)
    )
    with pytest.raises(ReservationTransitionError, match="expected"):
        running.release(
            proof_not_started=True,
            reason="operator_requested_refund",
            now=NOW + timedelta(seconds=2),
        )

    failed = running.fail(reason="worker_disappeared", now=NOW + timedelta(seconds=3))
    assert failed.status == "failed"
    assert failed.actual == {"http_requests": 10, "tool_wall_seconds": 20}
    assert failed.execution_uncertain is True
    assert failed.reconcile_consumed(
        {"http_requests": 10, "tool_wall_seconds": 20}
    ) == {"http_requests": 10, "tool_wall_seconds": 20}


def test_stale_reserved_work_is_released_but_stale_running_work_is_conservative():
    reserved = _requested().reserve(now=NOW, lease_seconds=10)
    released = reserved.recover_stale(now=NOW + timedelta(seconds=11))
    assert released.status == "released"
    assert released.actual == {"http_requests": 0, "tool_wall_seconds": 0}
    assert released.reconcile_consumed(
        {"http_requests": 10, "tool_wall_seconds": 20}
    ) == {"http_requests": 0, "tool_wall_seconds": 0}

    running = reserved.start(
        worker_id="worker-1", now=NOW + timedelta(seconds=1), lease_seconds=10
    )
    failed = running.recover_stale(now=NOW + timedelta(seconds=12))
    assert failed.status == "failed"
    assert failed.execution_uncertain is True
    assert failed.actual == {"http_requests": 10, "tool_wall_seconds": 20}


def test_stale_running_work_uses_durable_receipt_when_available():
    running = _requested().reserve(now=NOW, lease_seconds=10).start(
        worker_id="worker-1", now=NOW + timedelta(seconds=1), lease_seconds=10
    )
    recovered = running.recover_stale(
        now=NOW + timedelta(seconds=12),
        actual_from_receipt={"http_requests": 3, "tool_wall_seconds": 7},
        execution_receipt_hash=RECEIPT_HASH,
    )
    assert recovered.status == "failed"
    assert recovered.execution_uncertain is False
    assert recovered.execution_receipt_hash == RECEIPT_HASH
    assert recovered.reconcile_consumed(
        {"http_requests": 10, "tool_wall_seconds": 20}
    ) == {"http_requests": 3, "tool_wall_seconds": 7}


def test_lease_and_worker_ownership_fail_closed():
    reserved = _requested().reserve(now=NOW, lease_seconds=10)
    with pytest.raises(ReservationTransitionError, match="expired"):
        reserved.start(worker_id="worker-1", now=NOW + timedelta(seconds=11))

    running = reserved.start(worker_id="worker-1", now=NOW + timedelta(seconds=1))
    with pytest.raises(ReservationTransitionError, match="owning worker"):
        running.heartbeat(worker_id="worker-2", now=NOW + timedelta(seconds=2))
    with pytest.raises(ReservationTransitionError, match="not stale"):
        running.recover_stale(now=NOW + timedelta(seconds=2))


def test_actual_usage_must_fit_the_original_hold_and_terminal_records_are_immutable():
    running = _requested().reserve(now=NOW).start(
        worker_id="worker-1", now=NOW + timedelta(seconds=1)
    )
    with pytest.raises(ReservationTransitionError, match="exceeds"):
        running.commit(
            actual={"http_requests": 11},
            execution_receipt_hash=RECEIPT_HASH,
            now=NOW + timedelta(seconds=2),
        )

    committed = running.commit(
        actual={"http_requests": 5},
        execution_receipt_hash=RECEIPT_HASH,
        now=NOW + timedelta(seconds=2),
    )
    with pytest.raises(ReservationTransitionError, match="expected"):
        committed.fail(reason="late_failure", now=NOW + timedelta(seconds=3))


def test_serialized_record_is_json_safe_and_contains_no_execution_secrets():
    record = _requested().reserve(now=NOW)
    public = record.canonical_dict()
    assert public["reservation_id"] == "reservation-1"
    assert public["owner_kind"] == "hunt"
    assert public["requested"] == {"http_requests": 10, "tool_wall_seconds": 20}
    assert public["created_at"].endswith("+00:00")
    assert "authorization" not in repr(public).lower()
    assert "cookie" not in repr(public).lower()


def test_requested_action_can_be_cancelled_before_hold_without_mutating_ledger():
    released = _requested().release(
        proof_not_started=True,
        reason="cancelled_before_transactional_hold",
        now=NOW + timedelta(seconds=1),
    )
    assert released.status == "released"
    assert released.hold_applied is False
    current = {"http_requests": 2, "tool_wall_seconds": 3}
    assert released.reconcile_consumed(current) == current


def test_expired_running_lease_cannot_be_revived_by_late_heartbeat():
    running = _requested().reserve(now=NOW, lease_seconds=10).start(
        worker_id="worker-1", now=NOW + timedelta(seconds=1), lease_seconds=10
    )
    with pytest.raises(ReservationTransitionError, match="already expired"):
        running.heartbeat(worker_id="worker-1", now=NOW + timedelta(seconds=12))


def test_failure_reason_is_machine_readable_and_preexecution_usage_is_impossible():
    requested = _requested()
    with pytest.raises(ReservationTransitionError, match="machine-readable"):
        requested.release(
            proof_not_started=True,
            reason="token=do-not-store-this free text",
            now=NOW + timedelta(seconds=1),
        )

    reserved = requested.reserve(now=NOW)
    with pytest.raises(ReservationTransitionError, match="cannot report consumed"):
        reserved.fail(
            reason="preflight_failed",
            actual={"http_requests": 1},
            now=NOW + timedelta(seconds=1),
        )
