from __future__ import annotations

import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from runtime.receipts import CapabilityReceipt


def _receipt(**overrides):
    values = {
        "capability_name": "web.crawl",
        "adapter_name": "katana",
        "adapter_version": "1",
        "target_id": "target-1",
        "hunt_id": "hunt-1",
        "status": "succeeded",
        "input_digest": "a" * 64,
        "parser_version": "katana-lines/v1",
        "receipt_id": "receipt-1",
        "started_at": "2026-08-20T12:00:00+00:00",
        "finished_at": "2026-08-20T12:00:02+00:00",
    }
    values.update(overrides)
    return CapabilityReceipt(**values)


def test_receipt_hash_binds_budget_reservation_and_measured_usage():
    receipt = _receipt(
        budget_reservation_id="reservation-1",
        budget_reservation_state="committed",
        budget_reserved={"http_requests": 10},
        budget_consumed={"http_requests": 4},
    )
    public = receipt.public_dict()
    assert public["budget_reservation_id"] == "reservation-1"
    assert public["budget_reservation_state"] == "committed"
    assert public["receipt_hash"] == receipt.receipt_hash
    assert len(receipt.receipt_hash) == 64

    changed = _receipt(
        budget_reservation_id="reservation-1",
        budget_reservation_state="committed",
        budget_reserved={"http_requests": 10},
        budget_consumed={"http_requests": 5},
    )
    assert changed.receipt_hash != receipt.receipt_hash


def test_receipt_requires_an_owner_and_honest_timeout_state():
    with pytest.raises(ValueError, match="belong to a scan or hunt"):
        _receipt(hunt_id=None)
    linked = _receipt(scan_id="scan-1")
    assert linked.scan_id == "scan-1" and linked.hunt_id == "hunt-1"
    with pytest.raises(ValueError, match="marked partial"):
        _receipt(status="timed_out", timed_out=True)


def test_reservation_state_requires_id_and_must_be_terminal():
    with pytest.raises(ValueError, match="requires budget_reservation_id"):
        _receipt(budget_reservation_state="committed")
    with pytest.raises(ValueError, match="terminal"):
        _receipt(
            budget_reservation_id="reservation-1",
            budget_reservation_state="running",
        )


def test_input_digest_is_validated_and_normalized():
    with pytest.raises(ValueError, match="input_digest"):
        _receipt(input_digest="not-a-digest")
    receipt = _receipt(input_digest="A" * 64)
    assert receipt.input_digest == "a" * 64
