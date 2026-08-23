from __future__ import annotations

import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from runtime.receipts import CapabilityReceipt, redact_receipt_value


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


def test_receipt_round_trips_and_rejects_a_tampered_persisted_hash():
    receipt = _receipt(
        budget_reserved={"http_requests": 2},
        budget_consumed={"http_requests": 1},
    )
    assert CapabilityReceipt.from_dict(receipt.public_dict()) == receipt

    tampered = receipt.public_dict()
    tampered["budget_consumed"] = {"http_requests": 2}
    with pytest.raises(ValueError, match="hash"):
        CapabilityReceipt.from_dict(tampered)


def test_receipt_requires_an_owner_and_honest_timeout_state():
    with pytest.raises(ValueError, match="belong to a scan or hunt"):
        _receipt(hunt_id=None)
    linked = _receipt(scan_id="scan-1")
    assert linked.scan_id == "scan-1" and linked.hunt_id == "hunt-1"
    with pytest.raises(ValueError, match="marked partial"):
        _receipt(status="timed_out", timed_out=True)
    with pytest.raises(ValueError, match="successful terminal"):
        _receipt(partial=True)


def test_reservation_state_requires_id_terminal_state_and_reserved_amounts():
    with pytest.raises(ValueError, match="requires budget_reservation_id"):
        _receipt(budget_reservation_state="committed")
    with pytest.raises(ValueError, match="terminal"):
        _receipt(
            budget_reservation_id="reservation-1",
            budget_reservation_state="running",
        )
    with pytest.raises(ValueError, match="requires budget_reserved"):
        _receipt(
            budget_reservation_id="reservation-1",
            budget_reservation_state="committed",
        )


def test_input_digest_and_timestamps_are_validated_and_normalized():
    with pytest.raises(ValueError, match="input_digest"):
        _receipt(input_digest="not-a-digest")
    receipt = _receipt(input_digest="A" * 64, started_at="2026-08-20T12:00:00Z")
    assert receipt.input_digest == "a" * 64
    assert receipt.started_at == "2026-08-20T12:00:00+00:00"
    with pytest.raises(ValueError, match="timezone"):
        _receipt(started_at="2026-08-20T12:00:00")
    with pytest.raises(ValueError, match="earlier"):
        _receipt(finished_at="2026-08-20T11:59:59+00:00")


def test_receipt_redacts_execution_observations_errors_and_url_secrets_before_hashing():
    receipt = _receipt(
        redacted_execution={
            "argv": ["curl", "https://user:pass@example.test/?token=abc&safe=1"],
            "headers": {"Authorization": "Bearer super-secret", "X-Test": "safe"},
            "cookie": "session=secret",
        },
        observations=[{
            "url": "https://example.test/api?api_key=secret-value",
            "password": "do-not-persist",
        }],
        errors=["Authorization: Bearer leaked-token"],
    )
    text = repr(receipt.public_dict())
    assert "super-secret" not in text
    assert "do-not-persist" not in text
    assert "secret-value" not in text
    assert "leaked-token" not in text
    assert "safe" in text
    assert receipt.public_dict()["redacted_execution"]["cookie"] == "***"


def test_budget_usage_must_be_declared_and_fit_the_reservation():
    with pytest.raises(ValueError, match="absent"):
        _receipt(budget_consumed={"http_requests": 1})
    with pytest.raises(ValueError, match="exceeds"):
        _receipt(
            budget_reserved={"http_requests": 1},
            budget_consumed={"http_requests": 2},
        )
    with pytest.raises(ValueError, match="unknown budget"):
        _receipt(budget_reserved={"magic_tokens": 1})


def test_binary_observation_material_is_replaced_by_hash_and_size():
    value = redact_receipt_value({"body": b"binary-secret"})
    assert value["body"]["size"] == len(b"binary-secret")
    assert len(value["body"]["bytes_sha256"]) == 64
    assert "binary-secret" not in repr(value)
