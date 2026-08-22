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
        "started_at": "2026-08-22T12:00:00+00:00",
        "finished_at": "2026-08-22T12:00:01+00:00",
    }
    values.update(overrides)
    return CapabilityReceipt(**values)


def test_camel_case_secret_keys_are_redacted_natively():
    value = redact_receipt_value({
        "accessToken": "token-secret",
        "clientSecret": "client-secret",
        "safeValue": "visible",
    })
    assert value["accessToken"] == "***"
    assert value["clientSecret"] == "***"
    assert value["safeValue"] == "visible"


def test_artifact_references_are_redacted_before_hashing_or_exposure():
    receipt = _receipt(
        artifact_refs=[
            "https://objects.example.test/evidence?access_token=wire-secret",
            "https://user:pass@example.test/private",
        ],
    )
    public = repr(receipt.public_dict())
    assert "wire-secret" not in public
    assert "user:pass" not in public
    assert "access_token=***" in public


def test_success_requires_committed_reservation_and_terminal_timestamp():
    with pytest.raises(ValueError, match="committed"):
        _receipt(
            budget_reservation_id="reservation-1",
            budget_reservation_state="released",
            budget_reserved={"http_requests": 1},
            budget_consumed={"http_requests": 0},
        )
    with pytest.raises(ValueError, match="cannot report consumed"):
        _receipt(
            status="failed",
            budget_reservation_id="reservation-1",
            budget_reservation_state="released",
            budget_reserved={"http_requests": 1},
            budget_consumed={"http_requests": 1},
        )
    with pytest.raises(ValueError, match="requires finished_at"):
        _receipt(status="failed", finished_at=None)
