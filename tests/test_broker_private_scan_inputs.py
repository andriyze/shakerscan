from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from api.scan.private_inputs import (
    BROKER_PRIVATE_SCAN_INPUT_SCHEMA,
    BrokerPrivateScanInputError,
    BrokerPrivateScanInputs,
    private_replay_plan_payload,
    replay_plan_from_private_payload,
)
from scanner.scanner_tools.request_replay import (
    ReplayAuthorization,
    build_replay_plan,
)


def _plan():
    return build_replay_plan(
        [{
            "id": "request-1",
            "method": "POST",
            "url": "https://app.example.test/api/items?token=secret",
            "headers": {"Authorization": "Bearer secret"},
            "body": '{"name":"secret"}',
            "body_mode": "raw",
            "auth_type": "bearer",
            "has_sensitive_material": True,
        }],
        allowed_origins=("https://app.example.test",),
        default_origin="https://app.example.test",
        authorization=ReplayAuthorization(
            active_testing=True,
            allow_state_changing_http=True,
            approval_receipt_id="10000000-0000-4000-8000-000000000001",
        ),
    )


def test_private_replay_plan_round_trip_preserves_exact_digest():
    plan = _plan()
    payload = private_replay_plan_payload(plan)

    restored = replay_plan_from_private_payload(payload)

    assert restored.input_digest == plan.input_digest
    assert restored.requests[0].wire_dict() == plan.requests[0].wire_dict()


def test_private_scan_bundle_is_bound_to_lease_and_exposes_request_map():
    now = datetime(2026, 8, 23, 19, 0, tzinfo=timezone.utc)
    payload = {
        "schema_version": BROKER_PRIVATE_SCAN_INPUT_SCHEMA,
        "lease_id": "lease-1",
        "worker_id": "broker:worker-1",
        "plan_digest": "a" * 64,
        "target_binding_digest": "b" * 64,
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "options": {"auth_header": "Bearer secret"},
        "replay_plans": {"inputs.collection_00": private_replay_plan_payload(_plan())},
    }

    private = BrokerPrivateScanInputs.from_payload(
        payload,
        lease_id="lease-1",
        worker_id="broker:worker-1",
        plan_digest="a" * 64,
        target_binding_digest="b" * 64,
        now=now,
    )

    assert private.options["auth_header"] == "Bearer secret"
    assert private.request_map()["request-1"].body == b'{"name":"secret"}'

    with pytest.raises(BrokerPrivateScanInputError, match="authority"):
        BrokerPrivateScanInputs.from_payload(
            payload,
            lease_id="lease-2",
            worker_id="broker:worker-1",
            plan_digest="a" * 64,
            target_binding_digest="b" * 64,
            now=now,
        )


def test_private_replay_tamper_is_rejected_by_input_digest():
    payload = private_replay_plan_payload(_plan())
    payload["requests"][0]["body_b64"] = "dGFtcGVyZWQ="
    with pytest.raises(BrokerPrivateScanInputError, match="sealed digest"):
        replay_plan_from_private_payload(payload)
