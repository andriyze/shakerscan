from __future__ import annotations

import asyncio
import json

from api.scan.finalizer import finalize_scan_report
from tests.test_scan_orchestrator import FakeBackend, _plan, _result
from api.scan.capability_result import CapabilityResultStatus


_FORBIDDEN_REMOTE_KEYS = {
    "database_url",
    "postgres_dsn",
    "redis_url",
    "password",
    "authorization",
    "cookie",
    "private_key",
    "client_secret",
    "api_key",
}


def _keys(value):
    keys = set()
    if isinstance(value, dict):
        for key, item in value.items():
            keys.add(str(key).lower())
            keys.update(_keys(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            keys.update(_keys(item))
    return keys


def test_remote_action_authority_contains_no_datastore_or_target_secret_material():
    plan = _plan()
    backend = FakeBackend(plan, "broker")

    lease = asyncio.run(backend.acquire_action(plan.actions[0]))
    payload = lease.remote_payload()
    encoded = json.dumps(payload, sort_keys=True).lower()

    assert _keys(payload).isdisjoint(_FORBIDDEN_REMOTE_KEYS)
    assert "postgres" not in encoded
    assert "redis://" not in encoded
    assert "secret-canary-value" not in encoded


def test_report_finalization_consumes_only_frozen_receipts_and_observations():
    plan = _plan()
    action_results = {
        action.action_id: _result(
            action, status=CapabilityResultStatus.SUCCESS,
        )
        for action in plan.actions
        if action.action_id != "finalize.report"
    }

    report = finalize_scan_report(
        plan=plan,
        target_url="https://app.example.test",
        action_results=action_results,
        observations={action_id: () for action_id in action_results},
    )

    assert report["scan_metadata"]["finalizer"] == "pure_receipt_projection/v1"
    assert report["coverage"]["status"] == "complete"
