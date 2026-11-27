from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from scan.operational_metrics import (  # noqa: E402
    OPERATIONAL_EVENT_KEY,
    operational_event_snapshot,
    record_operational_event,
    scan_operational_metrics,
)


class _Redis:
    def __init__(self):
        self.values = {}

    def hincrby(self, key, field, amount):
        assert key == OPERATIONAL_EVENT_KEY
        self.values[field] = self.values.get(field, 0) + amount

    def hgetall(self, key):
        assert key == OPERATIONAL_EVENT_KEY
        return dict(self.values)


class _Conn:
    async def fetchrow(self, query, *_args):
        assert "unexpected_legacy_execution" in query
        return {
            "action_plans_compiled": 12,
            "continuations_compiled": 3,
            "stale_action_leases": 2,
            "uncertain_execution": 4,
            "stale_broker_leases": 1,
            "oldest_broker_lease_seconds": 91,
            "broker_redeliveries": 2,
            "required_action_failures": 5,
            "missing_required_results": 1,
            "manifest_failures": 1,
            "artifact_transfer_failures": 2,
            "target_transport_blocks": 3,
            "approval_revocations": 1,
            "secret_redaction_events_24h": 8,
            "unreliable_grade_count": 2,
            "unexpected_legacy_execution": 1,
            "missing_required_migrations": 1,
        }

    async def fetch(self, query, *_args):
        if "FROM budget_reservations" in query:
            return [{"status": "reserved", "count": 4}, {"status": "committed", "count": 9}]
        if "jsonb_array_elements_text" in query:
            return [{"reason": "adapter_failed", "count": 2}]
        if "FROM scan_work_manifests" in query:
            return [
                {"authority": "passive", "scans": 3, "endpoints_observed": 40},
                {"authority": "active", "scans": 2, "endpoints_observed": 30},
            ]
        raise AssertionError(query)


def test_operational_metrics_are_content_free_and_raise_required_alerts():
    redis_client = _Redis()
    record_operational_event(redis_client, "continuation_rejected")
    record_operational_event(redis_client, "manifest_download_failure")
    record_operational_event(redis_client, "broker_duplicate_result")
    metrics = asyncio.run(scan_operational_metrics(
        _Conn(),
        redis_client=redis_client,
        reconciliation={"status": "degraded", "inconsistent_count": 2},
        worker_fingerprint_mismatches=3,
    ))

    assert metrics["schema_version"] == "scan-operational-metrics/v1"
    assert metrics["content_free"] is True
    assert metrics["counters"]["action_plans_compiled"] == 12
    assert metrics["counters"]["continuations_rejected"] == 1
    assert metrics["counters"]["manifest_failures"] == 2
    assert metrics["counters"]["broker_duplicate_results"] == 1
    assert metrics["action_reservations_by_state"] == {"reserved": 4, "committed": 9}
    assert metrics["endpoint_inventory"]["passive"]["endpoints_observed"] == 40
    assert metrics["grade_reliability_reasons"] == {"adapter_failed": 2}
    assert {item["code"] for item in metrics["alerts"]} == {
        "stuck_action",
        "reservation_action_mismatch",
        "missing_required_result",
        "stale_broker",
        "branch_release_fingerprint_mismatch",
        "migration_version_mismatch",
        "repeated_uncertain_execution",
        "unexpected_legacy_execution",
    }


def test_operational_event_names_are_allowlisted_and_failure_is_best_effort():
    redis_client = _Redis()
    assert record_operational_event(redis_client, "target_transport_block") is True
    assert operational_event_snapshot(redis_client)["counters"]["target_transport_block"] == 1
    with pytest.raises(ValueError):
        record_operational_event(redis_client, "target=https://secret.example")

    assert record_operational_event(None, "continuation_compiled") is False
    assert operational_event_snapshot(None)["available"] is False
