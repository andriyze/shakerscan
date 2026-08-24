"""Content-free V2 runtime metrics derived from canonical durable ledgers."""

from __future__ import annotations

from typing import Any, Mapping


OPERATIONAL_EVENT_KEY = "shakerscan:v2:operational_events"
OPERATIONAL_EVENTS = frozenset({
    "approval_revocation",
    "broker_duplicate_result",
    "continuation_compiled",
    "continuation_rejected",
    "manifest_download_failure",
    "manifest_upload_failure",
    "model_intake_e2e_fail",
    "model_intake_e2e_pass",
    "target_transport_block",
})

_CORE_SQL = r"""
WITH cutover AS (
    SELECT COALESCE(
        (SELECT applied_at FROM app_schema_migrations
          WHERE name='v2_scan_capability_actions_v1'),
        'epoch'::timestamptz
    ) AS applied_at
)
SELECT
    (SELECT COUNT(*) FROM scans
      WHERE scan_generation='v2' AND scan_action_plan_digest IS NOT NULL)
        AS action_plans_compiled,
    (SELECT COUNT(*) FROM scan_action_plan_revisions WHERE revision=1)
        AS continuations_compiled,
    (SELECT COUNT(*) FROM scan_capability_actions
      WHERE status IN ('leased','running')
        AND lease_expires_at IS NOT NULL AND lease_expires_at <= NOW())
        AS stale_action_leases,
    (SELECT COUNT(*) FROM budget_reservations WHERE execution_uncertain=true)
        AS uncertain_execution,
    (SELECT COUNT(*) FROM broker_job_leases
      WHERE status='leased' AND lease_expires_at <= NOW())
        AS stale_broker_leases,
    (SELECT COALESCE(MAX(EXTRACT(EPOCH FROM (NOW()-created_at))), 0)::bigint
       FROM broker_job_leases WHERE status='leased')
        AS oldest_broker_lease_seconds,
    (SELECT COUNT(*) FROM broker_job_leases WHERE delivery_attempts > 1)
        AS broker_redeliveries,
    (SELECT COUNT(*) FROM scan_capability_actions
      WHERE required=true AND status IN ('failed','timed_out','blocked'))
        AS required_action_failures,
    (SELECT COUNT(*) FROM scan_capability_actions
      WHERE required=true
        AND status IN ('success','partial','skipped','blocked','failed','cancelled','timed_out')
        AND result_json IS NULL)
        AS missing_required_results,
    (SELECT COUNT(*) FROM scan_capability_actions
      WHERE reason_code='manifest_unavailable')
        AS manifest_failures,
    (SELECT COUNT(*) FROM scan_artifacts WHERE status IN ('upload_failed','missing'))
        AS artifact_transfer_failures,
    (SELECT COUNT(*) FROM scan_capability_actions
      WHERE reason_code='scope_invalid')
        AS target_transport_blocks,
    (SELECT COUNT(*) FROM scan_capability_actions
      WHERE reason_code='authorization_revoked')
        AS approval_revocations,
    (SELECT COUNT(*) FROM evidence_objects
      WHERE redaction_profile IS NOT NULL AND created_at >= NOW()-INTERVAL '24 hours')
        AS secret_redaction_events_24h,
    (SELECT COUNT(*) FROM scans
      WHERE result #>> '{coverage,grade_reliability,reliable}'='false')
        AS unreliable_grade_count,
    (SELECT COUNT(*) FROM scans s CROSS JOIN cutover c
      WHERE s.run_kind='web_dast' AND s.created_at >= c.applied_at
        AND (
            s.scan_generation <> 'v2'
            OR s.scan_job_digest IS NULL
            OR s.scan_job_payload='{}'::jsonb
        )) AS unexpected_legacy_execution,
    (SELECT COUNT(*) FROM (VALUES
        ('v2_budget_reservations_v2'),
        ('v2_scan_capability_actions_v1'),
        ('v2_scan_action_budget_link_v1'),
        ('v2_scan_action_continuations_v1'),
        ('v2_scan_plan_revision_chain_v1'),
        ('v2_scan_work_manifests_request_candidates_v1')
      ) AS expected(name)
      LEFT JOIN app_schema_migrations m ON m.name=expected.name
      WHERE m.name IS NULL) AS missing_required_migrations
"""

_RESERVATION_STATES_SQL = r"""
SELECT status, COUNT(*) AS count
FROM budget_reservations
GROUP BY status
ORDER BY status
"""

_GRADE_REASONS_SQL = r"""
SELECT reason, COUNT(*) AS count
FROM scans
CROSS JOIN LATERAL jsonb_array_elements_text(
    CASE
        WHEN jsonb_typeof(result #> '{coverage,grade_reliability,reasons}')='array'
        THEN result #> '{coverage,grade_reliability,reasons}'
        ELSE '[]'::jsonb
    END
) AS reason
GROUP BY reason
ORDER BY reason
"""

_ENDPOINT_INVENTORY_SQL = r"""
SELECT
    CASE WHEN COALESCE((s.policy_json->>'active_testing')::boolean, false)
         THEN 'active' ELSE 'passive' END AS authority,
    COUNT(DISTINCT m.scan_id) AS scans,
    COALESCE(SUM(m.entry_count), 0) AS endpoints_observed
FROM scan_work_manifests m
JOIN scans s ON s.id=m.scan_id
WHERE m.kind='endpoint'
GROUP BY authority
ORDER BY authority
"""


def _count(row: Mapping[str, Any], name: str) -> int:
    try:
        return max(0, int(row.get(name) or 0))
    except (TypeError, ValueError):
        return 0


def record_operational_event(redis_client: Any, event: str) -> bool:
    """Increment one allowlisted event counter without storing event payloads."""
    name = str(event or "").strip().lower()
    if name not in OPERATIONAL_EVENTS:
        raise ValueError("unsupported operational event")
    try:
        redis_client.hincrby(OPERATIONAL_EVENT_KEY, name, 1)
        return True
    except Exception:
        return False


def operational_event_snapshot(redis_client: Any) -> dict[str, Any]:
    try:
        raw = redis_client.hgetall(OPERATIONAL_EVENT_KEY) or {}
        decoded = {
            (key.decode("utf-8", "replace") if isinstance(key, bytes) else str(key)):
            int(value.decode("ascii") if isinstance(value, bytes) else value)
            for key, value in raw.items()
        }
        available = True
    except Exception:
        decoded = {}
        available = False
    return {
        "available": available,
        "counters": {
            name: max(0, int(decoded.get(name, 0)))
            for name in sorted(OPERATIONAL_EVENTS)
        },
    }


def _alert(code: str, count: int, *, severity: str = "warning") -> dict[str, Any]:
    return {"code": code, "severity": severity, "count": max(0, int(count))}


async def scan_operational_metrics(
    conn: Any,
    *,
    redis_client: Any = None,
    reconciliation: Mapping[str, Any] | None = None,
    worker_fingerprint_mismatches: int = 0,
    legacy_compatibility_calls: int = 0,
) -> dict[str, Any]:
    """Aggregate V2 ledger health without targets, action IDs, or secret values."""
    core = dict(await conn.fetchrow(_CORE_SQL) or {})
    reservations = {
        str(row.get("status") or "unknown"): _count(row, "count")
        for row in await conn.fetch(_RESERVATION_STATES_SQL)
    }
    grade_reasons = {
        str(row.get("reason") or "unknown"): _count(row, "count")
        for row in await conn.fetch(_GRADE_REASONS_SQL)
    }
    endpoint_rows = {
        str(row.get("authority") or "unknown"): {
            "scans": _count(row, "scans"),
            "endpoints_observed": _count(row, "endpoints_observed"),
        }
        for row in await conn.fetch(_ENDPOINT_INVENTORY_SQL)
    }
    events = operational_event_snapshot(redis_client)
    event_counts = events["counters"]
    reconciliation = dict(reconciliation or {})

    counters = {
        name: _count(core, name)
        for name in (
            "action_plans_compiled",
            "continuations_compiled",
            "stale_action_leases",
            "uncertain_execution",
            "stale_broker_leases",
            "oldest_broker_lease_seconds",
            "broker_redeliveries",
            "required_action_failures",
            "missing_required_results",
            "manifest_failures",
            "artifact_transfer_failures",
            "target_transport_blocks",
            "approval_revocations",
            "secret_redaction_events_24h",
            "unreliable_grade_count",
            "unexpected_legacy_execution",
            "missing_required_migrations",
        )
    }
    counters["continuations_compiled"] = max(
        counters["continuations_compiled"],
        int(event_counts.get("continuation_compiled", 0)),
    )
    counters["continuations_rejected"] = int(
        event_counts.get("continuation_rejected", 0)
    )
    counters["broker_duplicate_results"] = int(
        event_counts.get("broker_duplicate_result", 0)
    )
    counters["manifest_failures"] += int(
        event_counts.get("manifest_upload_failure", 0)
        + event_counts.get("manifest_download_failure", 0)
    )
    counters["target_transport_blocks"] += int(
        event_counts.get("target_transport_block", 0)
    )
    counters["approval_revocations"] += int(
        event_counts.get("approval_revocation", 0)
    )
    counters["legacy_compatibility_calls"] = max(
        0, int(legacy_compatibility_calls),
    )

    alerts: list[dict[str, Any]] = []
    if counters["stale_action_leases"]:
        alerts.append(_alert("stuck_action", counters["stale_action_leases"], severity="error"))
    mismatch = _count(reconciliation, "inconsistent_count")
    if mismatch:
        alerts.append(_alert("reservation_action_mismatch", mismatch, severity="error"))
    if counters["missing_required_results"]:
        alerts.append(_alert("missing_required_result", counters["missing_required_results"], severity="error"))
    if counters["stale_broker_leases"]:
        alerts.append(_alert("stale_broker", counters["stale_broker_leases"], severity="error"))
    if worker_fingerprint_mismatches:
        alerts.append(_alert("branch_release_fingerprint_mismatch", worker_fingerprint_mismatches, severity="error"))
    if counters["missing_required_migrations"]:
        alerts.append(_alert("migration_version_mismatch", counters["missing_required_migrations"], severity="error"))
    if counters["uncertain_execution"] > 1:
        alerts.append(_alert("repeated_uncertain_execution", counters["uncertain_execution"], severity="error"))
    if counters["unexpected_legacy_execution"]:
        alerts.append(_alert("unexpected_legacy_execution", counters["unexpected_legacy_execution"], severity="error"))

    return {
        "schema_version": "scan-operational-metrics/v1",
        "counters": counters,
        "action_reservations_by_state": reservations,
        "action_reservation_reconciliation": reconciliation,
        "grade_reliability_reasons": grade_reasons,
        "endpoint_inventory": {
            "passive": endpoint_rows.get("passive", {"scans": 0, "endpoints_observed": 0}),
            "active": endpoint_rows.get("active", {"scans": 0, "endpoints_observed": 0}),
            "recall_status": "requires_known-target_benchmark_denominator",
        },
        "model_intake_e2e": {
            "passed": int(event_counts.get("model_intake_e2e_pass", 0)),
            "failed": int(event_counts.get("model_intake_e2e_fail", 0)),
        },
        "event_telemetry_available": events["available"],
        "alerts": alerts,
        "content_free": True,
    }


__all__ = [
    "OPERATIONAL_EVENT_KEY",
    "OPERATIONAL_EVENTS",
    "operational_event_snapshot",
    "record_operational_event",
    "scan_operational_metrics",
]
