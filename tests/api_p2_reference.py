"""The 2.11.0 milestone-2 SQL these reads replaced, kept verbatim as the oracle for equality tests.

tests/test_api_p2_scale_postgres.py runs each against the same fixture as its replacement and
asserts the same answer. Nothing in the product uses this module.
"""
# ruff: noqa: E501
from __future__ import annotations

# scan/operational_metrics.py
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

# scan/action_budget_reconciliation.py
_RECONCILIATION_SQL = r"""
WITH cutover AS (
    SELECT COALESCE(
        (SELECT applied_at FROM app_schema_migrations
          WHERE name='v2_scan_action_budget_link_v1'),
        'epoch'::timestamptz
    ) AS applied_at
)
SELECT
    (
        SELECT COUNT(*)
          FROM scan_capability_actions a
         CROSS JOIN cutover c
         WHERE a.receipt_json->>'budget_reservation_id' IS NOT NULL
           AND a.reservation_id IS NULL
           AND a.updated_at >= c.applied_at
    ) AS receipt_link_missing,
    (
        SELECT COUNT(*)
          FROM scan_capability_actions a
          JOIN budget_reservations r ON r.id=a.reservation_id
         CROSS JOIN cutover c
         WHERE a.updated_at >= c.applied_at
           AND (r.owner_kind <> 'scan'
            OR r.owner_id <> a.scan_id::text
            OR r.action_id <> a.action_id
            OR r.action_digest <> a.action_digest
            OR r.capability_name <> a.capability_name
            OR (
                a.status IN ('success','partial','failed','timed_out')
                AND (
                    r.status NOT IN ('committed','released','failed')
                    OR r.execution_receipt_hash IS DISTINCT FROM a.receipt_hash
                )
            ))
    ) AS linked_authority_mismatch,
    (
        SELECT COUNT(*)
          FROM scan_capability_actions a
          JOIN budget_reservations r ON r.id=a.reservation_id
         CROSS JOIN cutover c
         WHERE a.updated_at < c.applied_at
           AND (r.owner_kind <> 'scan'
            OR r.owner_id <> a.scan_id::text
            OR r.action_id <> a.action_id
            OR r.action_digest <> a.action_digest
            OR r.capability_name <> a.capability_name
            OR (
                a.status IN ('success','partial','failed','timed_out')
                AND (
                    r.status NOT IN ('committed','released','failed')
                    OR r.execution_receipt_hash IS DISTINCT FROM a.receipt_hash
                )
            ))
    ) AS legacy_historical_mismatch,
    (
        SELECT COUNT(*)
          FROM scan_capability_actions a
         WHERE a.status IN ('leased','running')
           AND a.reservation_id IS NULL
           AND a.capability_name <> 'scan.execute'
           AND a.updated_at < now() - INTERVAL '30 seconds'
    ) AS stale_execution_without_hold,
    (
        SELECT COUNT(*)
          FROM budget_reservations r
          JOIN scan_capability_actions a
            ON r.owner_kind='scan'
           AND r.owner_id=a.scan_id::text
           AND r.action_id=a.action_id
           AND r.action_digest=a.action_digest
         WHERE r.status IN ('committed','released','failed')
           AND a.status NOT IN (
               'success','partial','skipped','blocked','failed','cancelled','timed_out'
           )
           AND r.updated_at < now() - INTERVAL '5 minutes'
    ) AS stale_terminal_reservation_without_action,
    (
        SELECT COUNT(*)
          FROM scan_capability_actions a
         WHERE a.reservation_id IS NOT NULL
    ) AS linked_action_count
"""

# scan list (scan/assessment.py)
SCAN_LIST_ASSESSMENT_COLUMNS = """
    s.result->'result'->>'risk_assessment_state' AS risk_assessment_state,
    s.result->'result'->'application_observed' AS application_observed
"""

# exposure/service_store.py (ORDER BY kind,id LIMIT $5 OFFSET $6 was appended)
TARGETS_SQL = """
WITH inventory_targets AS (
 SELECT id, 'web'::text AS kind, COALESCE(name,url) AS label, url AS locator,
        root_domain, NULL::integer AS locator_generation, NULL::timestamptz AS locator_changed_at
 FROM targets WHERE is_active=true AND COALESCE(discovery_source,'') <> 'model-intake'
 UNION ALL
 SELECT d.id, 'device', d.name, d.primary_locator, NULL::text, d.locator_generation,
        COALESCE((SELECT max(changed_at) FROM device_locator_history h WHERE h.device_target_id=d.id), d.created_at)
 FROM device_targets d WHERE d.is_active=true
)
SELECT * FROM inventory_targets
WHERE ($1::text='all' OR kind=$1) AND ($2::uuid IS NULL OR id=$2)
 AND ($3::text IS NULL OR lower(root_domain)=$3 OR
      (kind='device' AND (lower(locator)=$3 OR right(lower(locator),length($3)+1)='.'||$3)))
 AND ($4::text='' OR strpos(lower(label),$4)>0 OR strpos(lower(locator),$4)>0)
"""

# devices/router.py list_devices (f-string: {where}, params, then $n+1 limit, $n+2 offset)
DEVICES_SQL = """SELECT d.*, p.name AS policy_name,
                       (SELECT COUNT(*) FROM device_services ds WHERE ds.device_target_id=d.id AND ds.state='open') AS services_count,
                       (SELECT (s.result->'device_posture'->'completeness'->>'complete')::boolean
                          FROM scans s WHERE s.id=d.last_scan_id) AS last_posture_complete,
                       (SELECT s.result->'device_posture'->'decision'->>'decision'
                          FROM scans s WHERE s.id=d.last_scan_id) AS last_posture_decision,
                       (SELECT (s.result->'device_posture'->'reachability')
                                   - 'attempts' - 'nmap_host_discovery'
                          FROM scans s WHERE s.id=d.last_scan_id) AS last_reachability
                FROM device_targets d LEFT JOIN device_policies p ON p.id=d.policy_id
                WHERE {where} ORDER BY d.updated_at DESC LIMIT ${len(params)+1} OFFSET ${len(params)+2}"""

# investigation_routes/router.py
CANDIDATES_SQL = """SELECT c.*, COUNT(*) OVER() AS total_count,
                      (SELECT COUNT(*) FROM investigation_candidate_observations o
                       WHERE o.candidate_id=c.id) AS observation_count
               FROM investigation_candidates c
               WHERE ($1::text IS NULL OR c.plane=$1)
                 AND ($2::uuid IS NULL OR c.target_id=$2)
                 AND ($3::uuid IS NULL OR c.device_target_id=$3)
                 AND ($4::text IS NULL OR c.status=$4)
               ORDER BY c.last_seen_at DESC, c.id DESC
               LIMIT $5 OFFSET $6"""

# runtime/credential_store.py list_library
LIBRARY_SQL = """SELECT p.*, hb.allowed_capabilities,
                      (SELECT count(*) FROM credential_profile_bindings g
                        WHERE g.profile_id=p.id AND g.binding_kind='target'
                          AND g.binding_id<>p.target_id::text AND g.revoked_at IS NULL)
                        AS shared_target_count,
                      COUNT(*) OVER() AS total_count
               FROM credential_profiles p
               LEFT JOIN credential_profile_bindings hb
                 ON hb.profile_id=p.id AND hb.binding_kind='target'
                AND hb.binding_id=p.target_id::text
               WHERE ($1::boolean OR p.is_active=true)
                 AND ($2::text IS NULL OR p.name ILIKE $2 OR COALESCE(p.principal_label,'') ILIKE $2)
               ORDER BY p.is_active DESC, lower(p.name), p.id
               LIMIT $3 OFFSET $4"""

# ai_targets/router.py get_ai_inventory
AI_SCANS_SQL = """
            SELECT
                s.id, s.target_id, s.ai_target_id, s.target_url, s.status,
                s.scan_type, s.run_kind, s.options, s.result, s.created_at, s.completed_at,
                t.root_domain, t.discovery_source
            FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            LEFT JOIN ai_targets ait ON s.ai_target_id = ait.id
            WHERE s.result IS NOT NULL
              AND (s.scan_role IS NULL OR s.scan_role <> 'shard')
              AND (
                $1::text IS NULL
                OR t.root_domain = $1::text
                OR LOWER(ait.endpoint_url) LIKE '%' || LOWER($1::text) || '%'
              )
            ORDER BY s.created_at DESC
            LIMIT $2
        """

# api.py get_scan, parallel children
SHARD_ROWS_SQL = """
                SELECT id, scan_role, shard_index, status, score, grade,
                       findings_count, current_phase, progress, duration_seconds,
                       executing_node_id, worker_id, execution_context,
                       result, options
                FROM scans
                WHERE parent_scan_id = $1
                ORDER BY shard_index
        """

# evidence_routes/router.py list_evidence_instances
EVIDENCE_SQL = """
            SELECT *
            FROM evidence_instances
            WHERE ($2::uuid IS NULL OR finding_id = $2)
              AND ($3::uuid IS NULL OR tool_receipt_id = $3)
            ORDER BY created_at DESC
            LIMIT $1
            """
