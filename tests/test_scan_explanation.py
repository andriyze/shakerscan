from __future__ import annotations

import json

from api.scan.explanation import (
    action_list_response,
    build_scan_execution_explanation,
    capability_list_response,
    coverage_response,
)


SCAN_ID = "11111111-1111-4111-8111-111111111111"


def _plan():
    common = {
        "placement": {
            "eligible_backends": ["local", "broker"],
            "private_environment_ref": "/private/never-public.json",
        },
        "supporting": False,
        "dependencies": [],
        "requested_budget": {"http_requests": 4, "tool_wall_seconds": 10},
    }
    return {
        "schema_version": "scan-action-plan/v1",
        "scan_id": SCAN_ID,
        "plan_digest": "a" * 64,
        "execution_plan_digest": "b" * 64,
        "target_binding_digest": "c" * 64,
        "actions": [
            {
                **common,
                "action_id": "baseline.http",
                "action_digest": "d" * 64,
                "stage": "deterministic_baseline",
                "ordinal": 0,
                "capability_name": "http.request",
                "output_schema": "http-observation/v1",
                "required": True,
                "admission_status": "planned",
                "capability_args": {
                    "authorization": "must-never-be-public",
                    "path": "/private",
                },
            },
            {
                **common,
                "action_id": "verify.xss.0",
                "action_digest": "e" * 64,
                "stage": "active_verification",
                "ordinal": 1,
                "capability_name": "xss.verify",
                "required": False,
                "admission_status": "skipped",
                "reason_code": "insufficient_plan_budget",
                "capability_args": {"candidate_index": 0},
            },
            {
                **common,
                "action_id": "finalize.report",
                "action_digest": "f" * 64,
                "stage": "finalize_evidence",
                "ordinal": 2,
                "capability_name": "scan.finalize",
                "required": True,
                "admission_status": "planned",
                "capability_args": {"report_only": True},
            },
        ],
    }


def _rows():
    return [
        {
            "action_id": "baseline.http",
            "ordinal": 0,
            "status": "partial",
            "reason_code": "output_truncated",
            "backend_name": "broker",
            "worker_id": "broker:worker-1",
            "attempt": 1,
            "requested_budget": {"http_requests": 4, "tool_wall_seconds": 10},
            "result_json": {
                "budget_reserved": {"http_requests": 4, "tool_wall_seconds": 10},
                "budget_consumed": {"http_requests": 2, "tool_wall_seconds": 4},
                "observation_manifest_ref": {
                    "manifest_id": "22222222-2222-4222-8222-222222222222",
                    "count": 1,
                    "size_bytes": 120,
                    "sha256": "1" * 64,
                    "manifest_digest": "2" * 64,
                },
            },
            "receipt_json": {
                "receipt_id": "33333333-3333-4333-8333-333333333333",
                "receipt_hash": "3" * 64,
                "parser_version": "http-observation/v1",
                "redacted_execution": {
                    "authorization": "still-never-public",
                    "provenance": {
                        "source_revision": "revision-1",
                        "binary_path": "/opt/tools/httpx",
                    },
                },
            },
        },
        {
            "action_id": "verify.xss.0",
            "ordinal": 1,
            "status": "skipped",
            "reason_code": "insufficient_plan_budget",
        },
        {
            "action_id": "finalize.report",
            "ordinal": 2,
            "status": "planned",
        },
    ]


def test_execution_explanation_is_content_safe_and_explicit():
    explanation = build_scan_execution_explanation(
        scan_id=SCAN_ID,
        scan_status="running",
        plan_payload=_plan(),
        action_rows=_rows(),
        plan_budget_limits={
            "max_http_requests": 20,
            "max_tool_wall_seconds": 60,
        },
    )

    assert explanation["schema_version"] == "scan-execution-explanation/v1"
    assert [stage["status"] for stage in explanation["stage_timeline"]] == [
        "partial", "complete_with_gaps", "pending",
    ]
    action = explanation["actions"][0]
    assert action["placement"] == {
        "eligible_backends": ["local", "broker"],
        "backend": "broker",
        "worker_id": "broker:worker-1",
        "attempt": 1,
    }
    assert action["budget"]["consumed"]["http_requests"] == 2
    assert action["budget"]["allocated"]["http_requests"] == 4
    assert action["budget"]["released"] == {
        "http_requests": 2,
        "tool_wall_seconds": 6,
    }
    assert explanation["budget"] == {
        "limit": {"http_requests": 20, "tool_wall_seconds": 60},
        "allocated": {"http_requests": 12, "tool_wall_seconds": 30},
        "reserved": {"http_requests": 4, "tool_wall_seconds": 10},
        "consumed": {"http_requests": 2, "tool_wall_seconds": 4},
        "released": {"http_requests": 2, "tool_wall_seconds": 6},
        "uncertain": {},
        "unallocated": {"http_requests": 8, "tool_wall_seconds": 30},
    }
    assert action["output_schema"] == "http-observation/v1"
    assert action["observation"]["count"] == 1
    assert action["receipt"]["provenance"]["source_revision"] == "revision-1"
    serialized = json.dumps(explanation)
    assert "must-never-be-public" not in serialized
    assert "still-never-public" not in serialized
    assert "/private/never-public.json" not in serialized
    assert '"capability_args"' not in serialized


def test_execution_explanation_reports_uncertain_reservation_separately():
    rows = _rows()
    rows[0].update({
        "result_json": {},
        "reservation_status": "failed",
        "reservation_hold_applied": True,
        "reservation_requested": {"http_requests": 4, "tool_wall_seconds": 10},
        "reservation_actual": {"http_requests": 1, "tool_wall_seconds": 2},
        "execution_uncertain": True,
    })

    explanation = build_scan_execution_explanation(
        scan_id=SCAN_ID,
        scan_status="failed",
        plan_payload=_plan(),
        action_rows=rows,
    )

    assert explanation["actions"][0]["budget"]["uncertain"] == {
        "http_requests": 4,
        "tool_wall_seconds": 10,
    }
    assert explanation["actions"][0]["budget"]["released"] == {}
    assert explanation["budget"]["uncertain"] == {
        "http_requests": 4,
        "tool_wall_seconds": 10,
    }


def test_execution_explanation_marks_required_partial_grade_unreliable():
    explanation = build_scan_execution_explanation(
        scan_id=SCAN_ID,
        scan_status="completed",
        plan_payload=_plan(),
        action_rows=_rows(),
    )

    coverage = explanation["coverage"]
    assert coverage["status"] == "partial"
    assert coverage["grade_reliability"] == {
        "reliable": False,
        "reasons": ["output_truncated"],
        "reason_labels": ["The bounded output limit was reached"],
        "warning": "The grade is provisional because required coverage did not complete cleanly.",
    }
    assert coverage["capability_coverage"]["required"] == 1
    assert coverage["capability_coverage"]["partial"] == 1
    assert coverage["optional_gaps"][0]["action_id"] == "verify.xss.0"
    assert explanation["transport_parity"]["broker_eligible"] is True


def test_execution_explanation_preserves_final_report_grade_reliability():
    rows = _rows()
    rows[0]["status"] = "success"
    rows[0]["reason_code"] = None
    explanation = build_scan_execution_explanation(
        scan_id=SCAN_ID,
        scan_status="completed",
        plan_payload=_plan(),
        action_rows=rows,
        report={
            "coverage": {
                "status": "complete",
                "grade_reliability": {
                    "reliable": False,
                    "reasons": ["unproven_critical_high"],
                },
            },
        },
    )

    assert explanation["coverage"]["grade_reliability"] == {
        "reliable": False,
        "reasons": ["unproven_critical_high"],
        "reason_labels": [
            "High or critical candidates still require deterministic proof",
        ],
        "warning": (
            "The grade is provisional until the listed verification conditions are resolved."
        ),
    }


def test_execution_explanation_fails_closed_for_reasonless_unreliable_report():
    rows = _rows()
    rows[0]["status"] = "success"
    rows[0]["reason_code"] = None
    explanation = build_scan_execution_explanation(
        scan_id=SCAN_ID,
        scan_status="completed",
        plan_payload=_plan(),
        action_rows=rows,
        report={
            "coverage": {
                "status": "complete",
                "grade_reliability": {"reliable": False, "reasons": []},
            },
        },
    )

    assert explanation["coverage"]["grade_reliability"]["reliable"] is False
    assert explanation["coverage"]["grade_reliability"]["reasons"] == [
        "report_grade_unreliable",
    ]


def test_public_endpoint_projections_have_stable_schemas():
    explanation = build_scan_execution_explanation(
        scan_id=SCAN_ID,
        scan_status="completed",
        plan_payload=_plan(),
        action_rows=_rows(),
    )

    assert action_list_response(explanation)["schema_version"] == "scan-action-list/v1"
    assert capability_list_response(explanation)["schema_version"] == "scan-capability-coverage/v1"
    assert coverage_response(explanation)["schema_version"] == "scan-coverage-explanation/v1"
    assert capability_list_response(explanation)["capabilities"][0]["capability_name"] == "http.request"


def test_parallel_parent_explanation_uses_verified_child_merge():
    plan = _plan()
    plan["actions"].insert(-1, {
        "action_id": "inputs.collection_00",
        "action_digest": "9" * 64,
        "stage": "discover_surface",
        "ordinal": 2,
        "capability_name": "collections.replay_safe",
        "output_schema": "request-collection-replay/v2",
        "required": True,
        "supporting": True,
        "dependencies": [],
        "requested_budget": {"http_requests": 4, "tool_wall_seconds": 60},
        "placement": {"eligible_backends": ["local", "broker"]},
        "admission_status": "planned",
    })
    report = {
        "canonical_action_execution": {
            "plan_digest": "child-backbone",
            "actions": [],
            "finalization_action": {
                "action_id": "finalize.report",
                "status": "success",
            },
        },
        "coverage": {
            "status": "complete",
            "grade_reliability": {"reliable": True, "reasons": []},
        },
        "parallel": {
            "canonical_action_execution": {
                "partial": True,
                "actions": [
                    {
                        "action_id": "baseline.http",
                        "stage": "deterministic_baseline",
                        "capability_name": "http.request",
                        "required": True,
                        "status": "success",
                        "reason_code": None,
                        "budget_reserved": {"http_requests": 4},
                        "budget_consumed": {"http_requests": 2},
                    },
                    {
                        "action_id": "verify.xss.0",
                        "stage": "active_verification",
                        "capability_name": "xss.verify",
                        "required": False,
                        "status": "skipped",
                        "reason_code": "insufficient_plan_budget",
                    },
                    {
                        "action_id": "inputs.collection_00",
                        "stage": "discover_surface",
                        "capability_name": "collections.replay_safe",
                        "required": True,
                        "status": "failed",
                        "reason_code": "adapter_failed",
                        "budget_reserved": {"http_requests": 4},
                        "budget_consumed": {"http_requests": 4},
                    },
                ],
            },
        },
    }

    explanation = build_scan_execution_explanation(
        scan_id=SCAN_ID,
        scan_status="completed",
        plan_payload=plan,
        action_rows=[],
        report=report,
    )

    matrix = explanation["coverage"]["capability_coverage"]
    assert matrix["total"] == 3
    assert matrix["completed"] == 1
    assert matrix["failed"] == 1
    assert matrix["skipped"] == 1
    assert matrix["pending"] == 0
    collection = next(
        item for item in explanation["actions"]
        if item["action_id"] == "inputs.collection_00"
    )
    assert collection["status"] == "failed"
    assert collection["reason_code"] == "adapter_failed"
    assert explanation["coverage"]["grade_reliability"] == {
        "reliable": False,
        "reasons": ["adapter_failed", "parallel_child_incomplete"],
        "reason_labels": [
            "The capability adapter failed",
            "At least one parallel shard completed with partial coverage",
        ],
        "warning": "The grade is provisional because required coverage did not complete cleanly.",
    }
