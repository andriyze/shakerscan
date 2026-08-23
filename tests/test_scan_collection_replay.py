from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from api.runtime.request_collection_store import RequestCollectionSelection
from api.runtime.json_fields import json_array_field, json_object_field
from api.runtime.models import TargetBinding
from api.runtime.request_replay_executor import (
    ReplayTransportResult,
    execute_replay_plan,
)
from api.scan.collection_replay import (
    ScanCollectionReplayContractError,
    merge_scan_budget_usage,
    remaining_scan_replay_capacity,
    scan_replay_authorization,
    scan_replay_ledger_limits,
    scan_replay_runtime_http_ceiling,
    scan_replay_selector,
)
from scanner.scanner_tools.request_collections import validate_and_index
from scanner.scanner_tools.request_replay import build_selected_replay_plan


def _budget() -> dict[str, int]:
    return {
        "max_duration_seconds": 1_200,
        "max_http_requests": 100,
        "max_endpoints": 50,
        "max_browser_actions": 20,
        "max_tcp_ports": 10,
        "max_tool_wall_seconds": 60,
        "max_workers": 2,
    }


def test_database_json_fields_decode_serialized_arrays_and_objects():
    assert json_array_field('["https://api.example.test"]') == [
        "https://api.example.test"
    ]
    assert json_array_field(b'["192.0.2.10"]') == ["192.0.2.10"]
    assert json_object_field('{"safe_methods_only":true}') == {
        "safe_methods_only": True
    }
    assert json_array_field('{"not":"an-array"}') == []
    assert json_object_field('["not-an-object"]') == {}


def test_safe_scan_forces_read_only_even_if_stored_selector_is_tampered():
    selection = RequestCollectionSelection(
        methods=("GET", "POST"), safe_methods_only=False, max_requests=20,
    )
    selector = scan_replay_selector(
        selection, "safe_reads", runtime_limit=10,
    )

    assert selector.safe_methods_only is True
    assert selector.limit == 10
    assert selector.methods == ("GET", "POST")
    assert scan_replay_authorization("safe_reads", {
        "active_testing": True,
        "allow_state_changing_http": True,
        "approval_receipt_id": "must-not-be-inherited",
    }).public_dict() == {
        "active_testing": False,
        "allow_state_changing_http": False,
        "approval_bound": False,
    }


@pytest.mark.parametrize(
    ("policy", "approval", "message"),
    [
        ({"allow_state_changing_http": True}, "approval-1", "active_testing"),
        ({"active_testing": True}, "approval-1", "state-changing HTTP"),
        (
            {"active_testing": True, "allow_state_changing_http": True},
            None,
            "target-bound approval",
        ),
    ],
)
def test_confirmed_active_requires_all_independent_authority_signals(
    policy, approval, message,
):
    with pytest.raises(ScanCollectionReplayContractError, match=message):
        scan_replay_authorization(
            "confirmed_active", policy, approval_receipt_id=approval,
        )


def test_confirmed_active_scan_preserves_exact_post_body_and_content_type():
    document = {
        "info": {"name": "Exact active replay", "schema": "v2.1"},
        "item": [{
            "name": "Create order",
            "request": {
                "method": "POST",
                "url": "https://api.example.test/orders?tenant=one",
                "header": [
                    {"key": "Content-Type", "value": "application/json"},
                    {"key": "Authorization", "value": "Bearer worker-only"},
                ],
                "body": {"mode": "raw", "raw": '{"sku":"A-1","count":2}'},
            },
        }],
    }
    payload, _summary, rows = validate_and_index(document)
    selection = RequestCollectionSelection(
        request_ids=(rows[0]["request_id"],),
        safe_methods_only=False,
        max_requests=1,
    )
    selector = scan_replay_selector(
        selection, "confirmed_active", runtime_limit=1,
    )
    authorization = scan_replay_authorization(
        "confirmed_active",
        {"active_testing": True, "allow_state_changing_http": True},
        approval_receipt_id="approval-1",
    )
    plan = build_selected_replay_plan(
        payload,
        selector,
        allowed_origins=["https://api.example.test"],
        default_origin="https://api.example.test",
        authorization=authorization,
    )

    wire = plan.wire_requests()[0]
    assert wire["method"] == "POST"
    assert wire["url"] == "https://api.example.test/orders?tenant=one"
    assert wire["headers"]["Content-Type"] == "application/json"
    assert wire["body"] == b'{"sku":"A-1","count":2}'
    assert "worker-only" not in repr(plan.public_dict())


def test_shared_executor_reserves_and_settles_exact_scan_replay():
    class Transport:
        def __init__(self):
            self.wire = None

        async def send(
            self, request, *, target, timeout_seconds, follow_redirects,
        ):
            self.wire = request.wire_dict()
            return ReplayTransportResult(
                status_code=201,
                connected_address=target.allowed_addresses[0],
                final_url=request.url,
                response_headers={"Content-Type": "application/json"},
                response_body=b'{"id":1}',
                elapsed_ms=2,
            )

    async def drive():
        document = {
            "info": {"name": "Scan replay", "schema": "v2.1"},
            "item": [{
                "name": "Create",
                "request": {
                    "method": "POST",
                    "url": "https://api.example.test/items",
                    "header": [{
                        "key": "Content-Type", "value": "application/json",
                    }],
                    "body": {"mode": "raw", "raw": '{"name":"exact"}'},
                },
            }],
        }
        payload, _summary, rows = validate_and_index(document)
        selection = RequestCollectionSelection(
            request_ids=(rows[0]["request_id"],),
            safe_methods_only=False,
            max_requests=1,
        )
        plan = build_selected_replay_plan(
            payload,
            scan_replay_selector(
                selection, "confirmed_active", runtime_limit=1,
            ),
            allowed_origins=["https://api.example.test"],
            authorization=scan_replay_authorization(
                "confirmed_active",
                {"active_testing": True, "allow_state_changing_http": True},
                approval_receipt_id="approval-1",
            ),
        )
        transitions = []
        settlements = []

        async def persist_transition(record, ledger):
            transitions.append((record.status, dict(ledger)))

        async def persist_settlement(record, receipt, ledger):
            settlements.append((record, receipt, dict(ledger)))

        transport = Transport()
        outcome = await execute_replay_plan(
            plan,
            target=TargetBinding(
                target_id="target-1",
                target_kind="api",
                canonical_host="api.example.test",
                allowed_origins=("https://api.example.test",),
                allowed_addresses=("192.0.2.10",),
            ),
            owner_kind="scan",
            owner_id="scan-1",
            worker_id="worker-1",
            limits={
                "http_requests": 10,
                "state_changing_requests": 10,
                "tool_wall_seconds": 60,
            },
            consumed={
                "http_requests": 0,
                "state_changing_requests": 0,
                "tool_wall_seconds": 0,
            },
            transport=transport,
            additional_budget={"tool_wall_seconds": 10},
            on_reservation=persist_transition,
            on_settlement=persist_settlement,
            require_durable_persistence=True,
        )
        return outcome, transitions, settlements, transport.wire

    outcome, transitions, settlements, wire = asyncio.run(drive())

    assert [item[0] for item in transitions] == ["requested", "reserved", "running"]
    assert outcome.reservation.status == "committed"
    assert outcome.reservation.actual["http_requests"] == 1
    assert outcome.reservation.actual["state_changing_requests"] == 1
    assert settlements[0][1].scan_id == "scan-1"
    assert wire["body"] == b'{"name":"exact"}'


def test_scan_capacity_reserves_a_minimal_baseline_and_honors_runtime_grant():
    limits = scan_replay_ledger_limits(_budget())
    capacity = remaining_scan_replay_capacity(
        limits=limits,
        consumed={"http_requests": 10, "tool_wall_seconds": 4},
        runtime_http_ceiling=25,
    )

    assert capacity.http_requests == 14
    assert capacity.tool_wall_seconds == 55
    assert limits["state_changing_requests"] == limits["http_requests"] == 100


def test_scan_replay_does_not_treat_compatibility_active_grant_as_http_budget():
    options = {
        "custom_budget": {"request_max": 10},
        "request_budget_mode": "compatibility",
        "request_budget_reserved": 1,
        "domain_rate_active_endpoint_grant": 1,
    }
    assert scan_replay_runtime_http_ceiling(options, _budget()) == 10

    options["request_budget_mode"] = "enforce"
    assert scan_replay_runtime_http_ceiling(options, _budget()) == 1


def test_final_scan_budget_usage_keeps_durable_replay_settlement():
    assert merge_scan_budget_usage(
        {"http_requests": 3, "tool_wall_seconds": 1},
        {"http_requests": 7, "browser_actions": 2},
    ) == {
        "http_requests": 10,
        "tool_wall_seconds": 1,
        "browser_actions": 2,
    }


def test_scan_worker_routes_collections_through_shared_durable_executor():
    root = Path(__file__).resolve().parents[1]
    worker = (root / "api" / "worker.py").read_text()
    start = worker.index("async def _execute_scan_request_collections")
    end = worker.index("\n\ndef _apply_scan_collection_replay_remaining_budget", start)
    handler = worker[start:end]
    process_start = worker.index("async def process_scan_job")
    process_end = worker.index("\n\nasync def process_scan_plan_job", process_start)
    process = worker[process_start:process_end]

    assert 'FROM scans s JOIN targets t' in handler
    assert 'persisted_options.get("request_collections")' in handler
    assert "runtime_budget_options = dict(persisted_options)" in handler
    assert 'runtime_budget_options["request_budget_reserved"]' in handler
    assert "request_collection_selection_digest" in handler
    assert "decrypt_secret" in handler
    assert "build_selected_replay_plan" in handler
    assert 'owner_kind="scan"' in handler
    assert "PostgresBudgetReservationStore" in handler
    assert "create_requested" in handler
    assert "persist_transition" in handler
    assert "persist_terminal" in handler
    assert "ReplayExecutionAdapter(" in handler
    assert "CapabilityExecutor().execute(" in handler
    assert '"collections.replay_active"' in handler
    assert 'replay_policy == "confirmed_active"' in handler
    assert "adapter_managed_cancellation=True" in handler
    assert "cancelled=lambda: _scan_cancel_requested(scan_id)" in handler
    assert 'summary["cancelled"] = True' in handler
    assert "Pinn" in handler and "ReplayTransport" in handler
    assert '"require_durable_persistence": True' in handler
    assert process.index("_execute_scan_request_collections") < process.index(
        "_hydrate_generic_scan_credentials"
    ) < process.index("run_scan(")
    assert 'raise ValueError("Cancelled by user")' in process


def test_scan_api_requires_single_owner_and_freezes_replay_binding():
    source = (Path(__file__).resolve().parents[1] / "api" / "api.py").read_text()
    submit_start = source.index('async def submit_scan')
    submit_end = source.index('\n\n@app.get("/scans/{scan_id}")', submit_start)
    submit = source[submit_start:submit_end]

    assert "confirmed_active_collection_replay" in submit
    assert "always_require_receipt=bool(" in submit
    assert "_freeze_scan_collection_target_binding" in submit
    assert "request_collection_exact_replay_requires_single_scan_owner" in submit
    assert 'options_payload["shards"] = None' in submit
    assert 'options_payload["auto_sharded"] = False' in submit
