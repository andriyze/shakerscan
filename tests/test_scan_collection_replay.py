from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

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
    narrow_replay_plan_to_request_manifest,
    remaining_scan_replay_capacity,
    scan_replay_authorization,
    scan_replay_ledger_limits,
    scan_replay_runtime_http_ceiling,
    scan_replay_selector,
    validate_scan_replay_request_manifest,
)
from api.scan.work_manifests import build_request_manifest
from scanner.scanner_tools.request_collections import validate_and_index
from scanner.scanner_tools.request_replay import build_selected_replay_plan


def _budget() -> dict[str, int]:
    return {
        "max_duration_seconds": 1_200,
        "max_http_requests": 100,
        "max_state_changing_requests": 6,
        "max_endpoints": 50,
        "max_hosts": 8,
        "max_browser_actions": 20,
        "max_tcp_ports": 10,
        "max_tool_wall_seconds": 60,
        "max_workers": 2,
    }


def test_decrypted_replay_plan_must_match_immutable_request_manifest():
    manifest = build_request_manifest(
        scan_id="40000000-0000-4000-8000-000000000001",
        target_binding_digest="a" * 64,
        source_action_ids=("inputs.collection_00",),
        requests=({
            "request_ref_id": "get-health",
            "route_id": "b" * 64,
            "method": "GET",
            "auth_lane": "primary",
            "selected_shard": None,
            "safe_method": True,
            "body_schema_digest": None,
        },),
    )
    matching = SimpleNamespace(requests=(SimpleNamespace(
        request_id="get-health", method="GET",
    ),))
    substituted = SimpleNamespace(requests=(SimpleNamespace(
        request_id="get-admin", method="GET",
    ),))

    validate_scan_replay_request_manifest(matching, manifest)
    with pytest.raises(
        ScanCollectionReplayContractError, match="immutable request manifest",
    ):
        validate_scan_replay_request_manifest(substituted, manifest)


def test_private_replay_plan_is_narrowed_to_child_manifest_and_reindexed():
    document = {
        "info": {"name": "Partitioned replay", "schema": "v2.1"},
        "item": [
            {"name": "one", "request": {
                "method": "GET", "url": "https://api.example.test/one",
            }},
            {"name": "two", "request": {
                "method": "GET", "url": "https://api.example.test/two",
            }},
            {"name": "three", "request": {
                "method": "GET", "url": "https://api.example.test/three",
            }},
        ],
    }
    payload, _summary, rows = validate_and_index(document)
    selector = scan_replay_selector(
        RequestCollectionSelection(max_requests=3),
        "safe_reads",
        runtime_limit=3,
    )
    plan = build_selected_replay_plan(
        payload,
        selector,
        allowed_origins=["https://api.example.test"],
        default_origin="https://api.example.test",
    )
    assigned = (plan.requests[2], plan.requests[0])
    manifest = build_request_manifest(
        scan_id="40000000-0000-4000-8000-000000000001",
        target_binding_digest="a" * 64,
        source_action_ids=("inputs.collection_00",),
        requests=tuple({
            "request_ref_id": request.request_id,
            "route_id": ("b" if index == 0 else "c") * 64,
            "method": request.method,
            "auth_lane": "anonymous",
            "selected_shard": 1,
            "safe_method": True,
            "body_schema_digest": None,
        } for index, request in enumerate(assigned)),
    )

    narrowed = narrow_replay_plan_to_request_manifest(plan, manifest)

    assert tuple(request.request_id for request in narrowed.requests) == tuple(
        request.request_id for request in assigned
    )
    assert tuple(request.ordinal for request in narrowed.requests) == (0, 1)
    assert narrowed.input_digest != plan.input_digest


def test_private_replay_narrowing_fails_when_child_reference_is_absent():
    plan = SimpleNamespace(requests=())
    manifest = build_request_manifest(
        scan_id="40000000-0000-4000-8000-000000000001",
        target_binding_digest="a" * 64,
        source_action_ids=("inputs.collection_00",),
        requests=({
            "request_ref_id": "missing",
            "route_id": "b" * 64,
            "method": "GET",
            "auth_lane": "anonymous",
            "selected_shard": 0,
            "safe_method": True,
            "body_schema_digest": None,
        },),
    )
    with pytest.raises(
        ScanCollectionReplayContractError, match="missing child request authority",
    ):
        narrow_replay_plan_to_request_manifest(plan, manifest)


def _capture_request_manifest(request_ids):
    return build_request_manifest(
        scan_id="40000000-0000-4000-8000-000000000001",
        target_binding_digest="a" * 64,
        source_action_ids=("inputs.collection_00",),
        requests=tuple({
            "request_ref_id": request_id,
            "route_id": f"{index + 1:064x}",
            "method": "GET",
            "auth_lane": "anonymous",
            "selected_shard": None,
            "safe_method": True,
            "body_schema_digest": None,
        } for index, request_id in enumerate(request_ids)),
    )


def test_a_capture_indexed_before_path_credentials_were_withheld_still_replays_the_rest():
    """A capture whose request list was written before path credentials were withheld lists
    such a request as supported, so a Scan's request manifest names it. The worker never sends
    it: narrowing leaves it out and replays the rest instead of failing the action, and a
    manifest whose every request is withheld is skipped (``ScanCollectionReplayWithheld``).
    Any other missing reference still fails closed. Unit fixtures only."""
    from api.capture.flows import CaptureFlow, har_entry
    from api.scan.collection_replay import ScanCollectionReplayWithheld

    def entry(path):
        return har_entry(CaptureFlow.model_validate({
            "method": "GET", "url": f"https://app.example.test{path}",
        }))[0]

    secret = "Zx9Qp2Lm7Rt4Wv8Yb3NcKd5Hj6"
    payload = {"format": "capture", "document": {"log": {"version": "1.2", "entries": [
        entry("/api/items"), entry(f"/s/{secret}/dashboard"), entry("/api/orders"),
    ]}}}
    selector = scan_replay_selector(
        RequestCollectionSelection(max_requests=10), "safe_reads", runtime_limit=10,
    )
    plan = build_selected_replay_plan(
        payload, selector,
        allowed_origins=["https://app.example.test"],
        default_origin="https://app.example.test",
    )
    from scanner.scanner_tools.device_request_formats import resolve_imported_requests

    items, withheld, orders = (request["id"] for request in resolve_imported_requests(payload))
    assert [request.request_id for request in plan.requests] == [items, orders]
    # What an index row written before the rule offered: all three requests supported.
    manifest = _capture_request_manifest((orders, withheld, items))

    with pytest.raises(ScanCollectionReplayContractError, match="missing child request authority"):
        narrow_replay_plan_to_request_manifest(plan, manifest)
    narrowed = narrow_replay_plan_to_request_manifest(plan, manifest, payload=payload)
    assert [request.request_id for request in narrowed.requests] == [orders, items]
    assert [request.ordinal for request in narrowed.requests] == [0, 1]
    assert secret not in repr(narrowed.wire_requests())

    with pytest.raises(ScanCollectionReplayWithheld, match="none is replayed"):
        narrow_replay_plan_to_request_manifest(
            plan, _capture_request_manifest((withheld,)), payload=payload,
        )
    with pytest.raises(ScanCollectionReplayContractError, match="missing child request authority") as other:
        narrow_replay_plan_to_request_manifest(
            plan, _capture_request_manifest((items, "f" * 24)), payload=payload,
        )
    assert not isinstance(other.value, ScanCollectionReplayWithheld)
    # An ordinary HAR of the same traffic withholds nothing: the request is replayed as supplied.
    har_plan = build_selected_replay_plan(
        {"format": "har", "document": payload["document"]}, selector,
        allowed_origins=["https://app.example.test"],
        default_origin="https://app.example.test",
    )
    assert len(har_plan.requests) == 3


def test_rows_the_previous_index_showed_unmasked_still_build_a_scan_and_never_replay():
    """A capture indexed by the previous release stored each row as ``redact_url`` showed it,
    every request supported. For a path the shared mask shows as it is (``/s/a1b2c3d4/``,
    ``/share/doc-2024/``, ``sessionid=1234``) the stored route still passes the unchanged
    sensitive-path gate, so a Scan request manifest is built from those rows; the worker resolves
    the capture again, never replays the withheld requests, and replays the rest. A selection
    or a Hunt queue naming them by id leaves them out the same way. Unit fixtures only."""
    from api.capture.flows import CaptureFlow, har_entry
    from api.scan.work_manifests import route_id
    from scanner.scanner_tools.device_request_formats import resolve_imported_requests
    from scanner.scanner_tools.request_collections import (
        RequestSelector, redacted_index, replay_queue_refusal, select_requests,
    )
    from scanner.scanner_tools.url_redaction import redact_url

    paths = ["/api/items", "/s/a1b2c3d4/dashboard", "/share/doc-2024/view", "/api/sessionid=1234/me"]
    urls = [f"https://app.example.test{path}" for path in paths]
    payload = {"format": "capture", "document": {"log": {"version": "1.2", "entries": [
        har_entry(CaptureFlow.model_validate({"method": "GET", "url": url}))[0] for url in urls
    ]}}}
    resolved = resolve_imported_requests(payload)
    ids = [request["id"] for request in resolved]
    assert [request["error"] for request in resolved] == [None] + ["captured_path_credential_withheld"] * 3
    legacy_rows = redacted_index([
        {"id": request_id, "method": "GET", "url": redact_url(url), "supported": True}
        for request_id, url in zip(ids, urls, strict=True)
    ])
    assert [row["normalized_path"] for row in legacy_rows] == paths
    manifest = build_request_manifest(
        scan_id="40000000-0000-4000-8000-000000000002",
        target_binding_digest="a" * 64,
        source_action_ids=("inputs.collection_00",),
        requests=tuple({
            "request_ref_id": row["request_id"],
            "route_id": route_id(
                target_binding_digest="a" * 64, method="GET", scheme="https",
                host="app.example.test", port=443, canonical_path=row["normalized_path"],
                query_parameter_names=[],
            ),
            "method": "GET", "auth_lane": "anonymous", "selected_shard": None,
            "safe_method": True, "body_schema_digest": None,
        } for row in legacy_rows),
    )
    plan = build_selected_replay_plan(
        payload,
        scan_replay_selector(RequestCollectionSelection(max_requests=10), "safe_reads", runtime_limit=10),
        allowed_origins=["https://app.example.test"],
        default_origin="https://app.example.test",
    )
    narrowed = narrow_replay_plan_to_request_manifest(plan, manifest, payload=payload)
    assert [request.request_id for request in narrowed.requests] == [ids[0]]
    wire = repr(narrowed.wire_requests())
    assert all(secret not in wire for secret in ("a1b2c3d4", "doc-2024", "sessionid"))

    by_id = RequestSelector(request_ids=tuple(ids), safe_methods_only=False)
    assert [request["id"] for request in select_requests(payload, by_id)] == [ids[0]]
    assert replay_queue_refusal(payload, ids, {ids[0]}) is None
    assert "recorded path carries a credential" in replay_queue_refusal(payload, ids[1:], {ids[0]})


def test_a_hunt_queue_of_withheld_capture_requests_is_refused_by_name():
    from scanner.scanner_tools.request_collections import replay_queue_refusal

    payload = {"format": "capture", "document": {"log": {"version": "1.2", "entries": [
        {"request": {"method": "GET", "url": "https://app.example.test/api/items"}},
        {"request": {"method": "GET", "url": "https://app.example.test/s/Zx9Qp2Lm7Rt4Wv8Yb3NcKd5Hj6/x"}},
    ]}}}
    from scanner.scanner_tools.device_request_formats import resolve_imported_requests

    items, withheld = (request["id"] for request in resolve_imported_requests(payload))
    allowed = {items}
    assert replay_queue_refusal(payload, [items], allowed) is None
    assert replay_queue_refusal(payload, [items, withheld], allowed) is None  # the selection skips it
    assert "recorded path carries a credential" in replay_queue_refusal(payload, [withheld], allowed)
    assert "exceed the saved collection selection" in replay_queue_refusal(payload, ["f" * 24], allowed)
    assert "exceed the saved collection selection" in replay_queue_refusal(payload, [], allowed)


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


def test_safe_authentication_requires_active_approval_without_state_permission():
    with pytest.raises(ScanCollectionReplayContractError, match="active_testing"):
        scan_replay_authorization(
            "safe_authentication", {}, approval_receipt_id="approval-1",
        )
    with pytest.raises(ScanCollectionReplayContractError, match="target-bound approval"):
        scan_replay_authorization(
            "safe_authentication", {"active_testing": True},
        )

    authorization = scan_replay_authorization(
        "safe_authentication",
        {"active_testing": True, "allow_state_changing_http": False},
        approval_receipt_id="approval-1",
    )
    assert authorization.safe_authentication_only is True
    assert authorization.allow_state_changing_http is False
    assert authorization.approval_receipt_id == "approval-1"


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
            authorized_budget={
                "http_requests": 4,
                "state_changing_requests": 3,
                "tool_wall_seconds": 20,
            },
            receipt_capability_name="collections.replay_active",
            receipt_input_digest="c" * 64,
            on_reservation=persist_transition,
            on_settlement=persist_settlement,
            require_durable_persistence=True,
        )
        return outcome, transitions, settlements, transport.wire

    outcome, transitions, settlements, wire = asyncio.run(drive())

    assert [item[0] for item in transitions] == ["requested", "reserved", "running"]
    assert outcome.reservation.status == "committed"
    assert dict(outcome.reservation.requested) == {
        "http_requests": 4,
        "state_changing_requests": 3,
        "tool_wall_seconds": 20,
    }
    assert outcome.reservation.actual["http_requests"] == 1
    assert outcome.reservation.actual["state_changing_requests"] == 1
    assert settlements[0][1].scan_id == "scan-1"
    assert settlements[0][1].capability_name == "collections.replay_active"
    assert settlements[0][1].input_digest == "c" * 64
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
    assert limits["state_changing_requests"] == 6
    assert limits["hosts_attempted"] == 8
    assert limits["http_requests"] == 100


def test_scan_replay_accepts_zero_unrelated_parallel_child_dimensions():
    budget = {
        **_budget(),
        "max_browser_actions": 0,
        "max_tcp_ports": 0,
        "max_hosts": 0,
    }

    assert scan_replay_ledger_limits(budget) == {
        "http_requests": 100,
        "state_changing_requests": 6,
        "browser_actions": 0,
        "tcp_ports_attempted": 0,
        "hosts_attempted": 0,
        "tool_wall_seconds": 60,
    }


@pytest.mark.parametrize("field", ["max_http_requests", "max_tool_wall_seconds"])
def test_scan_replay_requires_positive_http_and_time_authority(field):
    budget = {**_budget(), field: 0}

    with pytest.raises(ScanCollectionReplayContractError, match="positive integer"):
        scan_replay_ledger_limits(budget)


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
    scheduler_start = worker.index("async def _execute_reserved_deterministic_scan")
    scheduler_end = worker.index(
        "\n\nasync def _execute_scan_subdomain_discovery", scheduler_start,
    )
    scheduler = worker[scheduler_start:scheduler_end]
    dispatcher = (root / "api" / "scan" / "action_adapter.py").read_text()

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
    assert 'canonical_action.action_id' in handler
    assert 'canonical_action.action_digest' in handler
    assert '"authorized_budget": requested_budget' in handler
    assert "_execute_scan_request_collections" not in process
    assert process.index("_hydrate_generic_scan_credentials") < process.index(
        "_execute_reserved_deterministic_scan("
    )
    assert "_execute_scan_request_collections(" in scheduler
    assert "trusted_primary_headers=resolve_scan_http_principal(" in scheduler
    assert "private_replay_plan_loader=load_private_replay_plan" in scheduler
    assert "async def _collection_replay" in dispatcher
    assert "self._private_replay_plan(action)" in dispatcher
    assert "collection_replay_result_holder" not in scheduler
    assert "collection_replay_result_holder" not in process
    assert "class DatabaseNeutralScanActionDispatcher:" in dispatcher
    assert "ScanOrchestrator(" in scheduler


def test_scan_api_allows_canonical_parallel_replay_and_freezes_binding():
    root = Path(__file__).resolve().parents[1]
    source = (root / "api" / "api.py").read_text()
    worker = (root / "api" / "worker.py").read_text()
    submit_start = source.index('async def _submit_scan')
    submit_end = source.index("\nasync def submit_batch_endpoint", submit_start)
    submit = source[submit_start:submit_end]

    assert "confirmed_active_collection_replay" in submit
    assert "always_require_receipt=durable_approval_required" in submit
    assert "require_target_binding=durable_approval_required" in submit
    assert "require_expiry=durable_approval_required" in submit
    assert "_freeze_scan_collection_target_binding" in submit
    assert "request_collection_exact_replay_requires_single_scan_owner" not in submit
    assert "ParallelRequestWork(" in worker
    assert "typed parallel request selection was assigned twice" in worker
    assert "request_partitions[child.index] = selected" in worker
    assert "narrow_replay_plan_to_request_manifest(" in worker
