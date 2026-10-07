"""A cancelled batch reports `cancelled`, never a budget dimension or a timeout.

A batch stopped by cancellation went through the same stop-reason rule as a batch that
ran out of budget: with a candidate left over it stated `insufficient_plan_budget` or the
dimension an earlier unfunded candidate lacked, and with an earlier wall-killed attempt the
backend settled it TIMED_OUT. Cancellation is distinct and stops execution, so the batch
now settles CANCELLED with reason `cancelled`.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
import uuid

from scan.action_adapter import batch_stop_reason
from scan.capability_result import CapabilityResultReason, CapabilityResultStatus
from tests.test_action_stop_dimension import _outcome, _wall_killed
from tests.test_template_batch_empty_timeout_retry import _matched, _passive_batch
from tests.test_scan_action_adapter import _dispatcher, _lease, _noop


def test_cancellation_outranks_every_budget_and_time_reason():
    for kwargs in (
        {"exhausted": {"http_requests"}},
        {"exhausted": {"state_changing_requests"}},
        {"exhausted": {"tool_wall_seconds"}},
        {"ceiling_stops": {"http_requests"}},
        {},
    ):
        assert batch_stop_reason(
            ["timeout"], unattempted=2, cancelled=True, **kwargs,
        ) == "cancelled"
    assert batch_stop_reason([], unattempted=2, exhausted={"http_requests"}) == (
        "http_request_budget_exhausted"
    ), "without cancellation the dimension still stands"


def test_a_cancelled_receipt_is_cancelled_even_with_a_wall_killed_attempt():
    receipt = SimpleNamespace(
        status="cancelled", timed_out=True, partial=True,
        errors=("cancelled", "timeout"),
    )
    assert _outcome(receipt) == (
        CapabilityResultStatus.CANCELLED, CapabilityResultReason.CANCELLED,
    )


def test_a_template_batch_cancelled_mid_run_settles_cancelled(monkeypatch):
    import scan.action_adapter as action_adapter_module
    from runtime.models import ScanPolicy

    plan, action, backend = _passive_batch()
    cancel = {"requested": False}

    async def execute(_self, context, adapter, **_kwargs):
        path = adapter._process_payload["execution_target"].split("app.example.test", 1)[1]
        granted = dict(context.requested_budget)
        # The operator cancels while the first attempt is running; it is wall-killed.
        cancel["requested"] = True
        return _wall_killed(path, granted)

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    dispatcher = _dispatcher(plan, backend, policy=ScanPolicy())
    dispatcher.cancelled = lambda: cancel["requested"]

    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert receipt.status == "cancelled"
    assert receipt.errors[0] == "cancelled"
    assert receipt.redacted_execution["unattempted_count"] == 2
    assert _outcome(receipt) == (
        CapabilityResultStatus.CANCELLED, CapabilityResultReason.CANCELLED,
    )


def test_an_uncancelled_template_batch_is_unchanged(monkeypatch):
    import scan.action_adapter as action_adapter_module
    from runtime.models import ScanPolicy

    plan, action, backend = _passive_batch()

    async def execute(_self, context, adapter, **_kwargs):
        path = adapter._process_payload["execution_target"].split("app.example.test", 1)[1]
        return _matched(path, dict(context.requested_budget))

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    dispatcher = _dispatcher(plan, backend, policy=ScanPolicy())

    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert receipt.status == "success"
    assert not receipt.errors


def test_a_request_batch_cancelled_before_its_candidates_settles_cancelled():
    from runtime.models import ScanPolicy
    from scan.action_plan import ScanAction, ScanActionPlan
    from scan.work_manifests import build_request_candidate_manifest, build_request_manifest
    from tests.test_scan_action_adapter import TARGET, Backend, _action, ReplayAuthorization, build_replay_plan

    scan_id = str(uuid.uuid4())
    request = build_replay_plan(
        ({
            "id": "credential-login:primary", "method": "POST",
            "url": "https://app.example.test/rest/user/login",
            "headers": {"Content-Type": "application/json"},
            "body": '{"email":"disposable@example.test","password":"private"}',
            "body_mode": "application/json", "auth_type": "none",
            "has_sensitive_material": True,
        },),
        allowed_origins=TARGET.allowed_origins,
        authorization=ReplayAuthorization(
            active_testing=True, allow_state_changing_http=True,
            approval_receipt_id="credential-workflow",
        ),
    ).requests[0]
    request_manifest = build_request_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        source_action_ids=("inputs.auth_primary",),
        requests=({
            "request_ref_id": request.request_id, "route_id": "d" * 64, "method": "POST",
            "auth_lane": "primary", "selected_shard": None,
            "request_class": "safe_authentication", "content_type": "application/json",
            "body_field_names": ["email", "password"],
            "selection_digest": "e" * 64, "body_schema_digest": "f" * 64,
        },),
    )
    candidates = build_request_candidate_manifest(
        (request_manifest,), source_action_ids=("inputs.auth_primary",), maximum=10,
    )
    action = _action(
        "verify.request_sqli", "sqli.request_verify_batch", 0,
        capability_args={
            "request_candidate_manifest_ref": candidates.reference().canonical_dict(),
            "slice": {"start": 0, "count": 2},
            "profile": "balanced_batch_v1",
            "proof_policy": "deterministic_differential_required",
        },
    )
    action = ScanAction(**{
        **action.digest_material(),
        # Too little left for the candidate: uncancelled, this batch names the dimension.
        "requested_budget": {"http_requests": 1, "state_changing_requests": 1, "tool_wall_seconds": 20},
    })
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(action,),
    )
    backend = Backend(manifests={candidates.manifest_id: candidates})

    def run(cancelled):
        dispatcher = _dispatcher(
            plan, backend,
            policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
        )
        dispatcher._private_requests[request.request_id] = request
        dispatcher.cancelled = lambda: cancelled
        return asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    uncancelled = run(False)
    assert uncancelled.errors[0] == "http_request_budget_exhausted"

    receipt = run(True)
    assert receipt.status == "cancelled"
    assert receipt.errors[0] == "cancelled"
    assert _outcome(receipt) == (
        CapabilityResultStatus.CANCELLED, CapabilityResultReason.CANCELLED,
    )
