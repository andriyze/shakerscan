"""A template sweep endpoint that timed out before reporting anything gets one funded retry.

On a starved host every nuclei attempt of a passive slice could reach its wall share before the
tool reported anything: the batch spent its whole reservation, counted every endpoint as
attempted and returned no findings. Such an endpoint is retried once after the first pass, from
what the batch reservation has left and only with a larger share than it timed out on; an
endpoint that still produced nothing is reported as unexamined.
"""

from __future__ import annotations

import asyncio
import dataclasses
import uuid

from hunt.capability_executor import CapabilityAdapterResult
from runtime.models import ScanPolicy
import scan.action_adapter as action_adapter_module
from scan.action_plan import ScanActionPlan
from scan.work_manifests import (
    build_candidate_manifest,
    build_canonical_passive_nuclei_template_manifest,
    build_endpoint_manifest,
)
from tests.test_scan_action_adapter import TARGET, Backend, _action, _dispatcher, _lease, _noop

BUDGET = {"http_requests": 30, "tool_wall_seconds": 60}


def _passive_batch():
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id,
        target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2",
            "status": "complete",
            "reason": None,
            "endpoints": [
                {
                    "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
                    "normalized_path": path, "concrete_path": path, "query_keys": [],
                    "source": "web.crawl",
                }
                for path in ("/slow", "/fast-one", "/fast-two")
            ],
        },
        source_action_ids=("discover.web_crawl",),
    )
    templates = build_canonical_passive_nuclei_template_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
    )
    action = dataclasses.replace(
        _action(
            "passive.templates.batch.00000", "templates.passive_batch", 0,
            capability_args={
                "target_manifest_ref": endpoints.reference().canonical_dict(),
                "template_manifest_ref": templates.reference().canonical_dict(),
                "slice": {"start": 0, "count": 3},
                "profile": "fast",
            },
        ),
        requested_budget=dict(BUDGET),
        action_digest=None,
    )
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(action,),
    )
    backend = Backend(manifests={
        endpoints.manifest_id: endpoints, templates.manifest_id: templates,
    })
    return plan, action, backend


def _run(monkeypatch, outcome):
    """Execute the batch with ``outcome(path, call_number, granted)`` deciding each attempt."""
    plan, action, backend = _passive_batch()
    calls: list[tuple[str, int]] = []

    async def execute(_self, context, adapter, **_kwargs):
        path = adapter._process_payload["execution_target"].split("app.example.test", 1)[1]
        granted = dict(context.requested_budget)
        calls.append((path, int(granted["tool_wall_seconds"])))
        return outcome(path, sum(1 for seen, _ in calls if seen == path), granted)

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    dispatcher = _dispatcher(plan, backend, policy=ScanPolicy())
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    return receipt, calls, backend, (plan, action, dispatcher)


def _timed_out_empty(granted):
    return CapabilityAdapterResult(
        status="partial", timed_out=True, partial=True, errors=("timeout",),
        actual_budget={"http_requests": 1, "tool_wall_seconds": granted["tool_wall_seconds"]},
        execution_started=True, parser_version="nuclei-jsonl/v1",
    )


def _matched(path, granted, seconds=2):
    return CapabilityAdapterResult(
        status="success",
        observations=({
            "kind": "template_match", "template_id": "http-missing-security-headers",
            "severity": "info", "matched_at": f"https://app.example.test{path}",
        },),
        actual_budget={"http_requests": 1, "tool_wall_seconds": min(seconds, granted["tool_wall_seconds"])},
        execution_started=True, parser_version="nuclei-jsonl/v1",
    )


def _matches(receipt):
    return sorted(
        item["matched_at"].split("app.example.test", 1)[1]
        for item in receipt.observations if item.get("kind") == "template_match"
    )


def _within_reservation(receipt):
    return all(int(receipt.budget_consumed.get(name, 0)) <= limit for name, limit in BUDGET.items())


def test_an_endpoint_that_timed_out_empty_is_retried_from_the_residual_and_recovered(monkeypatch):
    def outcome(path, call, granted):
        if path == "/slow" and call == 1:
            return _timed_out_empty(granted)
        return _matched(path, granted)

    receipt, calls, backend, (_, action, _) = _run(monkeypatch, outcome)

    # The first pass splits the 60s between the endpoints; the retry runs last, on what the two
    # fast endpoints left, and with a larger share than the one that timed out.
    first_share = next(wall for path, wall in calls if path == "/slow")
    assert calls[-1][0] == "/slow" and calls[-1][1] > first_share
    assert _matches(receipt) == ["/fast-one", "/fast-two", "/slow"]
    assert receipt.status == "success" and receipt.timed_out is False
    execution = receipt.redacted_execution
    assert (execution["retried_count"], execution["recovered_count"], execution["unexamined_count"]) == (1, 1, 0)
    assert execution["attempted_count"] == 3 and execution["unattempted_count"] == 0
    assert "timeout" not in receipt.errors
    assert _within_reservation(receipt)
    # The retry is its own immutable checkpoint beside the first attempt.
    assert len(backend.attempts[action.action_id]) == 4


def test_an_endpoint_that_never_reports_is_unexamined_and_the_batch_says_so(monkeypatch):
    def outcome(path, call, granted):
        if path == "/slow":
            return _timed_out_empty(granted)
        return _matched(path, granted)

    receipt, calls, _, _ = _run(monkeypatch, outcome)

    assert [path for path, _ in calls].count("/slow") == 2
    assert _matches(receipt) == ["/fast-one", "/fast-two"]
    assert receipt.status == "partial" and receipt.timed_out is True
    execution = receipt.redacted_execution
    assert execution["unexamined_count"] == 1 and execution["recovered_count"] == 0
    assert len(execution["unexamined_candidate_ids"]) == 1
    assert "timeout" in receipt.errors
    assert _within_reservation(receipt)


def test_no_retry_when_the_residual_is_no_larger_than_the_share_that_timed_out(monkeypatch):
    # Every endpoint uses its whole share: nothing is left, so retrying would fail the same way.
    def outcome(path, call, granted):
        return _timed_out_empty(granted)

    receipt, calls, _, _ = _run(monkeypatch, outcome)

    assert sorted(path for path, _ in calls) == ["/fast-one", "/fast-two", "/slow"]
    assert receipt.status == "partial" and receipt.timed_out is True
    assert receipt.redacted_execution["unexamined_count"] == 3
    assert receipt.redacted_execution["retried_count"] == 0
    assert _within_reservation(receipt)


def test_partial_output_from_a_timed_out_attempt_is_kept_and_not_retried(monkeypatch):
    # Output the tool printed before its wall is trustworthy evidence: kept, no retry needed.
    def outcome(path, call, granted):
        if path == "/slow":
            matched = _matched(path, granted, seconds=granted["tool_wall_seconds"])
            return dataclasses.replace(matched, status="partial", timed_out=True, partial=True, errors=("timeout",))
        return _matched(path, granted)

    receipt, calls, _, _ = _run(monkeypatch, outcome)

    assert [path for path, _ in calls].count("/slow") == 1
    assert _matches(receipt) == ["/fast-one", "/fast-two", "/slow"]
    assert receipt.status == "partial" and receipt.timed_out is True
    assert receipt.redacted_execution["unexamined_count"] == 0


def test_a_resumed_batch_replays_the_retry_without_running_anything(monkeypatch):
    def outcome(path, call, granted):
        if path == "/slow" and call == 1:
            return _timed_out_empty(granted)
        return _matched(path, granted)

    first, calls, _, (plan, action, dispatcher) = _run(monkeypatch, outcome)
    executed = len(calls)
    resumed = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert len(calls) == executed, "a resume must replay checkpoints, not run the tool again"
    assert resumed.status == first.status == "success"
    assert _matches(resumed) == _matches(first)
    assert resumed.redacted_execution["recovered_count"] == 1
    assert resumed.redacted_execution["resumed_count"] == 4


def test_verification_batches_are_not_retried(monkeypatch):
    """Only template sweeps retry; a dalfox or sqlmap attempt keeps its single attempt."""
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id,
        target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [
                {
                    "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
                    "normalized_path": path, "concrete_path": path, "query_keys": ["q"],
                    "source": "web.crawl",
                }
                for path in ("/one", "/two")
            ],
        },
        source_action_ids=("discover.web_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.web_crawl",), maximum=10,
    )
    action = _action(
        "verify.xss.batch.00000", "xss.verify_batch", 0,
        capability_args={
            "candidate_manifest_ref": candidates.reference().canonical_dict(),
            "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
            "slice": {"start": 0, "count": 2},
            "profile": "balanced", "proof_policy": "deterministic",
        },
    )
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(action,),
    )
    calls = []

    async def execute(_self, context, adapter, **_kwargs):
        calls.append(adapter._process_payload["execution_target"])
        return _timed_out_empty(dict(context.requested_budget))

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    dispatcher = _dispatcher(
        plan,
        Backend(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates}),
        policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
    )
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert len(calls) == 2
    assert receipt.status == "partial" and receipt.timed_out is True
    assert receipt.redacted_execution["retried_count"] == 0
    assert receipt.redacted_execution["unexamined_count"] == 0
