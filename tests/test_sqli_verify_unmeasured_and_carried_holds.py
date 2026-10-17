"""A required SQLi slice is not stopped by a start-up "measurement" or a diluted extension hold.

Lab Scan 13bd3497 (2.11.0 at 24d32428, honey with a /hub/ browser capture) reported coverage
partial on every thorough run. Its required verify.sqli.r01 (1,600 requests / 720 s) ended
timed_out after 11 s and 15 requests: ``/hub/api/tickets/1*`` settled U, B and E with one
request each (the unauthenticated replay answered 401), the stage guard read sqlmap's one-second
start-up as ~1 s per response and refused T (189 requests) against the 177 s left. Each of the
seven continuations then held 480 requests for that one candidate followed by three carried
ones, split them four ways (120 < 189) and stopped on the request ceiling without sending a
request. Fixture data below is shaped after those receipts; nothing here is a live measurement.
"""

from __future__ import annotations

import asyncio
import dataclasses
import uuid
from types import SimpleNamespace

import pytest
import scan.action_adapter as action_adapter_module
from hunt.capability_executor import CapabilityAdapterResult
from runtime.models import ScanPolicy
from scan.action_plan import ScanActionPlan
from scan.sqli_stages import prior_stages, run_staged_sqli_attempt
from scan.verification_extension import EXTENDS_ARG
from scan.work_manifests import build_candidate_manifest, build_endpoint_manifest

from tests.test_scan_action_adapter import TARGET, Backend, _dispatcher, _lease, _noop
from tests.test_scan_action_adapter import _action as plan_action

NEGATIVE = {"U": 53, "B": 87, "E": 144, "T": 189}


def _staged(run_stage, budget):
    async def checkpoint(_item):
        return None

    return asyncio.run(run_staged_sqli_attempt(
        candidate_attempt_id="6" * 64, candidate_id="tickets", budget=budget,
        prior=prior_stages((), "6" * 64), own_action_id="verify.sqli.r01",
        run_stage=run_stage, checkpoint=checkpoint, cancelled=lambda: False,
        round_wall_ceiling=900,
    ))


def test_one_request_stages_are_not_a_rate_that_refuses_the_time_based_unit():
    calls = []

    async def run_stage(technique, budget, _latency):
        calls.append((technique, dict(budget)))
        # sqlmap stops after the 401 baseline: one request, one second of process start-up.
        return SimpleNamespace(
            status="success", timed_out=False, errors=(), observations=(),
            actual_budget={"http_requests": 1, "tool_wall_seconds": 1},
        )

    outcome = _staged(run_stage, {"http_requests": 400, "tool_wall_seconds": 180})

    assert [technique for technique, _ in calls] == ["U", "B", "E", "T"]
    assert outcome.status == "success" and outcome.timed_out is False
    assert "timeout" not in outcome.errors


def test_a_measured_rate_still_stops_a_unit_that_cannot_fit():
    # The guard is unchanged once a stage sent enough requests to measure the target.
    calls = []

    async def run_stage(technique, budget, _latency):
        calls.append(technique)
        need = NEGATIVE[technique]
        return SimpleNamespace(
            status="success", timed_out=False, errors=(), observations=(),
            actual_budget={"http_requests": need, "tool_wall_seconds": need},
        )

    outcome = _staged(run_stage, {"http_requests": 1_000, "tool_wall_seconds": 180})

    assert calls == ["U", "B"]
    assert outcome.stages[-1] == {"technique": "E", "outcome": "wall_exhausted"}
    assert outcome.status == "partial" and outcome.timed_out is True


@pytest.mark.parametrize("others", ["finished", "refused"])
def test_an_extension_funds_its_unfinished_candidate_not_the_ones_it_carries(monkeypatch, others):
    # "refused": the three others were refused unauthenticated (401) in the slice; the
    # extension re-runs them without traffic, so they need no hold either.
    scan_id = str(uuid.uuid4())
    paths = ("/api/tickets/1", "/api/users/1", "/api/baskets/1", "/api/orders/1")
    endpoints = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [
                {
                    "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
                    "normalized_path": path, "concrete_path": path, "query_keys": ["q"],
                    "source": "web.crawl",
                }
                for path in paths
            ],
        },
        source_action_ids=("discover.web_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.web_crawl",), maximum=10,
    )
    args = {
        "candidate_manifest_ref": candidates.reference().canonical_dict(),
        "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
        "slice": {"start": 0, "count": 4},
        "profile": "thorough_batch_v1", "proof_policy": "deterministic_differential_required",
    }
    actions = [
        dataclasses.replace(
            plan_action(
                action_id, "sqli.verify_batch", ordinal,
                capability_args={**args, **({EXTENDS_ARG: extends} if extends else {})},
            ),
            requested_budget=budget, action_digest=None,
        )
        for ordinal, (action_id, extends, budget) in enumerate((
            ("verify.sqli.r01", None, {"http_requests": 1_600, "tool_wall_seconds": 720}),
            ("verify.sqli.r01.ext.r02", "verify.sqli.r01",
             {"http_requests": 480, "tool_wall_seconds": 1_173}),
        ))
    ]
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=tuple(actions),
    )
    # The slice's first candidate is the one left unfinished, so three carried ones follow it.
    first = {"path": None}
    calls = []

    async def execute(_self, context, adapter, **_kwargs):
        target = adapter._process_payload["execution_target"]
        path = target.split("app.example.test", 1)[1].split("?")[0]
        technique = adapter._process_payload["scanner_options"]["technique"]
        first["path"] = first["path"] or path
        held = dict(context.requested_budget)
        calls.append((path, technique, held))
        need = 189 if technique == "T" else 20
        if others == "refused" and path != first["path"]:
            return CapabilityAdapterResult(
                status="success", actual_budget={"http_requests": 1, "tool_wall_seconds": 1},
                observations=({"kind": "verifier_baseline_response", "http_status": 401,
                               "login_redirect": False, "www_authenticate": False},),
                execution_started=True, parser_version="sqlmap-output/v1",
            )
        return CapabilityAdapterResult(
            status="success", actual_budget={
                "http_requests": need,
                # The first candidate answers in 3 s; the other three in a tenth of a second.
                "tool_wall_seconds": need * 3 if path == first["path"] else max(1, need // 10),
            },
            execution_started=True, parser_version="sqlmap-output/v1",
        )

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    backend = Backend(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates})
    dispatcher = _dispatcher(
        plan, backend, policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
    )
    slice_receipt = asyncio.run(dispatcher(actions[0], _lease(plan, actions[0]), _noop))
    in_slice = len(calls)
    extension = asyncio.run(dispatcher(actions[1], _lease(plan, actions[1]), _noop))

    # At 3 s per measured request the slice's first candidate cannot fit its next unit in the
    # wall its share has left, so it stops wall-stopped; the other three finish.
    assert slice_receipt.status != "success"
    resumed = calls[in_slice:]
    assert resumed and {path for path, _, _ in resumed} == {first["path"]}
    assert resumed[-1][1] == "T"
    # The whole 480-request hold is the unfinished candidate's; the carried three need none.
    assert resumed[0][2]["http_requests"] == 480
    if others == "refused":
        assert extension.redacted_execution["carried_count"] == 0
        assert extension.errors[0] == "authentication_required"
        return
    assert extension.redacted_execution["carried_count"] == 3
    assert extension.status == "success", (extension.status, extension.errors)


def test_nosqli_records_a_path_segment_slice_as_inapplicable_not_unattempted(monkeypatch):
    # 13bd3497's verify.nosqli.r01: four /hub/api/<name>/1* path candidates, all skipped,
    # reported partial (output_truncated) and failed the required nosqli family.
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [
                {"method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
                 "normalized_path": f"/api/{name}/{{int}}", "concrete_path": f"/api/{name}/1",
                 "query_keys": [], "source": "web.spec_ingest"}
                for name in ("tickets", "users", "baskets", "orders")
            ],
        },
        source_action_ids=("discover.spec",),
    )
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.spec",), maximum=10,
    )
    assert {item.get("parameter_location") for item in candidates.entries} == {"path"}
    action = plan_action(
        "verify.nosqli.r01", "nosqli.verify_batch", 0,
        capability_args={
            "candidate_manifest_ref": candidates.reference().canonical_dict(),
            "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
            "slice": {"start": 0, "count": len(candidates.entries)},
        },
    )
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(action,),
    )

    async def execute(_self, _context, _adapter, **_kwargs):
        raise AssertionError("the NoSQL differential must not run against a path segment")

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    backend = Backend(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates})
    dispatcher = _dispatcher(
        plan, backend, policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
    )

    result = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert result.status == "success", result.errors
    assert result.redacted_execution["unattempted_count"] == 0
    assert result.redacted_execution["inapplicable_count"] == len(candidates.entries)
    assert [item["reason"] for item in result.observations] == (
        ["path_segment_candidate"] * len(candidates.entries)
    )
