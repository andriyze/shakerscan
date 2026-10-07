"""An extension re-runs only what the slice it extends could not finish.

The extended slice's candidates that reached a verdict are carried into the extension with
no budget and no repeat traffic; only the wall-killed ones run again, on the extension's
larger, latency-scaled hold.
"""

from __future__ import annotations

import asyncio
import dataclasses
import uuid

import scan.action_adapter as action_adapter_module
from hunt.capability_executor import CapabilityAdapterResult
from runtime.models import ScanPolicy
from scan.action_plan import ScanActionPlan
from scan.verification_extension import EXTENDS_ARG
from scan.work_manifests import build_candidate_manifest, build_endpoint_manifest
from tests.test_scan_action_adapter import TARGET, Backend, _action as plan_action, _dispatcher, _lease, _noop



def test_an_extension_reruns_only_the_candidates_its_slice_could_not_finish(monkeypatch):
    scan_id = str(uuid.uuid4())
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
                for path in ("/fast", "/slow")
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
        "slice": {"start": 0, "count": 2},
        "profile": "balanced_batch_v1", "proof_policy": "deterministic_proof_contract_required",
    }
    budget = {"http_requests": 1400, "tool_wall_seconds": 400}
    original = dataclasses.replace(
        plan_action("verify.xss.r01", "xss.verify_batch", 0, capability_args=args),
        requested_budget=dict(budget), action_digest=None,
    )
    extension = dataclasses.replace(
        plan_action(
            "verify.xss.r01.ext.r02", "xss.verify_batch", 1,
            capability_args={**args, EXTENDS_ARG: "verify.xss.r01"},
        ),
        requested_budget={"http_requests": 3150, "tool_wall_seconds": 900}, action_digest=None,
    )
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(original, extension),
    )
    calls = []

    async def execute(_self, context, adapter, **_kwargs):
        target = adapter._process_payload["execution_target"]
        calls.append((target, dict(context.requested_budget)))
        wall = context.requested_budget["tool_wall_seconds"]
        if "/slow" in target and wall < 400:
            return CapabilityAdapterResult(
                status="partial", partial=True, timed_out=True, errors=("timeout",),
                actual_budget={"http_requests": 20, "tool_wall_seconds": wall},
                execution_started=True, parser_version="dalfox-jsonl/v1",
            )
        return CapabilityAdapterResult(
            status="success", actual_budget={"http_requests": 30, "tool_wall_seconds": 20},
            execution_started=True, parser_version="dalfox-jsonl/v1",
        )

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    backend = Backend(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates})
    dispatcher = _dispatcher(plan, backend, policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"))

    first = asyncio.run(dispatcher(original, _lease(plan, original), _noop))
    assert first.timed_out is True and len(calls) == 2
    calls.clear()

    receipt = asyncio.run(dispatcher(extension, _lease(plan, extension), _noop))

    assert [target.rsplit("/", 1)[-1].split("?")[0] for target, _ in calls] == ["slow"]
    assert calls[0][1]["tool_wall_seconds"] > 400, "the carried candidate leaves its share to the rerun"
    assert receipt.status == "success" and receipt.timed_out is False
    execution = receipt.redacted_execution
    assert execution["extends"] == "verify.xss.r01" and execution["carried_count"] == 1
    assert execution["attempted_count"] == 2 and execution["unattempted_count"] == 0
    # A carried candidate is neither re-run nor re-charged.
    assert receipt.budget_consumed["http_requests"] == 30
    carried = [
        item for item in receipt.observations
        if item.get("kind") == "candidate_attempt" and item.get("carried_from")
    ]
    assert len(carried) == 1
