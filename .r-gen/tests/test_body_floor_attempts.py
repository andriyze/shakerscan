"""A verifier slice that now holds a body attempt's floor attempts its body candidate.

A thorough SQLi slice holding one request-body candidate used to hold 400 requests and 180 s
with no mutation hold; the adapter refused the candidate before any traffic. At the body floor
(480 requests, 480 mutations, 420 s) the same slice attempts it. These tests drive the real
batch adapter with a fake sqlmap process runner; no scanner process runs.
"""

from __future__ import annotations

import asyncio
import dataclasses
import uuid

from runtime.models import ScanPolicy
from scan.action_plan import ScanActionPlan
from scan.work_manifests import build_candidate_manifest, build_endpoint_manifest
from tests.test_body_attempt_mutation_accounting import _runner
from tests.test_scan_action_adapter import TARGET, Backend, _action, _dispatcher, _lease, _noop


def _body_slice_run(requested):
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [{
                "method": "POST", "scheme": "https", "host": "app.example.test", "port": 443,
                "normalized_path": "/graphql", "concrete_path": "/graphql", "query_keys": [],
                "content_type": "application/json", "body_field_names": ["query"],
                "source": "inputs.custom_endpoints",
            }],
        },
        source_action_ids=("discover.web_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.web_crawl",), maximum=10,
        allow_state_changing_http=True,
    )
    assert len(candidates.entries) == 1 and candidates.entries[0].get("body_field_names")
    action = dataclasses.replace(
        _action("verify.sqli.r01", "sqli.verify_batch", 0, capability_args={
            "candidate_manifest_ref": candidates.reference().canonical_dict(),
            "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
            "slice": {"start": 0, "count": 1},
            "profile": "thorough_batch_v1",
            "proof_policy": "deterministic_differential_required",
        }),
        requested_budget=dict(requested), action_digest=None,
    )
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(action,),
    )
    backend = Backend(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates})
    dispatcher = _dispatcher(plan, backend, policy=ScanPolicy(
        active_testing=True, allow_state_changing_http=True, approval_receipt_id="approval-1",
    ))
    runner, calls = _runner("sqlmap", "sqlmap-output/v1", sent=40)
    dispatcher.process_runner = runner
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    return receipt, calls


def test_the_adapter_attempts_the_body_candidate_at_the_new_hold():
    receipt, calls = _body_slice_run(
        {"http_requests": 480, "state_changing_requests": 480, "tool_wall_seconds": 420},
    )
    assert calls, "the body candidate is attempted"
    assert receipt.budget_consumed["http_requests"] > 0


def test_at_the_old_hold_the_adapter_refused_it_before_any_traffic():
    receipt, calls = _body_slice_run({"http_requests": 400, "tool_wall_seconds": 180})
    assert not calls
    assert receipt.status == "partial"
    assert receipt.budget_consumed.get("http_requests", 0) == 0
