"""A browser proof whose every attempt failed leaves the XSS family partial, end to end.

Unit fixtures, not a live Scan. The real batch aggregator (``_xss_browser_proof_batch``) runs
three candidates whose browser attempts all fail (``CapabilityExecutor`` stubbed to the result the
browser adapter returns when the browser cannot start); the receipt is settled as the execution
backend settles it and handed to the real finalizer next to an XSS verifier that did its work and
flagged a reflection only the browser proof can promote. Nothing proved or ruled that reflection
out, so the family is partial, the Scan's coverage is not complete and its grade is not reliable.
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import replace

from hunt.capability_executor import CapabilityAdapterResult
from runtime.models import ScanPolicy
import scan.action_adapter as action_adapter_module
from scan.action_plan import ScanActionPlan
from scan.work_manifests import build_candidate_manifest, build_endpoint_manifest
from tests.test_scan_action_adapter import TARGET, Backend, _action, _dispatcher, _lease, _noop

from api.scan.capability_result import CapabilityResultReason as Reason
from api.scan.capability_result import CapabilityResultStatus as Status
from api.scan.execution_backend import PostgresScanExecutionBackend
from tests.test_honest_family_coverage_sweep import (
    _companion_that_worked, _finalize, _planned_slice, _result_with_observation_count, _settled,
    _work_rows,
)

# What the browser adapter returns for each attempt when the browser cannot start.
BROWSER_UNAVAILABLE = "playwright_unavailable"


def _failed_browser_proof_receipt(monkeypatch):
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [{
                "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
                "normalized_path": "/", "concrete_path": "/", "query_keys": [],
                "browser_fragment_path": "/search", "browser_fragment_query_keys": ["q", "r", "s"],
                "source": "web.browser_crawl",
            }],
        },
        source_action_ids=("discover.browser_crawl",),
    )
    candidates = build_candidate_manifest(endpoints, source_action_ids=("discover.browser_crawl",), maximum=10)
    assert len(candidates.entries) == 3
    action = _action(
        "prove.xss", "xss.browser_prove_batch", 0,
        capability_args={
            "candidate_manifest_ref": candidates.reference().canonical_dict(),
            "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
            "slice": {"start": 0, "count": 3},
        },
    )
    action = replace(action, action_digest=None, requested_budget={
        "browser_actions": 60, "http_requests": 600, "tool_wall_seconds": 600,
    })
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=(action,))

    async def execute(_self, _context, _adapter, **_kwargs):
        return CapabilityAdapterResult(status="failed", errors=(BROWSER_UNAVAILABLE,), actual_budget={},
                                       parser_version="xss-browser-proof/v1")

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    backend = Backend(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates})
    return asyncio.run(_dispatcher(
        plan, backend, policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
    )(action, _lease(plan, action), _noop))


def test_a_browser_proof_whose_attempts_all_failed_leaves_xss_partial_and_the_grade_unreliable(monkeypatch):
    receipt = _failed_browser_proof_receipt(monkeypatch)
    attempts = [item for item in receipt.observations if item.get("kind") == "candidate_attempt"]
    assert [item["status"] for item in attempts] == ["failed"] * 3
    status, reason = PostgresScanExecutionBackend._receipt_outcome(
        object.__new__(PostgresScanExecutionBackend), receipt)
    passive, passive_result, passive_rows = _companion_that_worked("xss")
    verifier = _planned_slice("verify.family", "xss.verify_batch", 1)
    proof = _planned_slice("prove.family", "xss.browser_prove_batch", 2, required=False)
    # A reflection Dalfox flagged with its headless check off: only the browser proof promotes it.
    reflected = ({"kind": "xss_alert", "candidate_id": "c-0", "alert_type": "R",
                  "url": "https://app.example.test/search", "param": "q", "proof_state": "candidate"},)
    verifier_rows = (*_work_rows(verifier), *reflected)
    proof_rows = tuple(dict(item) for item in receipt.observations)
    report, row = _finalize(
        (passive, verifier, proof),
        {passive.action_id: passive_result,
         verifier.action_id: _result_with_observation_count(verifier, len(verifier_rows)),
         proof.action_id: _settled(proof, Status(status.value), Reason(reason.value), proof_rows)},
        {passive.action_id: passive_rows, verifier.action_id: verifier_rows, proof.action_id: proof_rows},
        "xss",
    )
    assert Status(status.value) is Status.PARTIAL
    assert row["coverage_status"] == "partial", row
    assert report["coverage"]["status"] != "complete"
    assert "xss" in report["coverage"]["selected_family_gaps"]
    assert report["result"]["grade_reliable"] is False
    assert row["reason"] == "proof_attempts_unresolved"
    assert row["proof_escalation"]["unresolved_candidates"] == 3
