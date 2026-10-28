"""A proof whose page the service did not serve leaves its family partial, through the Scan.

The real batch handlers (``xss.browser_prove_batch``, ``sqli.prove_batch``), capability executor,
result settlement and finalizer, with a fake Playwright page and a fake replay transport standing
in for the target (unit fixtures, not a live Scan): a proof page answered 503, 429 or 404 leaves
the attempt unresolved, the proof action settles ``target_unavailable`` and the family reads
partial with ``proof_attempts_unresolved``, so the Scan is not complete and its grade not reliable.
A page that loaded and did not run the payload still reads complete. The adapters' own cases are
in ``test_proof_page_not_served.py``.
"""
from __future__ import annotations

import asyncio
import urllib.parse
import uuid
from dataclasses import replace

import pytest

import capabilities.browser as scan_browser  # the module the Scan dispatcher runs
from runtime.models import ScanPolicy
import scan.action_adapter as action_adapter_module
from scan.action_plan import ScanActionPlan
from scan.work_manifests import build_candidate_manifest, build_endpoint_manifest
from tests.test_scan_action_adapter import (
    TARGET, Backend, ReplayTransportResult, _action, _dispatcher, _lease, _noop,
)

from api.scan.capability_result import CapabilityResultReason as Reason
from api.scan.capability_result import CapabilityResultStatus as Status
from api.scan.execution_backend import PostgresScanExecutionBackend
from tests.test_honest_family_coverage_sweep import (
    _companion_that_worked, _finalize, _planned_slice, _result_with_observation_count, _settled,
    _work_rows,
)
from tests.test_xss_proof_fidelity import _install_fake_browser

NEVER_FIRES = "a-marker-that-never-fires"




def _settle(receipt):
    status, reason = PostgresScanExecutionBackend._receipt_outcome(
        object.__new__(PostgresScanExecutionBackend), receipt)
    return Status(status.value), (Reason(reason.value) if reason is not None else None)


def _browser_proof_receipt(monkeypatch, status):
    # The browser capability the Scan dispatcher runs gets the fake page and proxy.
    page, _seen = _install_fake_browser(
        monkeypatch, requires_auth=False, status=status, modules=(scan_browser,),
    )
    page.marker = NEVER_FIRES
    monkeypatch.setattr(scan_browser, "XSS_PROOF_SETTLE_SECONDS", 0)
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [{
                "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
                "normalized_path": "/", "concrete_path": "/", "query_keys": [],
                "browser_fragment_path": "/search", "browser_fragment_query_keys": ["q"],
                "source": "web.browser_crawl",
            }],
        },
        source_action_ids=("discover.browser_crawl",),
    )
    candidates = build_candidate_manifest(endpoints, source_action_ids=("discover.browser_crawl",), maximum=10)
    assert len(candidates.entries) == 1
    action = replace(_action(
        "prove.xss", "xss.browser_prove_batch", 0,
        capability_args={
            "candidate_manifest_ref": candidates.reference().canonical_dict(),
            "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
            "slice": {"start": 0, "count": 1},
        },
    ), action_digest=None, requested_budget={
        "browser_actions": 20, "http_requests": 200, "tool_wall_seconds": 200,
    })
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=(action,))
    backend = Backend(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates})
    return asyncio.run(_dispatcher(
        plan, backend, policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
    )(action, _lease(plan, action), _noop))


def _xss_family(receipt):
    status, reason = _settle(receipt)
    passive, passive_result, passive_rows = _companion_that_worked("xss")
    verifier = _planned_slice("verify.family", "xss.verify_batch", 1)
    proof = _planned_slice("prove.family", "xss.browser_prove_batch", 2, required=False)
    # The reflection Dalfox flagged with its headless check off: only the browser proof promotes it.
    reflected = ({"kind": "xss_alert", "candidate_id": "c-0", "alert_type": "R",
                  "url": "https://app.example.test/search", "param": "q", "proof_state": "candidate"},)
    verifier_rows = (*_work_rows(verifier), *reflected)
    proof_rows = tuple(dict(item) for item in receipt.observations)
    report, row = _finalize(
        (passive, verifier, proof),
        {passive.action_id: passive_result,
         verifier.action_id: _result_with_observation_count(verifier, len(verifier_rows)),
         proof.action_id: _settled(proof, status, reason, proof_rows)},
        {passive.action_id: passive_rows, verifier.action_id: verifier_rows, proof.action_id: proof_rows},
        "xss",
    )
    return status, reason, report, row


@pytest.mark.parametrize("status", [503, 429, 404])
def test_a_scan_whose_proof_page_was_not_served_reads_partial_with_the_reason(monkeypatch, status):
    receipt = _browser_proof_receipt(monkeypatch, status)
    navigations = [item for item in receipt.observations if item.get("kind") == "browser_navigation"]
    assert [item["status_code"] for item in navigations] == [status]  # the proof really ran

    settled, reason, report, row = _xss_family(receipt)

    assert row["coverage_status"] == "partial", row
    assert row["reason"] == "proof_attempts_unresolved"
    assert row["proof_escalation"]["unresolved_candidates"] == 1
    assert "xss" in report["coverage"]["selected_family_gaps"]
    assert report["coverage"]["status"] != "complete"
    assert report["result"]["grade_reliable"] is False
    # The proof action names why, in its own result and the escalation's.
    assert settled is Status.PARTIAL
    assert reason is not None and reason.value == "target_unavailable"
    assert row["proof_escalation"]["reason"] == "target_unavailable"


def test_a_scan_whose_proof_page_loaded_without_running_the_payload_reads_complete(monkeypatch):
    receipt = _browser_proof_receipt(monkeypatch, 200)

    settled, reason, report, row = _xss_family(receipt)

    assert (settled, reason) == (Status.SUCCESS, None)
    assert row["coverage_status"] == "complete", row
    assert row["proof_escalation"]["unresolved_candidates"] == 0
    assert report["result"]["grade_reliable"] is True


def _sqli_proof_receipt(monkeypatch, control, payload):
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={"schema_version": "endpoint-manifest/v2", "status": "complete",
                          "reason": None, "endpoints": [{
                              "method": "GET", "scheme": "https", "host": "app.example.test",
                              "port": 443, "normalized_path": "/users/{int}",
                              "concrete_path": "/users/1", "query_keys": [],
                              "source": "web.spec_ingest"}]},
        source_action_ids=("discover.spec",))
    candidates = build_candidate_manifest(endpoints, source_action_ids=("discover.spec",), maximum=10)
    candidate = candidates.entries[0]
    dependency = _action("verify.sqli.00000", "sqli.verify_batch", 0)
    action = _action("prove.sqli.00000", "sqli.prove_batch", 1,
                     dependencies=(dependency.action_id,), capability_args={
                         "candidate_manifest_ref": candidates.reference().canonical_dict(),
                         "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
                         "slice": {"start": 0, "count": 1}})
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=(dependency, action))
    backend = Backend(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates},
                      observations={dependency.action_id: ({
                          "kind": "candidate_attempt", "candidate_id": candidate["candidate_id"],
                          "proof_state": "suspected"},)})
    statuses: list[int] = []

    class Transport:
        async def send(self, request, **_kwargs):
            value = urllib.parse.unquote(urllib.parse.urlsplit(request.url).path.rsplit("/", 1)[-1])
            status = control if value == "1" else payload
            statuses.append(status)
            return ReplayTransportResult(
                status_code=status, connected_address="192.0.2.10", final_url=request.url,
                response_headers={"Content-Type": "text/html"},
                response_body=b"<p>Service Unavailable</p>", elapsed_ms=5)

    monkeypatch.setattr(action_adapter_module.DatabaseNeutralScanActionDispatcher,
                        "_scan_replay_transport", lambda *a, **kw: Transport())
    receipt = asyncio.run(_dispatcher(
        plan, backend, policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
    )(action, _lease(plan, action), _noop))
    assert statuses  # the proof really sent its requests
    return receipt


def _sqli_family(receipt):
    status, reason = _settle(receipt)
    passive, passive_result, passive_rows = _companion_that_worked("sqli")
    verifier = _planned_slice("verify.family", "sqli.verify_batch", 1)
    proof = _planned_slice("prove.family", "sqli.prove_batch", 2, required=False)
    proof_rows = tuple(dict(item) for item in receipt.observations)
    report, row = _finalize(
        (passive, verifier, proof),
        {passive.action_id: passive_result,
         verifier.action_id: _result_with_observation_count(verifier, 3),
         proof.action_id: _settled(proof, status, reason, proof_rows)},
        {passive.action_id: passive_rows, verifier.action_id: _work_rows(verifier),
         proof.action_id: proof_rows},
        "sqli",
    )
    return status, reason, report, row


def test_a_scan_whose_sqli_proof_met_an_unavailable_service_reads_partial(monkeypatch):
    settled, reason, report, row = _sqli_family(_sqli_proof_receipt(monkeypatch, 503, 503))

    assert row["coverage_status"] == "partial", row
    assert row["reason"] == "proof_attempts_unresolved"
    assert row["proof_escalation"]["unresolved_candidates"] == 1
    assert "sqli" in report["coverage"]["selected_family_gaps"]
    assert report["result"]["grade_reliable"] is False
    assert settled is Status.PARTIAL
    assert reason is not None and reason.value == "target_unavailable"


def test_a_scan_whose_sqli_proof_route_answered_reads_complete(monkeypatch):
    settled, reason, report, row = _sqli_family(_sqli_proof_receipt(monkeypatch, 200, 200))

    assert (settled, reason) == (Status.SUCCESS, None)
    assert row["coverage_status"] == "complete", row
    assert row["proof_escalation"]["unresolved_candidates"] == 0
    assert report["result"]["grade_reliable"] is True
