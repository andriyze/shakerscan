"""The Scan's browser XSS proof must run under the identity its registry entry declares.

`xss.browser_prove_batch` is registered as the `playwright.xss_proof_batch` runtime, but its
adapter announced itself as plain `playwright`. The capability executor refuses an adapter the
registry does not name, so every Scan proof attempt raised before reaching the browser and the
action settled `adapter_failed`. A reflected XSS that Dalfox only flagged (its headless check is
off in a Scan, so it never reports a verified alert) was then dropped from the report.

Unit fixture: the request shape of a reflected-XSS lab target (GET /search?q, echoed raw into
HTML) with Dalfox's reflected-candidate alert. The browser is a stand-in Playwright runtime; the
capability executor and registry are the real ones, so the identity check is exercised.
"""
from __future__ import annotations

import asyncio
import sys
import uuid

import capabilities.browser as worker_browser
from capabilities.browser import XSSBrowserProofAdapter
from hunt.capability_executor import CapabilityExecutor
from hunt.fragment_xss_proof import HuntXSSBrowserProofAdapter
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import ScanPolicy
from scan.action_plan import ScanActionPlan
from scan.work_manifests import build_candidate_manifest, build_endpoint_manifest

from api.scan.finalizer import finalize_scan_report
from tests.test_scan_action_adapter import (
    TARGET,
    Backend,
    _action,
    _dispatcher,
    _lease,
    _noop,
)
from tests.test_scan_family_coverage import _batch_action, _family
from tests.test_scan_finalizer import _result_with_observation_count
from tests.test_scan_orchestrator import SCAN_ID, _action as _report_action
from tests.test_xss_proof_fidelity import _install_fake_browser


def test_each_browser_xss_prover_carries_an_identity_its_registry_entry_names():
    for adapter in (XSSBrowserProofAdapter, HuntXSSBrowserProofAdapter):
        spec = CAPABILITY_REGISTRY.require(adapter.capability_name)
        assert (adapter.adapter_name, adapter.adapter_version) in spec.adapter_identities(), (
            adapter.__name__
        )
    # The Hunt prover keeps the plain runtime identity its xss.verify alternate declares.
    assert HuntXSSBrowserProofAdapter.adapter_name == "playwright"


def _reflected_search_fixture():
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id,
        target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2",
            "status": "complete",
            "reason": None,
            "endpoints": [{
                "method": "GET", "scheme": "https",
                "host": "app.example.test", "port": 443,
                "normalized_path": "/search", "concrete_path": "/search",
                "query_keys": ["q"], "source": "web.crawl",
            }],
        },
        source_action_ids=("discover.web_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.web_crawl",), maximum=10,
    )
    candidate_id = str(candidates.entries[0]["candidate_id"])
    manifests = {
        "candidate_manifest_ref": candidates.reference().canonical_dict(),
        "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
        "slice": {"start": 0, "count": 1},
    }
    verify = _action("verify.xss.r01", "xss.verify_batch", 0, capability_args={
        **manifests, "profile": "balanced", "proof_policy": "deterministic",
    })
    prove = _action(
        "prove.xss.r01", "xss.browser_prove_batch", 1,
        dependencies=(verify.action_id,), capability_args=manifests,
    )
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(verify, prove),
    )
    # What Dalfox reports for this route with its headless check off: a reflected (R)
    # candidate, never a verified alert, so only the browser proof can promote it.
    dalfox_signal = (
        {
            "kind": "candidate_attempt", "candidate_id": candidate_id,
            "attempt_id": "1" * 64, "family": "xss", "status": "success",
            "proof_state": "candidate",
        },
        {
            "kind": "xss_alert", "candidate_id": candidate_id, "alert_type": "R",
            "url": "https://app.example.test/search", "param": "q",
            "proof_state": "candidate",
        },
    )
    backend = Backend(
        manifests={
            endpoints.manifest_id: endpoints,
            candidates.manifest_id: candidates,
        },
        observations={verify.action_id: dalfox_signal},
    )
    return plan, prove, backend, candidate_id, dalfox_signal


def test_a_dalfox_flagged_reflection_is_proven_in_the_browser_and_reported(monkeypatch):
    plan, prove, backend, candidate_id, dalfox_signal = _reflected_search_fixture()
    page, _seen = _install_fake_browser(monkeypatch, requires_auth=False)
    # The stand-in runtime patches the packaged module; the Scan dispatcher imports the
    # worker-path module, so point it at the same stand-in proxy.
    monkeypatch.setattr(
        worker_browser, "PinnedSocksProxy",
        sys.modules["api.capabilities.browser"].PinnedSocksProxy,
    )
    page.marker = f"shakerscan_xss_{candidate_id[:12]}"
    executed = []
    real_execute = CapabilityExecutor.execute

    async def recording_execute(self, context, adapter, **kwargs):
        executed.append((context.specification.name, adapter.adapter_name))
        return await real_execute(self, context, adapter, **kwargs)

    monkeypatch.setattr(CapabilityExecutor, "execute", recording_execute)

    receipt = asyncio.run(_dispatcher(
        plan, backend,
        policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
    )(prove, _lease(plan, prove), _noop))

    assert executed == [("xss.browser_prove_batch", "playwright.xss_proof_batch")]
    assert receipt.status == "success", receipt.errors
    assert not [error for error in receipt.errors if "adapter_fault" in str(error)]
    proof = next(
        item for item in receipt.observations if item.get("kind") == "xss_browser_proof"
    )
    assert proof["proof_state"] == "verified"
    assert proof["candidate_id"] == candidate_id
    attempts = list(backend.attempts[prove.action_id].values())
    assert [item["status"] for item in attempts] == ["success"]

    # The proven candidate becomes the report's verified finding.
    verify = _batch_action("verify.xss.r01", "xss.verify_batch", 0, count=1)
    proof_action = _batch_action(
        "prove.xss.r01", "xss.browser_prove_batch", 1, count=1, required=False,
    )
    final = _report_action(
        "finalize.report", 2, dependencies=(verify.action_id, proof_action.action_id),
    )
    report_plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(verify, proof_action, final),
    )
    report = finalize_scan_report(
        plan=report_plan, target_url="https://app.example.test",
        action_results={
            verify.action_id: _result_with_observation_count(verify, len(dalfox_signal)),
            proof_action.action_id: _result_with_observation_count(
                proof_action, len(receipt.observations),
            ),
        },
        observations={
            verify.action_id: dalfox_signal,
            proof_action.action_id: tuple(receipt.observations),
        },
    )
    titles = [item["title"] for item in report["findings"]]
    assert "Verified cross-site scripting" in titles
    row = _family(report, "xss")
    assert row["verified_findings"] == 1
    assert row["proof_escalation"]["status"] == "complete"
