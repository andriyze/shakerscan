"""A Scan policy that selects no check family is refused, and never graded clean (soak N27).

Soak probe 89770439 posted ``policy: {include_families: [], exclude_families: ["recon",
"nuclei_passive"]}``. It was admitted, resolved to no family, ran only the baseline probes for
9 seconds and was graded A 100 with coverage "complete". Only the custom preset refused an
empty set; excluding every family of the passive or standard preset slipped through.
"""

from __future__ import annotations

import asyncio

import pytest

from api.scan import read_router
from api.scan.contracts import resolve_scan_contract


@pytest.mark.parametrize("policy", [
    {"include_families": [], "exclude_families": ["recon", "nuclei_passive", "sensitive_exposure"]},
    {"preset": "passive", "exclude_families": ["nuclei_passive", "recon", "sensitive_exposure"]},
    {
        "active_testing": True,
        "exclude_families": ["recon", "nuclei_passive", "xss", "sqli", "sensitive_exposure"],
    },
])
def test_a_policy_that_excludes_every_family_is_refused(policy):
    with pytest.raises(ValueError, match="removes every family of the"):
        resolve_scan_contract(budget_profile="balanced", policy=policy)


def test_excluding_some_families_is_still_admitted():
    contract = resolve_scan_contract(
        budget_profile="balanced", policy={"exclude_families": ["nuclei_passive"]},
    )
    assert contract.execution_plan.resolved_families == ("recon", "sensitive_exposure")
    # The soak probe's exclusions no longer empty the passive preset: its read-only
    # exposure checks still run, so the Scan examines something and is admitted.
    soak = resolve_scan_contract(
        budget_profile="balanced",
        policy={"include_families": [], "exclude_families": ["recon", "nuclei_passive"]},
    )
    assert soak.execution_plan.resolved_families == ("sensitive_exposure",)


def test_the_preview_refuses_it_with_a_precise_422():
    with pytest.raises(read_router.HTTPException) as refused:
        asyncio.run(read_router.preview_scan_contract(
            read_router.ScanFamilyPreviewRequest(
                preset="passive",
                exclude_families=["recon", "nuclei_passive", "sensitive_exposure"],
            )
        ))
    assert refused.value.status_code == 422
    assert refused.value.detail == (
        "exclude_families removes every family of the passive preset "
        "(nuclei_passive, recon, sensitive_exposure); select at least one family"
    )


def test_submission_maps_the_refusal_to_422():
    # POST /scans resolves the contract and maps its ValueError to 422 with the message.
    from tests.api_sources import definition_source

    source = definition_source("_submit_scan")
    assert "scan_contract = resolve_scan_contract(" in source
    assert "raise HTTPException(status_code=422, detail=str(exc)) from exc" in source


def test_a_stored_plan_with_no_family_never_reads_as_a_clean_complete_scan():
    from api.scan.action_plan import ScanActionPlan
    from api.scan.capability_result import CapabilityResultStatus
    from api.scan.finalizer import finalize_scan_report
    from tests.test_scan_orchestrator import SCAN_ID, _action, _result

    # The 89770439 shape: the always-compiled probe and the baseline, nothing from a family,
    # under an execution plan that resolved no family.
    probe = _action("discover.web_probe", 0, capability_name="web.probe")
    baseline = _action("baseline.http", 1)
    final = _action("finalize.report", 2, dependencies=(probe.action_id, baseline.action_id))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(probe, baseline, final),
    )
    results = {
        probe.action_id: _result(probe, status=CapabilityResultStatus.SUCCESS),
        baseline.action_id: _result(baseline, status=CapabilityResultStatus.SUCCESS),
    }
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results=results, observations={}, resolved_families=(),
    )
    coverage = report["coverage"]
    assert coverage["status"] == "partial"
    assert "no_families_selected" in coverage["reasons"]
    assert coverage["grade_reliability"]["reliable"] is False
    assert "no_families_selected" in coverage["grade_reliability"]["reasons"]
    assert report["scan_metadata"]["grade_reliable"] is False

    # A plan that resolved a family, or a caller without the execution plan, is unaffected.
    for families in (("recon",), None):
        clean = finalize_scan_report(
            plan=plan, target_url="https://app.example.test",
            action_results=results, observations={}, resolved_families=families,
        )
        assert "no_families_selected" not in clean["coverage"]["reasons"]
        assert "no_families_selected" not in clean["coverage"]["grade_reliability"]["reasons"]


def test_the_worker_hands_the_finalizer_its_resolved_families(monkeypatch):
    import asyncio as _asyncio
    from types import SimpleNamespace

    import api.scan.action_adapter as adapter_module

    seen = {}

    def finalize(**kwargs):
        seen.update(kwargs)
        return {"report_digest": "0" * 64}

    monkeypatch.setattr(adapter_module, "finalize_scan_report", finalize)

    class Backend:
        async def load_result(self, _action_id):
            return None

    dispatcher = object.__new__(adapter_module.DatabaseNeutralScanActionDispatcher)
    dispatcher.plan = SimpleNamespace(actions=(), plan_digest="p" * 64)
    dispatcher.plan_revision = None
    dispatcher.target_url = "https://app.example.test"
    dispatcher.backend = Backend()
    dispatcher.options = {"scan_execution_plan": {"resolved_families": []}}
    dispatcher._private_replay_plans = {}
    dispatcher._private_requests = {}
    dispatcher._receipt = lambda *_args, **_kwargs: "receipt"
    action = SimpleNamespace(action_id="finalize.report")
    assert _asyncio.run(dispatcher._finalize(action)) == "receipt"
    assert seen["resolved_families"] == ()
