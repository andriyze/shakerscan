from __future__ import annotations

from runtime.models import ScanBudget, ScanPolicy
from scan.execution import ScanExecutionPlan
from scan.worker_contract import WorkerScanAdmission
from scan.worker_dispatch import (
    execution_result_metadata,
    is_deterministic_dast,
    prepare_worker_dispatch,
)


def _plan(*, active: bool = False) -> ScanExecutionPlan:
    return ScanExecutionPlan(
        policy=ScanPolicy(
            active_testing=active,
            allow_state_changing_http=active,
            network_discovery=active,
            subdomain_discovery=True,
            include_families=("xss", "sqli"),
            approval_receipt_id="approval-1" if active else None,
        ),
        budget_profile="balanced",
        budget=ScanBudget(1200, 5000, 2000, 200, 5000, 900, 4),
    )


def _options(plan: ScanExecutionPlan) -> dict:
    metadata = plan.option_metadata()
    metadata["scan_compatibility"] = {
        "legacy_executor_alias": "full" if plan.policy.active_testing else "deep",
        "temporary": True,
    }
    metadata["scan_type"] = "full" if plan.policy.active_testing else "deep"
    metadata["active"] = plan.policy.active_testing
    metadata["network_discovery"] = plan.policy.network_discovery
    metadata["subfinder"] = plan.policy.subdomain_discovery
    return metadata


def test_canonical_dispatch_maps_plan_budget_and_families():
    prepared, admission = prepare_worker_dispatch(_options(_plan(active=True)))
    assert admission.canonical is True
    assert prepared["scan_type"] == "full"
    assert prepared["custom_budget"] == {
        "max_duration_minutes": 20,
        "request_max": 5000,
        "max_urls": 2000,
    }
    assert prepared["include_families"] == ["xss", "sqli"]
    assert prepared["_v2_worker_authority"]["plan_digest"] == admission.plan.digest


def test_passive_dispatch_uses_same_engine_with_passive_backing():
    prepared, admission = prepare_worker_dispatch(_options(_plan()))
    assert admission.plan.engine == "scan"
    assert prepared["scan_type"] == "deep"
    assert prepared["active"] is False


def test_result_metadata_is_canonical_and_legacy_is_untouched():
    plan = _plan()
    admission = WorkerScanAdmission(True, "deep", plan)
    metadata = execution_result_metadata(admission)
    assert metadata["engine"] == "scan"
    assert metadata["plan_digest"] == plan.digest
    assert execution_result_metadata(WorkerScanAdmission(False, "standard")) is None


def test_non_dast_run_kinds_bypass_scan_admission():
    assert is_deterministic_dast({"run_kind": "web_dast"}) is True
    assert is_deterministic_dast({"run_kind": "device_posture"}) is False
    assert is_deterministic_dast({"run_kind": "model_intake"}) is False
