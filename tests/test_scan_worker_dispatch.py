from __future__ import annotations

from pathlib import Path

from runtime.models import ScanBudget, ScanPolicy
from scan.execution import ScanExecutionPlan
from scan.jobs import ScanShardAuthority, ScanShardBudget, scan_job_options_digest
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
        "browser_max_pages": 200,
        "api_probe_limit": 2000,
        "phase4_max_seconds": 900,
        "nuclei_max_targets": 2000,
        "active_worklist_max": 2000,
        "active_max_seconds": 900,
        "active_max_endpoints": 2000,
    }
    assert prepared["max_workers"] == 4
    assert prepared["allow_state_changing_http"] is True
    assert prepared["include_families"] == ["xss", "sqli"]
    assert prepared["_v2_worker_authority"]["plan_digest"] == admission.plan.digest
    assert prepared["_v2_worker_authority"]["executor"] == "native_fixed_stage"
    assert "backing_scan_type" not in prepared["_v2_worker_authority"]


def test_caller_legacy_tuning_cannot_expand_canonical_budget():
    options = _options(_plan(active=True))
    options["custom_budget"] = {
        "max_duration_minutes": 2880,
        "request_max": 1_000_000,
        "browser_max_pages": 2000,
        "nuclei_max_targets": 100_000,
        "active_max_endpoints": 10_000,
    }
    options["parallel_worker_count"] = 99
    prepared, _admission = prepare_worker_dispatch(options)
    assert prepared["custom_budget"]["max_duration_minutes"] == 20
    assert prepared["custom_budget"]["request_max"] == 5000
    assert prepared["custom_budget"]["browser_max_pages"] == 200
    assert prepared["custom_budget"]["nuclei_max_targets"] == 2000
    assert prepared["custom_budget"]["active_max_endpoints"] == 2000
    assert prepared["parallel_worker_count"] == 4


def test_canonical_shard_dispatch_uses_its_sub_budget_not_the_parent_budget():
    plan = _plan(active=True)
    options = _options(plan)
    options["custom_budget"] = {"request_max": 120, "max_urls": 30}
    authority = ScanShardAuthority(
        parent_scan_id="scan-parent",
        parent_execution_plan_digest=plan.digest,
        options_digest=scan_job_options_digest(options),
        shard_index=0,
        shard_count=2,
        shard_label="coverage[0]",
        sub_budget=ScanShardBudget(120, 120, 30, 4, 100, 50, 1),
    )
    options["canonical_shard_authority"] = authority.payload()

    prepared, admission = prepare_worker_dispatch(options)

    assert admission.canonical is True
    assert prepared["custom_budget"]["request_max"] == 120
    assert prepared["custom_budget"]["max_urls"] == 30
    assert prepared["custom_budget"]["browser_max_pages"] == 4
    assert prepared["max_workers"] == 1
    assert prepared["_v2_worker_authority"]["parent_scan_id"] == "scan-parent"


def test_canonical_shard_dispatch_allows_worker_only_credential_hydration_after_validation():
    plan = _plan()
    options = _options(plan)
    authority = ScanShardAuthority(
        parent_scan_id="scan-parent",
        parent_execution_plan_digest=plan.digest,
        options_digest=scan_job_options_digest(options),
        shard_index=0,
        shard_count=2,
        shard_label="auth:authed",
        sub_budget=ScanShardBudget(120, 120, 30, 4, 100, 50, 1),
    )
    options["canonical_shard_authority"] = authority.payload()
    options["auth_header"] = "Bearer hydrated-only-in-worker-memory"

    prepared, admission = prepare_worker_dispatch(options)

    assert admission.canonical is True
    assert prepared["auth_header"] == "Bearer hydrated-only-in-worker-memory"
    assert prepared["max_workers"] == 1


def test_passive_dispatch_uses_same_engine_with_passive_backing():
    prepared, admission = prepare_worker_dispatch(_options(_plan()))
    assert admission.plan.engine == "scan"
    assert prepared["scan_type"] == "deep"
    assert prepared["active"] is False
    assert "active_max_seconds" not in prepared["custom_budget"]


def test_result_metadata_is_canonical_and_legacy_is_untouched():
    plan = _plan()
    admission = WorkerScanAdmission(True, "deep", plan)
    metadata = execution_result_metadata(admission)
    assert metadata["engine"] == "scan"
    assert metadata["plan_digest"] == plan.digest
    assert metadata["executor"]["name"] == "native_fixed_stage"
    assert "compatibility" not in metadata
    assert execution_result_metadata(WorkerScanAdmission(False, "standard")) is None


def test_non_dast_run_kinds_bypass_scan_admission():
    assert is_deterministic_dast({"run_kind": "web_dast"}) is True
    assert is_deterministic_dast({"run_kind": "device_posture"}) is False
    assert is_deterministic_dast({"run_kind": "model_intake"}) is False


def test_primary_worker_owns_v2_admission_without_a_monkeypatch_wrapper():
    root = Path(__file__).resolve().parents[1]
    source = (root / "api" / "worker.py").read_text()
    start = source.index("async def run_scan(")
    end = source.index("\n\nasync def run_discovery", start)
    run_scan = source[start:end]

    assert "prepare_worker_dispatch(options)" in run_scan
    assert "execution_result_metadata" in source
    assert "_finalize_deterministic_scan_result(" in run_scan
    assert not (root / "api" / "worker_v2.py").exists()
    entrypoint = (root / "scanner" / "entrypoint.sh").read_text()
    assert "/app/worker_v2.py" not in entrypoint


def test_primary_worker_materializes_scan_job_v2_before_scope_and_freshness_checks():
    root = Path(__file__).resolve().parents[1]
    source = (root / "api" / "worker.py").read_text()
    start = source.index("async def process_job(")
    end = source.index("\n\ndef _mark_worker_processing_lease", start)
    handler = source[start:end]

    materialize = handler.index("_materialize_scan_job_v2")
    scope = handler.index("_revalidate_job_execution_scope")
    freshness = handler.index("_refuse_stale_job_if_needed")
    assert materialize < scope < freshness
    assert handler.count("_safe_requeue_payload(job_data)") == 3


def test_parallel_parent_fallback_requeues_canonical_scan_authority():
    root = Path(__file__).resolve().parents[1]
    source = (root / "api" / "worker.py").read_text()
    start = source.index("async def process_scan_plan_job(")
    end = source.index("\n\nasync def process_scan_shard_job", start)
    handler = source[start:end]
    fallback = handler[handler.index("# Not worth parallelizing"):]

    assert 'canonical_source = job_data.get("_canonical_queue_payload")' in fallback
    assert "CanonicalScanJob.from_queue_payload(canonical_source)" in fallback
    assert "standalone_payload = parent_job.queue_payload(" in fallback
    assert "enqueue_job(r, QUEUE_NAME, standalone_payload)" in fallback
