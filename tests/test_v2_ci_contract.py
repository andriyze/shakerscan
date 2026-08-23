from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "v2-contracts.yml"


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_v2_workflow_watches_runtime_scanner_and_gate_paths():
    text = _workflow_text()

    for path in (
        "api/capabilities/**",
        "api/agent_tools.py",
        "api/hunt/capability_executor.py",
        "api/parallel_scan.py",
        "api/broker_worker.py",
        "api/broker_worker_v2.py",
        "api/scan/**",
        "api/worker.py",
        "scanner/scanner.py",
        "scanner/scanner_tools/**",
        "scripts/release_gates.py",
        "tests/test_scan_*.py",
        "tests/test_hunt_*.py",
        "tests/test_*capability*.py",
        "tests/test_*adapter*.py",
        "tests/test_parallel_*.py",
        "tests/test_request_meter.py",
        "tests/test_subprocess_receipts.py",
        "tests/test_worker_scan_ai_gating.py",
        "tests/test_api_scan_option_masking.py",
        "tests/test_api_helpers.py",
        "tests/**",
    ):
        assert text.count(f"- {path}") >= 2, path


def test_v2_workflow_executes_new_runtime_contracts_and_release_gates():
    text = _workflow_text()

    for test_file in (
        "tests/test_scan_executor.py",
        "tests/test_scan_stage_scheduler.py",
        "tests/test_scan_capability_execution.py",
        "tests/test_external_process_budget.py",
        "tests/test_scan_action_plan.py",
        "tests/test_scan_action_compiler.py",
        "tests/test_scan_action_store.py",
        "tests/test_scan_capability_result.py",
        "tests/test_scan_orchestrator.py",
        "tests/test_scan_action_resume.py",
        "tests/test_worker_action_executor.py",
        "tests/test_scan_work_manifests.py",
        "tests/test_observation_manifests.py",
        "tests/test_observation_store.py",
        "tests/test_scan_placement_transport.py",
        "tests/test_deterministic_scan_execution_adapter.py",
        "tests/test_broker_scan_execution.py",
        "tests/test_broker_worker.py",
        "tests/test_canonical_tls_runtime.py",
        "tests/test_scan_subdomain_discovery.py",
        "tests/test_capability_executor.py",
        "tests/test_hunt_browser_capability.py",
        "tests/test_hunt_scanner_reservations.py",
        "tests/test_legacy_hunt_isolation.py",
        "tests/test_inline_capability_adapters.py",
        "tests/test_replay_capability_adapter.py",
        "tests/test_scanner_execution_adapter.py",
        "tests/test_request_meter.py",
        "tests/test_network_capabilities.py",
        "tests/test_scanner_fixed_budget_adapter.py",
        "tests/test_pinned_socks_proxy.py",
        "tests/test_subprocess_receipts.py",
        "tests/test_parallel_scan.py",
        "test_canonical_options_builder_erases_legacy_identity_and_uses_plan_budget",
        "test_canonical_schedule_queues_scan_job_v2_without_legacy_identity",
        "test_run_scan_uses_native_fixed_stage_contract_for_canonical_plan",
        "test_canonical_shard_builder_emits_secret_free_v2_queue_authority",
        "test_primary_api_parses_typed_native_hunt_start",
        "test_primary_api_preserves_policy_profile_alias_when_budget_profile_is_omitted",
        "test_primary_api_documents_the_native_hunt_request_and_response_models",
        "test_primary_api_rejects_legacy_hunt_start_without_migration_flag",
        "test_primary_api_rejects_legacy_hunt_start_even_with_old_override_env",
        "test_native_hunt_start_persists_exact_contract_and_capability_allowlist",
    ):
        assert test_file in text, test_file
    assert "python scripts/release_gates.py" in text
    assert "api/hunt/capability_executor.py" in text
    assert (ROOT / "api" / "hunt" / "capability_executor.py").is_file()


def test_v2_workflow_is_valid_yaml_with_required_contract_build_and_full_suite_jobs():
    workflow = yaml.safe_load(_workflow_text())

    assert workflow["name"] == "V2 migration contracts"
    assert set(workflow["jobs"]) == {"contracts", "complete-python", "images-api-ui"}
    steps = workflow["jobs"]["contracts"]["steps"]
    assert len([step for step in steps if "run" in step]) >= 10
    text = _workflow_text()
    assert "--collect-only" in text
    assert "--junitxml=artifacts/v2-full-python.xml" in text
    assert "--cov-report=xml:artifacts/v2-coverage.xml" in text
    assert "docker compose build" in text
    assert "scripts/docker_api_overlay_smoke.sh" in text
    assert "npm --prefix ui run build" in text
