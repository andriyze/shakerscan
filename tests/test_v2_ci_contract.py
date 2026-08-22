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
    ):
        assert text.count(f"- {path}") >= 2, path


def test_v2_workflow_executes_new_runtime_contracts_and_release_gates():
    text = _workflow_text()

    for test_file in (
        "tests/test_scan_executor.py",
        "tests/test_scan_stage_scheduler.py",
        "tests/test_scan_capability_execution.py",
        "tests/test_scan_subdomain_discovery.py",
        "tests/test_capability_executor.py",
        "tests/test_hunt_browser_capability.py",
        "tests/test_hunt_scanner_reservations.py",
        "tests/test_inline_capability_adapters.py",
        "tests/test_replay_capability_adapter.py",
        "tests/test_scanner_execution_adapter.py",
        "tests/test_request_meter.py",
        "tests/test_subprocess_receipts.py",
        "tests/test_parallel_scan.py",
        "test_canonical_options_builder_erases_legacy_identity_and_uses_plan_budget",
        "test_canonical_schedule_queues_scan_job_v2_without_legacy_identity",
        "test_run_scan_uses_native_fixed_stage_contract_for_canonical_plan",
        "test_canonical_shard_builder_emits_secret_free_v2_queue_authority",
    ):
        assert test_file in text, test_file
    assert "python scripts/release_gates.py" in text
    assert "api/hunt/capability_executor.py" in text
    assert (ROOT / "api" / "hunt" / "capability_executor.py").is_file()


def test_v2_workflow_is_valid_yaml_with_one_contract_job():
    workflow = yaml.safe_load(_workflow_text())

    assert workflow["name"] == "V2 migration contracts"
    assert set(workflow["jobs"]) == {"contracts"}
    steps = workflow["jobs"]["contracts"]["steps"]
    assert len([step for step in steps if "run" in step]) >= 10
