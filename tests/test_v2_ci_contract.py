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
        "api/scan/**",
        "api/worker.py",
        "scanner/scanner.py",
        "scanner/scanner_tools/**",
        "scripts/upgrade_smoke.sh",
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
        "ui/**",
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
        "tests/test_scan_fault_injection.py",
        "tests/test_scan_detection_parity.py",
        "tests/test_scan_security_invariants.py",
        "tests/test_scan_secret_surface_canary.py",
        "tests/test_scan_legacy_execution_removed.py",
        "tests/test_scan_compatibility_sunset.py",
        "tests/test_scan_operational_metrics.py",
        "tests/test_scan_action_resume.py",
        "tests/test_worker_action_executor.py",
        "tests/test_scan_authorization_revalidation.py",
        "tests/test_scan_dns_rebinding.py",
        "tests/test_scan_finalizer.py",
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
        "test_run_scan_rejects_monolithic_deterministic_execution",
        "test_canonical_shard_builder_emits_secret_free_v2_queue_authority",
        "test_primary_api_parses_typed_native_hunt_start",
        "test_primary_api_preserves_policy_profile_alias_when_budget_profile_is_omitted",
        "test_hunt_router_documents_the_native_request_and_response_models",
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
    assert set(workflow["jobs"]) == {
        "changes", "contracts", "complete-python", "ui-contract", "images-api-ui",
    }
    assert workflow["jobs"]["contracts"]["if"] == (
        "needs.changes.outputs.backend == 'true'"
    )
    assert workflow["jobs"]["complete-python"]["if"] == (
        "needs.changes.outputs.backend == 'true'"
    )
    assert workflow["jobs"]["ui-contract"]["if"] == (
        "needs.changes.outputs.ui == 'true'"
    )
    assert (
        workflow["jobs"]["images-api-ui"]["if"]
        == "github.event_name == 'workflow_dispatch'"
    )
    steps = workflow["jobs"]["contracts"]["steps"]
    assert len([step for step in steps if "run" in step]) >= 10
    image_steps = workflow["jobs"]["images-api-ui"]["steps"]
    image_checkout = next(
        step for step in image_steps if step.get("uses") == "actions/checkout@v6"
    )
    assert image_checkout["with"]["fetch-depth"] == 0
    text = _workflow_text()
    assert "scripts/run_complete_python_suite.py --collect-only" in text
    assert "scripts/run_complete_python_suite.py" in text
    assert "PYTHONPATH=.:api:scanner python -m pytest" in text
    assert "requests==2.34.2" in text
    assert "--coverage --artifacts-dir artifacts" in text
    runner = (ROOT / "scripts" / "run_complete_python_suite.py").read_text()
    assert 'artifacts / "v2-full-python.xml"' in runner
    assert 'artifacts / "v2-coverage.xml"' in runner
    assert "partition_test_files(repo_root)" in runner
    assert "./scanner.sh build" in text
    assert "python -m playwright install --with-deps chromium" in text
    assert "scripts/docker_api_overlay_smoke.sh" in text
    assert "npm --prefix ui run build" in text
    assert "npm --prefix ui run test:unit" in text
    assert "npm --prefix ui run test:browser" in text
    assert "node-version: 24" in text
    assert "python tests/e2e/run_e2e.py" in text
    assert "--area model_intake" in text
    assert "--scorecard artifacts/v2-model-intake-scorecard.json" in text
    assert "name: v2-model-intake-e2e" in text
    assert "python tests/e2e/run_external_wire_acceptance.py --json" in text
    assert "name: external-wire-${{ github.sha }}" in text
    assert "tests/e2e/run_scan_action_resume.py" in text
    assert "name: v2-scan-action-resume" in text


def test_ui_only_prs_run_portable_ui_and_browser_gates_without_backend_suite():
    smoke = (ROOT / ".github" / "workflows" / "e2e-pr.yml").read_text(
        encoding="utf-8",
    )
    release = (ROOT / ".github" / "workflows" / "release-candidate.yml").read_text(
        encoding="utf-8",
    )
    full_e2e = (ROOT / ".github" / "workflows" / "e2e.yml").read_text(
        encoding="utf-8",
    )

    assert 'echo "ui=true" >> "$GITHUB_OUTPUT"' in smoke
    assert "steps.changes.outputs.ui == 'true'" in smoke
    assert "npm --prefix ui run test:unit" in smoke
    assert "npm --prefix ui run test:browser" in smoke
    assert "python3 tests/e2e/run_e2e.py --area hunt" in smoke
    assert "node-version: 24" in smoke
    assert "npm --prefix ui run test:unit" in release
    assert "npm --prefix ui run test:unit" in full_e2e
    assert "npm --prefix ui run test:browser" in full_e2e
    assert 'PLAYWRIGHT_REAL_STACK: "1"' in full_e2e
    assert "artifacts/playwright.json" in full_e2e


def test_release_candidate_requires_candidate_image_external_wire_acceptance():
    text = (ROOT / ".github" / "workflows" / "release-candidate.yml").read_text(
        encoding="utf-8",
    )

    assert "Enforce candidate-image external wire ceilings" in text
    assert "run_external_wire_acceptance.py" in text
    assert "shakerscan-scanner:release-candidate" in text
    assert "source_sha:$source_sha" in text
    assert "name: external-wire-${{ needs.meta.outputs.candidate_sha }}" in text
    wire_runner = (
        ROOT / "tests" / "e2e" / "run_external_wire_acceptance.py"
    ).read_text(encoding="utf-8")
    assert "if args.worker_container is None:" in wire_runner


def test_v2_candidate_acceptance_is_exact_sha_nonpublishing_and_complete():
    path = ROOT / ".github" / "workflows" / "v2-candidate-acceptance.yml"
    text = path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)

    assert workflow["name"] == "V2 candidate acceptance (non-publishing)"
    assert workflow["permissions"] == {"contents": "read"}
    assert set(workflow["jobs"]) == {"accept"}
    assert "refs/heads/v2:refs/remotes/origin/v2" in text
    assert '[[ "$REQUESTED_SHA" =~ ^[0-9a-f]{40}$ ]]' in text
    assert "git merge-base --is-ancestor" in text
    assert text.count("./scanner.sh build") == 1
    assert "SHAKERSCAN_API_OVERLAY_PREBUILT=1" in text
    assert "docker compose up -d --no-build" in text
    assert "run_complete_python_suite.py" in text
    assert "run_external_wire_acceptance.py" in text
    assert "run_scan_cancellation_race.py" in text
    assert "run_scan_reservation_identity.py" in text
    assert "run_scan_action_resume.py" in text
    assert "INSTALLED_STACK_SMOKE_E2E" in text
    assert "run_scan_parity.py" in text
    assert "scripts/upgrade_smoke.sh" in text
    assert "scripts/release_preservation.py" in text
    assert "scripts/write_v2_candidate_acceptance.py" in text
    assert "github.workflow_sha" in text
    assert 'test "$(jq -r \'.publication\'' in text
    assert "docker/login-action" not in text
    assert "docker push" not in text
    assert "build-push-action" not in text
    assert "contents: write" not in text
    assert "packages: write" not in text


def test_package_native_and_installed_runtime_scan_contracts_run_in_isolated_steps():
    workflow = yaml.safe_load(_workflow_text())
    package_step = next(
        item
        for item in workflow["jobs"]["contracts"]["steps"]
        if item.get("name") == "Validate package-native Scan contracts"
    )
    installed_step = next(
        item
        for item in workflow["jobs"]["contracts"]["steps"]
        if item.get("name") == "Validate installed-runtime Scan contracts"
    )

    assert "env" not in package_step
    assert package_step["run"].count("python -m pytest") == 1
    assert installed_step["env"]["PYTHONPATH"] == "api:scanner"
    assert installed_step["run"].count("python -m pytest") == 1
    assert "tests/test_scan_action_plan.py" in package_step["run"]
    assert "tests/test_scan_v2_contract.py" in installed_step["run"]
