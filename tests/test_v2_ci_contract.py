"""Each test runs once per change: the suite pre-merge, the stack acceptance on final images.

`v2-contracts.yml` used to re-run hand-picked slices of the Python suite and the UI checks on every
pull request, the candidate `validate` job ran the complete suite a third time inside the image,
and `certify` ran the E2E areas the PR smoke had already run. These contracts pin the single place
each check now lives.
"""

from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def _text(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def _yaml(name: str) -> dict:
    return yaml.safe_load(_text(name))


def test_the_complete_python_suite_is_a_required_pre_merge_check_only():
    suite = _yaml("python-suite.yml")
    triggers = suite.get("on", suite.get(True))
    assert "pull_request" in triggers
    assert triggers["push"]["branches"] == ["main"]
    text = _text("python-suite.yml")
    assert "scripts/run_complete_python_suite.py --artifacts-dir artifacts" in text
    assert "--require-hashes" in text
    assert "python -m playwright install --with-deps chromium" in text
    for static_gate in (
        "scripts/generate_capability_inventory.py --check",
        "scripts/generate_install_manifest.py --check",
        "scripts/generate_scan_contract.py --check",
        "scripts/generate_hunt_contract.py --check",
        "scripts/check_installed_import_closure.py",
        "scripts/check_module_size.py",
        "scripts/check_documentation_policy.py",
        "scripts/check_surface_dispositions.py",
        "scripts/check_scan_target_transport.py",
    ):
        assert static_gate in text, static_gate
    assert "name: python-suite-${{ github.event.pull_request.head.sha || github.sha }}" in text


def test_v2_contracts_workflow_is_manual_stack_acceptance_only():
    workflow = _yaml("v2-contracts.yml")
    triggers = workflow.get("on", workflow.get(True))
    assert set(triggers) == {"workflow_dispatch"}, "nothing here may run on a pull request any more"
    assert set(workflow["jobs"]) == {"images-api-ui"}
    text = _text("v2-contracts.yml")
    assert "python -m pytest" not in text
    assert "scripts/run_complete_python_suite.py" not in text
    assert "scripts/release_gates.py" not in text
    assert "./scanner.sh build" in text
    assert "scripts/docker_api_overlay_smoke.sh" in text
    assert "python tests/e2e/run_external_wire_acceptance.py --json" in text
    assert "tests/e2e/run_scan_action_resume.py" in text
    assert "--area model_intake" in text
    image_checkout = next(
        step for step in workflow["jobs"]["images-api-ui"]["steps"]
        if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    assert len(image_checkout["uses"].split("@", 1)[1]) == 40
    assert image_checkout["with"]["fetch-depth"] == 0


def test_pr_smoke_runs_fast_areas_and_browser_once_and_skips_unrelated_changes():
    smoke = _text("e2e-pr.yml")
    assert 'echo "ui=true" >> "$GITHUB_OUTPUT"' in smoke
    assert 'echo "backend=true" >> "$GITHUB_OUTPUT"' in smoke
    assert "steps.changes.outputs.stack == 'true'" in smoke
    areas_step = smoke[smoke.index("Run the fast deterministic E2E areas"):]
    assert "if: steps.changes.outputs.backend == 'true'" in areas_step[:200]
    assert "python3 tests/e2e/run_e2e.py --area platform" in smoke
    assert "python3 tests/e2e/run_e2e.py --area ai_gate" in smoke
    assert "python3 tests/e2e/run_e2e.py --area hunt" in smoke
    # The slow areas run once, on the final images, in certification.
    assert "--area all" not in smoke
    assert "--area dast" not in smoke
    assert "--area model_intake" not in smoke
    assert "--profile e2e" not in smoke
    assert "SHAKERSCAN_RELEASE_DECLARED_DEBT" in smoke
    assert "npm --prefix ui run test:unit" in smoke
    assert "npm --prefix ui run build" in smoke
    assert "npm --prefix ui run test:browser" in smoke
    assert "scripts/run_complete_python_suite.py" not in smoke
    assert "node-version: 26" in smoke


def test_candidate_validate_reuses_the_main_suite_report_instead_of_rerunning():
    release = _text("release-candidate.yml")
    assert "Reuse the exact-source contract report from the required main check" in release
    assert 'gh run list --workflow=python-suite.yml --branch main --commit "$CANDIDATE_SHA"' in release
    assert 'gh run download "$run_id" -n "python-suite-${CANDIDATE_SHA}"' in release
    # The in-image run survives only as the fallback for a metadata-only merge.
    assert release.count("scripts/run_complete_python_suite.py") == 1
    assert "scripts/release_gates.py" not in release
    assert "npm --prefix ui run test:unit" not in release
    assert "npm --prefix ui run build" not in release[:release.index("build-runtime:")]
    assert "npm --prefix ui audit --omit=dev --audit-level=high" in release
    assert "make installed-stack-smoke" in release
    assert "INSTALLED_STACK_SMOKE_E2E" in release


def test_installed_stack_smoke_forwards_its_random_api_port_to_the_cli():
    smoke = (ROOT / "scripts" / "installed_stack_smoke.sh").read_text(encoding="utf-8")
    invocation = smoke[smoke.index('SHAKERSCAN_API="http://127.0.0.1:$API_PORT"'):]
    assert 'SHAKERSCAN_API_PORT="$API_PORT"' in invocation[:500]
    assert 'SHAKERSCAN_E2E_CLI="$BIN_DIR/shakerscan"' in invocation[:500]


def test_full_release_e2e_accepts_only_exact_main_candidates():
    text = _text("e2e.yml")
    # The candidate must be reachable from the protected default branch; the historical `v2`
    # integration branch is stale and would reject every current candidate.
    assert 'description: "Exact approved commit SHA on main"' in text
    assert "refs/heads/main:refs/remotes/origin/main" in text
    assert 'git merge-base --is-ancestor "$candidate_sha" origin/main' in text
    assert "origin/v2" not in text


def test_release_candidate_requires_candidate_image_external_wire_acceptance():
    text = _text("release-candidate.yml")
    assert "Enforce candidate-image external wire ceilings" in text
    assert "python tests/e2e/run_external_wire_acceptance.py" in text
    assert '--worker-container "$worker_name" --json' in text
    assert "artifacts/release-external-wire.json" in text
    assert 'test "$(jq -r \'.status\' artifacts/release-external-wire.json)" = passed' in text
    assert 'test "$(jq -r \'.tool_count\' artifacts/release-external-wire.json)" = 9' in text
