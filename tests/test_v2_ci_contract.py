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


def test_pr_smoke_runs_every_area_and_browser_once_and_skips_unrelated_changes():
    """The pull request runs the gates that used to kill candidates an hour after merge.

    Between 2.0.0 and 2.2.0, 56 of 60 release candidates failed, and the checks that failed them
    (the final-image vulnerability gate, the installed-stack DAST and Model Intake E2E) ran only in
    certification. The PR check now runs every E2E area on the PR-built stack, against the same
    Juice Shop target certification uses, with only the declared-debt rows tolerated.
    """
    smoke = _text("e2e-pr.yml")
    assert 'echo "ui=true" >> "$GITHUB_OUTPUT"' in smoke
    assert 'echo "backend=true" >> "$GITHUB_OUTPUT"' in smoke
    assert "steps.changes.outputs.stack == 'true'" in smoke
    areas_step = smoke[smoke.index("Run every E2E area on the built stack"):]
    assert "if: steps.changes.outputs.backend == 'true'" in areas_step[:200]
    assert "python3 tests/e2e/run_e2e.py --area all --scorecard artifacts/e2e-scorecard.json" in smoke
    assert "docker compose --profile e2e up -d" in smoke
    assert "SHAKERSCAN_E2E_DAST_TARGET: http://juice-shop:3000" in smoke
    assert "SHAKERSCAN_E2E_HUNT_TARGET: http://juice-shop:3000" in smoke
    assert "SHAKERSCAN_E2E_MODEL_INTAKE_OPERATOR_TOKEN" in smoke
    assert "SHAKERSCAN_RELEASE_DECLARED_DEBT" in smoke
    assert "npm --prefix ui run test:unit" in smoke
    assert "npm --prefix ui run build" in smoke
    assert "npm --prefix ui run test:browser" in smoke
    assert "scripts/run_complete_python_suite.py" not in smoke
    assert "node-version: 26" in smoke


def _steps(workflow_name: str, job_name: str) -> list[dict]:
    import yaml

    document = yaml.safe_load(_text(workflow_name))
    return [step for step in document["jobs"][job_name]["steps"] if isinstance(step, dict)]


def test_pr_smoke_applies_the_candidate_vulnerability_gate_to_the_built_images():
    """The PR image gate and the certification image gate are one policy, pinned in lockstep.

    Certification scans the five final manifests with Trivy; the PR scans the five images it
    just built with the same action, severity, fixed-only rule, exit code, waiver file, and
    per-image skip list. Any drift between the two makes this test fail, so the PR gate cannot
    quietly become weaker than the release gate again.
    """
    certify = next(
        step for step in _steps("release-candidate.yml", "vulnerability-scan")
        if step.get("name") == "Reject high or critical image vulnerabilities"
    )
    matrix = {
        target["name"]: target
        for target in __import__("yaml").safe_load(_text("release-candidate.yml"))
        ["jobs"]["vulnerability-scan"]["strategy"]["matrix"]["target"]
    }
    assert set(matrix) == {"scanner", "api", "model-intake", "ui", "signer"}
    policy_keys = ("format", "severity", "scanners", "ignore-unfixed", "exit-code")
    certify_policy = {key: certify["with"][key] for key in policy_keys}

    smoke_steps = _steps("e2e-pr.yml", "smoke")
    scans = [
        step for step in smoke_steps
        if str(step.get("uses", "")).startswith("aquasecurity/trivy-action@")
    ]
    assert len(scans) == len(matrix)
    for step in scans:
        assert step["uses"] == certify["uses"]
        assert step["if"] == "steps.changes.outputs.stack == 'true'"
        assert {key: step["with"][key] for key in policy_keys} == certify_policy
        image = step["with"]["trivyignores"].removeprefix(".trivyignore-")
        assert image in matrix, image
        assert step["with"]["skip-files"] == matrix[image]["skip_files"]
        assert step["with"]["skip-dirs"] == matrix[image]["skip_dirs"]
        assert step["with"]["output"] == f"trivy-{image}.json"
    resolve = next(step for step in smoke_steps if step.get("id") == "images")
    for image in matrix:
        assert f'--image "$image"' in resolve["run"]
    assert "for image in scanner api model-intake ui signer; do" in resolve["run"]
    assert "security/image-vulnerability-waivers.json" in resolve["run"]
    assert 'skip_files="/usr/local/bin/docker"' in resolve["run"]
    upload = next(step for step in smoke_steps if step.get("name") == "Upload E2E scorecard and browser results")
    assert "trivy-*.json" in upload["with"]["path"]


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


def test_model_intake_trust_anchor_lifecycle_is_a_hard_release_gate():
    e2e = (ROOT / "tests" / "e2e" / "run_e2e.py").read_text(encoding="utf-8")
    readiness = (ROOT / "docs" / "release-readiness.md").read_text(encoding="utf-8")
    lifecycle = e2e[e2e.index("# MI-6A/B/C:"):e2e.index("# MI-7:")]
    assert "sc.xfail" not in lifecycle
    assert 'sc.error("MI-6 durable trust-anchor lifecycle", e)' in lifecycle
    assert "MI-6 durable trust-anchor lifecycle | Ship as release-gated" in readiness


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


def test_platform_pool_gate_requires_always_on_pools_but_not_opt_in_devices():
    """P-4 gates on the three always-on execution pools and never on opt-in device capacity.

    Web DAST, agent-tool, and Model Intake workers start with every stack, so the platform smoke
    requires each of them current and ready. The device worker is opt-in behind a Compose profile,
    so a default `docker compose up -d` legitimately reports the device pool not_ready; requiring it
    ready or disabled failed the pre-merge smoke on exactly that expected state. The device pool must
    be reported with a status but must never gate Web DAST readiness.
    """
    e2e = (ROOT / "tests" / "e2e" / "run_e2e.py").read_text(encoding="utf-8")
    gate = e2e[e2e.index("readiness_deadline = _time.monotonic()"):]
    gate = gate[:gate.index("P-4 Fleet and workers surfaces")]
    assert '"web_dast", "agent_tool", "model_intake"' in gate
    assert 'all(pool.get("current", 0) > 0 and pool.get("status") == "ready" for pool in required_pools)' in gate
    assert 'isinstance(device_pool.get("status"), str)' in gate
    assert 'device_pool.get("status") in {"ready", "disabled"}' not in gate
