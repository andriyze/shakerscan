"""The required PR checks run in parallel shards without dropping any check.

`smoke` (e2e-pr.yml) and `python-suite` (python-suite.yml) used to be single jobs taking ~31 and
~12 minutes. Both now fan out to shard jobs and keep their required job as an aggregator. These
contracts pin what makes that safe: the shards select exactly the work the single job selected,
each piece once; the aggregator fails unless every shard passed; and completeness is still judged
over the union of the shards' evidence.
"""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from scripts.merge_e2e_scorecards import MergeError, merge

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SHARDS = ("dast", "core", "browser", "images")


def _workflow(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def _step(job: dict, name: str) -> dict:
    return next(step for step in job["steps"] if step.get("name") == name)


def _run_e2e_areas() -> list[str]:
    tree = ast.parse((ROOT / "tests" / "e2e" / "run_e2e.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "AREAS" for target in node.targets
        ):
            return [key.value for key in node.value.keys]
    raise AssertionError("run_e2e.py no longer defines AREAS")


def _select(tmp_path, *, shard, event, backend, stack, area):
    step = _step(_workflow("e2e-pr.yml")["jobs"]["smoke-shard"], "Select this shard's work")
    output = tmp_path / f"out-{shard}-{event}-{backend}-{stack}-{area}"
    env = {**os.environ, "SHARD": shard, "EVENT": event, "BACKEND": backend,
           "STACK": stack, "E2E_AREA": area, "GITHUB_OUTPUT": str(output)}
    subprocess.run(["bash", "-e", "-c", step["run"]], env=env, check=True,
                   capture_output=True, timeout=10)
    return dict(line.split("=", 1) for line in output.read_text().splitlines())


def _areas_for(args: str, areas: list[str]) -> list[str]:
    """What run_e2e.py runs for an argument string (its own --area/--exclude-area rules)."""
    tokens = args.split()
    if not tokens:
        return []
    selected = tokens[tokens.index("--area") + 1]
    excluded = {tokens[i + 1] for i, token in enumerate(tokens) if token == "--exclude-area"}
    chosen = areas if selected == "all" else [selected]
    return [area for area in chosen if area not in excluded]


@pytest.mark.parametrize("area", ["all", "platform", "model_intake", "ai_gate", "dast", "hunt"])
def test_pr_smoke_shards_run_each_selected_area_once(area, tmp_path):
    areas = _run_e2e_areas()
    expected = areas if area == "all" else [area]
    ran: list[str] = []
    for shard in SHARDS:
        out = _select(tmp_path, shard=shard, event="pull_request", backend="true",
                      stack="true", area=area)
        shard_areas = _areas_for(out["e2e_args"], areas)
        ran.extend(shard_areas)
        # Each shard that runs acceptance gets the full stack, exactly as the single job did.
        assert out["stack"] == ("true" if shard_areas or shard in {"browser", "images"} else "false")
    assert sorted(ran) == sorted(expected)  # every selected area, none twice, nothing extra


def test_pr_smoke_shards_keep_the_ui_only_and_merge_queue_scopes(tmp_path):
    for shard in SHARDS:
        ui_only = _select(tmp_path, shard=shard, event="pull_request", backend="false",
                          stack="false", area="all")
        assert ui_only == {"e2e_args": "", "stack": "false"}
        ui_image = _select(tmp_path, shard=shard, event="pull_request", backend="false",
                           stack="true", area="all")
        assert ui_image["e2e_args"] == ""
        assert ui_image["stack"] == ("true" if shard in {"browser", "images"} else "false")
        queue = _select(tmp_path, shard=shard, event="merge_group", backend="true",
                        stack="true", area="all")
        assert queue == {"e2e_args": "", "stack": "false"}


def test_pr_smoke_shard_selection_refuses_an_unknown_area(tmp_path):
    with pytest.raises(subprocess.CalledProcessError):
        _select(tmp_path, shard="core", event="pull_request", backend="true",
                stack="true", area="platform --exclude-area hunt")


def test_required_smoke_job_fails_unless_every_shard_passed():
    workflow = _workflow("e2e-pr.yml")
    shard_job = workflow["jobs"]["smoke-shard"]
    assert shard_job["strategy"]["fail-fast"] is False
    assert shard_job["strategy"]["matrix"]["shard"] == list(SHARDS)
    smoke = workflow["jobs"]["smoke"]
    assert smoke["needs"] == "smoke-shard"
    assert smoke["if"] == "${{ always() }}"
    require = _step(smoke, "Require every smoke shard to pass")
    assert require["env"]["SHARDS"] == "${{ needs.smoke-shard.result }}"
    assert '"$SHARDS" != success' in require["run"] and "exit 1" in require["run"]
    assert "if" not in require
    names = [step.get("name") for step in smoke["steps"]]
    merge_at = names.index("Merge the shard E2E scorecards")
    assert names.index("Collect the shard E2E scorecards") < merge_at
    assert merge_at < names.index("Report actual assertions and validate E2E completeness")
    merge_step = smoke["steps"][merge_at]
    assert "scripts/merge_e2e_scorecards.py --output artifacts/e2e-scorecard.json" in merge_step["run"]
    for job in (shard_job, smoke):
        assert not job.get("continue-on-error")
        assert not any(step.get("continue-on-error") for step in job["steps"])


def test_every_smoke_shard_builds_the_complete_stack_from_source():
    """The cache only warms layers; each shard still runs the complete ./scanner.sh build."""
    shard_job = _workflow("e2e-pr.yml")["jobs"]["smoke-shard"]
    names = [step.get("name") for step in shard_job["steps"]]
    launch = _step(shard_job, "Start the ShakerScan image build once the cached runtime is restored")
    bake = _step(shard_job, "Restore unchanged image layers from the build cache")
    build = _step(shard_job, "Build ShakerScan images")
    start = _step(shard_job, "Start ShakerScan stack")
    order = [names.index(step["name"]) for step in (launch, bake, build, start)]
    assert order == sorted(order)
    assert bake["uses"].startswith("docker/bake-action@") and len(bake["uses"].split("@")[1]) == 40
    assert bake["with"]["source"] == "."
    assert "./scanner.sh build >" in launch["run"]
    # The status is captured with || so the step's inherited -e cannot skip publishing it;
    # tests/test_ci_background_status.py executes the launcher and the waiter.
    assert '|| rc=$?' in launch["run"] and '"$RUNNER_TEMP/scanner-build.status"' in launch["run"]
    assert 'exit "$status"' in build["run"]
    for step in (launch, bake, build, start):
        assert step["if"] == "steps.shard.outputs.stack == 'true'"
    # Release and candidate images never read the PR smoke cache.
    for name in ("release-candidate.yml", "release.yml", "_build-images.yml", "build-on-main.yml"):
        assert "smoke-image-cache.hcl" not in (WORKFLOWS / name).read_text(encoding="utf-8")
        assert "scope=smoke-" not in (WORKFLOWS / name).read_text(encoding="utf-8")


def test_required_python_suite_fails_unless_every_shard_ran_and_passed():
    workflow = _workflow("python-suite.yml")
    shards = workflow["jobs"]["python-shard"]
    assert shards["strategy"]["fail-fast"] is False
    count = len(shards["strategy"]["matrix"]["shard"])
    assert shards["strategy"]["matrix"]["shard"] == list(range(1, count + 1))
    run = _step(shards, "Run this shard of the complete partitioned Python suite")["run"]
    assert f'--shard "${{{{ matrix.shard }}}}/{count}"' in run
    suite = workflow["jobs"]["python-suite"]
    assert set(suite["needs"]) == {"python-shard", "static-gates"}
    assert suite["if"] == "${{ always() }}"
    require = _step(suite, "Require every shard and the static gates to pass")
    assert require["env"] == {"SHARDS": "${{ needs.python-shard.result }}",
                              "STATIC_GATES": "${{ needs.static-gates.result }}"}
    assert "exit 1" in require["run"] and "if" not in require
    merge_step = _step(suite, "Prove the shards ran the complete partitioned Python suite once")
    assert f"--merge-shards {count}" in merge_step["run"]
    for job in workflow["jobs"].values():
        assert not job.get("continue-on-error")
        assert not any(step.get("continue-on-error") for step in job["steps"])


def _card(*areas, gate="pass", revision="abc1234"):
    return {
        "schema_version": "shakerscan-e2e-scorecard/v1",
        "gate": gate,
        "subject": {"source_revision": revision, "build_fingerprint": "f", "scanner_version": revision},
        "areas": [{"area": area, "gate": "pass", "rows": [{"name": f"{area} row", "passed": True}]}
                  for area in areas],
        "total_duration_seconds": 1.5,
    }


def test_merged_scorecard_is_the_union_and_passes_only_if_every_shard_passed():
    merged = merge([("dast", _card("dast")), ("core", _card("platform", "hunt"))])
    assert [area["area"] for area in merged["areas"]] == ["dast", "platform", "hunt"]
    assert merged["gate"] == "pass" and merged["total_duration_seconds"] == 3.0
    assert merged["subject"]["source_revision"] == "abc1234"
    failed = merge([("dast", _card("dast", gate="fail")), ("core", _card("platform"))])
    assert failed["gate"] == "fail"


def test_merge_refuses_duplicate_areas_mixed_deployments_and_empty_input():
    with pytest.raises(MergeError, match="appears in both"):
        merge([("a", _card("hunt")), ("b", _card("hunt"))])
    with pytest.raises(MergeError, match="different deployment"):
        merge([("a", _card("dast")), ("b", _card("hunt", revision="other"))])
    with pytest.raises(MergeError, match="no shard scorecards"):
        merge([])
    with pytest.raises(MergeError, match="records no areas"):
        merge([("a", {**_card("dast"), "areas": []})])


def test_the_completeness_gate_still_rejects_an_area_missing_from_every_shard(tmp_path):
    """A shard that silently dropped an area fails the unchanged summarize gate."""
    cards = []
    for name, areas in (("dast", ("dast",)), ("core", ("platform", "model_intake", "ai_gate"))):
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(_card(*areas)))
        cards.append(str(path))
    merged = tmp_path / "artifacts" / "e2e-scorecard.json"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "merge_e2e_scorecards.py"),
                    "--output", str(merged), *cards], check=True, capture_output=True, timeout=10)
    command = [sys.executable, str(ROOT / "scripts" / "summarize_e2e_debt.py"), str(merged)]
    for area in ("platform", "ai_gate", "model_intake", "dast", "hunt"):
        command += ["--require-area", area]
    result = subprocess.run(command, capture_output=True, timeout=10)
    assert result.returncode == 1
    assert "Required area missing: hunt" in json.loads(result.stdout)["validation_errors"]


def _github_if(expression: str, **values: str) -> bool:
    """Evaluate one of this workflow's step conditions (==, !=, &&, ||, parentheses only)."""
    import re
    python = expression
    for name, value in values.items():
        python = python.replace(name, repr(value))
    python = python.replace("&&", " and ").replace("||", " or ")
    assert not re.search(r"[a-z_]+\.[a-z_]+", python.replace("'", " ' ")), python
    return eval(python, {"__builtins__": {}})  # noqa: S307 - fixed workflow text, no names


def test_ui_contracts_run_in_exactly_one_shard_for_every_scope():
    shard_job = _workflow("e2e-pr.yml")["jobs"]["smoke-shard"]
    contracts = _step(shard_job, "Run UI contracts and production build")
    for command in ("npm --prefix ui ci", "npm --prefix ui run test:unit", "npm --prefix ui run build"):
        assert command in contracts["run"]
    for event in ("pull_request", "merge_group"):
        for stack in ("true", "false"):
            running = [shard for shard in SHARDS if _github_if(
                contracts["if"], **{"steps.changes.outputs.ui": "true",
                                    "steps.changes.outputs.stack": stack,
                                    "github.event_name": event, "matrix.shard": shard})]
            assert len(running) == 1, (event, stack, running)
            mocked = _github_if(_step(shard_job, "Run mocked browser contracts")["if"], **{
                "steps.changes.outputs.ui": "true", "steps.changes.outputs.stack": stack,
                "github.event_name": event, "matrix.shard": "browser"})
            # Wherever the mocked contracts run, the production build they serve ran in that shard.
            assert not mocked or running == ["browser"]


def test_browser_toolchain_install_still_gates_the_shard(tmp_path):
    """The install starts before the image build; its exit status still fails the shard."""
    shard_job = _workflow("e2e-pr.yml")["jobs"]["smoke-shard"]
    names = [step.get("name") for step in shard_job["steps"]]
    start = _step(shard_job, "Install the browser test toolchain while the images build")
    report = _step(shard_job, "Report the browser test toolchain install")
    assert "bash -e -o pipefail -c" in start["run"] and "playwright install chromium" in start["run"]
    assert names.index(start["name"]) < names.index("Build ShakerScan images")
    assert names.index(report["name"]) < names.index("Run real-stack browser acceptance")
    assert start["if"] == report["if"] == _step(shard_job, "Run real-stack browser acceptance")["if"]
    (tmp_path / "browser-toolchain.log").write_text("npm ci failed\n")
    (tmp_path / "browser-toolchain.status").write_text("3\n")
    result = subprocess.run(["bash", "-e", "-c", report["run"]], capture_output=True,
                            env={**os.environ, "RUNNER_TEMP": str(tmp_path)}, timeout=10)
    assert result.returncode == 3
    assert b"npm ci failed" in result.stdout


def test_the_image_build_step_fails_with_the_background_build_status(tmp_path):
    report = _step(_workflow("e2e-pr.yml")["jobs"]["smoke-shard"], "Build ShakerScan images")
    (tmp_path / "scanner-build.log").write_text("build failed in model_intake_overlay\n")
    (tmp_path / "scanner-build.status").write_text("1\n")
    result = subprocess.run(["bash", "-e", "-c", report["run"]], capture_output=True,
                            env={**os.environ, "RUNNER_TEMP": str(tmp_path)}, timeout=10)
    assert result.returncode == 1
    assert b"build failed in model_intake_overlay" in result.stdout
