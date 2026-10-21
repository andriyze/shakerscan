"""The pull request upgrade lanes install one release on both halves of the upgrade.

A pull request's upgrade lanes (upgrade-path.yml, installed-upgrade.yml) install the newest
candidate built on main. A pull request that changes VERSION paired its own runtime files with
main's images, and every version-bump pull request failed with "release identity mismatch"
(an expected-red lane). ``scripts/upgrade_lane_candidate.sh`` now checks out the candidate's own
commit, keeps the pull request's gate files, and records why. The release candidate's call is
unchanged and never runs the script.

These tests run the script against a local Git origin with a stub ``gh``; they are unit-test
fixtures, not a CI run. Whether GitHub's runner fetches the candidate commit is proven only by a
pull request run.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "upgrade_lane_candidate.sh"
WORKFLOWS = ROOT / ".github" / "workflows"
GATE = "scripts/upgrade_path_smoke.sh"


def _git(cwd: Path, *args: str) -> str:
    env = {
        **os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.test",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.test",
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
    }
    return subprocess.run(
        ["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True,
    ).stdout.strip()


def _commit(tree: Path, *, version: str, manifest: str, gate: str, message: str) -> str:
    (tree / "install").mkdir(exist_ok=True)
    (tree / "scripts").mkdir(exist_ok=True)
    (tree / "VERSION").write_text(version + "\n", encoding="utf-8")
    (tree / "install" / "MANIFEST.sha256").write_text(manifest, encoding="utf-8")
    (tree / GATE).write_text(gate, encoding="utf-8")
    _git(tree, "add", "-A")
    _git(tree, "commit", "-qm", message)
    return _git(tree, "rev-parse", "HEAD")


@pytest.fixture
def lane(tmp_path):
    """A main candidate commit on the origin, and a pull request checkout of a later commit."""
    origin, tree, stubs = tmp_path / "origin.git", tmp_path / "tree", tmp_path / "bin"
    tree.mkdir()
    stubs.mkdir()
    _git(tmp_path, "init", "-q", "--bare", str(origin))
    _git(origin, "config", "uploadpack.allowAnySHA1InWant", "true")
    _git(tree, "init", "-q")
    _git(tree, "remote", "add", "origin", str(origin))
    candidate = _commit(
        tree, version="2.11.0", manifest="candidate runtime\n", gate="old gate\n",
        message="candidate",
    )
    _git(tree, "push", "-q", "origin", "HEAD:refs/heads/main")
    return {"tmp": tmp_path, "tree": tree, "stubs": stubs, "candidate": candidate}


def _stub_gh(lane, receipt: dict) -> Path:
    receipt_file = lane["tmp"] / "receipt.json"
    receipt_file.write_text(json.dumps(receipt), encoding="utf-8")
    calls = lane["tmp"] / "gh-calls"
    gh = lane["stubs"] / "gh"
    gh.write_text(
        "#!/usr/bin/env bash\n"
        f"printf '%s\\n' \"$*\" >> '{calls}'\n"
        "case \"$1 $2\" in\n"
        "  'run list') echo 4242 ;;\n"
        "  'api '*) echo release-candidate-uncertified-x ;;\n"
        "  'run download')\n"
        "    while [ $# -gt 0 ]; do [ \"$1\" = -D ] && dir=\"$2\"; shift; done\n"
        f"    mkdir -p \"$dir\"; cp '{receipt_file}' \"$dir/release-candidate-receipt.json\" ;;\n"
        "  *) exit 9 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    gh.chmod(gh.stat().st_mode | stat.S_IXUSR)
    return calls


def _receipt(lane, **overrides) -> dict:
    manifest = hashlib.sha256(b"candidate runtime\n").hexdigest()
    return {
        "schema_version": "shakerscan-release-candidate/v1", "version": "2.11.0",
        "candidate_sha": lane["candidate"], "runtime_manifest_sha256": manifest, **overrides,
    }


def _run(lane, *args: str):
    output, summary = lane["tmp"] / "github-output", lane["tmp"] / "summary"
    output.write_text("", encoding="utf-8")
    env = {
        **os.environ, "PATH": f"{lane['stubs']}{os.pathsep}{os.environ['PATH']}",
        "GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(summary),
        "GH_TOKEN": "unused", "REPOSITORY": "example/shakerscan",
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
    }
    result = subprocess.run(
        ["bash", str(SCRIPT), "--out", "artifacts/candidate", *args], cwd=lane["tree"], env=env,
        capture_output=True, text=True, timeout=60,
    )
    outputs = dict(
        line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines() if "=" in line
    )
    return result, outputs, summary.read_text(encoding="utf-8") if summary.exists() else ""


def test_a_version_bump_installs_the_candidates_commit_with_the_pull_requests_gate(lane):
    tree = lane["tree"]
    pull_request = _commit(
        tree, version="2.11.1", manifest="pull request runtime\n", gate="new gate\n",
        message="bump",
    )
    _stub_gh(lane, _receipt(lane))
    result, outputs, summary = _run(lane, "--record", "artifacts/lane.json", GATE)
    assert result.returncode == 0, result.stderr
    assert _git(tree, "rev-parse", "HEAD") == lane["candidate"] != pull_request
    assert (tree / "VERSION").read_text(encoding="utf-8").strip() == "2.11.0"
    assert (tree / "install" / "MANIFEST.sha256").read_text(encoding="utf-8") == "candidate runtime\n"
    # The gate under test is the pull request's.
    assert (tree / GATE).read_text(encoding="utf-8") == "new gate\n"
    assert outputs == {
        "run_id": "4242", "candidate_version": "2.11.0",
        "candidate_sha": lane["candidate"], "pinned": "true",
    }
    record = json.loads((tree / "artifacts" / "lane.json").read_text(encoding="utf-8"))
    assert record["pinned_to_candidate_commit"] is True
    assert record["pull_request_version"] == "2.11.1"
    assert record["candidate"] == {
        "version": "2.11.0", "source_sha": lane["candidate"], "build_on_main_run": "4242",
    }
    assert record["gate_files"] == [GATE]
    # The reason is recorded where a reader of the run sees it, not left to a comment.
    for text in (record["reason"], summary):
        assert "2.11.1" in text and "2.11.0" in text and "release candidate" in text


def test_a_pull_request_on_the_candidates_version_keeps_its_own_tree(lane):
    tree = lane["tree"]
    head = _commit(
        tree, version="2.11.0", manifest="dependency bump\n", gate="new gate\n", message="deps",
    )
    _stub_gh(lane, _receipt(lane))
    result, outputs, _summary = _run(lane, GATE)
    assert result.returncode == 0, result.stderr
    assert _git(tree, "rev-parse", "HEAD") == head
    assert (tree / "install" / "MANIFEST.sha256").read_text(encoding="utf-8") == "dependency bump\n"
    assert outputs["pinned"] == "false"


def test_the_chosen_run_is_downloaded_again_not_the_newest(lane):
    _commit(lane["tree"], version="2.11.1", manifest="x\n", gate="new gate\n", message="bump")
    calls = _stub_gh(lane, _receipt(lane))
    result, outputs, _summary = _run(lane, "--run-id", "77", GATE)
    assert result.returncode == 0, result.stderr
    lines = calls.read_text(encoding="utf-8").splitlines()
    assert not any(line.startswith("run list") for line in lines)
    assert any(line.startswith("run download 77 ") for line in lines)
    assert outputs["run_id"] == "77"


@pytest.mark.parametrize("override, message", [
    ({"runtime_manifest_sha256": "0" * 64}, "runtime manifest differs"),
    ({"candidate_sha": "not-a-commit"}, "names no commit"),
    ({"version": ""}, "names no version"),
])
def test_an_inconsistent_candidate_fails_the_lane(lane, override, message):
    _commit(lane["tree"], version="2.11.1", manifest="x\n", gate="new gate\n", message="bump")
    _stub_gh(lane, _receipt(lane, **override))
    result, _outputs, _summary = _run(lane, GATE)
    assert result.returncode != 0
    assert message in result.stderr


@pytest.mark.parametrize("gate", ["../outside.sh", "/etc/passwd", "scripts/missing.sh"])
def test_a_gate_file_must_be_a_file_of_the_pull_requests_tree(lane, gate):
    _commit(lane["tree"], version="2.11.1", manifest="x\n", gate="new gate\n", message="bump")
    _stub_gh(lane, _receipt(lane))
    result, _outputs, _summary = _run(lane, gate)
    assert result.returncode != 0
    assert _git(lane["tree"], "log", "-1", "--format=%s") == "bump"


# --- the workflows ---------------------------------------------------------------------------


def _workflow(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def _trigger(workflow: dict) -> dict:
    # PyYAML reads the bare key `on` as True.
    return workflow.get("on") or workflow[True]


def _lane_steps(job: dict) -> list[dict]:
    return [step for step in job["steps"] if "scripts/upgrade_lane_candidate.sh" in step.get("run", "")]


@pytest.mark.parametrize("name, jobs", [
    ("upgrade-path.yml", ("baselines", "upgrade-path")),
    ("installed-upgrade.yml", ("installed-upgrade",)),
])
def test_only_the_pull_request_lane_runs_the_candidate_pin(name, jobs):
    workflow = _workflow(name)
    trigger = _trigger(workflow)
    gate_files = [
        path for path in trigger["pull_request"]["paths"]
        if path.startswith("scripts/") and path != "scripts/upgrade_lane_candidate.sh"
    ]
    assert "scripts/upgrade_lane_candidate.sh" in trigger["pull_request"]["paths"]
    for job_name in jobs:
        job = workflow["jobs"][job_name]
        [step] = _lane_steps(job)
        # A release candidate passes candidate_sha and its receipt: the step never runs there.
        assert step["if"] in {
            "${{ inputs.candidate_sha == '' }}", "${{ inputs.receipt_artifact == '' }}",
        }
        # It pins exactly the files whose change made the lane run.
        assert "$GATE_FILES" in step["run"]
        assert sorted(step["env"]["GATE_FILES"].split()) == sorted(gate_files)
        # The release candidate still installs its own receipt.
        downloads = [
            step for step in job["steps"]
            if step.get("uses", "").startswith("actions/download-artifact@")
        ]
        if job_name != "baselines":
            [download] = downloads
            assert download["if"] == "${{ inputs.receipt_artifact != '' }}"
            assert download["with"]["name"] == "${{ inputs.receipt_artifact }}"
        checkout = next(
            step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@")
        )
        assert checkout["with"]["ref"] == (
            "${{ inputs.candidate_sha || github.event.pull_request.head.sha }}"
        )


def test_every_matrix_job_reads_the_candidate_the_baselines_were_chosen_for():
    workflow = _workflow("upgrade-path.yml")
    baselines = workflow["jobs"]["baselines"]
    assert baselines["outputs"]["candidate_run"] == "${{ steps.candidate.outputs.run_id }}"
    steps = [step.get("id") for step in baselines["steps"]]
    # The tree is pinned before the baselines are read from its VERSION and STABLE_VERSION.
    assert steps.index("candidate") < steps.index("select")
    [step] = _lane_steps(workflow["jobs"]["upgrade-path"])
    assert step["env"]["CANDIDATE_RUN"] == "${{ needs.baselines.outputs.candidate_run }}"
    assert '--run-id "$CANDIDATE_RUN"' in step["run"]


def test_the_release_candidate_calls_both_lanes_with_its_exact_commit_and_receipt():
    jobs = _workflow("release-candidate.yml")["jobs"]
    for job_name in ("upgrade-path", "installed-upgrade"):
        job_with = jobs[job_name]["with"]
        assert job_with["candidate_sha"] == "${{ needs.meta.outputs.candidate_sha }}"
        assert "release-candidate-uncertified-" in job_with["receipt_artifact"]
        assert f"needs.{job_name}.result == 'success'" in jobs["certify"]["if"]
