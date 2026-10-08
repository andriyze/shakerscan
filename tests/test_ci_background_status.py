"""The PR shard's background builds always publish their exit status, and every wait is bounded.

Audit S003: `e2e-pr.yml` started `./scanner.sh build` and the browser toolchain install as
background subshells that wrote `$?` to a status file after the command. GitHub runs a
`shell: bash` step as `bash -e -o pipefail`, and the subshell inherits -e, so a failing command
ended the subshell before it wrote the status: the image waiter then sat out its 35-minute bound
and the browser waiter, which had none, held the shard until the job timeout.

These tests do not search the YAML text. They extract the steps' run scripts, execute them
exactly as the runner does with stub `docker`, `./scanner.sh`, `npm` and `npx` commands that
exit with chosen codes, and assert that the status is published promptly, that the waiter
exits with exactly that code, and that a status that never comes ends the wait at its bound.
"""

from __future__ import annotations

import os
from pathlib import Path
import signal
import stat
import subprocess
import time

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "e2e-pr.yml"
# How GitHub Actions runs a step declared `shell: bash`.
STEP_SHELL = ("bash", "--noprofile", "--norc", "-e", "-o", "pipefail")


def _run_script(name: str) -> str:
    job = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["smoke-shard"]
    step = next(step for step in job["steps"] if step.get("name") == name)
    assert step.get("shell") == "bash", name
    return step["run"]


SCANNER_LAUNCH = "Start the ShakerScan image build once the cached runtime is restored"
SCANNER_WAIT = "Build ShakerScan images"
BROWSER_LAUNCH = "Install the browser test toolchain while the images build"
BROWSER_WAIT = "Report the browser test toolchain install"


def _executable(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class _Runner:
    """One fake runner: a workspace, RUNNER_TEMP and stub commands first on PATH."""

    def __init__(self, tmp_path: Path) -> None:
        self.workspace = tmp_path / "workspace"
        self.temp = tmp_path / "runner-temp"
        self.bin = tmp_path / "bin"
        self.calls = tmp_path / "calls"
        for directory in (self.workspace, self.temp, self.bin):
            directory.mkdir()
        self.groups: list[int] = []
        # The cached worker image is present, so the image build starts at once.
        self.stub("docker", 'exit 0\n')

    def stub(self, name: str, body: str) -> None:
        target = self.workspace / name if name == "scanner.sh" else self.bin / name
        _executable(target, f'echo "{name} $*" >> "{self.calls}"\n{body}')

    def env(self, **extra: str) -> dict[str, str]:
        return {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "RUNNER_TEMP": str(self.temp),
            **extra,
        }

    def launch(self, step: str) -> subprocess.CompletedProcess:
        # Its own session, so the background supervisor it leaves running can be reaped. Its
        # output goes to a file: the supervisor outlives the step and would hold a pipe open.
        output = self.temp.parent / f"launch-{len(self.groups)}.out"
        with output.open("wb") as sink:
            process = subprocess.Popen(
                [*STEP_SHELL, "-c", _run_script(step)], cwd=self.workspace, env=self.env(),
                stdout=sink, stderr=subprocess.STDOUT, start_new_session=True,
            )
            self.groups.append(process.pid)
            process.wait(timeout=20)
        text = output.read_bytes()
        return subprocess.CompletedProcess(process.args, process.returncode, text, text)

    def wait(self, step: str, **extra: str) -> tuple[subprocess.CompletedProcess, float]:
        started = time.monotonic()
        result = subprocess.run(
            [*STEP_SHELL, "-c", _run_script(step)], cwd=self.workspace, env=self.env(**extra),
            capture_output=True, timeout=60,
        )
        return result, time.monotonic() - started

    def status_after(self, name: str, *, within: float) -> str | None:
        status = self.temp / name
        deadline = time.monotonic() + within
        while time.monotonic() < deadline:
            if status.is_file():
                return status.read_text(encoding="utf-8")
            time.sleep(0.05)
        return None

    def called(self) -> list[str]:
        return self.calls.read_text(encoding="utf-8").splitlines() if self.calls.exists() else []

    def reap(self) -> None:
        for group in self.groups:
            try:
                os.killpg(group, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass


@pytest.fixture
def runner(tmp_path):
    fake = _Runner(tmp_path)
    yield fake
    fake.reap()


@pytest.mark.parametrize("code", [0, 1, 7, 42])
def test_the_image_build_status_is_published_and_propagated_exactly(runner, code):
    runner.stub("scanner.sh", f'echo "building layer {code}"\nexit {code}\n')

    launched = runner.launch(SCANNER_LAUNCH)
    assert launched.returncode == 0, launched.stderr

    # Published promptly -- not after a waiter's bound -- whatever the build exited with.
    assert runner.status_after("scanner-build.status", within=10) == f"{code}\n"
    result, _elapsed = runner.wait(SCANNER_WAIT)
    assert result.returncode == code
    assert f"./scanner.sh build exit status: {code}".encode() in result.stdout
    assert f"building layer {code}".encode() in result.stdout
    assert any(call.startswith("scanner.sh build") for call in runner.called())


@pytest.mark.parametrize(
    ("npm_code", "npx_code", "expected", "npx_runs"),
    [
        (0, 0, 0, True),
        # npm ci fails: the install stops there (fail-fast inside the child) with its code.
        (5, 0, 5, False),
        (0, 9, 9, True),
    ],
)
def test_the_browser_toolchain_status_is_published_and_propagated_exactly(
    runner, npm_code, npx_code, expected, npx_runs,
):
    runner.stub("npm", f'echo "npm output"\nexit {npm_code}\n')
    runner.stub("npx", f'echo "npx output"\nexit {npx_code}\n')

    launched = runner.launch(BROWSER_LAUNCH)
    assert launched.returncode == 0, launched.stderr

    assert runner.status_after("browser-toolchain.status", within=10) == f"{expected}\n"
    calls = runner.called()
    assert calls[0] == "npm --prefix ui ci"
    assert any(call.startswith("npx --prefix ui playwright install chromium") for call in calls) is npx_runs
    result, _elapsed = runner.wait(BROWSER_WAIT)
    assert result.returncode == expected
    assert f"browser test toolchain install exit status: {expected}".encode() in result.stdout
    assert b"npm output" in result.stdout


def test_the_image_build_wait_is_bounded_when_no_status_ever_comes(runner):
    # The cached worker image never appears, so the build never starts and never reports.
    runner.stub("docker", "exit 1\n")
    runner.stub("scanner.sh", "exit 0\n")
    assert runner.launch(SCANNER_LAUNCH).returncode == 0

    result, elapsed = runner.wait(SCANNER_WAIT, SHAKERSCAN_SCANNER_BUILD_WAIT_SECONDS="3")

    assert result.returncode == 1
    assert elapsed < 20
    assert b"did not finish within 3 seconds" in result.stdout
    assert not (runner.temp / "scanner-build.status").exists()


def test_the_browser_toolchain_wait_is_bounded_and_streams_the_log(runner):
    # The install hangs after printing: the waiter shows that output and stops at its bound.
    runner.stub("npm", 'echo "fetching packages"\nsleep 600\n')
    runner.stub("npx", "exit 0\n")
    assert runner.launch(BROWSER_LAUNCH).returncode == 0

    result, elapsed = runner.wait(BROWSER_WAIT, SHAKERSCAN_BROWSER_TOOLCHAIN_WAIT_SECONDS="3")

    assert result.returncode == 1
    assert elapsed < 20
    assert b"did not finish within 3 seconds" in result.stdout
    assert b"fetching packages" in result.stdout


def test_the_production_bounds_stay_below_the_job_timeout():
    job = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["smoke-shard"]
    limit = int(job["timeout-minutes"]) * 60
    assert "${SHAKERSCAN_SCANNER_BUILD_WAIT_SECONDS:-2100}" in _run_script(SCANNER_WAIT)
    assert "${SHAKERSCAN_BROWSER_TOOLCHAIN_WAIT_SECONDS:-1200}" in _run_script(BROWSER_WAIT)
    assert 2100 < limit and 1200 < limit
