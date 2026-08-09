import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RETRY = ROOT / "scripts" / "retry-command.sh"


def _run(*command: str, attempts: int = 3, mode: str = "transient") -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.update(
        SHAKERSCAN_RETRY_ATTEMPTS=str(attempts),
        SHAKERSCAN_RETRY_BASE_DELAY_SECONDS="1",
        SHAKERSCAN_RETRY_MODE=mode,
    )
    return subprocess.run(
        [str(RETRY), *command],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_retry_command_returns_first_success_without_retry():
    result = _run("sh", "-c", "exit 0")

    assert result.returncode == 0
    assert "retrying" not in result.stderr


def test_retry_command_does_not_retry_permanent_failure():
    result = _run("sh", "-c", "echo 'Dockerfile: syntax error' >&2; exit 7", attempts=2)

    assert result.returncode == 7
    assert "not classified as transient" in result.stderr
    assert "attempt 1/2 failed" not in result.stderr


def test_retry_command_retries_transient_failure_then_succeeds(tmp_path):
    marker = tmp_path / "attempt"
    command = (
        f'if [ -f "{marker}" ]; then exit 0; fi; '
        f'touch "{marker}"; echo "TLS handshake timeout" >&2; exit 1'
    )

    result = _run("sh", "-c", command, attempts=2)

    assert result.returncode == 0
    assert "attempt 1/2 failed" in result.stderr


def test_retry_command_all_mode_preserves_legacy_opt_in():
    result = _run("sh", "-c", "exit 7", attempts=2, mode="all")

    assert result.returncode == 7
    assert "failed after 2 attempts (exit 7)" in result.stderr


def test_retry_command_rejects_invalid_configuration():
    env = dict(os.environ)
    env["SHAKERSCAN_RETRY_ATTEMPTS"] = "0"
    result = subprocess.run(
        [str(RETRY), "true"],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "positive integers" in result.stderr
