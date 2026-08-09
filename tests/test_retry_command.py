import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RETRY = ROOT / "scripts" / "retry-command.sh"


def _run(*command: str, attempts: int = 3) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.update(
        SHAKERSCAN_RETRY_ATTEMPTS=str(attempts),
        SHAKERSCAN_RETRY_BASE_DELAY_SECONDS="1",
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


def test_retry_command_retries_then_preserves_final_failure_status():
    result = _run("sh", "-c", "exit 7", attempts=2)

    assert result.returncode == 7
    assert "attempt 1/2 failed" in result.stderr
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
