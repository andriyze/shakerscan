"""A failed api-storage-init explains itself instead of a bare failed dependency."""
from __future__ import annotations

from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "scanner.sh").read_text()


def _fn(name: str) -> str:
    body = SCRIPT.split(f"\n{name}() {{", 1)[1].split("\n}", 1)[0]
    return f"{name}() {{{body}\n}}"


FUNCTIONS = "\n".join(_fn(name) for name in ("compose_up", "explain_storage_init_failure", "backup_key_file"))


def _run(*, up_status: int, container: str, exit_code: str) -> subprocess.CompletedProcess[str]:
    harness = f"""
set -e
SCRIPT_DIR=/srv/shakerscan
RED=''; NC=''
compose() {{
    case "$1" in
        up) echo "dependency failed to start: container api-storage-init exited (1)" >&2; return {up_status} ;;
        ps) printf '%s\\n' '{container}' ;;
        logs) echo "secret_store.SecretStoreUnavailable: credential encryption key /results/.credential_enc.key could not be created or read" ;;
    esac
}}
docker_cli() {{ printf '%s\\n' '{exit_code}'; }}
{FUNCTIONS}
compose_up -d
"""
    return subprocess.run(["bash", "-c", harness], capture_output=True, text=True, timeout=30)


def test_a_failed_storage_init_shows_its_log_and_the_key_guidance():
    result = _run(up_status=1, container="abc123", exit_code="1")
    assert result.returncode == 1
    assert "api-storage-init) failed" in result.stdout
    assert "  secret_store.SecretStoreUnavailable" in result.stdout
    assert "/srv/shakerscan/results/.credential_enc.key" in result.stdout
    assert "--include-key" in result.stdout


def test_other_start_failures_and_successful_starts_add_nothing():
    # Another service failed; the storage step itself succeeded.
    assert "api-storage-init" not in _run(up_status=1, container="abc123", exit_code="0").stdout
    # A source stack has no storage step at all.
    assert "api-storage-init" not in _run(up_status=1, container="", exit_code="1").stdout
    ok = _run(up_status=0, container="abc123", exit_code="1")
    assert ok.returncode == 0 and "api-storage-init" not in ok.stdout
