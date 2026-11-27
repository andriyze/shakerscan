"""The Model Intake signer role init waits for authenticated PostgreSQL, bounded.

Compose starts the init once pg_isready passes, which proves only that the server accepts
connections; password auth on a cold volume can lag by seconds. The old script ran a single
psql under `set -eu` and exited 2 on that race, failing `compose up`. These tests run the real
script against a stub psql that refuses N authenticated connections before accepting, and pin
that the bound is honored with a clear failure.
"""

from __future__ import annotations

import os
import pathlib
import stat
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "db" / "configure-model-intake-signer-role.sh"


def _stub_psql(tmp_path: pathlib.Path, *, refuse: int) -> pathlib.Path:
    """psql that fails the first `refuse` probe connections, then succeeds; records every call."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    counter = tmp_path / "probes"
    counter.write_text("0")
    log = tmp_path / "calls.log"
    stub = bin_dir / "psql"
    stub.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {log}\n"
        "case \"$*\" in\n"
        "  *'SELECT 1'*)\n"
        f"    n=$(cat {counter}); n=$((n + 1)); printf '%s' \"$n\" > {counter}\n"
        f"    [ \"$n\" -gt {refuse} ] && exit 0\n"
        "    echo 'psql: error: connection to server failed: FATAL: password authentication failed' >&2\n"
        "    exit 2 ;;\n"
        "  *) cat >/dev/null; exit 0 ;;\n"
        "esac\n"
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    return log


def _run(tmp_path: pathlib.Path, *, refuse: int, attempts: int) -> tuple[subprocess.CompletedProcess, list[str]]:
    log = _stub_psql(tmp_path, refuse=refuse)
    env = {
        **os.environ,
        "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}",
        "POSTGRES_PASSWORD": "scanner",
        "MODEL_INTAKE_SIGNER_DATABASE_PASSWORD": "signer-secret_1",
        "MODEL_INTAKE_SIGNER_INIT_ATTEMPTS": str(attempts),
        "MODEL_INTAKE_SIGNER_INIT_DELAY_SECONDS": "0",
    }
    result = subprocess.run(["sh", str(SCRIPT)], capture_output=True, text=True, env=env)
    calls = log.read_text().splitlines() if log.exists() else []
    return result, calls


def test_init_waits_through_early_auth_failures_then_configures_the_role(tmp_path):
    result, calls = _run(tmp_path, refuse=3, attempts=10)
    assert result.returncode == 0, result.stderr
    probes = [c for c in calls if "SELECT 1" in c]
    role_runs = [c for c in calls if "signer_password=" in c]
    assert len(probes) == 4, probes
    assert len(role_runs) == 1, calls
    # The role configuration ran only after the authenticated probe succeeded.
    assert calls.index(role_runs[0]) > calls.index(probes[-1])
    assert result.stderr.count("waiting for PostgreSQL authentication") == 3


def test_init_fails_closed_after_the_bounded_wait(tmp_path):
    result, calls = _run(tmp_path, refuse=100, attempts=4)
    assert result.returncode == 2
    assert "did not accept an authenticated scanner connection after 4 attempts" in result.stderr
    assert not [c for c in calls if "signer_password=" in c], "role script must not run unauthenticated"


def test_init_rejects_a_non_url_safe_signer_password(tmp_path):
    _stub_psql(tmp_path, refuse=0)
    env = {
        **os.environ,
        "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}",
        "POSTGRES_PASSWORD": "scanner",
        "MODEL_INTAKE_SIGNER_DATABASE_PASSWORD": "has spaces",
    }
    result = subprocess.run(["sh", str(SCRIPT)], capture_output=True, text=True, env=env)
    assert result.returncode == 1
    assert "must be URL-safe" in result.stderr
