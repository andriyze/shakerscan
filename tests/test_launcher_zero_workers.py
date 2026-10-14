"""`WORKERS=0` (or `--workers 0`) starts a stack without local scan workers, with a warning.

A control-plane or broker-only install runs its scans on other nodes; the launcher refused 0.
These run the real function (unit fixture: no Docker).
"""

from __future__ import annotations

import os
import pathlib
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "scanner.sh").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    body = SCRIPT.split(f"\n{name}() {{", 1)[1].split("\n}", 1)[0]
    return f"{name}() {{{body}\n}}"


def _resolve(workers: str) -> subprocess.CompletedProcess[str]:
    harness = "RED=''; NC=''\nruntime_memory_gb() { echo 16; }\nauto_workers_for_memory_gb() { echo 9; }\n" \
        + _fn("resolve_start_workers") + "\nresolve_start_workers\n"
    return subprocess.run(["bash", "-c", harness], capture_output=True, text=True, timeout=20, check=False,
                          env={**os.environ, "WORKERS": workers})


def test_zero_workers_is_accepted():
    result = _resolve("0")
    assert result.returncode == 0 and result.stdout.strip() == "0", result.stdout + result.stderr


@pytest.mark.parametrize("workers", ["-1", "21", "two", ""])
def test_other_values_outside_the_range_are_still_refused(workers):
    result = _resolve(workers)
    assert result.returncode == 1 and "between 0 and 20" in result.stderr, result.stdout + result.stderr


def test_auto_and_numbers_are_unchanged():
    assert _resolve("auto").stdout.strip() == "9"
    assert _resolve("20").stdout.strip() == "20"


def test_a_start_without_local_workers_says_where_scans_run():
    body = _fn("start_services")
    warning = body.split('if [ "$start_workers" -eq 0 ]; then', 1)[1].split("fi", 1)[0]
    assert "no local scan workers" in warning and "broker" in warning


IDENTITY = r"""
RED=''; GREEN=''; NC=''
SCANNER_VERSION=2.11.0
SHAKERSCAN_BUILD_IDENTITY_TIMEOUT=4
sleep() { :; }
api_probe_url() { echo http://api; }
ui_probe_url() { echo http://ui; }
curl() {
  case "$*" in
    *api/health*) echo '{"scanner_version":"2.11.0","worker_build":{"available":true,"fleet_uniform":false,"scanner_version":null}}' ;;
    *) echo '{"ui_version":"2.11.0"}' ;;
  esac
}
"""


def _identity(args: str) -> subprocess.CompletedProcess[str]:
    harness = IDENTITY + _fn("build_versions_match") + "\n" + _fn("verify_running_build_identity") \
        + f"\nverify_running_build_identity {args}\n"
    return subprocess.run(["bash", "-c", harness], capture_output=True, text=True, timeout=20, check=False,
                          env=dict(os.environ))


def test_without_local_workers_the_identity_check_needs_no_worker_report():
    """A broker-only start would otherwise fail closed: no local worker ever reports its build."""
    result = _identity("0")
    assert result.returncode == 0 and "no local scan workers" in result.stdout, result.stdout + result.stderr


def test_with_local_workers_a_missing_worker_report_still_fails_closed():
    assert _identity("3").returncode == 1
    assert _identity("").returncode == 1


def test_start_passes_its_worker_count_to_the_identity_check():
    assert 'verify_running_build_identity "$start_workers"' in _fn("start_services")
