"""`reset` starts the fresh stack the way `start` does.

It used to run `compose up` straight after `compose down -v`, without `set_build_env`: the release
version, commit and image identity the services are created with were left at Compose's defaults
("latest"), and none of the start preflight (runtime files, Redis readiness, device worker, health
and build-identity checks, release record) ran. These run the real function against stubs (unit
fixtures: no Docker).
"""

from __future__ import annotations

import os
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "scanner.sh").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    body = SCRIPT.split(f"\n{name}() {{", 1)[1].split("\n}", 1)[0]
    return f"{name}() {{{body}\n}}"


HARNESS = r"""
set -eu
RED=''; GREEN=''; YELLOW=''; NC=''
log() { printf '%s\n' "$*" >> "$CALLS"; }
compose() { log "compose $*"; }
compose_up() { log "compose_up $*"; }
docker_cli() { log "docker $*"; }
resolve_start_workers() { echo 3; }
remove_containers_outside_compose_down() { log remove-outside-compose; }
remove_scan_worker_containers() { log remove-scan-workers; }
set_build_env() { log set_build_env; }
note_running_release() { log note_running_release; }
start_services() { log "start_services $* backup=${SHAKERSCAN_PRE_UPGRADE_BACKUP:-1}"; }
""" + _fn("reset_database") + "\nreset_database\n"


def _reset(tmp_path: pathlib.Path, answer: str,
           harness: str = HARNESS) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    calls = tmp_path / "calls.log"
    calls.write_text("")
    result = subprocess.run(["bash", "-c", harness], input=f"{answer}\n", capture_output=True, text=True,
                            timeout=20, check=False, env={**os.environ, "CALLS": str(calls)})
    return result, calls.read_text().splitlines()


def test_reset_starts_the_fresh_stack_through_start(tmp_path):
    result, calls = _reset(tmp_path, "yes")
    assert result.returncode == 0, result.stdout + result.stderr
    # The version that ran is noted before the stack goes down.
    assert calls[:4] == ["note_running_release", "remove-outside-compose", "compose down -v --remove-orphans",
                         "remove-scan-workers"], calls
    # The emptied database is not saved as if it were being upgraded.
    assert "start_services 3 backup=0" in calls, calls
    assert not [call for call in calls if call.startswith(("compose_up", "compose up"))], calls
    assert "Database reset complete" in result.stdout


def test_a_cancelled_reset_changes_nothing(tmp_path):
    result, calls = _reset(tmp_path, "no")
    assert result.returncode == 0 and "Cancelled" in result.stdout
    assert calls == []


def test_start_sets_the_build_environment_before_any_service_is_created():
    body = _fn("start_services")
    assert body.index("set_build_env") < body.index("compose_up")
    assert body.index("set_build_env") < body.index("ensure_target_upgrade_backup")


def test_a_failed_start_is_not_reported_as_a_completed_reset(tmp_path):
    stub = 'start_services() { log "start_services $* backup=${SHAKERSCAN_PRE_UPGRADE_BACKUP:-1}"; }'
    assert stub in HARNESS
    failing = HARNESS.replace(stub, "start_services() { return 1; }")
    result, _ = _reset(tmp_path, "yes", failing)
    assert result.returncode != 0 and "Database reset complete" not in result.stdout
