"""`stop` and an upgrade `start` must not leave containers attached to the project networks.

A plain `compose down` skips the opt-in device and Gungnir lanes (their profiles are not active),
containers the API starts through the Docker socket (they carry no Compose config hash), and
one-off `compose run` containers. Each one kept `shakerscan_default` and
`shakerscan_signer-control` "in use" after `stop` and stayed on its old image. The upgrade's
`start` then failed: `--scale` collided with an API-started worker's name, a network Compose had
to recreate still had active endpoints, or the stale lanes failed the build-identity gate.

These tests run the real scanner.sh functions against a fake Docker CLI that records each call.
"""

from __future__ import annotations

import os
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "scanner.sh").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    # Anchor on the line start: `containers_outside_compose_down() {` is also a suffix of
    # `remove_containers_outside_compose_down() {`.
    body = SCRIPT.split(f"\n{name}() {{", 1)[1].split("\n}", 1)[0]
    return f"{name}() {{{body}\n}}"


def _run(harness: str, **env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", harness],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
        env={**os.environ, "COMPOSE_PROJECT_NAME": "shakerscan", **env},
    )


# Answers the Docker CLI calls the lifecycle helpers make, from environment variables:
#   ROWS         `name|service|config-hash|oneoff` rows of every project container
#   RUNNING_IDS  running project containers (`ps -q`)
#   RUNNING      running project container names
#   API          `name|oneoff` rows of running containers labelled with the api service
#   NETWORKS     project networks; HOLDERS the containers attached to each
FAKE_DOCKER = r'''
docker() {
    printf 'docker %s\n' "$*" >> "$CALLS"
    case "$*" in
        *config-hash*) printf '%s' "${ROWS:-}" ;;
        "ps -q --filter label=com.docker.compose.project=shakerscan") printf '%s' "${RUNNING_IDS:-}" ;;
        *"label=com.docker.compose.service=api"*)
            if [[ "$*" == *"label=com.docker.compose.oneoff=False"* ]]; then
                printf '%s' "${API:-}" | awk -F'|' '$2 == "False" { print $1 }'
            else
                printf '%s' "${API:-}" | awk -F'|' '{ print $1 }'
            fi
            ;;
        "ps --filter label=com.docker.compose.project=shakerscan --format {{.Names}}") printf '%s' "${RUNNING:-}" ;;
        "network ls "*) printf '%s' "${NETWORKS:-}" ;;
        "network inspect "*) printf '%s' "${HOLDERS:-}" ;;
    esac
}
'''

LIFECYCLE_FUNCTIONS = "\n".join(
    _fn(name)
    for name in (
        "project_container_rows",
        "containers_started_outside_compose",
        "containers_outside_compose_down",
        "remove_containers_outside_compose_down",
        "scan_worker_containers",
        "remove_scan_worker_containers",
        "running_compose_service_count",
        "build_versions_match",
        "start_clean_slate_reason",
        "doctor_leftover_containers",
        "stop_services",
    )
)

PRELUDE = "\n".join([
    "set -eu",
    "RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''",
    FAKE_DOCKER,
    "compose() { printf 'compose %s\\n' \"$*\" >> \"$CALLS\"; }",
    "api_probe_url() { printf 'http://127.0.0.1:8080'; }",
    "cli_hint() { printf 'shakerscan'; }",
    # The health probe answers with API_JSON, or fails like an unreachable API.
    "curl() { [ -n \"${API_JSON:-}\" ] || return 7; printf '%s' \"$API_JSON\"; }",
    "jq() { python3 -c 'import json, sys; print(json.load(sys.stdin).get(\"scanner_version\") or \"\")'; }",
    LIFECYCLE_FUNCTIONS,
])


def test_stop_removes_every_container_compose_down_leaves_attached(tmp_path):
    calls = tmp_path / "calls.txt"
    rows = "".join(
        f"{row}\n"
        for row in (
            "shakerscan-api-1|api|hash-api|False",
            "shakerscan-worker-1|worker|hash-worker|False",
            "shakerscan-worker-3|worker||False",
            "shakerscan-gungnir-worker-1|gungnir-worker||False",
            "shakerscan-device-worker-1|device-worker|hash-device|False",
            "shakerscan-api-run-5f2c|api|hash-api|True",
        )
    )

    result = _run(PRELUDE + "\nstop_services\n", CALLS=str(calls), ROWS=rows)

    assert result.returncode == 0, result.stdout + result.stderr
    lines = calls.read_text().splitlines()
    left_by_down = {
        "shakerscan-worker-3",  # API worker scaler: no config hash
        "shakerscan-gungnir-worker-1",  # API Gungnir auto-start: no config hash
        "shakerscan-device-worker-1",  # opt-in profile inactive for `down`
        "shakerscan-api-run-5f2c",  # one-off `compose run`
    }
    stop_calls = [line for line in lines if line.startswith("docker stop ")]
    assert len(stop_calls) == 1
    assert set(stop_calls[0].split()[2:]) == left_by_down
    removed = {line.split()[-1] for line in lines if line.startswith("docker rm -f ")}
    assert removed == left_by_down

    down = lines.index("compose down --remove-orphans")
    assert all(lines.index(f"docker rm -f {name}") < down for name in left_by_down)
    # Stopping must never delete the database or Redis volumes.
    assert not any(line.startswith("compose down") and ("-v" in line.split() or "--volumes" in line) for line in lines)


def test_stop_leaves_compose_down_alone_when_nothing_is_outside_it(tmp_path):
    calls = tmp_path / "calls.txt"
    rows = "shakerscan-api-1|api|hash-api|False\nshakerscan-worker-1|worker|hash-worker|False\n"

    result = _run(PRELUDE + "\nstop_services\n", CALLS=str(calls), ROWS=rows)

    assert result.returncode == 0, result.stdout + result.stderr
    lines = calls.read_text().splitlines()
    assert "compose down --remove-orphans" in lines
    assert not [line for line in lines if line.startswith(("docker stop", "docker rm"))]


def _clean_slate_reason(tmp_path, **env: str) -> str:
    result = _run(
        PRELUDE + "\nSCANNER_VERSION=2.5.6\nstart_clean_slate_reason\n",
        CALLS=str(tmp_path / "calls.txt"),
        **env,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


def test_start_converges_in_place_when_nothing_older_or_stray_is_running(tmp_path):
    assert _clean_slate_reason(tmp_path) == ""
    # The current release answering is the ordinary idempotent start.
    assert _clean_slate_reason(
        tmp_path, RUNNING_IDS="a1\n", API="shakerscan-api-1|False\n", API_JSON='{"scanner_version": "2.5.6"}'
    ) == ""
    # An API that is still booting is not bounced mid-migration.
    assert _clean_slate_reason(tmp_path, RUNNING_IDS="a1\n", API="shakerscan-api-1|False\n") == ""


def test_start_stops_first_when_an_older_release_answers(tmp_path):
    reason = _clean_slate_reason(
        tmp_path, RUNNING_IDS="a1\n", API="shakerscan-api-1|False\n", API_JSON='{"scanner_version": "2.5.4"}'
    )
    assert reason == "found ShakerScan 2.5.4 running"


def test_start_stops_first_when_the_api_started_containers_outside_compose(tmp_path):
    reason = _clean_slate_reason(
        tmp_path,
        ROWS="shakerscan-api-1|api|hash-api|False\nshakerscan-worker-3|worker||False\n",
        RUNNING_IDS="a1\n",
        API="shakerscan-api-1|False\n",
        API_JSON='{"scanner_version": "2.5.6"}',
    )
    assert reason == "found containers started outside Compose: shakerscan-worker-3"


def test_start_stops_first_when_containers_run_without_the_api(tmp_path):
    # What an interrupted stop leaves: lanes plus a one-off `compose run api ...` container, which
    # shares the api service label but serves nothing.
    reason = _clean_slate_reason(
        tmp_path,
        RUNNING_IDS="d1\ng1\nr1\n",
        API="shakerscan-api-run-5f2c|True\n",
    )
    assert reason == "found ShakerScan containers running without the API"


START_HARNESS = r'''
set -eu
RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
WORKERS=auto
USE_PREBUILT=1
API_IMAGE_REPO=release-api
SCANNER_IMAGE_REPO=release-worker
UI_IMAGE_REPO=release-ui
SCANNER_IMAGE_TAG=2.5.6
prepare_runtime_files() { :; }
persist_remote_access_env() { :; }
warn_if_ui_port_has_foreign_listener() { :; }
runtime_memory_gb() { printf '8\n'; }
resolve_start_workers() { printf '2\n'; }
restart_worker_count() { printf '4\n'; }
set_build_env() { :; }
pull_prebuilt_images() { printf 'pull\n'; }
resolve_docker_socket_gid() { printf '0\n'; }
write_dotenv_value() { :; }
record_runtime_mode() { :; }
compose() { printf 'compose:%s\n' "$*"; }
compose_up() {
__COMPOSE_UP__
}
api_probe_url() { printf 'http://api'; }
ui_probe_url() { printf 'http://ui'; }
api_base_url() { printf 'http://api'; }
ui_base_url() { printf 'http://ui'; }
cli_hint() { printf 'shakerscan'; }
wait_for_url() { :; }
verify_running_build_identity() { :; }
verify_specialized_worker_identity() { printf 'specialized:%s:%s\n' "$1" "$2"; }
running_device_worker_count() { printf '1\n'; }
running_compose_service_count() {
    case "$1" in
        gungnir-worker) printf '1\n' ;;
        *) printf '0\n' ;;
    esac
}
stop_services() { printf 'stop\n'; }
start_clean_slate_reason() { printf '%s' "$REASON"; }
start_services() {
__START_SERVICES__
}
start_services "$@"
'''


def _start(*args: str, reason: str) -> str:
    harness = (
        START_HARNESS.replace("__COMPOSE_UP__", SCRIPT.split("\ncompose_up() {", 1)[1].split("\n}", 1)[0])
        .replace("__START_SERVICES__", SCRIPT.split("\nstart_services() {", 1)[1].split("\n}", 1)[0])
    )
    result = subprocess.run(
        ["bash", "-c", harness, "harness", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
        env={**os.environ, "REASON": reason, "SCRIPT_DIR": str(ROOT)},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def test_upgrade_start_stops_everything_then_restores_lanes_and_worker_count():
    output = _start(reason="found ShakerScan 2.5.4 running")

    primary_up = "compose:up --no-build -d --scale worker=4"
    device_up = "compose:--profile devices up --no-build -d --force-recreate device-worker"
    gungnir_up = "compose:--profile gungnir up --no-build -d --force-recreate gungnir-worker"
    assert "Stopping the running stack first (found ShakerScan 2.5.4 running)" in output
    # Images are pulled before anything is taken down, so a failed pull leaves the old stack up.
    assert output.index("pull\n") < output.index("stop\n") < output.index(primary_up)
    assert output.index(primary_up) < output.index(device_up)
    assert output.index(primary_up) < output.index(gungnir_up)
    assert "specialized:0:1" in output


def test_upgrade_start_keeps_an_explicit_worker_count():
    output = _start("6", reason="found ShakerScan 2.5.4 running")

    assert "stop\n" in output
    assert "compose:up --no-build -d --scale worker=6" in output


def test_ordinary_start_neither_stops_nor_recreates_running_lanes():
    output = _start(reason="")

    assert "stop\n" not in output
    assert "compose:up --no-build -d --scale worker=2" in output
    assert "--force-recreate device-worker" not in output
    assert "--force-recreate gungnir-worker" not in output


RESTART_HARNESS = r'''
set -eu
prepare_runtime_files() { :; }
restart_worker_count() { printf '3\n'; }
# Both opt-in lanes run until `stop` removes them.
running_device_worker_count() { if [ -e "$STOPPED" ]; then printf '0\n'; else printf '1\n'; fi; }
running_compose_service_count() {
    if [ -e "$STOPPED" ]; then printf '0\n'; return 0; fi
    case "$1" in
        gungnir-worker) printf '1\n' ;;
        *) printf '0\n' ;;
    esac
}
stop_services() { printf 'stop\n'; : > "$STOPPED"; }
start_services() { printf 'start:%s\n' "$*"; }
restart_services() {
__RESTART_SERVICES__
}
restart_services
'''


def test_restart_counts_the_opt_in_lanes_before_stop_removes_them(tmp_path):
    harness = RESTART_HARNESS.replace(
        "__RESTART_SERVICES__", SCRIPT.split("\nrestart_services() {", 1)[1].split("\n}", 1)[0]
    )
    result = subprocess.run(
        ["bash", "-c", harness],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
        env={**os.environ, "STOPPED": str(tmp_path / "stopped")},
    )

    assert result.returncode == 0, result.stdout + result.stderr
    # workers, device-worker lane, Gungnir lane: all taken while the lanes were still running.
    assert result.stdout.splitlines() == ["stop", "start:3 1 1"]


def test_running_service_count_ignores_one_off_runs(tmp_path):
    result = _run(
        PRELUDE + "\nrunning_compose_service_count api\n",
        CALLS=str(tmp_path / "calls.txt"),
        API="shakerscan-api-run-5f2c|True\n",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "0"


def test_doctor_names_containers_left_running_without_the_api(tmp_path):
    result = _run(
        PRELUDE + "\ndoctor_leftover_containers\n",
        CALLS=str(tmp_path / "calls.txt"),
        RUNNING="shakerscan-device-worker-1\nshakerscan-gungnir-worker-1\n",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "running without the API" in result.stdout
    assert "shakerscan-device-worker-1 shakerscan-gungnir-worker-1" in result.stdout
    assert "'shakerscan stop'" in result.stdout
    assert " ok " not in result.stdout


def test_doctor_names_what_else_holds_a_project_network(tmp_path):
    calls = tmp_path / "calls.txt"
    result = _run(
        PRELUDE + "\ndoctor_leftover_containers\n",
        CALLS=str(calls),
        NETWORKS="shakerscan_default\n",
        HOLDERS="someone-elses-tool ",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "network shakerscan_default is still in use by: someone-elses-tool" in result.stdout
    assert "docker network disconnect -f shakerscan_default <name>" in result.stdout
    # Read-only: doctor reports, it never stops, removes, or disconnects anything.
    assert not [
        line
        for line in calls.read_text().splitlines()
        if line.startswith(("docker stop", "docker rm", "docker network rm", "docker network disconnect"))
    ]


def test_doctor_is_quiet_about_a_healthy_stack(tmp_path):
    result = _run(
        PRELUDE + "\ndoctor_leftover_containers\n",
        CALLS=str(tmp_path / "calls.txt"),
        RUNNING="shakerscan-api-1\nshakerscan-worker-1\n",
        API="shakerscan-api-1|False\n",
        NETWORKS="shakerscan_default\n",
        HOLDERS="shakerscan-api-1 shakerscan-worker-1 ",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ok no leftover ShakerScan containers or networks in use" in result.stdout
    assert "attention" not in result.stdout
