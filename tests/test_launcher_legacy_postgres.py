"""PostgreSQL 16 data a release before 2.6 left in `<project>_postgres-data` is never migrated now.

Releases 2.6 to 2.10 migrated that volume into `<project>_postgres-cluster` before anything could start
PostgreSQL. Once the migration was removed, nothing refused the old layout: `start` (and the
installer's start) ran `compose up -d postgres`, PostgreSQL 18 initialized a new, empty database in
a new postgres-cluster volume beside the real data, and the "pre-upgrade" dump was taken from the
empty one. The launcher now refuses every Compose call that can start PostgreSQL in that state;
`start`/`restart` refuse before anything is downloaded or stopped, and the commands that change the
install before their own `compose up` (`redis reset`, `rebuild`, `model-intake`, ...) refuse first.
When this install ran PostgreSQL 18 before, postgres-data is the copy a migration kept beside a lost
postgres-cluster, and the refusal points to backups/ instead.

Unit fixtures: Docker, Compose and the network are stubbed (a fake `docker` on PATH for the
start-level test); no container runs.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scanner.sh"
SAFETY = ROOT / "scripts" / "upgrade_safety.sh"
INSTALLER = ROOT / "install" / "index.sh"


def _extract(name: str, text: str | None = None) -> str:
    text = SCANNER.read_text(encoding="utf-8") if text is None else text
    match = re.search(rf"^{re.escape(name)}\(\) \{{\n.*?^\}}\n", text, re.MULTILINE | re.DOTALL)
    assert match, f"{name} not found"
    return match.group(0)


def _bash(script: str, **env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["bash", "-c", script], cwd=ROOT, capture_output=True, text=True, timeout=30,
                          check=False, env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", **env})


# --- compose(): every subcommand that can start PostgreSQL --------------------------------------

COMPOSE_HARNESS = r"""
set -u
RED=; GREEN=; YELLOW=; BLUE=; NC=
SCRIPT_DIR="$WORK"
is_truthy() { case "${1:-}" in 1|true|yes|on) return 0 ;; *) return 1 ;; esac; }
cli_hint() { echo shakerscan; }
# Volumes present: one file per volume name in $WORK/volumes.
docker() {
  echo "docker $*" >> "$WORK/calls.log"
  case "${1:-} ${2:-}" in
    "volume ls") ls -1 "$WORK/volumes" ;;
    "volume inspect") [ -e "$WORK/volumes/$3" ] ;;
    "ps -q"|"ps -aq") return 0 ;;
  esac
}
"""


def _compose(tmp_path: Path, args: str, volumes: tuple[str, ...], **env: str) -> subprocess.CompletedProcess[str]:
    (tmp_path / "volumes").mkdir(exist_ok=True)
    for name in volumes:
        (tmp_path / "volumes" / f"shakerscan_{name}").write_text("")
    script = "\n".join([
        COMPOSE_HARNESS,
        f'source "{SAFETY}"',
        "COMPOSE_FILE_ARGS=(-f docker-compose.release.yml)",
        "resolve_compose_command() { DOCKER_COMPOSE_CMD=(echo COMPOSE); }",
        _extract("compose_subcommand"),
        _extract("compose"),
        f"compose {args}; echo rc=$?",
    ])
    return _bash(script, WORK=str(tmp_path), **env)


STARTS_POSTGRES = [
    "up -d postgres",
    "up --no-build -d postgres",
    "up --no-build -d --scale worker=2",
    "--profile devices up --no-build -d --force-recreate device-worker",
    "--profile model-intake up --no-build -d model-intake-signer",
    "run --rm api python -c pass",
    "create postgres",
]


@pytest.mark.parametrize("args", STARTS_POSTGRES)
def test_compose_refuses_to_start_postgresql_beside_unmigrated_data(tmp_path, args):
    result = _compose(tmp_path, args, ("postgres-data", "redis-data"))
    assert "rc=1" in result.stdout, result.stdout + result.stderr
    assert "COMPOSE" not in result.stdout  # Docker Compose itself never ran
    # The refusal goes to stderr: callers often discard or capture Compose's stdout.
    assert "shakerscan_postgres-data" in result.stderr and "2.10.0" in result.stderr


@pytest.mark.parametrize("args", ["ps -q postgres", "down --remove-orphans", "logs --tail 20 api",
                                  "exec -T postgres pg_isready", "config --quiet", "pull api worker ui"])
def test_compose_still_runs_what_cannot_start_postgresql(tmp_path, args):
    result = _compose(tmp_path, args, ("postgres-data",))
    assert "rc=0" in result.stdout and f"COMPOSE -f docker-compose.release.yml {args}" in result.stdout, \
        result.stdout + result.stderr


@pytest.mark.parametrize("volumes", [("postgres-data", "postgres-cluster"), ("postgres-cluster",), ()])
def test_compose_starts_postgresql_once_the_data_is_migrated_or_on_a_new_host(tmp_path, volumes):
    result = _compose(tmp_path, "up --no-build -d postgres", volumes)
    assert "rc=0" in result.stdout and "COMPOSE -f docker-compose.release.yml up" in result.stdout, \
        result.stdout + result.stderr


def test_compose_starts_an_empty_database_beside_the_old_data_only_on_purpose(tmp_path):
    result = _compose(tmp_path, "up --no-build -d postgres", ("postgres-data",), SHAKERSCAN_ALLOW_NEW_DATABASE="1")
    assert "rc=0" in result.stdout and "COMPOSE" in result.stdout, result.stdout + result.stderr


def test_compose_asks_docker_about_the_volumes_once_per_run(tmp_path):
    (tmp_path / "volumes").mkdir()
    script = "\n".join([
        COMPOSE_HARNESS, f'source "{SAFETY}"', "COMPOSE_FILE_ARGS=(-f docker-compose.release.yml)",
        "resolve_compose_command() { DOCKER_COMPOSE_CMD=(echo COMPOSE); }",
        _extract("compose_subcommand"), _extract("compose"),
        "compose up -d redis; compose up -d postgres; compose run --rm api true",
    ])
    result = _bash(script, WORK=str(tmp_path))
    assert result.stdout.count("COMPOSE") == 3, result.stdout + result.stderr
    assert (tmp_path / "calls.log").read_text().count("docker volume ls") == 1


# --- credentials: a weak recorded password beside the old data is never rewritten ---------------


def _credentials(tmp_path: Path, command: str, existing_env: str) -> tuple[subprocess.CompletedProcess[str], str]:
    env_file = tmp_path / ".env"
    env_file.write_text(existing_env)
    script = "\n".join([
        "set -u",
        f'SCRIPT_DIR="{tmp_path}"',
        'RED=""; NC=""',
        'command_exists() { [ "$1" = docker ]; }',
        'compose() { echo "compose $*" >> "$SCRIPT_DIR/calls.log"; return 1; }',
        # Only the PostgreSQL 16 volume exists.
        'docker() { [ "$*" = "volume inspect shakerscan_postgres-data" ]; }',
        "sleep() { :; }",
        *(_extract(name) for name in ("read_dotenv_value", "write_dotenv_value", "generate_datastore_secret",
                                      "postgres_data_volume_exists", "ensure_runtime_datastore_credentials")),
        f'COMMAND="{command}"',
        "ensure_runtime_datastore_credentials; echo rc=$?",
    ])
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30, check=False,
                            env={**os.environ, "POSTGRES_PASSWORD": "", "REDIS_PASSWORD": "", "MINIO_ROOT_PASSWORD": ""})
    return result, env_file.read_text()


def test_a_weak_password_beside_unmigrated_data_is_not_replaced_by_a_command_that_cannot_rotate_it(tmp_path):
    """The role in the PostgreSQL 16 data still has the recorded password: writing a new one to .env
    without ALTER ROLE locks the release that migrates the data out of its own database."""
    result, env = _credentials(tmp_path, "build", "POSTGRES_PASSWORD=short\n")
    assert "rc=0" in result.stdout, result.stdout + result.stderr
    assert "POSTGRES_PASSWORD=short\n" in env


def test_a_start_beside_unmigrated_data_never_records_an_unrotated_password(tmp_path):
    result, env = _credentials(tmp_path, "start", "POSTGRES_PASSWORD=short\n")
    assert "rc=1" in result.stdout, result.stdout + result.stderr
    assert "POSTGRES_PASSWORD=short\n" in env
    # Another install directory's data: no recorded password at all.
    other = tmp_path / "other"
    other.mkdir()
    result, env = _credentials(other, "start", "")
    assert "rc=1" in result.stdout and "already exists, but" in result.stderr, result.stdout + result.stderr
    assert "POSTGRES_PASSWORD" not in env


# --- the installer: another directory's PostgreSQL 16 volume ---------------------------------------


def _foreign_install(tmp_path: Path, volume: str) -> subprocess.CompletedProcess[str]:
    source = INSTALLER.read_text(encoding="utf-8")
    script = "\n".join([
        "set -eu",
        f'INSTALL_DIR="{tmp_path}/install"',
        'OWNED_MANIFEST_NAME=".shakerscan-installed-files"',
        "INSTALL_URL=https://install.shakerscan.com",
        "say() { printf '%s\\n' \"$*\"; }",
        "have() { [ \"$1\" = docker ]; }",
        # No container of the project; only the named volume exists.
        f'docker() {{ case "$1 $2" in "ps -a") return 0 ;; "volume inspect") [ "$3" = "{volume}" ] ;; *) return 1 ;; esac; }}',
        _extract("refuse_foreign_install", source),
        "refuse_foreign_install",
        "echo PASSED",
    ])
    return subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=30, check=False,
                          env={"PATH": "/usr/bin:/bin"})


@pytest.mark.parametrize("volume", ["shakerscan_postgres-data", "shakerscan_postgres-cluster"])
def test_the_installer_refuses_to_take_over_another_directorys_database_volume(tmp_path, volume):
    result = _foreign_install(tmp_path, volume)
    assert result.returncode == 1 and "PASSED" not in result.stdout, result.stdout + result.stderr
    assert "a PostgreSQL data volume for Compose project 'shakerscan' already exists" in result.stderr


def test_the_installer_installs_on_a_host_without_a_database_volume(tmp_path):
    result = _foreign_install(tmp_path, "shakerscan_redis-data")
    assert result.returncode == 0 and "PASSED" in result.stdout, result.stdout + result.stderr


# --- the real `start` against a fake Docker ---------------------------------------------------------

FAKE_DOCKER = r"""#!/bin/bash
printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG"
vols="$FAKE_DOCKER_VOLUMES"
running() { [ "${FAKE_RUNNING:-0}" = 1 ]; }
case "$1" in
  compose)
    shift
    case " $* " in *" version "*) echo "Docker Compose version v2.30.0"; exit 0 ;; esac
    while [ $# -gt 0 ]; do
      case "$1" in
        -f|--file|-p|--project-name|--profile|--env-file|--project-directory) shift 2 ;;
        -*) shift ;;
        *) break ;;
      esac
    done
    case "${1:-}" in
      up|run|create)
        # What Docker does: the release Compose file's volume is created and PostgreSQL 18
        # initializes an empty database in it. No container starts in this fixture.
        : > "$vols/shakerscan_postgres-cluster"
        echo "fake docker: no container starts here" >&2
        exit 1 ;;
    esac
    exit 0 ;;
  volume)
    case "${2:-}" in
      ls) ls -1 "$vols"; exit 0 ;;
      inspect) [ -e "$vols/${3:-}" ]; exit ;;
      *) echo "fake docker: volume $2 is not allowed here" >&2; exit 1 ;;
    esac ;;
  ps)
    running && case "$*" in *project=shakerscan*) echo cid-old ;; esac
    exit 0 ;;
  inspect)
    if running; then
      case "$*" in
        *Config.Env*) echo SCANNER_VERSION=2.5.6 ;;
        *Mounts*) printf 'volume /var/lib/postgresql/data\nvolume /data\n' ;;
        *State.Status*) echo running ;;
      esac
    fi
    exit 0 ;;
esac
exit 0
"""

RUNTIME_FILES = ("scanner.sh", "docker-compose.release.yml", "scripts/upgrade_safety.sh",
                 "scripts/target_upgrade_backup.sh", "install/release-images.sh", "install/release-images.json",
                 "install/STABLE_VERSION", "db/init.sql")


def _start(tmp_path: Path, command: str, *, running: bool) -> tuple[subprocess.CompletedProcess[str], str, list[str]]:
    return _launch(tmp_path, command, "--prebuilt", "-y", running=running)


def _launch(tmp_path: Path, *args: str, running: bool = False,
            record: str | None = None) -> tuple[subprocess.CompletedProcess[str], str, list[str]]:
    """The real launcher in a copy of the runtime files, against the fake Docker, beside postgres-data."""
    install = tmp_path / "install"
    for relative in RUNTIME_FILES:
        (install / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, install / relative)
    (install / ".shakerscan-local-build").write_text("prebuilt\n")
    (install / ".env").write_text(f"POSTGRES_PASSWORD={'p' * 40}\nREDIS_PASSWORD={'r' * 40}\n")
    if record is not None:
        (install / ".release-images.current").write_text(record)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text(FAKE_DOCKER)
    for name, body in (("curl", "echo blocked: curl >&2; exit 7"), ("sudo", "echo blocked: sudo >&2; exit 1")):
        (bin_dir / name).write_text(f"#!/bin/sh\n{body}\n")
    for tool in bin_dir.iterdir():
        tool.chmod(0o755)
    volumes = tmp_path / "volumes"
    volumes.mkdir()
    for name in ("shakerscan_postgres-data", "shakerscan_redis-data"):
        (volumes / name).write_text("")
    log = tmp_path / "docker.log"
    log.write_text("")
    result = subprocess.run(
        ["bash", str(install / "scanner.sh"), *args], cwd=install, capture_output=True,
        text=True, timeout=120, check=False, stdin=subprocess.DEVNULL,
        env={"HOME": str(tmp_path / "home"), "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/sbin:/sbin", "TERM": "dumb",
             "FAKE_DOCKER_LOG": str(log), "FAKE_DOCKER_VOLUMES": str(volumes), "FAKE_RUNNING": "1" if running else "0",
             "SHAKERSCAN_PULL_IMAGES": "0", "SHAKERSCAN_REDIS_READY_SECONDS": "0",
             "SHAKERSCAN_REDIS_LOADING_SECONDS": "0"},
    )
    return result, log.read_text(), sorted(path.name for path in volumes.iterdir())


@pytest.mark.parametrize("running", [False, True], ids=["stopped", "running"])
@pytest.mark.parametrize("command", ["start", "restart"])
def test_start_refuses_unmigrated_postgresql_16_data_with_nothing_changed(tmp_path, command, running):
    """The verified failure: `start --prebuilt` on a stopped 2.5.6 install ran `compose up -d postgres`,
    which created shakerscan_postgres-cluster beside shakerscan_postgres-data."""
    result, docker_log, volumes = _start(tmp_path, command, running=running)
    output = result.stdout + result.stderr
    compose_calls = [line for line in docker_log.splitlines() if line.startswith("compose ")]
    changed = [line for line in compose_calls
               if re.search(r"\s(up|run|create|down|stop|rm|restart|pull)(\s|$)", line)]
    assert changed == [], changed
    assert volumes == ["shakerscan_postgres-data", "shakerscan_redis-data"]
    assert "pg_dump" not in docker_log
    assert result.returncode == 1, output + docker_log
    assert "shakerscan_postgres-data" in result.stderr and "SHAKERSCAN_INSTALL_VERSION=2.10.0" in result.stderr, output
    if running:
        assert "the running release keeps running" in result.stderr, output


def _changes(docker_log: str) -> list[str]:
    """Every Docker call in the log that changes a container, volume, network or image."""
    mutating = re.compile(r"\s(up|run|create|down|stop|rm|restart|pull|build|kill)(\s|$)")
    changed = []
    for line in docker_log.splitlines():
        if line.startswith("compose "):
            if mutating.search(line):
                changed.append(line)
        elif re.match(r"(rm|run|create|stop|kill|restart|build|buildx|pull|(volume|network|image) (rm|create|prune))(\s|$)",
                      line):
            changed.append(line)
    return changed


@pytest.mark.parametrize("args", [
    ("redis", "reset", "--yes"),
    ("model-intake", "enable"),
    ("model-intake", "disable"),
    ("scale", "2"),
    ("rebuild",),
    ("devices", "start"),
    ("devices", "restart"),
    ("gungnir", "start"),
    ("shell",),
], ids=lambda args: " ".join(args))
def test_commands_that_change_the_install_before_starting_containers_refuse_first(tmp_path, args):
    """`redis reset` removed Redis's volume (its copy was refused, silently) and then could not start
    Redis; `rebuild` removed the running workers; `model-intake` wrote .env. Each then reached a
    refused `compose up`. Now each is refused before it changes anything."""
    result, docker_log, volumes = _launch(tmp_path, *args, "--prebuilt", "-y", running=True)
    output = result.stdout + result.stderr
    assert _changes(docker_log) == [], docker_log
    assert volumes == ["shakerscan_postgres-data", "shakerscan_redis-data"]
    # Every launcher command records the API sandbox group first; nothing else may be written.
    env = [line for line in (tmp_path / "install" / ".env").read_text().splitlines()
           if not line.startswith("SHAKERSCAN_API_SANDBOX_GROUP_GID=")]
    assert env == [f"POSTGRES_PASSWORD={'p' * 40}", f"REDIS_PASSWORD={'r' * 40}"]
    assert result.returncode == 1, output + docker_log
    assert "shakerscan_postgres-data" in result.stderr and "never migrated" in result.stderr, output


@pytest.mark.parametrize("args", [("redis",), ("devices", "status"), ("model-intake", "status"), ("backup", "list"),
                                  ("logs", "api")], ids=lambda args: " ".join(args))
def test_commands_that_only_read_still_run_beside_the_old_data(tmp_path, args):
    result, docker_log, _ = _launch(tmp_path, *args, "--prebuilt", "-y")
    assert "never migrated" not in result.stdout + result.stderr, result.stdout + result.stderr
    assert _changes(docker_log) == [], docker_log


def test_start_beside_the_copy_a_migration_kept_points_to_backups(tmp_path):
    """A 2.10 record: postgres-cluster was lost (say `docker compose down -v`) and postgres-data is the
    copy kept on the migration day. 2.10.0 would migrate that stale copy again as if it were current."""
    result, docker_log, volumes = _launch(tmp_path, "start", "--prebuilt", "-y", record="# release 2.10.0\nref\n")
    output = result.stdout + result.stderr
    assert _changes(docker_log) == [] and volumes == ["shakerscan_postgres-data", "shakerscan_redis-data"], docker_log
    assert result.returncode == 1, output
    assert "missing although this install has started before" in result.stderr, output
    assert "backups" in result.stderr and "nothing recorded since" in result.stderr
    assert "never migrated" not in result.stderr and "SHAKERSCAN_INSTALL_VERSION=2.10.0" not in result.stderr


def test_a_source_checkout_start_is_pointed_to_the_2_10_0_tag(tmp_path):
    result, docker_log, volumes = _launch(tmp_path, "start", "--local", "-y")
    output = result.stdout + result.stderr
    assert _changes(docker_log) == [] and volumes == ["shakerscan_postgres-data", "shakerscan_redis-data"], docker_log
    assert result.returncode == 1, output
    assert "git checkout v2.10.0 && ./scanner.sh start --local" in result.stderr, output
    assert "install.shakerscan.com" not in result.stderr
