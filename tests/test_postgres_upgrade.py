"""PostgreSQL 16 -> 18 upgrade: the launcher migrates older data before anything can start PostgreSQL.

PostgreSQL 18 images refuse the old /var/lib/postgresql/data mount and cannot read 16 data files.
scripts/postgres_upgrade.sh copies an older cluster into the new major with pg_dumpall and verifies
it; `compose()` runs that guard before every subcommand that can start PostgreSQL. The real-image
path is exercised by scripts/postgres_upgrade_smoke.sh; these tests pin the decisions and wiring.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts" / "postgres_upgrade.sh"
SCANNER = ROOT / "scanner.sh"


def _extract(name: str) -> str:
    text = SCANNER.read_text(encoding="utf-8")
    match = re.search(rf"^{re.escape(name)}\(\) \{{\n.*?^\}}\n", text, re.MULTILINE | re.DOTALL)
    assert match, f"{name} not found in scanner.sh"
    return match.group(0)


def _bash(script: str, *, env: dict[str, str] | None = None, stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, input=stdin, cwd=ROOT,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", **(env or {})},
    )


def _plan(target: int, legacy: str = "", cluster: str = "", receipts: str = "") -> str:
    result = _bash(
        f'source "{MODULE}"; postgres_cluster_plan {target} "{legacy}" "{cluster}" "{receipts}"'
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@pytest.mark.parametrize(
    ("legacy", "cluster", "receipts", "expected"),
    [
        # A new host: PostgreSQL initializes 18 itself.
        ("", "", "", "fresh"),
        # An earlier release's data is copied into 18.
        ("16", "", "", "migrate legacy 16"),
        # After a verified copy the legacy volume stays for rollback, and that is not a reason to copy again.
        ("16", "18", "18", "ready"),
        ("", "18", "18", "ready"),
        # 18 initialized on a host that never had older data.
        ("", "18", "", "ready"),
        # 18 started before the upgrade ran: an empty cluster beside the real data must not win.
        ("16", "18", "", "conflict 18"),
    ],
)
def test_the_plan_for_a_postgresql_18_target(legacy, cluster, receipts, expected):
    assert _plan(18, legacy, cluster, receipts) == expected


def test_a_later_major_migrates_from_the_newest_older_cluster():
    assert _plan(19, "16", "18", "18") == "migrate cluster 18"
    assert _plan(19, "16", "17 18", "18") == "migrate cluster 18"
    assert _plan(19, "", "18 19", "18 19") == "ready"
    assert _plan(19, "", "18 19", "18") == "conflict 19"


def test_newer_data_than_the_target_is_a_refused_downgrade():
    assert _plan(18, "", "19", "") == "downgrade 19"
    assert _plan(18, "19", "", "") == "downgrade 19"


def test_a_target_older_than_the_cluster_layout_is_unsupported():
    assert _plan(16, "16", "", "") == "unsupported 16"
    assert _plan(17, "", "", "") == "unsupported 17"


COMPOSE_HARNESS = """
set -e
RED=""; NC=""
COMPOSE_FILE_ARGS=(-f docker-compose.release.yml)
resolve_compose_command() { DOCKER_COMPOSE_CMD=(echo COMPOSE); }
ensure_postgres_cluster_current() { echo GUARD; return "${GUARD_STATUS:-0}"; }
"""


def _compose(args: str, guard_status: int = 0) -> subprocess.CompletedProcess:
    script = "\n".join([
        COMPOSE_HARNESS, _extract("compose_subcommand"), _extract("compose"),
        f"compose {args}",
    ])
    return _bash(script, env={"GUARD_STATUS": str(guard_status)})


@pytest.mark.parametrize(
    "args",
    [
        "up -d --scale worker=2",
        "up -d postgres",
        "--profile devices up --no-build -d --force-recreate device-worker",
        "run --rm api python -c pass",
        "create postgres",
    ],
)
def test_every_subcommand_that_can_start_postgres_runs_the_upgrade_guard_first(args):
    result = _compose(args)
    assert result.returncode == 0, result.stderr
    # The guard reports on stderr, so callers that silence or capture Compose's stdout still show it.
    assert result.stderr.strip() == "GUARD"
    assert result.stdout.strip().startswith("COMPOSE -f docker-compose.release.yml")


@pytest.mark.parametrize(
    "args",
    [
        "ps -q",
        "down -v",
        "--profile up logs -f",
        "exec -T postgres pg_isready -U scanner",
        "config --images",
        "pull api worker",
        "stop",
    ],
)
def test_subcommands_that_cannot_start_postgres_skip_the_guard(args):
    result = _compose(args)
    assert result.returncode == 0, result.stderr
    assert "GUARD" not in result.stdout + result.stderr


def test_a_failed_guard_keeps_compose_from_starting_anything():
    result = _compose("up -d", guard_status=1)
    assert result.returncode == 1
    assert "COMPOSE" not in result.stdout


def test_reset_also_removes_the_data_kept_for_rollback(tmp_path):
    # `down -v` only removes Compose volumes; the legacy volume left for rollback would otherwise be
    # migrated straight back into the fresh cluster on the next start.
    log = tmp_path / "calls"
    script = "\n".join([
        'set -e; RED=""; GREEN=""; NC=""',
        f'source "{MODULE}"',
        f'LOG="{log}"',
        "COMPOSE_PROJECT_NAME=demo",
        "resolve_start_workers() { echo 1; }",
        'compose() { echo "compose $*" >> "$LOG"; }',
        'compose_up() { echo "compose_up $*" >> "$LOG"; }',
        'docker_cli() { echo "docker $*" >> "$LOG"; }',
        _extract("reset_database"),
        "reset_database",
    ])
    result = _bash(script, stdin="yes\n")
    assert result.returncode == 0, result.stderr
    lines = log.read_text().splitlines()
    assert lines == [
        "compose down -v",
        "docker volume rm -f demo_postgres-data",
        "compose_up -d --scale worker=1",
    ]


def _target_image(env: dict[str, str], dotenv: str = "") -> str:
    script = "\n".join([
        f'source "{MODULE}"',
        f'SCRIPT_DIR="{ROOT}"',
        "COMPOSE_FILE_ARGS=(-f docker-compose.release.yml)",
        f"read_dotenv_value() {{ [ \"$1\" = POSTGRES_IMAGE ] && printf '%s' '{dotenv}'; return 0; }}",
        "postgres_target_image",
    ])
    result = _bash(script, env=env)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _compose_postgres_image(name: str = "docker-compose.release.yml") -> str:
    service = yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))["services"]["postgres"]
    match = re.fullmatch(r"\$\{POSTGRES_IMAGE:-(.+)\}", service["image"])
    assert match, service["image"]
    return match.group(1)


def test_the_target_image_follows_compose_resolution():
    assert _target_image({}) == _compose_postgres_image()
    assert _target_image({}, dotenv="mirror.example/postgres:18") == "mirror.example/postgres:18"
    assert _target_image({"POSTGRES_IMAGE": "shell/postgres:18"}, dotenv="mirror.example/postgres:18") == \
        "shell/postgres:18"


@pytest.mark.parametrize("name", ["docker-compose.yml", "docker-compose.release.yml"])
def test_compose_runs_pinned_postgresql_18_on_the_cluster_volume(name):
    config = yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))
    image = _compose_postgres_image(name)
    assert re.fullmatch(r"postgres:18\.\d+-alpine[0-9.]*@sha256:[0-9a-f]{64}", image), image
    assert "postgres-cluster:/var/lib/postgresql" in config["services"]["postgres"]["volumes"]
    # The 18+ image refuses to start with anything mounted at the old data path.
    for service_name, service in config["services"].items():
        for volume in service.get("volumes", []) or []:
            assert not str(volume).endswith(":/var/lib/postgresql/data"), service_name
    assert "postgres-cluster" in config["volumes"]
    # Left undeclared on purpose: `down -v` must not delete the data kept for rolling back.
    assert "postgres-data" not in config["volumes"]
    signer_init = config["services"]["model-intake-signer-db-init"]["image"]
    assert signer_init == "${MODEL_INTAKE_SIGNER_POSTGRES_IMAGE:-" + image + "}"


def test_every_postgresql_pin_names_the_same_image():
    image = _compose_postgres_image()
    assert _compose_postgres_image("docker-compose.yml") == image
    smoke = (ROOT / "scripts" / "upgrade_smoke.sh").read_text(encoding="utf-8")
    assert f'POSTGRES_IMAGE="${{POSTGRES_IMAGE:-{image}}}"' in smoke


def test_the_installer_ships_the_upgrade_module_and_recognises_both_data_volumes():
    installer = (ROOT / "install" / "index.sh").read_text(encoding="utf-8")
    assert 'download "$REPO_RAW_BASE/scripts/postgres_upgrade.sh" "$INSTALL_DIR/scripts/postgres_upgrade.sh"' in installer
    assert '"${project}_postgres-cluster"' in installer and '"${project}_postgres-data"' in installer
    manifest = (ROOT / "install" / "MANIFEST.sha256").read_text(encoding="utf-8")
    assert re.search(r"^[0-9a-f]{64}  scripts/postgres_upgrade\.sh$", manifest, re.MULTILINE)


def test_the_launcher_refuses_to_run_without_the_upgrade_module(tmp_path):
    # Without the guard a start would let PostgreSQL 18 initialize an empty cluster beside the data.
    launcher = tmp_path / "scanner.sh"
    launcher.write_text(SCANNER.read_text(encoding="utf-8"), encoding="utf-8")
    result = subprocess.run(["bash", str(launcher), "status"], capture_output=True, text=True, cwd=tmp_path)
    assert result.returncode == 1
    assert "postgres_upgrade.sh is missing" in result.stderr


def _source_state(probe: dict[str, str], target: int = 18) -> str:
    lines = "\\n".join(f"{key}={value}" for key, value in probe.items())
    result = _bash(
        f'source "{MODULE}"; COMPOSE_PROJECT_NAME=demo; '
        f'postgres_source_state "$(printf "{lines}")" {target}'
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


RECEIPT = {"legacy_major": "16", "receipt_18_from_kind": "legacy", "receipt_18_from_major": "16",
           "receipt_18_source_control": "a" * 64}


def test_a_copy_whose_source_never_ran_again_is_unchanged():
    assert _source_state({**RECEIPT, "legacy_control": "a" * 64}) == "unchanged"


def test_a_rollback_that_ran_on_the_old_data_is_detected():
    # Any run of PostgreSQL 16 on the legacy volume rewrites pg_control, so its digest moves.
    assert _source_state({**RECEIPT, "legacy_control": "b" * 64}) == "diverged legacy 16"


def test_removed_old_data_and_pre_fingerprint_receipts_are_not_divergence():
    assert _source_state({k: v for k, v in RECEIPT.items() if k != "legacy_major"}) == "gone"
    legacy_receipt = {"legacy_major": "16", "legacy_control": "b" * 64,
                      "receipt_18_from_major": "16", "receipt_18_from_volume": "demo_postgres-data"}
    assert _source_state(legacy_receipt) == "unrecorded"


def test_a_later_major_compares_against_the_older_cluster_directory():
    probe = {"receipt_19_from_kind": "cluster", "receipt_19_from_major": "18",
             "receipt_19_source_control": "c" * 64, "control_18": "c" * 64}
    assert _source_state(probe, target=19) == "unchanged"
    assert _source_state({**probe, "control_18": "d" * 64}, target=19) == "diverged cluster 18"


def test_every_major_a_target_can_migrate_from_has_a_pinned_source_image():
    # Moving the stack to PostgreSQL 19 must keep an image that can read 18 data, or every 18 install
    # would stop at "no pinned image can read PostgreSQL 18 data".
    target = int(re.match(r"postgres:(\d+)\.", _compose_postgres_image()).group(1))
    for major in [16, *range(18, target)]:
        result = _bash(f'source "{MODULE}"; postgres_source_image_for_major {major}')
        assert result.returncode == 0, f"no pinned source image for PostgreSQL {major}"
        assert re.fullmatch(rf"postgres:{major}\.\d+-alpine[0-9.]*@sha256:[0-9a-f]{{64}}", result.stdout.strip())


def test_the_cli_offers_both_ways_to_resolve_a_rollback():
    script = "\n".join([
        'RED=""; NC=""',
        "cli_hint() { echo shakerscan; }",
        'remigrate_postgres_cluster() { echo REMIGRATE; }',
        'keep_current_postgres_cluster() { echo KEEP; }',
        _extract("db_upgrade_cmd"),
        "db_upgrade_cmd --remigrate; db_upgrade_cmd --keep-current; db_upgrade_cmd --bogus",
    ])
    result = _bash(script)
    assert result.stdout.splitlines()[:2] == ["REMIGRATE", "KEEP"]
    assert "--remigrate|--keep-current" in result.stderr


# --- Retention of the rollback data -------------------------------------------------------------

def _retention_plan(retention: int, age: str, state: str, has_data: str = "1") -> str:
    result = _bash(f'source "{MODULE}"; postgres_retention_plan {retention} "{age}" "{state}" "{has_data}"')
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@pytest.mark.parametrize(
    ("retention", "age", "state", "has_data", "expected"),
    [
        (30, "3", "unchanged", "1", "wait 27"),
        # The last week before deletion is announced on every start.
        (30, "23", "unchanged", "1", "notice 7"),
        (30, "29", "unchanged", "1", "notice 1"),
        (30, "30", "unchanged", "1", "expire"),
        (30, "400", "unchanged", "1", "expire"),
        # 0 keeps it until an operator removes it.
        (0, "400", "unchanged", "1", "keep"),
        # Data a rollback wrote to, or a copy that predates fingerprints or timestamps, is never
        # deleted automatically.
        (30, "400", "diverged", "1", "hold"),
        (30, "400", "unrecorded", "1", "hold"),
        (30, "", "unchanged", "1", "hold"),
        (30, "400", "unchanged", "", "none"),
    ],
)
def test_the_retention_plan(retention, age, state, has_data, expected):
    assert _retention_plan(retention, age, state, has_data) == expected


def _retention_days(env: dict[str, str], dotenv: str = "") -> subprocess.CompletedProcess:
    return _bash(
        f'source "{MODULE}"; '
        f"read_dotenv_value() {{ [ \"$1\" = SHAKERSCAN_POSTGRES_LEGACY_RETENTION_DAYS ] && printf '%s' '{dotenv}'; return 0; }}; "
        "postgres_legacy_retention_days",
        env=env,
    )


def test_the_retention_setting_defaults_to_30_days_and_reads_the_shell_then_dotenv():
    assert _retention_days({}).stdout.strip() == "30"
    assert _retention_days({}, dotenv="90").stdout.strip() == "90"
    assert _retention_days({"SHAKERSCAN_POSTGRES_LEGACY_RETENTION_DAYS": "0"}, dotenv="90").stdout.strip() == "0"
    assert _retention_days({"SHAKERSCAN_POSTGRES_LEGACY_RETENTION_DAYS": "007"}).stdout.strip() == "7"
    for bad in ("thirty", "-1", "1.5"):
        assert _retention_days({"SHAKERSCAN_POSTGRES_LEGACY_RETENTION_DAYS": bad}).returncode == 1, bad


def _stamp(days_ago: int) -> str:
    import datetime
    moment = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_ago, hours=1)
    return moment.strftime("%Y%m%dT%H%M%SZ")


def test_receipt_ages_and_deletion_dates():
    result = _bash(
        f'source "{MODULE}"; postgres_days_since {_stamp(31)}; postgres_days_since {_stamp(0)}; '
        "postgres_date_after 20261001T004718Z 30; postgres_days_since not-a-stamp || echo unparsable",
        env={"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"},
    )
    assert result.stdout.split() == ["31", "0", "2026-10-31", "unparsable"]


def test_the_notice_names_every_piece_of_rollback_data():
    result = _bash(
        f'source "{MODULE}"; COMPOSE_PROJECT_NAME=demo; '
        'postgres_describe_rollback_data "$(printf "legacy 16\\ncluster 17")"'
    )
    assert result.stdout == ("the PostgreSQL 16 volume demo_postgres-data and the PostgreSQL 17 directory "
                             "in demo_postgres-cluster")


def test_old_upgrade_dumps_expire_and_other_backups_are_never_touched(tmp_path):
    old = tmp_path / "backups" / f"postgres-16-to-18-{_stamp(31)}"
    recent = tmp_path / "backups" / f"postgres-16-to-18-{_stamp(5)}"
    operator_backup = tmp_path / "backups" / f"shakerscan-{_stamp(400)}"
    for directory in (old, recent, operator_backup):
        directory.mkdir(parents=True)
    for directory in (old, recent):
        (directory / "pg_dumpall.sql.gz").write_bytes(b"dump")
        (directory / "source-fingerprint.txt").write_text("kept as the upgrade's audit record")
    (operator_backup / "postgres.dump").write_bytes(b"operator backup")
    result = _bash(
        f'source "{MODULE}"; SCRIPT_DIR="{tmp_path}"; postgres_expire_aged_copies "replaced_dirs=" unused 30',
        env={"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"},
    )
    assert result.returncode == 0, result.stderr
    assert not (old / "pg_dumpall.sql.gz").exists()
    assert "removed" in (old / "DUMP-REMOVED.txt").read_text()
    assert (old / "source-fingerprint.txt").exists()
    assert (recent / "pg_dumpall.sql.gz").exists()
    assert (operator_backup / "postgres.dump").exists()


# --- Directories a container still uses are never deleted ----------------------------------------

FULL_PATH = "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin"
CANONICAL = {"Name": "/demo-postgres-1", "Config": {"Env": ["PGDATA=/var/lib/postgresql/18/docker"]},
             "Mounts": [{"Name": "demo_postgres-cluster", "Destination": "/var/lib/postgresql"}]}
UNKNOWN = {"Name": "/backup-shell", "Config": {"Env": ["PATH=/bin"]},
           "Mounts": [{"Name": "demo_postgres-cluster", "Destination": "/c"}]}
ASIDE = f"18/replaced-{_stamp(40)}"


def _recovery(directory: str, name: str = "/recovery") -> dict:
    # A recovery run on an older copy: the volume mounted elsewhere, PGDATA pointing into it.
    return {"Name": name, "Config": {"Env": ["POSTGRES_PASSWORD=x", f"PGDATA=/data/{directory}"]},
            "Mounts": [{"Name": "demo_postgres-cluster", "Destination": "/data"}]}


def _cluster_harness(directory: Path, containers: list[dict]) -> tuple[str, Path]:
    """Source the module with Docker answering from `containers` and the cluster shell recorded."""
    directory.mkdir(parents=True, exist_ok=True)
    log = directory / "calls"
    inspect = directory / "inspect.json"
    inspect.write_text(json.dumps(containers))
    ids = " ".join(f"id{index}" for index in range(len(containers)))
    harness = "\n".join([
        'RED=""; YELLOW=""; NC=""',
        f'source "{MODULE}"',
        f'SCRIPT_DIR="{directory}"; LOG="{log}"; COMPOSE_PROJECT_NAME=demo',
        "docker_cli() {",
        '    case "$1" in',
        f'        ps) echo "docker $*" >> "$LOG"; printf "%s\\n" {ids} ;;',
        f'        inspect) cat "{inspect}" ;;',
        '        *) echo "docker $*" >> "$LOG" ;;',
        "    esac",
        "}",
        'postgres_cluster_shell() { echo "shell $2" >> "$LOG"; }',
    ])
    return harness, log


def _calls(log: Path) -> list[str]:
    return log.read_text().splitlines() if log.exists() else []


def _expire_aside(directory: Path, containers: list[dict]) -> tuple[str, list[str]]:
    harness, log = _cluster_harness(directory, containers)
    result = _bash(harness + f'\npostgres_expire_aged_copies "replaced_dirs={ASIDE}" image 30', env={"PATH": FULL_PATH})
    assert result.returncode == 0, result.stderr
    return result.stdout, _calls(log)


def test_an_aged_set_aside_copy_a_recovery_container_uses_is_kept(tmp_path):
    out, calls = _expire_aside(tmp_path, [CANONICAL, _recovery(ASIDE)])
    assert not any(call.startswith("shell rm") for call in calls)
    assert f"The set-aside copy {ASIDE} is past its 30-day retention but container recovery still uses it" in out
    assert "removed on a later start" in out
    # Stopped containers count too: the lookup lists every container, not only running ones.
    assert "docker ps -aq --filter volume=demo_postgres-cluster" in calls


def test_a_container_whose_data_directory_cannot_be_placed_holds_every_directory(tmp_path):
    out, calls = _expire_aside(tmp_path, [UNKNOWN])
    assert not any(call.startswith("shell rm") for call in calls)
    assert "container backup-shell still uses it" in out


def test_the_stacks_own_postgresql_does_not_hold_other_directories(tmp_path):
    out, calls = _expire_aside(tmp_path, [CANONICAL])
    assert f"shell rm -rf '/var/lib/postgresql/{ASIDE}'" in calls
    assert f"Removed the set-aside copy {ASIDE}" in out


def test_the_copy_is_removed_once_no_container_uses_it(tmp_path):
    _, calls = _expire_aside(tmp_path, [])
    assert f"shell rm -rf '/var/lib/postgresql/{ASIDE}'" in calls


@pytest.mark.parametrize("data_directory", [f"{ASIDE}/nested", "18"])
def test_a_data_directory_inside_or_around_the_copy_holds_it(tmp_path, data_directory):
    _, calls = _expire_aside(tmp_path, [_recovery(data_directory)])
    assert not any(call.startswith("shell rm") for call in calls)


def test_an_older_major_directory_in_use_is_kept_past_its_retention(tmp_path):
    expire = '\npostgres_expire_rollback_data "cluster_majors=17 18" 18 image 30'
    harness, log = _cluster_harness(tmp_path / "held", [CANONICAL, _recovery("17/docker", "/pg17")])
    result = _bash(harness + expire, env={"PATH": FULL_PATH})
    assert result.returncode == 0, result.stderr
    assert not any(call.startswith("shell rm") for call in _calls(log))
    assert "PostgreSQL 17 rollback directory" in result.stdout and "container pg17 still uses it" in result.stdout

    harness, log = _cluster_harness(tmp_path / "free", [CANONICAL])
    result = _bash(harness + expire, env={"PATH": FULL_PATH})
    assert "shell rm -rf '/var/lib/postgresql/17'" in _calls(log)
    assert "Removed the PostgreSQL 17 rollback directory" in result.stdout


def _remove_legacy(directory: Path, containers: list[dict]) -> tuple[subprocess.CompletedProcess, list[str]]:
    harness, log = _cluster_harness(directory, containers)
    script = "\n".join([
        harness,
        "postgres_target_image() { echo image; }",
        "postgres_image_major() { echo 18; }",
        f"postgres_probe_volumes() {{ printf 'cluster_majors=17 18\\nreceipt_majors=18\\nreplaced_dirs={ASIDE}\\n'; }}",
        "postgres_volume_exists() { return 1; }",
        "remove_legacy_postgres_data",
    ])
    return _bash(script, env={"PATH": FULL_PATH}, stdin="remove\n"), _calls(log)


def test_remove_legacy_refuses_while_a_container_uses_a_directory_and_removes_nothing(tmp_path):
    result, calls = _remove_legacy(tmp_path, [CANONICAL, _recovery(ASIDE)])
    assert result.returncode == 1
    assert "container recovery still uses" in result.stderr and "Nothing was removed" in result.stderr
    # Not even the older major, which nothing uses: the refusal is all or nothing.
    assert not any(call.startswith("shell rm") for call in calls)


def test_remove_legacy_removes_everything_once_nothing_uses_it(tmp_path):
    result, calls = _remove_legacy(tmp_path, [CANONICAL])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "shell rm -rf '/var/lib/postgresql/17'" in calls
    assert f"shell rm -rf '/var/lib/postgresql/{ASIDE}'" in calls
    assert not (tmp_path / ".shakerscan-postgres.lock").exists()


# --- One PostgreSQL data operation at a time -----------------------------------------------------

def _hold_lock(directory: Path, pid: int) -> Path:
    lock = directory / ".shakerscan-postgres.lock"
    lock.mkdir(parents=True)
    (lock / "pid").write_text(f"{pid}\n")
    return lock


RETENTION = "\npostgres_expire_legacy_data() { echo EXPIRED; }\npostgres_apply_legacy_retention probe 18 image"


def test_retention_defers_while_another_operation_holds_the_lock(tmp_path):
    _hold_lock(tmp_path, os.getpid())
    harness, _ = _cluster_harness(tmp_path, [])
    result = _bash(harness + RETENTION, env={"PATH": FULL_PATH})
    assert result.returncode == 0, result.stderr
    assert "EXPIRED" not in result.stdout
    assert f"Another PostgreSQL data operation is running (process {os.getpid()})" in result.stdout


@pytest.mark.parametrize(
    "command", ["remove_legacy_postgres_data", "remigrate_postgres_cluster", "keep_current_postgres_cluster"],
)
def test_interactive_operations_refuse_while_another_holds_the_lock(tmp_path, command):
    _hold_lock(tmp_path, os.getpid())
    harness, log = _cluster_harness(tmp_path, [])
    result = _bash(harness + f"\n{command}", env={"PATH": FULL_PATH})
    assert result.returncode == 1
    assert "another PostgreSQL data operation is running" in result.stderr
    assert _calls(log) == []


def test_a_lock_left_by_a_process_that_exited_is_taken_over_and_released(tmp_path):
    finished = subprocess.run(["sh", "-c", "echo $$"], capture_output=True, text=True, check=True)
    lock = _hold_lock(tmp_path, int(finished.stdout))
    harness, _ = _cluster_harness(tmp_path, [])
    result = _bash(harness + RETENTION, env={"PATH": FULL_PATH})
    assert result.returncode == 0, result.stderr
    assert "EXPIRED" in result.stdout
    assert not lock.exists()


def test_the_lock_is_reentrant_within_one_process(tmp_path):
    harness, _ = _cluster_harness(tmp_path, [])
    script = harness + "\n" + "\n".join([
        "inner() { postgres_lock_acquire && echo INNER; postgres_lock_release; }",
        "postgres_locked inner",
        f'[ -e "{tmp_path}/.shakerscan-postgres.lock" ] && echo LEFT || echo RELEASED',
    ])
    assert _bash(script, env={"PATH": FULL_PATH}).stdout.split() == ["INNER", "RELEASED"]


# --- A copy is verified only when every verification query succeeded ----------------------------

FAKE_PSQL = r"""#!/bin/sh
db=""; cmd=""
while [ $# -gt 0 ]; do
    case "$1" in
        -d) db="$2"; shift 2 ;;
        -c) cmd="$2"; shift 2 ;;
        *) shift ;;
    esac
done
case "$cmd" in
    *pg_authid*) echo "role|scanner|t|t|abc"; exit 0 ;;
    *datname*)
        [ "$FAKE" = enumeration ] && { echo "ERROR: enumeration failed" >&2; exit 2; }
        [ "$FAKE" = empty ] && exit 0
        printf 'postgres\nscanner\nmy db\n'; exit 0 ;;
esac
cat > /dev/null
case "$db" in
    scanner)
        [ "$FAKE" = table ] && { echo "ERROR: table query failed" >&2; exit 3; }
        echo "table|public.t|5"; echo "sequence|public.t_id_seq|5" ;;
    "my db") echo "table|public.x|1" ;;
esac
"""


def _fingerprint(directory: Path, command: str, fake: str = "") -> subprocess.CompletedProcess:
    bin_dir = directory / "bin"
    bin_dir.mkdir(exist_ok=True)
    psql = bin_dir / "psql"
    psql.write_text(FAKE_PSQL)
    psql.chmod(0o755)
    script = "\n".join([
        f'source "{MODULE}"',
        # `docker exec -i <container> sh -s`: run the container's script here, against the fake psql.
        'docker_cli() { shift 3; "$@"; }',
        command,
    ])
    return _bash(script, env={"PATH": f"{bin_dir}:/usr/bin:/bin", "FAKE": fake})


def test_the_fingerprint_lists_every_database_including_one_named_with_spaces(tmp_path):
    result = _fingerprint(tmp_path, "postgres_cluster_fingerprint pg")
    assert result.returncode == 0, result.stderr
    assert sorted(result.stdout.splitlines()) == sorted([
        "role|scanner|t|t|abc",
        "db|postgres|present",
        "db|scanner|present", "db|scanner|table|public.t|5", "db|scanner|sequence|public.t_id_seq|5",
        "db|my db|present", "db|my db|table|public.x|1",
    ])


@pytest.mark.parametrize("fake", ["enumeration", "empty", "table"])
def test_a_failed_verification_query_fails_the_fingerprint(tmp_path, fake):
    # Before, an empty database list or a failed per-database query still exited 0, so a source and
    # a copy that both lost the same lines compared equal.
    assert _fingerprint(tmp_path, "postgres_cluster_fingerprint pg", fake).returncode != 0


def test_the_saved_fingerprint_is_sorted_and_a_failure_is_not_masked_by_the_sort(tmp_path):
    output = tmp_path / "fingerprint.txt"
    result = _fingerprint(tmp_path, f'postgres_write_fingerprint pg "{output}"')
    assert result.returncode == 0, result.stderr
    lines = output.read_text().splitlines()
    assert lines == sorted(lines) and "db|my db|present" in lines
    assert not (tmp_path / "fingerprint.txt.unsorted").exists()

    output.unlink()
    failed = _fingerprint(tmp_path, f'postgres_write_fingerprint pg "{output}"', "table")
    assert failed.returncode != 0
    assert not output.exists()
