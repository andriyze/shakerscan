"""Upgrades that look after themselves (scripts/upgrade_safety.sh, 2.10).

Owner, 2026-10-13, after a 2.8.3 -> 2.9.0 upgrade failed on a host low on disk and the user was left
choosing Docker volumes to delete: "User should not deal with this. Make sure this never happens
again." These run the real shell functions with stubbed `docker` and `compose` (unit fixtures: no
Docker); the lab acceptance fills a real disk and damages a real Redis append-only file.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import textwrap

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "upgrade_safety.sh"

PRELUDE = r"""
set -u
RED=; GREEN=; YELLOW=; BLUE=; NC=
SCRIPT_DIR="$WORK"
CALLS="$WORK/calls.log"; : > "$CALLS"
API_IMAGE_REPO=ghcr.io/x/shakerscan-api; SCANNER_IMAGE_REPO=ghcr.io/x/shakerscan-scanner
UI_IMAGE_REPO=ghcr.io/x/shakerscan-ui; MODEL_INTAKE_IMAGE_REPO=; MODEL_INTAKE_SIGNER_IMAGE_REPO=
SCANNER_VERSION="${SCANNER_VERSION:-2.10.0}"
is_truthy() { case "${1:-}" in 1|true|yes|on) return 0 ;; *) return 1 ;; esac; }
cli_hint() { echo shakerscan; }
sleep() { :; }
release_image_refs() { printf '%s\n' "${REFS:-ghcr.io/x/shakerscan-api@sha256:new1 ghcr.io/x/shakerscan-scanner@sha256:new2 ghcr.io/x/shakerscan-ui@sha256:new3}" | tr ' ' '\n'; }
# Docker's free space, in KB, read from a file the fake image removal grows.
echo "${FREE_GB:-50}" > "$WORK/free_gb"
docker_storage_free_kb() { echo $(( $(cat "$WORK/free_gb") * 1024 * 1024 )); }
# Images present locally: "ref id repo" lines; containers: image ids.
: > "$WORK/images"; : > "$WORK/containers"
docker() {
  echo "docker $*" >> "$CALLS"
  case "$1 $2" in
    "image inspect")
      local ref="${@: -1}" line
      line="$(awk -v ref="$ref" '$1 == ref' "$WORK/images" 2>/dev/null | head -1)"
      [ -n "$line" ] || return 1
      case "$*" in *--format*) echo "$line" | awk '{print $2}' ;; esac ;;
    "image rm")
      awk -v id="$3" '$2 != id' "$WORK/images" > "$WORK/images.new"; mv "$WORK/images.new" "$WORK/images"
      echo $(( $(cat "$WORK/free_gb") + ${FREED_PER_IMAGE:-4} )) > "$WORK/free_gb" ;;
    "images --no-trunc")
      awk -v repo="${@: -1}" '$3 == repo {print $2}' "$WORK/images" ;;
    "ps -aq") cat "$WORK/containers" ;;
    "inspect --format") echo "${@: -1}" ;;
    "volume rm") echo "volume removed $3" >> "$CALLS" ;;
    "volume inspect") [ -f "$WORK/volume_$3" ] ;;
  esac
}
compose() { echo "compose $*" >> "$CALLS"; case "$1" in logs) cat "$WORK/redis.log" 2>/dev/null ;; exec) echo "${EXEC_OUT:-}" ;; esac; }
: > "$WORK/redis.log"
"""


def run(tmp_path: Path, body: str, **env: str) -> subprocess.CompletedProcess[str]:
    script = PRELUDE + f'source "{SCRIPT}"\n' + textwrap.dedent(body)
    return subprocess.run(["bash", "-c", script], cwd=ROOT, capture_output=True, text=True, timeout=30,
                          env={"WORK": str(tmp_path), "PATH": "/usr/bin:/bin", **env}, check=False)


def calls(tmp_path: Path) -> str:
    return (tmp_path / "calls.log").read_text()


def test_enough_space_needs_nothing(tmp_path):
    result = run(tmp_path, "ensure_upgrade_space; echo rc=$?", FREE_GB="40")
    assert "rc=0" in result.stdout and "docker image rm" not in calls(tmp_path)


def test_older_shakerscan_images_are_removed_first_and_the_upgrade_proceeds(tmp_path):
    body = """
    cat > "$WORK/images" <<'X'
    ghcr.io/x/shakerscan-scanner@sha256:old2 id-old-scanner ghcr.io/x/shakerscan-scanner
    ghcr.io/x/shakerscan-api@sha256:old1 id-old-api ghcr.io/x/shakerscan-api
    postgres:18 id-postgres postgres
    X
    sed -i.bak 's/^ *//' "$WORK/images"
    ensure_upgrade_space; echo rc=$?
    """
    result = run(tmp_path, body, FREE_GB="10", FREED_PER_IMAGE="5")
    assert "rc=0" in result.stdout, result.stdout + result.stderr
    log = calls(tmp_path)
    assert "docker image rm id-old-scanner" in log and "docker image rm id-old-api" in log
    assert "id-postgres" not in log.split("image rm", 1)[-1]  # another product's image stays
    assert "volume" not in log


def test_not_enough_space_refuses_with_nothing_changed(tmp_path):
    result = run(tmp_path, "ensure_upgrade_space; echo rc=$?", FREE_GB="3")
    assert "rc=1" in result.stdout
    assert "Not enough disk space to upgrade" in result.stderr and "Nothing was changed" in result.stderr
    assert "Do not remove Docker volumes" in result.stderr
    assert "compose" not in calls(tmp_path) and "volume" not in calls(tmp_path)


def test_the_prune_keeps_this_release_the_previous_one_and_images_in_use(tmp_path):
    body = """
    cat > "$WORK/images" <<'X'
    ghcr.io/x/shakerscan-api@sha256:new1 id-current ghcr.io/x/shakerscan-api
    ghcr.io/x/shakerscan-api@sha256:prev1 id-previous ghcr.io/x/shakerscan-api
    ghcr.io/x/shakerscan-api@sha256:old1 id-old ghcr.io/x/shakerscan-api
    ghcr.io/x/shakerscan-api@sha256:used1 id-used ghcr.io/x/shakerscan-api
    X
    sed -i.bak 's/^ *//' "$WORK/images"
    printf '# release 2.9.0\\nghcr.io/x/shakerscan-api@sha256:prev1\\n' > "$WORK/.release-images.previous"
    echo id-used > "$WORK/containers"
    echo "removed=$(prune_superseded_release_images)"
    """
    result = run(tmp_path, body)
    assert "removed=1" in result.stdout, result.stdout + result.stderr
    removed = [line for line in calls(tmp_path).splitlines() if line.startswith("docker image rm")]
    assert removed == ["docker image rm id-old"]


def test_a_started_release_becomes_current_and_the_one_before_previous(tmp_path):
    body = """
    SHAKERSCAN_PRUNE_OLD_IMAGES=0
    REFS="a@sha256:1"; SCANNER_VERSION=2.9.0; record_started_release
    REFS="a@sha256:2"; SCANNER_VERSION=2.10.0; record_started_release
    REFS="a@sha256:2"; SCANNER_VERSION=2.10.0; record_started_release
    cat "$WORK/.release-images.current"; echo ---; cat "$WORK/.release-images.previous"
    """
    result = run(tmp_path, body)
    current, previous = result.stdout.split("---")
    assert "release 2.10.0" in current and "a@sha256:2" in current
    assert "release 2.9.0" in previous and "a@sha256:1" in previous  # a restart keeps it


def _redis(tmp_path: Path, states: str, log: str, **env: str) -> subprocess.CompletedProcess[str]:
    body = f"""
    printf '%s\\n' {states} > "$WORK/health"
    redis_health() {{ local s; s="$(head -1 "$WORK/health")"; [ "$(wc -l < "$WORK/health")" -gt 1 ] && sed -i.bak 1d "$WORK/health"; echo "$s"; }}
    wait_for_redis_healthy() {{ [ "$(redis_health)" = healthy ]; }}
    printf '%s\\n' "{log}" > "$WORK/redis.log"
    ensure_redis_ready; echo rc=$?
    """
    return run(tmp_path, body, **env)


def test_a_healthy_redis_is_left_alone(tmp_path):
    result = _redis(tmp_path, "healthy", "Ready to accept connections")
    assert "rc=0" in result.stdout and "redis-check-aof" not in calls(tmp_path)


def test_a_damaged_append_only_file_is_kept_and_repaired(tmp_path):
    result = _redis(tmp_path, "unhealthy healthy", "Bad file format reading the append only file")
    assert "rc=0" in result.stdout and "Redis repaired" in result.stdout, result.stdout + result.stderr
    log = calls(tmp_path)
    assert "tar czf /backup/redis-data.tgz" in log  # a copy first
    assert "redis-check-aof --fix" in log
    assert "volume rm" not in log
    assert list((tmp_path / "backups").glob("redis-*"))


def test_redis_starts_empty_only_when_repair_does_not_help_and_says_what_that_means(tmp_path):
    result = _redis(tmp_path, "unhealthy unhealthy healthy", "Bad file format reading the append only file")
    assert "rc=0" in result.stdout, result.stdout + result.stderr
    log = calls(tmp_path)
    assert log.index("tar czf") < log.index("docker volume rm shakerscan_redis-data")
    assert "postgres" not in log.split("volume rm", 1)[1]
    assert "scans, findings and evidence are in PostgreSQL and untouched" in result.stdout


def test_a_redis_that_cannot_write_gets_room_from_old_images_never_a_reset(tmp_path):
    result = _redis(tmp_path, "unhealthy healthy", "MISCONF Redis is configured to save RDB snapshots")
    assert "rc=0" in result.stdout, result.stdout + result.stderr
    assert "volume rm" not in calls(tmp_path)


def _backup(tmp_path: Path, state: str | None, has_data: str, **env: str) -> subprocess.CompletedProcess[str]:
    if state is not None:
        (tmp_path / ".release-images.current").write_text(f"# release {state}\nref\n")
    body = """
    compose() {
      echo "compose $*" >> "$CALLS"
      case "$*" in
        *"to_regclass('public.targets')"*) echo "$HAS_DATA" ;;
        *pg_database_size*) echo 1024 ;;
        *pg_dump*) echo DUMP ;;
      esac
    }
    ensure_pre_upgrade_backup; echo rc=$?
    ls "$WORK/backups" 2>/dev/null
    """
    return run(tmp_path, body, HAS_DATA=has_data, **env)


def test_a_version_changing_start_saves_the_database_first(tmp_path):
    result = _backup(tmp_path, "2.9.0", "t")
    assert "rc=0" in result.stdout and "pre-upgrade-2.9.0-to-2.10.0-" in result.stdout
    dump = next((tmp_path / "backups").glob("pre-upgrade-*/postgres.dump"))
    assert dump.read_text().strip() == "DUMP"


def test_the_first_upgrade_from_a_release_without_this_record_is_backed_up(tmp_path):
    result = _backup(tmp_path, None, "t")
    assert "pre-upgrade-earlier-to-2.10.0-" in result.stdout


def test_no_backup_for_a_restart_or_an_empty_database(tmp_path):
    assert "pre-upgrade" not in _backup(tmp_path, "2.10.0", "t").stdout
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    assert "pre-upgrade" not in _backup(fresh, None, "f").stdout


def test_status_warns_on_low_disk_and_a_missing_database_volume(tmp_path):
    (tmp_path / ".env").write_text("POSTGRES_PASSWORD=x\n")
    (tmp_path / ".release-images.current").write_text("# release 2.10.0\nref\n")
    result = run(tmp_path, "upgrade_safety_warnings", FREE_GB="4")
    assert "keep at least 20 GB free" in result.stdout
    assert "database volume is missing" in result.stdout
    (tmp_path / "volume_shakerscan_postgres-cluster").write_text("")
    assert "database volume is missing" not in run(tmp_path, "upgrade_safety_warnings", FREE_GB="40").stdout


def test_nothing_in_the_launcher_suggests_removing_volumes():
    launcher = (ROOT / "scanner.sh").read_text() + SCRIPT.read_text()
    assert "prune -af --volumes" not in launcher and "volume prune" not in launcher.replace(
        "Never remove Docker volumes (docker volume prune", "")
