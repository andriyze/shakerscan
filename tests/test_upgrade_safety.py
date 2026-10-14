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
  case "${1:-} ${2:-}" in
    "image inspect")
      local ref="${@: -1}" line
      line="$(awk -v ref="$ref" '$1 == ref || $2 == ref' "$WORK/images" 2>/dev/null | head -1)"
      [ -n "$line" ] || return 1
      case "$*" in *--format*) echo "$line" | awk '{print $2}' ;; esac ;;
    "image rm")
      awk -v id="$3" '$2 != id' "$WORK/images" > "$WORK/images.new"; mv "$WORK/images.new" "$WORK/images"
      echo $(( $(cat "$WORK/free_gb") + ${FREED_PER_IMAGE:-4} )) > "$WORK/free_gb" ;;
    "images --no-trunc")
      awk -v repo="${@: -1}" '$3 == repo {print $2}' "$WORK/images" ;;
    "ps -aq") cat "$WORK/containers" ;;
    "ps -q") cat "$WORK/containers" ;;
    "info >/dev/null"|"info "*) return 0 ;;
    "inspect --format") echo "${@: -1}" ;;
    "volume rm") echo "volume removed $3" >> "$CALLS" ;;
    "volume ls") return 0 ;;
    "volume inspect") [ -f "$WORK/volume_$3" ] ;;
  esac
}
compose() {
  echo "compose $*" >> "$CALLS"
  case "$1" in
    logs) cat "$WORK/redis.log" 2>/dev/null ;;
    exec) echo "${EXEC_OUT:-}" ;;
    run)
      # The archive: `compose run ... -v <dir>:/backup ... tar czf /backup/redis-data.tgz` writes it.
      local arg prev=""
      for arg in "$@"; do
        if [ "$prev" = "-v" ] && [ "${arg%%:/backup}" != "$arg" ] && [ "${ARCHIVE_FAILS:-0}" != 1 ]; then
          case "$*" in *"tar czf /backup/redis-data.tgz"*) echo data > "${arg%%:/backup}/redis-data.tgz" ;; esac
        fi
        prev="$arg"
      done ;;
  esac
}
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
    (tmp_path / ".release-images.current").write_text("# release 2.9.0\nghcr.io/x/shakerscan-api@sha256:prev\n")
    result = run(tmp_path, body, FREE_GB="10", FREED_PER_IMAGE="8")
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
    assert not [line for line in calls(tmp_path).splitlines() if line.startswith("compose ")]
    assert "volume" not in calls(tmp_path)


def test_the_low_disk_prune_keeps_this_release_the_previous_one_and_images_in_use(tmp_path):
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
    echo "removed=$(prune_unused_release_images)"
    """
    result = run(tmp_path, body)
    assert "removed=1" in result.stdout, result.stdout + result.stderr
    removed = [line for line in calls(tmp_path).splitlines() if line.startswith("docker image rm")]
    assert removed == ["docker image rm id-old"]


def test_a_started_release_becomes_current_and_the_one_before_previous(tmp_path):
    body = """
    SHAKERSCAN_PRUNE_OLD_IMAGES=0
    REFS="a@sha256:1"; SCANNER_VERSION=2.9.0; record_started_release keep
    REFS="a@sha256:2"; SCANNER_VERSION=2.10.0; record_started_release keep
    REFS="a@sha256:2"; SCANNER_VERSION=2.10.0; record_started_release keep
    cat "$WORK/.release-images.current"; echo ---; cat "$WORK/.release-images.previous"
    """
    result = run(tmp_path, body)
    current, previous = result.stdout.split("---")
    assert "release 2.10.0" in current and "a@sha256:2" in current
    assert "release 2.9.0" in previous and "a@sha256:1" in previous  # a restart keeps it


def _redis(tmp_path: Path, states: str, log: str, EXTRA: str = "", **env: str) -> subprocess.CompletedProcess[str]:
    body = EXTRA + f"""
    printf '%s\\n' {states} > "$WORK/health"
    redis_health() {{ local s; s="$(head -1 "$WORK/health")"; [ "$(wc -l < "$WORK/health")" -gt 1 ] && sed -i.bak 1d "$WORK/health"; echo "$s"; }}
    wait_for_redis_healthy() {{ [ "$(redis_health)" = healthy ]; }}
    printf '%s\\n' "{log}" > "$WORK/redis.log"
    ensure_redis_ready; echo rc=$? reset=$REDIS_STATE_RESET
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


def test_an_unknown_cause_never_removes_redis_data(tmp_path):
    result = _redis(tmp_path, "unhealthy unhealthy unhealthy", "something else entirely")
    assert "rc=1" in result.stdout and "nothing was removed" in result.stderr
    assert "volume rm" not in calls(tmp_path) and "tar czf" not in calls(tmp_path)


def test_a_redis_docker_cannot_report_on_is_left_as_it_is(tmp_path):
    result = _redis(tmp_path, "unknown", "Bad file format reading the append only file")
    assert "rc=1" in result.stdout and "nothing was changed" in result.stderr
    assert "volume rm" not in calls(tmp_path) and "redis-check-aof" not in calls(tmp_path)


def test_damaged_redis_data_is_never_reset_without_a_copy(tmp_path):
    body = """
    archive_redis_data() { echo "archive attempt" >> "$CALLS"; return 1; }
    """
    result = _redis(tmp_path, "unhealthy unhealthy unhealthy", "Bad file format reading the append only file",
                    EXTRA=body)
    assert "rc=1" in result.stdout and "left as it is" in result.stderr
    assert "volume rm" not in calls(tmp_path) and "redis-check-aof" not in calls(tmp_path)


def test_redis_starts_empty_only_when_repair_does_not_help_and_says_what_that_means(tmp_path):
    # first wait, the health re-check, the repair's wait: all unhealthy; then the empty start
    result = _redis(tmp_path, "unhealthy unhealthy unhealthy healthy",
                    "Bad file format reading the append only file")
    assert "rc=0" in result.stdout, result.stdout + result.stderr
    log = calls(tmp_path)
    assert log.index("tar czf") < log.index("docker volume rm shakerscan_redis-data")
    assert "postgres" not in log.split("volume rm", 1)[1]
    assert "scans, findings and evidence are in PostgreSQL and untouched" in result.stdout
    assert "reset=1" in result.stdout  # the launcher restarts the services onto the new Redis


def test_a_redis_that_cannot_write_gets_room_from_old_images_never_a_reset(tmp_path):
    result = _redis(tmp_path, "unhealthy healthy", "MISCONF Redis is configured to save RDB snapshots")
    assert "rc=0" in result.stdout, result.stdout + result.stderr
    assert "volume rm" not in calls(tmp_path)


def _backup(tmp_path: Path, state: str | None, has_data: str, previous: bool | str = False,
            **env: str) -> subprocess.CompletedProcess[str]:
    if state is not None:
        (tmp_path / ".release-images.current").write_text(f"# release {state}\nref\n")
    if previous:
        label = previous if isinstance(previous, str) else "running-before-upgrade"
        (tmp_path / ".release-images.previous").write_text(f"# release {label}\nid\n")
    body = """
    compose() {
      echo "compose $*" >> "$CALLS"
      case "$*" in
        *"to_regclass('public.targets')"*) [ "$HAS_DATA" = fail ] && { echo "connection refused"; return 2; }; echo "$HAS_DATA" ;;
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
    assert "rc=0" in result.stdout and "-2.9.0-to-2.10.0" in result.stdout
    dump = next((tmp_path / "backups").glob("pre-upgrade-*/postgres.dump"))
    assert dump.read_text().strip() == "DUMP"


def test_the_first_upgrade_from_a_release_without_this_record_is_backed_up(tmp_path):
    result = _backup(tmp_path, None, "t", previous=True)
    assert "-earlier-to-2.10.0" in result.stdout


def test_the_first_upgrade_backup_names_the_version_the_running_api_reported(tmp_path):
    """2.10 acceptance (D5): the backup was named "earlier-to-2.10.0" although 2.9.0 was running."""
    result = _backup(tmp_path, None, "t", previous="2.9.0")
    assert "-2.9.0-to-2.10.0" in result.stdout, result.stdout


def test_the_running_release_is_recorded_with_its_api_version(tmp_path):
    body = """
    echo id-running > "$WORK/containers"
    running_api_version() { echo 2.9.0; }
    remember_running_release
    cat "$WORK/.release-images.previous"
    """
    result = run(tmp_path, body)
    assert result.stdout.startswith("# release 2.9.0\nid-running"), result.stdout


def test_a_first_start_without_any_record_is_not_taken_for_an_upgrade(tmp_path):
    assert "pre-upgrade" not in _backup(tmp_path, None, "t").stdout


def test_cleanup_keeps_the_backup_just_made_whatever_the_version_names(tmp_path):
    backups = tmp_path / "backups"
    for name in ("pre-upgrade-20261001T000000Z-earlier-to-2.9.0", "pre-upgrade-20261005T000000Z-2.9.0-to-2.10.0"):
        (backups / name).mkdir(parents=True)
    result = _backup(tmp_path, "2.10.0", "t", SCANNER_VERSION="2.11.0")
    kept = sorted(path.name for path in backups.iterdir())
    assert len(kept) == 2 and kept[-1].endswith("-2.10.0-to-2.11.0"), (kept, result.stdout)
    assert "pre-upgrade-20261005T000000Z-2.9.0-to-2.10.0" in kept


def test_a_failed_database_check_stops_the_upgrade_instead_of_skipping_the_backup(tmp_path):
    result = _backup(tmp_path, "2.9.0", "fail")
    assert "rc=1" in result.stdout and "Cannot check the database" in result.stderr


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


def test_a_restart_with_nothing_to_download_never_needs_upgrade_room(tmp_path):
    body = """
    cat > "$WORK/images" <<'X'
    ghcr.io/x/shakerscan-api@sha256:new1 id1 ghcr.io/x/shakerscan-api
    ghcr.io/x/shakerscan-scanner@sha256:new2 id2 ghcr.io/x/shakerscan-scanner
    ghcr.io/x/shakerscan-ui@sha256:new3 id3 ghcr.io/x/shakerscan-ui
    X
    sed -i.bak 's/^ *//' "$WORK/images"
    ensure_upgrade_space; echo rc=$?
    """
    result = run(tmp_path, body, FREE_GB="2")
    assert "rc=0" in result.stdout and "Free disk space soon" in result.stdout
    assert "image rm" not in calls(tmp_path)


def test_disabled_pulls_skip_the_space_check(tmp_path):
    result = run(tmp_path, "ensure_upgrade_space; echo rc=$?", FREE_GB="1", SHAKERSCAN_PULL_IMAGES="0")
    assert "rc=0" in result.stdout and "docker" not in calls(tmp_path)


def test_the_first_upgrade_keeps_the_running_releases_images_for_rollback(tmp_path):
    body = """
    cat > "$WORK/images" <<'X'
    ghcr.io/x/shakerscan-api@sha256:new1 id-new ghcr.io/x/shakerscan-api
    ghcr.io/x/shakerscan-api@sha256:old1 id-running ghcr.io/x/shakerscan-api
    ghcr.io/x/shakerscan-api@sha256:older id-older ghcr.io/x/shakerscan-api
    X
    sed -i.bak 's/^ *//' "$WORK/images"
    echo id-running > "$WORK/containers"
    remember_running_release
    : > "$WORK/containers"   # the stack is stopped and recreated from the new release
    SHAKERSCAN_PRUNE_OLD_IMAGES=1 record_started_release prune
    """
    run(tmp_path, body)
    # 2.10 acceptance (D4): the routine cleanup removes only images this install recorded and has
    # superseded; an image it never recorded (another install's, or older leftovers) stays.
    assert "image rm" not in calls(tmp_path)


def test_nothing_is_pruned_without_any_release_record(tmp_path):
    body = """
    echo "ghcr.io/x/shakerscan-api@sha256:x id-x ghcr.io/x/shakerscan-api" > "$WORK/images"
    echo "n=$(prune_unused_release_images) m=$(prune_superseded_release_images)"
    """
    assert "n=0 m=0" in run(tmp_path, body).stdout and "image rm" not in calls(tmp_path)


def test_local_builds_are_recorded_and_never_pruned(tmp_path):
    body = """
    echo "ghcr.io/x/shakerscan-api@sha256:x id-x ghcr.io/x/shakerscan-api" > "$WORK/images"
    record_started_release keep
    record_started_release keep
    cat "$WORK/.release-images.current"
    """
    result = run(tmp_path, body)
    assert "# release 2.10.0" in result.stdout and "image rm" not in calls(tmp_path)
    assert "-to-" not in "".join(p.name for p in (tmp_path / "backups").glob("*")) if (tmp_path / "backups").exists() else True


def test_every_docker_call_goes_through_the_launchers_wrapper():
    script = SCRIPT.read_text()
    body = "\n".join(line for line in script.splitlines() if not line.lstrip().startswith("#"))
    import re
    bare = [line for line in body.splitlines()
            if re.search(r"(^|[^_a-z])docker (image|images|ps|inspect|volume|info|rm)\b", line)
            and "docker_cli" not in line and "docker image ls" not in line]
    assert bare == [], bare


def test_routine_cleanup_removes_only_this_installs_release_before_the_previous_one(tmp_path):
    """Three releases started in turn: after the third, the first one's images go; the second
    (previous) and third (current) stay, and an image this install never recorded stays."""
    body = """
    cat > "$WORK/images" <<'X'
    ghcr.io/x/shakerscan-api@sha256:r1 id-r1 ghcr.io/x/shakerscan-api
    ghcr.io/x/shakerscan-api@sha256:r2 id-r2 ghcr.io/x/shakerscan-api
    ghcr.io/x/shakerscan-api@sha256:r3 id-r3 ghcr.io/x/shakerscan-api
    ghcr.io/x/shakerscan-api@sha256:other id-other ghcr.io/x/shakerscan-api
    X
    sed -i.bak 's/^ *//' "$WORK/images"
    REFS="ghcr.io/x/shakerscan-api@sha256:r1"; SCANNER_VERSION=2.8.0; record_started_release prune
    REFS="ghcr.io/x/shakerscan-api@sha256:r2"; SCANNER_VERSION=2.9.0; record_started_release prune
    REFS="ghcr.io/x/shakerscan-api@sha256:r3"; SCANNER_VERSION=2.10.0; record_started_release prune
    """
    result = run(tmp_path, body)
    removed = [line for line in calls(tmp_path).splitlines() if line.startswith("docker image rm")]
    assert removed == ["docker image rm ghcr.io/x/shakerscan-api@sha256:r1"], result.stdout + result.stderr
    assert "Removed 1 image(s) of older ShakerScan releases" in result.stdout
    assert not (tmp_path / ".release-images.superseded").exists()


def test_a_superseded_image_still_in_use_stays_listed_for_next_time(tmp_path):
    body = """
    echo "ghcr.io/x/shakerscan-api@sha256:old id-old ghcr.io/x/shakerscan-api" > "$WORK/images"
    printf '# superseded\\nghcr.io/x/shakerscan-api@sha256:old\\n' > "$WORK/.release-images.superseded"
    echo id-old > "$WORK/containers"
    echo "n=$(prune_superseded_release_images)"
    cat "$WORK/.release-images.superseded"
    """
    result = run(tmp_path, body)
    assert "n=0" in result.stdout and "ghcr.io/x/shakerscan-api@sha256:old" in result.stdout
    assert "image rm" not in calls(tmp_path)


def test_this_releases_model_intake_images_are_protected_while_the_module_is_off():
    script = SCRIPT.read_text()
    assert "for ref in $(release_image_refs_all)" in script.split("protected_image_ids()", 1)[1].split("}", 1)[0]
    assert 'current="$(release_image_refs_all | sort)"' in script
    launcher = (ROOT / "scanner.sh").read_text()
    body = launcher.split("release_image_refs_all() {", 1)[1].split("\n}", 1)[0]
    assert "release_image_refs" in body and "model_intake_enabled || model_intake_image_refs" in body


_CLOCK = r"""
echo 0 > "$WORK/clock"
date() { case "$*" in *%s*) local t; t=$(( $(cat "$WORK/clock") + 10 )); echo "$t" > "$WORK/clock"; echo "$t" ;;
         *) command date "$@" ;; esac; }
redis_health() { echo $(( $(cat "$WORK/polls" 2>/dev/null || echo 0) + 1 )) > "$WORK/polls"; echo starting; }
"""


def test_a_crash_looping_redis_with_a_damaged_file_is_not_waited_on(tmp_path):
    """2.10 acceptance (D3): a Redis that fails on a damaged append-only file prints "Loading ..."
    on every restart; the wait took it for loading and delayed the repair by ~16 minutes."""
    body = _CLOCK + """
    printf '%s\\n' "* Loading RDB produced by version 8.10.2" "* Reading RDB base file on AOF loading..." \
        "# Bad file format reading the append only file appendonly.aof.1.incr.aof" > "$WORK/redis.log"
    wait_for_redis_healthy; echo "rc=$? polls=$(cat "$WORK/polls")"
    """
    result = run(tmp_path, body)
    assert "rc=1" in result.stdout, result.stdout + result.stderr
    assert int(result.stdout.split("polls=")[1].split()[0]) <= 2  # gave up at once (old code: 450 polls)


def test_a_redis_that_is_really_loading_is_still_waited_for(tmp_path):
    body = _CLOCK + """
    redis_container_state() { echo running; }
    printf '%s\\n' "* Loading RDB produced by version 8.10.2" "* DB loaded from base file" > "$WORK/redis.log"
    REDIS_READY_SECONDS=60; REDIS_LOADING_SECONDS=300
    wait_for_redis_healthy; echo "rc=$? clock=$(cat "$WORK/clock")"
    """
    result = run(tmp_path, body)
    assert "rc=1" in result.stdout, result.stdout + result.stderr
    assert int(result.stdout.split("clock=")[1].split()[0]) >= 300  # waited out the loading allowance
