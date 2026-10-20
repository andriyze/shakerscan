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
# Never the runner's own registry or install.
SHAKERSCAN_INSTALL_REGISTRY="${SHAKERSCAN_INSTALL_REGISTRY:-$WORK/registry/installs}"
SHAKERSCAN_HOME="${SHAKERSCAN_HOME:-$WORK/no-default-install}"
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
      [ -n "$line" ] || { echo "Error: No such image: $ref" >&2; return 1; }
      case "$*" in
        *RepoTags*) awk -v id="$(echo "$line" | awk '{print $2}')" '$2 == id {print $1}' "$WORK/images" ;;
        *--format*) echo "$line" | awk '{print $2}' ;;
      esac ;;
    "image rm")
      awk -v id="$3" '$1 != id && $2 != id' "$WORK/images" > "$WORK/images.new"; mv "$WORK/images.new" "$WORK/images"
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
            before: str = "", **env: str) -> subprocess.CompletedProcess[str]:
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
    """ + textwrap.dedent(before) + """
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
    echo "ghcr.io/x/shakerscan-api@sha256:run id-running ghcr.io/x/shakerscan-api" > "$WORK/images"
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
    kept = sorted(path.name for path in backups.glob("pre-upgrade-*"))
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


def test_routine_cleanup_never_removes_a_third_party_image_recorded_with_a_release(tmp_path):
    """Review F1: the first upgrade records the running project's images, postgres and caddy
    included; two releases later the routine cleanup must remove only ShakerScan's."""
    body = """
    cat > "$WORK/images" <<'X'
    ghcr.io/x/shakerscan-api@sha256:a29 id-api29 ghcr.io/x/shakerscan-api
    postgres:18.6-alpine id-postgres postgres
    caddy:2 id-caddy caddy
    ghcr.io/x/shakerscan-api@sha256:a210 id-api210 ghcr.io/x/shakerscan-api
    ghcr.io/x/shakerscan-api@sha256:a211 id-api211 ghcr.io/x/shakerscan-api
    X
    sed -i.bak 's/^ *//' "$WORK/images"
    printf 'id-api29\\nid-postgres\\nid-caddy\\n' > "$WORK/containers"
    running_api_version() { echo 2.9.0; }
    remember_running_release
    : > "$WORK/containers"
    REFS="ghcr.io/x/shakerscan-api@sha256:a210"; SCANNER_VERSION=2.10.0; record_started_release prune
    REFS="ghcr.io/x/shakerscan-api@sha256:a211"; SCANNER_VERSION=2.11.0; record_started_release prune
    head -3 "$WORK/.release-images.previous" >&2
    """
    result = run(tmp_path, body)
    removed = [line for line in calls(tmp_path).splitlines() if line.startswith("docker image rm")]
    assert removed == ["docker image rm id-api29"], removed
    assert "id-postgres" not in (tmp_path / ".release-images.superseded").read_text() \
        if (tmp_path / ".release-images.superseded").exists() else True


def test_the_same_version_with_other_image_names_keeps_the_previous_release(tmp_path):
    """Review F3: a CURRENT written without the optional module's images must not push the 2.9
    rollback release out when the same 2.10 starts again with them recorded."""
    body = """
    echo "ghcr.io/x/shakerscan-api@sha256:old1 id-old1 ghcr.io/x/shakerscan-api" > "$WORK/images"
    printf '# release 2.9.0\\nghcr.io/x/shakerscan-api@sha256:old1\\n' > "$WORK/.release-images.previous"
    printf '# release 2.10.0\\nghcr.io/x/shakerscan-api@sha256:new1\\n' > "$WORK/.release-images.current"
    REFS="ghcr.io/x/shakerscan-api@sha256:new1 ghcr.io/x/shakerscan-model-intake@sha256:mi"
    SCANNER_VERSION=2.10.0; record_started_release prune
    cat "$WORK/.release-images.previous"; echo ---; cat "$WORK/.release-images.current"
    """
    result = run(tmp_path, body)
    previous, current = result.stdout.split("---")
    assert "# release 2.9.0" in previous and "old1" in previous
    assert "shakerscan-model-intake@sha256:mi" in current
    assert "image rm" not in calls(tmp_path)


def test_a_superseded_entry_survives_a_docker_error_other_than_no_such_image(tmp_path):
    """Review F5."""
    body = """
    printf '# s\\nghcr.io/x/shakerscan-api@sha256:old\\n' > "$WORK/.release-images.superseded"
    docker() { echo "docker $*" >> "$CALLS"; case "$1 $2" in "image inspect") echo "permission denied" >&2; return 1 ;; esac; }
    echo "n=$(prune_superseded_release_images)"; cat "$WORK/.release-images.superseded"
    """
    result = run(tmp_path, body)
    assert "n=0" in result.stdout and "shakerscan-api@sha256:old" in result.stdout


def test_redis_loading_a_truncated_file_anyway_is_not_a_failure(tmp_path):
    """Review F2: "loaded anyway because aof-load-truncated is enabled" is Redis recovering by
    itself; the wait must keep waiting for healthy instead of starting a repair."""
    body = _CLOCK + """
    redis_container_state() { echo running; }
    redis_health() { n=$(( $(cat "$WORK/polls" 2>/dev/null || echo 0) + 1 )); echo $n > "$WORK/polls"
                     [ "$n" -ge 3 ] && echo healthy || echo starting; }
    printf '%s\\n' "# Short read while loading the AOF file appendonly.aof.1.incr.aof!" \
        "# AOF appendonly.aof.1.incr.aof loaded anyway because aof-load-truncated is enabled" > "$WORK/redis.log"
    wait_for_redis_healthy; echo "rc=$?"
    echo "kind=$(redis_failure_kind)"
    """
    result = run(tmp_path, body)
    assert "rc=0" in result.stdout, result.stdout + result.stderr
    assert "kind=unknown" in result.stdout


def test_the_backup_of_an_unversioned_running_release_says_earlier(tmp_path):
    """Review F8: the release compose defaults SCANNER_VERSION to "latest"."""
    assert "-earlier-to-2.10.0" in _backup(tmp_path, None, "t", previous="latest").stdout
    assert "-earlier-to-2.10.0" in _backup(tmp_path, None, "t", previous="2.10.0").stdout


def test_a_rollback_by_an_older_launcher_is_seen_from_the_running_api(tmp_path):
    """2.10 soak: after a rollback with an older launcher (which keeps no release record) the record
    still named 2.10.0, so upgrading the running 2.9.0 to 2.10.0 again skipped the backup."""
    result = _backup(tmp_path, "2.10.0", "t", before="running_api_version() { echo 2.9.0; }")
    assert "rc=0" in result.stdout and "-2.9.0-to-2.10.0" in result.stdout, result.stdout + result.stderr


def test_the_running_version_is_noted_before_the_stack_is_stopped(tmp_path):
    """A start that stops the running stack first (clean slate, restart) must still compare with the
    version that was running."""
    before = """
    running_api_version() { echo 2.9.0; }
    note_running_release
    running_api_version() { :; }   # the stack was stopped
    """
    result = _backup(tmp_path, "2.10.0", "t", before=before)
    assert "-2.9.0-to-2.10.0" in result.stdout, result.stdout + result.stderr


def test_a_start_by_a_launcher_that_keeps_no_record_means_a_backup_when_nothing_runs(tmp_path):
    """Nothing runs to ask, and a launcher that keeps no release record (or the installer) wrote the
    runtime marker after the record: the record cannot be trusted."""
    before = """
    touch -t 202610010000 "$WORK/.release-images.current"
    echo prebuilt > "$WORK/.shakerscan-local-build"
    """
    result = _backup(tmp_path, "2.10.0", "t", before=before)
    assert "rc=0" in result.stdout and "-unverified-2.10.0-to-2.10.0" in result.stdout, result.stdout + result.stderr


def test_a_restart_of_the_recorded_release_is_still_not_an_upgrade(tmp_path):
    before = """
    echo prebuilt > "$WORK/.shakerscan-local-build"
    touch -t 202610010000 "$WORK/.shakerscan-local-build"
    """
    assert "pre-upgrade" not in _backup(tmp_path, "2.10.0", "t", before=before).stdout
    running = tmp_path / "running"
    running.mkdir()
    same = _backup(running, "2.9.0", "t", before="running_api_version() { echo 2.10.0; }")
    assert "pre-upgrade" not in same.stdout, same.stdout
    unversioned = tmp_path / "unversioned"
    unversioned.mkdir()
    latest = _backup(unversioned, "2.10.0", "t", before="running_api_version() { echo latest; }")
    assert "pre-upgrade" not in latest.stdout, latest.stdout


# A record of 2.10.0 (image r10) and the 2.9.0 image (r9) an older launcher, or a hand-run Compose
# command, may have started since. Unit fixture: the stub's `docker inspect` names a container by its
# image id.
_RECORDED = r"""
printf '%s\n' 'ghcr.io/x/shakerscan-api@sha256:r9 id-r9 ghcr.io/x/shakerscan-api' \
    'ghcr.io/x/shakerscan-api@sha256:r10 id-r10 ghcr.io/x/shakerscan-api' > "$WORK/images"
printf '# release 2.10.0\nghcr.io/x/shakerscan-api@sha256:r10\n' > "$WORK/.release-images.current"
"""


def test_an_api_running_images_the_record_does_not_name_means_a_backup(tmp_path):
    """The record still named 2.10.0 while the API ran 2.9.0 images whose environment gives no
    usable version (started by hand with the release Compose file, which defaults it to "latest").
    Starting 2.10.0 skipped the backup although it migrates the 2.9.0 database."""
    before = _RECORDED + """
echo id-r9 > "$WORK/containers"
running_api_version() { echo latest; }
"""
    result = _backup(tmp_path, "2.10.0", "t", before=before)
    assert "rc=0" in result.stdout and "-unverified-2.10.0-to-2.10.0" in result.stdout, result.stdout + result.stderr


def test_a_stopped_api_container_the_record_does_not_name_means_a_backup(tmp_path):
    """Nothing runs to ask (the containers were stopped, not removed), and the runtime marker is
    older than the record: the stopped API container's image still shows the record is stale."""
    before = _RECORDED + """
echo prebuilt > "$WORK/.shakerscan-local-build"
touch -t 202610010000 "$WORK/.shakerscan-local-build"
echo id-r9 > "$WORK/containers"    # `docker ps -a` lists the stopped API container
running_api_version() { :; }       # nothing runs
"""
    result = _backup(tmp_path, "2.10.0", "t", before=before)
    assert "rc=0" in result.stdout and "-unverified-2.10.0-to-2.10.0" in result.stdout, result.stdout + result.stderr


def test_an_api_container_docker_cannot_inspect_means_a_backup(tmp_path):
    """Docker lists an API container but cannot say which image it was created from: the record
    cannot be checked against it, so it is not trusted."""
    before = _RECORDED + """
echo id-r10 > "$WORK/containers"
docker_cli() { case "$*" in *'{{.Image}}'*) return 1 ;; esac; docker "$@"; }
"""
    result = _backup(tmp_path, "2.10.0", "t", before=before)
    assert "rc=0" in result.stdout and "-unverified-2.10.0-to-2.10.0" in result.stdout, result.stdout + result.stderr


def test_a_record_whose_images_are_gone_is_not_trusted_while_an_api_container_exists(tmp_path):
    """The images the record names are no longer on this host, so they cannot be what the API
    container runs."""
    before = """
printf '%s\n' 'ghcr.io/x/shakerscan-api@sha256:r9 id-r9 ghcr.io/x/shakerscan-api' > "$WORK/images"
printf '# release 2.10.0\nghcr.io/x/shakerscan-api@sha256:r10\n' > "$WORK/.release-images.current"
echo id-r9 > "$WORK/containers"
"""
    result = _backup(tmp_path, "2.10.0", "t", before=before)
    assert "rc=0" in result.stdout and "-unverified-2.10.0-to-2.10.0" in result.stdout, result.stdout + result.stderr


def test_the_api_image_is_noted_before_the_stack_is_stopped(tmp_path):
    """A clean-slate start or a restart removes the containers before the backup is decided."""
    before = _RECORDED + """
echo id-r9 > "$WORK/containers"
note_running_release
: > "$WORK/containers"             # the start stopped and removed the stack
"""
    result = _backup(tmp_path, "2.10.0", "t", before=before)
    assert "-unverified-2.10.0-to-2.10.0" in result.stdout, result.stdout + result.stderr


def test_a_record_that_names_the_api_image_is_trusted(tmp_path):
    """No backup for a restart of the recorded release, whatever its API says about its version, nor
    for a local build, whose images the record does not name."""
    recorded = _backup(tmp_path, "2.10.0", "t", before=_RECORDED + """
echo id-r10 > "$WORK/containers"
running_api_version() { echo latest; }
""")
    assert "rc=0" in recorded.stdout and "pre-upgrade" not in recorded.stdout, recorded.stdout + recorded.stderr
    local_build = tmp_path / "local"
    local_build.mkdir()
    built = _backup(local_build, "2.10.0", "t", before=_RECORDED + """
echo 'shakerscan-api:latest id-local shakerscan-api' >> "$WORK/images"
echo id-local > "$WORK/containers"
""")
    assert "rc=0" in built.stdout and "pre-upgrade" not in built.stdout, built.stdout + built.stderr


def test_a_version_the_api_reports_still_decides_over_its_image(tmp_path):
    """The record lags behind the release that runs (a start that failed after 2.10.0 came up): a
    start of 2.10.0 is no upgrade, as before."""
    before = _RECORDED + """
printf '# release 2.9.0\nghcr.io/x/shakerscan-api@sha256:r9\n' > "$WORK/.release-images.current"
echo id-r10 > "$WORK/containers"
running_api_version() { echo 2.10.0; }
"""
    result = _backup(tmp_path, "2.9.0", "t", before=before)
    assert "rc=0" in result.stdout and "pre-upgrade" not in result.stdout, result.stdout + result.stderr


def test_without_any_record_a_running_release_of_another_version_is_backed_up(tmp_path):
    """A local build, or a release whose images were not recognised, leaves no record; the version
    its API reports still makes the start an upgrade."""
    result = _backup(tmp_path, None, "t", before="running_api_version() { echo 2.9.0; }")
    assert "rc=0" in result.stdout and "-2.9.0-to-2.10.0" in result.stdout, result.stdout + result.stderr
    same = tmp_path / "same"
    same.mkdir()
    assert "pre-upgrade" not in _backup(same, None, "t", before="running_api_version() { echo 2.10.0; }").stdout


def test_failed_attempts_never_rotate_out_the_first_dump_of_an_upgrade(tmp_path):
    """An API that exits mid-migration fails the start; each retry dumps the partly migrated
    database. The dump taken before any migration ran stays until a start succeeds."""
    # One distinct, ordered timestamp per attempt.
    clock = 'date() { n=$(cat "$WORK/n" 2>/dev/null || echo 0); echo $((n + 1)) > "$WORK/n"; echo "2026101${n}T000000Z"; }'
    for _ in range(4):
        result = _backup(tmp_path, "2.9.0", "t", before=clock)
        assert "rc=0" in result.stdout, result.stdout + result.stderr
    kept = sorted(path.name for path in (tmp_path / "backups").glob("pre-upgrade-*"))
    assert kept == ["pre-upgrade-20261010T000000Z-2.9.0-to-2.10.0",   # before any migration ran
                    "pre-upgrade-20261012T000000Z-2.9.0-to-2.10.0",
                    "pre-upgrade-20261013T000000Z-2.9.0-to-2.10.0"], kept


def test_a_successful_start_releases_the_first_dump_for_rotation(tmp_path):
    backups = tmp_path / "backups"
    backups.mkdir()
    (backups / ".pre-upgrade-pending").write_text("pre-upgrade-20261010T000000Z-2.9.0-to-2.10.0\n")
    result = run(tmp_path, "record_started_release keep; echo rc=$?")
    assert "rc=0" in result.stdout and not (backups / ".pre-upgrade-pending").exists()


_THREE = """
cat > "$WORK/images" <<'X'
ghcr.io/x/shakerscan-api@sha256:r1 id-r1 ghcr.io/x/shakerscan-api
ghcr.io/x/shakerscan-api@sha256:r2 id-r2 ghcr.io/x/shakerscan-api
ghcr.io/x/shakerscan-api@sha256:r3 id-r3 ghcr.io/x/shakerscan-api
ghcr.io/x/shakerscan-api@sha256:r4 id-r4 ghcr.io/x/shakerscan-api
X
sed -i.bak 's/^ *//' "$WORK/images"
"""


def _removed(tmp_path: Path) -> list[str]:
    return [line.split()[-1] for line in calls(tmp_path).splitlines() if line.startswith("docker image rm")]


def test_a_stopped_second_install_keeps_its_release_and_rollback_images(tmp_path):
    """2.11 C3: the routine cleanup of one install removed another, stopped install's images (no
    container protected them). Every install that recorded a release is registered host-wide."""
    other = tmp_path / "other-install"
    other.mkdir()
    registry = tmp_path / "registry" / "installs"
    registry.parent.mkdir()
    registry.write_text(f"{other}\n{tmp_path / 'removed-install'}\n")
    (other / ".release-images.current").write_text("# release 2.9.0\nghcr.io/x/shakerscan-api@sha256:r2\n")
    (other / ".release-images.previous").write_text("# release 2.8.0\nghcr.io/x/shakerscan-api@sha256:r1\n")
    body = _THREE + """
    REFS="ghcr.io/x/shakerscan-api@sha256:r1"; SCANNER_VERSION=2.8.0; record_started_release prune
    REFS="ghcr.io/x/shakerscan-api@sha256:r2"; SCANNER_VERSION=2.9.0; record_started_release prune
    REFS="ghcr.io/x/shakerscan-api@sha256:r3"; SCANNER_VERSION=2.10.0; record_started_release prune
    REFS="ghcr.io/x/shakerscan-api@sha256:r4"; SCANNER_VERSION=2.11.0; record_started_release prune
    echo "low-disk=$(prune_unused_release_images)"
    """
    result = run(tmp_path, body)
    assert _removed(tmp_path) == [], result.stdout + result.stderr  # r1, r2 are the other install's
    assert "low-disk=0" in result.stdout
    assert str(tmp_path.resolve()) in registry.read_text().splitlines()  # this install registered itself
    # Without the other install's records its images go.
    registry.write_text("")
    result = run(tmp_path, _THREE + "echo removed=$(prune_superseded_release_images)")
    assert sorted(_removed(tmp_path)) == ["ghcr.io/x/shakerscan-api@sha256:r1", "ghcr.io/x/shakerscan-api@sha256:r2"]


def test_a_stale_record_rollback_keeps_the_release_that_was_actually_running(tmp_path):
    """2.11 C9: after a rollback to 2.9 by a launcher that keeps no record, the record still says
    2.10. Upgrading to 2.11 kept the stale 2.10 record for rollback, and the 2.9 images that were
    running became removable."""
    (tmp_path / ".release-images.current").write_text("# release 2.10.0\nghcr.io/x/shakerscan-api@sha256:r3\n")
    (tmp_path / ".release-images.previous").write_text("# release 2.9.0\nghcr.io/x/shakerscan-api@sha256:r1\n")
    body = _THREE + """
    running_api_version() { echo 2.9.0; }
    echo id-r2 > "$WORK/containers"     # the rolled-back 2.9 runs from another pull (r2)
    note_running_release
    : > "$WORK/containers"              # the start replaced it
    REFS="ghcr.io/x/shakerscan-api@sha256:r4"; SCANNER_VERSION=2.11.0; record_started_release prune
    cat "$WORK/.release-images.previous"
    """
    result = run(tmp_path, body)
    assert "# release 2.9.0\nid-r2\n" in result.stdout, result.stdout + result.stderr
    removed = _removed(tmp_path)
    assert "id-r2" not in removed and "ghcr.io/x/shakerscan-api@sha256:r4" not in removed
    assert sorted(removed) == ["ghcr.io/x/shakerscan-api@sha256:r1", "ghcr.io/x/shakerscan-api@sha256:r3"], removed


def test_a_restart_of_the_release_that_runs_changes_no_kept_release(tmp_path):
    (tmp_path / ".release-images.current").write_text("# release 2.11.0\nghcr.io/x/shakerscan-api@sha256:r4\n")
    (tmp_path / ".release-images.previous").write_text("# release 2.10.0\nghcr.io/x/shakerscan-api@sha256:r3\n")
    body = _THREE + """
    running_api_version() { echo 2.11.0; }
    echo id-r4 > "$WORK/containers"
    note_running_release
    REFS="ghcr.io/x/shakerscan-api@sha256:r4"; SCANNER_VERSION=2.11.0; record_started_release prune
    cat "$WORK/.release-images.previous"
    """
    result = run(tmp_path, body)
    assert result.stdout.startswith("# release 2.10.0\nghcr.io/x/shakerscan-api@sha256:r3"), result.stdout
    assert _removed(tmp_path) == []


def test_keep_releases_three_keeps_two_rollback_releases(tmp_path):
    body = _THREE + """
    for n in 1 2 3 4; do REFS="ghcr.io/x/shakerscan-api@sha256:r$n"; SCANNER_VERSION=2.$((7 + n)).0; record_started_release prune; done
    head -1 "$WORK/.release-images.current" "$WORK/.release-images.previous" "$WORK/.release-images.previous.2"
    """
    result = run(tmp_path, body, SHAKERSCAN_KEEP_RELEASES="3")
    assert _removed(tmp_path) == ["ghcr.io/x/shakerscan-api@sha256:r1"], result.stdout + result.stderr
    assert "# release 2.11.0" in result.stdout and "# release 2.10.0" in result.stdout and "# release 2.9.0" in result.stdout
    assert "SHAKERSCAN_KEEP_RELEASES=3" in result.stdout


def test_keep_releases_one_keeps_no_rollback_images_and_a_lowered_value_releases_the_rest(tmp_path):
    body = _THREE + """
    for n in 1 2 3; do REFS="ghcr.io/x/shakerscan-api@sha256:r$n"; SCANNER_VERSION=2.$((7 + n)).0; record_started_release prune; done
    ls -A "$WORK" | grep release-images >&2
    SHAKERSCAN_KEEP_RELEASES=1
    source "$SCRIPT_UNDER_TEST"
    REFS="ghcr.io/x/shakerscan-api@sha256:r3"; SCANNER_VERSION=2.10.0; record_started_release prune
    """
    result = run(tmp_path, body, SHAKERSCAN_KEEP_RELEASES="3", SCRIPT_UNDER_TEST=str(SCRIPT))
    assert sorted(_removed(tmp_path)) == ["ghcr.io/x/shakerscan-api@sha256:r1", "ghcr.io/x/shakerscan-api@sha256:r2"], \
        result.stdout + result.stderr
    assert not (tmp_path / ".release-images.previous").exists()
    assert not (tmp_path / ".release-images.previous.2").exists()


# --- 2.11 C5: install directory space, datastores persisting, volumes, backup offer, images, Redis


def _upgrade_pending(tmp_path: Path) -> None:
    (tmp_path / ".release-images.current").write_text("# release 2.10.0\nref\n")


def test_an_upgrade_without_room_in_the_install_directory_stops_with_nothing_changed(tmp_path):
    _upgrade_pending(tmp_path)
    body = """
    df() { printf 'Filesystem 1024-blocks Used Available Capacity Mounted\\n/dev/x 100 1 %s 1%% /\\n' "$((1 * 1024 * 1024))"; }
    ensure_install_dir_space; echo rc=$?
    """
    result = run(tmp_path, body, SCANNER_VERSION="2.11.0")
    assert "rc=1" in result.stdout and "Not enough disk space in the install directory" in result.stderr
    assert "Nothing was changed" in result.stderr
    # A restart of the same release only warns.
    restart = run(tmp_path, body, SCANNER_VERSION="2.10.0")
    assert "rc=0" in restart.stdout and "Free disk space soon" in restart.stdout


def _persistence(tmp_path: Path, mounts: str, info: str, running: str = "2.10.0", version: str = "2.11.0"):
    _upgrade_pending(tmp_path)
    body = f"""
    echo cid > "$WORK/containers"
    running_api_version() {{ echo {running}; }}
    redis_container_state() {{ echo running; }}
    docker_cli() {{
      case "$*" in
        *"--format {{{{range .Mounts}}}}"*) printf '%s\\n' {mounts} ;;
        "ps -aq --filter"*|"ps -q --filter"*) echo cid ;;
        *) docker "$@" ;;
      esac
    }}
    compose() {{ echo "compose $*" >> "$CALLS"; case "$*" in *"INFO persistence"*) printf '%s\\n' {info} ;; esac; }}
    ensure_datastores_persisting; echo rc=$?
    """
    return run(tmp_path, body, SCANNER_VERSION=version)


def test_datastores_saving_to_their_volumes_let_the_upgrade_proceed(tmp_path):
    result = _persistence(tmp_path, '"volume /var/lib/postgresql" "volume /data"',
                          '"loading:0" "rdb_last_bgsave_status:ok" "aof_last_write_status:ok"')
    assert "rc=0" in result.stdout, result.stdout + result.stderr


def test_a_redis_that_cannot_save_stops_the_upgrade_before_anything_is_stopped(tmp_path):
    result = _persistence(tmp_path, '"volume /var/lib/postgresql" "volume /data"',
                          '"loading:0" "rdb_last_bgsave_status:err" "aof_last_write_status:err"')
    assert "rc=1" in result.stdout
    assert "last snapshot failed" in result.stderr and "append-only file" in result.stderr
    assert "the running release keeps running" in result.stderr
    assert "compose stop" not in calls(tmp_path) and "compose down" not in calls(tmp_path)


def test_data_outside_its_volume_stops_the_upgrade(tmp_path):
    result = _persistence(tmp_path, '"bind /docker-entrypoint-initdb.d/init.sql"',
                          '"loading:0" "rdb_last_bgsave_status:ok"')
    assert "rc=1" in result.stdout
    assert "PostgreSQL's data is not on its Docker volume" in result.stderr
    assert "Redis's data is not on its Docker volume" in result.stderr


def test_a_restart_of_the_running_release_is_not_held_by_the_persistence_check(tmp_path):
    result = _persistence(tmp_path, '""', '"rdb_last_bgsave_status:err"', running="2.11.0", version="2.11.0")
    assert "rc=0" in result.stdout, result.stdout + result.stderr


def test_a_start_never_creates_an_empty_database_over_a_lost_one(tmp_path):
    _upgrade_pending(tmp_path)
    result = run(tmp_path, "ensure_database_volume_present; echo rc=$?")
    assert "rc=1" in result.stdout and "would create an empty database" in result.stderr
    assert "SHAKERSCAN_ALLOW_NEW_DATABASE=1" in result.stderr
    (tmp_path / "volume_shakerscan_postgres-cluster").write_text("")
    assert "rc=0" in run(tmp_path, "ensure_database_volume_present; echo rc=$?").stdout
    (tmp_path / "volume_shakerscan_postgres-cluster").unlink()
    assert "rc=0" in run(tmp_path, "ensure_database_volume_present; echo rc=$?",
                         SHAKERSCAN_ALLOW_NEW_DATABASE="1").stdout
    # Docker cannot list volumes (permissions): never read as "missing".
    denied = run(tmp_path, 'docker_cli() { case "$1" in volume) return 1 ;; esac; }; ensure_database_volume_present; echo rc=$?')
    assert "rc=0" in denied.stdout
    first = tmp_path / "first"
    first.mkdir()
    assert "rc=0" in run(first, "ensure_database_volume_present; echo rc=$?").stdout


def test_reset_starts_with_an_empty_database_on_purpose():
    launcher = (ROOT / "scanner.sh").read_text()
    body = launcher.split("\nreset_database() {", 1)[1].split("\n}", 1)[0]
    assert "SHAKERSCAN_ALLOW_NEW_DATABASE=1 start_services" in body


def test_a_full_backup_is_taken_before_an_upgrade_when_asked(tmp_path):
    _upgrade_pending(tmp_path)
    body = """
    create_backup() { echo "full-backup" >> "$CALLS"; }
    offer_upgrade_backup; echo rc=$? taken=$UPGRADE_FULL_BACKUP_TAKEN
    """
    result = run(tmp_path, body, SCANNER_VERSION="2.11.0", SHAKERSCAN_UPGRADE_BACKUP="full")
    assert "rc=0 taken=1" in result.stdout and "full-backup" in calls(tmp_path)
    # Without a terminal and without the setting: the automatic database dump only.
    result = run(tmp_path, body, SCANNER_VERSION="2.11.0")
    assert "rc=0 taken=0" in result.stdout and "full-backup" not in calls(tmp_path)
    # Not an upgrade: nothing offered.
    result = run(tmp_path, body, SCANNER_VERSION="2.10.0", SHAKERSCAN_UPGRADE_BACKUP="full")
    assert "taken=0" in result.stdout and "full-backup" not in calls(tmp_path)


def test_a_failed_full_backup_stops_the_upgrade(tmp_path):
    _upgrade_pending(tmp_path)
    body = "create_backup() { return 1; }; offer_upgrade_backup; echo rc=$?"
    result = run(tmp_path, body, SCANNER_VERSION="2.11.0", SHAKERSCAN_UPGRADE_BACKUP="full")
    assert "rc=1" in result.stdout and "nothing was upgraded" in result.stderr


def test_the_start_offers_the_backup_and_skips_the_second_dump_when_it_was_taken():
    launcher = (ROOT / "scanner.sh").read_text()
    body = launcher.split("\nstart_services() {", 1)[1].split("\n}", 1)[0]
    assert body.index("ensure_install_dir_space") < body.index("pull_prebuilt_images")
    assert body.index("ensure_datastores_persisting") < body.index("stop_services")
    assert body.index("ensure_database_volume_present") < body.index("compose_up -d postgres")
    assert body.index("compose_up -d postgres") < body.index("offer_upgrade_backup") < body.index("ensure_pre_upgrade_backup")
    restart = launcher.split("\nrestart_services() {", 1)[1].split("\n}", 1)[0]
    assert restart.index("ensure_datastores_persisting") < restart.index("stop_services")


def test_images_prune_needs_a_release_record_and_keeps_every_protected_image(tmp_path):
    body = """
    echo "ghcr.io/x/shakerscan-api@sha256:x id-x ghcr.io/x/shakerscan-api" > "$WORK/images"
    images_cmd prune
    """
    result = run(tmp_path, body)
    assert "nothing was removed" in result.stdout and "image rm" not in calls(tmp_path)
    (tmp_path / ".release-images.current").write_text("# release 2.11.0\nghcr.io/x/shakerscan-api@sha256:new1\n")
    (tmp_path / ".release-images.previous").write_text("# release 2.10.0\nghcr.io/x/shakerscan-api@sha256:prev\n")
    body = """
    cat > "$WORK/images" <<'X'
    ghcr.io/x/shakerscan-api@sha256:new1 id-new ghcr.io/x/shakerscan-api
    ghcr.io/x/shakerscan-api@sha256:prev id-prev ghcr.io/x/shakerscan-api
    ghcr.io/x/shakerscan-api@sha256:old id-old ghcr.io/x/shakerscan-api
    redis:8 id-redis redis
    X
    sed -i.bak 's/^ *//' "$WORK/images"
    images_cmd prune
    """
    result = run(tmp_path, body)
    removed = [line for line in calls(tmp_path).splitlines() if line.startswith("docker image rm")]
    assert removed == ["docker image rm id-old"], result.stdout + result.stderr
    assert "Removed 1 ShakerScan image(s)" in result.stdout
    assert "volume" not in calls(tmp_path)


def test_images_lists_why_each_image_is_kept(tmp_path):
    (tmp_path / ".release-images.previous").write_text("# release 2.10.0\nghcr.io/x/shakerscan-api@sha256:prev\n")
    body = """
    cat > "$WORK/images" <<'X'
    ghcr.io/x/shakerscan-api@sha256:new1 id-new ghcr.io/x/shakerscan-api
    ghcr.io/x/shakerscan-api@sha256:prev id-prev ghcr.io/x/shakerscan-api
    ghcr.io/x/shakerscan-api@sha256:old id-old ghcr.io/x/shakerscan-api
    X
    sed -i.bak 's/^ *//' "$WORK/images"
    docker_cli() {
      case "$1 $2" in
        "images --no-trunc") awk -v repo="${@: -1}" '$3 == repo {print $2, $1, "1GB"}' "$WORK/images" ;;
        *) docker "$@" ;;
      esac
    }
    images_cmd
    """
    result = run(tmp_path, body)
    lines = {line.split()[0]: line for line in result.stdout.splitlines() if line.startswith("ghcr")}
    assert "kept: this-release" in lines["ghcr.io/x/shakerscan-api@sha256:new1"], result.stdout
    assert "release 2.10.0 (kept for rollback)" in lines["ghcr.io/x/shakerscan-api@sha256:prev"]
    assert "removable" in lines["ghcr.io/x/shakerscan-api@sha256:old"]
    assert "never removed" in result.stdout


def test_redis_reset_keeps_a_copy_then_starts_it_empty_and_reconnects_the_services(tmp_path):
    (tmp_path / "volume_shakerscan_redis-data").write_text("")
    body = """
    wait_for_redis_healthy() { return 0; }
    service_container() { echo cid; }
    redis_cmd reset --yes; echo rc=$?
    """
    result = run(tmp_path, body)
    assert "rc=0" in result.stdout, result.stdout + result.stderr
    log = calls(tmp_path)
    assert log.index("tar czf /backup/redis-data.tgz") < log.index("volume removed shakerscan_redis-data")
    assert "compose restart api worker agent-tool-worker" in log
    assert "postgres" not in log
    assert "queued again automatically" in result.stdout


def test_redis_reset_asks_first(tmp_path):
    result = run(tmp_path, "redis_cmd reset < /dev/null; echo rc=$?")
    assert "rc=1" in result.stdout and "Cancelled" in result.stdout
    assert "volume" not in calls(tmp_path)


def test_status_warns_when_redis_volume_is_missing(tmp_path):
    (tmp_path / ".release-images.current").write_text("# release 2.11.0\nref\n")
    result = run(tmp_path, "upgrade_safety_warnings")
    assert "Redis's volume is missing" in result.stdout
    (tmp_path / "volume_shakerscan_redis-data").write_text("")
    assert "Redis's volume is missing" not in run(tmp_path, "upgrade_safety_warnings").stdout


# --- review sweep L4: an install path with spaces; L5: the pre-2.6 PostgreSQL volume layout ---


def _spaced_install(tmp_path: Path) -> tuple[Path, Path]:
    """An install directory whose path contains spaces, and a canary file named like the first
    word-split fragment of that path (an unquoted ``rm -f`` of the fragments would remove it)."""
    work = tmp_path / "Shaker Scan install"
    work.mkdir()
    canary = tmp_path / "Shaker"
    canary.write_text("not ShakerScan's\n")
    return work, canary


def test_an_install_path_with_spaces_keeps_its_rollback_chain_and_images(tmp_path):
    work, canary = _spaced_install(tmp_path)
    body = _THREE + """
    for n in 1 2 3 4; do REFS="ghcr.io/x/shakerscan-api@sha256:r$n"; SCANNER_VERSION=2.$((7 + n)).0; record_started_release prune; done
    head -1 "$WORK/.release-images.current" "$WORK/.release-images.previous" "$WORK/.release-images.previous.2"
    echo "kept-refs:" $(host_kept_release_refs | sort -u)
    echo "low-disk=$(prune_unused_release_images)"
    """
    result = run(work, body, SHAKERSCAN_KEEP_RELEASES="3")
    assert _removed(work) == ["ghcr.io/x/shakerscan-api@sha256:r1"], result.stdout + result.stderr
    for version in ("2.11.0", "2.10.0", "2.9.0"):
        assert f"# release {version}" in result.stdout, result.stdout + result.stderr
    kept = result.stdout.split("kept-refs:", 1)[1].splitlines()[0].split()
    assert kept == [f"ghcr.io/x/shakerscan-api@sha256:r{n}" for n in (2, 3, 4)], result.stdout
    assert "low-disk=0" in result.stdout
    assert canary.exists()
    assert not list(work.glob(".release-images.keep.*")) and not (work / ".release-images.superseded").exists()


def test_an_install_path_with_spaces_rotates_its_backups_and_nothing_outside_them(tmp_path):
    work, canary = _spaced_install(tmp_path)
    backups = work / "backups"
    for name in ("pre-upgrade-20261001T000000Z-2.7.0-to-2.8.0", "pre-upgrade-20261003T000000Z-2.8.0-to-2.9.0",
                 "pre-upgrade-20261005T000000Z-2.9.0-to-2.10.0"):
        (backups / name).mkdir(parents=True)
    result = _backup(work, "2.10.0", "t", SCANNER_VERSION="2.11.0")
    kept = sorted(path.name for path in backups.glob("pre-upgrade-*"))
    assert len(kept) == 2 and kept[0] == "pre-upgrade-20261005T000000Z-2.9.0-to-2.10.0", (kept, result.stderr)
    assert kept[1].endswith("-2.10.0-to-2.11.0")
    assert canary.exists()


def test_a_running_release_before_2_6_keeps_its_database_on_the_postgres_data_volume(tmp_path):
    """Review sweep L5: a release before 2.6 mounts postgres-data at /var/lib/postgresql/data;
    the persistence check refused every upgrade from it as data outside its volume."""
    result = _persistence(tmp_path, '"volume /var/lib/postgresql/data" "volume /data"',
                          '"loading:0" "rdb_last_bgsave_status:ok" "aof_last_write_status:ok"',
                          running="2.5.6")
    assert "rc=0" in result.stdout, result.stdout + result.stderr


def test_data_outside_either_postgres_layout_names_both_volumes(tmp_path):
    result = _persistence(tmp_path, '"bind /var/lib/postgresql/data" "volume /data"',
                          '"loading:0" "rdb_last_bgsave_status:ok"')
    assert "rc=1" in result.stdout
    assert "shakerscan_postgres-cluster at /var/lib/postgresql" in result.stderr
    assert "shakerscan_postgres-data at /var/lib/postgresql/data before 2.6" in result.stderr


# --- review sweep re-check (L4): a newline in the install path ---------------------------------


def _newline_install(tmp_path: Path) -> tuple[Path, Path, Path]:
    """An install directory whose path contains a newline, with a canary file and a canary
    directory named like the path's first line-split fragment."""
    work = tmp_path / "Shaker\nScan install"
    work.mkdir()
    canary_file = tmp_path / "Shaker"
    canary_file.write_text("not ShakerScan's\n")
    canary_dir = tmp_path / "Scan install"
    canary_dir.mkdir()
    (canary_dir / "keep").write_text("not ShakerScan's\n")
    return work, canary_file, canary_dir


def test_backup_rotation_never_splits_a_path_with_a_newline(tmp_path):
    """The rotation listed backups with `ls -1d ... | read`, so `<tmp>/Shaker` (a fragment of the
    install path) reached `rm -rf`."""
    work, canary_file, canary_dir = _newline_install(tmp_path)
    (tmp_path / "Shaker").unlink()
    (tmp_path / "Shaker").mkdir()
    (tmp_path / "Shaker" / "keep").write_text("not ShakerScan's\n")
    backups = work / "backups"
    for name in ("pre-upgrade-20261001T000000Z-2.7.0-to-2.8.0", "pre-upgrade-20261003T000000Z-2.8.0-to-2.9.0",
                 "pre-upgrade-20261005T000000Z-2.9.0-to-2.10.0"):
        (backups / name).mkdir(parents=True)
    result = _backup(work, "2.10.0", "t", SCANNER_VERSION="2.11.0")
    kept = sorted(path.name for path in backups.glob("pre-upgrade-*"))
    assert len(kept) == 2 and kept[0] == "pre-upgrade-20261005T000000Z-2.9.0-to-2.10.0", (kept, result.stderr)
    assert (tmp_path / "Shaker" / "keep").exists() and (canary_dir / "keep").exists()


def test_the_release_chain_never_splits_a_path_with_a_newline(tmp_path):
    work, canary_file, canary_dir = _newline_install(tmp_path)
    body = _THREE + """
    for n in 1 2 3 4; do REFS="ghcr.io/x/shakerscan-api@sha256:r$n"; SCANNER_VERSION=2.$((7 + n)).0; record_started_release prune; done
    head -1 "$WORK/.release-images.current" "$WORK/.release-images.previous" "$WORK/.release-images.previous.2"
    echo "low-disk=$(prune_unused_release_images)"
    """
    result = run(work, body, SHAKERSCAN_KEEP_RELEASES="3")
    for version in ("2.11.0", "2.10.0", "2.9.0"):
        assert f"# release {version}" in result.stdout, result.stdout + result.stderr
    # No image is removed from an install whose path cannot be listed safely.
    assert _removed(work) == [] and "low-disk=0" in result.stdout
    assert canary_file.exists() and (canary_dir / "keep").exists()
    registry = work / "registry" / "installs"
    assert not registry.exists() or str(work) not in registry.read_text()


def test_a_start_or_restart_refuses_an_install_path_with_a_newline(tmp_path):
    work, _canary_file, _canary_dir = _newline_install(tmp_path)
    result = run(work, """
    stack_is_running() { return 0; }
    ensure_install_dir_space; echo start-rc=$?
    ensure_datastores_persisting; echo restart-rc=$?
    """)
    assert "start-rc=1" in result.stdout and "restart-rc=1" in result.stdout, result.stdout + result.stderr
    assert "contains a newline or another control character" in result.stderr
    assert "Nothing was changed" in result.stderr
    spaced = tmp_path / "Shaker Scan spaced"
    spaced.mkdir()
    assert "rc=0" in run(spaced, "ensure_install_path_safe; echo rc=$?").stdout
