# Sourced by the launcher (scanner.sh). Upgrades that look after themselves.
#
# A release upgrade must not need its operator to manage Docker. Before anything changes:
#   - remember_running_release: the images of the release that is about to be replaced are
#     recorded (kept for rollback) before its containers are stopped.
#   - ensure_upgrade_space: images this release still has to download must fit in Docker's
#     storage with a margin for PostgreSQL and Redis writes; ShakerScan's own superseded release
#     images are removed first (never a volume, never an image a container uses, never the
#     previous release); otherwise it refuses, naming the numbers, with nothing changed. A start
#     with nothing to download never needs this room.
#   - ensure_pre_upgrade_backup: a version-changing start dumps PostgreSQL first (outside Docker).
#   - ensure_redis_ready: Redis must be healthy before anything that depends on it. A damaged
#     append-only file is repaired (a copy of its data is kept first); a Redis that cannot write
#     gets room from old images. Only a damaged Redis whose data was copied may start empty: it
#     holds queues and job state, never scans, findings or evidence. A Redis that is loading,
#     cannot be inspected, or fails for an unknown reason is never reset.
# After a successful start, record_started_release remembers this release and the previous one;
# in prebuilt mode older ShakerScan images are then removed.
#
# Docker is always called through the launcher's docker_cli (sudo when the launcher needs it).
# Nothing here suggests `docker system prune --volumes`, which deletes the PostgreSQL data.

UPGRADE_MARGIN_GB="${SHAKERSCAN_UPGRADE_MARGIN_GB:-5}"
REDIS_READY_SECONDS="${SHAKERSCAN_REDIS_READY_SECONDS:-120}"
REDIS_LOADING_SECONDS="${SHAKERSCAN_REDIS_LOADING_SECONDS:-900}"
RELEASE_STATE_CURRENT="${SCRIPT_DIR}/.release-images.current"
RELEASE_STATE_PREVIOUS="${SCRIPT_DIR}/.release-images.previous"

# The launcher defines docker_cli (sudo when needed) later in scanner.sh, which replaces this.
if ! declare -F docker_cli >/dev/null 2>&1; then
    docker_cli() { docker "$@"; }
fi

# Estimated unpacked size of a release image that is not present yet, in GB, by repository.
release_image_estimate_gb() {
    case "$1" in
        *model-intake-signer*|*signer*) echo 1 ;;
        *model-intake*) echo 5 ;;
        *scanner*|*worker*) echo 7 ;;
        *-ui*|*/ui*) echo 1 ;;
        *-api*|*/api*) echo 2 ;;
        *) echo 3 ;;
    esac
}

# GB still to download for this release: the release images not present locally.
upgrade_missing_image_gb() {
    local image total=0
    for image in $(release_image_refs); do
        if ! docker_cli image inspect "$image" >/dev/null 2>&1; then
            total=$((total + $(release_image_estimate_gb "$image")))
        fi
    done
    echo "$total"
}

shakerscan_image_repositories() {
    printf '%s\n' "${API_IMAGE_REPO:-}" "${SCANNER_IMAGE_REPO:-}" "${UI_IMAGE_REPO:-}" \
        "${MODEL_INTAKE_IMAGE_REPO:-}" "${MODEL_INTAKE_SIGNER_IMAGE_REPO:-}" | sed '/^$/d' | sort -u
}

release_state_refs() {
    grep -hv '^#' "$@" 2>/dev/null | sed '/^$/d' || true
}

# The images this project's containers (running or stopped) use, by image id.
project_container_image_ids() {
    local project="${COMPOSE_PROJECT_NAME:-shakerscan}" container
    docker_cli ps -aq --filter "label=com.docker.compose.project=$project" 2>/dev/null \
        | while read -r container; do
            [ -n "$container" ] && docker_cli inspect --format '{{.Image}}' "$container" 2>/dev/null || true
        done
}

# Before a start replaces the running release, with no record of the release before it yet (the
# first upgrade with this launcher): record the images its containers use, so they are kept.
remember_running_release() {
    local images
    [ ! -f "$RELEASE_STATE_CURRENT" ] && [ ! -f "$RELEASE_STATE_PREVIOUS" ] || return 0
    images="$(project_container_image_ids | sed '/^$/d' | sort -u)"
    [ -n "$images" ] || return 0
    { printf '# release running-before-upgrade\n'; printf '%s\n' "$images"; } > "$RELEASE_STATE_PREVIOUS"
}

# Image ids that must stay: this release's, the recorded current and previous releases', and every
# image any container (running or stopped) uses.
protected_image_ids() {
    local ref container
    {
        for ref in $(release_image_refs) $(release_state_refs "$RELEASE_STATE_CURRENT" "$RELEASE_STATE_PREVIOUS"); do
            docker_cli image inspect --format '{{.Id}}' "$ref" 2>/dev/null || true
        done
        docker_cli ps -aq 2>/dev/null | while read -r container; do
            [ -n "$container" ] && docker_cli inspect --format '{{.Image}}' "$container" 2>/dev/null || true
        done
    } | sed '/^$/d' | sort -u
}

# Remove ShakerScan release images that are neither this release's, nor the recorded releases',
# nor used by any container. Never a volume, never another product's image, never forced. Without
# any record of a previous release nothing is removed (nothing would protect a rollback).
# Prints how many were removed.
prune_superseded_release_images() {
    local protected repo id
    if [ ! -f "$RELEASE_STATE_PREVIOUS" ] && [ ! -f "$RELEASE_STATE_CURRENT" ]; then
        echo 0
        return 0
    fi
    protected="$(protected_image_ids)"
    for repo in $(shakerscan_image_repositories); do
        docker_cli images --no-trunc --format '{{.ID}}' "$repo" 2>/dev/null | sort -u | while read -r id; do
            [ -n "$id" ] || continue
            if ! printf '%s\n' "$protected" | grep -qxF "$id"; then
                docker_cli image rm "$id" >/dev/null 2>&1 && echo removed
            fi
        done
    done | wc -l | tr -d ' '
}

docker_storage_free_gb() {
    local free_kb
    free_kb="$(docker_storage_free_kb)" || return 1
    [ -n "$free_kb" ] || return 1
    echo $((free_kb / 1024 / 1024))
}

stack_is_running() {
    [ -n "$(docker_cli ps -q --filter "label=com.docker.compose.project=${COMPOSE_PROJECT_NAME:-shakerscan}" 2>/dev/null)" ]
}

# Refuse an upgrade that would fill Docker's disk, after removing superseded ShakerScan images.
# A start with nothing to download never needs this room (only a warning when space is low).
ensure_upgrade_space() {
    local missing need free removed
    is_truthy "${SHAKERSCAN_PULL_IMAGES:-1}" || return 0
    missing="$(upgrade_missing_image_gb)"
    free="$(docker_storage_free_gb)" || return 0  # Docker Desktop: its disk is not visible here
    if [ "$missing" -eq 0 ]; then
        if [ "$free" -lt "$UPGRADE_MARGIN_GB" ]; then
            echo -e "${YELLOW}Docker has ${free} GB free; ShakerScan's database needs room to write. Free disk space soon.${NC}"
        fi
        return 0
    fi
    need=$((missing + UPGRADE_MARGIN_GB))
    [ "$free" -lt "$need" ] || return 0
    echo -e "${YELLOW}Docker has ${free} GB free; this release needs about ${need} GB (new images and room for the databases). Removing older ShakerScan images...${NC}"
    removed="$(prune_superseded_release_images)"
    free="$(docker_storage_free_gb || echo 0)"
    echo "Removed ${removed} older ShakerScan image(s); ${free} GB free now."
    [ "$free" -lt "$need" ] || return 0
    echo -e "${RED}Not enough disk space to upgrade: Docker has ${free} GB free and this release needs about ${need} GB.${NC}" >&2
    if stack_is_running; then
        echo "Nothing was changed: the running release keeps running." >&2
    else
        echo "Nothing was changed." >&2
    fi
    echo "Free disk space on this host (other files, or images of other projects: 'docker image ls')," >&2
    echo "then run '$(cli_hint) start' again. Do not remove Docker volumes: they hold ShakerScan's database." >&2
    return 1
}

started_release_version() {
    sed -n 's/^# release //p' "$RELEASE_STATE_CURRENT" 2>/dev/null | head -1
}

# After a successful start: this release becomes current, the one before it previous (kept for
# rollback). In prebuilt mode ("prune") older ShakerScan images are then removed.
record_started_release() {
    local current tmp removed prune="${1:-prune}"
    current="$(release_image_refs | sort)"
    if [ -f "$RELEASE_STATE_CURRENT" ]; then
        if [ "$(release_state_refs "$RELEASE_STATE_CURRENT" | sort)" != "$current" ] \
            || [ "$(started_release_version)" != "${SCANNER_VERSION:-unknown}" ]; then
            cp "$RELEASE_STATE_CURRENT" "$RELEASE_STATE_PREVIOUS"
        fi
    fi
    tmp="$RELEASE_STATE_CURRENT.tmp.$$"
    { printf '# release %s\n' "${SCANNER_VERSION:-unknown}"; printf '%s\n' "$current"; } > "$tmp"
    mv "$tmp" "$RELEASE_STATE_CURRENT"
    if [ "$prune" = prune ] && is_truthy "${SHAKERSCAN_PRUNE_OLD_IMAGES:-1}"; then
        removed="$(prune_superseded_release_images)"
        if [ "${removed:-0}" -gt 0 ]; then
            echo "Removed ${removed} image(s) of older ShakerScan releases (the previous release is kept for rollback)."
        fi
    fi
}

# Before a version-changing start against an existing database: dump PostgreSQL to
# backups/pre-upgrade-<time>-<from>-to-<to>/ (the newest two are kept). Needs PostgreSQL up.
ensure_pre_upgrade_backup() {
    local from to has_data size_kb free_kb dir stamp old
    is_truthy "${SHAKERSCAN_PRE_UPGRADE_BACKUP:-1}" || return 0
    to="${SCANNER_VERSION:-}"
    if [ -f "$RELEASE_STATE_CURRENT" ]; then
        from="$(started_release_version)"
    elif [ -f "$RELEASE_STATE_PREVIOUS" ]; then
        from="earlier"  # the first upgrade with this launcher: the running release was recorded
    else
        return 0        # no release ever recorded and none running: a first start, not an upgrade
    fi
    [ -n "$from" ] && [ -n "$to" ] && [ "$from" != "$to" ] || return 0
    if ! has_data="$(compose exec -T postgres psql -U scanner -d scanner -At -v ON_ERROR_STOP=1 \
        -c "SELECT to_regclass('public.targets') IS NOT NULL" 2>&1 | tr -d '\r'; exit "${PIPESTATUS[0]}")"; then
        echo -e "${RED}Cannot check the database before upgrading (${has_data}); nothing was changed.${NC}" >&2
        return 1
    fi
    [ "$has_data" = t ] || return 0
    size_kb="$(compose exec -T postgres psql -U scanner -d scanner -At \
        -c "SELECT pg_database_size('scanner')/1024" 2>/dev/null | tr -d '\r')"
    mkdir -p "$SCRIPT_DIR/backups"
    free_kb="$(df -Pk "$SCRIPT_DIR/backups" 2>/dev/null | awk 'END {print $4}')"
    if [ -n "$size_kb" ] && [ -n "$free_kb" ] && [ "$free_kb" -lt $((size_kb + 524288)) ]; then
        echo -e "${RED}Not enough disk space for the pre-upgrade database backup in $SCRIPT_DIR/backups: $((free_kb / 1024)) MB free, about $((size_kb / 1024 + 512)) MB needed.${NC}" >&2
        echo "Nothing was changed. Free disk space, then run '$(cli_hint) start' again." >&2
        return 1
    fi
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    dir="$SCRIPT_DIR/backups/pre-upgrade-${stamp}-${from}-to-${to}"
    ( umask 077; mkdir -p "$dir" )
    echo "Saving the database before upgrading ${from} to ${to}..."
    if ! compose exec -T postgres pg_dump -U scanner -d scanner -Fc > "$dir/postgres.dump"; then
        echo -e "${RED}The pre-upgrade database backup failed; nothing was changed.${NC}" >&2
        rm -rf -- "$dir"
        return 1
    fi
    [ ! -f "$SCRIPT_DIR/.env" ] || grep -vE '(^|[^A-Za-z0-9_])AI_CREDENTIAL_ENC_KEY[[:space:]]*[=:]' \
        "$SCRIPT_DIR/.env" > "$dir/runtime.env" || true
    printf 'created_at=%s\nfrom_release=%s\nto_release=%s\nkind=pre-upgrade\n' "$stamp" "$from" "$to" > "$dir/manifest.txt"
    echo "Database saved: $dir"
    # Names start with the time: the newest two are kept, and never the one just made.
    for old in $(ls -1d "$SCRIPT_DIR"/backups/pre-upgrade-* 2>/dev/null | sort -r | tail -n +3); do
        [ "$old" = "$dir" ] || rm -rf -- "$old"
    done
}

# healthy, starting, unhealthy, exited, missing, or unknown (Docker could not be asked).
redis_health() {
    local container state
    container="$(compose ps -q redis 2>/dev/null | head -1)"
    [ -n "$container" ] || { echo missing; return; }
    if ! state="$(docker_cli inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
        "$container" 2>/dev/null)"; then
        echo unknown
        return
    fi
    echo "${state:-unknown}"
}

redis_is_loading() {
    compose logs --no-color --tail 40 redis 2>/dev/null | grep -qiE "Loading|AOF loading"
}

# Healthy within `seconds`; a Redis still loading its data gets up to REDIS_LOADING_SECONDS.
wait_for_redis_healthy() {
    local seconds="${1:-$REDIS_READY_SECONDS}" waited=0 state
    while :; do
        state="$(redis_health)"
        [ "$state" = healthy ] && return 0
        [ "$state" = unknown ] && return 1
        if [ "$waited" -ge "$seconds" ]; then
            if { [ "$state" = starting ] || redis_is_loading; } && [ "$waited" -lt "$REDIS_LOADING_SECONDS" ]; then
                :
            else
                return 1
            fi
        fi
        sleep 2
        waited=$((waited + 2))
    done
}

redis_volume() {
    echo "${COMPOSE_PROJECT_NAME:-shakerscan}_redis-data"
}

# Redis's own reason for not becoming healthy: damaged, no_space, or unknown.
redis_failure_kind() {
    local logs
    logs="$(compose logs --no-color --tail 120 redis 2>/dev/null || true)"
    if printf '%s' "$logs" | grep -qiE "No space left on device|MISCONF|Read-only file system|Can't open the append-only file|Failed opening the temp RDB file"; then
        echo no_space
    elif printf '%s' "$logs" | grep -qiE "Bad file format reading the append only file|AOF.*(truncated|corrupt)|Unexpected end of file|Short read or OOM loading|redis-check-aof"; then
        echo damaged
    else
        echo unknown
    fi
}

# Keep a copy of Redis's data next to the backups. Returns 1 when no copy was made.
archive_redis_data() {
    local stamp dir
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    dir="$SCRIPT_DIR/backups/redis-$stamp"
    ( umask 077; mkdir -p "$dir" )
    compose stop redis >/dev/null 2>&1 || true
    if compose run --rm --no-deps -T -v "$dir:/backup" --entrypoint sh redis \
        -c 'tar czf /backup/redis-data.tgz -C /data .' >/dev/null 2>&1 && [ -s "$dir/redis-data.tgz" ]; then
        echo "Kept a copy of Redis's data: $dir/redis-data.tgz"
        return 0
    fi
    rm -rf -- "$dir"
    return 1
}

redis_give_up() {
    echo -e "${RED}$1${NC}" >&2
    echo "Redis's last messages:" >&2
    compose logs --no-color --tail 20 redis >&2 2>/dev/null || true
    echo "Run '$(cli_hint) doctor' and share its output. Do not remove Docker volumes: the PostgreSQL ones hold ShakerScan's database." >&2
    return 1
}

# Redis healthy before anything depends on it, repairing it when its own data is the problem.
ensure_redis_ready() {
    local kind
    compose up --no-build -d redis >/dev/null 2>&1 || true
    wait_for_redis_healthy && return 0
    if [ "$(redis_health)" = unknown ]; then
        redis_give_up "Docker cannot report Redis's state to the launcher; nothing was changed."
        return 1
    fi
    kind="$(redis_failure_kind)"
    case "$kind" in
        no_space)
            echo -e "${YELLOW}Redis cannot write to disk. Removing older ShakerScan images to make room...${NC}"
            echo "Removed $(prune_superseded_release_images) older ShakerScan image(s); $(docker_storage_free_gb 2>/dev/null || echo '?') GB free now."
            compose up --no-build -d --force-recreate redis >/dev/null 2>&1 || true
            wait_for_redis_healthy && return 0
            redis_give_up "Redis still cannot write to disk. Free disk space on this host, then run '$(cli_hint) start' again."
            return 1
            ;;
        damaged)
            echo -e "${YELLOW}Redis's saved state is damaged (an interrupted write, often a full disk). Repairing it...${NC}"
            if ! archive_redis_data; then
                echo "Making room to keep a copy first..."
                prune_superseded_release_images >/dev/null
                if ! archive_redis_data; then
                    redis_give_up "Could not keep a copy of Redis's damaged data (disk full?), so it was left as it is. Free disk space, then run '$(cli_hint) start' again."
                    return 1
                fi
            fi
            compose run --rm --no-deps -T --entrypoint sh redis -c \
                'cd /data/appendonlydir 2>/dev/null || exit 0; fixed=0; for m in *.manifest; do [ -f "$m" ] || continue; echo y | redis-check-aof --fix "$m" >/dev/null 2>&1 && fixed=1; done; [ "$fixed" = 1 ] || for f in *.incr.aof; do [ -f "$f" ] && echo y | redis-check-aof --fix "$f" >/dev/null 2>&1; done; true' \
                >/dev/null 2>&1 || true
            compose up --no-build -d --force-recreate redis >/dev/null 2>&1 || true
            if wait_for_redis_healthy; then
                echo -e "${GREEN}Redis repaired.${NC}"
                return 0
            fi
            # Damaged beyond repair, and a copy is kept: Redis starts empty. It holds queues and
            # job state only; scans, findings and evidence are in PostgreSQL.
            echo -e "${YELLOW}Redis could not be repaired; starting it with empty state (it holds only queues and job status; your scans, findings and evidence are in PostgreSQL and untouched).${NC}"
            compose rm -sf redis >/dev/null 2>&1 || true
            docker_cli volume rm "$(redis_volume)" >/dev/null 2>&1 || true
            compose up --no-build -d redis >/dev/null 2>&1 || true
            if wait_for_redis_healthy; then
                echo -e "${GREEN}Redis started with empty state. Scans that were waiting to start are queued again automatically within about 10 minutes; a scan that was already running is marked with an unknown outcome and can be started again from the Scans page.${NC}"
                return 0
            fi
            redis_give_up "Redis does not start even with empty state."
            return 1
            ;;
        *)
            # An unknown cause is never treated as damaged data: one restart, then a clear stop.
            compose up --no-build -d --force-recreate redis >/dev/null 2>&1 || true
            wait_for_redis_healthy && return 0
            redis_give_up "Redis is not healthy and the launcher does not recognise why; nothing was removed."
            return 1
            ;;
    esac
}

# For status and doctor: warnings about the conditions that break upgrades. Only when Docker
# answers (a permission error must never read as a missing volume).
upgrade_safety_warnings() {
    local free project
    project="${COMPOSE_PROJECT_NAME:-shakerscan}"
    docker_cli info >/dev/null 2>&1 || return 0
    if free="$(docker_storage_free_gb)" && [ "$free" -lt 20 ]; then
        echo "Docker has ${free} GB free; keep at least 20 GB free so the next upgrade can download its images."
    fi
    if [ -f "$SCRIPT_DIR/.env" ] && grep -q '^POSTGRES_PASSWORD=' "$SCRIPT_DIR/.env" 2>/dev/null \
        && [ -f "$RELEASE_STATE_CURRENT" ] \
        && docker_cli volume ls -q >/dev/null 2>&1 \
        && ! docker_cli volume inspect "${project}_postgres-cluster" >/dev/null 2>&1 \
        && ! docker_cli volume inspect "${project}_postgres-data" >/dev/null 2>&1; then
        echo "ShakerScan's database volume is missing although this install has started before; restore it from a backup in $SCRIPT_DIR/backups before using it."
    fi
}
