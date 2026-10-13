# Sourced by the launcher (scanner.sh). Upgrades that look after themselves.
#
# A release upgrade must not need its operator to manage Docker. Before anything changes:
#   - ensure_upgrade_space: the images this release still needs must fit in Docker's storage with
#     a margin for PostgreSQL and Redis writes; ShakerScan's own superseded release images are
#     removed first (never a volume, never an image a container uses, never the release kept for
#     rollback); otherwise it refuses, naming the numbers, with nothing changed.
#   - ensure_pre_upgrade_backup: a version-changing start dumps PostgreSQL first (outside Docker).
#   - ensure_redis_ready: Redis is started and healthy before anything that depends on it; a
#     damaged append-only file or a Redis that cannot persist is repaired (a copy of its data is
#     kept), and only as the last step is its state reset. Redis holds queues and job state, never
#     scans, findings or evidence.
# After a successful start, record_started_release remembers this release and the previous one,
# and prune_superseded_release_images removes older ShakerScan images.
#
# Every function here only ever removes ShakerScan release images or the Redis volume after its
# data was archived. Nothing here suggests `docker system prune --volumes`, which deletes the
# PostgreSQL data.

UPGRADE_MARGIN_GB="${SHAKERSCAN_UPGRADE_MARGIN_GB:-5}"
REDIS_READY_SECONDS="${SHAKERSCAN_REDIS_READY_SECONDS:-120}"
RELEASE_STATE_CURRENT="${SCRIPT_DIR}/.release-images.current"
RELEASE_STATE_PREVIOUS="${SCRIPT_DIR}/.release-images.previous"

# Estimated size of a release image that is not present yet, in GB, by its repository. Registries
# report compressed sizes; these are generous unpacked sizes. Unknown images count 3 GB.
release_image_estimate_gb() {
    case "$1" in
        *model-intake-signer*|*signer*) echo 1 ;;
        *model-intake*) echo 4 ;;
        *scanner*|*worker*) echo 5 ;;
        *-ui*|*/ui*) echo 1 ;;
        *-api*|*/api*) echo 2 ;;
        *) echo 3 ;;
    esac
}

# GB still to download for this release: the release images not present locally.
upgrade_missing_image_gb() {
    local image total=0
    for image in $(release_image_refs); do
        if ! docker image inspect "$image" >/dev/null 2>&1; then
            total=$((total + $(release_image_estimate_gb "$image")))
        fi
    done
    echo "$total"
}

shakerscan_image_repositories() {
    printf '%s\n' "${API_IMAGE_REPO:-}" "${SCANNER_IMAGE_REPO:-}" "${UI_IMAGE_REPO:-}" \
        "${MODEL_INTAKE_IMAGE_REPO:-}" "${MODEL_INTAKE_SIGNER_IMAGE_REPO:-}" | sed '/^$/d' | sort -u
}

# Image ids that must stay: this release's, the previous release's (rollback), and every image a
# container (running or stopped) uses.
protected_image_ids() {
    local ref
    {
        for ref in $(release_image_refs); do
            docker image inspect --format '{{.Id}}' "$ref" 2>/dev/null || true
        done
        if [ -f "$RELEASE_STATE_CURRENT" ] || [ -f "$RELEASE_STATE_PREVIOUS" ]; then
            grep -hv '^#' "$RELEASE_STATE_CURRENT" "$RELEASE_STATE_PREVIOUS" 2>/dev/null \
                | while read -r ref; do
                    [ -n "$ref" ] && docker image inspect --format '{{.Id}}' "$ref" 2>/dev/null || true
                done
        fi
        docker ps -aq 2>/dev/null | while read -r container; do
            [ -n "$container" ] && docker inspect --format '{{.Image}}' "$container" 2>/dev/null || true
        done
    } | sed '/^$/d' | sort -u
}

# Remove ShakerScan release images that are neither this release's, nor the previous one's, nor
# used by any container. Never a volume, never another product's image, never forced.
# Prints how many were removed.
prune_superseded_release_images() {
    local protected repo id removed=0
    protected="$(protected_image_ids)"
    for repo in $(shakerscan_image_repositories); do
        docker images --no-trunc --format '{{.ID}}' "$repo" 2>/dev/null | sort -u | while read -r id; do
            [ -n "$id" ] || continue
            if ! printf '%s\n' "$protected" | grep -qxF "$id"; then
                docker image rm "$id" >/dev/null 2>&1 && echo removed
            fi
        done
    done | wc -l | tr -d ' ' | { read -r removed; echo "${removed:-0}"; }
}

docker_storage_free_gb() {
    local free_kb
    free_kb="$(docker_storage_free_kb)" || return 1
    [ -n "$free_kb" ] || return 1
    echo $((free_kb / 1024 / 1024))
}

# Refuse an upgrade that would fill Docker's disk, after removing superseded ShakerScan images.
ensure_upgrade_space() {
    local need free removed
    need=$(( $(upgrade_missing_image_gb) + UPGRADE_MARGIN_GB ))
    if ! free="$(docker_storage_free_gb)"; then
        return 0  # Docker Desktop and similar: the daemon's disk is not visible from the host
    fi
    if [ "$free" -ge "$need" ]; then
        return 0
    fi
    echo -e "${YELLOW}Docker has ${free} GB free; this release needs about ${need} GB (new images and room for the databases). Removing older ShakerScan images...${NC}"
    removed="$(prune_superseded_release_images)"
    free="$(docker_storage_free_gb || echo 0)"
    echo "Removed ${removed} older ShakerScan image(s); ${free} GB free now."
    if [ "$free" -ge "$need" ]; then
        return 0
    fi
    echo -e "${RED}Not enough disk space to upgrade: Docker has ${free} GB free and this release needs about ${need} GB.${NC}" >&2
    echo "Nothing was changed: the running release keeps running. Free disk space on this host" >&2
    echo "(other files, or images of other projects: 'docker image ls'), then run '$(cli_hint) start' again." >&2
    echo "Do not remove Docker volumes: they hold ShakerScan's database." >&2
    return 1
}

# The release this install last started successfully (its image references), or nothing.
started_release_refs() {
    grep -v '^#' "$RELEASE_STATE_CURRENT" 2>/dev/null || true
}

# After a successful start: this release becomes current, the one before it previous (kept for
# rollback), and older ShakerScan images go.
record_started_release() {
    local current tmp removed
    current="$(release_image_refs | sort)"
    if [ -f "$RELEASE_STATE_CURRENT" ] && [ "$(started_release_refs | sort)" != "$current" ]; then
        cp "$RELEASE_STATE_CURRENT" "$RELEASE_STATE_PREVIOUS"
    fi
    tmp="$RELEASE_STATE_CURRENT.tmp.$$"
    { printf '# release %s\n' "${SCANNER_VERSION:-unknown}"; printf '%s\n' "$current"; } > "$tmp"
    mv "$tmp" "$RELEASE_STATE_CURRENT"
    if is_truthy "${SHAKERSCAN_PRUNE_OLD_IMAGES:-1}"; then
        removed="$(prune_superseded_release_images)"
        if [ "${removed:-0}" -gt 0 ]; then
            echo "Removed ${removed} image(s) of older ShakerScan releases (the previous release is kept for rollback)."
        fi
    fi
}

started_release_version() {
    sed -n 's/^# release //p' "$RELEASE_STATE_CURRENT" 2>/dev/null | head -1
}

# Before a version-changing start against an existing database: dump PostgreSQL to
# backups/pre-upgrade-<from>-to-<to>-<time>/ (the newest two are kept). Needs PostgreSQL up.
ensure_pre_upgrade_backup() {
    local from to has_data size_kb free_kb dir stamp
    from="$(started_release_version)"
    to="${SCANNER_VERSION:-}"
    # No record yet: this launcher never started here, so an existing database comes from an
    # earlier release (the first upgrade to a release with this launcher is the one that matters).
    [ -f "$RELEASE_STATE_CURRENT" ] || from="earlier"
    [ -n "$from" ] && [ -n "$to" ] && [ "$from" != "$to" ] || return 0
    is_truthy "${SHAKERSCAN_PRE_UPGRADE_BACKUP:-1}" || return 0
    has_data="$(compose exec -T postgres psql -U scanner -d scanner -At \
        -c "SELECT to_regclass('public.targets') IS NOT NULL" 2>/dev/null | tr -d '\r')"
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
    dir="$SCRIPT_DIR/backups/pre-upgrade-${from}-to-${to}-${stamp}"
    ( umask 077; mkdir -p "$dir" )
    echo "Saving the database before upgrading ${from} to ${to}..."
    if ! compose exec -T postgres pg_dump -U scanner -d scanner -Fc > "$dir/postgres.dump"; then
        echo -e "${RED}The pre-upgrade database backup failed; nothing was changed.${NC}" >&2
        rm -rf "$dir"
        return 1
    fi
    [ ! -f "$SCRIPT_DIR/.env" ] || grep -vE '(^|[^A-Za-z0-9_])AI_CREDENTIAL_ENC_KEY[[:space:]]*[=:]' \
        "$SCRIPT_DIR/.env" > "$dir/runtime.env" || true
    printf 'created_at=%s\nfrom_release=%s\nto_release=%s\nkind=pre-upgrade\n' "$stamp" "$from" "$to" > "$dir/manifest.txt"
    echo "Database saved: $dir"
    # The newest two pre-upgrade backups are kept.
    ls -1d "$SCRIPT_DIR"/backups/pre-upgrade-* 2>/dev/null | sort -r | tail -n +3 | while read -r old; do
        rm -rf "$old"
    done
}

redis_health() {
    local container
    container="$(compose ps -q redis 2>/dev/null | head -1)"
    [ -n "$container" ] || { echo missing; return; }
    docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
        "$container" 2>/dev/null || echo missing
}

wait_for_redis_healthy() {
    local seconds="${1:-$REDIS_READY_SECONDS}" waited=0 state
    while [ "$waited" -lt "$seconds" ]; do
        state="$(redis_health)"
        [ "$state" = healthy ] && return 0
        sleep 2
        waited=$((waited + 2))
    done
    return 1
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
    elif printf '%s' "$logs" | grep -qiE "Bad file format reading the append only file|Unrecoverable error|AOF.*(truncated|corrupt)|Short read|Bad file format reading|redis-check-aof|Unexpected end of file"; then
        echo damaged
    else
        echo unknown
    fi
}

# Keep a copy of Redis's data next to the backups before repairing or resetting it.
archive_redis_data() {
    local stamp dir
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    dir="$SCRIPT_DIR/backups/redis-$stamp"
    ( umask 077; mkdir -p "$dir" )
    compose stop redis >/dev/null 2>&1 || true
    if compose run --rm --no-deps -T -v "$dir:/backup" --entrypoint sh redis \
        -c 'tar czf /backup/redis-data.tgz -C /data .' >/dev/null 2>&1; then
        echo "Kept a copy of Redis's data: $dir/redis-data.tgz"
    else
        echo -e "${YELLOW}Could not copy Redis's data (it may be unreadable); continuing.${NC}"
    fi
}

# Redis healthy before anything depends on it, repairing it when its own data is the problem.
ensure_redis_ready() {
    local kind
    compose up --no-build -d redis >/dev/null 2>&1 || true
    wait_for_redis_healthy && return 0
    kind="$(redis_failure_kind)"
    case "$kind" in
        no_space)
            echo -e "${YELLOW}Redis cannot write to disk. Removing older ShakerScan images to make room...${NC}"
            echo "Removed $(prune_superseded_release_images) older ShakerScan image(s); $(docker_storage_free_gb 2>/dev/null || echo '?') GB free now."
            compose up --no-build -d --force-recreate redis >/dev/null 2>&1 || true
            if wait_for_redis_healthy; then
                return 0
            fi
            echo -e "${RED}Redis still cannot write to disk. Free disk space on this host, then run '$(cli_hint) start' again.${NC}" >&2
            echo "Do not remove Docker volumes: they hold ShakerScan's database." >&2
            return 1
            ;;
        damaged)
            echo -e "${YELLOW}Redis's saved state is damaged (an interrupted write, often a full disk). Repairing it...${NC}"
            archive_redis_data
            compose run --rm --no-deps -T --entrypoint sh redis -c \
                'cd /data/appendonlydir 2>/dev/null || exit 0; fixed=0; for m in *.manifest; do [ -f "$m" ] || continue; echo y | redis-check-aof --fix "$m" >/dev/null 2>&1 && fixed=1; done; [ "$fixed" = 1 ] || for f in *.incr.aof; do [ -f "$f" ] && echo y | redis-check-aof --fix "$f" >/dev/null 2>&1; done; true' \
                >/dev/null 2>&1 || true
            compose up --no-build -d --force-recreate redis >/dev/null 2>&1 || true
            if wait_for_redis_healthy; then
                echo -e "${GREEN}Redis repaired.${NC}"
                return 0
            fi
            ;;
        *)
            # An unknown cause: a restart first, in case it was transient.
            compose up --no-build -d --force-recreate redis >/dev/null 2>&1 || true
            if wait_for_redis_healthy 60; then
                return 0
            fi
            archive_redis_data
            ;;
    esac
    # Last step: Redis starts empty. It holds queues and job state only; scans, findings and
    # evidence are in PostgreSQL. Interrupted work is reconciled by the API and workers on start.
    echo -e "${YELLOW}Starting Redis with empty state (it holds only queues and job status; your scans, findings and evidence are in PostgreSQL and untouched).${NC}"
    compose rm -sf redis >/dev/null 2>&1 || true
    docker volume rm "$(redis_volume)" >/dev/null 2>&1 || true
    compose up --no-build -d redis >/dev/null 2>&1 || true
    if wait_for_redis_healthy; then
        echo -e "${GREEN}Redis started with empty state; scans that were running when it failed are shown as interrupted and can be started again.${NC}"
        return 0
    fi
    echo -e "${RED}Redis does not start. Its last messages:${NC}" >&2
    compose logs --no-color --tail 20 redis >&2 2>/dev/null || true
    echo "Run '$(cli_hint) doctor' and share its output; do not remove the PostgreSQL volumes." >&2
    return 1
}

# For status and doctor: warnings about the conditions that break upgrades.
upgrade_safety_warnings() {
    local free need project
    project="${COMPOSE_PROJECT_NAME:-shakerscan}"
    if free="$(docker_storage_free_gb)"; then
        need=$(( $(upgrade_missing_image_gb) + UPGRADE_MARGIN_GB ))
        [ "$need" -ge 20 ] || need=20
        if [ "$free" -lt "$need" ]; then
            echo "Docker has ${free} GB free; keep at least ${need} GB free so the next upgrade can download its images."
        fi
    fi
    if [ -f "$SCRIPT_DIR/.env" ] && grep -q '^POSTGRES_PASSWORD=' "$SCRIPT_DIR/.env" 2>/dev/null \
        && [ -f "$RELEASE_STATE_CURRENT" ] \
        && ! docker volume inspect "${project}_postgres-cluster" >/dev/null 2>&1 \
        && ! docker volume inspect "${project}_postgres-data" >/dev/null 2>&1; then
        echo "ShakerScan's database volume is missing although this install has started before; restore it from a backup in $SCRIPT_DIR/backups before using it."
    fi
}
