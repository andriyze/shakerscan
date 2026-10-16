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
#     The version it upgrades from is the one the running API reports; the release record only
#     when nothing runs, and a record that an older launcher's start (or a reinstall) may have left
#     out of date means a backup.
#   - ensure_redis_ready: Redis must be healthy before anything that depends on it. A damaged
#     append-only file is repaired (a copy of its data is kept first); a Redis that cannot write
#     gets room from old images. Only a damaged Redis whose data was copied may start empty: it
#     holds queues and job state, never scans, findings or evidence. A Redis that is loading,
#     cannot be inspected, or fails for an unknown reason is never reset.
# After a successful start, record_started_release remembers this release and the ones before it
# (SHAKERSCAN_KEEP_RELEASES releases in all, default 2: this one and one to roll back to); in
# prebuilt mode older ShakerScan images are then removed. Every install on this host that recorded
# releases is registered, so one install's cleanup never removes another (stopped) install's
# release or rollback images.
#
# Docker is always called through the launcher's docker_cli (sudo when the launcher needs it).
# Nothing here suggests `docker system prune --volumes`, which deletes the PostgreSQL data.

UPGRADE_MARGIN_GB="${SHAKERSCAN_UPGRADE_MARGIN_GB:-5}"
REDIS_READY_SECONDS="${SHAKERSCAN_REDIS_READY_SECONDS:-120}"
REDIS_LOADING_SECONDS="${SHAKERSCAN_REDIS_LOADING_SECONDS:-900}"
REDIS_STATE_RESET=0
RELEASE_STATE_CURRENT="${SCRIPT_DIR}/.release-images.current"
RELEASE_STATE_PREVIOUS="${SCRIPT_DIR}/.release-images.previous"
# Older kept releases (SHAKERSCAN_KEEP_RELEASES above 2): .release-images.previous.2, .3, ...
# Releases kept for rollback, this one included: at least 1 (no rollback images), default 2.
RELEASE_KEEP="${SHAKERSCAN_KEEP_RELEASES:-2}"
case "$RELEASE_KEEP" in ''|*[!0-9]*) RELEASE_KEEP=2 ;; esac
RELEASE_KEEP=$((10#$RELEASE_KEEP))
[ "$RELEASE_KEEP" -ge 1 ] || RELEASE_KEEP=1
# The installs on this host whose recorded releases every cleanup protects (one directory per line).
INSTALL_REGISTRY="${SHAKERSCAN_INSTALL_REGISTRY:-${XDG_STATE_HOME:-${HOME:-/root}/.local/state}/shakerscan/installs}"
# Images this install recorded and has since superseded (older than the previous release): the
# only images the routine cleanup after a start removes.
RELEASE_STATE_SUPERSEDED="${SCRIPT_DIR}/.release-images.superseded"
# The first pre-upgrade dump of an upgrade that has not started successfully yet (kept from rotation).
RELEASE_BACKUP_PENDING="${SCRIPT_DIR}/backups/.pre-upgrade-pending"

# The launcher defines docker_cli (sudo when needed) later in scanner.sh, which replaces this.
if ! declare -F docker_cli >/dev/null 2>&1; then
    docker_cli() { docker "$@"; }
fi
if ! declare -F release_image_refs_all >/dev/null 2>&1; then
    release_image_refs_all() { release_image_refs; }
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

# Whether an image (ref or id) belongs to one of this install's ShakerScan repositories, by any of
# its tags or digests. Third-party images (postgres, redis, caddy, ...) never do.
image_is_shakerscan() {
    local names repo
    names="$(docker_cli image inspect --format '{{range .RepoTags}}{{println .}}{{end}}{{range .RepoDigests}}{{println .}}{{end}}' \
        "$1" 2>/dev/null)" || return 1
    for repo in $(shakerscan_image_repositories); do
        printf '%s\n' "$names" | grep -qE "^${repo//./\\.}[:@]" && return 0
    done
    return 1
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
    local images version
    [ ! -f "$RELEASE_STATE_CURRENT" ] && [ ! -f "$RELEASE_STATE_PREVIOUS" ] || return 0
    images="$(project_container_image_ids | sed '/^$/d' | sort -u | while read -r id; do
        if image_is_shakerscan "$id"; then echo "$id"; fi; done)"
    [ -n "$images" ] || return 0
    version="$(running_api_version)"
    { printf '# release %s\n' "${version:-running-before-upgrade}"; printf '%s\n' "$images"; } > "$RELEASE_STATE_PREVIOUS"
}

# The version the running API reports in its environment (empty when unknown).
running_api_version() {
    local container
    container="$(docker_cli ps -q --filter "label=com.docker.compose.project=${COMPOSE_PROJECT_NAME:-shakerscan}" \
        --filter "label=com.docker.compose.service=api" 2>/dev/null | head -1)"
    [ -n "$container" ] || return 0
    docker_cli inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$container" 2>/dev/null \
        | sed -n 's/^SCANNER_VERSION=//p' | head -1 | tr -cd 'A-Za-z0-9._-'
}

# The version the API reported before this start stopped anything; empty when nothing ran or it did
# not say. Noted once per launcher run, before the first stop (restart, clean-slate start).
# With it, the ShakerScan images its containers use: the release a start replaces is kept for
# rollback by what actually ran, even when the release record says otherwise (a rollback by an
# older launcher, which keeps no record).
RELEASE_RUNNING_BEFORE_START=""
RELEASE_RUNNING_IMAGES=""
RELEASE_RUNNING_NOTED=0
note_running_release() {
    [ "$RELEASE_RUNNING_NOTED" = 1 ] && return 0
    RELEASE_RUNNING_BEFORE_START="$(running_api_version)"
    case "$RELEASE_RUNNING_BEFORE_START" in latest|dev|unknown) RELEASE_RUNNING_BEFORE_START="" ;; esac
    if [ -n "$RELEASE_RUNNING_BEFORE_START" ]; then
        RELEASE_RUNNING_IMAGES="$(project_container_image_ids | sed '/^$/d' | sort -u | while read -r id; do
            if image_is_shakerscan "$id"; then echo "$id"; fi; done)"
    fi
    RELEASE_RUNNING_NOTED=1
}

# The release record may not describe the database: since it was written, this install was started
# by a launcher that keeps no record (one older than 2.10, e.g. after a rollback) or reinstalled.
# Every launcher writes its runtime marker on a successful start (this one before the record), and
# the installer writes it too. With nothing running to ask, the two cannot be told apart.
release_record_is_stale() {
    local marker="${LOCAL_BUILD_MARKER:-$SCRIPT_DIR/.shakerscan-local-build}"
    [ -f "$marker" ] && [ -f "$RELEASE_STATE_CURRENT" ] && [ "$marker" -nt "$RELEASE_STATE_CURRENT" ]
}

# The kept-release records of an install directory (current, previous, previous.2, ...).
release_kept_files() {
    local dir="${1:-$SCRIPT_DIR}" file
    for file in "$dir/.release-images.current" "$dir/.release-images.previous" "$dir"/.release-images.previous.[0-9]*; do
        [ -f "$file" ] && printf '%s\n' "$file"
    done
    return 0
}

# Remember this install host-wide (best effort: an unwritable registry only loses the protection
# of this install's images from another install's cleanup).
register_install() {
    local dir
    dir="$(cd "$SCRIPT_DIR" 2>/dev/null && pwd -P)" || return 0
    grep -qxF "$dir" "$INSTALL_REGISTRY" 2>/dev/null && return 0
    mkdir -p "$(dirname "$INSTALL_REGISTRY")" 2>/dev/null && printf '%s\n' "$dir" >> "$INSTALL_REGISTRY" 2>/dev/null || true
}

# Every install whose records protect images: this one, the registered ones and the default curl
# install, whether running or stopped. A directory that no longer exists is skipped.
registered_install_dirs() {
    local dir
    {
        printf '%s\n' "$SCRIPT_DIR" "${SHAKERSCAN_HOME:-${HOME:-/root}/.shakerscan}"
        grep -v '^#' "$INSTALL_REGISTRY" 2>/dev/null || true
    } | sed '/^$/d' | while IFS= read -r dir; do
        [ -d "$dir" ] && (cd "$dir" 2>/dev/null && pwd -P)
    done | sort -u
}

# Image refs every install on this host keeps (its current release and its kept rollback releases).
host_kept_release_refs() {
    local dir
    registered_install_dirs | while IFS= read -r dir; do
        # shellcheck disable=SC2046
        release_state_refs $(release_kept_files "$dir")
    done
}

# Image ids that must stay: this release's, every install's recorded current and kept releases',
# and every image any container (running or stopped) uses.
protected_image_ids() {
    local ref container
    {
        for ref in $(release_image_refs_all) $(host_kept_release_refs | sort -u); do
            docker_cli image inspect --format '{{.Id}}' "$ref" 2>/dev/null || true
        done
        docker_cli ps -aq 2>/dev/null | while read -r container; do
            [ -n "$container" ] && docker_cli inspect --format '{{.Image}}' "$container" 2>/dev/null || true
        done
    } | sed '/^$/d' | sort -u
}

# Routine cleanup after a start: remove the images this install recorded and has since superseded
# (.release-images.superseded), unless protected; only ShakerScan images, never a third-party one;
# never a volume; never forced. An image still in use stays listed and is retried next time.
# Another install on this host is protected through the install registry (register_install),
# running or stopped. Limit: an install that has not started with a 2.11 or later launcher since
# (and is not the default ~/.shakerscan) is not registered yet.
# Prints how many were removed.
prune_superseded_release_images() {
    local protected ref id removed=0 keep=""
    [ -f "$RELEASE_STATE_SUPERSEDED" ] || { echo 0; return 0; }
    protected="$(protected_image_ids)"
    for ref in $(release_state_refs "$RELEASE_STATE_SUPERSEDED" | sort -u); do
        if ! id="$(docker_cli image inspect --format '{{.Id}}' "$ref" 2>&1)"; then
            # Gone already: forget it. Any other error (daemon, sudo): keep it for next time.
            printf '%s' "$id" | grep -qi "no such image" || keep="$keep$ref"$'\n'
            continue
        fi
        # Only ShakerScan's own images, never a third-party one recorded with the release.
        image_is_shakerscan "$id" || continue
        printf '%s\n' "$protected" | grep -qxF "$id" && { keep="$keep$ref"$'\n'; continue; }
        docker_cli image rm "$ref" >/dev/null 2>&1 || true
        if docker_cli image inspect "$id" >/dev/null 2>&1; then
            keep="$keep$ref"$'\n'   # in use, or only one of its names was removed: retry next time
        else
            removed=$((removed + 1))
        fi
    done
    if [ -n "$keep" ]; then
        printf '# superseded release images still present\n%s' "$keep" > "$RELEASE_STATE_SUPERSEDED"
    else
        rm -f "$RELEASE_STATE_SUPERSEDED"
    fi
    echo "$removed"
}

# Only when disk space would otherwise stop an upgrade or Redis: remove every ShakerScan release
# image on this host that is neither this release's, nor this install's recorded releases', nor
# used by any container (running or stopped). Never a volume, never another product's image, never
# forced. Without any record of a previous release nothing is removed (nothing would protect a
# rollback). Prints how many were removed.
prune_unused_release_images() {
    local protected repo id
    if [ -z "$(release_kept_files)" ]; then
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
    removed="$(prune_unused_release_images)"
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

# Append a release record's refs to the superseded list (removed by the routine cleanup unless
# something still protects them), then drop the record.
supersede_release_record() {
    [ -f "$1" ] || return 0
    release_state_refs "$1" >> "$RELEASE_STATE_SUPERSEDED"
    rm -f "$1"
}

release_record_version() {
    sed -n 's/^# release //p' "$1" 2>/dev/null | head -1
}

# This install's kept rollback records in order: previous, previous.2, previous.3, ...
kept_rollback_files() {
    local n
    [ ! -f "$RELEASE_STATE_PREVIOUS" ] || printf '%s\n' "$RELEASE_STATE_PREVIOUS"
    for n in $(ls -1A "$SCRIPT_DIR" 2>/dev/null | sed -n 's/^\.release-images\.previous\.\([0-9][0-9]*\)$/\1/p' | sort -n); do
        printf '%s\n' "$RELEASE_STATE_PREVIOUS.$n"
    done
}

# Push a release record to the front of the kept chain (previous, previous.2, ...): each kept
# record moves one place down; what falls beyond SHAKERSCAN_KEEP_RELEASES is superseded. A kept
# record of the same version as the new one is superseded (its images, when the same, stay
# protected by the new record).
push_kept_release() {
    local record="$1" version slots index file kept=() tmp
    version="$(release_record_version "$record")"
    slots=$((RELEASE_KEEP - 1))
    for file in $(kept_rollback_files); do
        if [ -n "$version" ] && [ "$(release_record_version "$file")" = "$version" ]; then
            supersede_release_record "$file"
        else
            kept+=("$file")
        fi
    done
    # Move into place from the end, through temporary names (a slot may be the next one's source).
    index=0
    for file in "$record" ${kept[@]+"${kept[@]}"}; do
        index=$((index + 1))
        tmp="$SCRIPT_DIR/.release-images.keep.$index.$$"
        if [ "$index" -le "$slots" ]; then
            cp "$file" "$tmp"
        else
            release_state_refs "$file" >> "$RELEASE_STATE_SUPERSEDED"
        fi
    done
    for file in ${kept[@]+"${kept[@]}"}; do rm -f "$file"; done
    index=0
    while [ "$index" -lt "$slots" ]; do
        index=$((index + 1))
        tmp="$SCRIPT_DIR/.release-images.keep.$index.$$"
        [ -f "$tmp" ] || break
        if [ "$index" -eq 1 ]; then
            mv "$tmp" "$RELEASE_STATE_PREVIOUS"
        else
            mv "$tmp" "$RELEASE_STATE_PREVIOUS.$index"
        fi
    done
}

# After a successful start: this release becomes current and the one it replaced is kept for
# rollback (SHAKERSCAN_KEEP_RELEASES in all). In prebuilt mode ("prune") older ShakerScan images
# are then removed.
record_started_release() {
    local current tmp removed prune="${1:-prune}" running_record
    # This release started: its pre-upgrade dump no longer needs protecting from rotation.
    rm -f "$RELEASE_BACKUP_PENDING"
    register_install
    current="$(release_image_refs_all | sort)"
    # A new version moves the current release down the kept chain. The same version with other
    # image names (an optional module recorded, the lock on or off) only rewrites current: the
    # kept releases stay.
    if [ -f "$RELEASE_STATE_CURRENT" ] && [ "$(started_release_version)" != "${SCANNER_VERSION:-unknown}" ]; then
        tmp="$RELEASE_STATE_CURRENT.old.$$"
        cp "$RELEASE_STATE_CURRENT" "$tmp"
        push_kept_release "$tmp"
        rm -f "$tmp"
    fi
    # The release that ran before this start is the one to roll back to, whatever the record says:
    # after a rollback by a launcher that keeps no record, the record still names the newer
    # release while the older one's images were running.
    if [ -n "$RELEASE_RUNNING_BEFORE_START" ] && [ -n "$RELEASE_RUNNING_IMAGES" ] \
        && [ "$RELEASE_RUNNING_BEFORE_START" != "${SCANNER_VERSION:-unknown}" ] \
        && [ "$(release_record_version "$RELEASE_STATE_PREVIOUS")" != "$RELEASE_RUNNING_BEFORE_START" ]; then
        running_record="$SCRIPT_DIR/.release-images.running.$$"
        { printf '# release %s\n' "$RELEASE_RUNNING_BEFORE_START"; printf '%s\n' "$RELEASE_RUNNING_IMAGES"; } > "$running_record"
        push_kept_release "$running_record"
        rm -f "$running_record"
    fi
    # A lowered SHAKERSCAN_KEEP_RELEASES releases the records beyond it.
    for tmp in $(kept_rollback_files); do
        case "$tmp" in
            "$RELEASE_STATE_PREVIOUS") [ "$RELEASE_KEEP" -ge 2 ] || supersede_release_record "$tmp" ;;
            *) [ "${tmp##*.}" -lt "$RELEASE_KEEP" ] || supersede_release_record "$tmp" ;;
        esac
    done
    tmp="$RELEASE_STATE_CURRENT.tmp.$$"
    { printf '# release %s\n' "${SCANNER_VERSION:-unknown}"; printf '%s\n' "$current"; } > "$tmp"
    mv "$tmp" "$RELEASE_STATE_CURRENT"
    if [ "$prune" = prune ] && is_truthy "${SHAKERSCAN_PRUNE_OLD_IMAGES:-1}"; then
        removed="$(prune_superseded_release_images)"
        if [ "${removed:-0}" -gt 0 ]; then
            echo "Removed ${removed} image(s) of older ShakerScan releases (kept for rollback: $((RELEASE_KEEP - 1)) earlier release(s); SHAKERSCAN_KEEP_RELEASES=${RELEASE_KEEP})."
        fi
    fi
}

# Before a version-changing start against an existing database: dump PostgreSQL to
# backups/pre-upgrade-<time>-<from>-to-<to>/ (the newest two are kept). Needs PostgreSQL up.
# The version this start upgrades from, or nothing when it is no upgrade (a restart of the same
# release, or a first start).
pending_upgrade_from() {
    local from
    note_running_release
    if [ -f "$RELEASE_STATE_CURRENT" ]; then
        # The running API is the truth; the record only when nothing ran to ask. A record that may
        # be out of date is not trusted: the database is saved, named for the recorded version.
        if [ -n "$RELEASE_RUNNING_BEFORE_START" ]; then
            from="$RELEASE_RUNNING_BEFORE_START"
        elif release_record_is_stale; then
            from="unverified-$(started_release_version | tr -cd 'A-Za-z0-9._-')"
        else
            from="$(started_release_version)"
        fi
    elif [ -f "$RELEASE_STATE_PREVIOUS" ]; then
        # the first upgrade with this launcher: the running release was recorded from its containers
        from="$(sed -n 's/^# release //p' "$RELEASE_STATE_PREVIOUS" 2>/dev/null | head -1 | tr -cd 'A-Za-z0-9._-')"
        case "$from" in ''|running-before-upgrade|latest|dev|"${SCANNER_VERSION:-}") from="earlier" ;; esac
    elif [ -n "$RELEASE_RUNNING_BEFORE_START" ]; then
        # No record, but a release runs (a local build, or a release whose images were not
        # recognised): it is what this start upgrades from.
        from="$RELEASE_RUNNING_BEFORE_START"
    else
        return 0        # no release ever recorded and none running: a first start, not an upgrade
    fi
    [ -n "$from" ] && [ -n "${SCANNER_VERSION:-}" ] && [ "$from" != "${SCANNER_VERSION:-}" ] || return 0
    printf '%s\n' "$from"
}

ensure_pre_upgrade_backup() {
    local from to has_data size_kb free_kb dir stamp old pending
    is_truthy "${SHAKERSCAN_PRE_UPGRADE_BACKUP:-1}" || return 0
    to="${SCANNER_VERSION:-}"
    note_running_release    # here, not in the subshell below, so it is noted once for the run
    from="$(pending_upgrade_from)"
    [ -n "$from" ] || return 0
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
    case "$from" in
        unverified-*) echo "Saving the database before starting ${to}: the release it last ran is not known for certain (recorded: ${from#unverified-})..." ;;
        *) echo "Saving the database before upgrading ${from} to ${to}..." ;;
    esac
    if ! compose exec -T postgres pg_dump -U scanner -d scanner -Fc > "$dir/postgres.dump"; then
        echo -e "${RED}The pre-upgrade database backup failed; nothing was changed.${NC}" >&2
        rm -rf -- "$dir"
        return 1
    fi
    [ ! -f "$SCRIPT_DIR/.env" ] || grep -vE '(^|[^A-Za-z0-9_])AI_CREDENTIAL_ENC_KEY[[:space:]]*[=:]' \
        "$SCRIPT_DIR/.env" > "$dir/runtime.env" || true
    printf 'created_at=%s\nfrom_release=%s\nto_release=%s\nkind=pre-upgrade\n' "$stamp" "$from" "$to" > "$dir/manifest.txt"
    echo "Database saved: $dir"
    # Until a start succeeds, the first dump of this upgrade is the only one taken before any
    # migration ran: later attempts (after one that failed mid-migration) must not rotate it out.
    pending="$(cat "$RELEASE_BACKUP_PENDING" 2>/dev/null || true)"
    if [ -z "$pending" ] || [ ! -d "$SCRIPT_DIR/backups/$pending" ]; then
        pending="$(basename "$dir")"
        printf '%s\n' "$pending" > "$RELEASE_BACKUP_PENDING"
    fi
    # Names start with the time: the newest two are kept, never the one just made, and never the
    # pending upgrade's first one.
    for old in $(ls -1d "$SCRIPT_DIR"/backups/pre-upgrade-* 2>/dev/null | sort -r | tail -n +3); do
        [ "$old" = "$dir" ] || [ "$(basename "$old")" = "$pending" ] || rm -rf -- "$old"
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

# The Redis container's own state (running, restarting, exited, ...), not its healthcheck.
# The project's Redis service container (never a one-off `compose run` container).
redis_service_container() {
    docker_cli ps -aq --filter "label=com.docker.compose.project=${COMPOSE_PROJECT_NAME:-shakerscan}" \
        --filter "label=com.docker.compose.service=redis" --filter "label=com.docker.compose.oneoff=False" \
        2>/dev/null | head -1
}

redis_container_state() {
    local container
    container="$(redis_service_container)"
    [ -n "$container" ] || { echo missing; return; }
    docker_cli inspect --format '{{.State.Status}}' "$container" 2>/dev/null || echo unknown
}

redis_restart_count() {
    local container
    container="$(redis_service_container)"
    [ -n "$container" ] || { echo 0; return; }
    docker_cli inspect --format '{{.RestartCount}}' "$container" 2>/dev/null || echo 0
}

# Still loading its data: running (not crash-looping) with a loading message in its latest output.
# A Redis that fails on a damaged file prints the same "Loading ..." lines on every restart.
redis_is_loading() {
    [ "$(redis_container_state)" = running ] || return 1
    compose logs --no-color --tail 40 redis 2>/dev/null | grep -qiE "Loading|AOF loading"
}

# Healthy within `seconds`; a Redis still loading its data gets up to REDIS_LOADING_SECONDS (wall
# clock). Stops waiting at once when Redis reports a known failure (damaged file, no space) or
# keeps restarting, so the repair is not delayed.
wait_for_redis_healthy() {
    local seconds="${1:-$REDIS_READY_SECONDS}" start since state restarts
    start=$(date +%s)
    since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"  # only what Redis says from now on (not before a repair)
    restarts="$(redis_restart_count)"
    while :; do
        state="$(redis_health)"
        [ "$state" = healthy ] && return 0
        [ "$state" = unknown ] && return 1
        redis_failed_fatally "$since" && return 1
        [ "$(redis_restart_count)" -le $((restarts + 1)) ] || return 1
        if [ $(( $(date +%s) - start )) -ge "$seconds" ]; then
            if { [ "$state" = starting ] || redis_is_loading; } \
                && [ $(( $(date +%s) - start )) -lt "$REDIS_LOADING_SECONDS" ]; then
                :
            else
                return 1
            fi
        fi
        sleep 2
    done
}

redis_volume() {
    echo "${COMPOSE_PROJECT_NAME:-shakerscan}_redis-data"
}

# Redis printed a fatal error since `since` (it stops, then restarts). Redis's non-fatal notice that
# it truncated an append-only file and "loaded anyway" (aof-load-truncated) is not one.
redis_failed_fatally() {
    compose logs --no-color --since "$1" redis 2>/dev/null | grep -v "loaded anyway" | grep -qiE \
        "Bad file format reading the append only file|Unrecoverable error reading the append only file|Short read or OOM loading DB|No space left on device|MISCONF|Can't open the append-only file|Read-only file system"
}

# Redis's own reason for not becoming healthy: damaged, no_space, or unknown.
redis_failure_kind() {
    local logs since="${1:-}"
    if [ -n "$since" ]; then
        logs="$(compose logs --no-color --since "$since" redis 2>/dev/null || true)"
    else
        logs="$(compose logs --no-color --tail 120 redis 2>/dev/null || true)"
    fi
    logs="$(printf '%s\n' "$logs" | grep -v "loaded anyway")"
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

# Recreate Redis's volume and start it empty (its data was copied, or is gone). Running services
# keep their old queue state: REDIS_STATE_RESET tells the caller to restart them.
start_redis_empty() {
    compose rm -sf redis >/dev/null 2>&1 || true
    docker_cli volume rm "$(redis_volume)" >/dev/null 2>&1 || true
    REDIS_STATE_RESET=1
    compose up --no-build -d redis >/dev/null 2>&1 || true
    if wait_for_redis_healthy; then
        echo -e "${GREEN}Redis started with empty state. Scans that were waiting to start are queued again automatically within about 10 minutes; a scan that was already running is marked with an unknown outcome and can be started again from the Scans page.${NC}"
        return 0
    fi
    redis_give_up "Redis does not start even with empty state."
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
            echo "Removed $(prune_unused_release_images) older ShakerScan image(s); $(docker_storage_free_gb 2>/dev/null || echo '?') GB free now."
            compose up --no-build -d --force-recreate redis >/dev/null 2>&1 || true
            wait_for_redis_healthy && return 0
            redis_give_up "Redis still cannot write to disk. Free disk space on this host, then run '$(cli_hint) start' again."
            return 1
            ;;
        damaged)
            echo -e "${YELLOW}Redis's saved state is damaged (an interrupted write, often a full disk). Repairing it...${NC}"
            if ! archive_redis_data; then
                echo "Making room to keep a copy first..."
                prune_unused_release_images >/dev/null
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
            start_redis_empty
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
        && ! docker_cli volume inspect "${project}_postgres-cluster" >/dev/null 2>&1; then
        echo "ShakerScan's database volume is missing although this install has started before; restore it from a backup in $SCRIPT_DIR/backups before using it."
    fi
    if [ -f "$RELEASE_STATE_CURRENT" ] && docker_cli volume ls -q >/dev/null 2>&1 \
        && ! docker_cli volume inspect "$(redis_volume)" >/dev/null 2>&1; then
        echo "Redis's volume is missing (it holds queues and job state only); the next start creates it empty and waiting scans are queued again automatically."
    fi
    if free="$(install_dir_free_gb)" && [ "$free" -lt "$INSTALL_DIR_MIN_FREE_GB" ]; then
        echo "The install directory $SCRIPT_DIR has ${free} GB free; backups and scan results are written there (keep at least ${INSTALL_DIR_MIN_FREE_GB} GB free)."
    fi
}

# --- install directory space -------------------------------------------------------------------

INSTALL_DIR_MIN_FREE_GB="${SHAKERSCAN_INSTALL_DIR_MIN_FREE_GB:-2}"
case "$INSTALL_DIR_MIN_FREE_GB" in ''|*[!0-9]*) INSTALL_DIR_MIN_FREE_GB=2 ;; esac

install_dir_free_gb() {
    local free_kb
    free_kb="$(df -Pk "$SCRIPT_DIR" 2>/dev/null | awk 'END {print $4}')"
    case "$free_kb" in ''|*[!0-9]*) return 1 ;; esac
    echo $((free_kb / 1024 / 1024))
}

# The install directory holds backups, scan results and the release records. An upgrade with too
# little room there stops before anything changes; any other start only warns.
ensure_install_dir_space() {
    local free
    free="$(install_dir_free_gb)" || return 0
    [ "$free" -lt "$INSTALL_DIR_MIN_FREE_GB" ] || return 0
    note_running_release
    if [ -n "$(pending_upgrade_from)" ]; then
        echo -e "${RED}Not enough disk space in the install directory $SCRIPT_DIR: ${free} GB free, at least ${INSTALL_DIR_MIN_FREE_GB} GB needed before an upgrade (the database is saved there first).${NC}" >&2
        if stack_is_running; then
            echo "Nothing was changed: the running release keeps running." >&2
        else
            echo "Nothing was changed." >&2
        fi
        echo "Free disk space there (old files in $SCRIPT_DIR/backups: '$(cli_hint) backup list'), then run '$(cli_hint) start' again." >&2
        return 1
    fi
    echo -e "${YELLOW}The install directory $SCRIPT_DIR has ${free} GB free; backups and scan results are written there. Free disk space soon.${NC}"
}

# --- datastores persisting before the switch -----------------------------------------------------

# The project's service container (never a one-off `compose run` one).
service_container() {
    docker_cli ps -aq --filter "label=com.docker.compose.project=${COMPOSE_PROJECT_NAME:-shakerscan}" \
        --filter "label=com.docker.compose.service=$1" --filter "label=com.docker.compose.oneoff=False" \
        2>/dev/null | head -1
}

# Whether a service's data directory is a Docker volume (not the container's own writable layer,
# which is lost when the container is recreated).
service_data_on_volume() {
    local container
    container="$(service_container "$1")"
    [ -n "$container" ] || return 1
    docker_cli inspect --format '{{range .Mounts}}{{.Type}} {{.Destination}}{{println}}{{end}}' "$container" 2>/dev/null \
        | grep -qxF "volume $2"
}

# Problems that would lose data when the running release is replaced, one per line; nothing when
# none. Only for a running stack: a stopped one has nothing in memory to lose.
datastore_persistence_problems() {
    local info
    if [ -n "$(service_container postgres)" ]; then
        service_data_on_volume postgres /var/lib/postgresql \
            || echo "PostgreSQL's data is not on its Docker volume (${COMPOSE_PROJECT_NAME:-shakerscan}_postgres-cluster)."
    fi
    if [ "$(redis_container_state)" = running ]; then
        service_data_on_volume redis /data \
            || echo "Redis's data is not on its Docker volume ($(redis_volume))."
        if ! info="$(compose exec -T redis sh -c 'REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli INFO persistence' 2>/dev/null | tr -d '\r')"; then
            echo "Redis cannot be asked whether it saves its data."
        else
            printf '%s\n' "$info" | grep -q '^loading:1' && echo "Redis is still loading its data."
            printf '%s\n' "$info" | grep -q '^rdb_last_bgsave_status:err' \
                && echo "Redis's last snapshot failed (often a full disk)."
            printf '%s\n' "$info" | grep -q '^aof_last_write_status:err' \
                && echo "Redis cannot write its append-only file (often a full disk)."
        fi
    fi
    return 0
}

# Before an upgrade replaces a running release: PostgreSQL and Redis must be persisting, or
# queued work and job state would be lost with the old containers. Nothing changed on refusal.
ensure_datastores_persisting() {
    local problems
    stack_is_running || return 0
    note_running_release
    [ -n "$(pending_upgrade_from)" ] || return 0
    problems="$(datastore_persistence_problems)"
    [ -n "$problems" ] || return 0
    echo -e "${RED}The running release cannot be replaced safely:${NC}" >&2
    printf '%s\n' "$problems" | sed 's/^/  /' >&2
    echo "Nothing was changed: the running release keeps running. Run '$(cli_hint) doctor' and fix this first" >&2
    echo "(free disk space for a failed save). Do not remove Docker volumes: they hold ShakerScan's database." >&2
    return 1
}

# A start must never create an empty database over a lost one: with a release recorded and no
# database volume, it stops (a `reset` empties the database on purpose and says so).
ensure_database_volume_present() {
    local project="${COMPOSE_PROJECT_NAME:-shakerscan}"
    is_truthy "${SHAKERSCAN_ALLOW_NEW_DATABASE:-0}" && return 0
    [ -f "$RELEASE_STATE_CURRENT" ] || return 0
    docker_cli volume ls -q >/dev/null 2>&1 || return 0   # Docker cannot say: never guess "missing"
    docker_cli volume inspect "${project}_postgres-cluster" >/dev/null 2>&1 && return 0
    echo -e "${RED}ShakerScan's database volume (${project}_postgres-cluster) is missing although this install has started before.${NC}" >&2
    echo "Starting now would create an empty database. Nothing was changed." >&2
    echo "Restore the database from a backup in $SCRIPT_DIR/backups ('$(cli_hint) backup list'), or, to start with" >&2
    echo "an empty database on purpose, run 'SHAKERSCAN_ALLOW_NEW_DATABASE=1 $(cli_hint) start'." >&2
    return 1
}

# --- a full backup offered before an upgrade ----------------------------------------------------

# Before a version-changing start against an existing database: offer a complete `backup` (the
# database, scan results and configuration, in $SCRIPT_DIR/backups, outside Docker). In a terminal
# the operator is asked (default yes); otherwise SHAKERSCAN_UPGRADE_BACKUP decides: "full", or
# "database" (default: the automatic pre-upgrade database dump only). Returns 0 with
# UPGRADE_FULL_BACKUP_TAKEN=1 when one was taken. Needs PostgreSQL up.
UPGRADE_FULL_BACKUP_TAKEN=0
offer_upgrade_backup() {
    local from choice="${SHAKERSCAN_UPGRADE_BACKUP:-}" answer
    is_truthy "${SHAKERSCAN_PRE_UPGRADE_BACKUP:-1}" || return 0
    note_running_release
    from="$(pending_upgrade_from)"
    [ -n "$from" ] || return 0
    declare -F create_backup >/dev/null 2>&1 || return 0
    if [ -z "$choice" ]; then
        if [ -t 0 ] && [ -t 1 ] && [ "${ASSUME_YES:-0}" != 1 ]; then
            echo "Upgrading ${from} to ${SCANNER_VERSION:-}."
            if read -r -p "Take a full backup first (database, scan results, configuration; kept in $SCRIPT_DIR/backups)? [Y/n] " answer; then
                case "$answer" in [nN]*) choice=database ;; *) choice=full ;; esac
            else
                choice=database
            fi
        else
            choice=database
        fi
    fi
    [ "$choice" = full ] || return 0
    echo "Taking a full backup before upgrading ${from} to ${SCANNER_VERSION:-}..."
    if ! create_backup; then
        echo -e "${RED}The backup before the upgrade failed; nothing was upgraded.${NC}" >&2
        return 1
    fi
    UPGRADE_FULL_BACKUP_TAKEN=1
}

# --- images ------------------------------------------------------------------------------------

# `images`: every ShakerScan image on this host and why it stays; `images prune`: remove the ones
# nothing keeps (never this release's, any install's current or kept rollback release, an image a
# container uses, a third-party image or a volume).
images_cmd() {
    case "${1:-list}" in
        list|"") list_shakerscan_images ;;
        prune) prune_shakerscan_images ;;
        *) echo "Usage: $(cli_hint) images [prune]" >&2; return 1 ;;
    esac
}

# "<id> <reason>" for every protected image id, first reason wins.
image_keep_reasons() {
    local ref dir file version container id
    for ref in $(release_image_refs_all); do
        id="$(docker_cli image inspect --format '{{.Id}}' "$ref" 2>/dev/null)" && echo "$id this-release"
    done
    while IFS= read -r dir; do
        for file in $(release_kept_files "$dir"); do
            version="$(release_record_version "$file")"
            case "$file" in
                */.release-images.current) version="release ${version:-?} (current)" ;;
                *) version="release ${version:-?} (kept for rollback)" ;;
            esac
            [ "$dir" = "$(cd "$SCRIPT_DIR" && pwd -P)" ] || version="$version of $dir"
            for ref in $(release_state_refs "$file"); do
                id="$(docker_cli image inspect --format '{{.Id}}' "$ref" 2>/dev/null)" && echo "$id ${version// /_}"
            done
        done
    done < <(registered_install_dirs)
    docker_cli ps -aq 2>/dev/null | while read -r container; do
        [ -n "$container" ] || continue
        id="$(docker_cli inspect --format '{{.Image}}' "$container" 2>/dev/null)" && echo "$id used-by-a-container"
    done
}

list_shakerscan_images() {
    local reasons repo id ref size reason
    reasons="$(image_keep_reasons)"
    printf '%-40s %-14s %-9s %s\n' "IMAGE" "ID" "SIZE" "STATUS"
    for repo in $(shakerscan_image_repositories); do
        docker_cli images --no-trunc --format '{{.ID}} {{.Repository}}:{{.Tag}} {{.Size}}' "$repo" 2>/dev/null \
            | sort -u -k1,1 | while read -r id ref size; do
                [ -n "$id" ] || continue
                reason="$(printf '%s\n' "$reasons" | awk -v id="$id" '$1 == id {print $2; exit}')"
                printf '%-40s %-14s %-9s %s\n' "${ref:0:40}" "$(echo "${id#sha256:}" | cut -c1-12)" "$size" \
                    "$( [ -n "$reason" ] && echo "kept: ${reason//_/ }" || echo "removable ('$(cli_hint) images prune')")"
            done
    done
    echo ""
    echo "Kept for rollback: $((RELEASE_KEEP - 1)) earlier release(s) (SHAKERSCAN_KEEP_RELEASES=${RELEASE_KEEP})."
    echo "Volumes (the database, Redis) are never removed by '$(cli_hint) images prune'."
}

prune_shakerscan_images() {
    local before after removed
    if [ -z "$(release_kept_files)" ]; then
        echo "This install has no release record yet, so nothing marks the images to keep for rollback; nothing was removed."
        echo "Start ShakerScan once with this launcher ('$(cli_hint) start'), then run '$(cli_hint) images prune' again."
        return 0
    fi
    before="$(docker_storage_free_gb 2>/dev/null || echo '?')"
    removed="$(prune_unused_release_images)"
    # What the routine cleanup still had listed is gone (or protected) now.
    [ ! -f "$RELEASE_STATE_SUPERSEDED" ] || prune_superseded_release_images >/dev/null
    after="$(docker_storage_free_gb 2>/dev/null || echo '?')"
    echo "Removed ${removed} ShakerScan image(s) that nothing keeps; Docker has ${after} GB free (was ${before} GB)."
    echo "Kept: this release, every install's current release and $((RELEASE_KEEP - 1)) earlier release(s) for rollback, and images containers use."
}

# --- Redis lost ------------------------------------------------------------------------------

# `redis status`: health, persistence and volume. `redis reset`: when Redis's data is lost or
# Redis cannot start: keep a copy of what is there (when it can be read), recreate the volume,
# start it empty and reconnect the services; waiting scans are queued again automatically.
redis_cmd() {
    case "${1:-status}" in
        status|"") redis_status ;;
        reset) redis_reset "${2:-}" ;;
        *) echo "Usage: $(cli_hint) redis [status|reset [--yes]]" >&2; return 1 ;;
    esac
}

redis_status() {
    local problems
    echo "Redis: $(redis_health) (container $(redis_container_state))"
    if docker_cli volume inspect "$(redis_volume)" >/dev/null 2>&1; then
        echo "Volume: $(redis_volume) present"
    else
        echo "Volume: $(redis_volume) MISSING (the next start creates it empty)"
    fi
    problems="$(datastore_persistence_problems | grep -i redis || true)"
    if [ -n "$problems" ]; then
        printf 'Problem: %s\n' "$problems"
    elif [ "$(redis_container_state)" = running ]; then
        echo "Persistence: saving normally"
    fi
    echo "Redis holds queues and job state only; scans, findings and evidence are in PostgreSQL."
}

redis_reset() {
    local confirm="$1" answer
    echo "This recreates Redis empty: queued work and job state are cleared (a copy is kept when it can be read)."
    echo "Scans, findings and evidence are in PostgreSQL and are not touched. Scans that were waiting are"
    echo "queued again automatically; a scan that was running is marked with an unknown outcome."
    if [ "$confirm" != "--yes" ] && [ "${ASSUME_YES:-0}" != 1 ]; then
        if ! read -r -p "Reset Redis now? (yes/no): " answer || [ "$answer" != yes ]; then
            echo "Cancelled"
            return 1
        fi
    fi
    if docker_cli volume inspect "$(redis_volume)" >/dev/null 2>&1; then
        archive_redis_data || echo -e "${YELLOW}Redis's data could not be copied (unreadable or no room); resetting without a copy.${NC}"
    fi
    start_redis_empty || return 1
    if [ -n "$(service_container api)" ]; then
        echo "Reconnecting the API and workers to Redis..."
        compose restart api worker agent-tool-worker >/dev/null 2>&1 || true
    fi
    REDIS_STATE_RESET=0
    echo -e "${GREEN}Redis was reset.${NC} Check with '$(cli_hint) status'."
}
