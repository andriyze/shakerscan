# shellcheck shell=bash
# PostgreSQL major-version upgrades for the ShakerScan launcher. Sourced by scanner.sh, which
# provides docker_cli, stop_services, read_dotenv_value, generate_datastore_secret and the colors.
#
# Earlier releases kept PostgreSQL 16 data in the `<project>_postgres-data` volume mounted at
# /var/lib/postgresql/data. PostgreSQL 18+ images keep each major in /var/lib/postgresql/<major>/docker
# and refuse to start on the old mount, and a newer major cannot open older data files at all. The
# stack now mounts `<project>_postgres-cluster` at /var/lib/postgresql. Before anything may start
# PostgreSQL, the launcher copies an older cluster into the target major with pg_dumpall, checks
# every table's row count, every sequence and every role, and only then publishes the new data
# directory. The upgrade only reads the source data (PostgreSQL's own startup and shutdown aside),
# and the source volume stays available for rollback. A start deletes it, with the upgrade's dump
# and any set-aside copies, once it is SHAKERSCAN_POSTGRES_LEGACY_RETENTION_DAYS old (default 30,
# 0 keeps it), announcing the date during the last week; `db-upgrade --remove-legacy` deletes it now.
# Neither deletes a directory a container still uses as its data (a recovery run on a set-aside
# copy, say), and every operation on the data holds one lock, so retention never runs mid-migration.
#
# Invariant: the target data directory <major>/docker exists only after a verified copy (the copy is
# built in <major>/migrating and renamed), or after PostgreSQL initialized an empty cluster on a host
# that had no older data. A target without a migration receipt next to older data is refused, never
# guessed at, so a cluster started too early can't hide the real data.

POSTGRES_LEGACY_VOLUME_NAME="postgres-data"
POSTGRES_CLUSTER_VOLUME_NAME="postgres-cluster"
POSTGRES_MIGRATION_RECEIPT="shakerscan-migration.txt"
POSTGRES_MIN_CLUSTER_MAJOR=18
POSTGRES_CLUSTER_CHECKED=0
POSTGRES_LEGACY_RETENTION_DEFAULT_DAYS=30
POSTGRES_LEGACY_NOTICE_DAYS=7

# Images that can read each older major's data. Every release before the cluster layout shipped 16.
postgres_source_image_for_major() {
    case "$1" in
        16) echo "postgres:16.15-alpine3.23@sha256:421b84e07a72bb8f3715f20501a1fdbe1219aad1fa4af7786a49d9a3f2480296" ;;
        *)
            if [ -n "${SHAKERSCAN_POSTGRES_SOURCE_IMAGE:-}" ]; then
                echo "$SHAKERSCAN_POSTGRES_SOURCE_IMAGE"
            else
                return 1
            fi
            ;;
    esac
}

postgres_project() {
    echo "${COMPOSE_PROJECT_NAME:-shakerscan}"
}

postgres_legacy_volume() {
    echo "$(postgres_project)_${POSTGRES_LEGACY_VOLUME_NAME}"
}

postgres_cluster_volume() {
    echo "$(postgres_project)_${POSTGRES_CLUSTER_VOLUME_NAME}"
}

postgres_volume_exists() {
    docker_cli volume inspect "$1" > /dev/null 2>&1
}

# One PostgreSQL data operation at a time: a migration, --remigrate, --keep-current, --remove-legacy
# and retention all take this lock, so retention never deletes a directory another launcher process
# is migrating from or recovering into. A directory lock (macOS has no flock) recording the holder's
# PID; a lock whose holder is gone is taken over. Re-entrant within one process.
POSTGRES_LOCK_DEPTH=0
POSTGRES_LOCK_HOLDER=""

postgres_lock_dir() {
    echo "$SCRIPT_DIR/.shakerscan-postgres.lock"
}

postgres_lock_acquire() {
    local lock holder
    if [ "$POSTGRES_LOCK_DEPTH" -gt 0 ]; then
        POSTGRES_LOCK_DEPTH=$((POSTGRES_LOCK_DEPTH + 1))
        return 0
    fi
    lock="$(postgres_lock_dir)"
    if ! mkdir "$lock" 2> /dev/null; then
        holder="$(cat "$lock/pid" 2> /dev/null || true)"
        if [ -n "$holder" ] && { kill -0 "$holder" 2> /dev/null || [ -d "/proc/$holder" ]; }; then
            POSTGRES_LOCK_HOLDER="$holder"
            return 1
        fi
        # No live holder. A lock still without a PID was taken a moment ago unless it is old.
        if [ -z "$holder" ] && [ -z "$(find "$lock" -maxdepth 0 -mmin +10 2> /dev/null)" ]; then
            POSTGRES_LOCK_HOLDER="unknown"
            return 1
        fi
        rm -rf -- "$lock"
        if ! mkdir "$lock" 2> /dev/null; then
            POSTGRES_LOCK_HOLDER="unknown"
            return 1
        fi
    fi
    echo "$$" > "$lock/pid"
    POSTGRES_LOCK_DEPTH=1
}

postgres_lock_release() {
    [ "$POSTGRES_LOCK_DEPTH" -gt 0 ] || return 0
    POSTGRES_LOCK_DEPTH=$((POSTGRES_LOCK_DEPTH - 1))
    [ "$POSTGRES_LOCK_DEPTH" -eq 0 ] && rm -rf -- "$(postgres_lock_dir)"
    return 0
}

# Run an interactive PostgreSQL data operation under the lock, or refuse while another one runs.
postgres_locked() {
    local status=0
    if ! postgres_lock_acquire; then
        echo -e "${RED}Error: another PostgreSQL data operation is running (process $POSTGRES_LOCK_HOLDER); nothing was changed. Retry when it has finished.${NC}" >&2
        return 1
    fi
    "$@" || status=$?
    postgres_lock_release
    return "$status"
}

# The containers, running or stopped, that use the cluster volume directory $1 (relative to the
# volume, such as 17 or 18/replaced-<stamp>) as their PostgreSQL data, one name per line. A
# container holds it when its PGDATA is that directory, inside it, or contains it. A container that
# mounts the volume with no PGDATA inside the mount could be using any of it, so it holds every
# directory. Fails (deletion must not proceed) when Docker cannot answer.
postgres_directory_holders() {
    local directory="$1" volume ids
    volume="$(postgres_cluster_volume)"
    ids="$(docker_cli ps -aq --filter "volume=$volume")" || return 1
    [ -n "$ids" ] || return 0
    # shellcheck disable=SC2086 # one argument per container ID
    docker_cli inspect $ids | python3 -c '
import json, posixpath, sys

volume, directory = sys.argv[1], posixpath.normpath(sys.argv[2].strip("/"))
for container in json.load(sys.stdin):
    name = (container.get("Name") or container.get("Id", "")[:12]).lstrip("/")
    env = dict(item.split("=", 1) for item in (container.get("Config") or {}).get("Env") or [] if "=" in item)
    pgdata = posixpath.normpath(env["PGDATA"]) if env.get("PGDATA") else ""
    relative = None
    for mount in container.get("Mounts") or []:
        if mount.get("Name") != volume:
            continue
        destination = posixpath.normpath(mount.get("Destination") or "/")
        if pgdata == destination:
            relative = ""
        elif pgdata.startswith(destination.rstrip("/") + "/"):
            relative = pgdata[len(destination.rstrip("/")) + 1:]
    if relative is None or relative == "" or relative == directory \
            or relative.startswith(directory + "/") or directory.startswith(relative + "/"):
        print(name)
' "$volume" "$directory"
}

# Remove directory $2 of the cluster volume unless a container holds it. When it is kept, prints the
# reason (for "... but <reason>") and fails.
postgres_remove_cluster_directory() {
    local image="$1" directory="$2" holders
    if ! holders="$(postgres_directory_holders "$directory")"; then
        echo "Docker could not report which containers use $(postgres_cluster_volume)"
        return 1
    fi
    if [ -n "$holders" ]; then
        echo "container $(printf '%s' "$holders" | paste -sd, - | sed 's/,/, /g') still uses it"
        return 1
    fi
    postgres_cluster_shell "$image" "rm -rf '/var/lib/postgresql/$directory'" > /dev/null 2>&1 || {
        echo "it could not be deleted"
        return 1
    }
}

# The image Compose will run: POSTGRES_IMAGE from the shell or .env, else the compose default.
postgres_target_image() {
    local image="${POSTGRES_IMAGE:-}" compose_file
    if [ -z "$image" ]; then
        image="$(read_dotenv_value POSTGRES_IMAGE)"
    fi
    if [ -z "$image" ]; then
        compose_file="${COMPOSE_FILE_ARGS[1]:-docker-compose.yml}"
        case "$compose_file" in
            /*) ;;
            *) compose_file="$SCRIPT_DIR/$compose_file" ;;
        esac
        image="$(sed -n 's/.*\${POSTGRES_IMAGE:-\([^}]*\)}.*/\1/p' "$compose_file" | head -n 1)"
    fi
    [ -n "$image" ] || return 1
    echo "$image"
}

postgres_image_major() {
    local version
    version="$(docker_cli run --rm --network none --entrypoint postgres "$1" --version 2>/dev/null)" || return 1
    version="$(printf '%s\n' "$version" | awk '{print $3}' | cut -d. -f1)"
    case "$version" in
        ''|*[!0-9]*) return 1 ;;
    esac
    echo "$version"
}

# Report what the data volumes hold, as key=value lines, without creating either volume.
postgres_probe_volumes() {
    local image="$1" legacy cluster
    local -a mounts=()
    legacy="$(postgres_legacy_volume)"
    cluster="$(postgres_cluster_volume)"
    if postgres_volume_exists "$legacy"; then
        mounts+=(-v "$legacy:/legacy:ro")
    fi
    if postgres_volume_exists "$cluster"; then
        mounts+=(-v "$cluster:/cluster:ro")
    fi
    if [ ${#mounts[@]} -eq 0 ]; then
        printf 'legacy_major=\ncluster_majors=\nreceipt_majors=\nreplaced_dirs=\n'
        return 0
    fi
    # Each cluster's global/pg_control is rewritten by every checkpoint, including the one at a clean
    # shutdown, so its digest changes whenever PostgreSQL has run on that data. A receipt records the
    # digest of the data it was copied from; the probe reports both so a later start can tell whether
    # an older release ran on the old data after the copy.
    docker_cli run --rm --network none "${mounts[@]}" --entrypoint sh "$image" -c '
        control() { [ -f "$1/global/pg_control" ] && sha256sum "$1/global/pg_control" | cut -d" " -f1; }
        legacy=""
        [ -f /legacy/PG_VERSION ] && legacy="$(tr -dc 0-9 < /legacy/PG_VERSION)"
        [ -n "$legacy" ] && printf "legacy_control=%s\n" "$(control /legacy)"
        majors=""; receipts=""; replaced=""
        for dir in /cluster/*/; do
            [ -d "$dir" ] || continue
            major="$(basename "$dir")"
            case "$major" in ""|*[!0-9]*) continue ;; esac
            if [ -f "$dir/docker/PG_VERSION" ]; then
                majors="$majors $major"
                printf "control_%s=%s\n" "$major" "$(control "$dir/docker")"
            fi
            for aside in "$dir"replaced-*/; do
                [ -d "$aside" ] && replaced="$replaced $major/$(basename "$aside")"
            done
            receipt="$dir/'"$POSTGRES_MIGRATION_RECEIPT"'"
            if [ -f "$receipt" ]; then
                receipts="$receipts $major"
                sed -nE "s/^(from_kind|from_major|from_volume|source_control|migrated_at|accepted_at)=/receipt_${major}_\1=/p" "$receipt"
            fi
        done
        printf "legacy_major=%s\ncluster_majors=%s\nreceipt_majors=%s\nreplaced_dirs=%s\n" \
            "$legacy" "${majors# }" "${receipts# }" "${replaced# }"
    '
}

postgres_probe_value() {
    printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -n 1
}

# Whether the data the target cluster was copied from has run since the copy. Prints one of:
#   unchanged | gone | unrecorded | diverged <legacy|cluster> <major>
# "diverged" means an older release ran on the old data after the upgrade (a rollback), so the
# copy may be missing whatever was written then; a start must not pick a side silently.
postgres_source_state() {
    local probe="$1" target="$2" kind major recorded current
    major="$(postgres_probe_value "$probe" "receipt_${target}_from_major")"
    recorded="$(postgres_probe_value "$probe" "receipt_${target}_source_control")"
    kind="$(postgres_probe_value "$probe" "receipt_${target}_from_kind")"
    if [ -z "$kind" ]; then
        case "$(postgres_probe_value "$probe" "receipt_${target}_from_volume")" in
            "$(postgres_legacy_volume)") kind="legacy" ;;
            *) kind="cluster" ;;
        esac
    fi
    if [ "$kind" = "legacy" ]; then
        [ "$(postgres_probe_value "$probe" legacy_major)" = "$major" ] && \
            current="$(postgres_probe_value "$probe" legacy_control)"
    else
        current="$(postgres_probe_value "$probe" "control_${major}")"
    fi
    if [ -z "$current" ]; then
        echo "gone"
    elif [ -z "$recorded" ]; then
        echo "unrecorded"
    elif [ "$current" = "$recorded" ]; then
        echo "unchanged"
    else
        echo "diverged $kind $major"
    fi
}

# Decide what a start must do, from the target major and what the volumes hold. Prints one of:
#   ready | fresh | migrate legacy <major> | migrate cluster <major> | conflict <major> |
#   downgrade <major> | unsupported <major>
postgres_cluster_plan() {
    local target="$1" legacy="$2" cluster_majors="$3" receipt_majors="$4"
    local major newest_older="" has_target=0 has_receipt=0

    if [ "$target" -lt "$POSTGRES_MIN_CLUSTER_MAJOR" ]; then
        echo "unsupported $target"
        return 0
    fi
    for major in $cluster_majors; do
        if [ "$major" -gt "$target" ]; then
            echo "downgrade $major"
            return 0
        fi
        if [ "$major" -eq "$target" ]; then
            has_target=1
        elif [ -z "$newest_older" ] || [ "$major" -gt "$newest_older" ]; then
            newest_older="$major"
        fi
    done
    if [ -n "$legacy" ] && [ "$legacy" -gt "$target" ]; then
        echo "downgrade $legacy"
        return 0
    fi
    for major in $receipt_majors; do
        [ "$major" -eq "$target" ] && has_receipt=1
    done

    if [ "$has_target" -eq 1 ]; then
        if [ "$has_receipt" -eq 1 ] || { [ -z "$legacy" ] && [ -z "$newest_older" ]; }; then
            echo "ready"
        else
            echo "conflict $target"
        fi
    elif [ -n "$newest_older" ]; then
        echo "migrate cluster $newest_older"
    elif [ -n "$legacy" ]; then
        echo "migrate legacy $legacy"
    else
        echo "fresh"
    fi
}

postgres_wait_ready() {
    local container="$1" pid1
    for _ in $(seq 1 90); do
        # The image's init runs a temporary socket-only server before exec'ing the real one as
        # PID 1; talking to the temporary server races the handoff.
        pid1="$(docker_cli exec "$container" cat /proc/1/comm 2>/dev/null || true)"
        if [ "$pid1" = "postgres" ] && docker_cli exec "$container" pg_isready -U scanner -d postgres > /dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo -e "${RED}PostgreSQL in $container did not become ready.${NC}" >&2
    docker_cli logs --tail 30 "$container" >&2 2>&1 || true
    return 1
}

# Row count of every table, last value of every sequence, every database and every role with a
# digest of its password hash, one line each, so source and copy compare as text once sorted.
# Fails when any query fails: a fingerprint missing a database's lines must never compare equal to
# another one missing the same lines.
postgres_cluster_fingerprint() {
    docker_cli exec -i "$1" sh -s <<'EOF'
set -e
psql -X -U scanner -d postgres -At -v ON_ERROR_STOP=1 -c "
    SELECT 'role|' || rolname || '|' || rolsuper || '|' || rolcanlogin || '|' || md5(coalesce(rolpassword, ''))
    FROM pg_authid WHERE rolname !~ '^pg_' ORDER BY 1"
databases="$(psql -X -U scanner -d postgres -At -v ON_ERROR_STOP=1 \
    -c "SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY 1")"
if [ -z "$databases" ]; then
    echo "no databases were listed" >&2
    exit 1
fi
table_sql="SELECT format('SELECT %L || count(*) FROM %I.%I', 'table|' || n.nspname || '.' || c.relname || '|', n.nspname, c.relname)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%'
ORDER BY 1 \gexec
SELECT 'sequence|' || schemaname || '.' || sequencename || '|' || coalesce(last_value::text, '') FROM pg_sequences ORDER BY 1;"
# One name per line, never split on spaces; each database's output is captured first, so a failed
# query stops the script instead of vanishing into a pipeline.
while IFS= read -r db; do
    [ -n "$db" ] || continue
    rows="$(printf '%s\n' "$table_sql" | psql -X -U scanner -d "$db" -At -v ON_ERROR_STOP=1)"
    printf 'db|%s|present\n' "$db"
    if [ -n "$rows" ]; then
        printf '%s\n' "$rows" | while IFS= read -r row; do
            printf 'db|%s|%s\n' "$db" "$row"
        done
    fi
done <<DATABASES
$databases
DATABASES
EOF
}

# The sorted fingerprint of the cluster in container $1, written to $2. Fails when the fingerprint
# does: sorting it in a pipeline would report sort's success instead.
postgres_write_fingerprint() {
    local container="$1" output="$2"
    postgres_cluster_fingerprint "$container" > "$output.unsorted" || return 1
    sort "$output.unsorted" > "$output" || return 1
    rm -f "$output.unsorted"
}

postgres_remove_upgrade_containers() {
    local project
    project="$(postgres_project)"
    docker_cli rm -f "${project}-pgupgrade-source" "${project}-pgupgrade-target" > /dev/null 2>&1 || true
}

postgres_cluster_shell() {
    local image="$1" script="$2"
    docker_cli run --rm --network none -v "$(postgres_cluster_volume):/var/lib/postgresql" \
        --entrypoint sh "$image" -c "$script"
}

postgres_upgrade_failed() {
    local backup_dir="$1" target_image="$2" target="$3" source_desc="$4" reason="$5"
    postgres_remove_upgrade_containers
    postgres_cluster_shell "$target_image" "rm -rf /var/lib/postgresql/$target/migrating /var/lib/postgresql/$target/$POSTGRES_MIGRATION_RECEIPT" \
        > /dev/null 2>&1 || true
    echo -e "${RED}PostgreSQL upgrade failed: $reason${NC}" >&2
    echo "The $source_desc is still in place and the stack was not started." >&2
    [ -z "$backup_dir" ] || echo "Details and the dump taken so far: $backup_dir" >&2
    echo "Fix the cause and run '$(cli_hint) start' again, or keep the previous ShakerScan release." >&2
    return 1
}

postgres_stop_volume_users() {
    local volume users
    for volume in "$@"; do
        postgres_volume_exists "$volume" || continue
        users="$(docker_cli ps -q --filter "volume=$volume")"
        if [ -n "$users" ]; then
            echo -e "${YELLOW}Stopping the running stack so its PostgreSQL data can be copied consistently...${NC}"
            stop_services || return 1
            users="$(docker_cli ps -q --filter "volume=$volume")"
            if [ -n "$users" ]; then
                echo -e "${RED}Containers outside this Compose project still use $volume: $users${NC}" >&2
                return 1
            fi
        fi
    done
}

postgres_ensure_cluster_volume() {
    local cluster
    cluster="$(postgres_cluster_volume)"
    postgres_volume_exists "$cluster" && return 0
    # Compose adopts a volume carrying its project and volume labels without warning, and
    # `down -v` still removes it with the rest of the project.
    docker_cli volume create \
        --label "com.docker.compose.project=$(postgres_project)" \
        --label "com.docker.compose.volume=$POSTGRES_CLUSTER_VOLUME_NAME" \
        "$cluster" > /dev/null
}

migrate_postgres_cluster() {
    local source_kind="$1" source_major="$2" target_image="$3" target="$4"
    local project source_image source_volume source_mount source_pgdata source_desc
    local backup_dir timestamp size_bytes need_kb free_kb temp_password source_control
    local src dst

    project="$(postgres_project)"
    src="${project}-pgupgrade-source"
    dst="${project}-pgupgrade-target"
    if ! source_image="$(postgres_source_image_for_major "$source_major")"; then
        echo -e "${RED}Error: no pinned image can read PostgreSQL $source_major data.${NC}" >&2
        echo "Set SHAKERSCAN_POSTGRES_SOURCE_IMAGE to a postgres:$source_major image and retry." >&2
        return 1
    fi
    if [ "$source_kind" = "legacy" ]; then
        source_volume="$(postgres_legacy_volume)"
        source_mount="/var/lib/postgresql/data"
        source_pgdata="/var/lib/postgresql/data"
    else
        source_volume="$(postgres_cluster_volume)"
        source_mount="/var/lib/postgresql"
        source_pgdata="/var/lib/postgresql/$source_major/docker"
    fi
    source_desc="PostgreSQL $source_major data in volume $source_volume"

    echo -e "${BLUE}Upgrading PostgreSQL $source_major to $target ($source_volume -> $(postgres_cluster_volume)).${NC}"
    echo "The data is copied and verified; the PostgreSQL $source_major data stays in place for rollback."

    postgres_stop_volume_users "$source_volume" "$(postgres_cluster_volume)" || return 1
    postgres_remove_upgrade_containers
    postgres_ensure_cluster_volume || return 1

    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    backup_dir="$SCRIPT_DIR/backups/postgres-${source_major}-to-${target}-${timestamp}"
    (umask 077 && mkdir -p "$backup_dir") || return 1
    chmod 700 "$backup_dir"
    printf '%s\n' "PostgreSQL upgrade did not complete; this dump is not verified." > "$backup_dir/.incomplete"

    echo "Starting PostgreSQL $source_major on the existing data..."
    if ! docker_cli run -d --name "$src" --network none -v "$source_volume:$source_mount" \
        -e PGDATA="$source_pgdata" "$source_image" > /dev/null; then
        postgres_upgrade_failed "$backup_dir" "$target_image" "$target" "$source_desc" "could not start PostgreSQL $source_major"
        return 1
    fi
    if ! postgres_wait_ready "$src"; then
        postgres_upgrade_failed "$backup_dir" "$target_image" "$target" "$source_desc" "PostgreSQL $source_major did not start on the existing data"
        return 1
    fi

    size_bytes="$(docker_cli exec "$src" psql -X -U scanner -d postgres -At -c \
        "SELECT sum(pg_database_size(datname))::bigint FROM pg_database")" || size_bytes=""
    case "$size_bytes" in ''|*[!0-9]*)
        postgres_upgrade_failed "$backup_dir" "$target_image" "$target" "$source_desc" "could not measure the database size"
        return 1 ;;
    esac
    need_kb=$((size_bytes / 1024 + 262144))
    free_kb="$(df -Pk "$backup_dir" | awk 'NR == 2 {print $4}')"
    if [ -n "$free_kb" ] && [ "$free_kb" -lt "$need_kb" ]; then
        postgres_upgrade_failed "$backup_dir" "$target_image" "$target" "$source_desc" \
            "the backup directory needs about $((need_kb / 1024)) MB free and has $((free_kb / 1024)) MB"
        return 1
    fi

    echo "Recording row counts, sequences, and roles..."
    if ! postgres_write_fingerprint "$src" "$backup_dir/source-fingerprint.txt"; then
        postgres_upgrade_failed "$backup_dir" "$target_image" "$target" "$source_desc" "could not read the source tables"
        return 1
    fi
    echo "Dumping PostgreSQL $source_major ($((size_bytes / 1048576)) MB)..."
    # gzip -1: on ShakerScan's text and JSON it compresses about as well as the default level at
    # roughly 2.5x the speed, and a single-threaded compressor is what bounds the dump.
    if ! (set -o pipefail; docker_cli exec "$src" pg_dumpall -U scanner | gzip -1 -c > "$backup_dir/pg_dumpall.sql.gz"); then
        postgres_upgrade_failed "$backup_dir" "$target_image" "$target" "$source_desc" "pg_dumpall failed"
        return 1
    fi
    if ! docker_cli stop -t 120 "$src" > /dev/null; then
        postgres_upgrade_failed "$backup_dir" "$target_image" "$target" "$source_desc" "PostgreSQL $source_major did not shut down cleanly"
        return 1
    fi
    docker_cli rm -f "$src" > /dev/null 2>&1 || true
    # The digest of the source's pg_control after its clean shutdown identifies the exact data that
    # was copied; any later run of an older release on it (a rollback) changes the digest.
    source_control="$(docker_cli run --rm --network none -v "$source_volume:/source:ro" --entrypoint sh \
        "$target_image" -c "sha256sum '/source${source_pgdata#"$source_mount"}/global/pg_control' | cut -d' ' -f1")"
    case "$source_control" in
        *[!0-9a-f]*|'')
            postgres_upgrade_failed "$backup_dir" "$target_image" "$target" "$source_desc" "could not fingerprint the source data"
            return 1 ;;
    esac

    # A leftover from an interrupted attempt is never published; start the copy from scratch.
    free_kb="$(postgres_cluster_shell "$target_image" \
        "rm -rf /var/lib/postgresql/$target/migrating /var/lib/postgresql/$target/$POSTGRES_MIGRATION_RECEIPT && df -Pk /var/lib/postgresql | awk 'NR == 2 {print \$4}'")"
    need_kb=$((size_bytes * 12 / 10 / 1024 + 262144))
    case "$free_kb" in ''|*[!0-9]*)
        postgres_upgrade_failed "$backup_dir" "$target_image" "$target" "$source_desc" "could not prepare the $(postgres_cluster_volume) volume"
        return 1 ;;
    esac
    if [ "$free_kb" -lt "$need_kb" ]; then
        postgres_upgrade_failed "$backup_dir" "$target_image" "$target" "$source_desc" \
            "Docker's disk needs about $((need_kb / 1024)) MB free for the new cluster and has $((free_kb / 1024)) MB"
        return 1
    fi

    echo "Initializing PostgreSQL $target..."
    # The bootstrap role must be `scanner`, as in the stack; the dump's ALTER ROLE then restores its
    # original password. The random password only covers the few seconds before that.
    temp_password="$(generate_datastore_secret)"
    if ! docker_cli run -d --name "$dst" --network none -v "$(postgres_cluster_volume):/var/lib/postgresql" \
        -e PGDATA="/var/lib/postgresql/$target/migrating" -e POSTGRES_USER=scanner \
        -e POSTGRES_PASSWORD="$temp_password" -e POSTGRES_DB=postgres "$target_image" > /dev/null; then
        postgres_upgrade_failed "$backup_dir" "$target_image" "$target" "$source_desc" "could not start PostgreSQL $target"
        return 1
    fi
    if ! postgres_wait_ready "$dst"; then
        postgres_upgrade_failed "$backup_dir" "$target_image" "$target" "$source_desc" "PostgreSQL $target did not initialize"
        return 1
    fi

    echo "Restoring into PostgreSQL $target..."
    # The only statement that must be skipped is the creation of the bootstrap role initdb already
    # made; everything else runs with ON_ERROR_STOP, so any incompatibility aborts the upgrade.
    if ! (set -o pipefail; gzip -dc "$backup_dir/pg_dumpall.sql.gz" | awk '$0 != "CREATE ROLE scanner;"' | \
        docker_cli exec -i "$dst" psql -X -q -U scanner -d postgres -v ON_ERROR_STOP=1 \
        > "$backup_dir/restore.log" 2>&1); then
        postgres_upgrade_failed "$backup_dir" "$target_image" "$target" "$source_desc" \
            "the restore into PostgreSQL $target stopped at an error (see restore.log)"
        return 1
    fi
    if ! docker_cli exec "$dst" vacuumdb -U scanner --all --analyze-only --quiet >> "$backup_dir/restore.log" 2>&1; then
        postgres_upgrade_failed "$backup_dir" "$target_image" "$target" "$source_desc" "ANALYZE failed after the restore"
        return 1
    fi

    echo "Verifying the copy..."
    if ! postgres_write_fingerprint "$dst" "$backup_dir/target-fingerprint.txt"; then
        postgres_upgrade_failed "$backup_dir" "$target_image" "$target" "$source_desc" "could not read the restored tables"
        return 1
    fi
    if ! diff -u "$backup_dir/source-fingerprint.txt" "$backup_dir/target-fingerprint.txt" > "$backup_dir/verify.diff"; then
        postgres_upgrade_failed "$backup_dir" "$target_image" "$target" "$source_desc" \
            "the copy does not match the source (see verify.diff)"
        return 1
    fi
    if ! docker_cli stop -t 120 "$dst" > /dev/null; then
        postgres_upgrade_failed "$backup_dir" "$target_image" "$target" "$source_desc" "PostgreSQL $target did not shut down cleanly"
        return 1
    fi
    docker_cli rm -f "$dst" > /dev/null 2>&1 || true

    printf 'from_kind=%s\nfrom_major=%s\nfrom_volume=%s\nsource_control=%s\nto_major=%s\nmigrated_at=%s\nbackup=%s\ntables_verified=%s\n' \
        "$source_kind" "$source_major" "$source_volume" "$source_control" "$target" "$timestamp" "$backup_dir" \
        "$(grep -c '|table|' "$backup_dir/source-fingerprint.txt")" > "$backup_dir/$POSTGRES_MIGRATION_RECEIPT"
    # Receipt first, then the rename that publishes the data directory: an interruption between the
    # two leaves no <major>/docker, so the next start simply repeats the copy.
    if ! docker_cli run --rm -i --network none -v "$(postgres_cluster_volume):/var/lib/postgresql" \
        --entrypoint sh "$target_image" -c "set -e
            cat > /var/lib/postgresql/$target/$POSTGRES_MIGRATION_RECEIPT
            mv /var/lib/postgresql/$target/migrating /var/lib/postgresql/$target/docker" \
        < "$backup_dir/$POSTGRES_MIGRATION_RECEIPT"; then
        postgres_upgrade_failed "$backup_dir" "$target_image" "$target" "$source_desc" "could not publish the new data directory"
        return 1
    fi
    rm -f "$backup_dir/.incomplete"
    echo -e "${GREEN}PostgreSQL upgraded to $target; $(grep -c '|table|' "$backup_dir/source-fingerprint.txt") tables verified.${NC}"
    echo "  Dump and verification: $backup_dir"
    echo "  The PostgreSQL $source_major data stays in $source_volume. After you have checked this release, reclaim it with:"
    echo "    $(cli_hint) db-upgrade --remove-legacy"
}

# Days the rollback data is kept after a verified upgrade; 0 keeps it until it is removed by hand.
postgres_legacy_retention_days() {
    local days="${SHAKERSCAN_POSTGRES_LEGACY_RETENTION_DAYS:-}"
    [ -n "$days" ] || days="$(read_dotenv_value SHAKERSCAN_POSTGRES_LEGACY_RETENTION_DAYS)"
    [ -n "$days" ] || days="$POSTGRES_LEGACY_RETENTION_DEFAULT_DAYS"
    case "$days" in
        *[!0-9]*) return 1 ;;
    esac
    echo "$((10#$days))"
}

# Whole days from a receipt timestamp such as 20261001T004718Z to now (python3 is a launcher dependency).
postgres_days_since() {
    python3 -c 'import datetime, sys
start = datetime.datetime.strptime(sys.argv[1], "%Y%m%dT%H%M%SZ").replace(tzinfo=datetime.timezone.utc)
print(int((datetime.datetime.now(datetime.timezone.utc) - start).total_seconds() // 86400))' "$1" 2>/dev/null
}

postgres_date_after() {
    python3 -c 'import datetime, sys
start = datetime.datetime.strptime(sys.argv[1], "%Y%m%dT%H%M%SZ")
print((start + datetime.timedelta(days=int(sys.argv[2]))).strftime("%Y-%m-%d"))' "$1" "$2" 2>/dev/null
}

# When the current copy last became the one to keep: a later --keep-current restarts the clock.
postgres_retention_start() {
    local probe="$1" target="$2" accepted
    accepted="$(postgres_probe_value "$probe" "receipt_${target}_accepted_at")"
    if [ -n "$accepted" ]; then
        echo "$accepted"
    else
        postgres_probe_value "$probe" "receipt_${target}_migrated_at"
    fi
}

# The rollback data a ready cluster leaves behind: the legacy volume and older major directories.
postgres_rollback_data() {
    local probe="$1" target="$2" major
    [ -n "$(postgres_probe_value "$probe" legacy_major)" ] && echo "legacy $(postgres_probe_value "$probe" legacy_major)"
    for major in $(postgres_probe_value "$probe" cluster_majors); do
        [ "$major" -lt "$target" ] && echo "cluster $major"
    done
    return 0
}

# What retention does with a ready cluster's rollback data. Prints one of:
#   none | keep | hold | wait <days left> | notice <days left> | expire
# keep: retention is 0. hold: the data cannot be shown safe to drop (it was used after the copy, or
# the copy predates source fingerprints or timestamps), so only an operator removes it. notice: the
# last POSTGRES_LEGACY_NOTICE_DAYS before expiry, when starts announce the date.
postgres_retention_plan() {
    local retention="$1" age="$2" source_state="$3" has_data="$4"
    if [ "$has_data" != "1" ]; then
        echo "none"
    elif [ "$retention" -eq 0 ]; then
        echo "keep"
    elif [ "$source_state" != "unchanged" ] || [ -z "$age" ]; then
        echo "hold"
    elif [ "$age" -ge "$retention" ]; then
        echo "expire"
    elif [ $((retention - age)) -le "$POSTGRES_LEGACY_NOTICE_DAYS" ]; then
        echo "notice $((retention - age))"
    else
        echo "wait $((retention - age))"
    fi
}

# "legacy 16" / "cluster 18" lines (from postgres_rollback_data) as one readable phrase.
postgres_describe_rollback_data() {
    local item described=""
    while read -r item; do
        case "$item" in
            legacy\ *) described="${described:+$described and }the PostgreSQL ${item#legacy } volume $(postgres_legacy_volume)" ;;
            cluster\ *) described="${described:+$described and }the PostgreSQL ${item#cluster } directory in $(postgres_cluster_volume)" ;;
        esac
    done <<EOF
$1
EOF
    printf '%s' "$described"
}

# Delete rollback data whose retention ran out. Never fails a start: anything that cannot be removed
# now (a container still holds it) is reported and retried on a later start.
postgres_expire_rollback_data() {
    local probe="$1" target="$2" image="$3" retention="$4" item major legacy reason
    legacy="$(postgres_legacy_volume)"
    while read -r item; do
        [ -n "$item" ] || continue
        major="${item#* }"
        if [ "${item%% *}" = "legacy" ]; then
            if [ -n "$(docker_cli ps -aq --filter "volume=$legacy")" ]; then
                echo -e "${YELLOW}The PostgreSQL $major rollback volume $legacy is past its $retention-day retention but a container still uses it; it is removed on a later start.${NC}"
            elif docker_cli volume rm "$legacy" > /dev/null 2>&1; then
                echo "Removed the PostgreSQL $major rollback volume $legacy ($retention days after the upgrade)."
            fi
        elif reason="$(postgres_remove_cluster_directory "$image" "$major")"; then
            echo "Removed the PostgreSQL $major rollback directory ($retention days after the upgrade)."
        else
            echo -e "${YELLOW}The PostgreSQL $major rollback directory in $(postgres_cluster_volume) is past its $retention-day retention but $reason; it is removed on a later start.${NC}"
        fi
    done <<EOF
$(postgres_rollback_data "$probe" "$target")
EOF
}

# Set-aside copies (from --remigrate) and upgrade dumps age on their own timestamps.
postgres_expire_aged_copies() {
    local probe="$1" image="$2" retention="$3" aside dump_dir age reason
    for aside in $(postgres_probe_value "$probe" replaced_dirs); do
        age="$(postgres_days_since "${aside##*/replaced-}")"
        [ -n "$age" ] && [ "$age" -ge "$retention" ] || continue
        # A recovery container may run on a set-aside copy: Docker refuses to remove a volume in use,
        # but nothing stops deleting a directory inside one.
        if reason="$(postgres_remove_cluster_directory "$image" "$aside")"; then
            echo "Removed the set-aside copy $aside ($retention days old)."
        else
            echo -e "${YELLOW}The set-aside copy $aside is past its $retention-day retention but $reason; it is removed on a later start.${NC}"
        fi
    done
    for dump_dir in "$SCRIPT_DIR"/backups/postgres-*-to-*-*; do
        [ -f "$dump_dir/pg_dumpall.sql.gz" ] || continue
        age="$(postgres_days_since "${dump_dir##*-}")"
        if [ -n "$age" ] && [ "$age" -ge "$retention" ] && rm -f "$dump_dir/pg_dumpall.sql.gz"; then
            printf 'pg_dumpall.sql.gz removed %s, %s days after the upgrade (SHAKERSCAN_POSTGRES_LEGACY_RETENTION_DAYS).\n' \
                "$(date -u +%Y-%m-%d)" "$retention" > "$dump_dir/DUMP-REMOVED.txt"
            echo "Removed the upgrade dump in ${dump_dir#"$SCRIPT_DIR"/} ($retention days old)."
        fi
    done
}

# Run on every start of a ready cluster, after the divergence check. Never fails a start.
postgres_apply_legacy_retention() {
    if ! postgres_lock_acquire; then
        echo -e "${YELLOW}Another PostgreSQL data operation is running (process $POSTGRES_LOCK_HOLDER); the rollback data is checked on a later start.${NC}"
        return 0
    fi
    postgres_expire_legacy_data "$@" || true
    postgres_lock_release
}

postgres_expire_legacy_data() {
    local probe="$1" target="$2" image="$3" retention start age state data plan
    if ! retention="$(postgres_legacy_retention_days)"; then
        echo -e "${YELLOW}SHAKERSCAN_POSTGRES_LEGACY_RETENTION_DAYS must be a whole number of days; keeping the PostgreSQL rollback data.${NC}"
        return 0
    fi
    [ "$retention" -gt 0 ] || return 0
    start="$(postgres_retention_start "$probe" "$target")"
    age=""
    [ -z "$start" ] || age="$(postgres_days_since "$start")"
    state="$(postgres_source_state "$probe" "$target")"
    data="$(postgres_rollback_data "$probe" "$target")"
    plan="$(postgres_retention_plan "$retention" "$age" "${state%% *}" "$([ -n "$data" ] && echo 1)")"
    case "$plan" in
        expire)
            postgres_expire_rollback_data "$probe" "$target" "$image" "$retention"
            ;;
        notice*)
            echo -e "${YELLOW}$(postgres_describe_rollback_data "$data"), kept for rolling back the PostgreSQL $target upgrade, is deleted automatically on $(postgres_date_after "$start" "$retention") (${plan#notice } day(s) left).${NC}"
            echo "  Keep it: set SHAKERSCAN_POSTGRES_LEGACY_RETENTION_DAYS=0 in .env. Delete it now: $(cli_hint) db-upgrade --remove-legacy"
            ;;
    esac
    postgres_expire_aged_copies "$probe" "$image" "$retention"
}

postgres_report_diverged() {
    local target="$1" state="$2" kind major source
    kind="$(printf '%s' "$state" | awk '{print $2}')"
    major="$(printf '%s' "$state" | awk '{print $3}')"
    if [ "$kind" = "legacy" ]; then
        source="volume $(postgres_legacy_volume)"
    else
        source="the PostgreSQL $major directory in $(postgres_cluster_volume)"
    fi
    echo -e "${RED}Error: the PostgreSQL $major data in $source has been used since it was copied to PostgreSQL $target.${NC}" >&2
    echo "An earlier ShakerScan release ran on it after the upgrade (a rollback), so the PostgreSQL $target" >&2
    echo "copy may be missing what was written then. Nothing was started. Choose which data to keep:" >&2
    echo "  $(cli_hint) db-upgrade --remigrate      copy the PostgreSQL $major data again; changes made on" >&2
    echo "                                          PostgreSQL $target since the first copy are set aside" >&2
    echo "  $(cli_hint) db-upgrade --keep-current   keep the PostgreSQL $target data; changes made on the" >&2
    echo "                                          PostgreSQL $major data since the copy are not carried over" >&2
}

# Called before anything that can start PostgreSQL. Idempotent and cheap once the cluster is current.
ensure_postgres_cluster_current() {
    local target_image target probe plan action detail source_state

    [ "$POSTGRES_CLUSTER_CHECKED" -eq 1 ] && return 0
    if ! target_image="$(postgres_target_image)"; then
        echo -e "${RED}Error: could not determine the PostgreSQL image.${NC}" >&2
        return 1
    fi
    if ! target="$(postgres_image_major "$target_image")"; then
        echo -e "${RED}Error: could not run $target_image to read its PostgreSQL version.${NC}" >&2
        return 1
    fi
    if ! probe="$(postgres_probe_volumes "$target_image")"; then
        echo -e "${RED}Error: could not inspect the PostgreSQL data volumes.${NC}" >&2
        return 1
    fi
    plan="$(postgres_cluster_plan "$target" "$(postgres_probe_value "$probe" legacy_major)" \
        "$(postgres_probe_value "$probe" cluster_majors)" "$(postgres_probe_value "$probe" receipt_majors)")"
    action="${plan%% *}"
    detail="${plan#* }"
    case "$action" in
        ready)
            source_state="$(postgres_source_state "$probe" "$target")"
            if [ "${source_state%% *}" = "diverged" ]; then
                postgres_report_diverged "$target" "$source_state"
                return 1
            fi
            postgres_apply_legacy_retention "$probe" "$target" "$target_image"
            ;;
        fresh)
            ;;
        migrate)
            postgres_locked migrate_postgres_cluster "${detail%% *}" "${detail#* }" "$target_image" "$target" || return 1
            ;;
        conflict)
            echo -e "${RED}Error: $(postgres_cluster_volume) already holds a PostgreSQL $target cluster that was not migrated,${NC}" >&2
            echo -e "${RED}while older PostgreSQL data still exists (volume $(postgres_legacy_volume) or an older major).${NC}" >&2
            echo "PostgreSQL $target was started before the upgrade ran, so it initialized an empty database." >&2
            echo "Your data is still in the older volume. To set the new cluster aside and migrate, run" >&2
            echo "  $(cli_hint) db-upgrade --remigrate" >&2
            return 1
            ;;
        downgrade)
            echo -e "${RED}Error: the data volumes hold PostgreSQL $detail, newer than $target_image (PostgreSQL $target).${NC}" >&2
            echo "Downgrading PostgreSQL is not supported; use a release that runs PostgreSQL $detail or newer." >&2
            return 1
            ;;
        unsupported)
            echo -e "${RED}Error: POSTGRES_IMAGE runs PostgreSQL $detail; this release requires PostgreSQL $POSTGRES_MIN_CLUSTER_MAJOR or newer.${NC}" >&2
            echo "Unset POSTGRES_IMAGE, or point it at a PostgreSQL $POSTGRES_MIN_CLUSTER_MAJOR+ image, then retry." >&2
            return 1
            ;;
        *)
            echo -e "${RED}Error: unexpected PostgreSQL upgrade plan: $plan${NC}" >&2
            return 1
            ;;
    esac
    POSTGRES_CLUSTER_CHECKED=1
}

postgres_upgrade_status() {
    local target_image target probe
    target_image="$(postgres_target_image)" || return 1
    target="$(postgres_image_major "$target_image")" || return 1
    probe="$(postgres_probe_volumes "$target_image")" || return 1
    echo "Target image:   $target_image (PostgreSQL $target)"
    echo "Legacy volume:  $(postgres_legacy_volume): $(postgres_volume_exists "$(postgres_legacy_volume)" && echo "PostgreSQL $(postgres_probe_value "$probe" legacy_major)" || echo "absent")"
    echo "Cluster volume: $(postgres_cluster_volume): majors [$(postgres_probe_value "$probe" cluster_majors)], migrated [$(postgres_probe_value "$probe" receipt_majors)]"
    echo "Plan:           $(postgres_cluster_plan "$target" "$(postgres_probe_value "$probe" legacy_major)" \
        "$(postgres_probe_value "$probe" cluster_majors)" "$(postgres_probe_value "$probe" receipt_majors)")"
    if printf ' %s ' "$(postgres_probe_value "$probe" receipt_majors)" | grep -q " $target "; then
        case "$(postgres_source_state "$probe" "$target")" in
            unchanged) echo "Source data:    unchanged since the copy (kept for rollback)" ;;
            gone) echo "Source data:    removed" ;;
            unrecorded) echo "Source data:    present; this copy predates source fingerprints" ;;
            diverged*) echo "Source data:    used since the copy (rollback); resolve with --remigrate or --keep-current" ;;
        esac
    fi
    if [ -n "$(postgres_probe_value "$probe" replaced_dirs)" ]; then
        echo "Set aside:      $(postgres_probe_value "$probe" replaced_dirs) (reclaim with db-upgrade --remove-legacy)"
    fi
    postgres_retention_status "$probe" "$target"
}

postgres_retention_status() {
    local probe="$1" target="$2" retention start age state data plan
    data="$(postgres_rollback_data "$probe" "$target")"
    [ -n "$data" ] || return 0
    if ! retention="$(postgres_legacy_retention_days)"; then
        echo "Rollback data:  kept (SHAKERSCAN_POSTGRES_LEGACY_RETENTION_DAYS is not a whole number of days)"
        return 0
    fi
    start="$(postgres_retention_start "$probe" "$target")"
    age=""
    [ -z "$start" ] || age="$(postgres_days_since "$start")"
    state="$(postgres_source_state "$probe" "$target")"
    plan="$(postgres_retention_plan "$retention" "$age" "${state%% *}" 1)"
    case "$plan" in
        keep) echo "Rollback data:  kept until removed (SHAKERSCAN_POSTGRES_LEGACY_RETENTION_DAYS=0)" ;;
        hold)
            case "$state" in
                unrecorded) echo "Rollback data:  kept until removed by hand (this copy predates source fingerprints); db-upgrade --remove-legacy deletes it" ;;
                *) echo "Rollback data:  kept until removed by hand (no upgrade timestamp); db-upgrade --remove-legacy deletes it" ;;
            esac
            ;;
        expire) echo "Rollback data:  past its $retention-day retention; the next start deletes it" ;;
        wait*|notice*) echo "Rollback data:  deleted automatically on $(postgres_date_after "$start" "$retention") (${plan#* } day(s) left; SHAKERSCAN_POSTGRES_LEGACY_RETENTION_DAYS=$retention)" ;;
    esac
}

# The older data a target cluster comes from: the receipt's record, else what a migration would use.
postgres_upgrade_source() {
    local probe="$1" target="$2" kind major newest=""
    kind="$(postgres_probe_value "$probe" "receipt_${target}_from_kind")"
    major="$(postgres_probe_value "$probe" "receipt_${target}_from_major")"
    if [ -n "$kind" ] && [ -n "$major" ]; then
        echo "$kind $major"
        return 0
    fi
    for major in $(postgres_probe_value "$probe" cluster_majors); do
        if [ "$major" -lt "$target" ] && { [ -z "$newest" ] || [ "$major" -gt "$newest" ]; }; then
            newest="$major"
        fi
    done
    if [ -n "$newest" ]; then
        echo "cluster $newest"
    elif [ -n "$(postgres_probe_value "$probe" legacy_major)" ]; then
        echo "legacy $(postgres_probe_value "$probe" legacy_major)"
    else
        return 1
    fi
}

# Interactive only: set the current cluster aside (not deleted) and copy the older data again. For a
# rollback that wrote to the old data, or a cluster PostgreSQL initialized before the upgrade ran.
remigrate_postgres_cluster() {
    postgres_locked postgres_remigrate_under_lock
}

postgres_remigrate_under_lock() {
    local target_image target probe source kind major stamp confirm
    target_image="$(postgres_target_image)" || return 1
    target="$(postgres_image_major "$target_image")" || return 1
    probe="$(postgres_probe_volumes "$target_image")" || return 1
    if ! printf ' %s ' "$(postgres_probe_value "$probe" cluster_majors)" | grep -q " $target "; then
        echo -e "${RED}Error: there is no PostgreSQL $target cluster to replace; '$(cli_hint) start' migrates on its own.${NC}" >&2
        return 1
    fi
    if ! source="$(postgres_upgrade_source "$probe" "$target")"; then
        echo -e "${RED}Error: there is no older PostgreSQL data to copy again.${NC}" >&2
        return 1
    fi
    if [ -n "$(postgres_probe_value "$probe" "receipt_${target}_from_major")" ] && \
        [ "$(postgres_source_state "$probe" "$target")" = "gone" ]; then
        echo -e "${RED}Error: the PostgreSQL data this cluster was copied from is no longer present; nothing to copy again.${NC}" >&2
        return 1
    fi
    kind="${source%% *}"
    major="${source#* }"
    echo -e "${YELLOW}This sets the current PostgreSQL $target data aside and copies the PostgreSQL $major data again.${NC}"
    echo "Anything written on PostgreSQL $target since then stays only in the set-aside copy."
    read -r -p "Type 'remigrate' to continue: " confirm || confirm=""
    if [ "$confirm" != "remigrate" ]; then
        echo "Cancelled; nothing was changed."
        return 1
    fi
    postgres_stop_volume_users "$(postgres_cluster_volume)" "$(postgres_legacy_volume)" || return 1
    postgres_remove_upgrade_containers
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    postgres_cluster_shell "$target_image" "set -e
        mv /var/lib/postgresql/$target/docker /var/lib/postgresql/$target/replaced-$stamp
        if [ -f /var/lib/postgresql/$target/$POSTGRES_MIGRATION_RECEIPT ]; then
            mv /var/lib/postgresql/$target/$POSTGRES_MIGRATION_RECEIPT /var/lib/postgresql/$target/replaced-$stamp/$POSTGRES_MIGRATION_RECEIPT
        fi" || return 1
    echo "Set the previous PostgreSQL $target data aside as $target/replaced-$stamp in $(postgres_cluster_volume)."
    migrate_postgres_cluster "$kind" "$major" "$target_image" "$target" || return 1
    POSTGRES_CLUSTER_CHECKED=1
}

# Interactive only: keep the current cluster after a rollback ran on the older data, and accept that
# what was written there since the copy is not carried over. The older data stays for rollback.
keep_current_postgres_cluster() {
    postgres_locked postgres_keep_current_under_lock
}

postgres_keep_current_under_lock() {
    local target_image target probe state kind major current confirm
    target_image="$(postgres_target_image)" || return 1
    target="$(postgres_image_major "$target_image")" || return 1
    probe="$(postgres_probe_volumes "$target_image")" || return 1
    state="$(postgres_source_state "$probe" "$target")"
    if [ "${state%% *}" != "diverged" ]; then
        echo "Nothing to resolve: the PostgreSQL $target data and its source agree ($state)."
        return 0
    fi
    kind="$(printf '%s' "$state" | awk '{print $2}')"
    major="$(printf '%s' "$state" | awk '{print $3}')"
    if [ "$kind" = "legacy" ]; then
        current="$(postgres_probe_value "$probe" legacy_control)"
    else
        current="$(postgres_probe_value "$probe" "control_${major}")"
    fi
    echo -e "${YELLOW}This keeps the PostgreSQL $target data. Changes made on the PostgreSQL $major data since the upgrade are not carried over.${NC}"
    read -r -p "Type 'keep' to continue: " confirm || confirm=""
    if [ "$confirm" != "keep" ]; then
        echo "Cancelled; nothing was changed."
        return 1
    fi
    postgres_cluster_shell "$target_image" "set -e
        receipt=/var/lib/postgresql/$target/$POSTGRES_MIGRATION_RECEIPT
        sed -i '/^source_control=/d; /^accepted_at=/d' \"\$receipt\"
        printf 'source_control=%s\naccepted_at=%s\n' '$current' '$(date -u +%Y%m%dT%H%M%SZ)' >> \"\$receipt\"" || return 1
    echo "Kept the PostgreSQL $target data. The PostgreSQL $major data stays for rollback."
}

# Interactive only: delete the data that a verified upgrade left behind for rollback.
remove_legacy_postgres_data() {
    postgres_locked postgres_remove_legacy_under_lock
}

postgres_remove_legacy_under_lock() {
    local target_image target probe plan legacy older major confirm replaced aside item holders reason
    target_image="$(postgres_target_image)" || return 1
    target="$(postgres_image_major "$target_image")" || return 1
    probe="$(postgres_probe_volumes "$target_image")" || return 1
    plan="$(postgres_cluster_plan "$target" "$(postgres_probe_value "$probe" legacy_major)" \
        "$(postgres_probe_value "$probe" cluster_majors)" "$(postgres_probe_value "$probe" receipt_majors)")"
    if [ "$plan" != "ready" ] || ! printf ' %s ' "$(postgres_probe_value "$probe" receipt_majors)" | grep -q " $target "; then
        echo -e "${RED}Error: there is no verified PostgreSQL $target upgrade to keep (plan: $plan); nothing was removed.${NC}" >&2
        return 1
    fi
    legacy="$(postgres_legacy_volume)"
    older=""
    for major in $(postgres_probe_value "$probe" cluster_majors); do
        [ "$major" -lt "$target" ] && older="$older $major"
    done
    replaced="$(postgres_probe_value "$probe" replaced_dirs)"
    if ! postgres_volume_exists "$legacy" && [ -z "$older" ] && [ -z "$replaced" ]; then
        echo "No pre-upgrade PostgreSQL data remains."
        return 0
    fi
    echo -e "${YELLOW}This permanently deletes the PostgreSQL data kept for rolling back the upgrade:${NC}"
    postgres_volume_exists "$legacy" && echo "  volume $legacy"
    for major in $older; do
        echo "  $(postgres_cluster_volume): PostgreSQL $major data directory"
    done
    for aside in $replaced; do
        echo "  $(postgres_cluster_volume): set-aside copy $aside"
    done
    echo "A previous ShakerScan release will no longer be able to start with its data."
    read -r -p "Type 'remove' to continue: " confirm || confirm=""
    if [ "$confirm" != "remove" ]; then
        echo "Cancelled; nothing was removed."
        return 1
    fi
    if postgres_volume_exists "$legacy" && [ -n "$(docker_cli ps -aq --filter "volume=$legacy")" ]; then
        echo -e "${RED}Error: a container still references $legacy; stop it and retry. Nothing was removed.${NC}" >&2
        return 1
    fi
    # Check every directory before deleting any, so a refusal leaves all of it in place.
    for item in $older $replaced; do
        if ! holders="$(postgres_directory_holders "$item")"; then
            echo -e "${RED}Error: Docker could not report which containers use $(postgres_cluster_volume); nothing was removed.${NC}" >&2
            return 1
        fi
        if [ -n "$holders" ]; then
            echo -e "${RED}Error: container $(printf '%s' "$holders" | paste -sd, - | sed 's/,/, /g') still uses $item in $(postgres_cluster_volume); stop it and retry. Nothing was removed.${NC}" >&2
            return 1
        fi
    done
    if postgres_volume_exists "$legacy"; then
        docker_cli volume rm "$legacy" > /dev/null || return 1
        echo "Removed volume $legacy"
    fi
    for major in $older; do
        reason="$(postgres_remove_cluster_directory "$target_image" "$major")" || {
            echo -e "${RED}Error: the PostgreSQL $major data directory was not removed: $reason.${NC}" >&2
            return 1
        }
        echo "Removed the PostgreSQL $major data directory"
    done
    for aside in $replaced; do
        reason="$(postgres_remove_cluster_directory "$target_image" "$aside")" || {
            echo -e "${RED}Error: the set-aside copy $aside was not removed: $reason.${NC}" >&2
            return 1
        }
        echo "Removed the set-aside copy $aside"
    done
}
