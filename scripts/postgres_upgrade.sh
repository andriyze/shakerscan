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
# and the source volume stays available for rollback until the operator removes it with
# `db-upgrade --remove-legacy`.
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
        printf 'legacy_major=\ncluster_majors=\nreceipt_majors=\n'
        return 0
    fi
    docker_cli run --rm --network none "${mounts[@]}" --entrypoint sh "$image" -c '
        legacy=""
        [ -f /legacy/PG_VERSION ] && legacy="$(tr -dc 0-9 < /legacy/PG_VERSION)"
        majors=""; receipts=""
        for dir in /cluster/*/; do
            [ -d "$dir" ] || continue
            major="$(basename "$dir")"
            case "$major" in ""|*[!0-9]*) continue ;; esac
            [ -f "$dir/docker/PG_VERSION" ] && majors="$majors $major"
            [ -f "$dir/'"$POSTGRES_MIGRATION_RECEIPT"'" ] && receipts="$receipts $major"
        done
        printf "legacy_major=%s\ncluster_majors=%s\nreceipt_majors=%s\n" "$legacy" "${majors# }" "${receipts# }"
    '
}

postgres_probe_value() {
    printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -n 1
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

# Row count of every table, last value of every sequence and every role with a digest of its
# password hash, one sorted line each, so source and copy compare as text.
postgres_cluster_fingerprint() {
    docker_cli exec -i "$1" sh -s <<'EOF'
set -e
psql -X -U scanner -d postgres -At -v ON_ERROR_STOP=1 -c "
    SELECT 'role|' || rolname || '|' || rolsuper || '|' || rolcanlogin || '|' || md5(coalesce(rolpassword, ''))
    FROM pg_authid WHERE rolname !~ '^pg_' ORDER BY 1"
for db in $(psql -X -U scanner -d postgres -At -c "SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY 1"); do
    psql -X -U scanner -d "$db" -At -v ON_ERROR_STOP=1 <<'SQL' | sed "s/^/db|$db|/"
SELECT format('SELECT %L || count(*) FROM %I.%I', 'table|' || n.nspname || '.' || c.relname || '|', n.nspname, c.relname)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%'
ORDER BY 1 \gexec
SELECT 'sequence|' || schemaname || '.' || sequencename || '|' || coalesce(last_value::text, '') FROM pg_sequences ORDER BY 1;
SQL
done
EOF
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
    local backup_dir timestamp size_bytes need_kb free_kb temp_password
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
    if ! postgres_cluster_fingerprint "$src" | sort > "$backup_dir/source-fingerprint.txt"; then
        postgres_upgrade_failed "$backup_dir" "$target_image" "$target" "$source_desc" "could not read the source tables"
        return 1
    fi
    echo "Dumping PostgreSQL $source_major ($((size_bytes / 1048576)) MB)..."
    if ! (set -o pipefail; docker_cli exec "$src" pg_dumpall -U scanner | gzip -c > "$backup_dir/pg_dumpall.sql.gz"); then
        postgres_upgrade_failed "$backup_dir" "$target_image" "$target" "$source_desc" "pg_dumpall failed"
        return 1
    fi
    docker_cli stop -t 60 "$src" > /dev/null 2>&1 || true
    docker_cli rm -f "$src" > /dev/null 2>&1 || true

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
    if ! postgres_cluster_fingerprint "$dst" | sort > "$backup_dir/target-fingerprint.txt"; then
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

    printf 'from_major=%s\nfrom_volume=%s\nto_major=%s\nmigrated_at=%s\nbackup=%s\ntables_verified=%s\n' \
        "$source_major" "$source_volume" "$target" "$timestamp" "$backup_dir" \
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

# Called before anything that can start PostgreSQL. Idempotent and cheap once the cluster is current.
ensure_postgres_cluster_current() {
    local target_image target probe plan action detail

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
        ready|fresh)
            ;;
        migrate)
            migrate_postgres_cluster "${detail%% *}" "${detail#* }" "$target_image" "$target" || return 1
            ;;
        conflict)
            echo -e "${RED}Error: $(postgres_cluster_volume) already holds a PostgreSQL $target cluster that was not migrated,${NC}" >&2
            echo -e "${RED}while older PostgreSQL data still exists (volume $(postgres_legacy_volume) or an older major).${NC}" >&2
            echo "PostgreSQL $target was started before the upgrade ran, so it initialized an empty database." >&2
            echo "Your data is still in the older volume. If nothing in the new cluster is needed, remove it with" >&2
            echo "  docker volume rm $(postgres_cluster_volume)" >&2
            echo "and run '$(cli_hint) start' again to migrate." >&2
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
}

# Interactive only: delete the data that a verified upgrade left behind for rollback.
remove_legacy_postgres_data() {
    local target_image target probe plan legacy older major confirm
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
    if ! postgres_volume_exists "$legacy" && [ -z "$older" ]; then
        echo "No pre-upgrade PostgreSQL data remains."
        return 0
    fi
    echo -e "${YELLOW}This permanently deletes the PostgreSQL data kept for rolling back the upgrade:${NC}"
    postgres_volume_exists "$legacy" && echo "  volume $legacy"
    for major in $older; do
        echo "  $(postgres_cluster_volume): PostgreSQL $major data directory"
    done
    echo "A previous ShakerScan release will no longer be able to start with its data."
    read -r -p "Type 'remove' to continue: " confirm || confirm=""
    if [ "$confirm" != "remove" ]; then
        echo "Cancelled; nothing was removed."
        return 1
    fi
    if postgres_volume_exists "$legacy"; then
        if [ -n "$(docker_cli ps -aq --filter "volume=$legacy")" ]; then
            echo -e "${RED}Error: a container still references $legacy; stop it and retry.${NC}" >&2
            return 1
        fi
        docker_cli volume rm "$legacy" > /dev/null || return 1
        echo "Removed volume $legacy"
    fi
    for major in $older; do
        postgres_cluster_shell "$target_image" "rm -rf /var/lib/postgresql/$major" || return 1
        echo "Removed the PostgreSQL $major data directory"
    done
}
