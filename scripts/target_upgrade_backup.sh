# Sourced by the launcher. Capture the old schema before converting tables to views.

# Tables whose rows are the operator's own (never seeded by db/init.sql).
TARGET_UPGRADE_DATA_TABLES="'targets','device_targets','scans','findings','ai_targets','credential_profiles','request_collections','hunt_runs','schedules','discovery_runs'"

ensure_target_upgrade_backup() {
    local legacy_kind initialized attempt pid1_comm tables table query
    compose up --no-build -d postgres
    # On a fresh volume the image first runs a temporary server for its init scripts, then shuts
    # it down and execs the real one. That temporary server answers pg_isready too, so a dump
    # taken then fails with "the database system is shutting down". Wait until the entrypoint
    # shell has handed PID 1 to the final postgres process.
    for attempt in $(seq 1 60); do
        pid1_comm="$(compose exec -T postgres cat /proc/1/comm 2>/dev/null | tr -d '\r\n')"
        # While the image's entrypoint shell is PID 1 the server is the temporary init one, even
        # when pg_isready already answers (observed: "bash ready" twice before "postgres").
        case "$pid1_comm" in
            bash|sh|docker-entrypoi*) sleep 1; continue ;;
        esac
        if compose exec -T postgres pg_isready -U scanner -d scanner >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    legacy_kind="$(compose exec -T postgres psql -U scanner -d scanner -At -v ON_ERROR_STOP=1 \
        -c "SELECT relkind FROM pg_class WHERE oid=to_regclass('public.device_targets')")" || return 1
    [ "$legacy_kind" = r ] || return 0
    # Only data an operator could lose needs saving. A brand-new database (db/init.sql, the first
    # start, or every `reset`) has its tables and migration markers but no such row: no backup.
    tables="$(compose exec -T postgres psql -U scanner -d scanner -At -v ON_ERROR_STOP=1 \
        -c "SELECT string_agg(t, ' ') FROM unnest(ARRAY[${TARGET_UPGRADE_DATA_TABLES}]) t WHERE to_regclass('public.' || t) IS NOT NULL")" || return 1
    query="SELECT false"
    for table in $tables; do
        query="$query OR EXISTS(SELECT 1 FROM public.$table)"
    done
    initialized="$(compose exec -T postgres psql -U scanner -d scanner -At -v ON_ERROR_STOP=1 -c "$query")" || return 1
    [ "$initialized" = t ] || return 0
    echo "Saving the pre-unification database and evidence before the target upgrade."
    create_backup || return 1
    echo "Downgrade requires this backup and the previous release; compatibility views are not rollback tables."
}
