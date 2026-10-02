# Sourced by the launcher. Capture the old schema before converting tables to views.
ensure_target_upgrade_backup() {
    local legacy_kind initialized attempt
    compose up --no-build -d postgres
    for attempt in $(seq 1 60); do
        if compose exec -T postgres pg_isready -U scanner -d scanner >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    legacy_kind="$(compose exec -T postgres psql -U scanner -d scanner -At -v ON_ERROR_STOP=1 \
        -c "SELECT relkind FROM pg_class WHERE oid=to_regclass('public.device_targets')")" || return 1
    [ "$legacy_kind" = r ] || return 0
    initialized="$(compose exec -T postgres psql -U scanner -d scanner -At -v ON_ERROR_STOP=1 \
        -c "SELECT to_regclass('public.app_schema_migrations') IS NOT NULL OR EXISTS(SELECT 1 FROM targets) OR EXISTS(SELECT 1 FROM device_targets)")" || return 1
    [ "$initialized" = t ] || return 0
    echo "Saving the pre-unification database and evidence before the target upgrade."
    create_backup || return 1
    echo "Downgrade requires this backup and the previous release; compatibility views are not rollback tables."
}
