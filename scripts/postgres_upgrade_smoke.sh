#!/usr/bin/env bash
# Exercise the launcher's PostgreSQL major upgrade (scripts/postgres_upgrade.sh) against the real
# images, in throwaway Compose projects that share nothing with a running stack:
#   1. 16 data in the legacy volume -> `scanner.sh db-upgrade` -> verified 18 cluster, credentials
#      and every row intact, with the source fingerprint in the receipt;
#   2. a second run is a no-op;
#   2b. a rollback that writes on 16 after the copy is refused rather than silently ignored, and is
#      resolved by --keep-current or --remigrate (the latter carrying the rollback's rows over);
#      --remove-legacy then reclaims the 16 volume and the set-aside copy;
#   3. an 18 cluster started before the upgrade (no receipt) beside 16 data is refused, and
#      --remigrate sets it aside and migrates;
#   4. a restore error (an extension 18 no longer ships) publishes nothing, and a retry after fixing
#      the source succeeds;
#   5. a host without data creates no volumes;
#   6. a POSTGRES_IMAGE override older than 18 is refused;
#   7. the rollback data expires after SHAKERSCAN_POSTGRES_LEGACY_RETENTION_DAYS (default 30): starts
#      announce the date in the last week, 0 keeps it, and expiry removes the 16 volume and the
#      upgrade dump while the 18 data stays intact.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="$$"
PREFIX="sspgsmoke${RUN_ID}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/postgres-upgrade-smoke.XXXXXX")"
PASSWORD="smoke-$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
SIGNER_PASSWORD="signer-$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"

# shellcheck source=scripts/postgres_upgrade.sh
source "$ROOT/scripts/postgres_upgrade.sh"
LEGACY_IMAGE="$(postgres_source_image_for_major 16)"
TARGET_IMAGE="$(sed -n 's/.*\${POSTGRES_IMAGE:-\([^}]*\)}.*/\1/p' "$ROOT/docker-compose.release.yml" | head -n 1)"

cleanup() {
    local ids
    ids="$(docker ps -aq --filter "name=${PREFIX}")"
    [ -z "$ids" ] || docker rm -f $ids > /dev/null 2>&1 || true
    ids="$(docker volume ls -q --filter "name=${PREFIX}")"
    [ -z "$ids" ] || docker volume rm -f $ids > /dev/null 2>&1 || true
    rm -rf -- "$WORK"
}
trap cleanup EXIT INT TERM

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

show() {
    printf '%s\n' "$1" | sed 's/\x1b\[[0-9;]*m//g; s/^/    | /'
}

wait_ready() {
    local container="$1" pid1
    for _ in $(seq 1 90); do
        pid1="$(docker exec "$container" cat /proc/1/comm 2>/dev/null || true)"
        if [ "$pid1" = "postgres" ] && docker exec "$container" pg_isready -U scanner -d postgres > /dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    docker logs --tail 40 "$container" >&2 || true
    fail "PostgreSQL in $container did not become ready"
}

# An install directory with only what `db-upgrade` needs, bound to its own Compose project.
make_install() {
    local project="$1" dir="$WORK/$1"
    mkdir -p "$dir/scripts" "$dir/db"
    cp "$ROOT/scanner.sh" "$ROOT/docker-compose.release.yml" "$ROOT/docker-compose.yml" "$dir/"
    cp "$ROOT/scripts/postgres_upgrade.sh" "$dir/scripts/"
    cp "$ROOT/db/init.sql" "$dir/db/"
    [ ! -f "$ROOT/VERSION" ] || cp "$ROOT/VERSION" "$dir/"
    printf 'POSTGRES_PASSWORD=%s\n' "$PASSWORD" > "$dir/.env"
    chmod 600 "$dir/.env"
    echo "$dir"
}

launcher() {
    local project="$1"
    shift
    (cd "$WORK/$project" && COMPOSE_PROJECT_NAME="$project" SHAKERSCAN_PULL_IMAGES=0 ./scanner.sh "$@")
}

# 16 data as an earlier release left it: the compose-labelled legacy volume, initialized by init.sql.
seed_legacy() {
    local project="$1" extra_sql="${2:-}" name="${1}-seed"
    docker volume create --label "com.docker.compose.project=$project" \
        --label com.docker.compose.volume=postgres-data "${project}_postgres-data" > /dev/null
    docker run -d --name "$name" --network none -e POSTGRES_USER=scanner -e POSTGRES_PASSWORD="$PASSWORD" \
        -e POSTGRES_DB=scanner -v "${project}_postgres-data:/var/lib/postgresql/data" \
        -v "$ROOT/db/init.sql:/docker-entrypoint-initdb.d/init.sql:ro" "$LEGACY_IMAGE" > /dev/null
    wait_ready "$name"
    docker exec -i "$name" psql -X -q -U scanner -d scanner -v ON_ERROR_STOP=1 <<SQL
CREATE ROLE smoke_signer LOGIN PASSWORD '$SIGNER_PASSWORD';
CREATE TABLE smoke_rows (id bigserial PRIMARY KEY, payload bytea, doc jsonb, note text);
INSERT INTO smoke_rows (payload, doc, note)
    SELECT decode(md5(g::text) || md5((g * 7)::text), 'hex'), jsonb_build_object('n', g, 'tags', jsonb_build_array('a', g % 5)), repeat('x', g % 300)
    FROM generate_series(1, 20000) g;
CREATE TABLE smoke_events (id bigint, at date NOT NULL) PARTITION BY RANGE (at);
CREATE TABLE smoke_events_2026 PARTITION OF smoke_events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
INSERT INTO smoke_events SELECT g, date '2026-01-01' + (g % 300) FROM generate_series(1, 5000) g;
GRANT SELECT ON smoke_rows TO smoke_signer;
CREATE DATABASE smoke_extra;
$extra_sql
SQL
    docker exec -i "$name" psql -X -q -U scanner -d smoke_extra -v ON_ERROR_STOP=1 \
        -c "CREATE TABLE t AS SELECT g AS id FROM generate_series(1, 777) g"
    docker stop -t 30 "$name" > /dev/null
    docker rm "$name" > /dev/null
}

count() {
    docker exec "$1" psql -X -U scanner -d "$2" -At -c "$3"
}

echo "== 1. legacy 16 data is migrated to $TARGET_IMAGE"
P1="${PREFIX}a"
make_install "$P1" > /dev/null
seed_legacy "$P1"
out="$(launcher "$P1" db-upgrade 2>&1)" || { echo "$out"; fail "db-upgrade failed on legacy data"; }
show "$out"
echo "$out" | grep -q "tables verified" || { echo "$out"; fail "db-upgrade did not report a verified copy"; }
echo "$out" | grep -q "Plan: *ready" || { echo "$out"; fail "status after the upgrade is not ready"; }
backup_dir="$(find "$WORK/$P1/backups" -maxdepth 1 -type d -name 'postgres-16-to-*' | head -n 1)"
[ -n "$backup_dir" ] && [ -s "$backup_dir/pg_dumpall.sql.gz" ] || fail "no dump was kept"
[ ! -e "$backup_dir/.incomplete" ] || fail "a successful upgrade left the backup marked incomplete"
[ "$(stat -c '%a' "$backup_dir" 2>/dev/null || stat -f '%Lp' "$backup_dir")" = "700" ] || fail "backup directory is not private"

# Start 18 exactly as Compose does: the cluster volume at /var/lib/postgresql and the image's PGDATA.
docker run -d --name "${P1}-pg18" -e POSTGRES_PASSWORD=unused -v "${P1}_postgres-cluster:/var/lib/postgresql" \
    "$TARGET_IMAGE" > /dev/null
wait_ready "${P1}-pg18"
[ "$(count "${P1}-pg18" scanner "SHOW server_version_num" | cut -c1-2)" = "18" ] || fail "cluster is not PostgreSQL 18"
[ "$(count "${P1}-pg18" scanner "SELECT count(*) FROM smoke_rows")" = "20000" ] || fail "smoke_rows lost rows"
[ "$(count "${P1}-pg18" scanner "SELECT count(*) FROM smoke_events")" = "5000" ] || fail "partitioned rows lost"
[ "$(count "${P1}-pg18" smoke_extra "SELECT count(*) FROM t")" = "777" ] || fail "second database lost rows"
[ "$(count "${P1}-pg18" scanner "SELECT nextval('smoke_rows_id_seq')")" = "20001" ] || fail "sequence was not carried over"
[ "$(count "${P1}-pg18" scanner "SELECT count(*) FROM information_schema.tables WHERE table_name = 'scans'")" = "1" ] || \
    fail "init.sql schema is missing"
# Both credentials survive: password authentication over TCP, as the API and the signer connect.
docker exec -e PGPASSWORD="$PASSWORD" "${P1}-pg18" psql -X -h 127.0.0.1 -U scanner -d scanner -At -c "SELECT 1" > /dev/null || \
    fail "the scanner password no longer authenticates"
docker exec -e PGPASSWORD="$SIGNER_PASSWORD" "${P1}-pg18" psql -X -h 127.0.0.1 -U smoke_signer -d scanner -At \
    -c "SELECT count(*) FROM smoke_rows" > /dev/null || fail "the signer role password no longer authenticates"
docker exec "${P1}-pg18" grep -Eq '^source_control=[0-9a-f]{64}$' /var/lib/postgresql/18/shakerscan-migration.txt || \
    fail "the receipt does not record the source fingerprint"
docker exec "${P1}-pg18" test ! -e /var/lib/postgresql/18/migrating || fail "staging directory left behind"
docker rm -f "${P1}-pg18" > /dev/null

echo "== 2. a second run is a no-op"
out="$(launcher "$P1" db-upgrade 2>&1)" || { echo "$out"; fail "second db-upgrade failed"; }
echo "$out" | grep -q "Upgrading PostgreSQL" && fail "second run migrated again"
[ "$(find "$WORK/$P1/backups" -maxdepth 1 -type d -name 'postgres-16-to-*' | wc -l | tr -d ' ')" = "1" ] || \
    fail "second run took another dump"

echo "== 2b. a rollback that writes on 16 is detected and resolved explicitly"
rollback_write() {
    docker run -d --name "${P1}-pg16" -v "${P1}_postgres-data:/var/lib/postgresql/data" "$LEGACY_IMAGE" > /dev/null
    wait_ready "${P1}-pg16"
    docker exec "${P1}-pg16" psql -X -q -U scanner -d scanner -c "INSERT INTO smoke_rows (note) VALUES ('$1')"
    docker stop -t 30 "${P1}-pg16" > /dev/null
    docker rm "${P1}-pg16" > /dev/null
}
count_18() {
    docker run -d --name "${P1}-check" -e POSTGRES_PASSWORD=unused -v "${P1}_postgres-cluster:/var/lib/postgresql" \
        "$TARGET_IMAGE" > /dev/null
    wait_ready "${P1}-check"
    count "${P1}-check" scanner "SELECT count(*) FROM smoke_rows"
    docker stop -t 30 "${P1}-check" > /dev/null
    docker rm "${P1}-check" > /dev/null
}
rollback_write "written during the first rollback"
if out="$(launcher "$P1" db-upgrade 2>&1)"; then
    echo "$out"
    fail "a start ignored writes made on 16 after the copy"
fi
show "$out"
echo "$out" | grep -q "has been used since it was copied" || { echo "$out"; fail "divergence was not explained"; }
out="$(printf 'keep\n' | launcher "$P1" db-upgrade --keep-current 2>&1)" || { echo "$out"; fail "--keep-current failed"; }
out="$(launcher "$P1" db-upgrade 2>&1)" || { echo "$out"; fail "start still refused after --keep-current"; }
echo "$out" | grep -q "unchanged since the copy" || { echo "$out"; fail "keep-current did not re-baseline the source"; }
[ "$(count_18)" = "20000" ] || fail "--keep-current changed the 18 data"

rollback_write "written during the second rollback"
out="$(printf 'nope\n' | launcher "$P1" db-upgrade --remigrate 2>&1)" && fail "--remigrate ran without confirmation"
out="$(printf 'remigrate\n' | launcher "$P1" db-upgrade --remigrate 2>&1)" || { echo "$out"; fail "--remigrate failed"; }
show "$out"
echo "$out" | grep -q "tables verified" || { echo "$out"; fail "--remigrate did not verify a new copy"; }
[ "$(count_18)" = "20002" ] || fail "--remigrate did not carry the rollback writes over"
status="$(launcher "$P1" db-upgrade --status 2>&1)"
echo "$status" | grep -q "Set aside: *18/replaced-" || { echo "$status"; fail "the replaced 18 data was not kept"; }
out="$(printf 'remove\n' | launcher "$P1" db-upgrade --remove-legacy 2>&1)" || { echo "$out"; fail "--remove-legacy failed"; }
docker volume inspect "${P1}_postgres-data" > /dev/null 2>&1 && fail "--remove-legacy kept the 16 volume"
status="$(launcher "$P1" db-upgrade --status 2>&1)"
echo "$status" | grep -q "Set aside" && { echo "$status"; fail "--remove-legacy kept the set-aside copy"; }
echo "$status" | grep -q "Plan: *ready" || { echo "$status"; fail "cluster is not ready after cleanup"; }
[ "$(count_18)" = "20002" ] || fail "cleanup changed the 18 data"

echo "== 3. an 18 cluster started before the upgrade is refused"
P3="${PREFIX}c"
make_install "$P3" > /dev/null
seed_legacy "$P3"
docker volume create --label "com.docker.compose.project=$P3" --label com.docker.compose.volume=postgres-cluster \
    "${P3}_postgres-cluster" > /dev/null
docker run -d --name "${P3}-early" -e POSTGRES_USER=scanner -e POSTGRES_PASSWORD="$PASSWORD" \
    -v "${P3}_postgres-cluster:/var/lib/postgresql" "$TARGET_IMAGE" > /dev/null
wait_ready "${P3}-early"
docker rm -f "${P3}-early" > /dev/null
if out="$(launcher "$P3" db-upgrade 2>&1)"; then
    echo "$out"
    fail "db-upgrade accepted an unmigrated 18 cluster beside 16 data"
fi
show "$out"
echo "$out" | grep -q "was not migrated" || { echo "$out"; fail "conflict was not explained"; }
out="$(printf 'remigrate\n' | launcher "$P3" db-upgrade --remigrate 2>&1)" || { echo "$out"; fail "--remigrate did not resolve the conflict"; }
echo "$out" | grep -q "Plan: *ready" || out="$(launcher "$P3" db-upgrade 2>&1)"
echo "$out" | grep -q "Plan: *ready" || { echo "$out"; fail "conflict resolution did not reach ready"; }

echo "== 4. a restore error publishes nothing, and a retry succeeds"
P4="${PREFIX}d"
make_install "$P4" > /dev/null
seed_legacy "$P4" "CREATE EXTENSION adminpack;"
if out="$(launcher "$P4" db-upgrade 2>&1)"; then
    echo "$out"
    fail "db-upgrade succeeded although the restore must fail"
fi
show "$out"
echo "$out" | grep -q "restore into PostgreSQL 18 stopped at an error" || { echo "$out"; fail "restore failure not reported"; }
failed_dir="$(find "$WORK/$P4/backups" -maxdepth 1 -type d -name 'postgres-16-to-*' | head -n 1)"
[ -e "$failed_dir/.incomplete" ] || fail "failed upgrade left the dump looking complete"
grep -q adminpack "$failed_dir/restore.log" || fail "restore.log does not name the failing statement"
docker run --rm -v "${P4}_postgres-cluster:/c" --entrypoint sh "$TARGET_IMAGE" -c \
    'test ! -e /c/18/docker && test ! -e /c/18/migrating && test ! -e /c/18/shakerscan-migration.txt' || \
    fail "a failed upgrade left a data directory or receipt in the cluster volume"
docker run -d --name "${P4}-fix" -v "${P4}_postgres-data:/var/lib/postgresql/data" "$LEGACY_IMAGE" > /dev/null
wait_ready "${P4}-fix"
docker exec "${P4}-fix" psql -X -q -U scanner -d scanner -c "DROP EXTENSION adminpack"
docker stop -t 30 "${P4}-fix" > /dev/null
docker rm "${P4}-fix" > /dev/null
out="$(launcher "$P4" db-upgrade 2>&1)" || { echo "$out"; fail "retry after fixing the source failed"; }
echo "$out" | grep -q "Plan: *ready" || { echo "$out"; fail "retry did not reach ready"; }

echo "== 5. a host without data creates no volumes"
P5="${PREFIX}e"
make_install "$P5" > /dev/null
out="$(launcher "$P5" db-upgrade 2>&1)" || { echo "$out"; fail "db-upgrade failed on an empty host"; }
echo "$out" | grep -q "Plan: *fresh" || { echo "$out"; fail "empty host is not planned as fresh"; }
[ -z "$(docker volume ls -q --filter "name=${P5}_")" ] || fail "db-upgrade created volumes on an empty host"

echo "== 6. a POSTGRES_IMAGE older than 18 is refused"
if out="$(cd "$WORK/$P5" && COMPOSE_PROJECT_NAME="$P5" POSTGRES_IMAGE="$LEGACY_IMAGE" ./scanner.sh db-upgrade 2>&1)"; then
    echo "$out"
    fail "db-upgrade accepted PostgreSQL 16 as the target"
fi
show "$out"
echo "$out" | grep -q "requires PostgreSQL 18 or newer" || { echo "$out"; fail "old target image was not explained"; }

echo "== 7. rollback data expires after the retention period, announced in the last week"
P7="${PREFIX}g"
make_install "$P7" > /dev/null
seed_legacy "$P7"
out="$(launcher "$P7" db-upgrade 2>&1)" || { echo "$out"; fail "db-upgrade failed in the retention scenario"; }
echo "$out" | grep -q "Rollback data: *deleted automatically on .* (30 day(s) left" || \
    { echo "$out"; fail "status does not show the retention date"; }
# Pretend the upgrade happened N days ago: the receipt's timestamp and the dump directory's stamp.
age_upgrade() {
    local stamp dir
    stamp="$(python3 -c 'import datetime, sys
print((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=int(sys.argv[1]), hours=1)).strftime("%Y%m%dT%H%M%SZ"))' "$1")"
    docker run --rm -v "${P7}_postgres-cluster:/c" --entrypoint sh "$TARGET_IMAGE" -c \
        "sed -i 's/^migrated_at=.*/migrated_at=$stamp/' /c/18/shakerscan-migration.txt"
    dir="$(find "$WORK/$P7/backups" -maxdepth 1 -type d -name 'postgres-16-to-*' | head -n 1)"
    mv "$dir" "$WORK/$P7/backups/postgres-16-to-18-$stamp"
}
age_upgrade 25
out="$(launcher "$P7" db-upgrade 2>&1)" || { echo "$out"; fail "a start in the notice week failed"; }
show "$out"
echo "$out" | grep -q "is deleted automatically on" || { echo "$out"; fail "the last week does not announce the deletion"; }
docker volume inspect "${P7}_postgres-data" > /dev/null 2>&1 || fail "the notice week removed the 16 volume"
age_upgrade 40
out="$(cd "$WORK/$P7" && COMPOSE_PROJECT_NAME="$P7" SHAKERSCAN_POSTGRES_LEGACY_RETENTION_DAYS=0 ./scanner.sh db-upgrade 2>&1)" || \
    { echo "$out"; fail "a start with retention 0 failed"; }
docker volume inspect "${P7}_postgres-data" > /dev/null 2>&1 || fail "retention 0 removed the 16 volume"
echo "$out" | grep -q "kept until removed (SHAKERSCAN_POSTGRES_LEGACY_RETENTION_DAYS=0)" || { echo "$out"; fail "retention 0 not reported"; }
out="$(launcher "$P7" db-upgrade 2>&1)" || { echo "$out"; fail "the expiring start failed"; }
show "$out"
echo "$out" | grep -q "Removed the PostgreSQL 16 rollback volume" || { echo "$out"; fail "expiry did not remove the 16 volume"; }
docker volume inspect "${P7}_postgres-data" > /dev/null 2>&1 && fail "the 16 volume survived its retention"
dump_dir="$(find "$WORK/$P7/backups" -maxdepth 1 -type d -name 'postgres-16-to-*' | head -n 1)"
[ ! -e "$dump_dir/pg_dumpall.sql.gz" ] && [ -f "$dump_dir/DUMP-REMOVED.txt" ] || fail "expiry did not remove the upgrade dump"
docker run -d --name "${P7}-pg18" -e POSTGRES_PASSWORD=unused -v "${P7}_postgres-cluster:/var/lib/postgresql" \
    "$TARGET_IMAGE" > /dev/null
wait_ready "${P7}-pg18"
[ "$(count "${P7}-pg18" scanner "SELECT count(*) FROM smoke_rows")" = "20000" ] || fail "expiry touched the 18 data"
docker rm -f "${P7}-pg18" > /dev/null

echo "PostgreSQL upgrade smoke: all scenarios passed"
