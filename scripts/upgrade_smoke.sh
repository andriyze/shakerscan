#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE_REF="${BASELINE_REF:-f27bbffda3451ce013aedfb250c7b018104f41d5}"
SCANNER_IMAGE="${SCANNER_IMAGE:-shakerscan-scanner:upgrade-smoke}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:16-alpine}"
SMOKE_CONTAINER="shakerscan-upgrade-smoke-$$"
SMOKE_TMP="$(mktemp -d "${TMPDIR:-/tmp}/shakerscan-upgrade-smoke.XXXXXX")"

cleanup() {
    docker rm -f "$SMOKE_CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$SMOKE_TMP"
}
trap cleanup EXIT INT TERM

git -C "$REPO_ROOT" cat-file -e "${BASELINE_REF}:db/init.sql"
git -C "$REPO_ROOT" show "${BASELINE_REF}:db/init.sql" > "$SMOKE_TMP/baseline.sql"

docker run --detach --name "$SMOKE_CONTAINER" \
    -e POSTGRES_USER=scanner \
    -e POSTGRES_PASSWORD=scanner \
    -e POSTGRES_DB=scanner \
    "$POSTGRES_IMAGE" >/dev/null

ready=0
for _attempt in $(seq 1 60); do
    if docker exec "$SMOKE_CONTAINER" pg_isready -U scanner -d scanner >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
if [ "$ready" -ne 1 ]; then
    echo "PostgreSQL did not become ready" >&2
    exit 1
fi

docker exec "$SMOKE_CONTAINER" createdb -U scanner scanner_dirty
docker exec -i "$SMOKE_CONTAINER" psql -v ON_ERROR_STOP=1 -U scanner -d scanner \
    < "$SMOKE_TMP/baseline.sql" >/dev/null
docker exec -i "$SMOKE_CONTAINER" psql -v ON_ERROR_STOP=1 -U scanner -d scanner_dirty \
    < "$SMOKE_TMP/baseline.sql" >/dev/null

cat > "$SMOKE_TMP/dirty.sql" <<'SQL'
INSERT INTO targets (
    id, url, name, root_domain, is_active, total_scans, active_findings_count
) VALUES
    ('11111111-1111-4111-8111-111111111111', 'http://upgrade.example.test',
     'survivor', 'example.test', true, 3, 3),
    ('22222222-2222-4222-8222-222222222222', 'https://upgrade.example.test/',
     'duplicate', 'example.test', true, 0, 0);

INSERT INTO scans (id, target_id, target_url, status, scan_type)
VALUES (
    '33333333-3333-4333-8333-333333333333',
    '22222222-2222-4222-8222-222222222222',
    'https://upgrade.example.test/', 'completed', 'quick'
);

INSERT INTO findings (id, scan_id, target_id, fingerprint, title, severity)
VALUES (
    '44444444-4444-4444-8444-444444444444',
    '33333333-3333-4333-8333-333333333333',
    '22222222-2222-4222-8222-222222222222',
    'upgrade-smoke-finding', 'Preserved upgrade finding', 'medium'
);

-- Reproduce the one-use fleet-token table shipped before bounded reusable
-- tokens. Current migrations must upgrade it in place without reactivating a
-- consumed credential.
CREATE TABLE IF NOT EXISTS node_join_tokens (
    token_hash TEXT PRIMARY KEY,
    role TEXT NOT NULL CHECK (role = 'worker'),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO node_join_tokens (token_hash, role, expires_at, consumed_at)
VALUES ('upgrade-consumed-token', 'worker', NOW() + INTERVAL '1 hour', NOW());
SQL
docker exec -i "$SMOKE_CONTAINER" psql -v ON_ERROR_STOP=1 -U scanner -d scanner_dirty \
    < "$SMOKE_TMP/dirty.sql" >/dev/null

run_scenario() {
    local database="$1"
    local scenario="$2"
    docker run --rm \
        --network "container:$SMOKE_CONTAINER" \
        -e PYTHONPATH=/app \
        -v "$REPO_ROOT/scripts:/upgrade-smoke:ro" \
        --entrypoint python \
        "$SCANNER_IMAGE" \
        /upgrade-smoke/upgrade_schema_smoke.py \
        --database-url "postgresql://scanner:${POSTGRES_PASSWORD:-scanner}@127.0.0.1:5432/$database" \
        --scenario "$scenario"
}

run_scenario scanner clean
run_scenario scanner_dirty dirty

echo "Upgrade smoke passed from $BASELINE_REF using $SCANNER_IMAGE"
