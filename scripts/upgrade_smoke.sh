#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE_REF="${BASELINE_REF:-v0.8.17}"
BASELINE_IMAGE="${BASELINE_IMAGE:-shakerscan/shakerscan-scanner:0.8.17}"
SCANNER_IMAGE="${SCANNER_IMAGE:-shakerscan-scanner:upgrade-smoke}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:16-alpine}"
UPGRADE_FERNET_KEY="${UPGRADE_FERNET_KEY:-MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=}"
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
    # The official image starts a temporary PostgreSQL server while it creates
    # the configured database, then stops it and execs the final server as PID
    # 1. pg_isready alone can catch that temporary window and the next command
    # is then terminated by the intentional handoff. Require the final PID 1 as
    # well as a live database probe before beginning either migration scenario.
    pid1_comm="$(docker exec "$SMOKE_CONTAINER" cat /proc/1/comm 2>/dev/null || true)"
    if [ "$pid1_comm" = "postgres" ] && \
       docker exec "$SMOKE_CONTAINER" pg_isready -U scanner -d scanner >/dev/null 2>&1; then
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

run_baseline_migrations() {
    local database="$1"
    docker run --rm \
        --network "container:$SMOKE_CONTAINER" \
        -e PYTHONPATH=/app \
        -e AI_CREDENTIAL_ENC_KEY="$UPGRADE_FERNET_KEY" \
        -v "$REPO_ROOT/scripts:/upgrade-smoke:ro" \
        --entrypoint python \
        "$BASELINE_IMAGE" \
        /upgrade-smoke/upgrade_baseline_migrate.py \
        --database-url "postgresql://scanner:${POSTGRES_PASSWORD:-scanner}@127.0.0.1:5432/$database"
}

# This is an upgrade from the installed previous stable runtime, not merely
# from a historical init.sql snapshot. Its runtime migrations are run twice to
# reproduce the exact schema operators currently have before candidate code is
# allowed to touch either database.
run_baseline_migrations scanner
run_baseline_migrations scanner_dirty

cat > "$SMOKE_TMP/dirty.sql" <<'SQL'
INSERT INTO targets (
    id, url, name, root_domain, is_active, total_scans, active_findings_count
) VALUES (
    '11111111-1111-4111-8111-111111111111', 'https://upgrade.example.test',
    'previous-stable-target', 'example.test', true, 3, 3
);

INSERT INTO scans (id, target_id, target_url, status, scan_type)
VALUES (
    '33333333-3333-4333-8333-333333333333',
    '11111111-1111-4111-8111-111111111111',
    'https://upgrade.example.test', 'completed', 'quick'
), (
    '55555555-5555-4555-8555-555555555555',
    '11111111-1111-4111-8111-111111111111',
    'https://upgrade.example.test', 'pending', 'smart'
);

INSERT INTO findings (id, scan_id, target_id, fingerprint, title, severity)
VALUES (
    '44444444-4444-4444-8444-444444444444',
    '33333333-3333-4333-8333-333333333333',
    '11111111-1111-4111-8111-111111111111',
    'upgrade-smoke-finding', 'Preserved upgrade finding', 'medium'
);

INSERT INTO evidence_objects (
    id, scan_id, finding_id, object_type, content_sha256, size_bytes,
    storage_uri, redaction_profile, retention_class, content
) VALUES (
    '88888888-8888-4888-8888-888888888888',
    '33333333-3333-4333-8333-333333333333',
    '44444444-4444-4444-8444-444444444444',
    'upgrade_fixture', repeat('e', 64), 2, 'inline:evidence_objects',
    'content-free', 'audit', '{"ok":true}'::jsonb
);

INSERT INTO ai_targets (
    id, name, target_type, endpoint_url, method, request_template,
    response_path, is_active
) VALUES (
    '66666666-6666-4666-8666-666666666666', 'Previous stable AI target',
    'rag', 'https://upgrade-ai.example.test/query', 'POST',
    '{"query":"{{prompt}}"}'::jsonb, '$.answer', true
);

INSERT INTO model_intake_submissions (
    id, scan_id, requested_by, requested_environment, source_kind,
    source_reference_hash, expected_artifact_sha256, state
) VALUES (
    '77777777-7777-4777-8777-777777777777',
    '33333333-3333-4333-8333-333333333333', 'upgrade-operator', 'staging',
    'https', repeat('a', 64), repeat('b', 64), 'submitted'
);

INSERT INTO target_credential_profiles (
    id, target_id, name, auth_kind, secret_value, secret_preview,
    metadata_json
) VALUES (
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    '11111111-1111-4111-8111-111111111111', 'previous-stable-primary',
    'authorization_header', 'enc:fernet:gAAAAABqjOkpEnKHD1nkbTvQ9EDmPSkIpNKrpYSl6J9Dhu-__j3Fxexhlt_gKDlUuvgLhvKKWps70ai6Y3fuIM0krd9bJtpuzMXSKv6vQm6_yC74aPUZ0R8AP4c8swLJKg6sZPispUsP',
    'Bearer …fixture', '{"fixture":true}'::jsonb
);

INSERT INTO research_episodes (
    id, target_id, objective, episode_version, execution_mode, status,
    max_risk_tier, allowed_families, budget_limits, created_by
) VALUES (
    'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    '11111111-1111-4111-8111-111111111111',
    'Previous stable legacy Hunt awaiting its planner', 'research/v1',
    'gated', 'awaiting_planner', 'active', '["xss"]'::jsonb,
    '{"max_steps":4}'::jsonb, 'upgrade-smoke'
);

INSERT INTO nodes (
    id, name, hostname, role, region, labels, status,
    desired_worker_count, active_worker_count
) VALUES (
    '99999999-9999-4999-8999-999999999999', 'previous-stable-worker',
    'upgrade-worker.example.test', 'worker', 'test', '{"fixture":true}'::jsonb,
    'draining', 1, 0
);
INSERT INTO node_credentials (
    id, node_id, credential_hash, credential_version
) VALUES (
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    '99999999-9999-4999-8999-999999999999', repeat('c', 64), 1
);
INSERT INTO node_join_tokens (
    token_hash, role, transport, expires_at, max_uses, use_count,
    last_used_at, consumed_at
) VALUES (
    'upgrade-consumed-token', 'worker', 'broker', NOW() + INTERVAL '1 hour',
    1, 1, NOW(), NOW()
);
SQL
docker exec -i "$SMOKE_CONTAINER" psql -v ON_ERROR_STOP=1 -U scanner -d scanner_dirty \
    < "$SMOKE_TMP/dirty.sql" >/dev/null

# Preserve the exact pre-upgrade state so the smoke can prove that an operator
# backup restores both historical rows and the published legacy schema.
docker exec "$SMOKE_CONTAINER" pg_dump -U scanner -d scanner_dirty --format=custom \
    > "$SMOKE_TMP/scanner_dirty.before-upgrade.dump"

run_scenario() {
    local database="$1"
    local scenario="$2"
    docker run --rm \
        --network "container:$SMOKE_CONTAINER" \
        -e PYTHONPATH=/app \
        -e AI_CREDENTIAL_ENC_KEY="$UPGRADE_FERNET_KEY" \
        -v "$REPO_ROOT/scripts:/upgrade-smoke:ro" \
        --entrypoint python \
        "$SCANNER_IMAGE" \
        /upgrade-smoke/upgrade_schema_smoke.py \
        --database-url "postgresql://scanner:${POSTGRES_PASSWORD:-scanner}@127.0.0.1:5432/$database" \
        --scenario "$scenario"
}

run_scenario scanner clean
run_scenario scanner_dirty dirty

# A real database restart must not depend on an in-memory migration or lease
# side effect. Verify the complete state again without rerunning migrations.
docker restart "$SMOKE_CONTAINER" >/dev/null
ready=0
for _attempt in $(seq 1 60); do
    if docker exec "$SMOKE_CONTAINER" pg_isready -U scanner -d scanner_dirty >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
if [ "$ready" -ne 1 ]; then
    echo "PostgreSQL did not recover after the upgrade restart" >&2
    exit 1
fi
run_scenario scanner_dirty verify_dirty

docker exec "$SMOKE_CONTAINER" dropdb -U scanner scanner_dirty
docker exec "$SMOKE_CONTAINER" createdb -U scanner scanner_dirty
docker exec -i "$SMOKE_CONTAINER" pg_restore \
    -U scanner -d scanner_dirty --exit-on-error \
    < "$SMOKE_TMP/scanner_dirty.before-upgrade.dump" >/dev/null
run_scenario scanner_dirty rollback

baseline_source_sha="$(git -C "$REPO_ROOT" rev-parse "$BASELINE_REF^{commit}")"
candidate_source_sha="${CANDIDATE_SHA:-$(git -C "$REPO_ROOT" rev-parse HEAD)}"
baseline_image_id="${BASELINE_IMAGE_DIGEST:-$(docker image inspect --format '{{.Id}}' "$BASELINE_IMAGE")}"
candidate_image_id="${CANDIDATE_IMAGE_DIGEST:-$(docker image inspect --format '{{.Id}}' "$SCANNER_IMAGE")}"
receipt_path="${UPGRADE_RECEIPT_PATH:-$SMOKE_TMP/upgrade-receipt.json}"
python3 "$REPO_ROOT/scripts/upgrade_acceptance_receipt.py" \
    --baseline-source-sha "$baseline_source_sha" \
    --candidate-source-sha "$candidate_source_sha" \
    --baseline-image "$baseline_image_id" \
    --candidate-image "$candidate_image_id" \
    --output "$receipt_path"

echo "Upgrade and rollback smoke passed from $BASELINE_REF using $SCANNER_IMAGE"
if [ -n "${UPGRADE_RECEIPT_PATH:-}" ]; then
    echo "Upgrade receipt: $receipt_path"
fi
