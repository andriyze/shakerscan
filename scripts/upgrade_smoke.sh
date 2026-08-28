#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STABLE_VERSION="$(tr -d '[:space:]' < "$REPO_ROOT/install/STABLE_VERSION")"
BASELINE_REF="${BASELINE_REF:-v${STABLE_VERSION}}"
BASELINE_IMAGE="${BASELINE_IMAGE:-shakerscan/shakerscan-scanner@sha256:1bfdd22e87bf90cead6a2c38cd98abd94c5a8eadeea9cee351ea9a484bd1d1fd}"
BASELINE_API_IMAGE="${BASELINE_API_IMAGE:-shakerscan/shakerscan-api@sha256:9349c5c0b4dc59c4c43de0583770ed03a996df6601adf49b175d40747a7f4a0a}"
BASELINE_UI_IMAGE="${BASELINE_UI_IMAGE:-shakerscan/shakerscan-ui@sha256:7811dd9ff647c546fe695cc139171694e90b2bc26a725ec6b0534fe94c8ce7bb}"
SCANNER_IMAGE="${SCANNER_IMAGE:-shakerscan-scanner:upgrade-smoke}"
# Untagged defaults resolve to `:latest`, which is whatever happens to be on the host
# -- so the smoke could pass while qualifying an upgrade the release does not ship, or
# fail on a clean runner where no such image exists. Callers name the exact candidate.
CANDIDATE_API_IMAGE="${CANDIDATE_API_IMAGE:-shakerscan-api:upgrade-smoke}"
CANDIDATE_UI_IMAGE="${CANDIDATE_UI_IMAGE:-shakerscan-ui:upgrade-smoke}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:16.15-alpine3.23@sha256:421b84e07a72bb8f3715f20501a1fdbe1219aad1fa4af7786a49d9a3f2480296}"
REDIS_IMAGE="${REDIS_IMAGE:-redis:7.4.11-alpine3.21@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf}"
UPGRADE_FERNET_KEY="${UPGRADE_FERNET_KEY:-MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=}"
SMOKE_CONTAINER="shakerscan-upgrade-smoke-$$"
ROLLBACK_REDIS_CONTAINER="shakerscan-rollback-redis-$$"
ROLLBACK_API_CONTAINER="shakerscan-rollback-api-$$"
ROLLBACK_UI_CONTAINER="shakerscan-rollback-ui-$$"
ROLLBACK_WORKER_CONTAINER="shakerscan-rollback-worker-$$"
CANDIDATE_REDIS_CONTAINER="shakerscan-candidate-redis-$$"
CANDIDATE_API_CONTAINER="shakerscan-candidate-api-$$"
CANDIDATE_UI_CONTAINER="shakerscan-candidate-ui-$$"
CANDIDATE_WORKER_CONTAINER="shakerscan-candidate-worker-$$"
UPGRADE_QUEUED_ID="upgrade-smoke-queued-$$"
UPGRADE_LEASED_ID="upgrade-smoke-leased-$$"
UPGRADE_QUEUED_JOB="{\"scan_id\":\"$UPGRADE_QUEUED_ID\",\"job_id\":\"$UPGRADE_QUEUED_ID\"}"
SMOKE_TMP="$(mktemp -d "${TMPDIR:-/tmp}/shakerscan-upgrade-smoke.XXXXXX")"

# A candidate image that is not present locally must stop the run, not be pulled from a
# registry: the point of this smoke is to qualify the images this build just produced.
for candidate_image in "$SCANNER_IMAGE" "$CANDIDATE_API_IMAGE" "$CANDIDATE_UI_IMAGE"; do
    if ! docker image inspect "$candidate_image" >/dev/null 2>&1; then
        echo "upgrade smoke: candidate image is not built locally: $candidate_image" >&2
        echo "build it first, or name the right one via SCANNER_IMAGE / CANDIDATE_API_IMAGE / CANDIDATE_UI_IMAGE" >&2
        exit 1
    fi
done

cleanup() {
    docker rm -f "$CANDIDATE_WORKER_CONTAINER" "$CANDIDATE_UI_CONTAINER" \
        "$CANDIDATE_API_CONTAINER" "$CANDIDATE_REDIS_CONTAINER" >/dev/null 2>&1 || true
    docker rm -f "$ROLLBACK_WORKER_CONTAINER" "$ROLLBACK_UI_CONTAINER" \
        "$ROLLBACK_API_CONTAINER" "$ROLLBACK_REDIS_CONTAINER" >/dev/null 2>&1 || true
    docker rm -f "$SMOKE_CONTAINER" >/dev/null 2>&1 || true
    rm -rf -- "$SMOKE_TMP"
}
trap cleanup EXIT INT TERM

if [ "$BASELINE_REF" != "v$STABLE_VERSION" ]; then
    echo "BASELINE_REF must match install/STABLE_VERSION (v$STABLE_VERSION)" >&2
    exit 1
fi

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
# --- Candidate full stack against the upgraded database -------------------------------------
# Applying candidate migrations through helper code proves the schema moves; it does not prove the
# release runs on it. Boot the candidate API, UI and worker against the dirty upgraded database and
# require them healthy, so an upgrade that migrates cleanly but cannot serve is caught here rather
# than by an operator.

seed_redis_upgrade_work() {
    # Queued and leased work an operator would have in flight across an upgrade. Each is tracked
    # by its OWN identity: an earlier version of this check seeded an unrelated lease and accepted
    # "queue drained OR some lease exists", so losing the queued job entirely still passed.
    docker exec "$CANDIDATE_REDIS_CONTAINER" redis-cli -a scanner --no-auth-warning \
        RPUSH scan_jobs "$UPGRADE_QUEUED_JOB" >/dev/null
    docker exec "$CANDIDATE_REDIS_CONTAINER" redis-cli -a scanner --no-auth-warning \
        SET "scan_lease:$UPGRADE_LEASED_ID" "upgrade-smoke-worker" EX 3600 >/dev/null
}

assert_redis_work_survived() {
    local still_queued claimed leased
    # The SPECIFIC queued job, not the queue length: still on the queue, or claimed by this exact
    # id, or settled with a terminal marker. Anything else means it was lost.
    still_queued="$(docker exec "$CANDIDATE_REDIS_CONTAINER" redis-cli -a scanner \
        --no-auth-warning LRANGE scan_jobs 0 -1 | grep -c "$UPGRADE_QUEUED_ID" || true)"
    claimed="$(docker exec "$CANDIDATE_REDIS_CONTAINER" redis-cli -a scanner --no-auth-warning \
        EXISTS "scan_lease:$UPGRADE_QUEUED_ID" | tr -d '[:space:]')"
    if [ "$still_queued" = "0" ] && [ "$claimed" != "1" ]; then
        echo "the queued job $UPGRADE_QUEUED_ID was neither preserved nor claimed across the upgrade" >&2
        exit 1
    fi
    # The pre-existing lease belongs to the worker that took it and must survive intact.
    leased="$(docker exec "$CANDIDATE_REDIS_CONTAINER" redis-cli -a scanner --no-auth-warning \
        GET "scan_lease:$UPGRADE_LEASED_ID" | tr -d '[:space:]')"
    if [ "$leased" != "upgrade-smoke-worker" ]; then
        echo "the pre-existing worker lease did not survive the upgrade: '${leased:-missing}'" >&2
        exit 1
    fi
}

run_operational_candidate() {
    docker run --detach --name "$CANDIDATE_REDIS_CONTAINER" \
        --network "container:$SMOKE_CONTAINER" \
        "$REDIS_IMAGE" redis-server --requirepass scanner >/dev/null
    for _attempt in $(seq 1 30); do
        docker exec "$CANDIDATE_REDIS_CONTAINER" redis-cli -a scanner --no-auth-warning PING \
            >/dev/null 2>&1 && break
        sleep 1
    done
    seed_redis_upgrade_work

    docker run --detach --name "$CANDIDATE_API_CONTAINER" \
        --network "container:$SMOKE_CONTAINER" \
        -e REDIS_URL=redis://:scanner@127.0.0.1:6379 \
        -e DATABASE_URL=postgresql://scanner:scanner@127.0.0.1:5432/scanner_dirty \
        -e AI_CREDENTIAL_ENC_KEY="$UPGRADE_FERNET_KEY" \
        -e RESULTS_DIR=/results \
        -v "$SMOKE_TMP/results:/results" \
        "$CANDIDATE_API_IMAGE" python3 /app/api.py >/dev/null
    docker run --detach --name "$CANDIDATE_UI_CONTAINER" \
        --network "container:$SMOKE_CONTAINER" \
        -e NEXT_PUBLIC_API_URL=http://127.0.0.1:8080 \
        "$CANDIDATE_UI_IMAGE" >/dev/null
    docker run --detach --name "$CANDIDATE_WORKER_CONTAINER" \
        --network "container:$SMOKE_CONTAINER" \
        -e REDIS_URL=redis://:scanner@127.0.0.1:6379 \
        -e DATABASE_URL=postgresql://scanner:scanner@127.0.0.1:5432/scanner_dirty \
        -e AI_CREDENTIAL_ENC_KEY="$UPGRADE_FERNET_KEY" \
        "$SCANNER_IMAGE" python3 /app/worker.py >/dev/null

    local healthy=0
    for _attempt in $(seq 1 120); do
        if docker run --rm --network "container:$SMOKE_CONTAINER" \
            --entrypoint sh "$SCANNER_IMAGE" -c \
            "curl -sf http://127.0.0.1:8080/health >/dev/null && curl -sf http://127.0.0.1:3000/ >/dev/null"; then
            healthy=1
            break
        fi
        sleep 1
    done
    if [ "$healthy" -ne 1 ]; then
        echo "candidate API/UI did not become healthy on the upgraded database" >&2
        docker logs "$CANDIDATE_API_CONTAINER" >&2 || true
        docker logs "$CANDIDATE_UI_CONTAINER" >&2 || true
        exit 1
    fi
    # Historical rows an operator had before the upgrade must still be served by the candidate.
    docker run --rm --network "container:$SMOKE_CONTAINER" \
        --entrypoint sh "$SCANNER_IMAGE" -c \
        "curl -sf 'http://127.0.0.1:8080/targets?limit=100' | grep -F 'upgrade.example.test' >/dev/null"
    if [ "$(docker inspect --format '{{.State.Running}}' "$CANDIDATE_WORKER_CONTAINER")" != "true" ]; then
        echo "candidate worker did not remain running on the upgraded database" >&2
        docker logs "$CANDIDATE_WORKER_CONTAINER" >&2 || true
        exit 1
    fi
    assert_redis_work_survived
    docker rm -f "$CANDIDATE_WORKER_CONTAINER" "$CANDIDATE_UI_CONTAINER" \
        "$CANDIDATE_API_CONTAINER" "$CANDIDATE_REDIS_CONTAINER" >/dev/null 2>&1 || true
}

mkdir -p "$SMOKE_TMP/results"
run_operational_candidate

run_scenario scanner_dirty rollback

run_operational_rollback() {
    # The baseline API image carries no default command: v0.8.18's compose file supplies
    # `command: ["python3", "/app/api.py"]`, and starting the image without it exits immediately,
    # so the health loop below could only ever time out. The worker already passed its command
    # explicitly; the API did not, which is why the rollback leg could not pass.
    docker run --detach --name "$ROLLBACK_REDIS_CONTAINER" \
        --network "container:$SMOKE_CONTAINER" \
        "$REDIS_IMAGE" redis-server --requirepass scanner >/dev/null
    docker run --detach --name "$ROLLBACK_API_CONTAINER" \
        --network "container:$SMOKE_CONTAINER" \
        -e REDIS_URL=redis://:scanner@127.0.0.1:6379 \
        -e DATABASE_URL=postgresql://scanner:scanner@127.0.0.1:5432/scanner_dirty \
        -e AI_CREDENTIAL_ENC_KEY="$UPGRADE_FERNET_KEY" \
        -e SCANNER_VERSION="$STABLE_VERSION" \
        -e SCANNER_EXPECTED_VERSION="$STABLE_VERSION" \
        -e GIT_COMMIT="$(git -C "$REPO_ROOT" rev-parse "$BASELINE_REF^{commit}")" \
        -e RESULTS_DIR=/results \
        -v "$SMOKE_TMP/results:/results" \
        "$BASELINE_API_IMAGE" python3 /app/api.py >/dev/null
    docker run --detach --name "$ROLLBACK_UI_CONTAINER" \
        --network "container:$SMOKE_CONTAINER" \
        -e NEXT_PUBLIC_API_URL=http://127.0.0.1:8080 \
        -e NEXT_PUBLIC_APP_VERSION="$STABLE_VERSION" \
        "$BASELINE_UI_IMAGE" >/dev/null
    docker run --detach --name "$ROLLBACK_WORKER_CONTAINER" \
        --network "container:$SMOKE_CONTAINER" \
        -e REDIS_URL=redis://:scanner@127.0.0.1:6379 \
        -e DATABASE_URL=postgresql://scanner:scanner@127.0.0.1:5432/scanner_dirty \
        -e AI_CREDENTIAL_ENC_KEY="$UPGRADE_FERNET_KEY" \
        -e SCANNER_VERSION="$STABLE_VERSION" \
        -e GIT_COMMIT="$(git -C "$REPO_ROOT" rev-parse "$BASELINE_REF^{commit}")" \
        "$BASELINE_IMAGE" python3 /app/worker.py >/dev/null

    local healthy=0
    for _attempt in $(seq 1 90); do
        if docker run --rm --network "container:$SMOKE_CONTAINER" \
            --entrypoint sh "$SCANNER_IMAGE" -c \
            "curl -sf http://127.0.0.1:8080/health >/dev/null && curl -sf http://127.0.0.1:3000/ >/dev/null"; then
            healthy=1
            break
        fi
        sleep 1
    done
    if [ "$healthy" -ne 1 ]; then
        echo "previous-stable API/UI did not become healthy after rollback" >&2
        docker logs "$ROLLBACK_API_CONTAINER" >&2 || true
        docker logs "$ROLLBACK_UI_CONTAINER" >&2 || true
        exit 1
    fi
    docker run --rm --network "container:$SMOKE_CONTAINER" \
        --entrypoint sh "$SCANNER_IMAGE" -c \
        "curl -sf 'http://127.0.0.1:8080/targets?limit=100' | grep -F 'upgrade.example.test' >/dev/null"
    if [ "$(docker inspect --format '{{.State.Running}}' "$ROLLBACK_WORKER_CONTAINER")" != "true" ]; then
        echo "Previous-stable worker did not remain running after rollback" >&2
        docker logs "$ROLLBACK_WORKER_CONTAINER" >&2 || true
        exit 1
    fi
}

mkdir -p "$SMOKE_TMP/results"
run_operational_rollback

baseline_source_sha="$(git -C "$REPO_ROOT" rev-parse "$BASELINE_REF^{commit}")"
candidate_source_sha="${CANDIDATE_SHA:-$(git -C "$REPO_ROOT" rev-parse HEAD)}"
baseline_image_id="${BASELINE_IMAGE_DIGEST:-$(docker image inspect --format '{{.Id}}' "$BASELINE_IMAGE")}"
candidate_image_id="${CANDIDATE_IMAGE_DIGEST:-$(docker image inspect --format '{{.Id}}' "$SCANNER_IMAGE")}"
receipt_path="${UPGRADE_RECEIPT_PATH:-$SMOKE_TMP/upgrade-receipt.json}"
python3 "$REPO_ROOT/scripts/upgrade_acceptance_receipt.py" \
    --baseline-version "$STABLE_VERSION" \
    --baseline-source-sha "$baseline_source_sha" \
    --candidate-source-sha "$candidate_source_sha" \
    --baseline-image "$baseline_image_id" \
    --candidate-image "$candidate_image_id" \
    --output "$receipt_path"

echo "Upgrade and operational rollback smoke passed from $BASELINE_REF using $SCANNER_IMAGE"
if [ -n "${UPGRADE_RECEIPT_PATH:-}" ]; then
    echo "Upgrade receipt: $receipt_path"
fi
