#!/usr/bin/env bash
# Upgrade a real installed release to this candidate, the way an operator does it, and roll back.
#
#   1. The previous stable release is installed by the real installer (this tree's install/index.sh,
#      which hands a pinned version over to that release's own installer) and given data: a target
#      with standing authorization, an authorization-header credential profile, an authenticated
#      scan, and incompressible bulk rows.
#   2. The candidate's runtime files and exact image digests replace it and `start` upgrades.
#      Everything the API shows must survive, and a new scan must still decrypt the stored credential.
#   3. The pinned installer rolls back to the previous release, which must start on its own data.
#
# When the previous release runs an older PostgreSQL major than the candidate (the 16 -> 18 move),
# the upgrade migrates and a write made during the rollback must make the next upgrade refuse; the
# operator's --remigrate must carry that write over, and --remove-legacy must reclaim the old data.
# When both run the same major, the same steps must preserve the data with no migration at all.
#
# Inputs: CANDIDATE_IMAGE_LOCK (a release-image-lock.env with the candidate's five digests),
# BASELINE_VERSION (default install/STABLE_VERSION), INSTALLED_UPGRADE_HOME, INSTALLED_UPGRADE_BULK_MB
# (default 256), UPGRADE_RECEIPT_PATH (JSON summary). Needs Docker, curl, jq and python3, and the
# runner to itself: it installs into Compose project `shakerscan` and removes it afterwards.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE_VERSION="${BASELINE_VERSION:-$(tr -d '[:space:]' < "$ROOT/install/STABLE_VERSION")}"
CANDIDATE_IMAGE_LOCK="${CANDIDATE_IMAGE_LOCK:?CANDIDATE_IMAGE_LOCK must name the candidate release-image-lock.env}"
# The launcher treats these as operator overrides that win over a release image lock. Inherited from
# the caller they would silently run other images than the baseline's and the candidate's locks name.
unset SCANNER_IMAGE API_IMAGE UI_IMAGE SIGNER_IMAGE MODEL_INTAKE_IMAGE
INSTALL_DIR="${INSTALLED_UPGRADE_HOME:-$HOME/.shakerscan-installed-upgrade}"
BULK_MB="${INSTALLED_UPGRADE_BULK_MB:-256}"
RECEIPT="${UPGRADE_RECEIPT_PATH:-$ROOT/artifacts/installed-upgrade-receipt.json}"
LOG_DIR="$(dirname "$RECEIPT")/installed-upgrade-logs"
API="http://127.0.0.1:8080"
FIXTURE="upgrade-fixture"
TIMINGS=""

mkdir -p "$LOG_DIR"
[ -s "$CANDIDATE_IMAGE_LOCK" ] || { echo "missing $CANDIDATE_IMAGE_LOCK" >&2; exit 2; }

fail() {
    echo "FAIL: $*" >&2
    diagnose > "$LOG_DIR/failure-diagnostics.txt" 2>&1 || true
    exit 1
}

# What a failed run leaves for the uploaded artifact: the cleanup trap removes the stack, so the
# container states and logs must be captured before it runs.
diagnose() {
    echo "== docker"; docker version --format '{{.Server.Version}}' 2>&1; docker compose version 2>&1
    echo "== containers"; docker ps -a --format '{{.Names}}	{{.Status}}	{{.Image}}' 2>&1
    echo "== api health"; curl -sS -m 10 -o - -w '
HTTP %{http_code}
' "$API/health" 2>&1 | tail -c 2000
    for container in shakerscan-api-1 shakerscan-postgres-1 shakerscan-api-storage-init-1; do
        echo "== logs $container"; docker logs --tail 300 "$container" 2>&1
        echo "== inspect $container"; docker inspect --format '{{.State.Status}} exit={{.State.ExitCode}} restarts={{.RestartCount}} oom={{.State.OOMKilled}} error={{.State.Error}}' "$container" 2>&1
    done
    echo "== launcher status"; launcher status 2>&1 | tail -60
}

note() {
    echo "== $*"
}

elapsed() {
    TIMINGS="$TIMINGS\"$1\": $2, "
}

cleanup() {
    if [ "${INSTALLED_UPGRADE_KEEP:-0}" != "1" ]; then
        docker rm -f "$FIXTURE" > /dev/null 2>&1 || true
        if [ -x "$INSTALL_DIR/scanner.sh" ]; then
            (cd "$INSTALL_DIR" && ./scanner.sh stop > /dev/null 2>&1) || true
        fi
        docker volume ls -q --filter label=com.docker.compose.project=shakerscan | xargs -r docker volume rm -f > /dev/null 2>&1 || true
        docker volume rm -f shakerscan_postgres-data shakerscan_postgres-cluster > /dev/null 2>&1 || true
        rm -rf -- "$INSTALL_DIR"
    fi
}
trap cleanup EXIT

launcher() {
    (cd "$INSTALL_DIR" && ./scanner.sh "$@")
}

api() {
    python3 - "$API" "$@" <<'PY'
import json, sys, urllib.request
base, method, path = sys.argv[1:4]
body = sys.argv[4] if len(sys.argv) > 4 else None
request = urllib.request.Request(base + path, method=method, data=body.encode() if body else None,
                                 headers={"content-type": "application/json"})
with urllib.request.urlopen(request, timeout=120) as response:
    raw = response.read()
print(raw.decode() if raw else "null")
PY
}

psql_scanner() {
    docker exec shakerscan-postgres-1 psql -X -U scanner -d scanner -At -c "$1"
}

# Capture first: `... | grep -q` under pipefail fails when grep exits before the writer finishes.
db_status_has() {
    local status
    status="$(launcher db-upgrade --status 2>&1)" || { echo "$status"; return 1; }
    grep -q "$1" <<< "$status" || { echo "$status"; return 1; }
}

compose_postgres_major() {
    sed -n 's/.*\${POSTGRES_IMAGE:-postgres:\([0-9][0-9]*\)\..*/\1/p' "$1" | head -n 1
}

# The stable API view of the data this test created; must match across every upgrade and rollback.
api_view() {
    local target_id="$1"
    for collection in targets scans findings; do
        printf '%s=%s\n' "$collection" "$(api GET "/$collection?limit=1" | jq -r '.total')"
    done
    printf 'profiles=%s\n' "$(api GET "/targets/$target_id/credential-profiles" | jq -c '[(.profiles // .)[] | [.name, .auth_kind]] | sort')"
    printf 'standing=%s\n' "$(api GET "/targets/$target_id/authorization" | jq -r '.authorization.standing')"
}

# Nothing the API showed may be gone. Counts may grow (continuous ASM keeps working in the
# background between snapshots); identities, credential profiles and authorization must be equal.
api_preserved() {
    python3 - "$1" "$2" <<'PY'
import sys
before = dict(line.split("=", 1) for line in sys.argv[1].splitlines())
after = dict(line.split("=", 1) for line in sys.argv[2].splitlines())
problems = [f"{k}: {before[k]} -> {after.get(k)}" for k in ("profiles", "standing") if after.get(k) != before[k]]
problems += [f"{k}: {before[k]} -> {after.get(k)}" for k in ("targets", "scans", "findings")
             if not after.get(k, "").isdigit() or int(after[k]) < int(before[k])]
print("\n".join(problems), file=sys.stderr)
sys.exit(1 if problems else 0)
PY
}

# An authenticated scan of the fixture; succeeds when its traffic includes the primary principal,
# which only happens once the worker decrypted the stored credential.
authenticated_scan() {
    local profile_id="$1" label="$2" scan_id status
    scan_id="$(api POST /scans "{\"target\":\"http://$FIXTURE:8000\",\"name\":\"$label\",\"budget_profile\":\"fast\",\"policy\":{\"active_testing\":true},\"credential_profile_ids\":[\"$profile_id\"]}" | jq -r '.id // .scan_id')"
    for _ in $(seq 1 120); do
        status="$(api GET "/scans/$scan_id" | jq -r '.status')"
        case "$status" in completed|partial|failed|error|cancelled) break ;; esac
        sleep 15
    done
    [ "$status" = "completed" ] || [ "$status" = "partial" ] || fail "$label scan ended $status"
    [ "$(psql_scanner "SELECT count(*) FROM http_transactions WHERE scan_id = '$scan_id' AND principal_slot = 'primary'")" -gt 0 ] || \
        fail "$label scan never authenticated with the stored credential"
    echo "$scan_id"
}

install_release() {
    local started
    started="$(date +%s)"
    SHAKERSCAN_HOME="$INSTALL_DIR" SHAKERSCAN_INSTALL_VERSION="$BASELINE_VERSION" \
        sh "$ROOT/install/index.sh" > "$LOG_DIR/$1.log" 2>&1 || { tail -40 "$LOG_DIR/$1.log"; fail "$1 failed"; }
    elapsed "$1" "$(( $(date +%s) - started ))"
}

overlay_candidate() {
    # Exactly the files the installer would download for this tree (its manifest), plus the manifest.
    (cd "$ROOT" && { echo install/MANIFEST.sha256; awk '{print $2}' install/MANIFEST.sha256; } | tar -cf - -T -) | \
        tar -xf - -C "$INSTALL_DIR"
    cp "$CANDIDATE_IMAGE_LOCK" "$INSTALL_DIR/release-image-lock.env"
}

note "1. install $BASELINE_VERSION with the real installer"
install_release install-baseline
BASELINE_MAJOR="$(compose_postgres_major "$INSTALL_DIR/docker-compose.release.yml")"
CANDIDATE_MAJOR="$(compose_postgres_major "$ROOT/docker-compose.release.yml")"
[ -n "$BASELINE_MAJOR" ] && [ -n "$CANDIDATE_MAJOR" ] || fail "could not read the PostgreSQL majors"
echo "PostgreSQL $BASELINE_MAJOR -> $CANDIDATE_MAJOR"

baseline_scanner="$(sed -n 's/^SCANNER_IMAGE=//p' "$INSTALL_DIR/release-image-lock.env")"
docker run -d --name "$FIXTURE" --network shakerscan_default --network-alias "$FIXTURE" \
    --entrypoint python3 "$baseline_scanner" -m http.server 8000 --directory /tmp > /dev/null
TARGET_ID="$(api POST /targets "{\"url\":\"http://$FIXTURE:8000\",\"name\":\"installed upgrade fixture\",\"cohort\":\"lab\"}" | jq -r '.id // .target.id')"
api POST "/targets/$TARGET_ID/authorization" '{"approved_by":"installed-upgrade-smoke","environment":"lab"}' > /dev/null
PROFILE_ID="$(api POST "/targets/$TARGET_ID/credential-profiles" '{"name":"upgrade-bearer","auth_kind":"authorization_header","secret":"Bearer installed-upgrade-0123456789abcdef"}' | jq -r '.id // .profile.id')"
authenticated_scan "$PROFILE_ID" "baseline authenticated" > /dev/null
psql_scanner "CREATE EXTENSION IF NOT EXISTS pgcrypto; CREATE TABLE zz_installed_upgrade_bulk (id bigserial PRIMARY KEY, blob bytea NOT NULL); INSERT INTO zz_installed_upgrade_bulk (blob) SELECT gen_random_bytes(1024) FROM generate_series(1, $((BULK_MB * 1024)));" > /dev/null
BEFORE="$(api_view "$TARGET_ID")"
DB_SIZE="$(psql_scanner "SELECT sum(pg_database_size(datname)) FROM pg_database")"

note "2. upgrade to the candidate"
overlay_candidate
started="$(date +%s)"
launcher start -y --prebuilt > "$LOG_DIR/upgrade.log" 2>&1 || { tail -40 "$LOG_DIR/upgrade.log"; fail "upgrade start failed"; }
elapsed upgrade "$(( $(date +%s) - started ))"
if [ "$BASELINE_MAJOR" -lt "$CANDIDATE_MAJOR" ]; then
    grep -q "PostgreSQL upgraded to $CANDIDATE_MAJOR" "$LOG_DIR/upgrade.log" || fail "the upgrade did not migrate PostgreSQL"
    db_status_has "Source data: *unchanged since the copy" || fail "the migration is not recorded"
else
    grep -q "Upgrading PostgreSQL" "$LOG_DIR/upgrade.log" && fail "a same-major upgrade migrated"
fi
[ "$(psql_scanner "SELECT current_setting('server_version_num')::int / 10000")" = "$CANDIDATE_MAJOR" ] || fail "not on PostgreSQL $CANDIDATE_MAJOR"
# Storage preparation must leave results/ setgid to the API group, or files workers write after
# start stay root-owned and the API cannot erase them when records are deleted.
[ -g "$INSTALL_DIR/results" ] || fail "results/ lost its setgid bit; the API cannot erase worker-written files"
api_preserved "$BEFORE" "$(api_view "$TARGET_ID")" || fail "the upgrade lost data the API showed before it"
authenticated_scan "$PROFILE_ID" "upgraded authenticated" > /dev/null

note "3. roll back to $BASELINE_VERSION with the pinned installer"
install_release rollback
[ "$(psql_scanner "SELECT current_setting('server_version_num')::int / 10000")" = "$BASELINE_MAJOR" ] || fail "the rollback is not on PostgreSQL $BASELINE_MAJOR"
psql_scanner "SELECT count(*) FROM targets WHERE id = '$TARGET_ID'" | grep -qx 1 || fail "the rollback lost the target"
ROLLBACK_TARGET="$(api POST /targets '{"url":"http://rollback-write.example.test","name":"written during rollback","cohort":"lab"}' | jq -r '.id // .target.id')"

note "4. upgrade again after the rollback wrote data"
overlay_candidate
if [ "$BASELINE_MAJOR" -lt "$CANDIDATE_MAJOR" ]; then
    if launcher start -y --prebuilt > "$LOG_DIR/reupgrade.log" 2>&1; then
        fail "the upgrade ignored data written during the rollback"
    fi
    grep -q "has been used since it was copied" "$LOG_DIR/reupgrade.log" || { tail -20 "$LOG_DIR/reupgrade.log"; fail "the refusal was not explained"; }
    started="$(date +%s)"
    printf 'remigrate\n' | launcher db-upgrade --remigrate > "$LOG_DIR/remigrate.log" 2>&1 || { tail -40 "$LOG_DIR/remigrate.log"; fail "--remigrate failed"; }
    elapsed remigrate "$(( $(date +%s) - started ))"
fi
launcher start -y --prebuilt > "$LOG_DIR/start-after-rollback.log" 2>&1 || { tail -40 "$LOG_DIR/start-after-rollback.log"; fail "start after the rollback failed"; }
psql_scanner "SELECT count(*) FROM targets WHERE id = '$ROLLBACK_TARGET'" | grep -qx 1 || fail "the rollback's write did not survive the upgrade"
if [ "$BASELINE_MAJOR" -lt "$CANDIDATE_MAJOR" ]; then
    printf 'remove\n' | launcher db-upgrade --remove-legacy > "$LOG_DIR/remove-legacy.log" 2>&1 || { cat "$LOG_DIR/remove-legacy.log"; fail "--remove-legacy failed"; }
    docker volume inspect shakerscan_postgres-data > /dev/null 2>&1 && fail "--remove-legacy kept the old volume"
    db_status_has "Plan: *ready" || fail "the cluster is not ready after cleanup"
fi
[ "$(api GET /health | jq -r '.status')" = "healthy" ] || fail "the upgraded stack is not healthy"

mkdir -p "$(dirname "$RECEIPT")"
cat > "$RECEIPT" <<JSON
{"schema": "shakerscan.installed-upgrade/v1", "baseline": "$BASELINE_VERSION", "postgres_from": $BASELINE_MAJOR,
 "postgres_to": $CANDIDATE_MAJOR, "database_bytes": $DB_SIZE, "seconds": {${TIMINGS%, }}, "result": "passed"}
JSON
echo "Installed upgrade smoke passed: $BASELINE_VERSION (PostgreSQL $BASELINE_MAJOR) -> candidate (PostgreSQL $CANDIDATE_MAJOR)"
