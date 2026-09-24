from pathlib import Path
root=Path.cwd()
p=root/'scanner.sh'; s=p.read_text()
def change(old,new):
 global s
 assert s.count(old)==1, (old[:120],s.count(old))
 s=s.replace(old,new)
change('    echo "  rebuild [opts]     Rebuild Docker images (cached by default)"', '    echo "  rebuild [opts]     Rebuild Docker images (cached; auto scope by default)"\n    echo "                       --no-smoke  Skip the post-rebuild execution smoke"\n    echo "                       auto        Smallest safe scope since the last clean full build"')
change('        --arg detail "$detail" \\\n', '''        --arg detail "$detail" \\
        --arg steps "${BUILD_STEP_TIMINGS:-}" \\
        --arg images "${BUILD_IMAGE_RESULTS:-}" \\
        --arg dirty "$(dirty_paths 2>/dev/null | head -n 20)" \\
        --arg smoke "${BUILD_SMOKE_RESULT:-}" \\
''')
change('detail:(if $detail == "" then null else $detail end)}\' \\', '''detail:(if $detail == "" then null else $detail end),
          steps:($steps | split(" ") | map(select(length > 0) | split("=") | {phase:.[0],seconds:(.[1]|tonumber)})),
          images:($images | split("\\n") | map(select(length > 0) | split(" ") | {tag:.[0],before:(if .[1]=="-" then null else .[1] end),after:(if .[2]=="-" then null else .[2] end),result:.[3]})),
          dirty_paths:($dirty | split("\\n") | map(select(length > 0))),
          smoke:(if $smoke == "" then null else $smoke end)}' \\''')
change('begin_build_receipt() {\n    BUILD_RECEIPT_ACTIVE=1', 'begin_build_receipt() {\n    BUILD_STEP_TIMINGS=""\n    BUILD_IMAGE_RESULTS=""\n    BUILD_SMOKE_RESULT=""\n    BUILD_RECEIPT_ACTIVE=1')
start=s.index('run_build_step() {'); end=s.index('\n# Print the ID of an image',start)
s=s[:start]+'''run_build_step() {
    local phase="$1"
    shift
    local exit_code started="$SECONDS"

    BUILD_RECEIPT_PHASE="$phase"
    write_build_receipt running 0
    if "$@"; then
        BUILD_STEP_TIMINGS="${BUILD_STEP_TIMINGS:-}${phase}=$((SECONDS - started)) "
        write_build_receipt running 0
        return 0
    else
        exit_code=$?
        BUILD_STEP_TIMINGS="${BUILD_STEP_TIMINGS:-}${phase}=$((SECONDS - started)) "
        fail_build "$exit_code" "command failed in ${phase}"
        return "$exit_code"
    fi
}
''' + s[end:]
helpers=r'''# Rebuild summaries include runtime configuration as well as filesystem layers. An ENV,
# entrypoint or label change matters even when every RootFS layer stays the same.
rebuild_image_tags() {
    local project="${COMPOSE_PROJECT_NAME:-shakerscan}"
    printf '%s\n' "${SCANNER_LOCAL_WORKER_IMAGE:-shakerscan-worker:local}" \
        "${MODEL_INTAKE_SANDBOX_IMAGE:-shakerscan-model-intake-sandbox:local}" \
        "${project}-api:latest" "${project}-ui:latest" "${project}-model-intake-signer:latest"
}

snapshot_image_ids() {
    local tag content digest
    while IFS= read -r tag; do
        content="$(docker_cli image inspect --format '{{json .Config}}|{{json .RootFS.Layers}}' "$tag" 2>/dev/null || true)"
        digest=""
        if [ -n "$content" ]; then
            digest="$(printf '%s' "$content" | { sha256sum 2>/dev/null || shasum -a 256; } | cut -c1-12)"
        fi
        printf '%s=%s\n' "$tag" "$digest"
    done < <(rebuild_image_tags)
}

diff_image_snapshots() {
    local before="$1" after="$2" tag id_before id_after state
    while IFS='=' read -r tag id_after; do
        [ -n "$tag" ] || continue
        id_before="$(printf '%s\n' "$before" | awk -F= -v t="$tag" '$1==t {print $2}')"
        if [ -z "$id_after" ]; then state="missing"
        elif [ -z "$id_before" ]; then state="new"
        elif [ "$id_before" = "$id_after" ]; then state="unchanged"
        else state="rebuilt"; fi
        printf '%s %s %s %s\n' "$tag" "${id_before:--}" "${id_after:--}" "$state"
    done <<< "$after"
}

print_build_summary() {
    local tag before after state entry
    echo -e "${BLUE}Build summary (source ${GIT_COMMIT:-unknown}):${NC}"
    printf '  %-46s %-10s %s\n' image result content
    while read -r tag before after state; do
        [ -n "$tag" ] || continue
        printf '  %-46s %-10s %s\n' "$tag" "$state" "$after"
    done <<< "${BUILD_IMAGE_RESULTS:-}"
    for entry in ${BUILD_STEP_TIMINGS:-}; do
        printf '  %s: %ss\n' "${entry%%=*}" "${entry#*=}"
    done
}

# Include both sides of renames. Quote unusual filenames conservatively: unrecognized
# paths select all rather than accidentally hiding a runtime input from scope inference.
dirty_paths() {
    git diff --name-only --no-renames HEAD -- 2>/dev/null || return 1
    git ls-files --others --exclude-standard 2>/dev/null
}

rebuild_scope_for_paths() {
    local path scope="none"
    while IFS= read -r path || [ -n "$path" ]; do
        [ -n "$path" ] || continue
        case "$path" in
            api/model_intake_signer*|api/model_intake_control_plane.py) scope="all" ;;
            skills/*|AGENTS.md|.claude/*|.agents/*|.opencode/*|api/*|scanner/*|runner/*|db/*|requirements*.txt|requirements*.lock|pyproject.toml)
                case "$scope" in none) scope="scanner" ;; ui) scope="all" ;; esac ;;
            ui/*)
                case "$scope" in none) scope="ui" ;; scanner) scope="all" ;; esac ;;
            docs/*|tests/*|.github/*|.local-gate/*|README.md|LICENSE|.gitignore|artifacts/*|audit-results/*|results/*|benchmarks/*) ;;
            *) scope="all" ;;
        esac
    done
    printf '%s\n' "$scope"
}

# A partial build cannot move the baseline for untouched images. A dirty build cannot
# describe a later reverted worktree by its commit alone. Fail conservatively to all.
rebuild_changed_paths() {
    local base
    base="$(jq -r 'select(.schema_version == "shakerscan-build-receipt/v1" and
        .status == "completed" and .phase == "complete" and .scope == "all" and
        ((.dirty_paths // []) | length) == 0) | .source_revision // empty' "$BUILD_RECEIPT_FILE" 2>/dev/null)" || return 1
    case "$base" in ""|unknown|dev|image:*|*-dirty) return 1 ;; esac
    [[ "$base" =~ ^[0-9a-f]{7,40}$ ]] || return 1
    git rev-parse --verify --quiet "${base}^{commit}" >/dev/null 2>&1 || return 1
    git diff --name-only --no-renames "$base" HEAD -- 2>/dev/null || return 1
    dirty_paths
}

# Probe only services that were running and have just been rebuilt. Never start a
# stopped stack or report absent workers as an execution pass. No target traffic.
post_rebuild_smoke() {
    local check_api="${1:-0}" check_workers="${2:-0}" worker tool flag failures=0
    if [ "$check_api" -eq 0 ] && [ "$check_workers" -eq 0 ]; then
        BUILD_SMOKE_RESULT="not_run:no_rebuilt_running_services"
        return 0
    fi
    echo -e "${BLUE}Post-rebuild smoke (no target traffic)...${NC}"
    if [ "$check_api" -gt 0 ]; then
        if ! wait_for_url "API contract" "$(api_probe_url)/scan/contracts" 120; then
            failures=$((failures + 1))
        fi
    fi
    if [ "$check_workers" -gt 0 ]; then
        worker="$(docker_cli ps --filter "label=com.docker.compose.project=${COMPOSE_PROJECT_NAME:-shakerscan}" \
            --filter "label=com.docker.compose.service=worker" --format '{{.Names}}' | head -n 1)"
        if [ -z "$worker" ]; then
            echo '  fail: rebuilt worker is not running' >&2
            failures=$((failures + 1))
        else
            if ! docker_cli exec "$worker" timeout 30 python3 -c 'import agent_tools, action_scope'; then
                failures=$((failures + 1))
            fi
            for tool in katana httpx nuclei naabu ffuf; do
                flag="-version"; [ "$tool" != ffuf ] || flag="-V"
                if ! docker_cli exec "$worker" timeout 30 "/opt/tools/$tool" "$flag"; then
                    echo "  fail: $tool does not execute" >&2
                    failures=$((failures + 1))
                fi
            done
        fi
    fi
    if [ "$failures" -gt 0 ]; then
        BUILD_SMOKE_RESULT="failed:${failures}"
        return 1
    fi
    BUILD_SMOKE_RESULT="passed"
}

'''
change('rebuild_images() {\n',helpers+'rebuild_images() {\n')
change('    local BUILD_SCOPE="all"\n', '    local BUILD_SCOPE="auto"\n    local RUN_SMOKE=1\n    local changed inferred images_before images_after\n')
a=s.index('rebuild_images() {'); b=s.index('\nrefresh_workers_after_rebuild',a)
part=s[a:b]
part=part.replace('            scanner)\n','            --no-smoke)\n                RUN_SMOKE=0\n                shift\n                ;;\n            auto)\n                BUILD_SCOPE="auto"\n                shift\n                ;;\n            scanner)\n',1)
part=part.replace('            all)\n                SERVICES=""','            all)\n                BUILD_SCOPE="all"\n                SERVICES=""',1)
part=part.replace('Usage: ./scanner.sh rebuild [--no-cache] [scanner|ui|all]','Usage: ./scanner.sh rebuild [--no-cache] [--no-smoke] [auto|scanner|ui|all]')
marker='    if [ -n "$NO_CACHE" ]; then\n'
auto=r'''    if [ "$BUILD_SCOPE" = "auto" ]; then
        if [ -z "$NO_CACHE" ] && changed="$(rebuild_changed_paths)"; then
            inferred="$(printf '%s\n' "$changed" | rebuild_scope_for_paths)"
            if [ "$inferred" = "none" ]; then
                images_before="$(snapshot_image_ids)"
                if ! printf '%s\n' "$images_before" | grep -q '=$'; then
                    echo -e "${GREEN}Nothing to rebuild: no image input changed since the last clean full build.${NC}"
                    return 0
                fi
                inferred="all"
            fi
            BUILD_SCOPE="$inferred"
        else
            BUILD_SCOPE="all"
        fi
        echo -e "${BLUE}Auto rebuild scope: ${BUILD_SCOPE}${NC}"
    fi
    # Derive these once after parsing, so explicit 'all' cannot be overridden by auto,
    # and the last explicit scope never retains another option's service selection.
    case "$BUILD_SCOPE" in
        ui) SERVICES="ui"; SERVICE_DESC="UI"; REFRESH_WORKERS=0 ;;
        scanner) SERVICES="api worker"; SERVICE_DESC="scanner services (api, worker)"; REFRESH_WORKERS=1 ;;
        all) SERVICES=""; SERVICE_DESC="all services"; REFRESH_WORKERS=1 ;;
    esac
    changed="$(dirty_paths 2>/dev/null || true)"
    if [ -n "$changed" ]; then
        echo -e "${YELLOW}Source tree is dirty; modified/untracked paths:${NC}"
        printf '%s\n' "$changed" | head -n 8 | sed 's/^/    /'
    fi

'''
assert part.count(marker)==1
part=part.replace(marker,auto+marker)
part=part.replace('    begin_build_receipt rebuild "$BUILD_SCOPE"','    begin_build_receipt rebuild "$BUILD_SCOPE"\n    images_before="$(snapshot_image_ids)"',1)
part=part.replace('    record_runtime_mode local', '    images_after="$(snapshot_image_ids)"\n    BUILD_IMAGE_RESULTS="$(diff_image_snapshots "$images_before" "$images_after")"\n    print_build_summary\n    record_runtime_mode local',1)
part=part.replace('    finish_build_receipt',r'''    if [ "$RUN_SMOKE" -eq 0 ]; then
        BUILD_SMOKE_RESULT="not_run:operator_skipped"
    elif [ "$SERVICES" = "ui" ]; then
        BUILD_SMOKE_RESULT="not_run:ui_only"
    else
        BUILD_RECEIPT_PHASE="smoke"
        post_rebuild_smoke "$existing_api" "$existing_workers" || { fail_build 1 "post-rebuild smoke failed"; return 1; }
    fi
    finish_build_receipt''',1)
s=s[:a]+part+s[b:]
p.write_text(s)
p=root/'README.md';s=p.read_text();marker='## Documentation\n'
assert s.count(marker)==1
s=s.replace(marker,'''## Local source rebuilds

```bash
./scanner.sh rebuild          # infer the smallest safe scope
./scanner.sh rebuild ui       # UI only
./scanner.sh rebuild scanner  # scanner runtime, Model Intake overlay, and API
./scanner.sh rebuild all      # force the complete local image set
```

Automatic scope uses the last successful **clean full build** as its baseline. A partial, dirty,
missing or unknown receipt falls back to a full rebuild rather than missing reverted edits or
changes in untouched images. Shipped agent guides and skills are image inputs, not ignored docs.
`--no-cache` forces rebuilding the selected scope without cache; `--no-smoke` explicitly skips the
execution smoke. The summary and `.shakerscan-build-receipt.json` retain step timings, image-content
changes and smoke status. Image content includes runtime configuration, not only filesystem layers.
Only already-running rebuilt services are probed; stopped services remain stopped. UI-only rebuilds
retain their existing UI identity check without probing or restarting API/workers.

'''+marker)
p.write_text(s)
