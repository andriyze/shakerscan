import json
import os
import re
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_local_compose_mounts_live_source_as_directories():
    # Commit 24adaa6 replaced the fragile single-file bind mounts
    # (./scanner/constants.py:/app/constants.py:ro) with DIRECTORY mounts under
    # /app/_src plus an entrypoint copy step. Single-file mounts inode-pinned on
    # macOS Docker and served stale/truncated files (silent "no output, exit 0"
    # scans). The live invariant: the whole scanner/ and api/ trees are mounted as
    # directories into both API and worker, and entrypoint.sh copies them over the
    # baked /app copies so the runtime uses live host source.
    compose = (ROOT / "docker-compose.yml").read_text()

    for mount in ("./scanner:/app/_src/scanner:ro", "./api:/app/_src/api:ro"):
        assert compose.count(mount) >= 2, f"{mount} should be mounted into API and worker"

    # The legacy single-file mounts must not creep back in.
    for module in ("constants.py", "grading.py", "target_context.py"):
        legacy = f"./scanner/{module}:/app/{module}:ro"
        assert legacy not in compose, f"legacy single-file mount {legacy} reintroduced"

    # entrypoint.sh must copy top-level .py plus the scanner_tools, wordlists, and
    # ai_gate package dirs from /app/_src/* over the baked /app copies (copy, not
    # symlink — a symlinked entrypoint puts sys.path[0] in the wrong tree).
    entrypoint = (ROOT / "scanner" / "entrypoint.sh").read_text()
    assert 'cp -f "$d"/*.py /app/' in entrypoint
    assert "scanner_tools" in entrypoint and "wordlists" in entrypoint and "ai_gate" in entrypoint
    assert "ln -s" not in entrypoint, "entrypoint must copy live source, not symlink it"


def test_compose_runtimes_enable_and_pass_the_documented_gated_execution_flag():
    local_compose = (ROOT / "docker-compose.yml").read_text()
    release_compose = (ROOT / "docker-compose.release.yml").read_text()

    expected = "AI_OPS_ROUTER_EXECUTE_ENABLED=${AI_OPS_ROUTER_EXECUTE_ENABLED:-true}"
    assert expected in local_compose
    assert expected in release_compose


def test_compose_runtimes_mount_installed_readme_for_in_app_docs():
    for compose_name in ("docker-compose.yml", "docker-compose.release.yml"):
        compose = (ROOT / compose_name).read_text()
        assert "SHAKERSCAN_README_PATH=/docs/README.md" in compose
        assert "./README.md:/docs/README.md:ro" in compose


def test_release_compose_separates_api_control_plane_from_workers():
    compose = (ROOT / "docker-compose.release.yml").read_text()
    api_block = re.search(
        r"(?ms)^  api:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)", compose
    ).group(0)
    worker_block = re.search(
        r"(?ms)^  worker:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)", compose
    ).group(0)

    assert "${API_IMAGE_REPO:-shakerscan/shakerscan-api}" in api_block
    assert "${SCANNER_IMAGE_REPO:-shakerscan/shakerscan-scanner}" not in api_block
    assert "${SCANNER_IMAGE_REPO:-shakerscan/shakerscan-scanner}" in worker_block
    assert "${API_IMAGE_REPO:-shakerscan/shakerscan-api}" not in worker_block


def test_docs_page_renders_markdown_without_raw_html_injection():
    page = (ROOT / "ui" / "src" / "app" / "docs" / "page.tsx").read_text()
    sidebar = (ROOT / "ui" / "src" / "components" / "Sidebar.tsx").read_text()

    assert "ReactMarkdown" in page
    assert "remarkGfm" in page
    assert "readFile" in page
    assert "dangerouslySetInnerHTML" not in page
    assert "href: '/docs', label: 'Docs'" in sidebar


def test_fleet_ui_is_capability_driven_and_keeps_remote_capacity_last():
    sidebar = (ROOT / "ui" / "src" / "components" / "Sidebar.tsx").read_text()
    dashboard = (ROOT / "ui" / "src" / "app" / "page.tsx").read_text()
    fleet_page = (ROOT / "ui" / "src" / "app" / "fleet" / "page.tsx").read_text()
    new_scan = (ROOT / "ui" / "src" / "app" / "scan" / "new" / "page.tsx").read_text()

    assert "fleetOnly: true" in sidebar
    assert "!item.fleetOnly || fleetEnabled" in sidebar
    assert "workers?.fleet?.enabled === true" in dashboard
    assert dashboard.index('aria-label="Increase local worker count"') < dashboard.rindex("{remoteAvailable} remote")
    assert "fleetState.status === 'unsupported'" in fleet_page
    assert "Multi-node Fleet is not supported on macOS" in fleet_page
    assert "Fleet is not enabled" in fleet_page
    assert "workerStats?.fleet?.enabled && <Card" in new_scan


def test_hosted_installer_packages_advertised_host_side_adapters():
    expected_downloads = (
        ".dockerignore",
        "db/configure-model-intake-signer-role.sh",
        "docker-compose.worker.yml",
        "docker-compose.broker-worker.yml",
        "scripts/shakerscan_mcp.py",
        "scripts/local_planner_adapter.py",
        "scripts/planner_evals.py",
        "scripts/fleet_cli.py",
        "scripts/fleet_acceptance.py",
        "scripts/model_intake_runner_cli.py",
        "scripts/build-model-intake-guest-rootfs.sh",
        "scripts/provision-model-intake-firecracker.sh",
        "api/command_arsenal.py",
        "api/model_intake_control_plane.py",
        "api/model_intake_components.py",
        "api/model_intake_loader_profiles.py",
        "api/model_intake_runner_inputs.py",
        "api/model_intake_runner_controller.py",
        "api/model_intake_runner_receipts.py",
        "api/model_intake_firecracker_runner.py",
        "api/model_intake_runner_service.py",
        "runner/guest/Dockerfile",
        "runner/guest/guest-init",
        "runner/guest/guest_worker.py",
        "runner/guest/requirements.in",
        "runner/guest/requirements.lock",
        "runner/host/requirements.in",
        "runner/host/requirements.lock",
        "runner/host/system-requirements.ubuntu.txt",
    )
    installer = (ROOT / "install" / "index.sh").read_text()
    hosted = (ROOT / "install" / "index.html").read_text()

    assert installer == hosted
    assert 'mkdir -p "$INSTALL_DIR/db" "$INSTALL_DIR/results" "$INSTALL_DIR/scripts" "$INSTALL_DIR/api"' in installer
    assert 'mkdir -p "$INSTALL_DIR/runner/guest" "$INSTALL_DIR/runner/host"' in installer
    for relative_path in expected_downloads:
        assert f'download "$REPO_RAW_BASE/{relative_path}" "$INSTALL_DIR/{relative_path}"' in installer
    assert 'chmod +x "$INSTALL_DIR/scripts/build-model-intake-guest-rootfs.sh"' in installer
    assert 'chmod +x "$INSTALL_DIR/scripts/provision-model-intake-firecracker.sh"' in installer


def test_prebuilt_runtime_defaults_to_the_downloaded_release_version():
    scanner = (ROOT / "scanner.sh").read_text()
    installer = (ROOT / "install" / "index.sh").read_text()

    assert 'release_version="$(get_release_version)"' in scanner
    assert 'export SCANNER_IMAGE_TAG="$release_version"' in scanner
    assert 'release_version" != "dev"' in scanner
    assert ': "\\${SCANNER_IMAGE_TAG:=$release_image_tag}"' in installer
    assert '"$BIN_DIR/shakerscan" start -y' in installer


def test_minimal_installed_research_adapter_has_all_imports(tmp_path):
    runtime = tmp_path / "runtime"
    for relative_path in (
        "scripts/local_planner_adapter.py",
        "scripts/planner_evals.py",
        "api/command_arsenal.py",
    ):
        source = ROOT / relative_path
        destination = runtime / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    result = subprocess.run(
        ["python3", str(runtime / "scripts" / "local_planner_adapter.py"), "--help"],
        cwd=runtime,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "{evaluate,plan,episode}" in result.stdout


def _write_fake_scan_commands(tmp_path: Path) -> tuple[Path, Path]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    capture = tmp_path / "payload.json"

    docker = fake_bin / "docker"
    docker.write_text("#!/bin/sh\nexit 0\n")
    docker.chmod(0o755)

    curl = fake_bin / "curl"
    curl.write_text(
        """#!/bin/bash
payload=''
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--data-binary" ]]; then
    payload="${2:-}"
    shift 2
  else
    shift
  fi
done
printf '%s' "$payload" > "$SHAKERSCAN_TEST_CAPTURE"
body="${SHAKERSCAN_TEST_BODY:-}"
if [[ -z "$body" ]]; then
  body='{"scan_id":"scan-123","status":"pending"}'
fi
printf '%s\\n%s' "$body" "${SHAKERSCAN_TEST_HTTP_CODE:-201}"
"""
    )
    curl.chmod(0o755)
    return fake_bin, capture


def test_scanner_wrapper_submits_unified_full_coverage_payload(tmp_path):
    fake_bin, capture = _write_fake_scan_commands(tmp_path)
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "SHAKERSCAN_TEST_CAPTURE": str(capture),
        # Do not inherit a remote host cached in the developer runtime .env;
        # this wrapper test asserts the portable default link.
        "SHAKERSCAN_PUBLIC_HOST": "localhost",
    }
    result = subprocess.run(
        [
            "bash",
            str(ROOT / "scanner.sh"),
            "scan",
            "https://app.example.test/path?value=one&other=two",
            "--type",
            "smart",
            "--execution",
            "coverage",
            "--coverage-depth",
            "deep",
            "--shards",
            "auto",
            "--auth-state-shards",
            "--approval-receipt",
            "approval-123",
            "--require-current-workers",
            "--confirm-active",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(capture.read_text())
    assert payload["target"] == "https://app.example.test/path?value=one&other=two"
    assert payload["options"]["scan_type"] == "smart"
    assert payload["options"]["parallel"] is True
    assert payload["options"]["shard_strategy"] == "coverage"
    assert payload["options"]["shards"] == "auto"
    assert payload["options"]["budget_profile"] == "exhaustive"
    assert payload["options"]["exploit_depth"] is True
    assert payload["options"]["auth_state_shards"] is True
    assert payload["options"]["approval_receipt_id"] == "approval-123"
    assert payload["options"]["require_current_workers"] is True
    assert "http://localhost:3000/scans/scan-123" in result.stdout


def test_scanner_wrapper_fails_loudly_on_api_rejection(tmp_path):
    fake_bin, capture = _write_fake_scan_commands(tmp_path)
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "SHAKERSCAN_TEST_CAPTURE": str(capture),
        "SHAKERSCAN_TEST_HTTP_CODE": "409",
        "SHAKERSCAN_TEST_BODY": '{"detail":{"error":"approval_required","message":"Approval required"}}',
    }
    result = subprocess.run(
        ["bash", str(ROOT / "scanner.sh"), "scan", "https://app.example.test"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    assert result.returncode != 0
    assert "HTTP 409" in result.stdout
    assert "Approval required" in result.stdout
    assert "Scan ID: null" not in result.stdout


def test_dockerfile_copies_all_scanner_modules_without_drift():
    # The prebuilt image must contain every top-level scanner module the runtime
    # imports — not just a hand-maintained subset that silently drifts (this is
    # how target_context.py went missing and crashed prebuilt deploys). Either a
    # glob copy, or an explicit copy of every scanner/*.py that runtime imports.
    dockerfile = (ROOT / "scanner" / "Dockerfile").read_text()
    scanner_dir = ROOT / "scanner"

    glob_copy = "COPY scanner/*.py /app/" in dockerfile
    if not glob_copy:
        # Fallback: if listed individually, every runtime-imported top-level
        # module must appear. target_context is the one that bit us.
        for module in ("scanner.py", "constants.py", "grading.py", "findings.py",
                       "reporting.py", "signals.py", "target_context.py"):
            assert f"COPY scanner/{module} /app/{module}" in dockerfile, (
                f"Dockerfile must COPY scanner/{module} (or use the glob)"
            )

    # Guard against re-introducing the latent bug specifically: target_context.py
    # exists and is imported, so it must be covered either way.
    assert (scanner_dir / "target_context.py").exists()
    assert glob_copy or "COPY scanner/target_context.py" in dockerfile


def test_dockerfile_copies_api_modules_without_drift():
    # Same drift class on the api side: api.py/worker.py import sibling modules
    # (retest_contract, session_manager, ...) that must be in the prebuilt image.
    dockerfile = (ROOT / "scanner" / "Dockerfile").read_text()
    api_glob = "COPY api/*.py /app/" in dockerfile
    if not api_glob:
        for module in ("api.py", "worker.py", "retest_contract.py", "session_manager.py"):
            assert f"COPY api/{module} /app/{module}" in dockerfile, (
                f"Dockerfile must COPY api/{module} (or use the glob)"
            )
    # scanner/*.py must be copied before api/*.py so the api versions of the
    # colliding module names (gungnir_worker.py, __init__.py) win — matching the
    # dev bind-mount.
    if api_glob and "COPY scanner/*.py /app/" in dockerfile:
        assert dockerfile.index("COPY scanner/*.py /app/") < dockerfile.index("COPY api/*.py /app/")


def test_worker_preflight_checks_scanner_subprocess_modules_and_symbols():
    worker = (ROOT / "api" / "worker.py").read_text()

    assert "scanner module symbol check" in worker
    assert "apply_dast_precision_policy" in worker
    # Preflight pins the interpreter to sys.executable so a missing/shadowed
    # python3 on PATH cannot quietly run the CLI check against the wrong runtime.
    assert "sys.executable, SCANNER_PATH, \"--help\"" in worker
    assert "sha256_16" in worker


def test_scanner_sh_records_local_build_mode_after_builds():
    script = (ROOT / "scanner.sh").read_text()

    assert "LOCAL_BUILD_MARKER" in script
    assert 'printf "local\\n" > "$LOCAL_BUILD_MARKER"' in script
    assert "Local-build mode recorded" in script
    assert "restart --prebuilt" in script


def test_scanner_sh_builds_shared_worker_and_intake_sandbox_image_once():
    script = (ROOT / "scanner.sh").read_text()
    helper = script.split("build_local_scanner_family() {", 1)[1].split("\n}", 1)[0]
    build_body = script.split("build_images() {", 1)[1].split("\n}", 1)[0]
    rebuild_body = script.split("rebuild_images() {", 1)[1].split("\n}", 1)[0]

    # Both services intentionally use the same scanner/Dockerfile without
    # build arguments. Exporting each Compose target separately duplicates a
    # multi-gigabyte image and can exhaust supported source-build hosts.
    assert "compose build $no_cache worker" in helper
    assert 'worker_image="${COMPOSE_PROJECT_NAME:-shakerscan}-worker:latest"' in helper
    assert "docker image inspect --format '{{.Id}}' \"$worker_image\"" in helper
    assert helper.count("compose images -q worker") == 1  # explanatory comment only
    assert 'docker image tag "$worker_image_id" "$sandbox_image"' in helper
    assert "compose build $no_cache api" in helper
    assert "compose build $no_cache model-intake-sandbox" not in helper

    assert "build_local_scanner_family" in build_body
    assert "compose build ui model-intake-signer" in build_body
    assert "compose build\n" not in build_body
    assert 'elif [ "$SERVICES" = "api worker" ]' in rebuild_body
    assert 'build_local_scanner_family "$NO_CACHE"' in rebuild_body
    assert "compose build $NO_CACHE ui model-intake-signer" in rebuild_body


def test_scanner_sh_retags_the_fresh_build_not_a_running_workers_retired_image():
    script = (ROOT / "scanner.sh").read_text()
    helper = script.split("build_local_scanner_family() {", 1)[1].split("\n}", 1)[0]
    image_id = "sha256:" + ("a" * 64)
    harness = f"""
set -eu
RED=''
NC=''
compose() {{ printf 'compose:%s\\n' "$*"; }}
docker() {{
  if [ "$1 $2" = 'image inspect' ]; then
    [ "${{@: -1}}" = 'release-candidate-worker:latest' ] || return 91
    printf '{image_id}\\n'
  elif [ "$1 $2" = 'image tag' ]; then
    printf 'tag:%s:%s\\n' "$3" "$4"
  else
    return 92
  fi
}}
build_local_scanner_family() {{
{helper}
}}
COMPOSE_PROJECT_NAME=release-candidate
MODEL_INTAKE_SANDBOX_IMAGE=release-sandbox:test
build_local_scanner_family
"""
    result = subprocess.run(
        ["bash", "-c", harness],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "compose:build worker" in result.stdout
    assert f"tag:{image_id}:release-sandbox:test" in result.stdout
    assert "compose:build api" in result.stdout


def test_scanner_sh_local_build_marker_controls_default_runtime_mode():
    script = (ROOT / "scanner.sh").read_text()

    assert '[ "$RUNTIME_MODE_EXPLICIT" -eq 0 ] && [ -f "$LOCAL_BUILD_MARKER" ]' in script
    assert 'USE_PREBUILT=0' in script
    assert 'rm -f "$LOCAL_BUILD_MARKER"' in script


def test_scanner_sh_forwards_join_local_build_instead_of_consuming_it():
    script = (ROOT / "scanner.sh").read_text()

    local_build_case = script.split("        --local-build)", 1)[1].split("            ;;", 1)[0]
    assert 'if [ "$COMMAND" = "join" ]' in local_build_case
    assert 'ARGS+=("$1")' in local_build_case


def test_scanner_sh_marks_only_a_live_matching_tailscale_bind_as_trusted():
    script = (ROOT / "scanner.sh").read_text()

    assert '[ "${SHAKERSCAN_BIND_HOST:-}" = "$tailscale_ip" ]' in script
    assert "export SHAKERSCAN_TRUSTED_REMOTE_TRANSPORT=tailscale" in script
    assert "unset SHAKERSCAN_TRUSTED_REMOTE_TRANSPORT" in script


def test_runtime_records_host_platform_for_fleet_ui_capabilities():
    script = (ROOT / "scanner.sh").read_text()

    prepare_body = script.split("prepare_runtime_files() {", 1)[1].split("\n}", 1)[0]
    assert "detect_platform" in prepare_body
    assert 'export SHAKERSCAN_HOST_PLATFORM="$PLATFORM"' in prepare_body
    assert 'write_dotenv_value SHAKERSCAN_HOST_PLATFORM "$SHAKERSCAN_HOST_PLATFORM"' in prepare_body
    for compose_name in ("docker-compose.yml", "docker-compose.release.yml"):
        compose = (ROOT / compose_name).read_text()
        assert "SHAKERSCAN_HOST_PLATFORM=${SHAKERSCAN_HOST_PLATFORM:-unknown}" in compose


def test_scanner_sh_worker_logs_aggregate_api_scaled_containers():
    script = (ROOT / "scanner.sh").read_text()

    assert "show_worker_logs" in script
    assert "worker_log_containers" in script
    assert "scan_worker_containers" in script
    assert 'label=com.docker.compose.project=$project' in script
    assert 'label=com.docker.compose.service=worker' in script
    assert "--filter name=worker" not in script
    assert 'if [ "$SERVICE" = "worker" ] || [ "$SERVICE" = "workers" ]; then' in script
    assert 'awk -v name="$container"' in script
    assert "compose logs -f worker" in script


def test_scanner_sh_worker_lifecycle_is_scoped_to_the_current_compose_project(tmp_path):
    script = (ROOT / "scanner.sh").read_text()
    functions = []
    for name in ("scan_worker_containers", "running_scan_worker_containers"):
        body = script.split(f"{name}() {{", 1)[1].split("\n}", 1)[0]
        functions.append(f"{name}() {{{body}\n}}")
    capture = tmp_path / "docker-args.txt"
    harness = "\n".join([
        "set -eu",
        f"CAPTURE={capture}",
        "docker() { printf '%s\\n' \"$*\" >> \"$CAPTURE\"; printf 'standalone-worker\\n'; }",
        *functions,
        "COMPOSE_PROJECT_NAME=standalone",
        "scan_worker_containers >/dev/null",
        "running_scan_worker_containers >/dev/null",
    ])
    result = subprocess.run(
        ["bash", "-c", harness],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    calls = capture.read_text().splitlines()
    assert len(calls) == 2
    for call in calls:
        assert "label=com.docker.compose.project=standalone" in call
        assert "label=com.docker.compose.service=worker" in call
        assert "name=worker" not in call


def test_scanner_sh_caps_automatic_mac_worker_fleet_for_laptop_restarts():
    script = (ROOT / "scanner.sh").read_text()
    assert 'SHAKERSCAN_AUTO_WORKER_MAX' in script
    assert '"$(uname -s 2>/dev/null || true)" = "Darwin"' in script
    assert 'auto_worker_max=5' in script
    assert '[ "$workers" -gt "$auto_worker_max" ]' in script


def test_scanner_sh_restart_and_rebuild_recreate_api_scaled_workers():
    script = (ROOT / "scanner.sh").read_text()

    assert "restart_worker_count" in script
    assert 'restart_workers="$(restart_worker_count)"' in script
    assert 'start_services "$restart_workers"' in script
    assert 'remove_scan_worker_containers "Removing API-scaled worker containers left outside Compose..."' in script
    assert "refresh_workers_after_rebuild" in script
    assert 'existing_workers="$(running_scan_worker_count)"' in script
    assert 'refresh_workers_after_rebuild "$existing_workers"' in script
    assert 'compose up --no-build -d --force-recreate --scale worker="$desired_count" worker' in script


def test_scanner_sh_status_prints_urls_and_reload_rejects_prebuilt_mode():
    script = (ROOT / "scanner.sh").read_text()

    status_body = script.split("show_status() {", 1)[1].split("\n}", 1)[0]
    reload_body = script.split("reload_services() {", 1)[1].split("\n}", 1)[0]
    assert 'echo "  UI:  $(ui_base_url)"' in status_body
    assert 'echo "  API: $(api_base_url)"' in status_body
    assert 'if [ "$USE_PREBUILT" -eq 1 ]' in reload_body
    assert "reload is only available in local-build mode" in reload_body


def test_scanner_sh_backup_is_private_and_fail_closed():
    script = (ROOT / "scanner.sh").read_text()

    assert "create_backup()" in script
    assert "umask 077" in script
    assert 'pg_dump -U scanner -d scanner -Fc' in script
    assert 'results.tar.gz' in script
    assert 'runtime.env' in script
    assert '.incomplete' in script
    assert 'backup)' in script


def test_standalone_datastore_credentials_are_generated_and_compose_has_no_known_fallback():
    script = (ROOT / "scanner.sh").read_text()
    assert "ensure_runtime_datastore_credentials" in script
    assert "generate_datastore_secret" in script
    assert "ensure_model_intake_operator_credential" in script
    assert "ensure_model_intake_signer_credentials" in script
    assert "write_dotenv_value MODEL_INTAKE_OPERATOR_TOKEN" in script
    assert "write_dotenv_value MODEL_INTAKE_SIGNER_INTERNAL_TOKEN" in script
    assert "write_dotenv_value MODEL_INTAKE_SIGNER_DATABASE_PASSWORD" in script
    for compose_name in ("docker-compose.yml", "docker-compose.release.yml"):
        compose = (ROOT / compose_name).read_text()
        assert "${POSTGRES_PASSWORD:-scanner}" not in compose
        assert "${REDIS_PASSWORD:-scanner}" not in compose
        assert "POSTGRES_PASSWORD is required" in compose
        assert "REDIS_PASSWORD is required" in compose
        assert "MODEL_INTAKE_OPERATOR_TOKEN=${MODEL_INTAKE_OPERATOR_TOKEN:-}" in compose


def test_go_tool_builder_retries_transient_network_failures_with_buildkit_caches():
    dockerfile = (ROOT / "scanner" / "Dockerfile").read_text()
    assert "ARG GO_INSTALL_ATTEMPTS=4" in dockerfile
    assert "--mount=type=cache,target=/go/pkg/mod,sharing=locked" in dockerfile
    assert "--mount=type=cache,target=/root/.cache/go-build,sharing=locked" in dockerfile
    assert "mkdir -p /go/pkg/mod/cache /root/.cache/go-build" in dockerfile
    assert "until install_tools" in dockerfile
    assert "Go module download failed" in dockerfile


def test_trivy_bundle_build_retries_transient_registry_failures():
    dockerfile = (ROOT / "scanner" / "Dockerfile").read_text()
    assert "ARG TRIVY_DOWNLOAD_ATTEMPTS=4" in dockerfile
    assert "curl --retry 4 --retry-all-errors" in dockerfile
    assert "until download_trivy_data" in dockerfile
    assert "Trivy data download failed" in dockerfile


def test_scanner_image_builds_network_tools_above_reviewed_security_floors():
    dockerfile = (ROOT / "scanner" / "Dockerfile").read_text()
    requirements = (ROOT / "scanner" / "requirements.txt").read_text()

    assert "build_tool()" in dockerfile
    assert "go build -mod=mod -trimpath" in dockerfile
    assert "golang.org/x/crypto@v0.53.0" in dockerfile
    assert "golang.org/x/net@v0.56.0" in dockerfile
    assert "golang.org/x/text@v0.39.0" in dockerfile
    assert "github.com/jackc/pgx/v5@v5.9.0" in dockerfile
    assert "apt-get purge -y --auto-remove" in dockerfile
    assert "playwright==1.62.0" in requirements
    assert "playwright/python:v1.62.0-noble@sha256:" in dockerfile


def test_compose_passes_secret_bound_gateway_and_join_rate_limit_to_api_processes():
    for compose_name in ("docker-compose.yml", "docker-compose.release.yml"):
        compose = (ROOT / compose_name).read_text()
        assert "FLEET_GATEWAY_PROXY_SECRET=${FLEET_GATEWAY_PROXY_SECRET:-}" in compose
        assert "FLEET_JOIN_RATE_LIMIT_PER_MINUTE=${FLEET_JOIN_RATE_LIMIT_PER_MINUTE:-30}" in compose


def test_scanner_help_describes_bounded_fleet_tokens_and_safe_restart_path():
    scanner = (ROOT / "scanner.sh").read_text()
    assert "fleet join-token   Mint a bounded ready-to-paste worker join command" in scanner
    assert "fleet revoke-join-token  Revoke unused enrollment-token capacity" in scanner
    assert "fleet accept       Run physical multi-node acceptance checks" in scanner
    assert "--max-uses 5 --transport broker" in scanner
    assert "Use scanner.sh rather than raw 'docker compose up' so remote-access trust is re-derived." in scanner
    assert "Mint a single-use ready-to-paste worker join command" not in scanner


def _run_datastore_credential_bootstrap(
    tmp_path, *, command, existing_env="", postgres_volume_exists=False
):
    """Execute scanner.sh's credential bootstrap in isolation.

    The real function is embedded in a 2000-line CLI, so the helpers it depends
    on are extracted verbatim and Docker/Compose are stubbed. That keeps this a
    behavioural test of the persistence rules rather than a string match.
    """
    script = (ROOT / "scanner.sh").read_text()
    wanted = (
        "read_dotenv_value",
        "write_dotenv_value",
        "generate_datastore_secret",
        "postgres_data_volume_exists",
        "ensure_runtime_datastore_credentials",
    )
    extracted = []
    for name in wanted:
        marker = f"\n{name}() {{\n"
        assert marker in script, f"{name} is missing from scanner.sh"
        body = script.split(marker, 1)[1].split("\n}\n", 1)[0]
        extracted.append(f"{name}() {{\n{body}\n}}\n")

    env_file = tmp_path / ".env"
    env_file.write_text(existing_env)

    harness = "\n".join([
        "set -u",
        f'SCRIPT_DIR="{tmp_path}"',
        'RED=""; NC=""',
        "command_exists() { [ \"$1\" = docker ]; }",
        # Any real Compose/Docker call in this path is a bug: rotation must not
        # be attempted for a fresh install with no PostgreSQL data volume.
        'compose() { echo "compose must not run" >&2; return 1; }',
        f'docker() {{ [ "{int(postgres_volume_exists)}" = "1" ]; }}',
        *extracted,
        f'COMMAND="{command}"',
        "ensure_runtime_datastore_credentials",
    ])

    result = subprocess.run(
        ["bash", "-c", harness],
        capture_output=True,
        text=True,
        env={**os.environ, "POSTGRES_PASSWORD": "", "REDIS_PASSWORD": ""},
    )
    assert result.returncode == 0, result.stderr
    values = {}
    for line in env_file.read_text().splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            values[key] = value
    return values


def test_fresh_install_records_both_datastore_passwords_for_build_only_commands(tmp_path):
    # Regression: a `build`/`rebuild` on a new install used to generate both
    # passwords, export them, then return early before writing either one.
    # `.env` was left without REDIS_PASSWORD, so a later plain `docker compose
    # up` failed closed on the required-variable guard.
    values = _run_datastore_credential_bootstrap(tmp_path, command="build")

    assert len(values.get("REDIS_PASSWORD", "")) >= 32
    assert len(values.get("POSTGRES_PASSWORD", "")) >= 32


def test_generated_redis_password_persists_even_when_postgres_rotation_is_deferred(tmp_path):
    # An existing data volume means the PostgreSQL role still holds the old
    # password, so a build-only command must not record the new one. Redis has
    # no durable credential and must still be persisted.
    values = _run_datastore_credential_bootstrap(
        tmp_path, command="build", postgres_volume_exists=True
    )

    assert len(values.get("REDIS_PASSWORD", "")) >= 32
    assert "POSTGRES_PASSWORD" not in values


def test_existing_datastore_passwords_are_preserved(tmp_path):
    existing = f"POSTGRES_PASSWORD={'p' * 40}\nREDIS_PASSWORD={'r' * 40}\n"
    values = _run_datastore_credential_bootstrap(
        tmp_path, command="build", existing_env=existing, postgres_volume_exists=True
    )

    assert values["POSTGRES_PASSWORD"] == "p" * 40
    assert values["REDIS_PASSWORD"] == "r" * 40


def test_ui_never_receives_the_model_intake_operator_secret():
    # Host and forwarding headers are caller-controlled across reverse proxies,
    # so the UI service is never a bearer-secret distribution endpoint.
    for compose_name in ("docker-compose.yml", "docker-compose.release.yml"):
        compose = (ROOT / compose_name).read_text()
        ui_block = re.split(r"\n  [a-z]", compose.split("\n  ui:\n", 1)[1], maxsplit=1)[0]
        assert "MODEL_INTAKE_OPERATOR_TOKEN=" not in ui_block
        assert "SHAKERSCAN_UI_OPERATOR_AUTOFILL=" not in ui_block

    route = (ROOT / "ui" / "src" / "app" / "api" / "model-intake" / "operator-credential" / "route.ts").read_text()
    assert "process.env.MODEL_INTAKE_OPERATOR_TOKEN" not in route
    assert "headers.get('x-forwarded-for')" not in route
    assert "headers.get('host')" not in route
    assert "manual_required" in route
