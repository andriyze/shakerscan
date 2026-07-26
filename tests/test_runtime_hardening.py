import json
import os
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


def test_docs_page_renders_markdown_without_raw_html_injection():
    page = (ROOT / "ui" / "src" / "app" / "docs" / "page.tsx").read_text()
    sidebar = (ROOT / "ui" / "src" / "components" / "Sidebar.tsx").read_text()

    assert "ReactMarkdown" in page
    assert "remarkGfm" in page
    assert "readFile" in page
    assert "dangerouslySetInnerHTML" not in page
    assert "href: '/docs', label: 'Docs'" in sidebar


def test_hosted_installer_packages_advertised_host_side_adapters():
    expected_downloads = (
        "docker-compose.worker.yml",
        "docker-compose.broker-worker.yml",
        "scripts/shakerscan_mcp.py",
        "scripts/local_planner_adapter.py",
        "scripts/planner_evals.py",
        "scripts/fleet_cli.py",
        "scripts/fleet_acceptance.py",
        "api/command_arsenal.py",
    )
    installer = (ROOT / "install" / "index.sh").read_text()
    hosted = (ROOT / "install" / "index.html").read_text()

    assert installer == hosted
    assert 'mkdir -p "$INSTALL_DIR/db" "$INSTALL_DIR/results" "$INSTALL_DIR/scripts" "$INSTALL_DIR/api"' in installer
    for relative_path in expected_downloads:
        assert f'download "$REPO_RAW_BASE/{relative_path}" "$INSTALL_DIR/{relative_path}"' in installer


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


def test_scanner_sh_worker_logs_aggregate_api_scaled_containers():
    script = (ROOT / "scanner.sh").read_text()

    assert "show_worker_logs" in script
    assert "worker_log_containers" in script
    assert "scan_worker_containers" in script
    assert "docker ps -a --filter name=worker" in script
    assert "/shakerscan/ && /worker/ && !/gungnir/" in script
    assert 'if [ "$SERVICE" = "worker" ] || [ "$SERVICE" = "workers" ]; then' in script
    assert 'awk -v name="$container"' in script
    assert "compose logs -f worker" in script


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
    for compose_name in ("docker-compose.yml", "docker-compose.release.yml"):
        compose = (ROOT / compose_name).read_text()
        assert "${POSTGRES_PASSWORD:-scanner}" not in compose
        assert "${REDIS_PASSWORD:-scanner}" not in compose
        assert "POSTGRES_PASSWORD is required" in compose
        assert "REDIS_PASSWORD is required" in compose


def test_go_tool_builder_retries_transient_network_failures_with_buildkit_caches():
    dockerfile = (ROOT / "scanner" / "Dockerfile").read_text()
    assert "ARG GO_INSTALL_ATTEMPTS=4" in dockerfile
    assert "--mount=type=cache,target=/go/pkg/mod" in dockerfile
    assert "--mount=type=cache,target=/root/.cache/go-build" in dockerfile
    assert "until install_tools" in dockerfile
    assert "Go module download failed" in dockerfile


def test_compose_passes_secret_bound_gateway_and_join_rate_limit_to_api_processes():
    for compose_name in ("docker-compose.yml", "docker-compose.release.yml"):
        compose = (ROOT / compose_name).read_text()
        assert "FLEET_GATEWAY_PROXY_SECRET=${FLEET_GATEWAY_PROXY_SECRET:-}" in compose
        assert "FLEET_JOIN_RATE_LIMIT_PER_MINUTE=${FLEET_JOIN_RATE_LIMIT_PER_MINUTE:-30}" in compose
