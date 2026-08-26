import json
import os
import re
import shlex
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def _compose_service_block(compose: str, service: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(service)}:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        compose,
    )
    assert match is not None, service
    return match.group(0)


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

    assert "${API_IMAGE:-shakerscan/shakerscan-api:latest}" in api_block
    assert "${SCANNER_IMAGE:-shakerscan/shakerscan-scanner:latest}" not in api_block
    assert "${SCANNER_IMAGE:-shakerscan/shakerscan-scanner:latest}" in worker_block
    assert "${API_IMAGE:-shakerscan/shakerscan-api:latest}" not in worker_block


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
    assert "`${localAvailable} workers available`" in dashboard
    assert "`${localAvailable} local workers available`" not in dashboard
    assert "fleetEnabled ? 'Increase local worker count' : 'Increase worker count'" in dashboard
    assert "Worker safety limit reached (${maxWorkers})" in dashboard
    assert "{workerCount} running · max {maxWorkers}" in dashboard
    assert dashboard.index("{fleetEnabled && (") < dashboard.rindex("{remoteAvailable} remote")
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
        "scripts/scan_cli.py",
        "scripts/rebuild_scan_report.py",
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
    assert (
        'mkdir -p "$INSTALL_DIR/db" "$INSTALL_DIR/results" '
        '"$INSTALL_DIR/scripts" "$INSTALL_DIR/api/scan" '
        '"$INSTALL_DIR/api/runtime"'
    ) in installer
    assert 'mkdir -p "$INSTALL_DIR/scanner/scanner_tools"' in installer
    assert 'mkdir -p "$INSTALL_DIR/runner/guest" "$INSTALL_DIR/runner/host"' in installer
    for relative_path in expected_downloads:
        assert f'download "$REPO_RAW_BASE/{relative_path}" "$INSTALL_DIR/{relative_path}"' in installer
    assert 'chmod +x "$INSTALL_DIR/scripts/build-model-intake-guest-rootfs.sh"' in installer
    assert 'chmod +x "$INSTALL_DIR/scripts/provision-model-intake-firecracker.sh"' in installer


def test_prebuilt_runtime_defaults_to_the_downloaded_release_version():
    scanner = (ROOT / "scanner.sh").read_text()
    installer = (ROOT / "install" / "index.sh").read_text()
    stable_version = (ROOT / "install" / "STABLE_VERSION").read_text().strip()
    release_rows = [
        line
        for line in (ROOT / "RELEASES.md").read_text().splitlines()
        if line.startswith(f"| {stable_version} |")
    ]

    assert 'release_version="$(get_release_version)"' in scanner
    assert 'export SCANNER_IMAGE_TAG="$release_version"' in scanner
    assert 'release_version" != "dev"' in scanner
    assert ': "\\${SCANNER_IMAGE_TAG:=$release_image_tag}"' in installer
    assert '"$BIN_DIR/shakerscan" start -y' in installer
    # The stable channel advances after publication. Pin the contract to a valid,
    # published ledger row instead of freezing a historical release number in the
    # runtime test (which previously made every later promotion fail validation).
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", stable_version)
    assert len(release_rows) == 1
    assert "pending" not in release_rows[0]
    assert "not published" not in release_rows[0]
    assert f"shakerscan/shakerscan-scanner:{stable_version}" in release_rows[0]
    assert 'CHANNEL_RAW_BASE="https://raw.githubusercontent.com/andriyze/shakerscan/main"' in installer
    assert 'REPO_RAW_BASE="https://raw.githubusercontent.com/andriyze/shakerscan/v${stable_version}"' in installer
    assert 'INSTALL_VERSION="${SHAKERSCAN_INSTALL_VERSION:-}"' in installer
    assert 'REPO_RAW_BASE="https://raw.githubusercontent.com/andriyze/shakerscan/v${INSTALL_VERSION}"' in installer


def test_upgrade_smoke_waits_for_final_postgres_process():
    script = (ROOT / "scripts" / "upgrade_smoke.sh").read_text()
    assert "cat /proc/1/comm" in script
    assert '[ "$pid1_comm" = "postgres" ]' in script
    assert "pg_isready -U scanner -d scanner" in script


def test_upgrade_smoke_proves_stateful_backup_rollback():
    script = (ROOT / "scripts" / "upgrade_smoke.sh").read_text()
    verifier = (ROOT / "scripts" / "upgrade_schema_smoke.py").read_text()

    assert "pg_dump -U scanner -d scanner_dirty --format=custom" in script
    assert "dropdb -U scanner scanner_dirty" in script
    assert "pg_restore" in script
    assert "run_scenario scanner_dirty rollback" in script
    assert 'STABLE_VERSION="$(tr -d' in script
    assert 'BASELINE_REF:-v${STABLE_VERSION}' in script
    assert "previous-stable API/UI did not become healthy" in script
    assert "shakerscan/shakerscan-scanner@sha256:1bfdd22e87bf90cead6a2c38cd98abd94c5a8eadeea9cee351ea9a484bd1d1fd" in script
    assert "run_baseline_migrations scanner_dirty" in script
    assert 'docker restart "$SMOKE_CONTAINER"' in script
    assert "run_scenario scanner_dirty verify_dirty" in script
    assert "upgrade_acceptance_receipt.py" in script
    assert "_assert_rollback" in verifier
    assert 'choices=("clean", "dirty", "verify_dirty", "rollback")' in verifier
    assert '"active_findings_count": 1 if upgraded else 3' in verifier


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


@contextmanager
def _scan_api(*, rejection: bool = False):
    state: dict[str, object] = {}

    class Handler(BaseHTTPRequestHandler):
        def _json(self, status: int, value: object) -> None:
            body = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            assert self.path == "/scan/contracts"
            self._json(200, {
                "schema_version": "scan-public-contract/v1",
                "families": [],
                "advanced_limits": [],
            })

        def do_POST(self):
            assert self.path == "/scans"
            length = int(self.headers.get("Content-Length") or 0)
            state["payload"] = json.loads(self.rfile.read(length))
            if rejection:
                self._json(409, {
                    "detail": {
                        "error": "approval_required",
                        "message": "Approval required",
                    },
                })
            else:
                self._json(201, {"scan_id": "scan-123", "status": "pending"})

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, state
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_scanner_wrapper_submits_canonical_full_coverage_payload():
    with _scan_api() as (port, state):
        env = {
            **os.environ,
            "SHAKERSCAN_PUBLIC_HOST": "127.0.0.1",
            "SHAKERSCAN_API_PORT": str(port),
            "SHAKERSCAN_UI_PORT": "3000",
        }
        result = subprocess.run(
            [
                "bash",
                str(ROOT / "scanner.sh"),
                "scan",
                "https://app.example.test/path?value=one&other=two",
                "--budget-profile",
                "thorough",
                "--active-testing",
                "--execution",
                "coverage",
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
    payload = state["payload"]
    assert payload["target"] == "https://app.example.test/path?value=one&other=two"
    assert payload["budget_profile"] == "thorough"
    assert payload["policy"]["active_testing"] is True
    assert payload["options"]["parallel"] is True
    assert payload["options"]["shard_strategy"] == "coverage"
    assert payload["options"]["shards"] == "auto"
    assert payload["options"]["auth_state_shards"] is True
    assert payload["approval_receipt_id"] == "approval-123"
    assert payload["options"]["require_current_workers"] is True
    assert "scan_type" not in json.dumps(payload)
    assert "exploit_depth" not in json.dumps(payload)
    assert "http://localhost:3000/scans/scan-123" in result.stdout


def test_scanner_wrapper_fails_loudly_on_api_rejection():
    with _scan_api(rejection=True) as (port, _state):
        env = {
            **os.environ,
            "SHAKERSCAN_PUBLIC_HOST": "127.0.0.1",
            "SHAKERSCAN_API_PORT": str(port),
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
    assert "HTTP 409" in result.stderr
    assert "Approval required" in result.stderr
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


def test_worker_image_and_dev_sync_package_canonical_runtime_modules():
    dockerfile = (ROOT / "scanner" / "Dockerfile").read_text()
    entrypoint = (ROOT / "scanner" / "entrypoint.sh").read_text()

    # Every importable api package must be baked into the image, so a domain
    # extracted out of api.py cannot be missing from the runtime.
    api_packages = sorted(
        path.name
        for path in (ROOT / "api").iterdir()
        if path.is_dir() and (path / "__init__.py").is_file()
    )
    for package in api_packages:
        assert f"COPY api/{package} /app/{package}" in dockerfile
    # The dev-source sync must cover every api package generically. A hardcoded
    # list silently drops each newly extracted package until the baked
    # entrypoint is rebuilt, which is a restart-time ImportError.
    assert "for package_dir in /app/_src/api/*/" in entrypoint
    assert '[ -f "$package_dir/__init__.py" ] || continue' in entrypoint
    assert 'cp -rf "$package_dir." "/app/$package/"' in entrypoint


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
    assert "record_runtime_mode local" in script
    assert "record_runtime_mode prebuilt" in script
    assert "Local-build mode recorded" in script
    assert "restart --prebuilt" in script


def test_scanner_sh_builds_shared_worker_and_intake_sandbox_image_once():
    script = (ROOT / "scanner.sh").read_text()
    helper = script.split("build_local_scanner_family() {", 1)[1].split("\n}", 1)[0]
    build_body = script.split("build_images() {", 1)[1].split("\n}", 1)[0]
    rebuild_body = script.split("rebuild_images() {", 1)[1].split("\n}", 1)[0]

    # The common runtime is exported exactly once. The sandbox reuses that
    # image byte-for-byte and the API is a thin derivative image.
    assert "compose build $no_cache worker" in helper
    assert 'worker_image="${SCANNER_LOCAL_WORKER_IMAGE:-shakerscan-worker:local}"' in helper
    assert "docker image inspect --format '{{.Id}}' \"$worker_image\"" in helper
    assert "compose images -q worker" not in helper
    assert 'docker image tag "$worker_image_id" "$sandbox_image"' in helper
    assert "compose build $no_cache api" in helper
    assert "scanner/toolchain a second time" in helper
    assert "compose build $no_cache model-intake-sandbox" not in helper

    assert "build_local_images" in build_body
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
run_build_step() {{ shift; "$@"; }}
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
SCANNER_LOCAL_WORKER_IMAGE=release-candidate-worker:latest
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


def test_clean_build_storage_admission_fails_early_with_durable_receipt(tmp_path):
    script = (ROOT / "scanner.sh").read_text()
    start = script.index("docker_storage_free_kb() {")
    end = script.index("\nbuild_local_scanner_family() {", start)
    helpers = script[start:end]
    receipt = tmp_path / "build-receipt.json"
    docker_root = tmp_path / "docker-root"
    docker_root.mkdir()
    harness = f"""
set +e
RED=''
BLUE=''
YELLOW=''
NC=''
GIT_COMMIT=test-revision
BUILD_RECEIPT_FILE={shlex.quote(str(receipt))}
BUILD_RECEIPT_ACTIVE=0
BUILD_RECEIPT_OPERATION=''
BUILD_RECEIPT_PHASE=not_started
BUILD_RECEIPT_STARTED_AT=''
docker() {{
  if [ "$1" = info ]; then printf '%s\\n' {shlex.quote(str(docker_root))}; return 0; fi
  printf 'unexpected docker mutation: %s\\n' "$*" >&2
  return 90
}}
df() {{ printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\nmock 40000000 30000000 10485760 75%% %s\\n' {shlex.quote(str(docker_root))}; }}
{helpers}
begin_build_receipt rebuild
check_build_storage --no-cache all
exit_code=$?
printf 'exit=%s\\n' "$exit_code"
exit 0
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
    assert "exit=1" in result.stdout
    assert "Build failed during phase: preflight" in result.stderr
    assert "docker builder prune -af" in result.stderr
    assert "docker system prune -af --volumes" in result.stderr
    payload = json.loads(receipt.read_text())
    assert payload["schema_version"] == "shakerscan-build-receipt/v1"
    assert payload["status"] == "failed"
    assert payload["phase"] == "preflight"
    assert payload["source_revision"] == "test-revision"
    assert payload["free_kb"] == 10485760
    assert "22 GiB required" in payload["detail"]


def test_api_overlay_smoke_proves_shared_layers_identity_and_role_isolation():
    smoke = (ROOT / "scripts" / "docker_api_overlay_smoke.sh").read_text()
    makefile = (ROOT / "Makefile").read_text()

    assert 'SCANNER_RUNTIME_IMAGE=$WORKER_IMAGE' in smoke
    assert 'SHAKERSCAN_API_OVERLAY_PREBUILT' in smoke
    assert 'docker image inspect "$API_IMAGE"' in smoke
    assert '($api | length) == (($worker | length) + 1)' in smoke
    assert '$api[0:($worker | length)] == $worker' in smoke
    assert 'worker image must not contain Docker' in smoke
    assert 'Docker version 27.5.1, build 9f9e405' in smoke
    assert 'runtime API must not carry Buildx' in smoke
    assert 'release-manifest.json' in smoke
    assert '64 * 1024 * 1024' in smoke
    assert "e2e-api-overlay:" in makefile
    assert "scripts/docker_api_overlay_smoke.sh" in makefile


def test_scanner_sh_local_build_marker_controls_default_runtime_mode():
    script = (ROOT / "scanner.sh").read_text()
    gitignore = (ROOT / ".gitignore").read_text()

    assert 'case "$persisted_mode"' in script
    assert "local)" in script
    assert "prebuilt) USE_PREBUILT=1" in script
    assert "has_local_source_tree" in script
    source_tree = script.split("has_local_source_tree() {", 1)[1].split("\n}", 1)[0]
    assert '[ -f "$SCRIPT_DIR/docker-compose.yml" ]' in source_tree
    assert '[ -f "$SCRIPT_DIR/scanner/Dockerfile" ]' in source_tree
    assert '[ -f "$SCRIPT_DIR/ui/Dockerfile" ]' in source_tree
    assert 'rm -f "$LOCAL_BUILD_MARKER"' not in script
    assert ".shakerscan-local-build" in gitignore
    ignored = subprocess.run(
        ["git", "check-ignore", "--quiet", "--no-index", ".shakerscan-local-build"],
        cwd=ROOT,
        check=False,
    )
    assert ignored.returncode == 0


def test_source_reload_restarts_every_editable_execution_role():
    script = (ROOT / "scanner.sh").read_text()
    reload_body = script.split("reload_services() {", 1)[1].split("\n}", 1)[0]

    assert "compose restart api worker" in reload_body
    assert "compose --profile devices restart device-worker" in reload_body
    assert "compose restart agent-tool-worker" in reload_body


def test_runtime_mode_matrix_keeps_source_local_and_curl_prebuilt(tmp_path):
    script = (ROOT / "scanner.sh").read_text()
    source_tree_fn = script.split("has_local_source_tree() {", 1)[1].split("\n}", 1)[0]
    configure_fn = script.split("configure_runtime_mode() {", 1)[1].split("\n}", 1)[0]

    def resolve(runtime: Path, *, marker: str = "", explicit_local: bool = False) -> str:
        runtime.mkdir(parents=True, exist_ok=True)
        if marker:
            (runtime / ".shakerscan-local-build").write_text(marker + "\n")
        harness = f"""
set -eu
SCRIPT_DIR={shlex.quote(str(runtime))}
LOCAL_BUILD_MARKER="$SCRIPT_DIR/.shakerscan-local-build"
PREBUILT_COMPOSE_FILE=docker-compose.release.yml
DEFAULT_PREBUILT_IMAGE_TAG=latest
IMAGE_TAG_OVERRIDE=''
RUNTIME_MODE_EXPLICIT={1 if explicit_local else 0}
USE_PREBUILT={0 if explicit_local else 1}
is_truthy() {{ case "${{1:-}}" in 1|true|yes|on) return 0 ;; *) return 1 ;; esac; }}
get_release_version() {{ printf '0.0.0\n'; }}
update_compose_file_args() {{
  if [ "$USE_PREBUILT" -eq 1 ]; then
    COMPOSE_FILE_ARGS="docker-compose.release.yml"
  else
    COMPOSE_FILE_ARGS="docker-compose.yml"
  fi
}}
has_local_source_tree() {{
{source_tree_fn}
}}
configure_runtime_mode() {{
{configure_fn}
}}
configure_runtime_mode start
printf '%s|%s\n' "$USE_PREBUILT" "$COMPOSE_FILE_ARGS"
"""
        result = subprocess.run(
            ["bash", "-c", harness],
            cwd=ROOT,
            env={"PATH": os.environ["PATH"]},
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout.strip().splitlines()[-1]

    source = tmp_path / "source"
    for relative in (
        "docker-compose.yml",
        "docker-compose.release.yml",
        "scanner/Dockerfile",
        "scanner/Dockerfile.api",
        "ui/Dockerfile",
    ):
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    curl_runtime = tmp_path / "curl"
    curl_runtime.mkdir(parents=True, exist_ok=True)
    (curl_runtime / "docker-compose.release.yml").touch()

    assert resolve(source) == "0|docker-compose.yml"
    assert resolve(source, marker="prebuilt") == "1|docker-compose.release.yml"
    assert resolve(source, marker="prebuilt", explicit_local=True) == "0|docker-compose.yml"
    assert resolve(curl_runtime) == "1|docker-compose.release.yml"
    assert resolve(curl_runtime, marker="local") == "1|docker-compose.release.yml"


def test_local_start_reuses_a_current_full_build_and_rebuilds_an_unproven_set():
    script = (ROOT / "scanner.sh").read_text()
    compose_up = script.split("compose_up() {", 1)[1].split("\n}", 1)[0]
    start_services = script.split("start_services() {", 1)[1].split("\n}", 1)[0]

    harness_template = r'''
set -eu
RED=''
GREEN=''
BLUE=''
NC=''
WORKERS=1
USE_PREBUILT=__MODE__
API_IMAGE_REPO=release-api
SCANNER_IMAGE_REPO=release-worker
UI_IMAGE_REPO=release-ui
SCANNER_IMAGE_TAG=release-tag
prepare_runtime_files() { :; }
persist_remote_access_env() { :; }
resolve_start_workers() { printf '1\n'; }
set_build_env() { :; }
pull_prebuilt_images() { printf 'pull-prebuilt\n'; }
build_local_images() { printf 'build-local\n'; }
local_application_images_ready() { return __READY_RC__; }
record_runtime_mode() { printf 'record:%s\n' "$1"; }
compose() { printf 'compose:%s\n' "$*"; }
compose_up() {
__COMPOSE_UP__
}
api_probe_url() { printf 'http://api'; }
ui_probe_url() { printf 'http://ui'; }
api_base_url() { printf 'http://api'; }
ui_base_url() { printf 'http://ui'; }
wait_for_url() { :; }
verify_running_build_identity() { :; }
verify_specialized_worker_identity() { :; }
running_compose_service_count() { printf '1\n'; }
running_device_worker_count() { printf '0\n'; }
start_services() {
__START_SERVICES__
}
start_services
'''

    outputs = {}
    for mode, ready_rc in ((0, 0), (0, 1), (1, 1)):
        harness = (
            harness_template.replace("__MODE__", str(mode))
            .replace("__READY_RC__", str(ready_rc))
            .replace("__COMPOSE_UP__", compose_up)
            .replace("__START_SERVICES__", start_services)
        )
        result = subprocess.run(
            ["bash", "-c", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        outputs[(mode, ready_rc)] = result.stdout

    assert "build-local" not in outputs[(0, 0)]
    assert "complete application image set" in outputs[(0, 0)]
    assert "compose:up --no-build -d --scale worker=1" in outputs[(0, 0)]

    assert outputs[(0, 1)].count("build-local") == 1
    assert "pull-prebuilt" not in outputs[(0, 1)]
    assert "record:local" in outputs[(0, 1)]
    assert "compose:up --no-build -d --scale worker=1" in outputs[(0, 1)]

    assert "build-local" not in outputs[(1, 1)]
    assert outputs[(1, 1)].count("pull-prebuilt") == 1
    assert "record:prebuilt" in outputs[(1, 1)]
    assert "compose:up --no-build -d --scale worker=1" in outputs[(1, 1)]


def test_build_receipt_scopes_prevent_partial_rebuilds_from_authorizing_startup():
    script = (ROOT / "scanner.sh").read_text()
    writer = script.split("write_build_receipt() {", 1)[1].split("\n}", 1)[0]
    readiness = script.split("local_application_images_ready() {", 1)[1].split("\n}", 1)[0]
    rebuild = script.split("rebuild_images() {", 1)[1].split("\n}", 1)[0]

    assert '--arg scope "$BUILD_RECEIPT_SCOPE"' in writer
    assert 'operation:$operation,scope:$scope' in writer
    assert '.scope == "all"' in readiness
    assert '.source_revision == $revision' in readiness
    assert 'BUILD_SCOPE="ui"' in rebuild
    assert 'BUILD_SCOPE="scanner"' in rebuild
    assert 'begin_build_receipt rebuild "$BUILD_SCOPE"' in rebuild


def test_local_image_receipt_acceptance_is_behavioral_and_fail_closed(tmp_path):
    script = (ROOT / "scanner.sh").read_text()
    readiness = script.split("local_application_images_ready() {", 1)[1].split("\n}", 1)[0]
    receipt = tmp_path / "receipt.json"

    def probe(*, scope: str = "all", revision: str = "current", missing: str = "") -> str:
        receipt.write_text(
            json.dumps(
                {
                    "schema_version": "shakerscan-build-receipt/v1",
                    "operation": "rebuild",
                    "scope": scope,
                    "status": "completed",
                    "phase": "complete",
                    "source_revision": revision,
                }
            )
        )
        harness = f"""
set -eu
BUILD_RECEIPT_FILE={shlex.quote(str(receipt))}
GIT_COMMIT=current
SCANNER_LOCAL_WORKER_IMAGE=worker:local
MODEL_INTAKE_SANDBOX_IMAGE=sandbox:local
COMPOSE_PROJECT_NAME=acceptance
MISSING_IMAGE={shlex.quote(missing)}
docker() {{
  [ "$1 $2" = "image inspect" ] || return 90
  [ "$3" != "$MISSING_IMAGE" ]
}}
local_application_images_ready() {{
{readiness}
}}
if local_application_images_ready; then printf 'ready\n'; else printf 'rebuild\n'; fi
"""
        result = subprocess.run(
            ["bash", "-c", harness],
            cwd=ROOT,
            env={"PATH": os.environ["PATH"]},
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout.strip()

    assert probe() == "ready"
    assert probe(scope="ui") == "rebuild"
    assert probe(revision="old") == "rebuild"
    assert probe(missing="acceptance-model-intake-signer:latest") == "rebuild"


def test_source_compose_has_one_scanner_build_owner_and_never_pulls_local_tags():
    compose = (ROOT / "docker-compose.yml").read_text()

    worker = _compose_service_block(compose, "worker")
    api = _compose_service_block(compose, "api")
    assert "dockerfile: scanner/Dockerfile" in worker
    assert "pull_policy: never" in worker
    assert "shakerscan-worker:local" in worker
    assert "dockerfile: scanner/Dockerfile.api" in api
    assert "SCANNER_RUNTIME_IMAGE: ${SCANNER_LOCAL_WORKER_IMAGE:-shakerscan-worker:local}" in api

    for service in ("agent-tool-worker", "device-worker", "model-intake-sandbox"):
        block = _compose_service_block(compose, service)
        assert "pull_policy: never" in block
        assert "\n    build:" not in block


def test_ui_docker_context_excludes_host_build_artifacts():
    compose = (ROOT / "docker-compose.yml").read_text()
    ignored = (ROOT / "ui" / ".dockerignore").read_text().splitlines()

    assert "context: ./ui" in _compose_service_block(compose, "ui")
    for path in ("node_modules", ".next", ".env", ".env.*", "*.tsbuildinfo"):
        assert path in ignored


def test_curl_installer_remains_release_only_and_does_not_package_source_builds():
    installer = (ROOT / "install" / "index.sh").read_text()

    assert 'download "$REPO_RAW_BASE/docker-compose.release.yml"' in installer
    assert 'download "$REPO_RAW_BASE/docker-compose.yml"' not in installer
    assert 'download "$REPO_RAW_BASE/scanner/Dockerfile"' not in installer
    assert 'download "$REPO_RAW_BASE/ui/Dockerfile"' not in installer
    assert '"$BIN_DIR/shakerscan" start -y' in installer


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


def test_model_intake_sandbox_queue_is_private_and_runs_as_its_owner():
    script = (ROOT / "scanner.sh").read_text()
    prepare_body = script.split("prepare_runtime_files() {", 1)[1].split("\n}", 1)[0]
    assert "MODEL_INTAKE_SANDBOX_UID" in prepare_body
    assert "MODEL_INTAKE_SANDBOX_GID" in prepare_body
    assert "ensure_directory_mode results/model-intake-sandbox 700" in prepare_body
    assert "ensure_directory_mode results/model-intake-sandbox 777" not in prepare_body
    for compose_name in (
        "docker-compose.yml",
        "docker-compose.release.yml",
        "docker-compose.worker.yml",
        "docker-compose.broker-worker.yml",
    ):
        compose = (ROOT / compose_name).read_text()
        assert 'user: "${MODEL_INTAKE_SANDBOX_UID:-10001}:${MODEL_INTAKE_SANDBOX_GID:-10001}"' in compose

    dockerfile = (ROOT / "scanner" / "Dockerfile").read_text()
    assert "useradd --uid 10001 --user-group --create-home scanner" in dockerfile


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
    assert 'restart_device_workers="$(running_device_worker_count)"' in script
    assert 'start_services "$restart_workers" "$restart_device_workers"' in script
    assert 'if [ "$restore_device_workers" -gt 0 ]; then' in script
    assert "Recreating connected-device worker from the selected image" in script
    assert "compose --profile devices up --no-build -d --force-recreate device-worker" in script
    assert 'remove_scan_worker_containers "Removing API-scaled worker containers left outside Compose..."' in script
    assert "refresh_workers_after_rebuild" in script
    assert 'existing_workers="$(running_scan_worker_count)"' in script
    assert 'refresh_workers_after_rebuild "$existing_workers" "$existing_model_intake_sandbox"' in script
    assert 'existing_agent_tool_worker="$(running_compose_service_count agent-tool-worker)"' in script
    assert 'refresh_running_service_after_rebuild agent-tool-worker "$existing_agent_tool_worker"' in script
    assert 'existing_device_workers="$(running_device_worker_count)"' in script
    assert 'refresh_device_worker_after_rebuild "$existing_device_workers"' in script
    assert 'if [ "$(running_device_worker_count)" -gt 0 ]; then' in script
    assert "compose --profile devices restart device-worker" in script
    assert "Docker is running, but this user cannot access the Docker daemon" in script
    assert 'compose up --no-build -d --no-deps --force-recreate model-intake-sandbox' in script
    assert 'compose up --no-build -d --force-recreate --scale worker="$desired_count" worker' in script
    assert 'refresh_running_service_after_rebuild api "$existing_api"' in script
    assert 'refresh_running_service_after_rebuild ui "$existing_ui"' in script
    assert 'refresh_running_service_after_rebuild model-intake-signer "$existing_model_intake_signer"' in script
    assert 'compose up --no-build -d --no-deps --force-recreate "$service"' in script
    assert "Run './scanner.sh restart' if you also need to recreate API/UI containers." not in script


def test_scanner_sh_restart_preserves_opted_in_device_capacity_on_current_image():
    script = (ROOT / "scanner.sh").read_text()
    compose_up = script.split("compose_up() {", 1)[1].split("\n}", 1)[0]
    start_services = script.split("start_services() {", 1)[1].split("\n}", 1)[0]
    restart_services = script.split("restart_services() {", 1)[1].split("\n}", 1)[0]

    harness = r'''
set -eu
RED=''
GREEN=''
YELLOW=''
BLUE=''
NC=''
WORKERS=1
USE_PREBUILT=0
API_IMAGE_REPO=release-api
SCANNER_IMAGE_REPO=release-worker
UI_IMAGE_REPO=release-ui
SCANNER_IMAGE_TAG=release-tag
prepare_runtime_files() { printf 'prepare\n'; }
persist_remote_access_env() { :; }
resolve_start_workers() { printf '1\n'; }
restart_worker_count() { printf '3\n'; }
set_build_env() { :; }
pull_prebuilt_images() { printf 'pull-prebuilt\n'; }
build_local_images() { printf 'build-local\n'; }
local_application_images_ready() { return 0; }
record_runtime_mode() { printf 'record:%s\n' "$1"; }
compose() { printf 'compose:%s\n' "$*"; }
compose_up() {
__COMPOSE_UP__
}
api_probe_url() { printf 'http://api'; }
ui_probe_url() { printf 'http://ui'; }
api_base_url() { printf 'http://api'; }
ui_base_url() { printf 'http://ui'; }
wait_for_url() { :; }
verify_running_build_identity() { :; }
verify_specialized_worker_identity() { printf 'specialized:%s:%s\n' "$1" "$2"; }
running_compose_service_count() { printf '1\n'; }
running_device_worker_count() { printf '1\n'; }
stop_services() { printf 'stop\n'; }
start_services() {
__START_SERVICES__
}
restart_services() {
__RESTART_SERVICES__
}
restart_services
'''
    harness = (
        harness.replace("__COMPOSE_UP__", compose_up)
        .replace("__START_SERVICES__", start_services)
        .replace("__RESTART_SERVICES__", restart_services)
    )
    result = subprocess.run(
        ["bash", "-c", harness],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    output = result.stdout
    primary_up = "compose:up --no-build -d --scale worker=3"
    device_up = "compose:--profile devices up --no-build -d --force-recreate device-worker"
    assert output.count("build-local") == 0
    assert output.count(device_up) == 1
    assert output.index(primary_up) < output.index(device_up)
    assert "specialized:1:1" in output


def test_local_and_release_device_workers_use_stable_readiness_identity():
    source_compose = (ROOT / "docker-compose.yml").read_text()
    release_compose = (ROOT / "docker-compose.release.yml").read_text()

    assert "hostname: shakerscan-device-worker" in source_compose
    assert "hostname: shakerscan-device-worker" in release_compose


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
    assert "ensure_model_intake_local_session_secret" in script
    assert "ensure_model_intake_signer_credentials" in script
    assert "write_dotenv_value MODEL_INTAKE_OPERATOR_TOKEN" in script
    assert "write_dotenv_value MODEL_INTAKE_LOCAL_SESSION_SECRET" in script
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


def test_api_owns_loopback_session_signing_and_ui_never_receives_the_operator_secret():
    # The durable operator bearer never enters the UI. The UI server presents a
    # separate bootstrap secret to the API, which alone owns session signing.
    for compose_name in ("docker-compose.yml", "docker-compose.release.yml"):
        compose = (ROOT / compose_name).read_text()
        ui_block = re.split(r"\n  [a-z]", compose.split("\n  ui:\n", 1)[1], maxsplit=1)[0]
        assert "MODEL_INTAKE_OPERATOR_TOKEN=" not in ui_block
        assert "MODEL_INTAKE_LOCAL_SESSION_SECRET=${MODEL_INTAKE_LOCAL_SESSION_SECRET:-}" in ui_block

    route = (ROOT / "ui" / "src" / "app" / "api" / "model-intake" / "operator-credential" / "route.ts").read_text()
    assert "process.env.MODEL_INTAKE_OPERATOR_TOKEN" not in route
    assert "MODEL_INTAKE_LOCAL_SESSION_SECRET" in route
    assert "createHmac" not in route
    assert "http://api:8080/model-intake/operator-session" in route
    # The guarantee is that the API layer — never the UI — mints and signs the
    # loopback session. Assert it against the api/ tree rather than one file, so
    # module decomposition cannot silently move signing out of the API or make
    # this gate vacuous.
    api_sources = {
        path.name: path.read_text(encoding="utf-8")
        for path in (ROOT / "api").rglob("*.py")
    }
    assert any(
        "def _mint_model_intake_local_session" in text
        for text in api_sources.values()
    )
    assert any(
        '@app.get("/model-intake/operator-session")' in text
        or '@router.get("/model-intake/operator-session")' in text
        for text in api_sources.values()
    )


def test_startup_fails_closed_on_mixed_release_images_and_ui_reports_baked_identity():
    script = (ROOT / "scanner.sh").read_text()
    dockerfile = (ROOT / "ui" / "Dockerfile").read_text()
    route = (ROOT / "ui" / "src" / "app" / "api" / "build-identity" / "route.ts").read_text()

    assert "verify_running_build_identity" in script
    assert "/api/build-identity" in script
    assert "using the complete cached" in script
    assert 'docker image inspect "$image"' in script
    assert "UI_BUILD_VERSION" in dockerfile
    assert "COPY --from=builder /app/UI_BUILD_VERSION ./UI_BUILD_VERSION" in dockerfile
    assert "readFileSync" in route
    assert "UI_BUILD_VERSION" in route
    assert "ui_version" in route


def test_source_build_version_marks_untracked_runtime_files_dirty(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@shakerscan.local"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "ShakerScan Test"], cwd=tmp_path, check=True)
    (tmp_path / "tracked.py").write_text("value = 1\n")
    subprocess.run(["git", "add", "tracked.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=tmp_path, check=True)

    script = (ROOT / "scanner.sh").read_text()
    body = script.split("get_build_version() {", 1)[1].split("\n}", 1)[0]
    harness = "get_build_version() {" + body + "\n}\nget_build_version\n"
    clean = subprocess.run(
        ["bash", "-c", harness], cwd=tmp_path, check=True, capture_output=True, text=True,
    ).stdout.strip()
    assert clean and not clean.endswith("-dirty")

    (tmp_path / "new_runtime_module.py").write_text("value = 2\n")
    dirty = subprocess.run(
        ["bash", "-c", harness], cwd=tmp_path, check=True, capture_output=True, text=True,
    ).stdout.strip()
    assert dirty == f"{clean}-dirty"


def test_source_candidate_build_preserves_explicit_release_identity():
    script = (ROOT / "scanner.sh").read_text()
    body = script.split("set_build_env() {", 1)[1].split("\n}", 1)[0]
    harness = f"""
get_build_version() {{ echo local-short-sha; }}
get_release_version() {{ echo 2.0.0; }}
set_build_env() {{{body}
}}
USE_PREBUILT=0
DEFAULT_PREBUILT_IMAGE_TAG=latest
PLATFORM=linux
SCANNER_VERSION=2.0.0
GIT_COMMIT=0123456789abcdef0123456789abcdef01234567
unset NEXT_PUBLIC_APP_VERSION
set_build_env
printf '%s|%s|%s\n' "$SCANNER_VERSION" "$GIT_COMMIT" "$NEXT_PUBLIC_APP_VERSION"
"""
    result = subprocess.run(
        ["bash", "-c", harness], check=True, capture_output=True, text=True,
    ).stdout.strip()
    assert result == (
        "2.0.0|0123456789abcdef0123456789abcdef01234567|2.0.0"
    )


def test_full_rebuild_verifies_the_recreated_running_stack_before_success():
    script = (ROOT / "scanner.sh").read_text()
    rebuild = script.split("rebuild_images() {", 1)[1].split("\n}\n\nrefresh_workers_after_rebuild", 1)[0]
    assert rebuild.index("refresh_running_service_after_rebuild ui") < rebuild.index(
        "verify_running_build_identity"
    )
    assert rebuild.index("verify_running_build_identity") < rebuild.index("Rebuild complete")


def test_macos_build_network_can_follow_host_vpn_without_changing_runtime_networks():
    script = (ROOT / "scanner.sh").read_text()
    compose = (ROOT / "docker-compose.yml").read_text()

    assert 'export SHAKERSCAN_BUILD_NETWORK="host"' in script
    assert 'export SHAKERSCAN_BUILD_NETWORK="default"' in script
    for service in ("api", "model-intake-signer", "fleet-edge", "worker", "gungnir-worker", "ui"):
        assert "network: ${SHAKERSCAN_BUILD_NETWORK:-default}" in _compose_service_block(compose, service)
    for service in ("agent-tool-worker", "device-worker", "model-intake-sandbox"):
        assert "network: ${SHAKERSCAN_BUILD_NETWORK:-default}" not in _compose_service_block(compose, service)
    assert "network_mode: ${SHAKERSCAN_BUILD_NETWORK" not in compose
