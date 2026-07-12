from pathlib import Path


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


def test_local_compose_passes_the_documented_gated_execution_flag_to_api():
    compose = (ROOT / "docker-compose.yml").read_text()

    assert "AI_OPS_ROUTER_EXECUTE_ENABLED=${AI_OPS_ROUTER_EXECUTE_ENABLED:-false}" in compose


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
