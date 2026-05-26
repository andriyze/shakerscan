from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_local_compose_mounts_all_scanner_top_level_modules():
    compose = (ROOT / "docker-compose.yml").read_text()

    for module in ("constants.py", "grading.py", "findings.py", "reporting.py", "signals.py"):
        mount = f"./scanner/{module}:/app/{module}:ro"
        assert compose.count(mount) >= 2, f"{mount} should be mounted into API and worker"


def test_worker_preflight_checks_scanner_subprocess_modules_and_symbols():
    worker = (ROOT / "api" / "worker.py").read_text()

    assert "scanner module symbol check" in worker
    assert "apply_dast_precision_policy" in worker
    assert "python3\", SCANNER_PATH, \"--help\"" in worker
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
