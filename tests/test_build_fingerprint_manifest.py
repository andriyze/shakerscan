from pathlib import Path

from scanner.scanner_tools.build_fingerprint import (
    FINGERPRINT_SOURCE_FILES,
    hash_source_files,
    source_file_map,
)


def test_shared_fingerprint_manifest_covers_current_execution_contracts():
    names = {name for name, _, _ in FINGERPRINT_SOURCE_FILES}

    assert len(names) == len(FINGERPRINT_SOURCE_FILES)
    assert {
        "worker.py",
        "scanner.py",
        "attempt_telemetry.py",
        "request_meter.py",
        "build_fingerprint.py",
    } <= names


def test_source_manifest_is_complete_and_hashable_from_checkout():
    root = Path(__file__).resolve().parents[1]
    files = source_file_map(str(root))

    assert all(Path(path).is_file() for path in files.values())
    assert {
        "api.py",
        "asm_inventory.py",
        "command_arsenal.py",
        "family_proof.py",
        "invariant_contracts.py",
        "retest_contract.py",
        "workflow_experiment.py",
        "scanner_tools/access_control_checks.py",
        "scanner_tools/model_intake_semgrep.yml",
        "ai_gate/corpora/arcanum_evasions.json",
        "wordlists/common.txt",
        "payloads/sqli/time-based.txt",
        "runtime/requirements.lock",
        "runtime/entrypoint.sh",
        "runtime/scanner.Dockerfile",
        "model_intake_locks/firecracker-runtime.lock",
        "model_intake_locks/firecracker-guest-worker.py",
        "model_intake_locks/firecracker-guest-init",
        "model_intake_locks/firecracker-guest.Dockerfile",
        "model_intake_locks/semgrep.lock",
    } <= set(files)
    assert hash_source_files(files, require_all=True)


def test_security_rule_guest_lock_and_guest_code_changes_invalidate_fingerprint(tmp_path):
    workspace = tmp_path / "workspace"
    (workspace / "scanner" / "scanner_tools").mkdir(parents=True)
    (workspace / "scanner" / "model_intake_tools").mkdir(parents=True)
    (workspace / "runner" / "guest").mkdir(parents=True)
    (workspace / "scanner" / "payloads" / "sqli").mkdir(parents=True)
    (workspace / "api").mkdir()
    (workspace / "scanner" / "scanner.py").write_text("SCAN = 1\n", encoding="utf-8")
    scanner_dockerfile = workspace / "scanner" / "Dockerfile"
    scanner_dockerfile.write_text("FROM python:3.12\n", encoding="utf-8")
    payload_pack = workspace / "scanner" / "payloads" / "sqli" / "custom.txt"
    payload_pack.write_text("baseline\n", encoding="utf-8")
    (workspace / "api" / "worker.py").write_text("WORKER = 1\n", encoding="utf-8")
    semgrep = workspace / "scanner" / "scanner_tools" / "model_intake_semgrep.yml"
    semgrep.write_text("rules: []\n", encoding="utf-8")
    guest_lock = workspace / "runner" / "guest" / "requirements.lock"
    guest_lock.write_text("torch==2.13.0\n", encoding="utf-8")
    guest_worker = workspace / "runner" / "guest" / "guest_worker.py"
    guest_worker.write_text("RUNTIME = 1\n", encoding="utf-8")
    (workspace / "runner" / "guest" / "guest-init").write_text("#!/bin/sh\n", encoding="utf-8")
    (workspace / "runner" / "guest" / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")

    before = hash_source_files(source_file_map(str(workspace)), require_all=True)
    semgrep.write_text("rules: [changed]\n", encoding="utf-8")
    after_rule = hash_source_files(source_file_map(str(workspace)), require_all=True)
    guest_lock.write_text("torch==2.14.0\n", encoding="utf-8")
    after_lock = hash_source_files(source_file_map(str(workspace)), require_all=True)
    guest_worker.write_text("RUNTIME = 2\n", encoding="utf-8")
    after_guest_code = hash_source_files(source_file_map(str(workspace)), require_all=True)
    scanner_dockerfile.write_text("FROM python:3.13\n", encoding="utf-8")
    after_scanner_dockerfile = hash_source_files(source_file_map(str(workspace)), require_all=True)
    payload_pack.write_text("changed\n", encoding="utf-8")
    after_payload_pack = hash_source_files(source_file_map(str(workspace)), require_all=True)

    assert before and before != after_rule != after_lock != after_guest_code
    assert after_guest_code != after_scanner_dockerfile != after_payload_pack


def test_installed_support_directory_is_not_mistaken_for_source_checkout(tmp_path):
    workspace = tmp_path / "workspace"
    (workspace / "api").mkdir(parents=True)
    (workspace / "api" / "model_intake_control_plane.py").write_text(
        "SUPPORT = 1\n", encoding="utf-8"
    )

    files = source_file_map(str(workspace))

    assert "model_intake_control_plane.py" not in files
    assert files["scanner.py"] == str(workspace / "scanner" / "scanner.py")
    assert hash_source_files(files, require_all=True) is None
