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
    } <= set(files)
    assert hash_source_files(files, require_all=True)
