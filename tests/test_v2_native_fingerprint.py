from __future__ import annotations

import os
from pathlib import Path
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools.build_fingerprint import (
    V2_API_RUNTIME_PACKAGES,
    hash_source_files,
    runtime_file_map,
    source_file_map,
)


def _write(path: Path, content: str = "x = 1\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_source_fingerprint_natively_includes_every_v2_authority_package(tmp_path):
    root = tmp_path / "workspace"
    _write(root / "scanner" / "scanner.py")
    _write(root / "api" / "worker.py")
    _write(root / "scanner" / "scanner_tools" / "base.py")
    for package in V2_API_RUNTIME_PACKAGES:
        _write(root / "api" / package / "contract.py", f"PACKAGE = {package!r}\n")

    files = source_file_map(str(root))
    for package in V2_API_RUNTIME_PACKAGES:
        assert f"{package}/contract.py" in files
    assert getattr(source_file_map, "_shakerscan_v2_package_fingerprint", False) is True

    before = hash_source_files(files, require_all=True)
    _write(root / "api" / "hunt" / "contract.py", "PACKAGE = 'hunt-v2-changed'\n")
    after = hash_source_files(source_file_map(str(root)), require_all=True)
    assert before and after and before != after


def test_runtime_fingerprint_uses_same_logical_v2_package_keys(tmp_path):
    root = tmp_path / "app"
    _write(root / "worker.py")
    _write(root / "scanner_tools" / "base.py")
    for package in V2_API_RUNTIME_PACKAGES:
        _write(root / package / "contract.py", f"PACKAGE = {package!r}\n")

    files = runtime_file_map(
        str(root),
        model_intake_lock_root=str(tmp_path / "locks"),
        build_input_root=str(tmp_path / "build-inputs"),
    )
    for package in V2_API_RUNTIME_PACKAGES:
        assert f"{package}/contract.py" in files
    assert getattr(runtime_file_map, "_shakerscan_v2_package_fingerprint", False) is True
