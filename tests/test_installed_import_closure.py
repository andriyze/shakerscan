"""The public installer must ship every module its installed files import.

`install/index.sh` is a hand-maintained list of `download` lines. The API and workers run from
images containing the whole tree, so the list only covers what runs on the HOST -- the CLI and the
provisioners it calls. That made omissions invisible in development and fatal on a real install:
the exact-head installer smoke failed with `ModuleNotFoundError: No module named
'runtime.json_fields'`, because `api/runtime/receipts.py` imports it with a hard relative import and
the manifest did not list it. Nothing in CI could see the drift.

This gate closes that loop: it recomputes the transitive first-party import closure of the
installed files and fails when any reachable module is missing.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _checker():
    path = ROOT / "scripts" / "check_installed_import_closure.py"
    spec = importlib.util.spec_from_file_location("installed_import_closure_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = _checker()


def test_the_installer_ships_its_whole_import_closure():
    missing = checker.missing_modules()
    assert not missing, (
        "install/index.sh does not ship these modules, which installed files import: "
        + "; ".join(
            f"{target} <- {sorted(reachers)[0]}" for target, reachers in sorted(missing.items())
        )
    )


def test_the_modules_the_audit_named_are_shipped():
    # Regression anchors for the two the release audit reported by name.
    installed = checker.installed_paths()
    assert "api/runtime/json_fields.py" in installed
    assert "api/model_intake_runner_storage.py" in installed


def test_relative_imports_are_followed():
    # The omission that broke the installer is a hard `from .json_fields import ...`. A closure that
    # only followed absolute imports would have reported OK on the broken manifest.
    reached = checker.imported_paths("api/runtime/receipts.py")
    assert "api/runtime/json_fields.py" in reached


def test_every_download_line_names_a_file_that_exists():
    # A manifest entry for a deleted file makes the installer fail late, on the operator's machine.
    missing_on_disk = sorted(
        path for path in checker.installed_paths()
        if not (ROOT / path).exists()
    )
    assert not missing_on_disk, f"install/index.sh downloads files that no longer exist: {missing_on_disk}"


def test_the_checker_detects_a_removed_module():
    # Prove the gate bites rather than trivially passing: drop a known-required line and confirm the
    # closure reports it.
    original = (ROOT / "install" / "index.sh").read_text(encoding="utf-8")
    needle = 'download "$REPO_RAW_BASE/api/runtime/json_fields.py" "$INSTALL_DIR/api/runtime/json_fields.py"\n'
    assert needle in original
    try:
        (ROOT / "install" / "index.sh").write_text(original.replace(needle, "", 1), encoding="utf-8")
        missing = checker.missing_modules()
        assert "api/runtime/json_fields.py" in missing
    finally:
        (ROOT / "install" / "index.sh").write_text(original, encoding="utf-8")
    assert not checker.missing_modules()
