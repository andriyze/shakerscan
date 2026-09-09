"""Lifecycle code must participate in both source and installed-image freshness."""

from pathlib import Path

import pytest

from scanner.scanner_tools.build_fingerprint import (
    hash_source_files, runtime_file_map, source_file_map,
)


FILES = ("__init__.py", "inventory.py", "router.py", "service.py")


def _layout(root: Path, *, installed: bool) -> Path:
    package = root / ("data_lifecycle" if installed else "api/data_lifecycle")
    package.mkdir(parents=True)
    for name in FILES:
        (package / name).write_text("REVISION = 1\n", encoding="utf-8")
    if not installed:
        (root / "scanner").mkdir()
        (root / "scanner/scanner.py").write_text("SCANNER = 1\n")
        (root / "api/worker.py").write_text("WORKER = 1\n")
    return package


def _map(root: Path, *, installed: bool) -> dict[str, str]:
    if installed:
        return runtime_file_map(str(root), str(root / "locks"), str(root / "inputs"))
    return source_file_map(str(root))


@pytest.mark.parametrize("installed", [False, True], ids=["source", "installed"])
@pytest.mark.parametrize("filename", FILES)
def test_lifecycle_edit_invalidates_freshness(tmp_path, installed, filename):
    package = _layout(tmp_path, installed=installed)
    before = hash_source_files(_map(tmp_path, installed=installed), require_all=True)
    assert before is not None
    (package / filename).write_text("REVISION = 2\n", encoding="utf-8")
    after = hash_source_files(_map(tmp_path, installed=installed), require_all=True)
    assert after is not None and after != before


def test_source_and_installed_layouts_use_identical_lifecycle_keys(tmp_path):
    source, installed = tmp_path / "checkout", tmp_path / "app"
    _layout(source, installed=False)
    _layout(installed, installed=True)
    source_files = {k: v for k, v in _map(source, installed=False).items()
                    if k.startswith("data_lifecycle/")}
    installed_files = {k: v for k, v in _map(installed, installed=True).items()
                       if k.startswith("data_lifecycle/")}
    assert set(source_files) == {f"data_lifecycle/{name}" for name in FILES}
    assert set(installed_files) == set(source_files)
    assert hash_source_files(source_files, require_all=True) == hash_source_files(
        installed_files, require_all=True,
    )


def test_lifecycle_bytecode_does_not_change_freshness(tmp_path):
    package = _layout(tmp_path, installed=False)
    before = hash_source_files(source_file_map(str(tmp_path)), require_all=True)
    cache = package / "__pycache__"
    cache.mkdir()
    (cache / "service.pyc").write_bytes(b"irrelevant cache")
    assert hash_source_files(source_file_map(str(tmp_path)), require_all=True) == before
