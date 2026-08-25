from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from scripts.run_complete_python_suite import (
    CompleteSuiteError,
    _environment,
    _package_import_styles,
    merge_junit_reports,
    partition_test_files,
)


def test_partition_is_exhaustive_disjoint_and_keeps_import_worlds_separate():
    root = Path(__file__).resolve().parents[1]
    package, compatibility = partition_test_files(root)
    discovered = set((root / "tests").rglob("test_*.py"))

    assert set(package).isdisjoint(compatibility)
    assert set(package) | set(compatibility) == discovered
    assert all("package" in _package_import_styles(path, root) for path in package)
    assert all(
        "package" not in _package_import_styles(path, root)
        for path in compatibility
    )


def test_partition_rejects_a_test_that_imports_both_api_layouts(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_mixed.py").write_text(
        "import api\nfrom api.scan import finalizer\n", encoding="utf-8",
    )
    (tests / "test_compat.py").write_text("value = 1\n", encoding="utf-8")

    with pytest.raises(CompleteSuiteError, match="mixes package and compatibility"):
        partition_test_files(tmp_path)


@pytest.mark.parametrize("package_native", [True, False])
def test_partition_environment_preserves_the_launch_interpreters_packages(package_native):
    root = Path(__file__).resolve().parents[1]
    env = _environment(root, package_native=package_native)
    paths = env["PYTHONPATH"].split(":")

    assert str(root) in paths
    assert str(root / "api") in paths
    assert str(root / "scanner") in paths
    assert any(path.endswith("site-packages") for path in paths)


def test_junit_reports_are_combined_without_losing_suite_totals(tmp_path):
    first = tmp_path / "first.xml"
    second = tmp_path / "second.xml"
    output = tmp_path / "full.xml"
    first.write_text(
        '<testsuites><testsuite name="package" tests="2" failures="1" '
        'errors="0" skipped="0" time="0.5" /></testsuites>',
        encoding="utf-8",
    )
    second.write_text(
        '<testsuite name="compatibility" tests="3" failures="0" '
        'errors="1" skipped="1" time="1.25" />',
        encoding="utf-8",
    )

    merge_junit_reports((first, second), output)

    root = ET.parse(output).getroot()
    assert root.attrib == {
        "name": "v2-full-python",
        "tests": "5",
        "failures": "1",
        "errors": "1",
        "skipped": "1",
        "time": "1.750000",
    }
    assert [suite.get("name") for suite in root.findall("testsuite")] == [
        "package", "compatibility",
    ]
