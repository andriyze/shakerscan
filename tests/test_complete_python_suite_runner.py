from __future__ import annotations

import json
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from scripts.run_complete_python_suite import (
    SHARD_MANIFEST_SCHEMA,
    CompleteSuiteError,
    _environment,
    _package_import_styles,
    merge_junit_reports,
    merge_shards,
    parse_shard,
    partition_test_files,
    shard_paths,
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
    assert any(
        path.endswith(("site-packages", "dist-packages")) for path in paths
    )


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


def _shard_fixture(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    for name in ("a", "b", "c"):
        (tests / f"test_pkg_{name}.py").write_text(
            "from api.scan import finalizer\n", encoding="utf-8",
        )
    for name in ("a", "b", "c", "d", "e"):
        (tests / f"test_compat_{name}.py").write_text("import api\n", encoding="utf-8")
    return partition_test_files(tmp_path)


def _write_shards(tmp_path, artifacts, count, *, drop=None, duplicate=None):
    package, compatibility = partition_test_files(tmp_path)
    artifacts.mkdir(exist_ok=True)
    for index in range(1, count + 1):
        groups = {
            "package": [p.relative_to(tmp_path).as_posix()
                        for p in shard_paths(package, index, count)],
            "compatibility": [p.relative_to(tmp_path).as_posix()
                              for p in shard_paths(compatibility, index, count)],
        }
        for names in groups.values():
            if drop in names:
                names.remove(drop)
        if duplicate and index == count:
            groups["compatibility"].append(duplicate)
        stem = f"v2-shard-{index}-of-{count}"
        (artifacts / f"{stem}-manifest.json").write_text(json.dumps({
            "schema": SHARD_MANIFEST_SCHEMA, "shard": index, "count": count, **groups,
        }), encoding="utf-8")
        (artifacts / f"{stem}-python.xml").write_text(
            f'<testsuite name="shard{index}" tests="2" failures="0" errors="0" '
            f'skipped="0" time="1.0" />', encoding="utf-8",
        )


def test_shards_split_each_group_into_disjoint_exhaustive_slices():
    root = Path(__file__).resolve().parents[1]
    package, compatibility = partition_test_files(root)
    for group in (package, compatibility):
        slices = [set(shard_paths(group, index, 4)) for index in range(1, 5)]
        assert set().union(*slices) == set(group)
        assert sum(len(part) for part in slices) == len(group)
        assert all(part for part in slices)


@pytest.mark.parametrize("value", ["0/4", "5/4", "1", "a/b", "2/0"])
def test_shard_selector_rejects_impossible_slices(value):
    with pytest.raises(CompleteSuiteError):
        parse_shard(value)


def test_merged_shards_must_cover_the_partition_exactly_once(tmp_path):
    _shard_fixture(tmp_path)
    artifacts = tmp_path / "artifacts"
    _write_shards(tmp_path, artifacts, 3)
    assert merge_shards(tmp_path, artifacts, 3) == 0
    root = ET.parse(artifacts / "v2-full-python.xml").getroot()
    assert root.get("tests") == "6"
    assert len(root.findall("testsuite")) == 3


def test_a_test_file_missing_from_every_shard_fails_the_merge(tmp_path):
    _shard_fixture(tmp_path)
    artifacts = tmp_path / "artifacts"
    _write_shards(tmp_path, artifacts, 2, drop="tests/test_compat_c.py")
    with pytest.raises(CompleteSuiteError, match="ran in no shard"):
        merge_shards(tmp_path, artifacts, 2)


def test_a_test_file_run_by_two_shards_fails_the_merge(tmp_path):
    _shard_fixture(tmp_path)
    artifacts = tmp_path / "artifacts"
    _write_shards(tmp_path, artifacts, 2, duplicate="tests/test_compat_a.py")
    with pytest.raises(CompleteSuiteError, match="ran in shards"):
        merge_shards(tmp_path, artifacts, 2)


def test_a_missing_shard_fails_the_merge(tmp_path):
    _shard_fixture(tmp_path)
    artifacts = tmp_path / "artifacts"
    _write_shards(tmp_path, artifacts, 3)
    (artifacts / "v2-shard-2-of-3-python.xml").unlink()
    with pytest.raises(CompleteSuiteError, match="shard 2/3 produced no JUnit report"):
        merge_shards(tmp_path, artifacts, 3)
    _write_shards(tmp_path, artifacts, 3)
    (artifacts / "v2-shard-3-of-3-manifest.json").unlink()
    with pytest.raises(CompleteSuiteError, match="shard 3/3 produced no manifest"):
        merge_shards(tmp_path, artifacts, 3)


def test_a_failed_shard_report_fails_the_merged_suite(tmp_path):
    _shard_fixture(tmp_path)
    artifacts = tmp_path / "artifacts"
    _write_shards(tmp_path, artifacts, 2)
    (artifacts / "v2-shard-1-of-2-python.xml").write_text(
        '<testsuite name="shard1" tests="2" failures="1" errors="0" skipped="0" time="1" />',
        encoding="utf-8",
    )
    assert merge_shards(tmp_path, artifacts, 2) == 1
