#!/usr/bin/env python3
"""Run every Python test without mixing incompatible API import layouts.

The source checkout intentionally supports two import layouts during the V2
migration: package-native modules (``api.scan.*`` and
``scanner.scanner_tools.*``) and installed-runtime compatibility modules
(``api.py``, ``scanner.py``, and their siblings).  Importing both layouts in one
interpreter makes collection order decide which implementation subsequent tests
receive.  This runner partitions tests by their static import contract and
executes both exhaustive groups in fresh interpreters.
"""

from __future__ import annotations

import argparse
import ast
import os
from pathlib import Path
import site
import subprocess
import sys
import xml.etree.ElementTree as ET


class CompleteSuiteError(RuntimeError):
    """The complete-suite partition or artifact contract is invalid."""


def _local_module_paths(
    repo_root: Path, module: str, imported_names: tuple[str, ...] = (),
) -> tuple[Path, ...]:
    if not module:
        return ()
    base = repo_root.joinpath(*module.split("."))
    candidates = [base.with_suffix(".py"), base / "__init__.py"]
    candidates.extend(
        base / f"{name}.py"
        for name in imported_names
        if name != "*" and name.isidentifier()
    )
    return tuple(path for path in candidates if path.is_file())


def _package_import_styles(
    path: Path,
    repo_root: Path | None = None,
    *,
    _cache: dict[Path, frozenset[str]] | None = None,
    _visiting: set[Path] | None = None,
) -> frozenset[str]:
    path = path.resolve()
    repo_root = (repo_root or path.parents[1]).resolve()
    cache = _cache if _cache is not None else {}
    visiting = _visiting if _visiting is not None else set()
    if path in cache:
        return cache[path]
    if path in visiting:
        return frozenset()
    visiting.add(path)
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError) as exc:
        raise CompleteSuiteError(f"cannot inspect {path}: {exc}") from exc
    styles: set[str] = set()
    local_dependencies: set[Path] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {"api", "scanner"}:
                    styles.add("compatibility")
                elif alias.name.startswith(("api.", "scanner.")):
                    styles.add("package")
                else:
                    local_dependencies.update(
                        _local_module_paths(repo_root, alias.name)
                    )
        elif isinstance(node, ast.ImportFrom):
            module = str(node.module or "")
            if module in {"api", "scanner"} or module.startswith(
                ("api.", "scanner.")
            ):
                styles.add("package")
            elif node.level == 0:
                imported_names = tuple(alias.name for alias in node.names)
                local_dependencies.update(
                    _local_module_paths(repo_root, module, imported_names)
                )
    for dependency in local_dependencies:
        styles.update(_package_import_styles(
            dependency,
            repo_root,
            _cache=cache,
            _visiting=visiting,
        ))
    visiting.remove(path)
    result = frozenset(styles)
    cache[path] = result
    return result


def partition_test_files(repo_root: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    tests_root = repo_root / "tests"
    discovered = tuple(sorted(tests_root.rglob("test_*.py")))
    if not discovered:
        raise CompleteSuiteError("no Python tests were discovered")
    cache: dict[Path, frozenset[str]] = {}
    package: list[Path] = []
    compatibility: list[Path] = []
    for path in discovered:
        styles = _package_import_styles(path, repo_root, _cache=cache)
        if styles == {"package", "compatibility"}:
            raise CompleteSuiteError(
                f"{path.relative_to(repo_root)} mixes package and compatibility api imports"
            )
        (package if "package" in styles else compatibility).append(path)
    assigned = set(package) | set(compatibility)
    if assigned != set(discovered) or set(package) & set(compatibility):
        raise CompleteSuiteError("complete-suite partition is not exhaustive and disjoint")
    if not package or not compatibility:
        raise CompleteSuiteError("both API import-layout groups must contain tests")
    return tuple(package), tuple(compatibility)


def _suite_elements(path: Path) -> list[ET.Element]:
    root = ET.parse(path).getroot()
    if root.tag == "testsuite":
        return [root]
    if root.tag == "testsuites":
        return list(root.findall("testsuite"))
    raise CompleteSuiteError(f"unexpected JUnit root in {path}: {root.tag}")


def merge_junit_reports(inputs: tuple[Path, ...], output: Path) -> None:
    suites: list[ET.Element] = []
    for path in inputs:
        if path.exists():
            suites.extend(_suite_elements(path))
    if not suites:
        raise CompleteSuiteError("no JUnit reports were produced")
    totals: dict[str, float] = {
        "tests": 0,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
        "time": 0.0,
    }
    for suite in suites:
        for name in ("tests", "failures", "errors", "skipped"):
            totals[name] += int(suite.get(name, "0"))
        totals["time"] += float(suite.get("time", "0"))
    root = ET.Element("testsuites", {
        "name": "v2-full-python",
        "tests": str(int(totals["tests"])),
        "failures": str(int(totals["failures"])),
        "errors": str(int(totals["errors"])),
        "skipped": str(int(totals["skipped"])),
        "time": f"{totals['time']:.6f}",
    })
    for suite in suites:
        root.append(suite)
    output.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(root).write(output, encoding="utf-8", xml_declaration=True)


def _environment(repo_root: Path, *, package_native: bool) -> dict[str, str]:
    api_root = repo_root / "api"
    scanner_root = repo_root / "scanner"
    ordered = (
        (repo_root, api_root, scanner_root)
        if package_native
        else (api_root, scanner_root, repo_root)
    )
    # A source checkout intentionally puts ``scanner/`` on PYTHONPATH so its
    # security ``sitecustomize`` can install frozen DNS for canonical worker
    # subprocesses. On Homebrew Python that also changes the automatically
    # selected prefix site-packages directory from ``/opt/homebrew/lib`` to the
    # Cellar path, which can hide the pytest/coverage installation used to
    # launch this runner. Preserve only the current interpreter's package roots
    # after the deliberate repository import order.
    package_roots = [
        Path(value).resolve()
        for value in [*site.getsitepackages(), site.getusersitepackages()]
        if value and Path(value).is_dir()
    ]
    paths = list(ordered)
    for path in package_roots:
        if path not in paths:
            paths.append(path)
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(str(path) for path in paths)
    return env


def _run_group(
    repo_root: Path,
    *,
    name: str,
    paths: tuple[Path, ...],
    package_native: bool,
    collect_only: bool,
    coverage: bool,
    coverage_file: Path,
    junit_path: Path | None,
) -> int:
    pytest_args = ["-q", "-p", "no:cacheprovider"]
    if collect_only:
        pytest_args.extend(["-q", "--collect-only"])
    if junit_path is not None:
        pytest_args.append(f"--junitxml={junit_path}")
    pytest_args.extend(str(path.relative_to(repo_root)) for path in paths)
    command = [sys.executable]
    if coverage:
        command.extend([
            "-m", "coverage", "run", "--parallel-mode",
            "--source=api,scanner", "-m", "pytest",
        ])
    else:
        command.extend(["-m", "pytest"])
    command.extend(pytest_args)
    env = _environment(repo_root, package_native=package_native)
    if coverage:
        env["COVERAGE_FILE"] = str(coverage_file)
    print(f"[{name}] {len(paths)} files", flush=True)
    return subprocess.run(command, cwd=repo_root, env=env, check=False).returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--collect-only", action="store_true")
    parser.add_argument("--coverage", action="store_true")
    parser.add_argument("--artifacts-dir", type=Path, default=Path("artifacts"))
    args = parser.parse_args(argv)
    if args.collect_only and args.coverage:
        parser.error("--collect-only and --coverage are mutually exclusive")

    repo_root = Path(__file__).resolve().parents[1]
    package, compatibility = partition_test_files(repo_root)
    artifacts = (repo_root / args.artifacts_dir).resolve()
    coverage_file = artifacts / ".coverage.v2"
    if not args.collect_only:
        artifacts.mkdir(parents=True, exist_ok=True)
    if args.coverage:
        for stale in artifacts.glob(f"{coverage_file.name}*"):
            stale.unlink()

    reports = {
        "package": artifacts / "v2-package-python.xml",
        "compatibility": artifacts / "v2-compatibility-python.xml",
    }
    results = [
        _run_group(
            repo_root,
            name="package-native",
            paths=package,
            package_native=True,
            collect_only=args.collect_only,
            coverage=args.coverage,
            coverage_file=coverage_file,
            junit_path=None if args.collect_only else reports["package"],
        ),
        _run_group(
            repo_root,
            name="installed-runtime compatibility",
            paths=compatibility,
            package_native=False,
            collect_only=args.collect_only,
            coverage=args.coverage,
            coverage_file=coverage_file,
            junit_path=None if args.collect_only else reports["compatibility"],
        ),
    ]
    if args.collect_only:
        return 1 if any(results) else 0

    merge_junit_reports(
        (reports["package"], reports["compatibility"]),
        artifacts / "v2-full-python.xml",
    )
    if args.coverage:
        env = dict(os.environ)
        env["COVERAGE_FILE"] = str(coverage_file)
        combine = subprocess.run(
            [sys.executable, "-m", "coverage", "combine", str(artifacts)],
            cwd=repo_root, env=env, check=False,
        ).returncode
        xml = subprocess.run(
            [
                sys.executable, "-m", "coverage", "xml", "-o",
                str(artifacts / "v2-coverage.xml"),
            ],
            cwd=repo_root, env=env, check=False,
        ).returncode if combine == 0 else combine
        results.extend([combine, xml])
    return 1 if any(results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
