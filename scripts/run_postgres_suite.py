#!/usr/bin/env python3
"""Run every database-backed Python test against real PostgreSQL and Redis, with no env skips.

The complete Python suite runs without databases, so every test that needs a disposable
PostgreSQL database or Redis skips there. This runner is the other half of that contract:

* it discovers the database-backed test files from source (``*_postgres.py`` files, and any
  test file that reads, directly or through a ``tests`` module it imports, a ``*TEST*_DSN``,
  ``*TEST*_DATABASE_URL``, ``*TEST*_REDIS_URL`` or ``*TEST*_POSTGRES_CONTAINER`` variable);
* it refuses to run when a discovered variable has no provisioning entry below;
* it creates a separate database for every PostgreSQL variable, sets every
  ``*_POSTGRES_REQUIRED`` flag, and runs the discovered files with the same import-layout
  partition and whole-group collection the complete suite uses;
* ``--verify`` fails when any test in a discovered file skipped, xfailed or xpassed (unless it is
  on the commented ALLOWED_NOT_PASSED list), failed, or when a discovered file passed no case;
* ``--cross-check`` fails when a test that the database-less complete suite skipped for a missing
  database, or skipped in a module run here, did not pass here, so a database-backed test outside the discovery rule cannot hide.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit, urlunsplit
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.run_complete_python_suite import (  # noqa: E402
    SHARD_SELECT_ENV,
    _run_group,
    merge_junit_reports,
    partition_test_files,
)

SERVICE_ENV = re.compile(
    r"^[A-Z][A-Z0-9_]*TEST[A-Z0-9_]*_(?:DSN|DATABASE_URL|REDIS_URL|POSTGRES_CONTAINER)$"
)
REQUIRED_FLAG = re.compile(r"^[A-Z][A-Z0-9_]*_POSTGRES_REQUIRED$")
# Skip reasons that mean "no database/Redis was provided". Other skips (a missing browser,
# native tool or release-only schema) are reported but belong to other gates.
ENV_SKIP = re.compile(
    r"postgres|database|\bdsn\b|_dsn\b|database_url|redis|restore fixture|asyncpg",
    re.IGNORECASE,
)

# Each variable gets its own database. Modules that read the same variable share that database,
# as they do in their dedicated workflows, and run one after another.
POSTGRES_DATABASES = {
    "ASSURANCE_TEST_DATABASE_URL": "shakerscan_assurance_test",
    "COLLECTION_TEST_DATABASE_URL": "shakerscan_collection_retry_test",
    "CREDENTIAL_GRANTS_TEST_DATABASE_URL": "shakerscan_credential_grants_test",
    "DISCOVERED_SECRETS_TEST_DATABASE_URL": "shakerscan_discovered_secrets_test",
    "DISCOVERY_TEST_DATABASE_URL": "shakerscan_discovery_test",
    "EVIDENCE_INTEGRITY_TEST_DATABASE_URL": "shakerscan_evidence_integrity_test",
    "FINDINGS_PROOF_SQL_TEST_DATABASE_URL": "shakerscan_proof_sql_test",
    "FINDING_SERVICE_TEST_POSTGRES_DSN": "shakerscan_finding_service_test",
    "FINDING_VERDICT_TEST_DATABASE_URL": "shakerscan_verdict_test",
    "HUNT_TEST_POSTGRES_DSN": "hunt_records",
    "LIFECYCLE_TEST_DATABASE_URL": "shakerscan_lifecycle_test",
    "LIST_CONTRACT_TEST_DATABASE_URL": "shakerscan_list_contract_test",
    "SERVICE_INTELLIGENCE_TEST_DATABASE_URL": "shakerscan_service_intelligence_test",
    "SHAKERSCAN_TEST_HUNT_LEDGER_DSN": "shakerscan_hunt_ledger_test",
    "SHAKERSCAN_TEST_PUBLIC_RETRY_DSN": "shakerscan_public_retry_test",
    "SHAKERSCAN_TEST_SCHEDULE_DATABASE_URL": "maintenance_test",
    "SUBDOMAIN_TARGETS_TEST_DATABASE_URL": "shakerscan_subdomain_test",
    "TARGET_ASSET_TEST_DATABASE_URL": "target_assets_test",
}
REDIS_DATABASES = {
    "SHAKERSCAN_TEST_REDIS_URL": 14,
    "SSH_TEST_REDIS_URL": 15,
}
# The dump/restore acceptance inspects the labelled, auto-removed container behind the DSN.
CONTAINER_ENV = "ASSURANCE_TEST_POSTGRES_CONTAINER"
PROVISIONED = frozenset((*POSTGRES_DATABASES, *REDIS_DATABASES, CONTAINER_ENV))
REPORT = "postgres-python.xml"
# Test ids (``classname::name``) in a discovered file that may legitimately skip or xfail here,
# each with a comment saying why. Anything else that does not pass fails the job.
ALLOWED_NOT_PASSED: dict[str, str] = {}


class PostgresSuiteError(RuntimeError):
    """The database-backed suite is incomplete or skipped for a missing database."""


def _string_literals(tree: ast.AST) -> set[str]:
    return {
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }


def _local_imports(tree: ast.AST, tests_root: Path) -> set[Path]:
    """Modules under ``tests/`` that a test file imports (``tests.x`` or ``from tests import x``)."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    paths = set()
    for name in names:
        parts = name.split(".")
        if parts[0] != "tests" or len(parts) < 2:
            continue
        candidate = tests_root.joinpath(*parts[1:]).with_suffix(".py")
        if candidate.is_file():
            paths.add(candidate.resolve())
    return paths


def _service_names(
    path: Path, tests_root: Path, cache: dict[Path, frozenset[str]], visiting: set[Path],
) -> frozenset[str]:
    """Service variables a test module reads itself or through the ``tests`` modules it imports."""
    path = path.resolve()
    if path in cache:
        return cache[path]
    if path in visiting:
        return frozenset()
    visiting.add(path)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names = {value for value in _string_literals(tree) if SERVICE_ENV.match(value)}
    for dependency in _local_imports(tree, tests_root):
        names.update(_service_names(dependency, tests_root, cache, visiting))
    visiting.discard(path)
    cache[path] = frozenset(names)
    return cache[path]


def discover(repo_root: Path) -> dict[Path, frozenset[str]]:
    """Every database-backed test file, with the service variables it needs."""
    tests_root = (repo_root / "tests").resolve()
    cache: dict[Path, frozenset[str]] = {}
    found = {}
    for path in sorted(tests_root.rglob("test_*.py")):
        names = _service_names(path, tests_root, cache, set())
        if path.name.endswith("_postgres.py"):
            names |= {"*_postgres.py"}
        if names:
            found[path.resolve()] = names
    if not found:
        raise PostgresSuiteError("no database-backed test files were discovered")
    return found


def required_flags(repo_root: Path) -> tuple[str, ...]:
    flags = set()
    for path in (repo_root / "tests").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        flags.update(value for value in _string_literals(tree) if REQUIRED_FLAG.match(value))
    return tuple(sorted(flags))


def unprovisioned(found: dict[Path, frozenset[str]]) -> dict[str, list[str]]:
    missing: dict[str, list[str]] = {}
    for path, names in found.items():
        for name in sorted(names - PROVISIONED - {"*_postgres.py"}):
            missing.setdefault(name, []).append(path.name)
    return missing


def _with_database(server_url: str, database: str) -> str:
    parts = urlsplit(server_url)
    return urlunsplit(parts._replace(path="/" + database, query="", fragment=""))


def service_environment(
    repo_root: Path, *, postgres_url: str, redis_url: str, container: str,
    withhold: tuple[str, ...] = (),
) -> dict[str, str]:
    env = {name: _with_database(postgres_url, db) for name, db in POSTGRES_DATABASES.items()}
    env.update({name: _with_database(redis_url, str(db)) for name, db in REDIS_DATABASES.items()})
    env[CONTAINER_ENV] = container
    env.update({flag: "1" for flag in required_flags(repo_root)})
    for name in withhold:
        env.pop(name, None)
    return env


async def _create_databases(postgres_url: str) -> None:
    import asyncpg

    conn = await asyncpg.connect(_with_database(postgres_url, "postgres"))
    try:
        existing = {row["datname"] for row in await conn.fetch("SELECT datname FROM pg_database")}
        for database in sorted(set(POSTGRES_DATABASES.values()) - existing):
            # Names come from the fixed table above, never from input.
            await conn.execute(f'CREATE DATABASE "{database}"')
    finally:
        await conn.close()


def _module_prefix(repo_root: Path, path: Path) -> str:
    return ".".join(path.relative_to(repo_root).with_suffix("").parts)


def _cases(report: Path) -> list[ET.Element]:
    if not report.is_file():
        raise PostgresSuiteError(f"missing JUnit report {report}")
    return list(ET.parse(report).getroot().iter("testcase"))


def _case_id(case: ET.Element) -> str:
    return f"{case.get('classname', '')}::{case.get('name', '')}"


def _outcome(case: ET.Element) -> str:
    for tag in ("failure", "error", "skipped"):
        if case.find(tag) is not None:
            return tag
    return "passed"


def verify(repo_root: Path, report: Path, found: dict[Path, frozenset[str]]) -> list[str]:
    """Every discovered file must pass at least one case and skip or xfail none.

    The runner sets ``xfail_strict``, so an xpass is a failure and an xfail is a skip here.
    """
    cases = _cases(report)
    problems = []
    for case in cases:
        if _outcome(case) == "skipped" and _case_id(case) not in ALLOWED_NOT_PASSED:
            skip = case.find("skipped")
            reason = (skip.get("message") or skip.text or "").strip()
            kind = ("skipped for a missing database" if ENV_SKIP.search(reason)
                    else "skipped or xfailed with a database")
            problems.append(f"{kind}: {_case_id(case)} ({reason})")
    for path in found:
        prefix = _module_prefix(repo_root, path)
        own = [case for case in cases if case.get("classname", "") == prefix
               or case.get("classname", "").startswith(prefix + ".")]
        if not any(_outcome(case) == "passed" for case in own):
            problems.append(f"discovered file passed no test case: {path.relative_to(repo_root)}")
    if any(_outcome(case) in {"failure", "error"} for case in cases):
        problems.append("database-backed tests failed")
    if not cases:
        problems.append("the database-backed suite ran no test")
    return problems


def cross_check(full_report: Path, report: Path) -> list[str]:
    """Every case the complete suite skipped for a missing database, or skipped in a module this
    suite ran, must have passed here."""
    cases = _cases(report)
    passed = {_case_id(case) for case in cases if _outcome(case) == "passed"}
    modules = {case.get("classname", "") for case in cases}
    problems = []
    for case in _cases(full_report):
        skip = case.find("skipped")
        if skip is None or _case_id(case) in passed:
            continue
        reason = (skip.get("message") or skip.text or "").strip()
        if ENV_SKIP.search(reason) or case.get("classname", "") in modules:
            problems.append(f"skipped in the complete suite and not passed with databases: "
                            f"{_case_id(case)} ({reason})")
    return problems


def _summary(cases: list[ET.Element]) -> str:
    skipped = sum(case.find("skipped") is not None for case in cases)
    return f"{len(cases)} cases, {len(cases) - skipped} executed, {skipped} skipped"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--artifacts-dir", type=Path, default=Path("artifacts"))
    parser.add_argument("--postgres-url", help="server URL, e.g. postgresql://postgres@127.0.0.1:5432")
    parser.add_argument("--redis-url", help="server URL, e.g. redis://127.0.0.1:6379")
    parser.add_argument("--postgres-container", default="",
                        help="name of the labelled disposable container behind --postgres-url")
    parser.add_argument("--withhold", action="append", default=[], metavar="VARIABLE",
                        help="leave one service variable unset (proves --verify fails)")
    parser.add_argument("--list", action="store_true", help="print the discovered files and exit")
    parser.add_argument("--verify", type=Path, metavar="REPORT",
                        help="only check an existing database-backed report")
    parser.add_argument("--cross-check", nargs=2, type=Path, metavar=("FULL_REPORT", "REPORT"),
                        help="require every env-skipped test of FULL_REPORT to pass in REPORT")
    args = parser.parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]

    if args.cross_check:
        problems = cross_check(*args.cross_check)
        for problem in problems:
            print(f"::error::{problem}")
        if not problems:
            print("every test the complete suite skipped for a missing database passed with one")
        return 1 if problems else 0

    found = discover(repo_root)
    missing = unprovisioned(found)
    if args.list:
        for path, names in found.items():
            print(f"{path.relative_to(repo_root)}\t{' '.join(sorted(names))}")
        print(f"{len(found)} database-backed test files")
    if missing:
        for name, files in sorted(missing.items()):
            print(f"::error::{name} has no provisioning entry in scripts/run_postgres_suite.py "
                  f"(read by {', '.join(files)})")
        return 1
    if args.list:
        return 0

    artifacts = (repo_root / args.artifacts_dir).resolve()
    report = artifacts / REPORT
    if args.verify is None:
        if not args.postgres_url or not args.redis_url:
            parser.error("--postgres-url and --redis-url are required to run the suite")
        asyncio.run(_create_databases(args.postgres_url))
        os.environ.update(service_environment(
            repo_root, postgres_url=args.postgres_url, redis_url=args.redis_url,
            container=args.postgres_container, withhold=tuple(args.withhold),
        ))
        # An unexpected pass of an xfail test fails; an xfail is reported as a skip and verified.
        os.environ["PYTEST_ADDOPTS"] = (os.environ.get("PYTEST_ADDOPTS", "") + " -o xfail_strict=true").strip()
        artifacts.mkdir(parents=True, exist_ok=True)
        package, compatibility = partition_test_files(repo_root)
        reports, failed_groups = [], []
        for name, paths, native in (("package", package, True),
                                    ("compatibility", compatibility, False)):
            select = tuple(path for path in paths if path.resolve() in found)
            group_report = artifacts / f"postgres-{name}-python.xml"
            group_report.unlink(missing_ok=True)
            code = _run_group(
                repo_root, name=f"postgres {name}", paths=paths, package_native=native,
                collect_only=False, coverage=False, coverage_file=artifacts / ".coverage.pg",
                junit_path=group_report, select=select,
                select_file=artifacts / f"postgres-{name}-files.json",
            )
            if select:
                reports.append(group_report)
            if code:
                failed_groups.append(f"{name} (pytest exit {code})")
        os.environ.pop(SHARD_SELECT_ENV, None)
        merge_junit_reports(tuple(reports), report)
        (artifacts / "postgres-manifest.json").write_text(json.dumps({
            "files": {str(path.relative_to(repo_root)): sorted(names)
                      for path, names in found.items()},
            "withheld": sorted(args.withhold),
        }, indent=2) + "\n", encoding="utf-8")
    else:
        report = args.verify.resolve()

    cases = _cases(report)
    problems = verify(repo_root, report, found)
    if args.verify is None:
        problems += [f"pytest failed in the {group} group" for group in failed_groups]
    print(f"database-backed suite: {len(found)} files, {_summary(cases)}")
    for problem in problems:
        print(f"::error::{problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
