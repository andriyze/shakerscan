"""The database-backed suite finds every database test and fails when one skips for no database.

Unit tests of scripts/run_postgres_suite.py over synthetic JUnit fixtures and this tree's tests;
the real PostgreSQL run is the `python-suite postgres` CI job.
"""
from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET

import yaml

from scripts.run_postgres_suite import (
    CONTAINER_ENV,
    POSTGRES_DATABASES,
    PROVISIONED,
    cross_check,
    discover,
    main,
    required_flags,
    service_environment,
    unprovisioned,
    verify,
)

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def _junit(path: Path, cases: list[tuple[str, str, str | None]]) -> Path:
    suite = ET.Element("testsuite")
    for classname, name, skip in cases:
        case = ET.SubElement(suite, "testcase", classname=classname, name=name)
        if skip is not None:
            ET.SubElement(case, "skipped", message=skip)
    root = ET.Element("testsuites")
    root.append(suite)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)
    return path


def test_discovery_finds_every_postgres_file_and_every_test_that_reads_a_test_dsn():
    found = {path.relative_to(ROOT).as_posix(): names for path, names in discover(ROOT).items()}
    assert all(name in found for name in (
        p.relative_to(ROOT).as_posix() for p in (ROOT / "tests").rglob("test_*_postgres.py")))
    # Not named *_postgres.py: found by the variable they read.
    assert "HUNT_TEST_POSTGRES_DSN" in found["tests/test_hunt_action_outcomes.py"]
    assert "SHAKERSCAN_TEST_SCHEDULE_DATABASE_URL" in found["tests/test_managed_schedule_edits.py"]
    assert "SHAKERSCAN_TEST_REDIS_URL" in found["tests/test_domain_rate.py"]
    # Found through the database module it imports its DSN from.
    assert "ASSURANCE_TEST_DATABASE_URL" in found["tests/test_authenticated_validation_worker.py"]
    # Application settings such as DATABASE_URL are not test databases.
    assert "tests/test_broker_worker.py" not in found


def test_every_variable_a_test_reads_is_provisioned_with_its_own_database():
    assert unprovisioned(discover(ROOT)) == {}
    assert len(set(POSTGRES_DATABASES.values())) == len(POSTGRES_DATABASES)
    assert POSTGRES_DATABASES["FINDING_SERVICE_TEST_POSTGRES_DSN"] == "shakerscan_finding_service_test"
    env = service_environment(ROOT, postgres_url="postgresql://postgres@127.0.0.1:5432",
                              redis_url="redis://127.0.0.1:6379", container="pg")
    assert env["TARGET_ASSET_TEST_DATABASE_URL"] == "postgresql://postgres@127.0.0.1:5432/target_assets_test"
    assert env["SSH_TEST_REDIS_URL"] == "redis://127.0.0.1:6379/15" and env[CONTAINER_ENV] == "pg"
    assert set(PROVISIONED) <= set(env)
    assert required_flags(ROOT) and all(env[flag] == "1" for flag in required_flags(ROOT))
    withheld = service_environment(ROOT, postgres_url="postgresql://h", redis_url="redis://h",
                                   container="pg", withhold=("HUNT_TEST_POSTGRES_DSN",))
    assert "HUNT_TEST_POSTGRES_DSN" not in withheld


def test_an_unprovisioned_variable_fails_before_anything_runs(tmp_path):
    # Built at run time, so this file itself reads no unprovisioned variable.
    name = "_".join(("NEW", "TEST", "DATABASE", "URL"))
    found = {tmp_path / "test_new.py": frozenset({name})}
    assert unprovisioned(found) == {name: ["test_new.py"]}


def test_verify_fails_on_a_skip_for_a_missing_database_and_keeps_other_skips(tmp_path):
    found = {ROOT / "tests" / "test_domain_rate.py": frozenset({"SHAKERSCAN_TEST_REDIS_URL"})}
    ok = _junit(tmp_path / "ok.xml", [
        ("tests.test_domain_rate", "test_a", None),
        ("tests.test_domain_rate", "test_b", "native nmap is not installed"),
    ])
    assert verify(ROOT, ok, found) == []
    for reason in ("TARGET_ASSET_TEST_DATABASE_URL is not configured",
                   "disposable PostgreSQL DSN not configured",
                   "set SHAKERSCAN_TEST_REDIS_URL to a disposable Redis to run the Lua itself",
                   "requires explicitly labelled restore fixture",
                   "could not import 'asyncpg': No module named 'asyncpg'"):
        skipped = _junit(tmp_path / "skip.xml", [("tests.test_domain_rate", "test_a", reason)])
        assert any("missing database" in problem for problem in verify(ROOT, skipped, found)), reason


def test_verify_fails_when_a_discovered_file_produced_no_test_case(tmp_path):
    found = {ROOT / "tests" / "test_domain_rate.py": frozenset({"SHAKERSCAN_TEST_REDIS_URL"})}
    other = _junit(tmp_path / "other.xml", [("tests.test_domain_rate_x", "test_a", None)])
    assert verify(ROOT, other, found) == [
        "discovered file produced no test case: tests/test_domain_rate.py"]


def test_cross_check_requires_every_database_skip_of_the_complete_suite_to_pass(tmp_path):
    full = _junit(tmp_path / "full.xml", [
        ("tests.test_x_postgres", "test_a", "TARGET_ASSET_TEST_DATABASE_URL is not configured"),
        ("tests.test_y", "test_b", "explicit installed Chromium path required"),
        ("tests.test_y", "test_c", None),
    ])
    passed = _junit(tmp_path / "pg.xml", [("tests.test_x_postgres", "test_a", None)])
    assert cross_check(full, passed) == []
    missing = _junit(tmp_path / "pg-missing.xml", [("tests.test_other", "test_a", None)])
    assert len(cross_check(full, missing)) == 1
    assert main(["--cross-check", str(full), str(missing)]) == 1


def test_ci_requires_the_postgres_job_and_the_candidate_certifies_with_it():
    suite = yaml.safe_load((WORKFLOWS / "python-suite.yml").read_text(encoding="utf-8"))["jobs"]
    run = "\n".join(step.get("run", "") for step in suite["postgres"]["steps"])
    assert "scripts/run_postgres_suite.py" in run and "--withhold" not in run
    assert "postgres" in suite["python-suite"]["needs"]
    aggregate = "\n".join(step.get("run", "") for step in suite["python-suite"]["steps"])
    assert '"$POSTGRES" != success' in aggregate
    assert "run_postgres_suite.py --cross-check artifacts/v2-full-python.xml" in aggregate
    candidate = yaml.safe_load(
        (WORKFLOWS / "release-candidate.yml").read_text(encoding="utf-8"))["jobs"]
    assert "postgres-suite" in candidate["certify"]["needs"]
    certify = "\n".join(step.get("run", "") for step in candidate["certify"]["steps"])
    assert "run_postgres_suite.py --verify" in certify and "--cross-check" in certify
    candidate_run = "\n".join(step.get("run", "") for step in candidate["postgres-suite"]["steps"])
    assert "scripts/run_postgres_suite.py" in candidate_run and "--withhold" not in candidate_run
