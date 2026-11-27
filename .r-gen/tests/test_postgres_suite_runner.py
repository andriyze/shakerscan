"""The database-backed suite finds every database test and fails when one skips for no database.

Unit tests of scripts/run_postgres_suite.py over synthetic JUnit fixtures and this tree's tests;
the real PostgreSQL run is the `python-suite postgres` CI job.
"""
from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET

import yaml

from scripts.run_postgres_suite import (
    ALLOWED_NOT_PASSED,
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


def _skip_type(path: Path, cases: list[tuple[str, str, str | None, str | None]]) -> Path:
    """Like _junit, with the <skipped type> pytest writes (``pytest.xfail`` for an xfail)."""
    suite = ET.Element("testsuite")
    for classname, name, skip, kind in cases:
        case = ET.SubElement(suite, "testcase", classname=classname, name=name)
        if skip is not None:
            ET.SubElement(case, "skipped", message=skip, type=kind or "pytest.skip")
    root = ET.Element("testsuites")
    root.append(suite)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)
    return path


DOMAIN_RATE = {ROOT / "tests" / "test_domain_rate.py": frozenset({"SHAKERSCAN_TEST_REDIS_URL"})}


def test_verify_passes_only_when_every_case_of_every_discovered_file_passed(tmp_path):
    ok = _junit(tmp_path / "ok.xml", [("tests.test_domain_rate", "test_a", None),
                                      ("tests.test_domain_rate.TestLua", "test_b", None)])
    assert verify(ROOT, ok, DOMAIN_RATE) == []
    assert ALLOWED_NOT_PASSED == {}


def test_verify_fails_on_a_skip_for_a_missing_database(tmp_path):
    for reason in ("TARGET_ASSET_TEST_DATABASE_URL is not configured",
                   "disposable PostgreSQL DSN not configured",
                   "set SHAKERSCAN_TEST_REDIS_URL to a disposable Redis to run the Lua itself",
                   "requires explicitly labelled restore fixture",
                   "could not import 'asyncpg': No module named 'asyncpg'"):
        skipped = _junit(tmp_path / "skip.xml", [("tests.test_domain_rate", "test_a", None),
                                                 ("tests.test_domain_rate", "test_b", reason)])
        assert any("missing database" in problem for problem in verify(ROOT, skipped, DOMAIN_RATE)), reason


def test_verify_fails_on_a_reworded_or_unrelated_skip(tmp_path):
    for reason in ("needs PG", "native nmap is not installed"):
        skipped = _junit(tmp_path / "skip.xml", [("tests.test_domain_rate", "test_a", None),
                                                 ("tests.test_domain_rate", "test_b", reason)])
        assert verify(ROOT, skipped, DOMAIN_RATE) == [
            f"skipped or xfailed with a database: tests.test_domain_rate::test_b ({reason})"]


def test_verify_fails_on_a_file_whose_cases_all_xfail(tmp_path):
    xfail = _skip_type(tmp_path / "xfail.xml", [
        ("tests.test_domain_rate", "test_a", "known broken", "pytest.xfail"),
        ("tests.test_domain_rate", "test_b", "known broken", "pytest.xfail"),
    ])
    problems = verify(ROOT, xfail, DOMAIN_RATE)
    assert len([p for p in problems if p.startswith("skipped or xfailed")]) == 2
    assert "discovered file passed no test case: tests/test_domain_rate.py" in problems


def test_verify_fails_on_a_file_with_no_executed_case(tmp_path):
    other = _junit(tmp_path / "other.xml", [("tests.test_domain_rate_x", "test_a", None)])
    assert verify(ROOT, other, DOMAIN_RATE) == [
        "discovered file passed no test case: tests/test_domain_rate.py"]


def test_the_runner_makes_an_xpass_fail():
    source = (ROOT / "scripts" / "run_postgres_suite.py").read_text(encoding="utf-8")
    assert "-o xfail_strict=true" in source


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
    # A reworded reason still counts when its module ran with databases.
    reworded = _junit(tmp_path / "full-reworded.xml", [("tests.test_x_postgres", "test_b", "needs PG")])
    assert len(cross_check(reworded, passed)) == 1
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
    # The validate job runs the suite in its own checkout of the candidate meta verified on main.
    assert "postgres-suite" not in candidate
    certify = "\n".join(step.get("run", "") for step in candidate["certify"]["steps"])
    assert "run_postgres_suite.py --verify" in certify and "--cross-check" in certify
    candidate_run = "\n".join(step.get("run", "") for step in candidate["validate"]["steps"])
    assert "scripts/run_postgres_suite.py" in candidate_run and "--withhold" not in candidate_run


def test_ci_databases_are_the_production_images_and_checkouts_keep_no_token():
    import re

    compose = (ROOT / "docker-compose.release.yml").read_text(encoding="utf-8")
    images = {name: re.search(rf"\$\{{{name}_IMAGE:-([^}}]+)\}}", compose)[1]
              for name in ("POSTGRES", "REDIS")}
    for workflow, job in (("python-suite.yml", "postgres"), ("release-candidate.yml", "validate")):
        spec = yaml.safe_load((WORKFLOWS / workflow).read_text(encoding="utf-8"))["jobs"][job]
        run = "\n".join(step.get("run", "") for step in spec["steps"])
        assert "mirror.gcr.io/library/" + images["POSTGRES"] in run
        redis = "mirror.gcr.io/library/" + images["REDIS"]
        assert redis in run or spec["services"]["redis"]["image"] == redis
        checkouts = [step for step in spec["steps"] if step.get("uses", "").startswith("actions/checkout@")]
        assert checkouts and all(step["with"]["persist-credentials"] is False for step in checkouts)
