"""The rollback leg of the upgrade smoke must demand exactly the previous-stable schema back.

The first V2-to-V2 candidate (2.0.1 against the 2.0.0 baseline) failed certification with
``rollback retained candidate-only table budget_reservations``: the assertion hardcoded the
tables and migration marker that were candidate-only against the pre-V2 0.8.18 baseline, but
every V2 baseline already owns them, so a correct restore of the pre-upgrade backup was
reported as a failed rollback. The expectations are now derived from an inventory of what the
baseline runtime actually created.
"""

from __future__ import annotations

import asyncio
import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location(
        "upgrade_schema_smoke_under_test", ROOT / "scripts" / "upgrade_schema_smoke.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


V2_TABLES = ["app_schema_migrations", "budget_reservations", "credential_profiles", "targets"]
V2_MIGRATIONS = ["v2_budget_reservations_v2", "v2_target_credentials_to_generic_v1"]


class FakeConn:
    """Answers the two probes the rollback assertion makes against a restored database."""

    def __init__(self, tables, migrations):
        self.tables = set(tables)
        self.migrations = set(migrations)

    async def fetchval(self, sql, *params):
        if "to_regclass" in sql:
            return params[0].removeprefix("public.") in self.tables
        if "app_schema_migrations" in sql:
            return params[0] in self.migrations
        raise AssertionError(f"unexpected probe: {sql}")


@pytest.fixture
def smoke(monkeypatch):
    module = _load()

    async def _fixture_ok(conn, *, upgraded):
        assert upgraded is False

    monkeypatch.setattr(module, "_assert_stable_fixture", _fixture_ok)
    return module


def test_candidate_only_objects_are_the_difference_from_the_baseline(smoke):
    expectations = smoke.rollback_expectations(
        {"tables": ["targets", "scans"], "migrations": ["m1"]},
        {"tables": ["targets", "scans", "brand_new"], "migrations": ["m1", "m2"]},
    )
    assert expectations["tables"] == {
        "absent": ["brand_new"],
        "present": ["scans", "targets"],
        "dropped_by_candidate": [],
    }
    assert expectations["migrations"] == {
        "absent": ["m2"],
        "present": ["m1"],
        "dropped_by_candidate": [],
    }


def test_a_v2_baseline_owning_the_v2_objects_makes_them_baseline_not_candidate_only(smoke):
    baseline = {"tables": V2_TABLES, "migrations": V2_MIGRATIONS}
    expectations = smoke.rollback_expectations(baseline, baseline)
    assert expectations["tables"]["absent"] == []
    assert expectations["migrations"]["absent"] == []
    assert "budget_reservations" in expectations["tables"]["present"]
    assert "v2_budget_reservations_v2" in expectations["migrations"]["present"]


def test_rollback_accepts_v2_objects_the_previous_stable_created(smoke):
    # This is the exact 2.0.1-over-2.0.0 shape: identical schema before and after, and the
    # restored backup carries the V2 tables because the baseline created them.
    baseline = {"tables": V2_TABLES, "migrations": V2_MIGRATIONS}
    expectations = smoke.rollback_expectations(baseline, baseline)
    asyncio.run(smoke._assert_rollback(FakeConn(V2_TABLES, V2_MIGRATIONS), expectations))


def test_rollback_still_rejects_a_retained_candidate_only_table(smoke):
    baseline = {"tables": ["targets"], "migrations": []}
    upgraded = {"tables": ["targets", "candidate_only"], "migrations": ["v2_new"]}
    expectations = smoke.rollback_expectations(baseline, upgraded)
    with pytest.raises(RuntimeError, match="retained candidate-only table candidate_only"):
        asyncio.run(
            smoke._assert_rollback(FakeConn(["targets", "candidate_only"], []), expectations)
        )
    with pytest.raises(RuntimeError, match="retained candidate-only migration v2_new"):
        asyncio.run(
            smoke._assert_rollback(
                FakeConn(["targets", "app_schema_migrations"], ["v2_new"]), expectations
            )
        )


def test_rollback_rejects_a_restore_that_lost_a_previous_stable_object(smoke):
    baseline = {"tables": ["targets", "scans"], "migrations": ["m1"]}
    expectations = smoke.rollback_expectations(baseline, baseline)
    with pytest.raises(RuntimeError, match="lost previous-stable table scans"):
        asyncio.run(smoke._assert_rollback(FakeConn(["targets"], ["m1"]), expectations))
    with pytest.raises(RuntimeError, match="lost previous-stable migration m1"):
        asyncio.run(smoke._assert_rollback(FakeConn(["targets", "scans"], []), expectations))


def test_the_rollback_scenario_requires_both_inventories(smoke, monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv", ["x", "--database-url", "postgresql://x", "--scenario", "rollback"]
    )
    with pytest.raises(SystemExit):
        smoke.main()
    assert "requires --baseline-inventory and --upgraded-inventory" in capsys.readouterr().err
