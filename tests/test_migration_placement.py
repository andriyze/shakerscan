"""Schema and data migrations must reach databases that were converted long ago.

``_run_schema_migrations_once`` (api/retest_contract.py) is the frozen baseline: once a database
is converted, ``run_unified_startup`` (api/targets/asset_migration.py) skips it on every later
start. A table, column, index, constraint, trigger, function or view added only there never reaches
an upgraded database. This test inventories the DDL in the baseline as it shipped in 2.8.1 (a
release whose installs are already converted) and fails when the current baseline has an object
that is neither in that inventory nor installed by the always-run path.

Columns are keyed by table (``ADD COLUMN table.column``), with or without ``IF NOT EXISTS``.
Regenerate the frozen inventory only from a released tag:
``SHAKERSCAN_UPDATE_BASELINE_INVENTORY=v2.8.1 pytest tests/test_migration_placement.py``.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import re
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "tests" / "fixtures" / "baseline_schema_inventory.json"
OBJECT = re.compile(
    r"\b(CREATE TABLE|CREATE (?:UNIQUE )?INDEX(?: CONCURRENTLY)?|CREATE (?:OR REPLACE )?FUNCTION|"
    r"CREATE (?:OR REPLACE )?VIEW|CREATE (?:OR REPLACE )?TRIGGER|CREATE TYPE|ADD CONSTRAINT)"
    r"(?:\s+IF NOT EXISTS)?\s+([A-Za-z_][\w.]*)", re.IGNORECASE)
ALTER = re.compile(r"\bALTER TABLE(?:\s+IF EXISTS)?(?:\s+ONLY)?\s+([A-Za-z_][\w.]*)", re.IGNORECASE)
COLUMN = re.compile(r"\bADD COLUMN(?:\s+IF NOT EXISTS)?\s+([A-Za-z_]\w*)", re.IGNORECASE)
KIND = re.compile(r"\b(?:OR REPLACE|UNIQUE|CONCURRENTLY)\s+", re.IGNORECASE)
#: Baseline-only objects known to be missing on converted databases, each with where its fix lives.
#: test_known_gaps_are_still_open fails once one is fixed, so the entry is removed and the guard
#: covers it again.
KNOWN_GAPS = {
    "ADD COLUMN discovery_runs.requested_by": (
        "added by 2.8.2 to the baseline only; the always-run fix ships with 2.8.3 and reaches this "
        "branch when main is merged"),
}


def _function_source(source: str, name: str) -> str:
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name == name:
            return ast.get_source_segment(source, node) or ""
    raise AssertionError(f"{name} not found")


def _inventory(text: str) -> set[str]:
    found = {f"{KIND.sub('', match.group(1)).upper()} {match.group(2).lower()}"
             for match in OBJECT.finditer(text)}
    tables = [(match.start(), match.group(1).lower()) for match in ALTER.finditer(text)]
    for match in COLUMN.finditer(text):
        table = next((name for position, name in reversed(tables) if position < match.start()), "?")
        found.add(f"ADD COLUMN {table}.{match.group(1).lower()}")
    return found


def _always_run_sources() -> str:
    """run_unified_startup and every module it imports to install schema or migrate data."""
    startup = _function_source((ROOT / "api/targets/asset_migration.py").read_text(), "run_unified_startup")
    texts = [startup]
    modules = set(re.findall(r"from (?:api\.)?([\w.]+) import", startup))
    modules |= {f"targets{name}" for name in re.findall(r"from (\.\w+) import", startup)}
    modules |= {f"targets.{name}" for name in re.findall(r'f"\{__package__\}\.(\w+)"', startup)}
    for module in modules:
        relative = module.replace(".", "/") + ".py"
        for base in (ROOT / "api", ROOT):
            if (base / relative).is_file():
                texts.append((base / relative).read_text(encoding="utf-8"))
                break
    return "\n".join(texts)


def _baseline(source: str | None = None) -> str:
    source = source if source is not None else (ROOT / "api/retest_contract.py").read_text(encoding="utf-8")
    return _function_source(source, "_run_schema_migrations_once")


def _frozen() -> set[str]:
    tag = os.environ.get("SHAKERSCAN_UPDATE_BASELINE_INVENTORY")
    if tag:
        shipped = subprocess.run(["git", "show", f"{tag}:api/retest_contract.py"], cwd=ROOT, check=True,
                                 capture_output=True, text=True).stdout
        INVENTORY.write_text(json.dumps({"tag": tag, "objects": sorted(_inventory(_baseline(shipped)))},
                                        indent=1) + "\n", encoding="utf-8")
    return set(json.loads(INVENTORY.read_text(encoding="utf-8"))["objects"])


def _baseline_only(extra: str = "") -> set[str]:
    return _inventory(_baseline() + extra) - _frozen() - _inventory(_always_run_sources())


def test_no_schema_change_lives_only_in_the_converted_db_skipped_baseline():
    unexpected = sorted(_baseline_only() - set(KNOWN_GAPS))
    assert not unexpected, (
        "These schema objects are added only in _run_schema_migrations_once, which never runs on an "
        "already-converted database. Install them from run_unified_startup (the always-run path): "
        f"{unexpected}")


def test_known_gaps_are_still_open():
    """A fixed gap must leave KNOWN_GAPS so the guard above covers it again."""
    assert set(KNOWN_GAPS) <= _baseline_only(), sorted(set(KNOWN_GAPS) - _baseline_only())


def test_the_frozen_inventory_comes_from_a_released_baseline():
    data = json.loads(INVENTORY.read_text(encoding="utf-8"))
    assert re.fullmatch(r"v\d+\.\d+\.\d+", data["tag"]) and len(data["objects"]) > 100
    assert "CREATE TABLE target_instruction_proposals" not in data["objects"]


def test_inventory_reader_sees_the_baseline_and_the_always_run_path():
    """Guards the guard: both sides must actually be read, or the tests above prove nothing."""
    always = _inventory(_always_run_sources())
    assert "CREATE TABLE target_instruction_proposals" in always
    assert "ADD CONSTRAINT target_instruction_proposals_shape" in always
    assert "ADD COLUMN target_instruction_proposals.kind" in always
    assert "CREATE TABLE hunt_credential_uses" in always


@pytest.mark.parametrize("statement", [
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS brand_new_column TEXT;",
    "ALTER TABLE hunt_runs ADD COLUMN IF NOT EXISTS kind TEXT;",  # the name exists on another table
    "ALTER TABLE scans ADD COLUMN status_two TEXT;",  # without IF NOT EXISTS
    "CREATE TABLE brand_new_table (id UUID);",
    "CREATE INDEX idx_brand_new ON scans(id);",
    "CREATE TRIGGER trg_brand_new BEFORE INSERT ON scans FOR EACH ROW EXECUTE FUNCTION f();",
])
def test_the_guard_flags_a_baseline_only_addition(statement):
    assert _baseline_only("\n" + statement) - _baseline_only()


def test_agent_write_origin_migration_runs_unconditionally_on_every_startup():
    startup = _function_source((ROOT / "api/targets/asset_migration.py").read_text(), "run_unified_startup")
    tree = ast.parse(startup)
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and getattr(node.func, "id", None) == "mark_unconfirmed_agent_writes"]
    assert len(calls) == 1
    for gate in (node for node in ast.walk(tree) if isinstance(node, (ast.If, ast.IfExp))):
        assert calls[0] not in list(ast.walk(gate)), "the migration must not sit inside a conditional"
    assert "mark_unconfirmed_agent_writes" not in _baseline()
    assert "target_instruction_proposals" not in _baseline()
