"""The frozen schema baseline must not grow.

``retest_contract._run_schema_migrations_once`` runs only until a database is converted to the
unified target model; ``targets.asset_migration.run_unified_startup`` skips it afterwards. A schema
change or data migration added only there reaches fresh installs but never an upgraded one (2.8.2
shipped ``discovery_runs.requested_by`` that way and every upgraded install answered
``POST /discovery`` with 500).

This test records every SQL statement, every awaited migration helper or method (a store's
``ensure_schema``, ``module.migrate_x``), every statement run from a name (``conn.execute(NEW_SQL)``)
and every loop over statements the baseline (and the module-level helpers it calls) contains, as
digests, and refuses a new one. The bodies of helpers in other modules are not read: their own
changes are not caught here. New schema and data
migrations belong in the always-run section of ``run_unified_startup``. If a baseline edit is
genuinely needed (and the same change also reaches converted databases), update
``tests/fixtures/schema_baseline_frozen.json`` with the digest the failure names.
"""
from __future__ import annotations

import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "api" / "retest_contract.py"
FIXTURE = ROOT / "tests" / "fixtures" / "schema_baseline_frozen.json"
BASELINE = "_run_schema_migrations_once"
SQL = re.compile(r"\b(ALTER|CREATE|DROP|INSERT|UPDATE|DELETE|COMMENT|TRUNCATE)\b", re.IGNORECASE)


def _text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return ast.unparse(node)
    return None


def _called_name(node: ast.Call) -> str | None:
    return node.func.id if isinstance(node.func, ast.Name) else None


# Connection methods that run SQL; their non-literal first argument is recorded by its source.
_EXECUTES = frozenset({"execute", "executemany", "fetch", "fetchrow", "fetchval"})


def baseline_entries(source: str | None = None) -> list[str]:
    """Normalized SQL statements and awaited helper names of the baseline and of the module-level
    functions it reaches, with repeats."""
    tree = ast.parse(source if source is not None else SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE))
    functions = {
        node.name: node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert BASELINE in functions, f"{BASELINE} moved; update this guard"
    entries: list[str] = []
    seen: set[str] = set()
    pending = [BASELINE]
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        for node in ast.walk(functions[name]):
            text = _text(node)
            if text is not None and SQL.search(text):
                entries.append("sql:" + " ".join(text.split()))
            if isinstance(node, ast.Await) and isinstance(node.value, ast.Call):
                call = node.value
                called = _called_name(call)
                if called:
                    entries.append("await:" + called)
                elif isinstance(call.func, ast.Attribute) and call.func.attr in _EXECUTES:
                    # ``conn.execute(NEW_SQL)``: a statement held in a name, built or imported.
                    if call.args and _text(call.args[0]) is None:
                        entries.append("execute:" + ast.unparse(call.args[0]))
                elif isinstance(call.func, ast.Attribute):
                    # ``Store().ensure_schema(conn)``, ``module.migrate_x(conn)``.
                    entries.append("await:" + ast.unparse(call.func))
            if isinstance(node, (ast.For, ast.AsyncFor)):
                # ``for statement in NEW_STATEMENTS: await conn.execute(statement)``.
                entries.append("for:" + ast.unparse(node.iter))
            if isinstance(node, ast.Call):
                called = _called_name(node)
                if called in functions and called not in seen:
                    pending.append(called)
    return entries


def digest(entry: str) -> str:
    return hashlib.sha256(entry.encode("utf-8")).hexdigest()[:20]


def test_the_frozen_baseline_gains_no_statement_or_migration():
    recorded = Counter(json.loads(FIXTURE.read_text(encoding="utf-8"))["digests"])
    current = baseline_entries()
    by_digest = {digest(entry): entry for entry in current}
    added = Counter(digest(entry) for entry in current) - recorded
    assert not added, (
        "New schema or migration in the frozen baseline (retest_contract._run_schema_migrations_once), "
        "which a converted database never runs again. Put it in the always-run section of "
        "targets.asset_migration.run_unified_startup instead:\n"
        + "\n".join(f"  {key}: {by_digest[key][:160]}" for key in sorted(added))
    )


def test_the_guard_sees_the_statements_that_2_8_2_misplaced():
    """The guard would have refused the 2.8.2 additions: they are recognized entries."""
    for entry in (
        "sql:ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS requested_by TEXT",
        "await:recompute_spanning_target_roots",
        "await:repair_target_host_spellings",
    ):
        assert digest(entry) not in json.loads(FIXTURE.read_text(encoding="utf-8"))["digests"]
    entries = baseline_entries()
    assert len(entries) > 100  # the walk reaches the baseline's statements, not an empty body
    assert any(entry.startswith("await:") for entry in entries)


@pytest.mark.parametrize("addition", [
    'await conn.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS fixture_column TEXT")',
    'await conn.execute("ALTER TABLE " + "scans ADD COLUMN fixture_column TEXT")',
    "await conn.execute(FIXTURE_NEW_DDL)",
    "for fixture_statement in FIXTURE_NEW_STATEMENTS:\n                await conn.execute(fixture_statement)",
    "await FixtureStore().ensure_schema(conn)",
    "await fixture_module.migrate_fixture(conn)",
    "await migrate_fixture_rows(conn)",
])
def test_the_guard_refuses_each_way_of_adding_a_migration(addition):
    """Each form a new migration takes in the baseline is a new entry."""
    source = SOURCE.read_text(encoding="utf-8")
    anchor = "            # Scan and Hunt capability budgets share one durable reservation store."
    assert source.count(anchor) == 1
    changed = source.replace(anchor, "            " + addition + "\n" + anchor)
    recorded = Counter(json.loads(FIXTURE.read_text(encoding="utf-8"))["digests"])
    added = Counter(digest(entry) for entry in baseline_entries(changed)) - recorded
    assert added, addition


def _startup_source() -> str:
    source = (ROOT / "api" / "targets" / "asset_migration.py").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "run_unified_startup":
            return ast.get_source_segment(source, node) or ""
    raise AssertionError("run_unified_startup moved; update this guard")


@pytest.mark.parametrize("called", ["mark_unconfirmed_agent_writes", "recompute_spanning_target_roots"])
def test_always_run_migrations_are_not_behind_a_conditional(called):
    """The always-run section runs on every start: a migration inside an ``if`` (such as the
    "not yet converted" branch) would again reach fresh installs only."""
    tree = ast.parse(_startup_source())
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and _called_name(node) == called]
    assert len(calls) == 1, called
    for gate in (node for node in ast.walk(tree) if isinstance(node, (ast.If, ast.IfExp))):
        assert calls[0] not in list(ast.walk(gate)), f"{called} sits inside a conditional"


def test_the_proposal_schema_is_installed_by_the_always_run_path():
    startup = _startup_source()
    assert "INSTRUCTION_PROPOSAL_SCHEMA_SQL" in startup
    for entry in baseline_entries():
        assert "target_instruction_proposals" not in entry and "mark_unconfirmed_agent_writes" not in entry
