"""The frozen schema baseline must not grow.

``retest_contract._run_schema_migrations_once`` runs only until a database is converted to the
unified target model; ``targets.asset_migration.run_unified_startup`` skips it afterwards. A schema
change or data migration added only there reaches fresh installs but never an upgraded one (2.8.2
shipped ``discovery_runs.requested_by`` that way and every upgraded install answered
``POST /discovery`` with 500).

This test records every SQL statement and every awaited migration helper the baseline (and the
module-level helpers it calls) contains, as digests, and refuses a new one. New schema and data
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


def baseline_entries() -> list[str]:
    """Normalized SQL statements and awaited helper names of the baseline and of the module-level
    functions it reaches, with repeats."""
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE))
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
                called = _called_name(node.value)
                if called:
                    entries.append("await:" + called)
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
