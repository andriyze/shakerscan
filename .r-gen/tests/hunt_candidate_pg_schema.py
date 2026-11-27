"""Real DDL for the disposable-PostgreSQL candidate tests.

The candidate tables are created by the startup migration (``api/retest_contract.py``) and the
evidence tables by ``db/init.sql``. Tests load those exact statements instead of a hand-written
copy, so a predicate on a real column (for example ``hunt_actions.status``) is actually exercised.
Foreign keys to tables these tests do not create are removed; everything else is kept.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_TABLES = ("investigation_candidates", "investigation_candidate_observations")
EVIDENCE_TABLES = ("hunt_actions", "http_transactions", "findings")
_KEPT_REFERENCES = set(CANDIDATE_TABLES)
_REFERENCE = re.compile(
    r"\s+REFERENCES\s+(\w+)\s*\([^)]*\)(?:\s+ON\s+DELETE\s+(?:CASCADE|SET NULL|RESTRICT|NO ACTION))?"
)


def _strip_foreign_references(statement: str) -> str:
    return _REFERENCE.sub(
        lambda match: match.group(0) if match.group(1) in _KEPT_REFERENCES else "", statement,
    )


def _init_sql_table(sql: str, name: str) -> str:
    match = re.search(r"CREATE TABLE (?:IF NOT EXISTS )?%s \(.*?\n\);" % name, sql, re.S)
    if match is None:
        raise AssertionError(f"db/init.sql no longer creates {name}")
    return _strip_foreign_references(match.group(0))


def _migration_statements(source: str, table: str) -> list[str]:
    """The migration's CREATE TABLE, ADD COLUMN and CREATE INDEX statements for one table."""
    statements = re.findall(r'await conn\.execute\("""(.*?)"""\)', source, re.S)
    selected = []
    for statement in statements:
        text = " ".join(statement.split())
        if (
            text.startswith(f"CREATE TABLE IF NOT EXISTS {table} (")
            or text.startswith(f"ALTER TABLE {table} ADD COLUMN")
            or re.match(rf"CREATE (UNIQUE )?INDEX IF NOT EXISTS \w+ ON {table}\(", text)
        ):
            selected.append(_strip_foreign_references(statement.strip()))
    if not selected:
        raise AssertionError(f"the startup migration no longer creates {table}")
    return selected


def candidate_schema_sql() -> str:
    init_sql = (ROOT / "db" / "init.sql").read_text(encoding="utf-8")
    migration = (ROOT / "api" / "retest_contract.py").read_text(encoding="utf-8")
    parts = [_init_sql_table(init_sql, name) for name in EVIDENCE_TABLES]
    for table in CANDIDATE_TABLES:
        parts.extend(statement + ";" for statement in _migration_statements(migration, table))
    return "\n".join(parts)


def migration_index_names(table: str) -> set[str]:
    migration = (ROOT / "api" / "retest_contract.py").read_text(encoding="utf-8")
    return {
        match.group(1)
        for statement in _migration_statements(migration, table)
        if (match := re.search(r"INDEX IF NOT EXISTS (\w+)", statement))
    }
