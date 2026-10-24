"""Real DDL for the scope and approval receipt tables in disposable-PostgreSQL tests.

Both tables are created only by the startup migration (``api/retest_contract.py``). Tests load its
exact statements -- the CREATE TABLE, every ADD COLUMN and the indexes -- instead of a hand-written
copy, so a column the code reads (``approval_receipts.action_context``) cannot be missing from a
test table while every installed database has it. The foreign key between the two tables is kept;
a reference to any other table is removed.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECEIPT_TABLES = ("scope_receipts", "approval_receipts")
_EXECUTED = re.compile(r'\.execute\(\s*"""(.*?)"""', re.DOTALL)
_REFERENCE = re.compile(
    r"\s+REFERENCES\s+(\w+)\s*\([^)]*\)(?:\s+ON\s+DELETE\s+(?:CASCADE|SET NULL|RESTRICT|NO ACTION))?"
)


def _statements_for(source: str, table: str) -> list[str]:
    selected = []
    for statement in _EXECUTED.findall(source):
        text = " ".join(statement.split())
        if text.startswith((f"CREATE TABLE IF NOT EXISTS {table} (", f"ALTER TABLE {table} ")) or re.match(
            rf"CREATE (UNIQUE )?INDEX IF NOT EXISTS \w+ ON {table}\(", text,
        ):
            selected.append(_REFERENCE.sub(
                lambda match: match.group(0) if match.group(1) in RECEIPT_TABLES else "",
                statement.strip(),
            ))
    creates = [item for item in selected if item.startswith(f"CREATE TABLE IF NOT EXISTS {table} (")]
    if len(creates) != 1:
        raise AssertionError(f"the startup migration no longer creates {table} exactly once")
    return selected


def receipt_schema_sql() -> str:
    """scope_receipts then approval_receipts, as the startup migration builds them."""
    source = (ROOT / "api" / "retest_contract.py").read_text(encoding="utf-8")
    return "\n".join(
        statement + ";" for table in RECEIPT_TABLES for statement in _statements_for(source, table)
    )
