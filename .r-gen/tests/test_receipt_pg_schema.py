"""PostgreSQL tests build the receipt tables from the startup migration, never by hand.

Two test modules wrote their own ``approval_receipts`` without ``action_context``, a column every
installed database has. When the worker's credential gate began to read it, every test on those
tables failed with UndefinedColumnError: the fixture had drifted, not the schema. These checks run
without PostgreSQL, so the drift is caught where the database tests are skipped.
"""
from __future__ import annotations

import re
from pathlib import Path

from tests.receipt_pg_schema import RECEIPT_TABLES, receipt_schema_sql

ROOT = Path(__file__).resolve().parents[1]
_HAND_WRITTEN = re.compile(
    r"CREATE\s+(?:TEMP(?:ORARY)?\s+|UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
    r"(approval_receipts|scope_receipts)\b",
    re.IGNORECASE,
)
_CONSTRAINT_WORDS = {"constraint", "check", "primary", "unique", "foreign"}


def _columns(sql: str, table: str) -> set[str]:
    """Columns the statements give ``table``: its CREATE TABLE body and its ADD COLUMN clauses."""
    create = re.search(rf"CREATE TABLE IF NOT EXISTS {table} \((.*?)\n\s*\);", sql, re.DOTALL)
    assert create, f"no CREATE TABLE for {table}"
    columns = {
        match.group(1).lower()
        for line in create.group(1).splitlines()
        if (match := re.match(r"\s*(\w+)\s+\w", line))
        and match.group(1).lower() not in _CONSTRAINT_WORDS
    }
    for alter in re.findall(rf"ALTER TABLE {table}\b(.*?);", sql, re.DOTALL):
        columns.update(name.lower() for name in re.findall(r"ADD COLUMN IF NOT EXISTS (\w+)", alter))
    return columns


def test_the_receipt_tables_carry_the_columns_the_credential_gate_reads():
    sql = receipt_schema_sql()
    columns = {table: _columns(sql, table) for table in RECEIPT_TABLES}
    assert "action_context" in columns["approval_receipts"]
    source = (ROOT / "api" / "runtime" / "credential_resolver.py").read_text(encoding="utf-8")
    select = re.search(
        r'"""SELECT (.*?)FROM approval_receipts a\s+JOIN scope_receipts s', source, re.DOTALL,
    )
    assert select, "the credential gate's receipt read moved; update this guard"
    read = re.findall(r"\b([as])\.(\w+)", select.group(1))
    assert ("a", "action_context") in read
    aliases = {"a": "approval_receipts", "s": "scope_receipts"}
    missing = [f"{aliases[alias]}.{column}" for alias, column in read
               if column not in columns[aliases[alias]]]
    assert not missing, f"the credential gate reads columns the startup migration never creates: {missing}"


def test_no_test_module_writes_its_own_receipt_table():
    offenders = sorted(
        f"{path.relative_to(ROOT)}: {table}"
        for path in (ROOT / "tests").rglob("*.py")
        if path.resolve() != Path(__file__).resolve()  # this guard's own samples
        for table in _HAND_WRITTEN.findall(path.read_text(encoding="utf-8"))
    )
    assert not offenders, (
        "build scope_receipts/approval_receipts with tests.receipt_pg_schema.receipt_schema_sql(), "
        f"not by hand: {offenders}"
    )


def test_the_guard_recognizes_the_hand_written_form_it_replaced():
    assert _HAND_WRITTEN.search("CREATE TABLE approval_receipts(id UUID PRIMARY KEY, risk_tier TEXT)")
    assert _HAND_WRITTEN.search('CREATE TABLE IF NOT EXISTS scope_receipts (id TEXT PRIMARY KEY)')
    assert not _HAND_WRITTEN.search("CREATE TABLE IF NOT EXISTS model_intake_approval_receipts (")
