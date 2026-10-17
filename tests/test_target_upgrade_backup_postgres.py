"""The pre-unification backup runs only for a database that holds the operator's data (2.11 C7).

A brand-new database (db/init.sql: the first start, and every `reset`) has the legacy table and
migration markers but no data row; it used to get a full backup on every such start. These run the
real launcher function against a real PostgreSQL database loaded from db/init.sql.
"""
import asyncio
import os
from pathlib import Path
import subprocess
import sys
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
DSN = os.environ.get("TARGET_ASSET_TEST_DATABASE_URL")

# `compose exec -T postgres psql ... -c SQL` answered from the test database (asyncpg, so no psql
# client is needed on the runner).
QUERY_HELPER = r"""
import asyncio, sys, asyncpg
async def main():
    conn = await asyncpg.connect(sys.argv[1])
    try:
        value = await conn.fetchval(sys.argv[2])
    finally:
        await conn.close()
    if isinstance(value, bytes):  # pg_class.relkind is "char"
        value = value.decode()
    print({True: "t", False: "f", None: ""}.get(value, value))
asyncio.run(main())
"""

SCRIPT = r"""
set -e
source "$1"
compose() {
    case "$*" in
        *"/proc/1/comm"*) printf 'postgres\n' ;;
        *pg_isready*) return 0 ;;
        *" psql "*)
            local sql="" prev=""
            for arg in "$@"; do [ "$prev" = "-c" ] && sql="$arg"; prev="$arg"; done
            printf '%s\n' "$sql" >> "$QUERIES"
            python3 -c "$QUERY_HELPER" "$TEST_DSN" "$sql" ;;
    esac
}
create_backup() { echo backup; }
ensure_target_upgrade_backup
echo launch
"""


async def _database(statements: list[str]) -> tuple[str, str]:
    asyncpg = pytest.importorskip("asyncpg")
    admin = await asyncpg.connect(DSN)
    name = "target_backup_" + uuid.uuid4().hex
    try:
        await admin.execute(f'CREATE DATABASE "{name}"')
    finally:
        await admin.close()
    conn = await asyncpg.connect(DSN, database=name)
    try:
        await conn.execute((ROOT / "db/init.sql").read_text())
        for statement in statements:
            await conn.execute(statement)
    finally:
        await conn.close()
    from urllib.parse import urlsplit, urlunsplit
    parts = urlsplit(DSN)
    return name, urlunsplit(parts._replace(path="/" + name))


async def _drop(name: str) -> None:
    import asyncpg
    admin = await asyncpg.connect(DSN)
    try:
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}"')
    finally:
        await admin.close()


def _launcher(statements: list[str], tmp_path: Path) -> list[str]:
    if not DSN:
        pytest.skip("TARGET_ASSET_TEST_DATABASE_URL is not configured")
    name, dsn = asyncio.run(_database(statements))
    try:
        result = subprocess.run(
            ["bash", "-c", SCRIPT, "fixture", str(ROOT / "scripts/target_upgrade_backup.sh")],
            env={**os.environ, "TEST_DSN": dsn, "QUERY_HELPER": QUERY_HELPER, "QUERIES": str(tmp_path / "queries"), "PATH": os.path.dirname(sys.executable) + ":" + os.environ.get("PATH", "")},
            text=True, capture_output=True, timeout=60, check=False,
        )
    finally:
        asyncio.run(_drop(name))
    assert result.returncode == 0, result.stdout + result.stderr
    return [line for line in result.stdout.splitlines() if line in {"backup", "launch"}]


def test_a_brand_new_database_is_not_backed_up(tmp_path):
    assert _launcher([], tmp_path) == ["launch"]
    # The legacy table is there, so the data check ran and found no row of the operator's.
    assert "SELECT false OR EXISTS(SELECT 1 FROM public.targets)" in (tmp_path / "queries").read_text()


@pytest.mark.parametrize("statement", [
    "INSERT INTO targets(url) VALUES('https://backup.test')",
    "INSERT INTO device_targets(name, primary_locator) VALUES('Router', 'router.test')",
])
def test_a_legacy_database_with_the_operators_data_is_backed_up_first(statement, tmp_path):
    assert _launcher([statement], tmp_path) == ["backup", "launch"]
