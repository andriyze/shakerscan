"""An upgraded database must have exactly the schema of a fresh install of the same code.

``tests/fixtures/upgrade_schemas/*.sql.gz`` are databases as released engines left them: that
release's ``db/init.sql`` plus its own startup, so converted to the unified target model (recorded
by ``scripts/generate_upgrade_schema_fixture.py``). Each is restored, the current startup runs on
it, and its catalog is compared with a fresh install (current ``db/init.sql`` plus the current
startup): columns with types, nullability and defaults, indexes, constraints, triggers, functions,
views and the recorded ``app_schema_migrations`` names. Any difference fails.

This covers schema owned by store ``ensure_schema`` helpers and module ``*_SCHEMA_SQL`` constants
that the static baseline guard (tests/test_schema_baseline_frozen.py) cannot read: whatever reaches
a fresh install must also reach an installed release.
"""
from __future__ import annotations

import asyncio
import gzip
import importlib
from pathlib import Path

import pytest

from targets.asset_migration import BoundConnectionPool
from tests.test_target_asset_startup_postgres import startup_database

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "upgrade_schemas"
RELEASES = sorted(path.name[:-len(".sql.gz")] for path in FIXTURES.glob("*.sql.gz"))

CATALOG = {
    "column": """SELECT c.relname, c.relkind::text, a.attname, format_type(a.atttypid, a.atttypmod),
                        a.attnotnull::text, COALESCE(pg_get_expr(d.adbin, d.adrelid), '')
                 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                 JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
                 LEFT JOIN pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
                 WHERE n.nspname = 'public' AND c.relkind IN ('r', 'v', 'm', 'p')""",
    "index": "SELECT tablename, indexname, indexdef FROM pg_indexes WHERE schemaname = 'public'",
    "constraint": """SELECT conrelid::regclass::text, conname, pg_get_constraintdef(oid)
                     FROM pg_constraint WHERE connamespace = 'public'::regnamespace""",
    "trigger": """SELECT tgrelid::regclass::text, tgname, pg_get_triggerdef(oid)
                  FROM pg_trigger WHERE NOT tgisinternal""",
    "function": """SELECT p.proname, pg_get_function_identity_arguments(p.oid), md5(pg_get_functiondef(p.oid))
                   FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.prokind = 'f'""",
    "view": "SELECT viewname, md5(definition) FROM pg_views WHERE schemaname = 'public'",
    "sequence": "SELECT sequencename, data_type::text FROM pg_sequences WHERE schemaname = 'public'",
    "migration": "SELECT name FROM app_schema_migrations",
}


def _check_text(definition: str) -> str:
    """A CHECK expression without grouping parentheses.

    A release database is recorded with pg_dump and restored, and PostgreSQL re-deparses a
    restored CHECK with flatter grouping (``a AND (b AND c)`` comes back as ``a AND b AND c``)
    than the same constraint created from its source. Every operand, operator and literal is still
    compared.
    """
    return " ".join(definition.replace("(", " ").replace(")", " ").split())


async def catalog(conn) -> set[tuple[str, ...]]:
    found: set[tuple[str, ...]] = set()
    for kind, query in CATALOG.items():
        for row in await conn.fetch(query):
            values = [str(value) for value in row]
            if kind == "constraint" and values[2].startswith("CHECK "):
                values[2] = _check_text(values[2])
            found.add((kind, *values))
    return found


async def _startup(conn) -> None:
    await importlib.import_module("retest_contract").run_schema_migrations(BoundConnectionPool(conn))


def _release_sql(release: str, server_version: int) -> str:
    text = gzip.decompress((FIXTURES / f"{release}.sql.gz").read_bytes()).decode("utf-8")
    if server_version < 170000:  # a newer pg_dump's setting an older server does not know
        text = "".join(line for line in text.splitlines(keepends=True)
                       if not line.startswith("SET transaction_timeout"))
    return text


def _describe(items: set[tuple[str, ...]]) -> str:
    return "\n".join("  " + " | ".join(value[:140] for value in item) for item in sorted(items)[:60])


def test_fixtures_cover_a_long_converted_release_and_the_previous_release():
    assert {"v2.8.1", "v2.8.3"} <= set(RELEASES)
    for release in RELEASES:
        text = gzip.decompress((FIXTURES / f"{release}.sql.gz").read_bytes()).decode("utf-8")
        assert "INSERT INTO public.app_schema_migrations VALUES ('unified_target_assets_v1'" in text, release
        assert not any(line.startswith("\\") for line in text.splitlines()), "psql meta-commands"
    # The 2.8.1 database is the shape 2.8.2's misplaced column never reached (2.8.3 repairs it), so
    # the comparison exercises that repair.
    shipped = gzip.decompress((FIXTURES / "v2.8.1.sql.gz").read_bytes()).decode("utf-8")
    runs = shipped[shipped.index("CREATE TABLE public.discovery_runs"):]
    assert "requested_by" not in runs[:runs.index(");")]


@pytest.mark.parametrize("release", RELEASES)
def test_an_upgraded_release_has_the_schema_of_a_fresh_install(release):
    async def run():
        async with startup_database() as fresh:
            await _startup(fresh)
            await _startup(fresh)  # a restart changes nothing either
            expected = await catalog(fresh)
            version = int(await fresh.fetchval("SHOW server_version_num"))
            # startup_database applies the current init.sql; this database must instead start as
            # the release left it.
            await fresh.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
            await fresh.execute(_release_sql(release, version))
            await fresh.execute("RESET search_path")
            assert await fresh.fetchval(
                "SELECT count(*) FROM app_schema_migrations WHERE name='unified_target_assets_v1'") == 1
            baseline_calls = []
            module = importlib.import_module("retest_contract")
            original = module._run_schema_migrations_once

            async def recorded(pool):
                baseline_calls.append(1)
                return await original(pool)
            module._run_schema_migrations_once = recorded
            try:
                await _startup(fresh)
            finally:
                module._run_schema_migrations_once = original
            assert baseline_calls == [], "a converted database must not rerun the frozen baseline"
            upgraded = await catalog(fresh)
        missing, extra = expected - upgraded, upgraded - expected
        assert not missing and not extra, (
            f"After upgrading {release} the schema differs from a fresh install.\n"
            f"Only on a fresh install ({len(missing)}):\n{_describe(missing)}\n"
            f"Only on the upgraded {release} ({len(extra)}):\n{_describe(extra)}")
    asyncio.run(run())
