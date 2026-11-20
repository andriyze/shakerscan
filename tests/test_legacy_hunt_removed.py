"""The legacy web and device Hunt engines are removed: routes, middleware, client and helpers.

Their tables (``agent_hunt_runs``, ``device_agent_runs``, ``device_agent_actions``) are dropped at
startup.
"""
from __future__ import annotations

import asyncio
import importlib
from pathlib import Path

from tests.api_sources import api_tree_source, declared_routes, definition_source, route_is_declared
from tests.test_target_asset_startup_postgres import BoundConnectionPool, startup_database

ROOT = Path(__file__).resolve().parents[1]


def test_no_route_remains_under_the_legacy_hunt_surfaces():
    for prefix in ("/agent/hunt", "/device-agent"):
        assert declared_routes(prefix) == (), f"{prefix} still declares routes"
    assert not route_is_declared("POST", "/devices/{device_id}/agent/session")
    # Unrelated agent reads that were never part of the engines stay.
    assert route_is_declared("GET", "/agent/findings/{target_id}")
    assert route_is_declared("GET", "/agent/tools/readiness")
    assert route_is_declared("POST", "/hunts/{hunt_id}/capabilities/{capability_name:path}")



def test_nothing_reads_or_writes_the_legacy_run_tables_outside_schema_and_retention():
    """The tables are history: only the schema, startup settlement and data lifecycle name them."""
    allowed = {"api/retest_contract.py", "api/targets/asset_migration.py", "api/target_dedupe.py",
               "api/data_lifecycle/inventory.py", "api/data_lifecycle/statuses.py"}
    offenders = []
    for path in sorted((ROOT / "api").rglob("*.py")):
        relative = path.relative_to(ROOT).as_posix()
        if relative in allowed:
            continue
        text = path.read_text()
        for statement in ("FROM agent_hunt_runs", "FROM device_agent_runs", "FROM device_agent_actions",
                          "INTO agent_hunt_runs", "INTO device_agent_runs", "INTO device_agent_actions",
                          "UPDATE agent_hunt_runs", "UPDATE device_agent_runs"):
            if statement in text:
                offenders.append(f"{relative}: {statement}")
    assert offenders == []



def test_startup_drops_the_removed_engines_tables_and_keeps_what_pointed_at_them():
    async def run():
        async with startup_database() as conn:
            module = importlib.import_module('retest_contract')
            await module.run_schema_migrations(BoundConnectionPool(conn))
            # A second start, as on every restart, finds nothing to drop and nothing missing.
            await module.run_schema_migrations(BoundConnectionPool(conn))

            for table in ('agent_hunt_runs', 'device_agent_runs', 'device_agent_actions'):
                assert await conn.fetchval("SELECT to_regclass($1)", table) is None
            # A candidate that named a legacy run keeps the identifier as plain data.
            columns = {row['column_name'] for row in await conn.fetch(
                "SELECT column_name FROM information_schema.columns WHERE table_name='investigation_candidates'")}
            assert {'agent_hunt_run_id', 'device_agent_run_id'} <= columns
    asyncio.run(run())
