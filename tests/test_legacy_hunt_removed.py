"""The legacy web and device Hunt engines are removed: routes, middleware, client and helpers.

Their rows stay in ``agent_hunt_runs`` and ``device_agent_runs`` as history. Startup settles any
run those engines left waiting for a planner, because nothing can continue or cancel it now.
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


def test_the_isolation_middleware_and_the_engine_code_are_gone():
    source = api_tree_source()
    assert not (ROOT / "api" / "hunt" / "legacy.py").exists()
    assert not (ROOT / "api" / "agent_text_toolcalls.py").exists()
    for symbol in (
        "LegacyHuntIsolationMiddleware", "async def run_agent_hunt_endpoint",
        "async def start_agent_hunt_session", "async def submit_agent_hunt_reply",
        "async def _run_agent_hunt(", "async def _agent_apply_reply", "def _agent_hunt_run_public",
        "def _device_agent_run_public", "async def _build_device_agent_context_pack",
        "class AgentHuntRequest", "class AgentHuntReplyRequest", "execute_agent_tool_endpoint",
        "verify_suspected_agent_finding",
    ):
        assert symbol not in source, f"{symbol} survived the legacy Hunt removal"
    assert "verifySuspectedAgentFinding" not in (ROOT / "ui" / "src" / "lib" / "api.ts").read_text()


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


def test_research_keeps_its_internal_launcher_and_planner_without_their_public_aliases():
    tree = api_tree_source()
    assert not route_is_declared("POST", "/research/launch")
    assert route_is_declared("POST", "/research/campaigns/launch")
    assert "async def launch_research_episode" in definition_source("launch_research_episode")
    assert not route_is_declared("POST", "/research/episodes/{episode_id}/plan-step")
    assert "async def plan_research_episode_step" not in tree
    assert "await hub._plan_research_episode_step(" in tree


def test_startup_settles_runs_the_removed_engines_left_waiting_and_keeps_history():
    async def run():
        async with startup_database() as conn:
            module = importlib.import_module('retest_contract')
            await module.run_schema_migrations(BoundConnectionPool(conn))
            target = await conn.fetchval("INSERT INTO targets(url) VALUES('https://legacy.test') RETURNING id")
            waiting, planning, finished = [await conn.fetchval(
                "INSERT INTO agent_hunt_runs(target_id, status, objective) VALUES($1,$2,'old') RETURNING id",
                target, status) for status in ('awaiting_planner', 'planning', 'completed')]

            await module.run_schema_migrations(BoundConnectionPool(conn))

            rows = {row['id']: row for row in await conn.fetch(
                "SELECT id, status, stop_reason, objective FROM agent_hunt_runs")}
            assert len(rows) == 3 and all(row['objective'] == 'old' for row in rows.values())
            for settled in (waiting, planning):
                assert (rows[settled]['status'], rows[settled]['stop_reason']) == (
                    'cancelled', 'legacy_engine_removed')
            assert rows[finished]['status'] == 'completed' and rows[finished]['stop_reason'] is None
            assert await conn.fetchval(
                "SELECT count(*) FROM device_agent_runs WHERE status IN ('awaiting_planner','planning')") == 0
    asyncio.run(run())
