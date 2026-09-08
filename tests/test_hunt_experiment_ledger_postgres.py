"""Opt-in real PostgreSQL ledger reads; isolated schema, not deployment acceptance."""

import asyncio
import json
import os
import re
import uuid
from pathlib import Path

import pytest

from api.hunt.run_service import HuntRunService


def test_concurrent_actions_survive_fresh_service_and_connections():
    dsn = os.environ.get("SHAKERSCAN_TEST_HUNT_LEDGER_DSN")
    if not dsn:
        pytest.skip("requires an explicitly selected disposable PostgreSQL instance")
    asyncpg = pytest.importorskip("asyncpg")

    async def run():
        schema = "hunt_ledger_test_" + uuid.uuid4().hex
        control = await asyncpg.connect(dsn)
        pool = None
        try:
            await control.execute(f'CREATE SCHEMA "{schema}"')
            await control.execute(f'SET search_path TO "{schema}",public')
            await control.execute("CREATE TABLE targets(id UUID PRIMARY KEY); "
                                  "CREATE TABLE device_targets(id UUID PRIMARY KEY)")
            ddl = (Path(__file__).resolve().parents[1] / "db/init.sql").read_text()
            for name in ("hunt_runs", "hunt_actions", "hunt_skill_events"):
                statement = re.search(rf"CREATE TABLE {name} \(.*?\n\);", ddl, re.DOTALL)
                assert statement is not None
                await control.execute(statement[0])
            target, hunt, other = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
            await control.execute("INSERT INTO targets VALUES($1)", target)
            for identifier in (hunt, other):
                await control.execute(
                    "INSERT INTO hunt_runs(id,target_kind,target_id) VALUES($1,'web',$2)",
                    identifier, target,
                )
            pool = await asyncpg.create_pool(dsn, min_size=1, max_size=4,
                                            server_settings={"search_path": schema + ",public"})

            async def append(index):
                async with pool.acquire() as conn:
                    await conn.execute(
                        "INSERT INTO hunt_actions(id,hunt_run_id,capability_name,status,input_summary) "
                        "VALUES($1,$2,'collections.inspect','running',$3)",
                        uuid.uuid4(), hunt,
                        json.dumps({"experiment_key": "a" * 32, "fixture_attempt": index}),
                    )

            await asyncio.gather(*(append(index) for index in range(10)))
            await pool.close()
            pool = await asyncpg.create_pool(dsn, min_size=1, max_size=2,
                                            server_settings={"search_path": schema + ",public"})
            service = HuntRunService(lambda: pool)
            restored = await service.get(str(hunt))
            assert len(restored["actions"]) == 10
            assert len({action["action_id"] for action in restored["actions"]}) == 10
            assert all(action["experiment_key"] == "a" * 32 for action in restored["actions"])
            assert all(action["status"] == "running" for action in restored["actions"])
            assert (await service.get(str(other)))["actions"] == []
        finally:
            if pool is not None:
                await pool.close()
            await control.execute(f'DROP SCHEMA "{schema}" CASCADE')
            await control.close()

    asyncio.run(run())
