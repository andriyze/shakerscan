"""A Hunt action refused for budget is admitted on retry once the budget is raised.

Before E2 the budget-shortage branch of admission stored a ``failed`` row, and every retry with
the same key replayed that refusal, even after an operator raised the budget. Only pre-E2
interfaces are imported, so the test fails on a462871a for the bug itself. Real PostgreSQL; the
audit redactor is a labelled double and admission stops at dispatch.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit
import uuid

import pytest
from fastapi import HTTPException

DSN = os.environ.get("HUNT_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")
ROOT = Path(__file__).resolve().parents[1]


def _table(ddl: str, name: str) -> str:
    return re.search(rf"CREATE TABLE {name} \(.*?\n\);", ddl, re.S)[0]


class Admitted(Exception):
    pass


def test_a_budget_refused_action_is_admitted_on_retry_after_the_budget_is_raised(monkeypatch):
    import asyncpg

    from hunt import interaction_router as router
    from hunt.action_service import HUNT_ACTION_SERVICE, HuntActionLifecycle
    from hunt.budget_amendments import HuntBudgetAmendmentRequest, apply_budget_amendment
    from hunt.credential_uses import HUNT_CREDENTIAL_USES_SCHEMA_SQL
    from hunt.start_contract import HUNT_BUDGET_PROFILES
    from runtime.reservation_store import BUDGET_RESERVATION_SCHEMA_SQL

    class StopAtDispatch(HuntActionLifecycle):
        def advance(self, phase):
            super().advance(phase)
            if phase == "dispatching":
                raise Admitted()

    assert urlsplit(DSN).hostname in {"localhost", "127.0.0.1", "::1", "postgres"}
    schema = "hunt_retry_" + uuid.uuid4().hex

    async def scenario():
        conn = await asyncpg.connect(DSN)
        pool = None
        try:
            await conn.execute(f'CREATE SCHEMA "{schema}"; SET search_path TO "{schema}"')
            ddl = (ROOT / "db/init.sql").read_text()
            await conn.execute("""CREATE TABLE targets(id UUID PRIMARY KEY, url TEXT, is_active BOOLEAN NOT NULL DEFAULT true,
                                                     metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb);
                                  CREATE TABLE device_targets(id UUID PRIMARY KEY)""")
            for table in ("hunt_runs", "hunt_actions", "hunt_budget_amendments", "hunt_credential_uses"):
                await conn.execute(_table(ddl, table))
            await conn.execute(HUNT_CREDENTIAL_USES_SCHEMA_SQL)
            await conn.execute(BUDGET_RESERVATION_SCHEMA_SQL)
            try:  # present from E2 on; absent before it
                from hunt.permission_store import HUNT_PERMISSION_SCHEMA_SQL
            except ImportError:
                HUNT_PERMISSION_SCHEMA_SQL = None
            if HUNT_PERMISSION_SCHEMA_SQL:
                await conn.execute(HUNT_PERMISSION_SCHEMA_SQL)
            target = uuid.uuid4()
            await conn.execute("INSERT INTO targets(id,url) VALUES($1,'https://app.example.test')", target)
            budget = dict(vars(HUNT_BUDGET_PROFILES["fast"]))
            for key in ("max_state_changing_requests", "max_udp_ports", "max_tcp_ports", "max_hosts",
                        "max_oob_interactions", "max_device_fragility_points", "max_active_actions"):
                budget[key] = 0
            budget["max_capability_calls"] = 1
            policy = {"allowed_capabilities": ["http.request"], "budget": budget, "active_testing": False}
            context = {"target": {"url": "https://app.example.test", "origins": ["https://app.example.test"]},
                       "authorized_target_addresses": ["203.0.113.10"], "credential_refs": []}
            hunt = await conn.fetchrow(
                """INSERT INTO hunt_runs(target_kind,target_id,status,budget_profile,policy_json,budget_json,
                                         budget_used_json,context_pack)
                   VALUES('web',$1,'active','fast',$2::jsonb,$3::jsonb,$4::jsonb,$5::jsonb) RETURNING *""",
                target, json.dumps(policy), json.dumps(budget), json.dumps({"agent_actions": 1}),
                json.dumps(context),
            )
            pool = await asyncpg.create_pool(DSN, min_size=1, max_size=4, server_settings={"search_path": schema})
            monkeypatch.setattr(router, "_pool", lambda: pool)
            monkeypatch.setattr(router, "_hunt_redacted_capability_input", lambda _name, values: dict(values))

            async def call():
                request = router.HuntCapabilityRequest(idempotency_key="retry-key-0001",
                                                       input={"method": "GET", "path": "/"})
                await router._require_executable_hunt_or_recorded_action(str(hunt["id"]), request.idempotency_key)
                prepared = HUNT_ACTION_SERVICE.prepare("http.request", request.input)
                lifecycle = StopAtDispatch(specification=prepared.specification)
                lifecycle.advance("validated")
                try:
                    return await router._execute_hunt_capability_lifecycle(
                        str(hunt["id"]), "http.request", request, lifecycle)
                except Admitted:
                    return "admitted"

            with pytest.raises(HTTPException) as refused:
                await call()
            assert refused.value.status_code == 409
            async with pool.acquire() as amend_conn:
                async with amend_conn.transaction():
                    await apply_budget_amendment(amend_conn, hunt["id"], HuntBudgetAmendmentRequest(
                        limits={"max_capability_calls": 5}, expected_revision=0,
                        idempotency_key="operator-raise", operator_confirmed=True, resume=True))
            # Before the fix this replayed the stored failed refusal, forever.
            assert await call() == "admitted"
            action = await conn.fetchrow("SELECT status FROM hunt_actions")
            assert action["status"] == "reserved"
            assert await conn.fetchval("SELECT COUNT(*) FROM budget_reservations WHERE status='reserved'") == 1
        finally:
            if pool is not None:
                await pool.close()
            await conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
            await conn.close()

    asyncio.run(scenario())
