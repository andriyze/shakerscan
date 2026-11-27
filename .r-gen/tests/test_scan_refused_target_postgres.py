"""A Scan refused at admission leaves no target behind (real PostgreSQL; run by the target-assets
job). The target row used to be committed before the DNS check, so a typo -- or `scan help` --
left a target such as https://help in the inventory although no scan was ever queued."""
import asyncio
import os
import socket

import pytest
from fastapi import HTTPException

from targets.asset_migration import BoundConnectionPool
from tests.receipt_pg_schema import receipt_schema_sql
from tests.test_target_asset_migration_postgres import database
from tests.test_target_asset_psl_postgres import _converted
from tests.test_target_asset_inputs_postgres import encryption


def test_a_scan_refused_at_dns_admission_leaves_no_target(monkeypatch):
    from api import api as api_module
    import target_resolution

    encryption(monkeypatch)

    async def dns_alias(_pool, target, **_kwargs):
        return target, None, None, None

    async def no_op(*_args, **_kwargs):
        return None

    async def unresolvable(_hostname):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(target_resolution, "system_lookup", unresolvable)
    monkeypatch.setattr(api_module, "get_redis", lambda: object())
    monkeypatch.setattr(api_module.target_dns_alias, "prepare_scan_dns_alias", dns_alias)
    monkeypatch.setattr(api_module, "_worker_freshness_snapshot", lambda: {"available": False})
    monkeypatch.setattr(api_module, "_require_approval_receipt_if_policy_enabled", no_op)
    monkeypatch.setattr(api_module, "_require_reachable_fleet_placement", no_op)

    async def run():
        async with database() as conn:
            await _converted(conn)
            monkeypatch.setattr(api_module, "db_pool", BoundConnectionPool(conn))
            with pytest.raises(HTTPException) as refused:
                await api_module._submit_scan(api_module.ScanRequest(
                    target="https://help", policy={"active_testing": False}))
            rows = await conn.fetch(
                "SELECT url FROM targets WHERE url IN ('https://help', 'host://help')")
            return refused.value, [row["url"] for row in rows]

    refused, rows = asyncio.run(run())
    assert refused.status_code == 422
    assert rows == []


def test_a_refused_receipt_keeps_its_blocked_audit_row_but_no_target(monkeypatch):
    """Admission is one transaction, so its rollback must not take the refusal's audit row with it.

    A submission whose approval receipt does not exist writes a durable 'blocked' command result
    before it raises. Inside the admission transaction that row was rolled back with the target.
    """
    import uuid

    from api import api as api_module
    from tests.test_target_asset_migration_postgres import _real_asyncpg

    encryption(monkeypatch)
    missing_receipt = str(uuid.uuid4())

    async def dns_alias(_pool, target, *, supplied_receipt_id=None, **_kwargs):
        return target, None, None, supplied_receipt_id

    async def no_op(*_args, **_kwargs):
        return None

    monkeypatch.setattr(api_module, "get_redis", lambda: object())
    monkeypatch.setattr(api_module.target_dns_alias, "prepare_scan_dns_alias", dns_alias)
    monkeypatch.setattr(api_module, "_worker_freshness_snapshot", lambda: {"available": False})
    monkeypatch.setattr(api_module, "_require_approval_receipt_if_policy_enabled", no_op)
    monkeypatch.setattr(api_module, "_require_reachable_fleet_placement", no_op)

    async def run():
        asyncpg = _real_asyncpg()
        async with database() as conn:
            await _converted(conn)
            await conn.execute(receipt_schema_sql())
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS command_results (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), command TEXT NOT NULL,
                    status TEXT NOT NULL, dry_run BOOLEAN NOT NULL DEFAULT false,
                    risk_tier TEXT NOT NULL, operation_plan_id UUID, scope_receipt_id TEXT,
                    approval_receipt_id UUID, campaign_id UUID, scan_id UUID,
                    finding_ids JSONB, hypothesis_ids JSONB, evidence_object_ids JSONB,
                    tool_receipt_ids JSONB, blocked_by JSONB, next_action TEXT,
                    operator_message TEXT NOT NULL, result_json JSONB, created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
            schema = await conn.fetchval("SELECT current_schema()")
            # A real pool: the audit row must survive on a connection of its own.
            pool = await asyncpg.create_pool(
                os.environ["TARGET_ASSET_TEST_DATABASE_URL"], min_size=1, max_size=3,
                server_settings={"search_path": f'"{schema}", public'},
            )
            try:
                monkeypatch.setattr(api_module, "db_pool", pool)
                with pytest.raises(HTTPException) as refused:
                    await api_module._submit_scan(api_module.ScanRequest(
                        target="https://shop.refused.test", approval_receipt_id=missing_receipt,
                        policy={"active_testing": False}))
            finally:
                await pool.close()
            targets = await conn.fetch(
                "SELECT url FROM targets WHERE url LIKE '%refused.test%'")
            blocked = await conn.fetch("SELECT status, blocked_by FROM command_results")
            return refused.value, [row["url"] for row in targets], blocked

    refused, targets, blocked = asyncio.run(run())
    assert refused.status_code == 404
    assert targets == []
    assert [row["status"] for row in blocked] == ["blocked"]
    assert "approval_receipt_not_found" in blocked[0]["blocked_by"]
