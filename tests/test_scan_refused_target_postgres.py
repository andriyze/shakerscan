"""A Scan refused at admission leaves no target behind (real PostgreSQL; run by the target-assets
job). The target row used to be committed before the DNS check, so a typo -- or `scan help` --
left a target such as https://help in the inventory although no scan was ever queued."""
import asyncio
import socket

import pytest
from fastapi import HTTPException

from targets.asset_migration import BoundConnectionPool
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
