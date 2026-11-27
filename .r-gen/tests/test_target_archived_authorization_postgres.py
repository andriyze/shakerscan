"""An archived target is never reported as authorized, and adding it again restores it (PostgreSQL).

Adding a target that had been archived answered ``already_exists`` with the archived row, which
stayed archived. Authorizing it then answered 200 with a full standing grant while every reader
(``GET /targets/{id}/authorization``, scan and Hunt admission) resolved an archived target to no
authorization, so an operator believed the target was cleared for active testing when it was not.
Now adding it again restores it (as ``PATCH is_active=true`` does), and authorizing a target that is
still archived is refused with 409 instead of a grant nobody can read back.

Lab-range addresses only; name resolution is a fixture and nothing is contacted. The schema is
db/init.sql plus every startup migration. Requires ``TARGET_ASSET_TEST_DATABASE_URL``.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
import sys
import types
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(ROOT / "scanner"))

from fastapi import HTTPException  # noqa: E402

from tests.test_scan_local_revocation_postgres import scan_database  # noqa: E402

pytest_plugins = ["tests.test_scan_local_revocation_postgres"]


def _router(monkeypatch, pool):
    import target_resolution
    from targets import router

    async def no_twin(*_args, **_kwargs):
        return None

    monkeypatch.setattr(target_resolution, "prefer_resolving_twin", no_twin)
    monkeypatch.setattr(router, "_pool_provider", lambda: pool)
    monkeypatch.setitem(router._deps, "load_effective_automation_settings", lambda: {})
    monkeypatch.setitem(router._deps, "safe_default_asm_config", lambda value: {})
    return router


def _target(url):
    return types.SimpleNamespace(url=url, name=None, scan_options={}, cohort="lab")


def _grant():
    return types.SimpleNamespace(approved_by="operator", environment=None, risk_tier="active")


def test_an_archived_target_is_refused_and_adding_it_again_restores_it(template_database, monkeypatch):
    async def run():
        from targets.archive import archive

        async with scan_database(template_database) as pool:
            router = _router(monkeypatch, pool)
            created = await router.create_target(_target("http://10.10.10.150:8081"))
            target_id = created["id"]
            await archive(pool, uuid.UUID(target_id))

            with pytest.raises(HTTPException) as refused:
                await router.authorize_target(target_id, _grant())
            assert refused.value.status_code == 409 and "archived" in refused.value.detail
            async with pool.acquire() as conn:
                assert await conn.fetchval(
                    "SELECT count(*) FROM approval_receipts WHERE action_context->>'target_id'=$1",
                    target_id) == 0
            assert (await router.get_target_authorization(target_id))["authorization"] is None

            again = await router.create_target(_target("http://10.10.10.150:8081/"))
            assert again["id"] == target_id and again["status"] == "restored"
            async with pool.acquire() as conn:
                assert await conn.fetchval("SELECT is_active FROM targets WHERE id=$1::uuid", target_id) is True

            granted = (await router.authorize_target(target_id, _grant()))["authorization"]
            assert granted["standing"] is True
            read_back = (await router.get_target_authorization(target_id))["authorization"]
            assert read_back is not None and read_back["approval_receipt_id"] == granted["approval_receipt_id"]

            # An active target that already exists is reported as before.
            assert (await router.create_target(_target("http://10.10.10.150:8081")))["status"] == "already_exists"
    asyncio.run(run())
