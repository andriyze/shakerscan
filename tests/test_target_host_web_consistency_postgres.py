"""Host assets and web targets agree (PostgreSQL).

* ``GET /targets`` lists web targets only; it now says so (``host_assets`` points at
  ``GET /targets/inventory``) and gives each row its place there (``inventory_kind``, ``asset_id``).
* Archiving the last web app on a host the inventory created for it archives that host too:
  it stayed active with no origins and kept counting in the inventory total. Restoring the web app
  brings the host back. A host a person added, or one with other active services, stays.
* An archived host's stored URL carries ``#retired=<id>`` so the same host can be added again
  (URL and canonical key are unique); readers are shown the host's own URL.

Lab-range addresses only; name resolution is a fixture and nothing is contacted. The schema is
db/init.sql plus every startup migration. Requires ``TARGET_ASSET_TEST_DATABASE_URL``.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
import sys
import types
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(ROOT / "scanner"))

from tests.test_scan_local_revocation_postgres import scan_database  # noqa: E402

pytest_plugins = ["tests.test_scan_local_revocation_postgres"]


def _router(monkeypatch, pool):
    import target_resolution
    from targets import asset_router, router

    async def no_twin(*_args, **_kwargs):
        return None

    monkeypatch.setattr(target_resolution, "prefer_resolving_twin", no_twin)
    monkeypatch.setattr(router, "_pool_provider", lambda: pool)
    monkeypatch.setattr(asset_router, "_pool_provider", lambda: pool)
    monkeypatch.setitem(router._deps, "load_effective_automation_settings", lambda: {})
    monkeypatch.setitem(router._deps, "safe_default_asm_config", lambda value: {})
    monkeypatch.setitem(router._deps, "sanitize_scan_options", lambda value: value)
    return router, asset_router


def _target(url):
    return types.SimpleNamespace(url=url, name=None, scan_options={}, cohort="lab")


async def _host_of(pool, target_id):
    async with pool.acquire() as conn:
        return await conn.fetchrow(
            """SELECT host.id, host.url, host.is_active FROM targets app JOIN targets host
               ON host.id=app.asset_owner_id WHERE app.id=$1::uuid""", target_id)


async def _inventory_total(asset_router):
    page = await asset_router.target_inventory(
        response=None, search="", connected_only=False, include_inactive=False, include_services=False,
        group_by=None, asset_type=None, environment=None, authorization=None, findings=None,
        activity=None, liveness=None, domain=None, sort="name", include_facets=False, web_only=False,
        limit=100, offset=0, cursor=None, fields=None, count=None, since=None, member_limit=20)
    return page["total"]


def test_list_targets_says_where_host_assets_are(template_database, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            router, asset_router = _router(monkeypatch, pool)
            web = await router.create_target(_target("http://10.10.10.160:8081"))
            await asset_router.create_host_target(asset_router.HostTargetCreate(locator="10.10.10.161"))
            listed = await router.list_targets(include_inactive=False, limit=100, offset=0)
            assert [row["url"] for row in listed["targets"]] == ["http://10.10.10.160:8081"]
            row = listed["targets"][0]
            host = await _host_of(pool, web["id"])
            assert row["inventory_kind"] == "service" and row["asset_id"] == str(host["id"])
            assert listed["host_assets"]["listed_here"] is False
            assert listed["host_assets"]["list"] == "/targets/inventory"
    asyncio.run(run())


def test_archiving_the_last_web_app_archives_its_host_and_restoring_brings_it_back(template_database, monkeypatch):
    async def run():
        from targets.archive import archive

        async with scan_database(template_database) as pool:
            router, asset_router = _router(monkeypatch, pool)
            web = await router.create_target(_target("http://10.10.10.170:8081"))
            host = await _host_of(pool, web["id"])
            assert host["is_active"] and host["url"] == "host://10.10.10.170"
            before = await _inventory_total(asset_router)

            archived = await archive(pool, uuid.UUID(web["id"]))
            assert archived["host_archived"] == str(host["id"])
            assert not (await _host_of(pool, web["id"]))["is_active"]
            assert await _inventory_total(asset_router) == before - 1

            # Readers see the host's own URL, not the archive bookkeeping suffix.
            shown = await router.get_target(str(host["id"]))
            assert shown["url"] == "host://10.10.10.170" and shown["is_active"] is False
            detail = await asset_router.get_target_asset(str(host["id"]))
            assert detail["target"]["url"] == "host://10.10.10.170"

            await router.update_target(web["id"], types.SimpleNamespace(
                name=None, is_active=True, scan_options=None, metadata_json=None, cohort=None))
            restored = await _host_of(pool, web["id"])
            assert restored["is_active"] and restored["url"] == "host://10.10.10.170"
            assert await _inventory_total(asset_router) == before
    asyncio.run(run())


def test_a_host_with_other_services_or_added_by_a_person_stays(template_database, monkeypatch):
    async def run():
        from targets.archive import archive

        async with scan_database(template_database) as pool:
            router, asset_router = _router(monkeypatch, pool)
            first = await router.create_target(_target("http://10.10.10.180:8081"))
            await router.create_target(_target("http://10.10.10.180:8082"))
            result = await archive(pool, uuid.UUID(first["id"]))
            assert "host_archived" not in result and (await _host_of(pool, first["id"]))["is_active"]

            await asset_router.create_host_target(asset_router.HostTargetCreate(locator="10.10.10.181"))
            only = await router.create_target(_target("http://10.10.10.181:8081"))
            result = await archive(pool, uuid.UUID(only["id"]))
            assert "host_archived" not in result and (await _host_of(pool, only["id"]))["is_active"]
    asyncio.run(run())
