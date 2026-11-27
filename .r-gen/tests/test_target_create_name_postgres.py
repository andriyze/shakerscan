"""Adding a web app that is already tracked keeps the name the person gives it (PostgreSQL).

A second web app on a known host (``http://host:3000/`` beside the host target) is often already a
row: a network discovery linked it as a service of the host, named by its URL, or an earlier add
gave it no name. POST /targets answered "already exists" and dropped the name, so lists showed the
URL (``name: null`` in ``GET /targets/lookup``). A name the person gives now fills a target with
none of its own; a name someone chose is never replaced, and an add without a name changes none.

Hosts are under the reserved ``.invalid`` domain and name resolution is a fixture: nothing is
contacted. The schema is db/init.sql plus every startup migration.

Requires ``TARGET_ASSET_TEST_DATABASE_URL`` (a disposable local PostgreSQL).
"""
from __future__ import annotations

import asyncio
from pathlib import Path
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(ROOT / "scanner"))

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


def _request(url, name=None):
    return types.SimpleNamespace(url=url, name=name, scan_options={}, cohort="lab")


def test_a_tracked_web_app_without_a_name_takes_the_name_given(template_database, monkeypatch):
    async def run():
        async with scan_database(template_database) as pool:
            router = _router(monkeypatch, pool)
            url = "http://shop.name.invalid:3000"
            first = await router.create_target(_request(url))
            assert first["status"] == "created"
            again = await router.create_target(_request(url + "/", "Shop (lab)"))
            assert again["status"] == "already_exists" and again["id"] == first["id"]
            async with pool.acquire() as conn:
                assert await conn.fetchval("SELECT name FROM targets WHERE id=$1::uuid", first["id"]) == "Shop (lab)"
                # A service record a discovery linked is named by its URL: a person's name replaces it.
                linked = await conn.fetchval(
                    "INSERT INTO targets(url,name,discovery_source) VALUES($1,$1,'device-service') RETURNING id",
                    "http://admin.name.invalid:8443")
            await router.create_target(_request("http://admin.name.invalid:8443", "Admin console"))
            # A chosen name stays; an add without a name changes nothing.
            await router.create_target(_request(url, "Other name"))
            await router.create_target(_request(url))
            async with pool.acquire() as conn:
                assert await conn.fetchval("SELECT name FROM targets WHERE id=$1", linked) == "Admin console"
                assert await conn.fetchval("SELECT name FROM targets WHERE id=$1::uuid", first["id"]) == "Shop (lab)"
    asyncio.run(run())
