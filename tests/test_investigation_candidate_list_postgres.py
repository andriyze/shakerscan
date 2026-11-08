"""The candidate list names each candidate's target and can leave out unversioned advisory matches.

On the installed schema (db/init.sql plus every startup migration): a web candidate and a device
advisory candidate carry their target's name and URL in both the legacy page and list/v1; an
automatic advisory match without a product version is left out with
``unversioned_advisories=exclude`` and counted alone with ``only``; ``status`` takes a list, so one
page covers every open status. The candidate rows are fixtures; no target is contacted.

Requires ``TARGET_ASSET_TEST_DATABASE_URL`` (a disposable local PostgreSQL).
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(ROOT / "scanner"))

from tests.test_scan_local_revocation_postgres import scan_database  # noqa: E402

pytest_plugins = ["tests.test_scan_local_revocation_postgres"]
from fastapi import HTTPException  # noqa: E402
from investigation_routes import router as inv  # noqa: E402


async def _fixtures(pool):
    """Fixture rows: one web target with a candidate, one host with three advisory candidates."""
    async with pool.acquire() as conn:
        web = await conn.fetchval(
            "INSERT INTO targets(url,name) VALUES('https://shop.list.test','Shop') RETURNING id")
        host = await conn.fetchval(
            "INSERT INTO device_targets(name,primary_locator) VALUES('Edge host','edge.list.test') RETURNING id")
        rows = [
            ("web", web, None, "xss", {"route": "/search"}, "new", "Reflected input"),
            ("device", None, host, "device_firmware_advisory",
             {"advisory_id": "CVE-2026-1", "cpe": "cpe:/a:nginx:nginx", "port": 443}, "new", "Unversioned A"),
            ("device", None, host, "device_firmware_advisory",
             {"advisory_id": "CVE-2026-2", "cpe": "cpe:/a:nginx:nginx", "port": 443}, "inconclusive", "Unversioned B"),
            ("device", None, host, "device_firmware_advisory",
             {"advisory_id": "CVE-2026-3", "cpe": "cpe:/a:nginx:nginx", "port": 443, "version": "1.18.0"},
             "blocked", "Versioned"),
            ("web", web, None, "xss", {"route": "/old"}, "refuted", "Refuted"),
        ]
        for index, (plane, target, device, family, locus, status, title) in enumerate(rows):
            await conn.execute(
                """INSERT INTO investigation_candidates(plane,target_id,device_target_id,family,canonical_locus,
                       title,claim,fingerprint,status,last_seen_at)
                   VALUES($1,$2,$3,$4,$5::jsonb,$6,$6,$7,$8,NOW() - make_interval(secs => $9))""",
                plane, target, device, family, json.dumps(locus), title, f"list-fixture-{index}", status, index)
    return web, host


async def _legacy(**args):
    base = {"plane": None, "target_id": None, "device_target_id": None, "status": None, "limit": 100,
            "offset": 0, "cursor": None, "count": None, "fields": None, "since": None}
    return await inv.list_investigation_candidates(None, **{**base, **args})


def test_candidates_carry_their_target_and_unversioned_advisories_can_be_left_out(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            inv.configure_investigation_router(lambda: pool)
            web, host = await _fixtures(pool)
            open_statuses = "new,verification_queued,verifying,inconclusive,blocked"

            everything = await _legacy(status=open_statuses)
            assert [c["title"] for c in everything["candidates"]] == [
                "Reflected input", "Unversioned A", "Unversioned B", "Versioned"]
            assert everything["total"] == 4
            names = {c["title"]: (c["target_name"], c["target_url"]) for c in everything["candidates"]}
            assert names["Reflected input"] == ("Shop", "https://shop.list.test")
            assert names["Versioned"] == ("Edge host", "host://edge.list.test")

            kept = await _legacy(status=open_statuses, unversioned_advisories="exclude")
            assert [c["title"] for c in kept["candidates"]] == ["Reflected input", "Versioned"]
            assert kept["total"] == 2
            hidden = await _legacy(status=open_statuses, unversioned_advisories="only", limit=1)
            assert hidden["total"] == 2 and len(hidden["candidates"]) == 1

            # Paging over the filtered list.
            second = await _legacy(status=open_statuses, unversioned_advisories="exclude", limit=1, offset=1)
            assert [c["title"] for c in second["candidates"]] == ["Versioned"] and second["total"] == 2

            # list/v1 summary rows carry the same names; a cursor stays bound to the filter.
            page = await _legacy(status=open_statuses, unversioned_advisories="exclude", count="exact", limit=1)
            assert page["items"][0]["target_name"] == "Shop" and page["total"] == 2
            follow = await _legacy(status=open_statuses, unversioned_advisories="exclude", limit=1,
                                   cursor=page["next_cursor"])
            assert [item["title"] for item in follow["items"]] == ["Versioned"]
            assert follow["items"][0]["target_name"] == "Edge host"
            with pytest.raises(HTTPException):
                await _legacy(status=open_statuses, limit=1, cursor=page["next_cursor"])

            for bad in ({"status": "new,bogus"}, {"unversioned_advisories": "sometimes"}):
                with pytest.raises(HTTPException) as refused:
                    await _legacy(**bad)
                assert refused.value.status_code == 422
            assert str(web) and str(host)
    asyncio.run(run())
