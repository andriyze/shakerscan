"""Several web apps on one host (different ports) all appear in their domain group (PostgreSQL).

E1-N2: "Add targets" registers each app of an IP host (http://10.10.10.100:8000, :3000, ...) as a
root target of the same root domain. ``/targets/grouped`` kept only the last root in URL order and
dropped the others, so the Coverage page never listed five of six apps, even with an endpoint
inventory ("0 targets with a persistent inventory" while two had 73 and 134 endpoints). Every
target of the group is now listed: the last root stays the group's root target, the other roots
are members beside the subdomains.

Requires ``TARGET_ASSET_TEST_DATABASE_URL`` (a disposable local PostgreSQL).
"""
from __future__ import annotations

import asyncio
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from tests.test_scan_local_revocation_postgres import scan_database  # noqa: E402

pytest_plugins = ["tests.test_scan_local_revocation_postgres"]
from list_contract import Page  # noqa: E402

HOST = "10.10.10.100"
PORTS = (1, 3000, 5002, 8000, 9001, 9002, 9999)


async def _seed(pool):
    async with pool.acquire() as conn:
        ids = {}
        for port in PORTS:
            ids[port] = await conn.fetchval(
                "INSERT INTO targets(url, name, root_domain, is_root) VALUES($1, $2, $3, $4) RETURNING id",
                f"http://{HOST}:{port}", f"app {port}", HOST, port != 1)
        for port, count in ((8000, 3), (3000, 2)):
            for index in range(count):
                await conn.execute(
                    """INSERT INTO target_endpoints(target_id, path, fingerprint, test_status)
                       VALUES($1, $2, $3, $4)""",
                    ids[port], f"/p{index}", f"GET /p{index}", "tested" if index == 0 else "untested")
        other = await conn.fetchval(
            "INSERT INTO targets(url, name, root_domain, is_root) VALUES('https://solo.test', 'solo', 'solo.test', true) "
            "RETURNING id")
    return ids, other


async def _page(conn, *, member_limit=20, has_inventory=False, summary=False):
    from targets import grouped_list, router as targets_router

    return await grouped_list.grouped_page(
        conn, Page(limit=20, cursor=None, sort="root_domain", count="exact"),
        filters={"sort": "root_domain", "has_inventory": has_inventory}, member_limit=member_limit,
        member_columns=f"{targets_router._GROUPED_TARGET_COLUMNS}, {targets_router._authorized_for_active_testing_sql()}",
        public_row=targets_router._public_target_row, has_inventory=has_inventory, summary=summary)


def _members(group):
    return ([group["root_target"]] if group["root_target"] else []) + group["subdomains"]


def test_every_app_on_one_host_is_listed_in_its_group(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            ids, _other = await _seed(pool)
            async with pool.acquire() as conn:
                body = await _page(conn)
        group = next(item for item in body["items"] if item["root_domain"] == HOST)
        assert group["root_target"]["id"] == str(ids[9999])  # the last root in URL order, as before
        assert sorted(member["id"] for member in _members(group)) == sorted(str(value) for value in ids.values())
        assert group["total_count"] == len(PORTS) and group["subdomain_count"] == len(PORTS) - 1
        assert not group["subdomains_truncated"]
        coverage = {member["url"]: member["asm_coverage"] for member in _members(group)}
        assert coverage[f"http://{HOST}:8000"]["total"] == 3
        assert coverage[f"http://{HOST}:3000"]["total"] == 2
        assert group["asm_coverage"]["total"] == 5 and group["asm_coverage"]["tested"] == 2
    asyncio.run(run())


def test_the_group_counts_and_findings_cover_every_root_of_the_host(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            ids, _other = await _seed(pool)
            async with pool.acquire() as conn:
                await conn.execute("UPDATE targets SET active_findings_count = 4 WHERE id = $1", ids[8000])
                await conn.execute("UPDATE targets SET active_findings_count = 1 WHERE id = $1", ids[9999])
                body = await _page(conn, member_limit=2)
        group = next(item for item in body["items"] if item["root_domain"] == HOST)
        assert group["total_findings"] == 5
        assert group["subdomain_count"] == len(PORTS) - 1
        assert len(group["subdomains"]) == 2 and group["subdomains_truncated"]
        # The rollup covers every member, not only the ones on the page.
        assert group["asm_coverage"]["total"] == 5
    asyncio.run(run())


def test_the_inventory_filter_and_summary_count_each_app(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            await _seed(pool)
            async with pool.acquire() as conn:
                body = await _page(conn, has_inventory=True, summary=True)
        assert [item["root_domain"] for item in body["items"]] == [HOST]
        inventoried = [member for member in _members(body["items"][0]) if member["asm_coverage"]]
        assert sorted(member["url"] for member in inventoried) == [f"http://{HOST}:3000", f"http://{HOST}:8000"]
        assert body["asm_summary"]["targets_with_inventory"] == 2
    asyncio.run(run())


@pytest.mark.parametrize("member_limit", [20, 1])
def test_a_domain_with_one_root_is_unchanged(template_database, member_limit):
    async def run():
        async with scan_database(template_database) as pool:
            _ids, other = await _seed(pool)
            async with pool.acquire() as conn:
                body = await _page(conn, member_limit=member_limit)
        group = next(item for item in body["items"] if item["root_domain"] == "solo.test")
        assert group["root_target"]["id"] == str(other)
        assert group["subdomains"] == [] and group["subdomain_count"] == 0 and group["total_count"] == 1
    asyncio.run(run())
