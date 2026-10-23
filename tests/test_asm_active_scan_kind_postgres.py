"""The scan blocking a target's ASM actions is linked and named by its kind (PostgreSQL, E1-N4).

The target's ASM view links the active scan that blocks its actions and says whether it is an
ASM batch or recon scan (hidden from the Scans list) or an ordinary one. A parallel scan's parent
is linked before its shards, even when the shards started later, and the scheduler state names
the blocking scan's kind (``active_scan_kind``) in its decision and at its top level. The real
queries run over the installed schema; no scan runs.

Requires ``TARGET_ASSET_TEST_DATABASE_URL`` (a disposable local PostgreSQL).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from tests.test_scan_local_revocation_postgres import scan_database  # noqa: E402

pytest_plugins = ["tests.test_scan_local_revocation_postgres"]

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


async def _target(conn):
    # No root domain: the per-domain rate cap (and its reservation store) is not consulted.
    return str(await conn.fetchval(
        "INSERT INTO targets(url, name, root_domain) VALUES('https://asm-kind.test', 'asm kind', NULL) RETURNING id"))


async def _scan(conn, target_id, role, *, started, status="running"):
    return str(await conn.fetchval(
        """INSERT INTO scans(target_id, target_url, status, scan_role, started_at, created_at)
           VALUES($1::uuid, 'https://asm-kind.test', $2, $3, $4, $4) RETURNING id""",
        target_id, status, role, started))


def test_a_parallel_scan_parent_is_listed_before_its_later_shards(template_database):
    from targets import router as targets_router

    async def run():
        async with scan_database(template_database) as pool:
            async with pool.acquire() as conn:
                target_id = await _target(conn)
                parent = await _scan(conn, target_id, "parent", started=T0)
                shards = [await _scan(conn, target_id, "shard", started=T0 + timedelta(minutes=minute))
                          for minute in (1, 2)]
                await _scan(conn, target_id, "standalone", started=T0 - timedelta(hours=1), status="completed")
                listed = await targets_router._asm_active_scans(conn, target_id)
            return parent, shards, listed

    parent, shards, listed = asyncio.run(run())
    assert [row["id"] for row in listed] == [parent, shards[1], shards[0]]
    assert [row["scan_role"] for row in listed] == ["parent", "shard", "shard"]


@pytest.mark.parametrize("role,kind", [
    ("standalone", "scan"), ("parent", "scan"), ("asm_batch", "asm"), ("asm_recon", "asm"),
])
def test_the_scheduler_state_names_the_blocking_scan_kind(template_database, role, kind):
    from targets import router as targets_router

    async def run():
        async with scan_database(template_database) as pool:
            async with pool.acquire() as conn:
                target_id = await _target(conn)
                blocker = await _scan(conn, target_id, role, started=T0)
                if role == "parent":
                    await _scan(conn, target_id, "shard", started=T0 + timedelta(minutes=1))
                state = await targets_router._asm_scheduler_state(conn, None, target_id)
            return blocker, state

    blocker, state = asyncio.run(run())
    assert state["active_scan_ids"][0] == blocker
    assert state["decision"]["active_scan_id"] == blocker
    assert state["decision"]["active_scan_kind"] == kind
    assert state["active_scan_kind"] == kind


def test_the_scheduler_state_has_no_kind_without_an_active_scan(template_database):
    from targets import router as targets_router

    async def run():
        async with scan_database(template_database) as pool:
            async with pool.acquire() as conn:
                target_id = await _target(conn)
                await _scan(conn, target_id, "asm_batch", started=T0, status="completed")
                return await targets_router._asm_scheduler_state(conn, None, target_id)

    state = asyncio.run(run())
    assert state["active_scan_ids"] == [] and state["active_scan_kind"] is None
    assert "active_scan_kind" not in state["decision"]
