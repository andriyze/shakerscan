"""Real persistence, ownership joins and deletion acceptance in an isolated schema.

Hunt record-integrity CI supplies HUNT_TEST_POSTGRES_DSN, so these tests execute
there rather than treating a SQL mock as database acceptance.
"""
from datetime import timedelta
import json
import os
from urllib.parse import urlsplit
import uuid

import pytest

from api.exposure.hunt_service_sources import hunt_service_sources
from api.exposure.service_inventory import build_inventory
from api.runtime.budget_reservations import DurableBudgetReservation
from api.runtime.reservation_store import PostgresBudgetReservationStore
from tests.test_hunt_service_sources import ACTION_ID, HUNT_ID, NOW, TARGET, TARGET_ID, fixture

DSN = os.environ.get("HUNT_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")


@pytest.mark.parametrize("kind", ["web", "api", "network", "device"])
@pytest.mark.asyncio
async def test_settled_hunt_observations_are_reusable_and_owner_deletion_removes_the_projection(kind):
    import asyncpg
    assert urlsplit(DSN).hostname in {"localhost", "127.0.0.1", "::1", "postgres"}
    schema = "hunt_services_" + uuid.uuid4().hex
    conn = await asyncpg.connect(DSN)
    try:
        await conn.execute(f'CREATE SCHEMA "{schema}"')
        await conn.execute(f'SET search_path TO "{schema}"')
        await conn.execute("""
          CREATE TABLE hunt_runs(id uuid PRIMARY KEY,target_id uuid,device_target_id uuid,
            target_kind text,created_at timestamptz,context_pack jsonb);
          CREATE TABLE hunt_actions(id uuid PRIMARY KEY,hunt_run_id uuid REFERENCES hunt_runs(id) ON DELETE CASCADE,
            capability_name text,status text,receipt_id uuid);
        """)
        store = PostgresBudgetReservationStore()
        await store.ensure_schema(conn)
        row, _, terminal, receipt = fixture(kind=kind, status="partial")
        target = dict(TARGET)
        if kind == "device":
            target.update(kind="device", locator="192.0.2.1", locator_generation=3,
                          locator_changed_at=NOW - timedelta(seconds=1))
        context = {"target": row["target_context"], "authorized_target_addresses": row["authorized_addresses"]}
        await conn.execute("INSERT INTO hunt_runs VALUES ($1,$2,$3,$4,$5,$6::jsonb)", uuid.UUID(HUNT_ID),
                           uuid.UUID(TARGET_ID) if kind != "device" else None,
                           uuid.UUID(TARGET_ID) if kind == "device" else None, kind, NOW, json.dumps(context))
        await conn.execute("INSERT INTO hunt_actions VALUES ($1,$2,$3,'running',NULL)",
                           uuid.UUID(ACTION_ID), uuid.UUID(HUNT_ID), receipt.capability_name)
        requested = DurableBudgetReservation.request(
            owner_kind="hunt", owner_id=HUNT_ID, capability_name=receipt.capability_name,
            amounts={"http_requests": 10}, reservation_id=terminal.reservation_id, now=NOW,
        )
        stored = await store.create_requested(conn, action_id=ACTION_ID, action_digest="a" * 64, record=requested)
        # A reserved/running action must not look like service evidence before settlement.
        assert (await hunt_service_sources(conn, target))[0] == []
        stored = await store.persist_transition(conn, previous=stored,
            current=stored.record.reserve(now=NOW, lease_seconds=30), ledger_after_hold={"http_requests": 10})
        stored = await store.persist_transition(conn, previous=stored,
            current=stored.record.start(worker_id="worker-1", now=NOW, lease_seconds=30))
        async with conn.transaction():
            await store.persist_terminal(conn, previous=stored, terminal=terminal,
                ledger_after_settlement={"http_requests": 2}, receipt=receipt)
            await conn.execute("UPDATE hunt_actions SET status='partial',receipt_id=$2 WHERE id=$1",
                               uuid.UUID(ACTION_ID), uuid.UUID(receipt.receipt_id))
        sources, warnings, truncated = await hunt_service_sources(conn, target)
        assert len(sources) == 1 and not warnings and not truncated
        service = build_inventory(target, sources, now=NOW)[0][0]
        assert service["port"] == 8443 and service["observation_status"] == "partial"
        assert service["evidence"][0]["hunt_id"] == HUNT_ID
        # Reload and repeated reads use one durable action, not a duplicate ingestion.
        assert await store.load(conn, terminal.reservation_id) is not None
        assert (await hunt_service_sources(conn, target))[0] == sources
        foreign = {**target, "id": str(uuid.uuid4())}
        assert (await hunt_service_sources(conn, foreign))[0] == []
        # Removed ownership cannot be resurrected from an orphan reservation receipt.
        await conn.execute("DELETE FROM hunt_runs WHERE id=$1", uuid.UUID(HUNT_ID))
        assert (await hunt_service_sources(conn, target))[0] == []
    finally:
        await conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await conn.close()
