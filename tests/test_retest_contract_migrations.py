import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import asm_inventory  # noqa: E402
import retest_contract  # noqa: E402


class _FakeMigrationConn:
    def __init__(self, rows, applied=None):
        self.rows = rows
        self.applied = applied
        self.fetch_called = False
        self.executed = []
        self.executemany_calls = []

    async def fetchval(self, query, *args):
        return self.applied

    async def fetch(self, query, *args):
        self.fetch_called = True
        return self.rows

    async def execute(self, query, *args):
        self.executed.append((query, args))

    async def executemany(self, query, args):
        self.executemany_calls.append((query, list(args)))


def _endpoint_row(**overrides):
    now = datetime(2026, 6, 16, 12, 0, tzinfo=timezone.utc)
    row = {
        "id": uuid.uuid4(),
        "target_id": uuid.uuid4(),
        "method": "GET",
        "path": "/users/42",
        "param_shape": "id",
        "fingerprint": "legacy",
        "source": "recon",
        "auth_state": "anonymous",
        "param_location": "query",
        "replay_spec": "GET /users/42?id=1",
        "content_type": None,
        "content_hash": None,
        "priority_score": 25,
        "test_status": "untested",
        "last_attempt_status": None,
        "last_verdict": None,
        "last_finding_id": None,
        "first_seen_at": now,
        "last_seen_at": now,
        "last_tested_at": None,
        "updated_at": now,
    }
    row.update(overrides)
    return row


def test_backfill_target_endpoint_fingerprints_skips_when_applied():
    conn = _FakeMigrationConn([], applied=1)

    asyncio.run(retest_contract._backfill_target_endpoint_fingerprints(conn))

    assert conn.fetch_called is False
    assert conn.executed == []
    assert conn.executemany_calls == []


def test_backfill_target_endpoint_fingerprints_dedupes_collisions():
    target_id = uuid.uuid4()
    tested_id = uuid.uuid4()
    duplicate_id = uuid.uuid4()
    old = datetime(2026, 6, 16, 10, 0, tzinfo=timezone.utc)
    new = datetime(2026, 6, 16, 12, 0, tzinfo=timezone.utc)
    expected_fp = asm_inventory.endpoint_fingerprint(
        "GET",
        "/users/42",
        "id",
        param_location="query",
        auth_state="anonymous",
    )
    rows = [
        _endpoint_row(
            id=tested_id,
            target_id=target_id,
            path="/users/42",
            fingerprint="legacy-a",
            test_status="tested",
            last_tested_at=old,
            last_seen_at=old,
            updated_at=old,
        ),
        _endpoint_row(
            id=duplicate_id,
            target_id=target_id,
            path="/users/43",
            fingerprint="legacy-b",
            test_status="untested",
            last_seen_at=new,
            updated_at=new,
        ),
    ]
    conn = _FakeMigrationConn(rows)

    asyncio.run(retest_contract._backfill_target_endpoint_fingerprints(conn))

    assert len(conn.executemany_calls) == 2
    temp_updates = conn.executemany_calls[0][1]
    assert {row_id for _tmp_fp, row_id in temp_updates} == {tested_id, duplicate_id}
    assert all(str(tmp_fp).startswith("__asm_fp_v2_tmp__") for tmp_fp, _row_id in temp_updates)

    delete_calls = [
        args for query, args in conn.executed
        if "DELETE FROM target_endpoints" in query
    ]
    assert delete_calls == [([duplicate_id],)]

    final_updates = conn.executemany_calls[1][1]
    assert final_updates == [(expected_fp, tested_id)]
    assert any(
        "INSERT INTO app_schema_migrations" in query
        and args == (retest_contract.ASM_ENDPOINT_FINGERPRINT_MIGRATION,)
        for query, args in conn.executed
    )


def test_target_principal_slot_migration_deactivates_ambiguous_rows_before_unique_index():
    conn = _FakeMigrationConn([])

    asyncio.run(retest_contract._migrate_target_principal_slots(conn))

    statements = [query for query, _args in conn.executed]
    assert len(statements) == 3
    assert "auth_state NOT IN ('user1', 'user2')" in statements[0]
    assert "ROW_NUMBER() OVER" in statements[1]
    assert "ORDER BY updated_at DESC, id DESC" in statements[1]
    assert "idx_target_principals_active_auth_slot" in statements[2]
    assert "WHERE is_active = true AND auth_state IN ('user1', 'user2')" in statements[2]
