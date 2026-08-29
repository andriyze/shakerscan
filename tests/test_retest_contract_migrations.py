import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone

import pytest

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


class _NoopTransaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False


class _FailingCanonicalInvariantConn(_FakeMigrationConn):
    def __init__(self, index_failures):
        super().__init__([], applied=1)
        self.index_failures = list(index_failures)
        self.index_attempts = 0

    async def fetchval(self, query, *args):
        if "app_schema_migrations" in query:
            return False
        if "indisunique" in query:
            return True
        return await super().fetchval(query, *args)

    async def execute(self, query, *args):
        self.executed.append((query, args))
        if "CREATE UNIQUE INDEX idx_targets_canonical_key" in query:
            self.index_attempts += 1
            if self.index_failures:
                raise self.index_failures.pop(0)

    def transaction(self):
        return _NoopTransaction()


class _FakePoolAcquire:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, traceback):
        return False


class _FakePool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return _FakePoolAcquire(self.conn)


class _EvidenceIdentityMigrationConn(_FakeMigrationConn):
    def __init__(self, *, applied=False, index_present=False):
        super().__init__([], applied=None)
        self.migration_applied = applied
        self.index_present = index_present

    async def fetchval(self, query, *args):
        if "app_schema_migrations" in query:
            return self.migration_applied
        if "to_regclass('idx_evidence_objects_finding_type_scan_unique')" in query:
            return self.index_present
        return None


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


def test_hypothesis_proof_link_migration_adds_durable_promoted_finding_ids():
    conn = _FakeMigrationConn([])

    asyncio.run(retest_contract._migrate_hypothesis_proof_links(conn))

    assert len(conn.executed) == 1
    statement, args = conn.executed[0]
    assert args == ()
    assert "ALTER TABLE hypotheses" in statement
    assert "promoted_finding_ids JSONB NOT NULL DEFAULT '[]'::jsonb" in statement


def test_active_finding_count_reconciliation_repairs_web_and_device_badges():
    conn = _FakeMigrationConn([])

    asyncio.run(retest_contract._reconcile_active_finding_counts(conn))

    statements = [query for query, _args in conn.executed]
    assert len(statements) == 2
    assert "UPDATE targets" in statements[0]
    assert "f.target_id=t.id" in statements[0]
    assert "UPDATE device_targets" in statements[1]
    assert "f.device_target_id=d.id" in statements[1]


def test_evidence_scan_identity_migration_marks_existing_index_without_rewriting_history():
    conn = _EvidenceIdentityMigrationConn(index_present=True)

    asyncio.run(retest_contract._migrate_evidence_scan_identity(conn))

    statements = [query for query, _args in conn.executed]
    assert not any("UPDATE evidence_objects" in query for query in statements)
    assert not any("DROP CONSTRAINT" in query for query in statements)
    assert any(
        "INSERT INTO app_schema_migrations" in query
        and args == (retest_contract.EVIDENCE_SCAN_IDENTITY_MIGRATION,)
        for query, args in conn.executed
    )


def test_evidence_scan_identity_legacy_repair_is_one_time_and_collision_safe():
    conn = _EvidenceIdentityMigrationConn()

    asyncio.run(retest_contract._migrate_evidence_scan_identity(conn))

    statements = [query for query, _args in conn.executed]
    repair_index = next(i for i, query in enumerate(statements) if "UPDATE evidence_objects" in query)
    index_index = next(i for i, query in enumerate(statements) if "CREATE UNIQUE INDEX" in query)
    ledger_index = next(i for i, query in enumerate(statements) if "INSERT INTO app_schema_migrations" in query)
    assert repair_index < index_index < ledger_index
    assert "NOT EXISTS" in statements[repair_index]
    assert "current_observation.scan_id=findings.scan_id" in statements[repair_index]


def test_evidence_scan_identity_migration_skips_after_ledger_entry():
    conn = _EvidenceIdentityMigrationConn(applied=True)

    asyncio.run(retest_contract._migrate_evidence_scan_identity(conn))

    assert conn.executed == []


def test_canonical_key_invariant_repairs_rewrites_and_recreates_index(monkeypatch):
    conn = _FailingCanonicalInvariantConn([])

    async def fake_merge(_conn):
        assert _conn is conn
        return 2

    monkeypatch.setattr("target_dedupe.merge_all_canonical_duplicates", fake_merge)

    asyncio.run(retest_contract._ensure_target_canonical_key_invariant(conn))

    assert conn.index_attempts == 1
    statements = [query for query, _args in conn.executed]
    assert any("DROP INDEX IF EXISTS idx_targets_canonical_key" in query for query in statements)
    assert any("UPDATE targets SET url=url" in query for query in statements)
    assert any(
        "INSERT INTO app_schema_migrations" in query
        and args == (retest_contract.TARGET_HOST_IDENTITY_MIGRATION,)
        for query, args in conn.executed
    )


def test_canonical_key_invariant_skips_data_rewrite_after_successful_migration():
    conn = _FailingCanonicalInvariantConn([])

    async def migrated_fetchval(query, *args):
        if "app_schema_migrations" in query:
            return True
        if "indisunique" in query:
            return True
        return None

    conn.fetchval = migrated_fetchval
    asyncio.run(retest_contract._ensure_target_canonical_key_invariant(conn))

    statements = [query for query, _args in conn.executed]
    assert not any("DROP INDEX IF EXISTS idx_targets_canonical_key" in query for query in statements)
    assert not any("UPDATE targets SET url=url" in query for query in statements)
    assert conn.index_attempts == 0


def test_schema_migration_failure_blocks_startup_and_releases_lock(monkeypatch):
    conn = _FailingCanonicalInvariantConn([])

    async def failed_merge(_conn):
        raise RuntimeError("retention preview blocks merge")

    monkeypatch.setattr("target_dedupe.merge_all_canonical_duplicates", failed_merge)

    with pytest.raises(retest_contract.SchemaMigrationError) as exc:
        asyncio.run(retest_contract.run_schema_migrations(_FakePool(conn)))

    message = str(exc.value)
    assert "startup is blocked" in message
    assert "idx_targets_canonical_key" in message
    assert "retention preview blocks merge" in message
    assert isinstance(exc.value.__cause__, RuntimeError)
    assert any(
        "CREATE TABLE IF NOT EXISTS budget_reservations" in query
        for query, _args in conn.executed
    )
    assert any(
        "CREATE TABLE IF NOT EXISTS scan_capability_actions" in query
        for query, _args in conn.executed
    )
    assert any("pg_advisory_unlock(8675309)" in query for query, _args in conn.executed)
