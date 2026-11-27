from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys
import uuid

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from scan.stage_store import (
    PostgresScanStageCheckpointStore,
    SCAN_STAGE_CHECKPOINT_SCHEMA_SQL,
    ScanStageCheckpointError,
    _history_digest,
    public_stage_row,
    stage_row_digest,
)


SCAN_ID = "11111111-1111-4111-8111-111111111111"


def _row(**overrides):
    value = {
        "index": 2,
        "name": "discover_surface",
        "enabled": True,
        "status": "completed",
        "reason": None,
        "adapter": "native_worker",
        "capability_names": ["web.probe", "web.crawl"],
        "output_keys": ["web.probe", "web.crawl"],
        "elapsed_ms": 25,
    }
    value.update(overrides)
    return value


class FakeConn:
    def __init__(self):
        self.executed = []
        self.rows = {}

    async def execute(self, query, *args):
        self.executed.append((query, args))
        return "OK"

    async def fetchrow(self, query, *args):
        key = (str(args[0]), args[1], args[2])
        incoming = {
            "scan_id": args[0],
            "job_id": args[1],
            "stage_index": args[2],
            "stage_name": args[3],
            "status": args[4],
            "execution_plan_digest": args[5],
            "target_binding_digest": args[6],
            "history_digest": args[7],
            "stage_row_digest": args[8],
            "stage_row_json": json.loads(args[9]),
            "worker_id": args[10],
        }
        existing = self.rows.get(key)
        if existing is not None and (
            existing["stage_name"] != incoming["stage_name"]
            or existing["execution_plan_digest"]
            != incoming["execution_plan_digest"]
            or existing["target_binding_digest"]
            != incoming["target_binding_digest"]
        ):
            return None
        self.rows[key] = incoming
        return incoming

    async def fetch(self, query, *args):
        scan_id, job_id = str(args[0]), args[1]
        return sorted(
            (
                row
                for (row_scan_id, row_job_id, _index), row in self.rows.items()
                if row_scan_id == scan_id and row_job_id == job_id
            ),
            key=lambda row: row["stage_index"],
        )


def _persist(store, conn, row=None, **overrides):
    values = {
        "scan_id": SCAN_ID,
        "job_id": "scan/job:1",
        "execution_plan_digest": "a" * 64,
        "target_binding_digest": "b" * 64,
        "history_digest": "c" * 64,
        "stage_row": row or _row(),
        "worker_id": "worker/node@1",
    }
    values.update(overrides)
    return asyncio.run(store.persist(conn, **values))


def test_public_stage_row_keeps_keys_but_never_private_output_values():
    row = public_stage_row(_row())
    serialized = json.dumps(row, sort_keys=True)
    assert row["output_keys"] == ["web.probe", "web.crawl"]
    assert "secret" not in serialized
    assert len(stage_row_digest(row)) == 64


@pytest.mark.parametrize("field", ["private_output", "observations", "errors"])
def test_public_stage_row_rejects_extra_private_fields(field):
    with pytest.raises(ScanStageCheckpointError, match="fields are invalid"):
        public_stage_row(_row(**{field: "secret"}))


def test_schema_is_idempotent_and_references_scan_lifecycle():
    conn = FakeConn()
    asyncio.run(PostgresScanStageCheckpointStore().ensure_schema(conn))
    assert conn.executed == [(SCAN_STAGE_CHECKPOINT_SCHEMA_SQL, ())]
    assert "REFERENCES scans(id) ON DELETE CASCADE" in SCAN_STAGE_CHECKPOINT_SCHEMA_SQL
    assert "v2_scan_stage_checkpoints_v1" in SCAN_STAGE_CHECKPOINT_SCHEMA_SQL


def test_persist_is_idempotent_for_one_stage_and_rejects_authority_change():
    conn = FakeConn()
    store = PostgresScanStageCheckpointStore()
    first = _persist(store, conn)
    second = _persist(store, conn, history_digest="d" * 64)
    assert first["stage_name"] == second["stage_name"]
    assert second["history_digest"] == "d" * 64
    assert second["scan_id"] == uuid.UUID(SCAN_ID)

    with pytest.raises(ScanStageCheckpointError, match="immutable Scan authority"):
        _persist(store, conn, execution_plan_digest="e" * 64)


def test_load_prefix_rejects_tampering_and_returns_only_content_free_rows():
    conn = FakeConn()
    store = PostgresScanStageCheckpointStore()
    first = _row(
        index=0, name="bind_target", capability_names=[], output_keys=[],
    )
    _persist(store, conn, row=first, history_digest=_history_digest([first]))
    second = _row(
        index=1, name="resolve_inputs", capability_names=[], output_keys=[],
    )
    _persist(
        store,
        conn,
        row=second,
        history_digest=_history_digest([first, second]),
    )

    prefix = asyncio.run(store.load_prefix(
        conn, scan_id=SCAN_ID, job_id="scan/job:1",
    ))
    assert prefix["last_stage"] == "resolve_inputs"
    assert prefix["content_free"] is True
    assert prefix["stages"] == [first, second]
    assert "secret" not in json.dumps(prefix)

    conn.rows[(SCAN_ID, "scan/job:1", 1)]["stage_row_json"][
        "status"
    ] = "failed"
    with pytest.raises(ScanStageCheckpointError, match="status mismatch"):
        asyncio.run(store.load_prefix(
            conn, scan_id=SCAN_ID, job_id="scan/job:1",
        ))


def test_checkpoint_schema_matches_init_and_upgrade_repair():
    init_sql = Path("db/init.sql").read_text()
    repair_sql = Path(
        "db/repairs/2026-08-22_v2_scan_stage_checkpoints.sql"
    ).read_text()
    for sql in (init_sql, repair_sql):
        assert "CREATE TABLE IF NOT EXISTS scan_stage_checkpoints" in sql or (
            "CREATE TABLE scan_stage_checkpoints" in sql
        )
        assert "stage_row_json JSONB" in sql
        assert "UNIQUE (scan_id, job_id, stage_name)" in sql
