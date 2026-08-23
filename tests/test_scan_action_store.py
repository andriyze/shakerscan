from __future__ import annotations

import asyncio
import json
from pathlib import Path
import uuid

import pytest

from api.runtime.models import ScanBudget, ScanPolicy, TargetBinding
from api.scan.action_plan import ScanActionPlanCompiler
from api.scan.action_store import (
    ACTION_LEASE_MIGRATION_NAME,
    MIGRATION_NAME,
    PostgresScanActionStore,
    SCAN_ACTION_SCHEMA_SQL,
    ScanActionStoreError,
)
from api.scan.budget_allocator import allocate_scan_action_plan
from api.scan.execution import ScanExecutionPlan
from api.scan.work_manifests import build_canonical_nuclei_template_manifest


SCAN_ID = "20000000-0000-4000-8000-000000000001"


def _plan(*, active=False):
    execution = ScanExecutionPlan(
        policy=ScanPolicy(
            active_testing=active,
            approval_receipt_id="approval-1" if active else None,
        ),
        budget_profile="fast",
        budget=ScanBudget(300, 1_000, 500, 50, 1_000, 180, 2),
    )
    target = TargetBinding(
        target_id="20000000-0000-4000-8000-000000000002",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
    )
    template = (
        build_canonical_nuclei_template_manifest(
            scan_id=SCAN_ID,
            target_binding_digest=target.digest,
        )
        if active else None
    )
    return ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=execution,
        target_binding=target,
        template_manifest_ref=(
            template.reference().canonical_dict() if template is not None else None
        ),
    )


class FakeConn:
    def __init__(self):
        self.executed = []
        self.plan_row = None
        self.actions = {}

    async def execute(self, query, *args):
        self.executed.append((query, args))
        return "OK"

    async def fetchrow(self, query, *args):
        if query.lstrip().startswith("UPDATE scans"):
            scan_id, digest, schema, raw = args
            if self.plan_row and self.plan_row["scan_action_plan_digest"] != digest:
                return None
            self.plan_row = {
                "id": scan_id,
                "scan_action_plan_json": json.loads(raw),
                "scan_action_plan_digest": digest,
                "scan_action_plan_schema": schema,
            }
            return self.plan_row
        if query.lstrip().startswith("INSERT INTO scan_capability_actions"):
            action_id = args[1]
            incoming = {
                "id": uuid.uuid4(),
                "action_id": action_id,
                "stage": args[2],
                "ordinal": args[3],
                "capability_name": args[4],
                "action_digest": args[8],
                "execution_plan_digest": args[9],
                "target_binding_digest": args[10],
                "status": args[17],
                "reason_code": args[18],
            }
            existing = self.actions.get(action_id)
            if existing and (
                existing["action_digest"] != incoming["action_digest"]
                or existing["ordinal"] != incoming["ordinal"]
                or existing["execution_plan_digest"] != incoming["execution_plan_digest"]
                or existing["target_binding_digest"] != incoming["target_binding_digest"]
            ):
                return None
            self.actions[action_id] = incoming
            return incoming
        if "FROM scans WHERE id=$1" in query:
            return self.plan_row
        raise AssertionError(f"unexpected query: {query}")

    async def fetch(self, query, *args):
        if "FROM scan_capability_actions" not in query:
            raise AssertionError(f"unexpected query: {query}")
        return sorted(self.actions.values(), key=lambda row: row["ordinal"])


def test_action_store_persists_and_reloads_content_addressed_plan_idempotently():
    plan = _plan()
    conn = FakeConn()
    store = PostgresScanActionStore()
    first = asyncio.run(store.persist_plan(conn, plan=plan))
    second = asyncio.run(store.persist_plan(conn, plan=plan))
    loaded = asyncio.run(store.load_plan(conn, scan_id=SCAN_ID))

    assert len(first) == len(second) == len(plan.actions)
    assert loaded == plan
    assert conn.plan_row["scan_action_plan_digest"] == plan.plan_digest
    assert all(row["status"] == "planned" for row in conn.actions.values())


def test_action_store_rejects_changed_plan_and_incomplete_or_tampered_index():
    plan = _plan()
    conn = FakeConn()
    store = PostgresScanActionStore()
    asyncio.run(store.persist_plan(conn, plan=plan))

    conn.plan_row["scan_action_plan_digest"] = "f" * 64
    with pytest.raises(ScanActionStoreError, match="metadata is inconsistent"):
        asyncio.run(store.load_plan(conn, scan_id=SCAN_ID))
    conn.plan_row["scan_action_plan_digest"] = plan.plan_digest

    removed = conn.actions.pop(plan.actions[-1].action_id)
    with pytest.raises(ScanActionStoreError, match="index is incomplete"):
        asyncio.run(store.load_plan(conn, scan_id=SCAN_ID))
    conn.actions[removed["action_id"]] = removed
    conn.actions[plan.actions[0].action_id]["action_digest"] = "e" * 64
    with pytest.raises(ScanActionStoreError, match="index conflicts"):
        asyncio.run(store.load_plan(conn, scan_id=SCAN_ID))


def test_action_store_schema_matches_fresh_install_and_upgrade_repair():
    conn = FakeConn()
    asyncio.run(PostgresScanActionStore().ensure_schema(conn))
    assert conn.executed == [(SCAN_ACTION_SCHEMA_SQL, ())]
    assert MIGRATION_NAME in SCAN_ACTION_SCHEMA_SQL
    assert ACTION_LEASE_MIGRATION_NAME in SCAN_ACTION_SCHEMA_SQL
    assert "REFERENCES scans(id) ON DELETE CASCADE" in SCAN_ACTION_SCHEMA_SQL

    init_sql = Path("db/init.sql").read_text(encoding="utf-8")
    repair_sql = Path(
        "db/repairs/2026-08-23_v2_scan_capability_actions.sql"
    ).read_text(encoding="utf-8")
    lease_repair_sql = Path(
        "db/repairs/2026-08-23_v2_scan_action_leases.sql"
    ).read_text(encoding="utf-8")
    receipt_repair_sql = Path(
        "db/repairs/2026-08-23_v2_scan_action_receipts.sql"
    ).read_text(encoding="utf-8")
    for source in (init_sql, repair_sql):
        assert "scan_action_plan_json" in source
        assert "CREATE TABLE" in source and "scan_capability_actions" in source
        assert "UNIQUE (scan_id, action_id)" in source
        assert "input_binding_digest" in source
        assert "observation_manifest_id" in source
    for source in (init_sql, SCAN_ACTION_SCHEMA_SQL, lease_repair_sql):
        assert "lease_token_hash" in source
        assert "lease_expires_at" in source
        assert "result_json" in source
    for source in (init_sql, SCAN_ACTION_SCHEMA_SQL, receipt_repair_sql):
        assert "receipt_json" in source


def test_action_store_persists_precomputed_optional_skip_reasons():
    raw = _plan(active=True)
    plan = allocate_scan_action_plan(
        raw,
        ScanBudget(300, 1_000, 500, 50, 1_000, 180, 2, 0, 25),
    ).plan
    conn = FakeConn()
    asyncio.run(PostgresScanActionStore().persist_plan(conn, plan=plan))

    skipped = [row for row in conn.actions.values() if row["status"] == "skipped"]
    assert skipped
    assert {row["reason_code"] for row in skipped} <= {
        "insufficient_plan_budget", "dependency_failed",
    }
