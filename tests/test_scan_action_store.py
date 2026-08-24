from __future__ import annotations

import asyncio
import copy
from dataclasses import replace
import json
from pathlib import Path
import uuid

import pytest

from api.runtime.models import ScanBudget, ScanPolicy, TargetBinding
from api.scan.action_plan import ScanActionPlanCompiler
from api.scan.action_store import (
    ACTION_CONTINUATION_MIGRATION_NAME,
    ACTION_BUDGET_LINK_MIGRATION_NAME,
    ACTION_LEASE_MIGRATION_NAME,
    ACTION_PLAN_REVISION_CHAIN_MIGRATION_NAME,
    MIGRATION_NAME,
    PostgresScanActionStore,
    SCAN_ACTION_SCHEMA_SQL,
    ScanActionStoreError,
)
from api.scan.budget_allocator import allocate_scan_action_plan
from api.scan.continuation import (
    ScanContinuationAllocation,
    ScanPlanRevision,
    merge_scan_action_continuation,
)
from api.scan.execution import ScanExecutionPlan
from api.scan.work_manifests import build_canonical_scan_nuclei_template_manifest


SCAN_ID = "20000000-0000-4000-8000-000000000001"


def _plan(*, active=False, defer=False):
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
    template = build_canonical_scan_nuclei_template_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=target.digest,
        include_active=active,
    )
    return ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=execution,
        target_binding=target,
        template_manifest_ref=template.reference().canonical_dict(),
        defer_manifest_actions=defer,
        include_finalizer=not defer,
    )


class FakeConn:
    def __init__(self):
        self.executed = []
        self.plan_row = None
        self.actions = {}
        self.revisions = {}
        self.fail_action_id = None

    class _Transaction:
        def __init__(self, conn):
            self.conn = conn
            self.snapshot = None

        async def __aenter__(self):
            self.snapshot = (
                copy.deepcopy(self.conn.plan_row),
                copy.deepcopy(self.conn.actions),
                copy.deepcopy(self.conn.revisions),
            )
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            if exc_type is not None:
                (
                    self.conn.plan_row,
                    self.conn.actions,
                    self.conn.revisions,
                ) = self.snapshot
            return False

    def transaction(self):
        return self._Transaction(self)

    async def execute(self, query, *args):
        self.executed.append((query, args))
        return "OK"

    async def fetchrow(self, query, *args):
        if query.lstrip().startswith("INSERT INTO scan_action_plan_revisions"):
            if "VALUES ($1,0" in query:
                scan_id, plan_digest, schema, revision_digest, raw_plan = args
                incoming = {
                    "scan_id": scan_id,
                    "revision": 0,
                    "plan_digest": plan_digest,
                    "parent_plan_digest": None,
                    "continuation_allocation_digest": None,
                    "revision_schema": schema,
                    "discovery_result_digest": None,
                    "work_manifest_refs_json": [],
                    "continuation_plan_digest": None,
                    "revision_digest": revision_digest,
                    "plan_json": json.loads(raw_plan),
                }
            else:
                (
                    scan_id, plan_digest, parent_digest, allocation_digest,
                    schema, discovery_digest, raw_refs, continuation_digest,
                    revision_digest, raw_plan,
                ) = args
                incoming = {
                    "scan_id": scan_id,
                    "revision": 1,
                    "plan_digest": plan_digest,
                    "parent_plan_digest": parent_digest,
                    "continuation_allocation_digest": allocation_digest,
                    "revision_schema": schema,
                    "discovery_result_digest": discovery_digest,
                    "work_manifest_refs_json": json.loads(raw_refs),
                    "continuation_plan_digest": continuation_digest,
                    "revision_digest": revision_digest,
                    "plan_json": json.loads(raw_plan),
                }
            existing = self.revisions.get(incoming["revision"])
            if existing and (
                existing["plan_digest"] != incoming["plan_digest"]
                or existing.get("revision_digest") not in {
                    None, incoming["revision_digest"],
                }
            ):
                return None
            self.revisions[incoming["revision"]] = incoming
            return incoming
        if query.lstrip().startswith("UPDATE scan_action_plan_revisions"):
            scan_id, plan_digest, allocation_digest = args
            root = self.revisions.get(0)
            if (
                root is None
                or root["scan_id"] != scan_id
                or root["plan_digest"] != plan_digest
                or root.get("continuation_allocation_digest")
                not in {None, allocation_digest}
            ):
                return None
            root["continuation_allocation_digest"] = allocation_digest
            return root
        if "FROM scan_action_plan_revisions" in query:
            return self.revisions[max(self.revisions)] if self.revisions else None
        if "SET scan_continuation_allocation_json=" in query:
            scan_id, digest, raw, parent_digest = args
            if (
                self.plan_row is None
                or self.plan_row["scan_action_plan_digest"] != parent_digest
                or self.plan_row.get("scan_continuation_allocation_digest")
                not in {None, digest}
            ):
                return None
            self.plan_row.update({
                "scan_continuation_allocation_json": json.loads(raw),
                "scan_continuation_allocation_digest": digest,
                "scan_continuation_applied_at": None,
            })
            return self.plan_row
        if "SET scan_action_plan_json=$5::jsonb" in query:
            scan_id, parent_digest, allocation_digest, digest, raw, schema = args
            if (
                self.plan_row is None
                or self.plan_row["scan_action_plan_digest"] != parent_digest
                or self.plan_row.get("scan_continuation_allocation_digest")
                != allocation_digest
                or self.plan_row.get("scan_continuation_applied_at") is not None
            ):
                return None
            self.plan_row.update({
                "id": scan_id,
                "scan_action_plan_json": json.loads(raw),
                "scan_action_plan_digest": digest,
                "scan_action_plan_schema": schema,
                "scan_continuation_applied_at": "applied",
            })
            return self.plan_row
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
            if action_id == self.fail_action_id:
                raise RuntimeError("injected action-index failure")
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


def test_action_store_rolls_back_header_and_index_on_mid_plan_failure():
    plan = _plan()
    conn = FakeConn()
    conn.fail_action_id = plan.actions[1].action_id

    with pytest.raises(RuntimeError, match="injected action-index failure"):
        asyncio.run(PostgresScanActionStore().persist_plan(conn, plan=plan))

    assert conn.plan_row is None
    assert conn.actions == {}
    assert conn.revisions == {}


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
    assert ACTION_CONTINUATION_MIGRATION_NAME in SCAN_ACTION_SCHEMA_SQL
    assert ACTION_BUDGET_LINK_MIGRATION_NAME in SCAN_ACTION_SCHEMA_SQL
    assert ACTION_PLAN_REVISION_CHAIN_MIGRATION_NAME in SCAN_ACTION_SCHEMA_SQL
    assert "REFERENCES scans(id) ON DELETE CASCADE" in SCAN_ACTION_SCHEMA_SQL
    assert "REFERENCES budget_reservations(id)" in SCAN_ACTION_SCHEMA_SQL
    assert "idx_scan_capability_actions_reservation" in SCAN_ACTION_SCHEMA_SQL

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
    continuation_repair_sql = Path(
        "db/repairs/2026-08-23_v2_scan_action_continuations.sql"
    ).read_text(encoding="utf-8")
    budget_link_repair_sql = Path(
        "db/repairs/2026-08-24_v2_scan_action_budget_link.sql"
    ).read_text(encoding="utf-8")
    revision_repair_sql = Path(
        "db/repairs/2026-08-24_v2_scan_plan_revision_chain.sql"
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
    for source in (init_sql, SCAN_ACTION_SCHEMA_SQL, continuation_repair_sql):
        assert "scan_continuation_allocation_json" in source
        assert "scan_action_plan_revisions" in source
    for source in (SCAN_ACTION_SCHEMA_SQL, budget_link_repair_sql):
        assert "scan_capability_actions_reservation_fk" in source
        assert "REFERENCES budget_reservations(id)" in source
        assert "r.action_digest=a.action_digest" in source
    for source in (init_sql, SCAN_ACTION_SCHEMA_SQL, revision_repair_sql):
        assert "revision_digest" in source
        assert "discovery_result_digest" in source
        assert "work_manifest_refs_json" in source


def test_action_store_applies_one_idempotent_continuation_revision():
    parent = _plan(defer=True)
    complete = _plan()
    finalizer = next(
        action for action in complete.actions
        if action.action_id == "finalize.report"
    )
    continuation = type(complete)(
        scan_id=complete.scan_id,
        execution_plan_digest=complete.execution_plan_digest,
        target_binding_digest=complete.target_binding_digest,
        actions=(replace(
            finalizer, ordinal=0, dependencies=(), action_digest=None,
        ),),
    )
    allocation = ScanContinuationAllocation(
        scan_id=parent.scan_id,
        parent_plan_digest=parent.plan_digest,
        execution_plan_digest=parent.execution_plan_digest,
        target_binding_digest=parent.target_binding_digest,
        parent_action_ids=tuple(action.action_id for action in parent.actions),
        budget_ceiling={
            "http_requests": 1_000,
            "state_changing_requests": 0,
            "browser_actions": 50,
            "tcp_ports_attempted": 1_000,
            "hosts_attempted": 500,
            "tool_wall_seconds": 180,
        },
        max_endpoint_entries=500,
        max_candidate_entries=1_000,
        allowed_capabilities=(),
    )
    amended = merge_scan_action_continuation(
        parent_plan=parent,
        continuation_plan=continuation,
        allocation=allocation,
    )
    template = build_canonical_scan_nuclei_template_manifest(
        scan_id=parent.scan_id,
        target_binding_digest=parent.target_binding_digest,
        include_active=False,
    )
    revision = ScanPlanRevision(
        scan_id=amended.scan_id,
        revision=1,
        plan_digest=amended.plan_digest,
        parent_plan_digest=parent.plan_digest,
        continuation_allocation_digest=allocation.allocation_digest,
        discovery_result_digest="d" * 64,
        work_manifest_references=(template.reference().canonical_dict(),),
        continuation_plan_digest=continuation.plan_digest,
    )
    conn = FakeConn()
    store = PostgresScanActionStore()

    asyncio.run(store.persist_plan(conn, plan=parent))
    asyncio.run(store.persist_continuation_allocation(
        conn, allocation=allocation, parent_plan=parent,
    ))
    loaded_allocation = asyncio.run(store.load_continuation_allocation(
        conn, scan_id=SCAN_ID,
    ))
    first = asyncio.run(store.amend_plan(
        conn,
        parent_plan=parent,
        amended_plan=amended,
        allocation=allocation,
        revision=revision,
    ))
    second = asyncio.run(store.amend_plan(
        conn,
        parent_plan=parent,
        amended_plan=amended,
        allocation=allocation,
        revision=revision,
    ))

    assert loaded_allocation == allocation
    assert len(first) == len(second) == len(amended.actions)
    assert asyncio.run(store.load_plan(conn, scan_id=SCAN_ID)) == amended
    assert asyncio.run(store.load_plan_revision(conn, scan_id=SCAN_ID)) == revision


def test_action_store_persists_precomputed_optional_skips_as_unsettled_actions():
    raw = _plan(active=True)
    plan = allocate_scan_action_plan(
        raw,
        ScanBudget(300, 1_000, 500, 50, 1_000, 180, 2, 0, 25),
    ).plan
    conn = FakeConn()
    asyncio.run(PostgresScanActionStore().persist_plan(conn, plan=plan))

    allocated_skips = {
        action.action_id: action
        for action in plan.actions
        if action.admission_status == "skipped"
    }
    assert allocated_skips
    persisted = {
        action_id: conn.actions[action_id]
        for action_id in allocated_skips
    }
    assert {row["status"] for row in persisted.values()} == {"planned"}
    assert {row["reason_code"] for row in persisted.values()} <= {
        "insufficient_plan_budget", "dependency_failed",
    }
