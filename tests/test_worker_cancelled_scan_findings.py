"""A cancelled canonical Scan keeps the findings its settled actions confirmed (worker entry).

``process_scan_job`` receives the report ``_execute_reserved_deterministic_scan`` builds after a
cancellation (``scan.cancelled_report``). The scan row stays ``cancelled``; its result and the
confirmed findings are persisted. Database, Redis and the scan executor are fixtures.
"""

import asyncio
import os
import sys
import types
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *args, **kwargs: None))

import worker  # noqa: E402
from scan.cancelled_report import mark_cancelled_scan_report  # noqa: E402
from scan.scan_deadline import load_scan_deadline  # noqa: E402

SCAN_ID = "22222222-2222-4222-8222-222222222222"
TARGET_ID = "33333333-3333-4333-8333-333333333333"


class _Redis:
    def __init__(self):
        self.hashes = []

    def hset(self, key, *args, mapping=None):
        self.hashes.append((key, dict(mapping or {})))

    def expire(self, *_args):
        return True

    def delete(self, *_args):
        return 1

    def lrange(self, *_args):
        return []

    def get(self, *_args):
        return None


class _Conn:
    def __init__(self, status: str):
        self.status = status
        self.kept_updates = []
        self.executions = []

    async def execute(self, query, *args):
        self.executions.append(query)
        return "UPDATE 1"

    async def fetchrow(self, query, *args):
        if "SELECT target_id, ai_target_id, device_target_id" in query:
            return {"target_id": uuid.UUID(TARGET_ID), "ai_target_id": None, "device_target_id": None}
        if "SELECT status FROM scans" in query:
            return {"status": self.status}
        return None

    async def fetchval(self, query, *args):
        if "RETURNING id" in query and "status IN ('cancelled','cancelling')" in query:
            self.kept_updates.append(args)
            return args[0] if self.status in {"cancelled", "cancelling"} else None
        if "SELECT status FROM scans" in query:
            return self.status
        return None

    async def fetch(self, *_args):
        return []


class _Pool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return self

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, *_args):
        return False


def _run(monkeypatch, *, status, report):
    conn = _Conn(status)
    redis = _Redis()
    saved = []

    async def identity(options, *_args):
        return options

    async def nothing(*_args, **_kwargs):
        return None

    async def execute_scan(*_args, **_kwargs):
        return report

    async def save_findings(scan_id, target_id, findings):
        saved.append((scan_id, target_id, list(findings)))
        return len(findings)

    async def queued(_scan_id):
        return "queued"

    async def artifact(*_args, **_kwargs):
        return "/tmp/result.json"

    async def archive(*_args, **_kwargs):
        return None

    monkeypatch.setattr(worker, "db_pool", _Pool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker, "_confirmed_scan_handoff_status", queued)
    monkeypatch.setattr(worker, "_standalone_scan_rate_reservation_amount", lambda _options: 0)
    monkeypatch.setattr(worker, "update_scan_progress", nothing)
    monkeypatch.setattr(worker, "send_heartbeats", lambda *_a, **_k: None)
    monkeypatch.setattr(worker, "_hydrate_generic_scan_credentials", identity)
    monkeypatch.setattr(worker, "_hydrate_managed_scan_credentials", identity)
    monkeypatch.setattr(worker, "_hydrate_scan_private_state_key", lambda options: options)
    monkeypatch.setattr(worker, "is_deterministic_dast", lambda _options: True)
    monkeypatch.setattr(worker, "_execute_reserved_deterministic_scan", execute_scan)
    monkeypatch.setattr(worker, "persist_result_artifact", artifact)
    monkeypatch.setattr(worker, "save_findings", save_findings)
    monkeypatch.setattr(worker.http_archive, "start_scan_capture", lambda *_a: False)
    monkeypatch.setattr(worker.http_archive, "drain_and_archive_scan_capture", archive)

    asyncio.run(worker.process_scan_job({
        "job_id": "job-cancelled-keep",
        "scan_id": SCAN_ID,
        "target": "https://example.test",
        "options": {"scan_type": "smart"},
    }))
    return conn, redis, saved


def _report():
    return mark_cancelled_scan_report({
        "target": "https://example.test",
        "findings": [{"title": "Missing HTTP response header: X-Frame-Options",
                      "severity": "info", "url": "https://example.test/"}],
        "result": {"score": 90, "grade": "A"},
        "coverage": {"status": "complete", "reasons": []},
        "scan_metadata": {},
    })


def test_a_cancelled_scan_keeps_its_confirmed_findings_and_stays_cancelled(monkeypatch):
    conn, redis, saved = _run(monkeypatch, status="cancelled", report=_report())

    assert saved == [(SCAN_ID, TARGET_ID, _report()["findings"])]
    assert len(conn.kept_updates) == 1
    args = conn.kept_updates[0]
    assert args[2] == 1  # findings_count
    assert args[5] == "cancelled"  # coverage_status
    # The cancelled row is never turned into a completed scan.
    assert not any("status = 'completed'" in query for query in conn.executions)
    assert redis.hashes[-1][1]["status"] == "cancelled"


def test_a_cancelled_scan_without_a_kept_report_still_saves_nothing(monkeypatch):
    error_report = {"target": "https://example.test", "error": "Cancelled by user",
                    "result": {"score": None, "grade": None}, "findings": []}
    conn, redis, saved = _run(monkeypatch, status="cancelled", report=error_report)
    assert saved == [] and conn.kept_updates == []
    assert redis.hashes[-1][1]["status"] == "cancelled"


def test_a_shard_runs_inside_its_parent_scans_time_limit(monkeypatch):
    from datetime import datetime

    parent = "55555555-5555-4555-8555-555555555555"
    starts = {parent: datetime(2026, 10, 10, 12, 0, 0),
              SCAN_ID: datetime(2026, 10, 10, 12, 30, 0)}
    asked = []

    class StartConn:
        async def fetchval(self, query, scan_uuid):
            assert "SELECT started_at FROM scans" in query
            asked.append(str(scan_uuid))
            return starts.get(str(scan_uuid))

    monkeypatch.setattr(worker, "db_pool", _Pool(StartConn()))
    shard = asyncio.run(load_scan_deadline(worker.db_pool, 
        scan_id=SCAN_ID, options={"_v2_worker_authority": {"parent_scan_id": parent}},
        max_duration_seconds=900,
    ))
    assert asked == [parent, SCAN_ID]
    assert shard.started_at == datetime(2026, 10, 10, 12, 0, 0).replace(
        tzinfo=__import__("datetime").timezone.utc).timestamp()
    # A shard whose own, smaller limit ends first keeps that one (the stale sweep reads it).
    asked.clear()
    small = asyncio.run(load_scan_deadline(worker.db_pool, 
        scan_id=SCAN_ID, options={"_v2_worker_authority": {"parent_scan_id": parent}},
        max_duration_seconds=3600, own_max_duration_seconds=180,
    ))
    assert small.max_duration_seconds == 180
    assert small.started_at == datetime(2026, 10, 10, 12, 30, 0).replace(
        tzinfo=__import__("datetime").timezone.utc).timestamp()
    asked.clear()
    standalone = asyncio.run(load_scan_deadline(worker.db_pool, 
        scan_id=SCAN_ID, options={}, max_duration_seconds=900,
    ))
    assert asked == [SCAN_ID] and standalone.max_duration_seconds == 900
    assert asyncio.run(load_scan_deadline(worker.db_pool, 
        scan_id=SCAN_ID, options={}, max_duration_seconds=0,
    )) is None


def test_an_unreadable_start_measures_the_limit_from_now(monkeypatch):
    import time

    class BrokenConn:
        async def fetchval(self, *_args):
            raise RuntimeError("database unavailable")

    monkeypatch.setattr(worker, "db_pool", _Pool(BrokenConn()))
    before = time.time()
    deadline = asyncio.run(load_scan_deadline(worker.db_pool, 
        scan_id=SCAN_ID, options={"_v2_worker_authority": "not-a-mapping"},
        max_duration_seconds=600,
    ))
    assert deadline is not None and deadline.started_at >= before


def test_a_kept_cancelled_report_names_the_cancelled_finalizer():
    report = mark_cancelled_scan_report({
        "findings": [], "coverage": {"status": "complete"},
        "canonical_action_execution": {
            "status_matrix": {"baseline.http": "success", "finalize.report": "success"},
            "finalization_action": {"action_id": "finalize.report", "status": "success"},
        },
    })
    execution = report["canonical_action_execution"]
    assert execution["finalization_action"]["status"] == "cancelled"
    assert execution["status_matrix"]["finalize.report"] == "cancelled"
    assert execution["finalized_after_cancellation"] is True


def test_a_report_finalized_before_the_cancellation_keeps_its_findings(monkeypatch):
    """B1: the cancel arrived while the report was finalized (the finalizer had already run):
    the Scan stays cancelled and keeps the report's findings."""
    report = {
        "target": "https://example.test",
        "findings": [{"title": "Reflected XSS", "severity": "high", "url": "https://example.test/q"}],
        "result": {"score": 40, "grade": "D"},
        "coverage": {"status": "complete", "reasons": []},
        "scan_metadata": {},
        "canonical_action_execution": {
            "status_matrix": {"baseline.http": "success", "finalize.report": "success"},
            "finalization_action": {"action_id": "finalize.report", "status": "success"},
        },
    }
    conn, redis, saved = _run(monkeypatch, status="cancelled", report=report)
    assert saved and saved[0][2][0]["title"] == "Reflected XSS"
    assert len(conn.kept_updates) == 1 and conn.kept_updates[0][5] == "cancelled"
    assert not any("status = 'completed'" in query for query in conn.executions)
    assert redis.hashes[-1][1]["status"] == "cancelled"
    stored = __import__("json").loads(conn.kept_updates[0][1])
    execution = stored["canonical_action_execution"]
    # The finalizer did run: its status is kept and the record says it ran before the cancel.
    assert execution["finalization_action"]["status"] == "success"
    assert execution["finalized_before_cancellation"] is True
    assert stored["scan_metadata"]["cancelled"] is True and stored["result"]["score"] == 40


def test_a_report_is_only_kept_for_a_cancelled_canonical_scan():
    from scan.cancelled_report import keep_report_finalized_before_cancellation

    canonical = {"findings": [], "canonical_action_execution": {}}
    assert keep_report_finalized_before_cancellation(dict(canonical), "running") == canonical
    assert keep_report_finalized_before_cancellation(dict(canonical), "failed") == canonical
    legacy = {"findings": [{"title": "x"}]}
    assert keep_report_finalized_before_cancellation(legacy, "cancelled") is legacy
    errored = {"error": "boom", "canonical_action_execution": {}}
    assert keep_report_finalized_before_cancellation(errored, "cancelled") is errored
    kept = keep_report_finalized_before_cancellation(dict(canonical), "cancelling")
    assert kept["scan_metadata"]["cancelled"] is True


def test_a_cancelled_parallel_parent_report_is_the_union_of_what_its_shards_kept():
    from scan.cancelled_report import cancelled_parallel_parent_report, is_kept_cancelled_report

    shared = {"title": "shared", "url": "https://example.test/a"}
    children = [
        {"id": "s0", "status": "completed", "shard_index": 0,
         "result": {"findings": [shared, {"title": "completed only"}]}},
        {"id": "s1", "status": "cancelled", "shard_index": 1,
         "result": mark_cancelled_scan_report({"findings": [shared, {"title": "kept"}], "coverage": {}})},
        # Cancelled with the old error result, or before it ran: nothing is kept from them.
        {"id": "s2", "status": "cancelled", "shard_index": 2,
         "result": {"error": "Cancelled by user", "findings": [{"title": "not kept"}]}},
        {"id": "s3", "status": "cancelled", "shard_index": 3, "result": None},
        {"id": "s4", "status": "failed", "shard_index": 4, "result": {"findings": [{"title": "failed"}]}},
    ]
    report = cancelled_parallel_parent_report(
        target_url="https://example.test", children=children,
        merge_key=lambda finding: finding["title"], extra_findings=[{"title": "recon"}],
    )
    assert [item["title"] for item in report["findings"]] == ["shared", "completed only", "kept", "recon"]
    assert is_kept_cancelled_report(report) and report["coverage"]["status"] == "cancelled"
    assert report["parallel"]["shards_kept"] == 2 and report["parallel"]["shards_total"] == 5


def test_a_work_round_cancelled_before_its_finalizer_reports_over_a_compiled_revision(monkeypatch):
    """A work round has no finalizer: the finalize-only revision is compiled, not persisted."""
    import scan.cancelled_report as cancelled_report
    from types import SimpleNamespace

    work = SimpleNamespace(action_id="verify.xss.r01")
    calls = {}

    class Dispatcher:
        plan = SimpleNamespace(actions=(work,))
        plan_revision = SimpleNamespace(revision=2)
        backend = SimpleNamespace(load_result=None)

        async def build_scan_report(self, *, plan=None, plan_revision=None):
            calls["built"] = (plan, plan_revision)
            return {"findings": [{"title": "kept"}], "coverage": {"status": "partial"}}

    async def load_result(_action_id):
        return object()

    Dispatcher.backend = SimpleNamespace(load_result=load_result)

    async def prepare(runtime, **kwargs):
        calls["prepare"] = kwargs
        return SimpleNamespace(plan="final-plan", revision="final-revision")

    async def load_allocation():
        return "allocation"

    monkeypatch.setattr(cancelled_report, "prepare_local_scan_continuation", prepare)
    report = asyncio.run(cancelled_report.cancelled_scan_report(
        Dispatcher(), scan_id=SCAN_ID, load_allocation=load_allocation, runtime="runtime",
    ))
    assert calls["prepare"]["revision_number"] == 3
    assert calls["prepare"]["finalize_only"] is True
    assert calls["built"] == ("final-plan", "final-revision")
    assert report["findings"] == [{"title": "kept"}] and report["coverage"]["status"] == "cancelled"

    async def no_allocation():
        return None

    import pytest
    with pytest.raises(ValueError, match="Cancelled by user"):
        asyncio.run(cancelled_report.cancelled_scan_report(
            Dispatcher(), scan_id=SCAN_ID, load_allocation=no_allocation, runtime="runtime",
        ))


def test_a_report_over_an_unstored_revision_says_so(monkeypatch):
    """Review of #399: the compiled finalize-only revision is never stored; the report must not
    send a reader to look for it."""
    import scan.cancelled_report as cancelled_report
    from types import SimpleNamespace

    class Dispatcher:
        async def build_scan_report(self, *, plan=None, plan_revision=None):
            return {"findings": [], "coverage": {}, "canonical_action_execution": {
                "finalization_action": {"action_id": "finalize.report", "status": "success"},
                "status_matrix": {"finalize.report": "success"}}}

    report = asyncio.run(cancelled_report.build_cancelled_scan_report(
        Dispatcher(), scan_id=SCAN_ID, finalization=("plan", SimpleNamespace(revision=3)),
    ))
    assert report["canonical_action_execution"]["plan_revision_stored"] is False
    stored = asyncio.run(cancelled_report.build_cancelled_scan_report(Dispatcher(), scan_id=SCAN_ID))
    assert "plan_revision_stored" not in stored["canonical_action_execution"]
