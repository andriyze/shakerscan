"""The actual merge worker must persist the same assessment its report exposes."""
import asyncio
import json
import uuid
from datetime import datetime, timezone

from tests import test_worker_scan_ai_gating as cases


def test_merge_worker_persists_no_grade_for_redirect_only_children(monkeypatch):
    worker = cases.worker
    parent_id = "55555555-5555-5555-5555-555555555555"
    now = datetime(2026, 9, 19, 12, tzinfo=timezone.utc)

    class Conn:
        def __init__(self):
            self.updates = []

        async def fetchrow(self, query, *args):
            return {"target_id": None, "target_url": "https://example.test",
                    "options": {"parallel_strategy": "family"}, "scan_type": "smart",
                    "created_at": now, "started_at": now, "job_id": "parent-job",
                    "status": "running", "campaign_id": None}

        async def fetch(self, query, *args):
            return [{"id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
                "status": "completed", "score": 100, "grade": "A*", "findings_count": 0,
                "shard_index": 0, "options": {"parallel_backbone": True},
                "started_at": now, "completed_at": now, "campaign_id": None,
                "error_message": None,
                "result": {"schema_version": "canonical-scan-report/v2",
                           "target": "https://example.test", "findings": [],
                           "reachability": {"status": "reachable"},
                           "result": {"application_observed": False,
                                      "risk_assessment_state": "not_examined",
                                      "score": 100, "grade": "A*", "grade_reliable": False}}}]

        async def execute(self, query, *args):
            self.updates.append((query, args))
            return "UPDATE 1"

    conn = Conn()
    monkeypatch.setattr(worker, "db_pool", cases._FakeAsmPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: cases._FakeJobRedis())
    monkeypatch.setattr(worker, "save_result_file", lambda result, job_id: f"/tmp/{job_id}.json")
    asyncio.run(worker.process_scan_merge_job({"parent_scan_id": parent_id}))
    updates = [args for query, args in conn.updates if "UPDATE scans SET status = $1" in query]
    assert len(updates) == 1
    args = updates[0]
    assert args[0] == "completed"  # a reachable redirect is not failed preflight
    assert args[2] is None and args[3] is None
    report = json.loads(args[1])
    assert report["result"]["risk_assessment_state"] == "not_examined"
    assert report["result"]["grade"] is None
    assert report["result"]["risk_score"] is None
