"""P3-13: fail-closed worker freshness — a build-stale worker must refuse a job
submitted with require_current_workers, not silently run stale code."""
import asyncio
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace())
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *a, **k: None))

import worker  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


def test_normal_job_is_not_refused():
    # No expected fingerprint / no require_current -> never refused.
    assert _run(worker._refuse_stale_job_if_needed({"options": {}})) is False


def test_current_worker_runs_matching_job():
    fp = worker._worker_build_fingerprint()
    if not fp:
        return  # no /app source to fingerprint in this env
    job = {"options": {"require_current_workers": True, "expected_build_fingerprint_at_submit": fp}}
    assert _run(worker._refuse_stale_job_if_needed(job)) is False


def test_stale_worker_refuses_and_requeues(monkeypatch):
    pushed = []

    class _FakeRedis:
        def rpush(self, queue, payload):
            pushed.append(queue)

        def hset(self, *a, **k):
            pass

    monkeypatch.setattr(worker, "get_redis", lambda: _FakeRedis())
    job = {"type": "scan", "job_id": "j1", "scan_id": "fake",
           "options": {"require_current_workers": True,
                       "expected_build_fingerprint_at_submit": "STALE_DOES_NOT_MATCH"}}
    refused = _run(worker._refuse_stale_job_if_needed(job))
    assert refused is True
    assert pushed == [worker.QUEUE_NAME]
    assert job["stale_requeue_attempts"] == 1
