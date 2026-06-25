"""P3-13: fail-closed worker freshness. A worker that cannot PROVE it is current
must refuse a job submitted with require_current_workers — running stale (or
unknown-build) code silently corrupts results. Deterministic: the build
fingerprint is mocked so the test does not depend on /app being present."""
import asyncio
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace())
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *a, **k: None))

import worker  # noqa: E402

CURRENT_FP = "deadbeefcafef00d"


def _job(expected, require=True, **extra):
    opts = {"require_current_workers": require}
    if expected is not None:
        opts["expected_build_fingerprint_at_submit"] = expected
    return {"type": "scan", "job_id": "j1", "scan_id": "fake", "options": opts, **extra}


def _run(coro):
    return asyncio.run(coro)


def test_normal_job_is_not_refused(monkeypatch):
    monkeypatch.setattr(worker, "_worker_build_fingerprint", lambda: CURRENT_FP)
    # No expected fingerprint / not require_current -> never refused.
    assert _run(worker._refuse_stale_job_if_needed({"options": {}})) is False
    assert _run(worker._refuse_stale_job_if_needed(_job(CURRENT_FP, require=False))) is False


def test_current_worker_runs_matching_job(monkeypatch):
    monkeypatch.setattr(worker, "_worker_build_fingerprint", lambda: CURRENT_FP)
    assert _run(worker._refuse_stale_job_if_needed(_job(CURRENT_FP))) is False


def test_stale_worker_refuses_and_requeues(monkeypatch):
    monkeypatch.setattr(worker, "_worker_build_fingerprint", lambda: "STALE_DIFFERENT")
    pushed = []

    class _FakeRedis:
        def rpush(self, queue, payload):
            pushed.append(queue)

        def hset(self, *a, **k):
            pass

    monkeypatch.setattr(worker, "get_redis", lambda: _FakeRedis())
    job = _job(CURRENT_FP)
    assert _run(worker._refuse_stale_job_if_needed(job)) is True
    assert pushed == [worker.QUEUE_NAME]
    assert job["stale_requeue_attempts"] == 1


def test_unknown_fingerprint_fails_closed(monkeypatch):
    # A worker that cannot fingerprint itself is NOT provably current -> must refuse
    # (this was a fail-OPEN bug: unknown was treated as safe-to-run).
    monkeypatch.setattr(worker, "_worker_build_fingerprint", lambda: None)
    pushed = []
    monkeypatch.setattr(worker, "get_redis",
                        lambda: types.SimpleNamespace(rpush=lambda q, p: pushed.append(q), hset=lambda *a, **k: None))
    assert _run(worker._refuse_stale_job_if_needed(_job(CURRENT_FP))) is True
    assert pushed == [worker.QUEUE_NAME]
