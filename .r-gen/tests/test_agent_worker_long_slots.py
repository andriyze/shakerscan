"""A long job waiting for one of the agent-tool worker's long slots keeps its queue lease.

The agent-tool worker runs three leased jobs at once, a long action (sqli.verify, templates.scan,
a port scan) in at most two of them, so a short call (http.request, artifact.inspect) never waits
behind long actions (tests/test_hunt_concurrent_actions.py). A long job leased while both long
slots are taken waits inside the worker's leased execution: its queue lease is renewed while it
waits, so it is never reclaimed and run twice, and it does not hold the slot the short call runs
in. The worker stamps when each Hunt capability job's work starts, after that wait, because the
API counts the call's own time from then (tests/test_hunt_worker_result_wait.py).

Unit fixtures: Redis, the queue lease calls and the job handler are doubles; the worker's leased
runner, its heartbeat guard and the scheduler are the worker's own.
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import worker  # noqa: E402
from hunt import agent_job_concurrency as jobs  # noqa: E402


def _lease(index):
    return worker.QueueLease(
        queue_name="agent_tool_jobs", payload="{}", stream_key="agent_tool_jobs:stream",
        message_id=f"{index}-0",
    )


def _job(index, name):
    job_type = "canonical_http_capability" if name == "http.request" else "canonical_scanner_capability"
    return {"job_id": f"job-{index}", "type": job_type, "capability_name": name}


def test_a_long_job_waiting_for_a_slot_keeps_its_lease_and_a_short_job_runs(monkeypatch):
    ran, beats, acknowledged, gates = [], [], [], {}

    async def process(job):
        ran.append(job["job_id"])
        gates[job["job_id"]] = gate = asyncio.Event()
        await gate.wait()

    monkeypatch.setattr(worker, "AGENT_TOOL_ONLY_WORKER", True)
    monkeypatch.setattr(worker, "QUEUE_LEASE_HEARTBEAT_SECONDS", 0.01)
    monkeypatch.setattr(worker, "process_job", process)
    monkeypatch.setattr(worker, "heartbeat_lease", lambda _redis, lease, _consumer: beats.append(lease.message_id) or True)
    monkeypatch.setattr(worker, "acknowledge_lease", lambda _redis, lease: acknowledged.append(lease.message_id) or True)

    async def dispatch(index, name):
        await jobs.dispatch(None, _lease(index), _job(index, name),
                            execute=worker._run_job_under_lease, enabled=True)
        await asyncio.sleep(0.05)

    async def scenario():
        try:
            await dispatch(1, "sqli.verify")
            await dispatch(2, "templates.scan")
            await dispatch(3, "xss.verify")
            assert ran == ["job-1", "job-2"] and jobs._waiting == 1
            # The waiting job's lease is renewed while it waits, as a running job's is.
            assert "3-0" in beats
            # The short job is leased and runs at once beside the two long ones.
            await asyncio.wait_for(dispatch(4, "http.request"), 1)
            assert ran[-1] == "job-4"
            gates["job-4"].set()
            await asyncio.sleep(0.05)
            assert acknowledged == ["4-0"]
            # A long slot frees: the waiting job runs, and only then is its lease acknowledged.
            gates["job-1"].set()
            await asyncio.sleep(0.05)
            assert ran[-1] == "job-3" and "3-0" not in acknowledged
            for gate in gates.values():
                gate.set()
            await asyncio.sleep(0.05)
            assert sorted(acknowledged) == ["1-0", "2-0", "3-0", "4-0"]
            assert jobs._long_running == 0 and jobs._waiting == 0
        finally:
            await jobs.close()

    asyncio.run(asyncio.wait_for(scenario(), 10))  # a stalled scheduler fails, never hangs


class _StampRedis:
    """Labelled double: records the job hash fields the worker writes."""

    def __init__(self, fail=False):
        self.fields, self.fail = {}, fail

    def hset(self, key, mapping):
        if self.fail:
            raise ConnectionError("redis unavailable")
        self.fields.setdefault(key, {}).update(mapping)


def test_work_start_is_stamped_when_the_work_starts_not_when_the_job_is_leased(monkeypatch):
    redis = _StampRedis()
    gates = {}

    async def process(job):
        gates[job["job_id"]] = gate = asyncio.Event()
        await gate.wait()

    monkeypatch.setattr(worker, "AGENT_TOOL_ONLY_WORKER", True)
    monkeypatch.setattr(worker, "process_job", process)
    monkeypatch.setattr(worker, "acknowledge_lease", lambda *_args: True)
    monkeypatch.setattr(worker, "heartbeat_lease", lambda *_args: True)

    async def dispatch(index, name):
        await jobs.dispatch(redis, _lease(index), _job(index, name),
                            execute=worker._run_job_under_lease, enabled=True)
        await asyncio.sleep(0.05)

    async def scenario():
        try:
            await dispatch(1, "sqli.verify")
            await dispatch(2, "templates.scan")
            await dispatch(3, "xss.verify")
            await dispatch(4, "http.request")
            assert set(redis.fields) == {"job:job-1", "job:job-2", "job:job-4"}
            assert all(set(fields) == {"work_started_at"} for fields in redis.fields.values())
            # The long job that waited for a slot is stamped when it leaves the wait.
            gates["job-1"].set()
            await asyncio.sleep(0.05)
            assert "job:job-3" in redis.fields
            for gate in gates.values():
                gate.set()
        finally:
            await jobs.close()

    asyncio.run(asyncio.wait_for(scenario(), 10))


def test_the_work_start_stamp_never_fails_the_job_and_names_only_hunt_capability_jobs(monkeypatch):
    ran = []

    async def process(job):
        ran.append(job["job_id"])

    monkeypatch.setattr(worker, "AGENT_TOOL_ONLY_WORKER", False)
    monkeypatch.setattr(worker, "process_job", process)
    monkeypatch.setattr(worker, "acknowledge_lease", lambda *_args: True)
    broken = _StampRedis(fail=True)
    asyncio.run(worker._run_job_under_lease(broken, _lease(6), _job(6, "http.request")))
    assert ran == ["job-6"]
    # An ordinary worker stamps a Hunt capability job too (the API waits for it the same way),
    # and nothing else.
    redis = _StampRedis()
    asyncio.run(worker._run_job_under_lease(redis, _lease(7), _job(7, "http.request")))
    asyncio.run(worker._run_job_under_lease(redis, _lease(8), {"job_id": "job-8", "type": "scan"}))
    assert set(redis.fields) == {"job:job-7"} and ran == ["job-6", "job-7", "job-8"]


def test_an_ordinary_worker_runs_its_job_without_the_long_slots(monkeypatch):
    ran = []

    async def process(job):
        ran.append(job["job_id"])

    monkeypatch.setattr(worker, "AGENT_TOOL_ONLY_WORKER", False)
    monkeypatch.setattr(worker, "process_job", process)
    monkeypatch.setattr(worker, "acknowledge_lease", lambda *_args: True)

    async def in_lane(*_args):  # never reached on a Web DAST worker
        raise AssertionError("an ordinary worker job went through the agent-tool lanes")

    monkeypatch.setattr(jobs, "in_lane", in_lane)
    asyncio.run(worker._run_job_under_lease(None, _lease(5), _job(5, "sqli.verify")))
    assert ran == ["job-5"]
