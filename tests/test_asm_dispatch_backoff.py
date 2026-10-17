"""The Continuous ASM dispatcher must back off a target whose dispatch failed.

Before the fix, a target whose enqueue raised (typically ``422: ASM Scan target DNS
resolution failed`` for a host that no longer resolves) was retried on every tick:
the dispatcher stamps ``asm_last_test_at`` only on the success path, so a failing
target stayed eligible forever and hammered the log every ``ASM_DISPATCH_INTERVAL``.

These tests pin the fix: a failed dispatch records a ``dispatch_failed`` decision
with a ``next_eligible_at`` backoff, and a target still inside that backoff is skipped
without any dispatch bookkeeping being run.
"""
import asyncio
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import api as api_module  # noqa: E402


class _FakeAcquire:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, *exc):
        return False


class _Conn:
    """Answers the dispatcher's bounded selection: fingerprints, then the due targets' rows."""

    def __init__(self, rows):
        self.rows = rows
        self.executed = []
        self.queries = []

    async def fetch(self, query, *_args):
        self.queries.append(query)
        if "md5(" in query:
            return [{"id": row["id"], "fingerprint": "f"} for row in self.rows]
        if "metadata_json->'asm_last_decision'" in query:
            return [{**row, "last_decision": (row.get("metadata_json") or {}).get("asm_last_decision")}
                    for row in self.rows]
        return []  # batched counts: nothing active, claimable or tested

    async def fetchval(self, query, *_args):
        return None

    async def fetchrow(self, query, *_args):
        return None

    async def execute(self, query, *args):
        self.executed.append((query, args))
        return "UPDATE 1"


class _Pool:
    """``acquire()`` hands out the same fake connection; optionally fails on the Nth call."""

    def __init__(self, conn, fail_on_call=None):
        self.conn = conn
        self.calls = 0
        self.fail_on_call = fail_on_call

    def acquire(self):
        self.calls += 1
        if self.fail_on_call is not None and self.calls == self.fail_on_call:
            raise RuntimeError("pool exhausted")
        return _FakeAcquire(self.conn)


def _target_row(metadata_json=None):
    return {
        "id": uuid.uuid4(),
        "url": "http://gone.example.test:3000",
        "root_domain": "example.test",
        "scan_options": None,
        "asm_config": None,
        "asm_last_test_at": None,
        "asm_last_recon_at": None,
        "metadata_json": metadata_json,
    }


def _dns_failure(*_args, **_kwargs):
    raise HTTPException(status_code=422, detail="ASM Scan target DNS resolution failed")


async def _async_dns_failure(*_args, **_kwargs):
    _dns_failure()


@pytest.fixture
def quiet_redis(monkeypatch):
    monkeypatch.setattr(api_module, "get_redis", lambda: object())


def _run(pool):
    asyncio.run(api_module.run_asm_dispatch(pool))


def test_dispatch_failure_records_a_backoff_decision(monkeypatch, quiet_redis, capsys):
    row = _target_row()
    conn = _Conn([row])
    recorded = []

    async def record(conn_, target_id, decision, *, source, active_scan_ids=None, previous=None):
        recorded.append((str(target_id), dict(decision), source))
        return dict(decision)

    monkeypatch.setattr(api_module, "_persist_asm_decision", record)
    monkeypatch.setattr(api_module, "_enqueue_asm_recon", _async_dns_failure)

    started = datetime.now(timezone.utc)
    _run(_Pool(conn))

    assert "[asm] dispatch error for http://gone.example.test:3000" in capsys.readouterr().out
    assert len(recorded) == 1, "a failed dispatch must be recorded like every other dispatcher decision"
    target_id, decision, source = recorded[0]
    assert target_id == str(row["id"])
    assert source == "dispatcher"
    assert decision["action"] == "none"
    assert decision["blocked_by"] == "dispatch_failed"
    assert "DNS resolution failed" in decision["reason"]
    eligible_at = datetime.fromisoformat(decision["next_eligible_at"].replace("Z", "+00:00"))
    # The backoff reuses the target's own min test interval (60 minutes by default).
    assert eligible_at >= started + timedelta(minutes=59)
    assert eligible_at <= started + timedelta(minutes=61)


def test_target_inside_dispatch_backoff_is_skipped(monkeypatch, quiet_redis):
    eligible_at = datetime.now(timezone.utc) + timedelta(minutes=30)
    row = _target_row(metadata_json={
        "asm_last_decision": {
            "action": "none",
            "blocked_by": "dispatch_failed",
            "next_eligible_at": eligible_at.isoformat(),
        },
    })
    conn = _Conn([row])

    async def must_not_run(*_args, **_kwargs):
        raise AssertionError("a backed-off target must not reach dispatch bookkeeping")

    monkeypatch.setattr(api_module, "_enqueue_asm_recon", must_not_run)
    pool = _Pool(conn)
    _run(pool)
    # Only the initial target fetch touches the pool; nothing per-target is acquired.
    assert pool.calls == 1
    assert conn.executed == []


def test_expired_dispatch_backoff_lets_the_target_dispatch_again(monkeypatch, quiet_redis):
    eligible_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    row = _target_row(metadata_json={
        "asm_last_decision": {
            "action": "none",
            "blocked_by": "dispatch_failed",
            "next_eligible_at": eligible_at.isoformat(),
        },
    })
    conn = _Conn([row])
    reached = []

    async def observe(*_args, **_kwargs):
        reached.append(True)
        raise HTTPException(status_code=422, detail="stop here")

    monkeypatch.setattr(api_module, "_enqueue_asm_recon", observe)

    async def record(*_args, **_kwargs):
        return {}

    monkeypatch.setattr(api_module, "_persist_asm_decision", record)
    _run(_Pool(conn))
    assert reached == [True], "an expired backoff must not keep the target parked"


def test_failure_to_record_the_backoff_does_not_crash_the_tick(monkeypatch, quiet_redis, capsys):
    conn = _Conn([_target_row()])
    monkeypatch.setattr(api_module, "_enqueue_asm_recon", _async_dns_failure)
    # acquire #1 = due targets and their counts, #2 = per-target work, #3 = recording the failure.
    pool = _Pool(conn, fail_on_call=3)
    _run(pool)  # must not raise
    out = capsys.readouterr().out
    assert "[asm] dispatch error for" in out
    assert "could not record dispatch failure" in out


class _StoringConn(_Conn):
    """Keeps what the dispatcher records, as the targets row would, and its fingerprint."""

    def __init__(self, rows):
        super().__init__(rows)
        self.fingerprint = "f1"

    async def fetch(self, query, *args):
        self.queries.append(query)
        if "md5(" in query:
            return [{"id": row["id"], "fingerprint": self.fingerprint} for row in self.rows]
        if "metadata_json->'asm_last_decision'" in query:
            wanted = {str(value) for value in args[0]}
            return [{**row, "last_decision": (row.get("metadata_json") or {}).get("asm_last_decision")}
                    for row in self.rows if str(row["id"]) in wanted]
        return []

    async def execute(self, query, *args):
        self.executed.append((query, args))
        if "asm_last_decision" in query:
            target = next(row for row in self.rows if row["id"] == args[1])
            target["metadata_json"] = {"asm_last_decision": __import__("json").loads(args[0])}
        return "UPDATE 1"


def _quiet_target():
    row = _target_row()
    row["asm_last_recon_at"] = datetime.now(timezone.utc) - timedelta(hours=1)  # recon not due
    return row


def test_counts_are_loaded_once_per_tick_not_once_per_target(quiet_redis):
    conn = _StoringConn([_quiet_target() for _ in range(25)])
    _run(_Pool(conn))
    per_target_counts = [q for q in conn.queries if "COUNT(*)" in q.upper()]
    # active, claimable, tested-today and per-domain: one query each for all 25 targets.
    assert len(per_target_counts) == 4
    assert all("ANY(" in q or "unnest(" in q for q in per_target_counts)


def test_an_unchanged_decision_is_not_rewritten_and_a_deferred_target_is_not_reevaluated(quiet_redis):
    row = _quiet_target()
    conn = _StoringConn([row])
    _run(_Pool(conn))
    writes = [q for q, _args in conn.executed if "asm_last_decision" in q]
    assert len(writes) == 1, row["metadata_json"]
    assert row["metadata_json"]["asm_last_decision"]["blocked_by"] == "no_claimable_endpoints", row["metadata_json"]

    conn.queries.clear()
    _run(_Pool(conn))  # not due yet: only the fingerprint read, no per-target work at all
    assert len(conn.queries) == 1 and "md5(" in conn.queries[0]

    conn.fingerprint = "f2"  # its ASM configuration changed: due now
    _run(_Pool(conn))
    assert any("metadata_json->'asm_last_decision'" in q for q in conn.queries)
    writes = [q for q, _args in conn.executed if "asm_last_decision" in q]
    assert len(writes) == 1, "the same decision is not written again (only recorded_at would differ)"


def test_due_schedule_bounds_a_tick_and_prefers_the_most_overdue():
    from asm_dispatch_selection import AsmDueSchedule

    schedule = AsmDueSchedule()
    now = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)
    rows = [{"id": f"t{i}", "fingerprint": "f"} for i in range(10)]
    assert len(schedule.select(rows, now=now, limit=3)) == 3
    for i in range(10):
        schedule.schedule(f"t{i}", "f", {"blocked_by": "min_interval",
                                         "next_eligible_at": (now + timedelta(minutes=i)).isoformat()}, now=now)
    later = now + timedelta(minutes=2, seconds=30)
    assert schedule.select(rows, now=later, limit=10) == ["t0", "t1", "t2"]
    # Decisions that can change at any moment are due on the next tick.
    schedule.schedule("t9", "f", {"blocked_by": "active_scan"}, now=now)
    assert "t9" in schedule.select(rows, now=now, limit=10)
    # Nothing is deferred past the recheck ceiling, whatever its next_eligible_at says.
    schedule.schedule("t8", "f", {"blocked_by": "daily_endpoint_cap",
                                  "next_eligible_at": (now + timedelta(hours=24)).isoformat()}, now=now)
    assert "t8" in schedule.select(rows, now=now + timedelta(hours=1), limit=10)
