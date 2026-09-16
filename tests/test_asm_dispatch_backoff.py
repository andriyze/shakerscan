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
    def __init__(self, rows):
        self.rows = rows
        self.executed = []

    async def fetch(self, query, *_args):
        return self.rows

    async def fetchval(self, query, *_args):
        return 0

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


@pytest.fixture
def quiet_redis(monkeypatch):
    monkeypatch.setattr(api_module, "get_redis", lambda: object())


def _run(pool):
    asyncio.run(api_module.run_asm_dispatch(pool))


def test_dispatch_failure_records_a_backoff_decision(monkeypatch, quiet_redis, capsys):
    row = _target_row()
    conn = _Conn([row])
    recorded = []

    async def record(conn_, target_id, decision, *, source, active_scan_ids=None):
        recorded.append((str(target_id), dict(decision), source))

    monkeypatch.setattr(api_module, "_persist_asm_decision", record)
    monkeypatch.setattr(api_module.asm_inventory, "claimable_count", _dns_failure)

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

    def must_not_run(*_args, **_kwargs):
        raise AssertionError("a backed-off target must not reach dispatch bookkeeping")

    monkeypatch.setattr(api_module.asm_inventory, "claimable_count", must_not_run)
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

    def observe(*_args, **_kwargs):
        reached.append(True)
        raise HTTPException(status_code=422, detail="stop here")

    monkeypatch.setattr(api_module.asm_inventory, "claimable_count", observe)

    async def record(*_args, **_kwargs):
        return None

    monkeypatch.setattr(api_module, "_persist_asm_decision", record)
    _run(_Pool(conn))
    assert reached == [True], "an expired backoff must not keep the target parked"


def test_failure_to_record_the_backoff_does_not_crash_the_tick(monkeypatch, quiet_redis, capsys):
    conn = _Conn([_target_row()])
    monkeypatch.setattr(api_module.asm_inventory, "claimable_count", _dns_failure)
    # acquire #1 = target list, #2 = per-target work, #3 = recording the failure.
    pool = _Pool(conn, fail_on_call=3)
    _run(pool)  # must not raise
    out = capsys.readouterr().out
    assert "[asm] dispatch error for" in out
    assert "could not record dispatch failure" in out
