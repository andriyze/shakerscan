"""Finalized exhausted Hunts close transports; unfinished admitted work retains them."""
import asyncio
from contextlib import asynccontextmanager, suppress
import sqlite3
from types import SimpleNamespace
from uuid import uuid4

import pytest

from api.capabilities.ssh_transport import SshTransportPool
from api.hunt.ssh_routing import session_key, worker_key
from api.hunt.ssh_worker_lifecycle import maintain_ssh_sessions


class _Runs:
    """Execute the maintenance predicate with only PostgreSQL's ANY syntax adapted."""

    def __init__(self, finished, unfinished):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("CREATE TABLE hunt_runs(id TEXT, status TEXT, completed_at TEXT)")
        self.db.executemany("INSERT INTO hunt_runs VALUES(?, ?, ?)", [
            (finished, "budget_exhausted", "2026-10-04T00:00:00Z"),
            (unfinished, "budget_exhausted", None),
        ])

    @asynccontextmanager
    async def acquire(self):
        yield self

    async def fetch(self, query, identifiers):
        query = query.replace("id=ANY($1::uuid[])", "id IN (" + ",".join("?" for _ in identifiers) + ")")
        return [{"id": row[0]} for row in self.db.execute(query, [str(value) for value in identifiers])]


class _Directory:
    def __init__(self, sessions):
        self.values = {session_key(item.session_id): "published" for item in sessions}

    def set(self, key, value, *, ex):
        self.values[key] = value

    def delete(self, key):
        self.values.pop(key, None)


@pytest.mark.parametrize("unfinished_busy", [False, True], ids=["idle-reuse", "admitted-drain"])
def test_finalized_exhausted_hunt_reaped_without_closing_unfinished_session(unfinished_busy):
    async def scenario():
        reaped = asyncio.Event()

        class Transports(SshTransportPool):
            def reap(self, active_hunts=None):
                removed = super().reap(active_hunts)
                reaped.set()
                return removed

        finished, unfinished = str(uuid4()), str(uuid4())
        transports = Transports()
        sessions = []
        for owner in (finished, unfinished):
            session, _ = transports.acquire((owner, "binding", "192.0.2.1", 22, str(uuid4()), 1))
            session.transport = SimpleNamespace(is_active=lambda: True, is_authenticated=lambda: True,
                                                close=lambda: None)
            transports.release(session)
            sessions.append(session)
        closed, kept = sessions
        kept.busy = unfinished_busy
        directory = _Directory(sessions)
        runs = _Runs(finished, unfinished)
        worker = "fixture-ssh-owner"
        task = asyncio.create_task(maintain_ssh_sessions(directory, runs, worker, transports=transports))
        try:
            await asyncio.wait_for(reaped.wait(), 1)
            assert closed.closed and closed.session_id not in transports.sessions
            assert session_key(closed.session_id) not in directory.values
            assert kept.usable() and kept.session_id in transports.sessions
            assert session_key(kept.session_id) in directory.values
            assert worker_key(worker) in directory.values
            if unfinished_busy:
                assert kept.busy, "Admitted commands must be allowed to drain after budget exhaustion"
            else:
                reused, was_reused = transports.acquire(kept.binding, kept.session_id)
                assert reused is kept and was_reused
                transports.release(reused)
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
            runs.db.close()

    asyncio.run(scenario())
