"""Archive/claim ordering with no target I/O; real PostgreSQL cases live alongside lifecycle acceptance."""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import uuid4
import pytest
from fastapi import HTTPException

from api.targets.archive import archive
from api.schedules.router import claim_due_schedule
from api.schedules.managed_occurrences import claim


class Connection:
    def __init__(self, active=True):
        self.active, self.events = active, []
    @asynccontextmanager
    async def transaction(self):
        self.events.append('begin')
        yield
        self.events.append('commit')
    async def fetchval(self, sql, *args):
        self.events.append(sql)
        return args[0]
    async def fetchrow(self, sql, *args):
        self.events.append(sql)
        if 'FOR SHARE OF t' in sql:
            return {'id': args[0], 'url':'https://example.invalid'} if self.active else None
        raise AssertionError('Archived target must not reach the schedule row')
    async def execute(self, sql, *args):
        self.events.append(sql)
        self.active = False
    async def fetch(self, sql, *args):
        self.events.append(sql)
        return [{'id':uuid4()}]


class Pool:
    def __init__(self, conn): self.conn = conn
    @asynccontextmanager
    async def acquire(self): yield self.conn


def test_archive_pauses_schedules_atomically_without_touching_jobs():
    conn = Connection()
    result = asyncio.run(archive(Pool(conn), uuid4()))
    assert result['schedules_paused'] == 1 and result['records_deleted'] is False
    assert result['running_work_cancelled'] is False
    assert conn.events[0] == 'begin' and conn.events[-1] == 'commit'
    sql = ' '.join(conn.events)
    assert 'FOR UPDATE' in sql and 'UPDATE schedules' in sql and 'next_run_at=NULL' in sql
    assert 'DELETE' not in sql and 'UPDATE scans' not in sql


def test_archived_target_cannot_be_claimed_by_either_scheduler():
    async def check():
        for managed in (False, True):
            conn = Connection(active=False)
            pool = Pool(conn)
            now = datetime.now(timezone.utc)
            result = (await claim(pool, uuid4(), 'https://gateway.invalid', {}, now=now) if managed
                      else await claim_due_schedule(pool, schedule_id=uuid4(), now=now))
            assert not result
            assert not any('UPDATE schedules' in sql or 'INSERT INTO' in sql for sql in conn.events)
    asyncio.run(check())


def test_schedule_cannot_be_reenabled_after_target_archive(monkeypatch):
    from api.schedules import router
    conn = Connection(active=False)
    monkeypatch.setattr(router, '_pool_provider', lambda: Pool(conn))
    async def unexpected_resolution(_url):
        raise AssertionError('An archived target must be refused before DNS')
    monkeypatch.setattr(router, 'validate_schedule_target_destination', unexpected_resolution)
    with pytest.raises(HTTPException) as error:
        asyncio.run(router.update_schedule(str(uuid4()), router.ScheduleUpdate(is_active=True)))
    assert error.value.status_code == 409
    assert not any('UPDATE schedules' in sql for sql in conn.events)
