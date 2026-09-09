"""Completed replay and expired preview need no inventory/writer locks."""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi import HTTPException
from api.data_lifecycle.service import execute
from api.data_lifecycle.inventory import digest


def completed():
    operation, approval, finding = uuid4(), uuid4(), uuid4()
    manifest = {'kind':'findings', 'root_ids':[str(finding)]}
    payload = {'manifest':manifest, 'selection':{'kind':'findings', 'finding_ids':[str(finding)]},
        'preview_hash':digest(manifest), 'expires_at':(datetime.now(timezone.utc)-timedelta(days=1)).isoformat(),
        'result':{'status':'deleted', 'operation_id':str(operation), 'approval_receipt_id':str(approval),
                  'deleted_ids':[str(finding)], 'deleted':1, 'idempotent_replay':False}}
    return {'id':operation, 'approval_receipt_id':approval, 'status':'completed', 'result_json':payload}


class ReadOnlyPool:
    def __init__(self, row): self.row, self.reads = row, 0
    @asynccontextmanager
    async def acquire(self): yield self
    @asynccontextmanager
    async def transaction(self): yield self
    async def fetchrow(self, sql, *args):
        assert sql.startswith('SELECT * FROM command_results')
        assert 'FOR UPDATE' not in sql
        self.reads += 1
        return self.row
    async def execute(self, *args):
        raise AssertionError('Preflight/replay must not request writer locks or perform mutations')
    async def fetch(self, *args):
        raise AssertionError('Preflight/replay must not enumerate the catalog')


def test_completed_replay_is_read_only_even_after_preview_expiry():
    row = completed(); pool = ReadOnlyPool(row)
    result = asyncio.run(execute(pool, row['id'], row['approval_receipt_id'],
                 preview_hash=row['result_json']['preview_hash']))
    assert result['idempotent_replay'] is True and result['deleted'] == 1
    assert pool.reads == 1


@pytest.mark.parametrize('mismatch', ['approval','hash','kind','entity','stored_result'])
def test_replay_still_checks_exact_request_binding_without_writer_locks(mismatch):
    row = completed(); pool = ReadOnlyPool(row)
    approval = uuid4() if mismatch == 'approval' else row['approval_receipt_id']
    kwargs = {'preview_hash':'f' * 64} if mismatch == 'hash' else {}
    if mismatch == 'kind': kwargs['kind'] = 'target'
    if mismatch == 'entity': kwargs['entity_id'] = uuid4()
    if mismatch == 'stored_result': row['result_json']['result']['operation_id'] = str(uuid4())
    with pytest.raises(HTTPException) as exc:
        asyncio.run(execute(pool, row['id'], approval, **kwargs))
    assert exc.value.status_code == 409
    assert pool.reads == 1


def test_expired_preview_is_rejected_before_catalog_or_locks():
    row = completed(); row['status'] = 'approval_required'
    with pytest.raises(HTTPException, match='expired'):
        asyncio.run(execute(ReadOnlyPool(row), row['id'], row['approval_receipt_id']))
