"""Fault-injection tests for database-only uploads, not execution retries.

In-memory transactional doubles exercise outcome boundaries. Run PostgreSQL and
real collection-route integration acceptance before publishing these changes.
"""
import asyncio
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest
from public_retry_atomic import acquire_for_atomic_retry, execute_atomic_write


class Transaction:
    def __init__(self, conn):
        self.conn = conn
    async def __aenter__(self):
        self.conn.local = deepcopy(self.conn.pool.state)
        self.conn.baseline = deepcopy(self.conn.local)
        return self
    async def __aexit__(self, typ, *_):
        c = self.conn
        try:
            if typ is None:
                failure = c.pool.commit_failure
                c.pool.commit_failure = None
                if failure == 'before':
                    raise ConnectionError('fixture commit refused')
                if c.local != c.baseline:
                    c.pool.state = deepcopy(c.local)
                if failure == 'after':
                    raise ConnectionError('fixture lost commit acknowledgement')
        finally:
            if c.holds_lock:
                c.pool.locked = False
        return False


class Connection:
    def __init__(self, pool):
        self.pool = pool
        self.holds_lock = False
    def transaction(self):
        return Transaction(self)
    async def fetchval(self, _sql, *_):
        if self.pool.locked:
            return False
        self.pool.locked = True
        self.holds_lock = True
        return True
    async def fetchrow(self, sql, *args):
        if sql.lstrip().startswith('INSERT'):
            if self.local['receipt']:
                return None
            self.local['receipt'] = {'method': args[0], 'path': args[1], 'key_sha256': args[2],
                                     'request_sha256': args[3], 'state': 'processing'}
            return {'method': args[0]}
        return deepcopy(self.local['receipt'])
    async def execute(self, _sql, *args):
        self.local['receipt'].update(state='completed', response_status=args[4],
                                     response_headers=args[5], response_body=args[6])
        return 'UPDATE 1'


class Acquire:
    def __init__(self, pool):
        self.conn = Connection(pool)
    async def __aenter__(self):
        return self.conn
    async def __aexit__(self, *_):
        return False


class Pool:
    def __init__(self):
        self.state = {'receipt': None, 'effects': 0}
        self.locked = False
        self.commit_failure = None
    def acquire(self):
        return Acquire(self)


class Middleware:
    def __init__(self, app):
        self.app = app
    @staticmethod
    async def _json_response(send, status, detail):
        await send({'type': 'http.response.start', 'status': status, 'headers': [(b'content-type', b'application/json')]})
        await send({'type': 'http.response.body', 'body': json.dumps({'detail': detail}).encode()})
    @staticmethod
    async def _replay(send, row):
        await send({'type': 'http.response.start', 'status': row['response_status'],
                    'headers': [(b'content-type', b'application/json'), (b'idempotency-replayed', b'true')]})
        await send({'type': 'http.response.body', 'body': row['response_body']})


async def emit(send, status=200, body=b'{"id":"synthetic-collection"}'):
    await send({'type': 'http.response.start', 'status': status, 'headers': [(b'content-type', b'application/json')]})
    await send({'type': 'http.response.body', 'body': body})


def app_for(pool, failure=None):
    async def app(_scope, _receive, send):
        if failure == 'before_effect':
            raise RuntimeError('fixture interruption')
        async with acquire_for_atomic_retry(pool) as conn:
            conn.local['effects'] += 1
        if failure == 'after_effect':
            raise RuntimeError('fixture interruption')
        if failure == 'cancel':
            raise asyncio.CancelledError
        await emit(send, status=422 if failure == 'reject' else 200,
                   body=b'x' * 100 if failure == 'oversize' else b'{"id":"synthetic-collection"}')
    return app


async def exchange(pool, app=None, request_digest='b' * 64, sender=None, cap=4096):
    out = []
    async def capture(message):
        out.append(message)
    await execute_atomic_write(
        Middleware(app or app_for(pool)),
        scope={'type': 'http', 'method': 'POST', 'path': '/request-collections'},
        messages=[{'type': 'http.request', 'body': b'{}', 'more_body': False}],
        send=sender or capture, pool=pool, key_digest='a' * 64, request_digest=request_digest,
        max_response_bytes=cap,
    )
    return out


def test_success_then_replay_does_not_repeat_mutation():
    async def run():
        p = Pool()
        first = await exchange(p)
        second = await exchange(p)
        assert p.state['effects'] == 1
        assert p.state['receipt']['state'] == 'completed'
        assert first[-1]['body'] == second[-1]['body']
        assert (b'idempotency-replayed', b'true') in second[0]['headers']
    asyncio.run(run())


@pytest.mark.parametrize('failure', ['before_effect', 'after_effect', 'cancel'])
def test_interruption_rolls_back_reservation_and_mutation(failure):
    async def run():
        p = Pool()
        with pytest.raises((RuntimeError, asyncio.CancelledError)):
            await exchange(p, app_for(p, failure))
        assert p.state == {'receipt': None, 'effects': 0}
        assert not p.locked
        assert (await exchange(p))[0]['status'] == 200
        assert p.state['effects'] == 1
    asyncio.run(run())


def test_response_delivery_failure_preserves_replay_receipt():
    async def run():
        p = Pool()
        async def broken_send(_message):
            assert p.state['receipt']['state'] == 'completed'
            raise ConnectionError('fixture disconnected client')
        with pytest.raises(ConnectionError):
            await exchange(p, sender=broken_send)
        assert (await exchange(p))[0]['status'] == 200
        assert p.state['effects'] == 1
    asyncio.run(run())


@pytest.mark.parametrize('when', ['before', 'after'])
def test_uncertain_commit_recovers_both_or_neither(when):
    async def run():
        p = Pool()
        p.commit_failure = when
        with pytest.raises(ConnectionError):
            await exchange(p)
        assert p.state['effects'] == (1 if when == 'after' else 0)
        assert (await exchange(p))[0]['status'] == 200
        assert p.state['effects'] == 1
    asyncio.run(run())


def test_rejection_rolls_back_any_partial_mutation():
    async def run():
        p = Pool()
        assert (await exchange(p, app_for(p, 'reject')))[0]['status'] == 422
        assert p.state == {'receipt': None, 'effects': 0}
        assert (await exchange(p))[0]['status'] == 200
    asyncio.run(run())


def test_historical_unknown_receipt_is_not_erased():
    async def run():
        p = Pool()
        p.state = {'receipt': {'state': 'processing', 'request_sha256': 'b' * 64}, 'effects': 1}
        before = deepcopy(p.state)
        assert (await exchange(p))[0]['status'] == 409
        assert p.state == before
    asyncio.run(run())


def test_same_key_different_request_is_rejected():
    async def run():
        p = Pool()
        await exchange(p)
        assert (await exchange(p, request_digest='c' * 64))[0]['status'] == 409
        assert p.state['effects'] == 1
    asyncio.run(run())


def test_oversized_response_rolls_back_and_reports_safe_failure():
    async def run():
        p = Pool()
        # Set cap above the small rejection but below the synthetic response.
        async def app(scope, receive, send):
            async with acquire_for_atomic_retry(p) as conn:
                conn.local['effects'] += 1
            await emit(send, body=b'x' * 4097)
        assert (await exchange(p, app, cap=4096))[0]['status'] == 503
        assert p.state == {'receipt': None, 'effects': 0}
    asyncio.run(run())


def test_concurrent_duplicate_returns_conflict_then_replays():
    async def run():
        p = Pool()
        entered, release = asyncio.Event(), asyncio.Event()
        async def paused(scope, receive, send):
            entered.set()
            await release.wait()
            await app_for(p)(scope, receive, send)
        first = asyncio.create_task(exchange(p, paused))
        await entered.wait()
        assert (await exchange(p))[0]['status'] == 409
        release.set()
        await first
        await exchange(p)
        assert p.state['effects'] == 1
    asyncio.run(run())


def test_awaited_child_task_can_share_connection_serially():
    async def run():
        p = Pool()
        async def app(scope, receive, send):
            await asyncio.create_task(app_for(p)(scope, receive, send))
        assert (await exchange(p, app))[0]['status'] == 200
        assert p.state['effects'] == 1
    asyncio.run(run())


def test_handler_cannot_switch_database():
    async def run():
        p, other = Pool(), Pool()
        async def app(scope, receive, send):
            async with acquire_for_atomic_retry(other):
                raise AssertionError('must not acquire unrelated connection')
        with pytest.raises(RuntimeError):
            await exchange(p, app)
        assert p.state == {'receipt': None, 'effects': 0}
    asyncio.run(run())


def test_unsupported_execution_route_is_never_transactionally_retried():
    async def run():
        p = Pool()
        with pytest.raises(ValueError):
            await execute_atomic_write(Middleware(app_for(p)),
                scope={'method': 'POST', 'path': '/scans'}, messages=[], send=None,
                pool=p, key_digest='a' * 64, request_digest='b' * 64, max_response_bytes=4096)
        assert p.state == {'receipt': None, 'effects': 0}
    asyncio.run(run())


def test_real_asgi_middleware_child_task_preserves_atomic_connection():
    from fastapi import FastAPI
    async def run():
        p = Pool()
        app = FastAPI()
        @app.middleware('http')
        async def boundary(request, call_next):
            return await call_next(request)
        @app.post('/request-collections')
        async def create_collection():
            async with acquire_for_atomic_retry(p) as conn:
                conn.local['effects'] += 1
            return {'id': 'synthetic-collection'}
        out = []
        async def capture(message):
            out.append(message)
        async def still_connected():
            await asyncio.Event().wait()
        await execute_atomic_write(
            Middleware(app), scope={
                'type':'http', 'method':'POST', 'path':'/request-collections',
                'raw_path':b'/request-collections', 'root_path':'', 'query_string':b'',
                'scheme':'http', 'http_version':'1.1',
                'asgi':{'version':'3.0', 'spec_version':'2.4'},
                'server':('test', 80), 'client':('127.0.0.1', 1),
                'headers':[(b'content-type',b'application/json'),(b'content-length',b'2')],
            }, messages=[{'type':'http.request','body':b'{}','more_body':False}],
            send=capture, pool=p, key_digest='a'*64, request_digest='b'*64,
            max_response_bytes=4096, receive_after_body=still_connected,
        )
        assert out[0]['status'] == 200
        assert p.state['effects'] == 1
        assert p.state['receipt']['state'] == 'completed'
    asyncio.run(run())
