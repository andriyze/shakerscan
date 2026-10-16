"""Continuation measures, skip-advice accounting and legacy triage receipts against real PostgreSQL
through the actual app.

Fixture rows (identified where written): completed Scans with recorded technologies, endpoint
inventory rows, findings and finished http.request actions with their recorded request and response
summary; no live target runs here.
"""
import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4, uuid5

import pytest
from httpx import ASGITransport, AsyncClient

from hunt import knowledge_changes, knowledge_continue
from tests.test_instruction_proposals_postgres import _prepared
from tests.test_interpretations_postgres import _fixture_finding, _hunt, _web_target
from tests.test_knowledge_changes_postgres import ORIGIN, SESSION, _endpoint, _request, _scan
from tests.test_target_asset_startup_postgres import startup_database


@pytest.fixture(autouse=True)
def _no_caches(monkeypatch, tmp_path):
    import secret_store
    monkeypatch.setattr(knowledge_changes, 'MIN_REFRESH_SECONDS', 0.0)
    monkeypatch.setattr(knowledge_changes, 'BRIEFING_CACHE_SECONDS', 0.0)
    monkeypatch.setattr(knowledge_changes, 'REPORT_CACHE_SECONDS', 0.0)
    monkeypatch.setattr(knowledge_continue, 'REPORT_CACHE_SECONDS', 0.0)
    monkeypatch.setattr(knowledge_continue, 'BRIEFING_CACHE_SECONDS', 0.0)
    knowledge_changes._last_refresh.clear()
    # Decision receipts need the persisted installation key (a clean runner has no /results).
    monkeypatch.delenv('AI_CREDENTIAL_ENC_KEY', raising=False)
    monkeypatch.setenv('AI_CREDENTIAL_ENC_KEY_FILE', str(tmp_path / 'receipt.key'))
    monkeypatch.setattr(secret_store, '_loaded', False)
    monkeypatch.setattr(secret_store, '_fernet', None)


def _ago(**delta):
    return datetime.now(timezone.utc) - timedelta(**delta)


def _conditions(route, obj):
    return {'origin': ORIGIN, 'method': 'GET', 'route': route, 'objects': [obj],
            'technique': 'http.request cross-tenant read'}


def _negative(evidence, route, obj):
    return {'kind': 'negative_result', 'negative_state': 'experiment_completed_negative',
            'title': 'No cross-tenant read', 'evidence_refs': [evidence], 'conditions': _conditions(route, obj)}


async def _events(conn, target, kind='report_read'):
    return await conn.fetch('SELECT * FROM knowledge_continue_events WHERE target_id=$1 AND kind=$2 ORDER BY first_at',
                            target, kind)


def test_continuing_after_a_release_is_measured_from_the_records(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://app.changes.test')
            await conn.execute('UPDATE targets SET created_at=$2 WHERE id=$1', target, _ago(days=30))  # fixture
            await _scan(conn, target, tech={'Express': '4.18'}, at=_ago(days=9))
            for path in ('/api/invoices/{id}', '/api/orders/{id}', '/api/legacy'):
                await _endpoint(conn, target, 'GET', path, first_seen=_ago(days=9))
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                # Day 1: two negatives and one more request on the legacy route.
                day1 = (await _hunt(operator, target)).hunt
                await conn.execute('UPDATE hunt_runs SET created_at=$2 WHERE id=$1', UUID(day1.id), _ago(days=8))
                invoices = await _request(conn, day1.id, path='/api/invoices/17', at=_ago(days=8))
                orders = await _request(conn, day1.id, path='/api/orders/5', at=_ago(days=8))
                await _request(conn, day1.id, path='/api/legacy', status=200, at=_ago(days=8))
                await conn.execute('UPDATE hunt_actions SET started_at=$2 WHERE hunt_run_id=$1', UUID(day1.id),
                                   _ago(days=8))  # fixture: they ran on day 1
                negative = await day1.ok('knowledge.record', _negative(invoices, '/api/invoices/{id}', 'invoice:17'))
                await day1.ok('knowledge.record', _negative(orders, '/api/orders/{id}', 'order:5'))
                # The release, then a new route.
                released = await operator.post(f'/targets/{target}/knowledge/releases',
                                               json={'label': '2.0', 'released_at': _ago(days=1).isoformat()})
                assert released.status_code == 201, released.text
                await _endpoint(conn, target, 'GET', '/api/exports', first_seen=_ago(hours=1))

                # Nobody read the report yet: nothing to measure.
                empty = (await operator.get(f'/targets/{target}/knowledge/continue/measures')).json()
                assert 'Nobody read' in empty['note'] and empty['incorrect_suppression']['skip_advice'] == 0

                # The operator reads it twice: one event, two reads, the required re-tests kept.
                report = await operator.get(f'/targets/{target}/knowledge/continue')
                assert report.status_code == 200, report.text
                assert report.json()['cache']['cached'] is False
                await operator.get(f'/targets/{target}/knowledge/continue')
                [read] = await _events(conn, target)
                assert read['reads'] == 2 and read['reader'].startswith('operator:') and read['hunt_run_id'] is None
                required = json.loads(read['required'])
                # Unbound entries (no principal named) are re-tested from their recorded route.
                assert {item['path'] for item in required} == {'/api/invoices/{id}', '/api/orders/{id}'}
                assert {route['path'] for route in json.loads(read['routes'])} == {'/api/exports'}
                assert 'No cross-tenant read' not in read['required'] + read['routes']  # no text

                # Day 8: a Hunt reads the report, repeats the legacy request (redundant), then re-tests
                # the invoice: it answers 200 now (a regression), recorded beside the negative.
                day8 = (await _hunt(operator, target)).hunt
                await day8.ok('knowledge.continue', {})
                assert len(await _events(conn, target)) == 2
                await _request(conn, day8.id, path='/api/legacy', status=200)
                retest = await _request(conn, day8.id, path='/api/invoices/17', status=200, keys=('id', 'tenant'),
                                        digest='2' * 64)
                observed = await day8.ok('knowledge.record', {
                    'kind': 'observation', 'title': 'Invoice 17 readable cross-tenant', 'evidence_refs': [retest],
                    'conditions': _conditions('/api/invoices/{id}', 'invoice:17')})
                assert observed['result']['interpretation']['kind'] == 'observation'

                measures = await operator.get(f'/targets/{target}/knowledge/continue/measures')
                assert measures.status_code == 200, measures.text
                result = measures.json()
                assert result['started_by'] == 'operator' and result['reads'] == {'total': 3, 'operators': 1, 'hunts': 1}
                assert result['required_retests']['listed_at_start'] == 2
                assert result['required_retests']['run'] == 1 and result['required_retests']['not_run'] == 1
                assert result['required_retests']['not_run_items'][0]['path'] == '/api/orders/{id}'
                assert result['first_useful_step']['action_id'] == retest
                assert result['first_useful_step']['seconds'] >= 0
                assert result['redundant_requests'] == {**result['redundant_requests'],
                                                        'requests_after_start': 2, 'redundant': 1, 'share': 0.5}
                [changed] = result['new_results']['changed_outcomes']
                assert changed['earlier_id'] == negative['result']['interpretation']['id']
                assert (changed['earlier_outcome'], changed['outcome']) == ('experiment_completed_negative', 'observation')
                assert result['incorrect_suppression']['contradicted'] == 0

                usage = (await operator.get('/knowledge/continue/usage', params={'weeks': 2})).json()
                assert sum(item['operators'] for item in usage['items']) >= 1
                assert sum(item['reads'] for item in usage['items']) == 3
                # A planner cannot read the measures (operator routes only).
                bad = await operator.get(f'/targets/{target}/knowledge/continue/measures', params={'since': 'x' * 101})
                assert bad.status_code == 422
    asyncio.run(run())


def test_skip_advice_is_kept_and_a_later_change_counts_as_incorrect_suppression(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://app.changes.test')
            await _scan(conn, target, tech={'Express': '4.18'}, at=_ago(hours=2))
            await _endpoint(conn, target, 'GET', '/api/invoices/{id}')
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                hunt = (await _hunt(operator, target)).hunt
                evidence = await _request(conn, hunt.id)
                conditions = {**_conditions('/api/invoices/{id}', 'invoice:17'), 'principals': [SESSION]}
                saved = await hunt.ok('knowledge.record', {**_negative(evidence, '/api/invoices/{id}', 'invoice:17'),
                                                           'conditions': conditions})
                entry = saved['result']['interpretation']
                assert entry['dependencies']['conditions_check']['consistent'] is True
                assert entry['dependencies']['conditions_check']['fields']['principals'] == 'matched'
                await _request(conn, hunt.id)
                answer = (await hunt.ok('knowledge.check_experiment', {'conditions': conditions}))['result']
                assert answer['skip'] is True
                await hunt.ok('knowledge.check_experiment', {'conditions': conditions})
                [advice] = await _events(conn, target, 'skip_advice')
                assert str(advice['entry_id']) == entry['id'] and advice['reads'] == 2
                assert json.loads(advice['request'])['path'] == '/api/invoices/17'
                # Later the same request answers 200: the advice was wrong; the measures say so.
                await _request(conn, hunt.id, status=200, keys=('id',), digest='3' * 64,
                               at=datetime.now(timezone.utc) + timedelta(seconds=1))
                again = (await hunt.ok('knowledge.check_experiment', {'conditions': conditions}))['result']
                assert again['skip'] is False
                since = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
                result = (await operator.get(f'/targets/{target}/knowledge/continue/measures',
                                             params={'since': since})).json()
                suppression = result['incorrect_suppression']
                assert suppression['skip_advice'] == 1 and suppression['contradicted'] == 1
                assert suppression['items'][0]['entry_id'] == entry['id']
    asyncio.run(run())


async def _revert(client, target, receipt):
    return await client.post(f"/targets/{target}/knowledge/decisions/{receipt['id']}/revert",
                             json={'receipt_sha256': receipt['receipt_sha256']})


def test_triage_inverse_serializes_a_concurrent_operator_write(monkeypatch):
    """A writer arriving after inverse preflight waits for its transaction, then wins;
    the engine never silently overwrites a newer committed decision."""
    async def run():
        import asyncpg
        from targets import triage_receipts
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://triage-lock.test')
            finding = await _fixture_finding(conn, target)
            database = await conn.fetchval('SELECT current_database()')
            writer = await asyncpg.connect(os.environ['TARGET_ASSET_TEST_DATABASE_URL'], database=database)
            checked, proceed = asyncio.Event(), asyncio.Event()
            original = triage_receipts.restore

            async def paused_restore(*args):
                checked.set()
                await asyncio.wait_for(proceed.wait(), timeout=10)
                return await original(*args)

            monkeypatch.setattr(triage_receipts, 'restore', paused_restore)
            inverse = concurrent = None
            try:
                async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as client:
                    changed = await client.patch(f'/findings/{finding}', json={'status': 'accepted_risk'},
                                                 headers={'x-shakerscan-decision-id': str(uuid4())})
                    assert changed.status_code == 200, changed.text
                    inverse = asyncio.create_task(_revert(client, target, changed.json()['decision_receipt']))
                    await asyncio.wait_for(checked.wait(), timeout=10)
                    concurrent = asyncio.create_task(writer.execute(
                        "UPDATE findings SET status='resolved', updated_at=clock_timestamp() WHERE id=$1", finding))
                    # Inspect real blocking, rather than assuming a short sleep proves a lock.
                    for _ in range(100):
                        if await conn.fetchval('SELECT cardinality(pg_blocking_pids($1)) > 0', writer.get_server_pid()):
                            break
                        await asyncio.sleep(0.01)
                    else:
                        raise AssertionError('the concurrent finding writer was not blocked by the inverse lock')
                    assert not concurrent.done()
                    proceed.set()
                    response = await asyncio.wait_for(inverse, timeout=10)
                    assert response.status_code == 200, response.text
                    await asyncio.wait_for(concurrent, timeout=10)
                    assert await conn.fetchval('SELECT status FROM findings WHERE id=$1', finding) == 'resolved'
            finally:
                proceed.set()
                for task in (inverse, concurrent):
                    if task is not None and not task.done():
                        task.cancel()
                await asyncio.gather(*(t for t in (inverse, concurrent) if t is not None), return_exceptions=True)
                await writer.close()
    asyncio.run(run())


def test_legacy_triage_writes_record_a_reversible_receipt(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://triage.test')
            other = await _web_target(conn, 'https://other-triage.test')
            finding = await _fixture_finding(conn, target)
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as client:
                advertised = await client.get('/knowledge/decisions?limit=1')
                assert 'legacy_triage' in advertised.json()['supported_decisions']
                # Without the gateway's decision id the route behaves as before (no receipt).
                plain = await client.patch(f'/findings/{finding}', json={'notes': 'first look'})
                assert plain.status_code == 200 and 'decision_receipt' not in plain.json()
                assert await conn.fetchval('SELECT count(*) FROM target_operator_decisions') == 0

                decision = str(uuid4())
                body = {'status': 'accepted_risk', 'notes': 'owner accepts', 'analyst_verdict': 'accepted_risk'}
                changed = await client.patch(f'/findings/{finding}', json=body,
                                             headers={'x-shakerscan-decision-id': decision})
                assert changed.status_code == 200, changed.text
                receipt = changed.json()['decision_receipt']
                assert receipt['decision'] == 'legacy_triage' and receipt['id'] == decision
                assert changed.json()['status'] == 'accepted_risk'
                # The same decision id and body replays the receipt; another body under it is refused.
                replay = await client.patch(f'/findings/{finding}', json=body,
                                            headers={'x-shakerscan-decision-id': decision})
                assert replay.json()['decision_receipt']['id'] == decision
                reused = await client.patch(f'/findings/{finding}', json={'status': 'resolved'},
                                            headers={'x-shakerscan-decision-id': decision})
                assert reused.status_code == 409
                reverted = await _revert(client, target, receipt)
                assert reverted.status_code == 200, reverted.text
                row = await conn.fetchrow('SELECT status, notes, analyst_verdict FROM findings WHERE id=$1', finding)
                assert dict(row) == {'status': 'active', 'notes': 'first look', 'analyst_verdict': None}

                # A dismissal ended by a status change comes back when that change is reverted.
                dismissed = await client.post(f'/targets/{target}/findings/{finding}/dismiss',
                                              json={'reason': 'false_positive', 'note': 'Reviewed'})
                assert dismissed.status_code == 200, dismissed.text
                ended = await client.patch(f'/findings/{finding}', json={'status': 'active'},
                                           headers={'x-shakerscan-decision-id': str(uuid4())})
                assert ended.status_code == 200, ended.text
                assert await conn.fetchval("""SELECT status FROM target_interpretations WHERE finding_id=$1""",
                                           finding) == 'reopened'
                assert (await _revert(client, target, ended.json()['decision_receipt'])).status_code == 200
                assert await conn.fetchval('SELECT status FROM findings WHERE id=$1', finding) == 'false_positive'
                assert await conn.fetchval("""SELECT status FROM target_interpretations WHERE finding_id=$1""",
                                           finding) == 'active'

                # Bulk: one target's findings per receipt; changed records block the revert.
                second = await _fixture_finding(conn, target, title='Second')
                elsewhere = await _fixture_finding(conn, other, title='Elsewhere')
                mixed = await client.post('/findings/bulk', json={'finding_ids': [str(second), str(elsewhere)],
                                                                  'status': 'resolved'},
                                          headers={'x-shakerscan-decision-id': str(uuid4())})
                assert mixed.status_code == 409
                assert await conn.fetchval('SELECT status FROM findings WHERE id=$1', second) == 'active'
                bulk = await client.post('/findings/bulk', json={'finding_ids': [str(second)], 'status': 'resolved'},
                                         headers={'x-shakerscan-decision-id': str(uuid4())})
                assert bulk.status_code == 200 and bulk.json()['updated'] == 1, bulk.text
                await conn.execute("UPDATE findings SET notes='touched later' WHERE id=$1", second)
                assert (await _revert(client, target, bulk.json()['decision_receipt'])).status_code == 409
                assert await conn.fetchval('SELECT status FROM findings WHERE id=$1', second) == 'resolved'

                # Finding exceptions: a reverted creation is deleted, an update restored, a deletion restored.
                decision = str(uuid4())
                created = await client.post('/finding-exceptions', headers={'x-shakerscan-decision-id': decision},
                                            json={'finding_id': str(finding), 'target_id': str(target),
                                                  'owner': 'sec', 'approver': 'lead', 'reason': 'compensated', 'status': 'revoked',
                                                  'expires_at': (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()})
                assert created.status_code == 200, created.text
                exception = created.json()['id']
                assert exception == str(uuid5(UUID(decision), 'finding-exception'))
                assert (await _revert(client, target, created.json()['decision_receipt'])).status_code == 200
                assert await conn.fetchval('SELECT count(*) FROM finding_exceptions WHERE id=$1', UUID(exception)) == 0
                kept = await client.post('/finding-exceptions', json={
                    'finding_id': str(finding), 'target_id': str(target), 'owner': 'sec', 'approver': 'lead',
                    'reason': 'original', 'status': 'revoked', 'expires_at': (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()})
                kept_id = kept.json()['id']
                updated = await client.patch(f'/finding-exceptions/{kept_id}', json={'reason': 'changed'},
                                             headers={'x-shakerscan-decision-id': str(uuid4())})
                assert updated.status_code == 200 and updated.json()['reason'] == 'changed', updated.text
                assert (await _revert(client, target, updated.json()['decision_receipt'])).status_code == 200
                assert await conn.fetchval('SELECT reason FROM finding_exceptions WHERE id=$1', UUID(kept_id)) == 'original'
                deleted = await client.delete(f'/finding-exceptions/{kept_id}',
                                              headers={'x-shakerscan-decision-id': str(uuid4())})
                assert deleted.status_code == 200, deleted.text
                assert await conn.fetchval('SELECT count(*) FROM finding_exceptions WHERE id=$1', UUID(kept_id)) == 0
                assert (await _revert(client, target, deleted.json()['decision_receipt'])).status_code == 200
                assert await conn.fetchval('SELECT reason FROM finding_exceptions WHERE id=$1', UUID(kept_id)) == 'original'
                # Review sweep: the receipt's target is the finding's; a client naming another
                # target for it is refused and nothing is written.
                misfiled = await client.post('/finding-exceptions', headers={'x-shakerscan-decision-id': str(uuid4())},
                                             json={'finding_id': str(finding), 'target_id': str(other),
                                                   'owner': 'sec', 'approver': 'lead', 'reason': 'misfiled',
                                                   'status': 'revoked', 'expires_at': (datetime.now(timezone.utc)
                                                                                       + timedelta(days=30)).isoformat()})
                assert misfiled.status_code == 409, misfiled.text
                assert await conn.fetchval("SELECT count(*) FROM finding_exceptions WHERE reason='misfiled'") == 0
                # An exception naming no target and no finding on one cannot carry a receipt.
                targetless = await client.post('/finding-exceptions', headers={'x-shakerscan-decision-id': str(uuid4())},
                                               json={'fingerprint': 'abc', 'owner': 'sec', 'approver': 'lead',
                                                     'reason': 'global', 'status': 'revoked', 'expires_at': (datetime.now(timezone.utc)
                                                                                        + timedelta(days=30)).isoformat()})
                assert targetless.status_code == 422
                assert await conn.fetchval("SELECT count(*) FROM finding_exceptions WHERE fingerprint='abc'") == 0
                # The generic decision route never applies a triage decision.
                generic = await client.post(f'/targets/{target}/knowledge/decisions', json={
                    'receipt_id': str(uuid4()), 'target_id': str(target), 'decision': 'legacy_triage',
                    'triage_route': 'finding_patch', 'finding_ids': [str(finding)], 'triage': {'status': 'resolved'}})
                assert generic.status_code == 422
                assert await conn.fetchval('SELECT status FROM findings WHERE id=$1', finding) == 'false_positive'
    asyncio.run(run())
