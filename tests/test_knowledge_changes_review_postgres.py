"""Regression tests for the independent review of the applicability change (false skips and noise).

Each test reproduces a reviewer's proof against real PostgreSQL through the real app. Fixtures
(identified where written) follow tests/test_knowledge_changes_postgres.py: Scans, inventory rows,
findings and finished http.request actions whose input summaries are written through the real
redaction step (recorded_input), so a body, a principal binding or a pinned address is recorded the
way the Hunt action ledger records it.
"""
import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import asyncpg
from httpx import ASGITransport, AsyncClient

from tests.test_knowledge_changes_postgres import (  # noqa: F401 - the autouse fixture applies here too
    ORIGIN, SESSION, _check, _endpoint, _entry, _negative, _no_refresh_interval, _request, _scan, recorded_input,
)
from tests.test_interpretations_postgres import _hunt, _web_target
from tests.test_instruction_proposals_postgres import _prepared
from tests.test_target_asset_startup_postgres import startup_database


async def _setup(conn, monkeypatch, route='/api/invoices/{id}'):
    app_module = await _prepared(conn, monkeypatch)
    target = await _web_target(conn, ORIGIN)
    await _scan(conn, target, tech={'Express': '4.18'}, at=datetime.now(timezone.utc) - timedelta(hours=2))
    await _endpoint(conn, target, 'GET', route)
    return app_module, target


def _client(app_module):
    return AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator')


def test_p1_1_requests_that_are_not_plain_never_bind_or_skip(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module, target = await _setup(conn, monkeypatch)
            async with _client(app_module) as operator:
                hunt = (await _hunt(operator, target)).hunt
                for extra, principals in (({'json_body': {'owner': 'victim'}}, [SESSION]),
                                          ({'form_body': {'user': 'x'}}, [SESSION]),
                                          ({'session': None, 'as_principal': 'primary'}, ['anonymous']),
                                          ({'via_address': '203.0.113.9'}, [SESSION]),
                                          ({'follow_redirects': True}, [SESSION])):
                    evidence = await _request(conn, hunt.id, **extra)
                    stored = json.loads(await conn.fetchval('SELECT input_summary FROM hunt_actions WHERE id=$1',
                                                            UUID(evidence)))['input']
                    assert 'json_body' not in stored and 'form_body' not in stored  # recorded as the ledger does
                    entry = (await hunt.ok('knowledge.record', _negative(evidence, principals=principals)))
                    entry = entry['result']['interpretation']
                    assert entry['dependencies']['binding']['bound'] is False, extra
                    await _request(conn, hunt.id, **extra)  # repeated, unchanged
                    answer = await _check(hunt, _negative(evidence, principals=principals)['conditions'])
                    assert answer['skip'] is False, extra
    asyncio.run(run())


def test_p1_2_a_negative_on_another_origin_never_skips_the_default_origin(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module, target = await _setup(conn, monkeypatch)
            async with _client(app_module) as operator:
                hunt = (await _hunt(operator, target)).hunt
                other = f'{ORIGIN}:8443'
                evidence = await _request(conn, hunt.id, origin=other)
                entry = (await hunt.ok('knowledge.record', _negative(evidence, origin=other)))['result']['interpretation']
                assert entry['dependencies']['binding']['bound'] is True
                await _request(conn, hunt.id, origin=other)
                assert (await _check(hunt, _negative(evidence, origin=other)['conditions']))['skip'] is True
                # The default origin is another experiment (a different key): nothing to reuse.
                default = await _check(hunt, _negative(evidence)['conditions'])
                assert default['skip'] is False and default['identical'] == []
                # Naming the default origin for a request sent to :8443 never binds.
                wrong = (await hunt.ok('knowledge.record', _negative(evidence)))['result']['interpretation']
                assert wrong['dependencies']['binding']['bound'] is False
                assert (await _check(hunt, _negative(evidence)['conditions']))['skip'] is False
    asyncio.run(run())


def test_p1_3_every_placeholder_needs_its_own_named_object(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module, target = await _setup(conn, monkeypatch, route='/api/users/{id}/invoices/{id}')
            async with _client(app_module) as operator:
                hunt = (await _hunt(operator, target)).hunt
                evidence = await _request(conn, hunt.id, path='/api/users/5/invoices/17')
                loose = _negative(evidence, route='/api/users/{uid}/invoices/{id}')
                entry = (await hunt.ok('knowledge.record', loose))['result']['interpretation']
                assert entry['dependencies']['binding']['bound'] is False
                await _request(conn, hunt.id, path='/api/users/5/invoices/17')
                assert (await _check(hunt, loose['conditions']))['skip'] is False
                exact = _negative(evidence, route='/api/users/{uid}/invoices/{id}', objects=['user:5', 'invoice:17'])
                bound = (await hunt.ok('knowledge.record', exact))['result']['interpretation']
                assert bound['dependencies']['binding']['bound'] is True
                assert (await _check(hunt, exact['conditions']))['skip'] is True
                # User 6 is a different experiment.
                other = await _check(hunt, {**exact['conditions'], 'objects': ['user:6', 'invoice:17']})
                assert other['skip'] is False and other['identical'] == []
    asyncio.run(run())


def test_p1_4_a_body_only_change_revalidates_a_negative(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module, target = await _setup(conn, monkeypatch)
            async with _client(app_module) as operator:
                hunt = (await _hunt(operator, target)).hunt
                evidence = await _request(conn, hunt.id, status=200, keys=('items', 'total'),
                                          at=datetime.now(timezone.utc) - timedelta(seconds=30))
                entry = (await hunt.ok('knowledge.record', _negative(evidence)))['result']['interpretation']
                # Same status, media type and keys, another body (another tenant's items).
                await _request(conn, hunt.id, status=200, keys=('items', 'total'), digest='2' * 64)
                answer = await _check(hunt, _negative(evidence)['conditions'])
                assert answer['skip'] is False
                row = await _entry(conn, entry['id'])
                assert row['applicability'] == 'needs_revalidation'
                assert json.loads(row['applicability_reason'])['changes'][0]['field'] == 'body_digest'
    asyncio.run(run())


def test_p2_1_a_change_is_never_hidden_behind_later_requests(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module, target = await _setup(conn, monkeypatch)
            async with _client(app_module) as operator:
                hunt = (await _hunt(operator, target)).hunt
                start = datetime.now(timezone.utc) - timedelta(minutes=30)
                await conn.execute('UPDATE hunt_runs SET created_at=$2 WHERE id=$1', UUID(hunt.id),
                                   start - timedelta(minutes=1))
                evidence = await _request(conn, hunt.id, at=start)
                entry = (await hunt.ok('knowledge.record', _negative(evidence)))['result']['interpretation']
                # The same request answered 200 once ...
                await _request(conn, hunt.id, status=200, keys=('id', 'owner'), at=start + timedelta(minutes=1))
                # ... then 2,000 other requests and 500 repeats answering 403 again, before any read.
                other = [(uuid4(), UUID(hunt.id), json.dumps(recorded_input({'method': 'GET', 'path': f'/x/{i}'})),
                          json.dumps({'observations': []}), start + timedelta(minutes=2, milliseconds=i))
                         for i in range(2000)]
                await conn.executemany("""INSERT INTO hunt_actions(id,hunt_run_id,capability_name,status,input_summary,
                    result_summary,completed_at) VALUES($1,$2,'http.request','completed',$3::jsonb,$4::jsonb,$5)""",
                    other)
                for index in range(500):
                    await _request(conn, hunt.id, at=start + timedelta(minutes=3, milliseconds=index))
                answer = await _check(hunt, _negative(evidence)['conditions'])
                assert answer['skip'] is False
                assert (await _entry(conn, entry['id']))['applicability'] == 'needs_revalidation'
    asyncio.run(run())


def test_p2_2_an_entry_another_evaluation_holds_is_never_reused(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module, target = await _setup(conn, monkeypatch)
            async with _client(app_module) as operator:
                hunt = (await _hunt(operator, target)).hunt
                evidence = await _request(conn, hunt.id, at=datetime.now(timezone.utc) - timedelta(seconds=30))
                entry = (await hunt.ok('knowledge.record', _negative(evidence)))['result']['interpretation']
                await _request(conn, hunt.id)
                assert (await _check(hunt, _negative(evidence)['conditions']))['skip'] is True
                await _scan(conn, target, tech={'Express': '5.0'})  # significant, not yet evaluated
                other = await asyncpg.connect(os.environ['TARGET_ASSET_TEST_DATABASE_URL'],
                                              database=await conn.fetchval('SELECT current_database()'))
                try:
                    async with other.transaction():
                        await other.execute('SELECT 1 FROM target_interpretations WHERE id=$1 FOR UPDATE',
                                            UUID(entry['id']))
                        held = await _check(hunt, _negative(evidence)['conditions'])
                finally:
                    await other.close()
                assert held['skip'] is False
                assert 'not evaluated' in held['identical'][0]['reuse']['reason']
                after = await _check(hunt, _negative(evidence)['conditions'])
                assert after['skip'] is False and 'needs_revalidation' in after['identical'][0]['reuse']['reason']
    asyncio.run(run())


def test_p2_5_reuse_needs_a_fresh_observation_a_scan_can_provide_it(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module, target = await _setup(conn, monkeypatch)
            async with _client(app_module) as operator:
                first = (await _hunt(operator, target)).hunt
                evidence = await _request(conn, first.id)
                await first.ok('knowledge.record', _negative(evidence))
                await _request(conn, first.id)
                assert (await _check(first, _negative(evidence)['conditions']))['skip'] is True
                # A later Hunt has not observed anything yet: the same applicable entry is not reused.
                second = (await _hunt(operator, target)).hunt
                answer = await _check(second, _negative(evidence)['conditions'])
                assert answer['skip'] is False and 'not observed again' in answer['identical'][0]['reuse']['reason']
                # A Scan after that Hunt started saw the same deployment and the route: re-observed.
                await _scan(conn, target, tech={'Express': '4.18'},
                            at=datetime.now(timezone.utc) + timedelta(seconds=1))
                await conn.execute("UPDATE target_endpoints SET last_seen_at=NOW() + interval '2 seconds'")
                answer = await _check(second, _negative(evidence)['conditions'])
                assert answer['skip'] is True
                assert answer['identical'][0]['reuse']['reobserved']['by'].startswith('a Scan')
    asyncio.run(run())


def test_p2_3_p2_4_dismissals_reopen_on_regression_never_on_noise_and_follow_merges(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module, target = await _setup(conn, monkeypatch)

            async def finding(fingerprint=None, on=None):
                """Fixture: a scanner finding row."""
                return await conn.fetchval("""INSERT INTO findings(target_id,fingerprint,title,severity,tool,url)
                    VALUES($1,$2,'X','medium','nuclei','https://app.changes.test/s') RETURNING id""",
                    on or target, fingerprint or uuid4().hex)

            async with _client(app_module) as operator:
                async def dismiss(found):
                    response = await operator.post(f'/targets/{target}/findings/{found}/dismiss',
                                                   json={'reason': 'false_positive', 'note': 'n'})
                    assert response.status_code == 200, response.text
                    return response.json()['dismissal']['id']

                for verdict in ('false_positive', 'error', 'inconclusive'):
                    found = await finding()
                    dismissal = await dismiss(found)
                    await conn.execute('UPDATE findings SET last_verification_verdict=$2 WHERE id=$1', found, verdict)
                    await operator.get(f'/targets/{target}/negative-results')
                    assert (await _entry(conn, dismissal))['status'] == 'active', verdict
                    assert await conn.fetchval('SELECT status FROM findings WHERE id=$1', found) == 'false_positive'
                # Resolved and detected again (the scanner's resurfacing count): a regression.
                found = await finding()
                dismissal = await dismiss(found)
                await conn.execute('UPDATE findings SET resurfaced_count=resurfaced_count+1 WHERE id=$1', found)
                await operator.get(f'/targets/{target}/negative-results')
                row = await _entry(conn, dismissal)
                assert row['status'] == 'reopened' and 'resurfaced' in row['status_note']

            # A merge of duplicate targets keeps the person's decision on the surviving finding.
            duplicate = await _web_target(conn, 'https://dup.changes.test')
            shared = uuid4().hex
            survivor = await finding(fingerprint=shared)
            merged = await finding(fingerprint=shared, on=duplicate)
            await conn.execute("UPDATE findings SET updated_at=NOW() - interval '1 day' WHERE id=$1", survivor)
            async with _client(app_module) as operator:
                response = await operator.post(f'/targets/{duplicate}/findings/{merged}/dismiss',
                                               json={'reason': 'accepted_risk', 'note': 'Known'})
                assert response.status_code == 200, response.text
                dismissal = response.json()['dismissal']['id']
            from target_dedupe import merge_target_group
            await merge_target_group(conn, target, [duplicate])
            row = await _entry(conn, dismissal)
            assert row is not None and row['status'] == 'active' and row['finding_id'] == survivor
            assert await conn.fetchval('SELECT status FROM findings WHERE id=$1', survivor) == 'accepted_risk'
            async with _client(app_module) as operator:
                await operator.get(f'/targets/{target}/negative-results')
            assert (await _entry(conn, dismissal))['status'] == 'active'
    asyncio.run(run())
