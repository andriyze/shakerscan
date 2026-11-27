"""query kind=traffic against real PostgreSQL: the calls already archived for a target.

The actual app, startup migrations, Hunt admission and the Hunt query route. Archive rows inserted
directly are fixture rows: what the archive writer records for a call that was sent.
"""
import asyncio
import json
from uuid import UUID, uuid4

from httpx import ASGITransport, AsyncClient

from api.runtime.http_archive_search import searchable_url
from tests.test_interpretations_postgres import _hunt, _web_target
from tests.test_instruction_proposals_postgres import _prepared
from tests.test_target_asset_startup_postgres import startup_database


async def _call(conn, target, hunt, method, url, status, *, slot=None, capability='http.request', legacy=False):
    """Fixture: one archived call of this Hunt, stored as the archive writer stores it."""
    call = uuid4()
    await conn.execute(
        """INSERT INTO http_transactions(id,plane,hunt_run_id,target_id,capability_name,principal_slot,
                                         method,url,status_code,search_url,started_at)
           VALUES($1,'hunt',$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp())""",
        call, UUID(hunt.id), UUID(str(target)), capability, slot, method, url, status,
        None if legacy else searchable_url(url))
    return str(call)


def test_a_hunt_searches_the_calls_already_archived_for_its_target(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://app.traffic.test')
            other = await _web_target(conn, 'https://other.traffic.test')
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                earlier = (await _hunt(operator, target)).hunt
                hunt = (await _hunt(operator, target)).hunt
                elsewhere = (await _hunt(operator, other)).hunt
                listed = await _call(conn, target, earlier, 'GET',
                                     'https://user:PASSWORDVALUE@app.traffic.test/api/orders?token=QUERYSECRET', 200,
                                     slot='primary')
                denied = await _call(conn, target, earlier, 'GET', 'https://app.traffic.test/api/orders/7', 403,
                                     slot='secondary')
                mine = await _call(conn, target, hunt, 'POST', 'https://app.traffic.test/api/orders', 201)
                await _call(conn, target, earlier, 'GET', 'https://app.traffic.test/api/orders/8', 200, legacy=True)
                await _call(conn, other, elsewhere, 'GET', 'https://other.traffic.test/api/orders', 200)

                async def traffic(asker=hunt, expect=200, **filters):
                    response = await operator.post(f'/hunts/{asker.id}/query',
                                                   json={'kind': 'traffic', 'filter': filters})
                    assert response.status_code == expect, response.text
                    return response.json()

                report = await traffic()
                assert report['supported'] is True and report['is_proof'] is False and report['has_more'] is False
                # Every call to this target's asset, newest first; none from another target.
                assert len(report['rows']) == 4 and report['rows'][1]['transaction_id'] == mine
                assert 'other.traffic.test' not in json.dumps(report)
                # The masked origin and path only: no userinfo, no query, no stored raw URL.
                first = next(row for row in report['rows'] if row['transaction_id'] == listed)
                assert first['url'] == 'https://app.traffic.test/api/orders'
                assert 'PASSWORDVALUE' not in json.dumps(report) and 'QUERYSECRET' not in json.dumps(report)
                assert (first['hunt_id'], first['by_this_hunt'], first['principal_slot']) == (earlier.id, False, 'primary')

                # Filters narrow by path, method, status and who sent it.
                assert [row['transaction_id'] for row in (await traffic(path_contains='/orders/7'))['rows']] == [denied]
                assert [row['transaction_id'] for row in (await traffic(status_class='4xx'))['rows']] == [denied]
                assert [row['transaction_id'] for row in (await traffic(method='post'))['rows']] == [mine]
                assert [row['transaction_id'] for row in (await traffic(by='this_hunt'))['rows']] == [mine]
                assert len((await traffic(by='other_runs', status_code=200))['rows']) == 2
                assert [row['transaction_id'] for row in (await traffic(principal_slot='secondary'))['rows']] == [denied]
                # A path search cannot be used to confirm a withheld value, and LIKE wildcards are literal.
                assert (await traffic(path_contains='QUERYSECRET'))['rows'] == []
                assert (await traffic(path_contains='PASSWORDVALUE'))['rows'] == []
                assert (await traffic(path_contains='%'))['rows'] == []
                # A call archived before the masked URL existed has none and matches no path search.
                assert sum(row['url'] is None for row in report['rows']) == 1

                for bad in ({'status_code': 99}, {'status_class': '6xx'}, {'plane': 'device'}, {'by': 'nobody'},
                            {'text_contains': 'x'}, {'method': ''}):
                    await traffic(expect=422, **bad)

                # A retracted Hunt's calls are left out, like the rest of what it wrote.
                retracted = await operator.post(f'/targets/{target}/hunts/{earlier.id}/interpretations/retract',
                                                json={'note': 'This Hunt read a prompt injection'})
                assert retracted.status_code == 200, retracted.text
                assert [row['transaction_id'] for row in (await traffic())['rows']] == [mine]
    asyncio.run(run())
