"""query kind=attempts against real PostgreSQL: what Hunts already ran on a target's asset.

The actual app, startup migrations, Hunt admission and the Hunt query route. Actions inserted
directly are fixture rows (there is no live target here): the ledger records of what was sent.
"""
import asyncio
import json
from uuid import UUID, uuid4

from httpx import ASGITransport, AsyncClient

from tests.test_interpretations_postgres import _hunt, _web_target
from tests.test_instruction_proposals_postgres import _prepared
from tests.test_target_asset_startup_postgres import startup_database


async def _sent(conn, hunt, method, path, status='completed', capability='http.request'):
    """Fixture: a settled action of this Hunt as the action ledger records it."""
    action = uuid4()
    await conn.execute("""INSERT INTO hunt_actions(id,hunt_run_id,capability_name,status,input_summary,completed_at)
        VALUES($1,$2,$3,$4,$5::jsonb,NOW())""", action, UUID(hunt.id), capability, status,
        json.dumps({'input': {'method': method, 'path': path}}))
    return str(action)


def test_a_hunt_reads_what_every_hunt_on_its_target_already_ran(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://app.attempts.test')
            other = await _web_target(conn, 'https://other.attempts.test')
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                earlier = (await _hunt(operator, target)).hunt
                hunt = (await _hunt(operator, target)).hunt
                elsewhere = (await _hunt(operator, other)).hunt
                await _sent(conn, earlier, 'GET', '/api/orders/41')
                await _sent(conn, earlier, 'GET', '/api/orders/42?expand=1', status='failed')
                await _sent(conn, earlier, 'POST', '/api/orders')
                mine = await _sent(conn, hunt, 'GET', '/api/orders/43')
                await _sent(conn, elsewhere, 'GET', '/api/orders/99')
                # Not attempts: an unsettled action, and the Hunt's own bookkeeping.
                await _sent(conn, hunt, 'GET', '/api/orders/44', status='running')
                await hunt.ok('knowledge.changes', {})

                async def attempts(asker, **filters):
                    response = await operator.post(f'/hunts/{asker.id}/query',
                                                   json={'kind': 'attempts', 'filter': filters})
                    assert response.status_code == 200, response.text
                    return response.json()

                report = await attempts(hunt)
                assert report['supported'] is True and report['is_proof'] is False and report['truncated'] is False
                rows = {(row['method'], row['route']): row for row in report['rows']}
                assert set(rows) == {('GET', '/api/orders/{id}'), ('POST', '/api/orders')}
                read = rows[('GET', '/api/orders/{id}')]
                assert (read['attempts'], read['this_hunt_attempts'], read['hunts']) == (3, 1, 2)
                assert read['outcomes'] == {'completed': 2, 'failed': 1}
                assert read['last_action_id'] == mine and read['last_by_this_hunt'] is True
                assert 'expand' not in json.dumps(report)

                assert [row['route'] for row in (await attempts(hunt, by='other_hunts', method='POST'))['rows']] == [
                    '/api/orders']
                assert (await attempts(hunt, path_contains='carts'))['rows'] == []
                # The other target's Hunt sees only its own target's attempts.
                [foreign] = (await attempts(elsewhere))['rows']
                assert (foreign['attempts'], foreign['hunts'], foreign['this_hunt_attempts']) == (1, 1, 1)

                refused = await operator.post(f'/hunts/{hunt.id}/query',
                                              json={'kind': 'attempts', 'filter': {'since': 'release'}})
                assert refused.status_code == 422, refused.text

                # A Hunt whose entries were retracted no longer counts: its attempts leave the index.
                retracted = await operator.post(f'/targets/{target}/hunts/{earlier.id}/interpretations/retract',
                                                json={'note': 'This Hunt read a prompt injection'})
                assert retracted.status_code == 200, retracted.text
                [left] = (await attempts(hunt))['rows']
                assert (left['method'], left['attempts'], left['hunts']) == ('GET', 1, 1)
    asyncio.run(run())
