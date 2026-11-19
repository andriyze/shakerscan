"""query kind=coverage_gaps: graph auth boundaries related to the coverage ledger.

The pure relation, then the actual app on real PostgreSQL through the Hunt query route. Graph edges
and coverage events inserted directly are fixture rows: what a Scan's graph builder and the
coverage ledger record.
"""
import asyncio
import json
from uuid import UUID, uuid4

from httpx import ASGITransport, AsyncClient

from api.hunt.coverage_gaps import boundary_coverage, route_of
from tests.test_interpretations_postgres import _hunt, _web_target
from tests.test_instruction_proposals_postgres import _prepared
from tests.test_target_asset_startup_postgres import startup_database


def _edge(consumer, producer='route:GET /api/orders', **attributes):
    return {'id': uuid4(), 'src_key': producer, 'dst_key': consumer, 'last_seen_at': None,
            'attributes': json.dumps({'source_principal': 'alice', 'excluded_principal': 'bob', **attributes})}


def _angle(family, route, status, method=None, hunt='h1'):
    return {'family': family, 'status': status, 'hunt_run_id': hunt,
            'locus_json': {'route': route, **({'method': method} if method else {})}}


def test_a_route_key_gives_its_method_and_route_template():
    assert route_of('route:GET /api/orders/7?expand=1') == ('GET', '/api/orders/{id}')
    assert route_of('route:/api/orders') == (None, '/api/orders')
    assert route_of('route:POST https://app.test/api/orders') == ('POST', '/api/orders')
    assert route_of('object:order_id') == (None, None) and route_of('route:') == (None, None)


def test_a_boundary_is_examined_only_by_authorization_coverage_on_its_own_route_and_method():
    rows = boundary_coverage(
        [_edge('route:GET /api/orders/7', object_id_key='order_id'), _edge('route:DELETE /api/orders/7'),
         _edge('route:GET /api/invoices/9'), _edge('route:GET /api/profile'), _edge('object:not-a-route')],
        [_angle('bola', '/api/orders/{id}', 'negative', 'GET'),
         _angle('BOLA', '/api/orders/12', 'testing', 'DELETE', hunt='h2'),
         _angle('xss', '/api/invoices/{id}', 'negative', 'GET'),       # not an authorization family
         _angle('bola', '/api/profile', 'planned'), _angle('idor', '/api/profile/', 'candidate', hunt='h2')])
    by_route = {(row['method'], row['route']): row for row in rows}
    assert by_route[('GET', '/api/orders/{id}')]['coverage'] == 'examined'
    assert by_route[('GET', '/api/orders/{id}')]['object_key'] == 'order_id'
    assert by_route[('DELETE', '/api/orders/{id}')]['coverage'] == 'in_progress'
    assert by_route[('GET', '/api/invoices/{id}')]['coverage'] == 'untested'
    # A method-less angle covers the route; examined wins over in progress; both Hunts are counted.
    profile = by_route[('GET', '/api/profile')]
    assert (profile['coverage'], profile['angle_statuses'], profile['hunts_with_coverage']) == (
        'examined', ['candidate', 'planned'], 2)
    # Untested first, and an edge that is not route-to-route is left out.
    assert [row['coverage'] for row in rows] == ['untested', 'in_progress', 'examined', 'examined']


def test_a_hunt_reads_the_untested_boundaries_of_its_target(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://app.gaps.test')
            other = await _web_target(conn, 'https://other.gaps.test')

            async def edge(owner, consumer):
                await conn.execute(
                    """INSERT INTO application_graph_edges(target_id, src_key, dst_key, edge_type, attributes)
                       VALUES($1,'route:GET /api/orders',$2,'auth_boundary',$3::jsonb)""",
                    UUID(str(owner)), consumer, json.dumps({'source_principal': 'alice', 'excluded_principal': 'bob'}))

            async def angle(hunt, family, route, status):
                await conn.execute(
                    """INSERT INTO hunt_coverage_angle_events(hunt_run_id, fingerprint, family, locus_json, status)
                       VALUES($1,$2,$3,$4::jsonb,$5)""",
                    UUID(hunt.id), f'fp-{uuid4()}', family, json.dumps({'route': route, 'method': 'GET'}), status)

            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                earlier = (await _hunt(operator, target)).hunt
                hunt = (await _hunt(operator, target)).hunt
                await edge(target, 'route:GET /api/orders/7')
                await edge(target, 'route:GET /api/invoices/9')
                await edge(other, 'route:GET /api/elsewhere/1')
                await conn.execute(
                    """INSERT INTO application_graph_edges(target_id, src_key, dst_key, edge_type)
                       VALUES($1,'route:GET /api/orders','object:order_id','produces')""", UUID(str(target)))
                await angle(earlier, 'bola', '/api/orders/{id}', 'negative')

                async def gaps(expect=200, **filters):
                    response = await operator.post(f'/hunts/{hunt.id}/query',
                                                   json={'kind': 'coverage_gaps', 'filter': filters})
                    assert response.status_code == expect, response.text
                    return response.json()

                report = await gaps()
                assert report['supported'] is True and report['is_proof'] is False
                assert report['boundaries'] == 2 and report['by_coverage'] == {
                    'untested': 1, 'in_progress': 0, 'examined': 1}
                [gap] = report['rows']
                assert (gap['method'], gap['route'], gap['coverage']) == ('GET', '/api/invoices/{id}', 'untested')
                assert (gap['source_principal'], gap['excluded_principal']) == ('alice', 'bob')
                assert 'elsewhere' not in json.dumps(await gaps(coverage='all'))
                assert [row['route'] for row in (await gaps(coverage='examined'))['rows']] == ['/api/orders/{id}']
                assert (await gaps(coverage='all', path_contains='invoices'))['count'] == 1
                await gaps(expect=422, coverage='nope')
                await gaps(expect=422, family='bola')

                # A retracted Hunt's coverage no longer counts: its boundary is untested again.
                retracted = await operator.post(f'/targets/{target}/hunts/{earlier.id}/interpretations/retract',
                                                json={'note': 'This Hunt read a prompt injection'})
                assert retracted.status_code == 200, retracted.text
                assert (await gaps())['by_coverage'] == {'untested': 2, 'in_progress': 0, 'examined': 0}
    asyncio.run(run())
