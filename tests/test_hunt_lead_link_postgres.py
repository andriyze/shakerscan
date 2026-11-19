"""One ledger of intent, against real PostgreSQL: the lead board is where "worth testing" lives.

The actual app, startup migrations, Hunt start, the capability route, the coverage route and the
Hunt query route. Actions inserted by ``_ran`` are fixture rows: what the action ledger records.
"""
import asyncio
import json
import sys
from uuid import UUID, uuid4

from httpx import ASGITransport, AsyncClient

from tests.test_interpretations_postgres import _hunt, _ran, _web_target
from tests.test_instruction_proposals_postgres import _prepared
from tests.test_target_asset_startup_postgres import startup_database

DIMENSIONS = {'route': '/api/orders/{id}', 'method': 'GET'}
ANGLE = {'family': 'bola', 'locus': {'method': 'GET', 'route': '/api/orders/{id}'}}


async def _propose(hunt, **fields):
    result = await hunt.ok('hypothesis.propose', {
        'family': 'bola', 'title': 'Orders are readable across tenants', 'dedupe_dimensions': DIMENSIONS, **fields})
    return result['result']['hypothesis']


async def _sent(conn, hunt):
    """Fixture: a completed action of this Hunt that sent one request to the target."""
    action = uuid4()
    await conn.execute(
        """INSERT INTO hunt_actions(id,hunt_run_id,capability_name,status,result_summary,completed_at)
           VALUES($1,$2,'http.request','completed',$3::jsonb,NOW())""", action, UUID(hunt.id),
        json.dumps({'budget_accounting': {'actual': {'http_requests': 1}}}))
    return str(action)


async def _lead(conn, lead_id):
    row = await conn.fetchrow("SELECT status, claim_owner, version, metadata_json FROM hypotheses WHERE id=$1",
                              UUID(lead_id))
    return {**dict(row), 'metadata': json.loads(row['metadata_json'])}


def test_what_is_worth_testing_is_recorded_as_a_lead_not_as_a_note(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://app.leadlink-notes.test')
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                hunt = (await _hunt(operator, target)).hunt
                for kind in ('hypothesis', 'next_step'):
                    refused = await hunt.call('knowledge.record', {'kind': kind, 'title': 'Try the admin API'})
                    # The capability's contract no longer lists the kind.
                    assert refused.status_code == 422 and 'kind' in refused.text, refused.text
                # An operator's write is refused the same way: the board is the one place.
                operator_write = await operator.post(f'/targets/{target}/interpretations', json={
                    'kind': 'next_step', 'title': 'Try the admin API'})
                assert operator_write.status_code == 422 and 'kind_moved_to_lead_board' in operator_write.text
                assert await conn.fetchval("SELECT count(*) FROM target_interpretations") == 0
                # The kinds that describe what the records mean are written as before.
                await hunt.ok('knowledge.record', {'kind': 'note', 'title': 'The admin API exists'})
    asyncio.run(run())


def test_a_coverage_angle_that_names_a_lead_moves_it(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://app.leadlink.test')
            other = await _web_target(conn, 'https://other.leadlink.test')
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                hunt = (await _hunt(operator, target)).hunt
                second = (await _hunt(operator, target)).hunt
                elsewhere = (await _hunt(operator, other)).hunt
                lead = await _propose(hunt)
                foreign = await _propose(elsewhere)

                async def angle(asker, expect=200, **fields):
                    response = await operator.post(f'/hunts/{asker.id}/coverage-angles', json={**ANGLE, **fields})
                    assert response.status_code == expect, response.text
                    return response.json()

                # planned: this Hunt holds the lead.
                planned = await angle(hunt, status='planned', hypothesis_id=lead['id'])
                assert planned['angle']['hypothesis_id'] == lead['id']
                assert planned['lead'] == {'hypothesis_id': lead['id'], 'moved': True, 'steps': ['claimed'],
                                           'status': 'claimed'}
                assert (await _lead(conn, lead['id']))['claim_owner'] == f'hunt:{hunt.id}'

                # Another Hunt's angle on the same lead is recorded, and the lead stays with its holder.
                blocked = await angle(second, status='planned', hypothesis_id=lead['id'])
                assert blocked['lead']['moved'] is False and blocked['lead']['reason'] == 'held_by_another'

                # testing: what the angle says it runs and expects lets the lead enter testing.
                testing = await angle(hunt, status='testing', hypothesis_id=lead['id'],
                                      mechanism='GET the order as tenant-b', hypothesis='200 with tenant-a data')
                assert testing['lead']['steps'] == ['testing'] and testing['lead']['status'] == 'testing'

                # negative: a test that found nothing is counted and the lead is handed back.
                evidence = await _sent(conn, hunt)
                negative = await angle(hunt, status='negative', hypothesis_id=lead['id'],
                                       mechanism='GET the order as tenant-b', evidence_action_ids=[evidence])
                assert negative['lead']['steps'] == ['open'] and negative['lead']['status'] == 'open'
                stored = await _lead(conn, lead['id'])
                mine = stored['metadata']['tests'][f'hunt:{hunt.id}']
                assert stored['claim_owner'] is None and mine['no_signal_count'] == 1
                assert mine['reason_code'] == 'expected_signal_absent' and evidence in mine['action_ids']
                # The next Hunt sees the lead open again, ranked with one prior failure.
                checkpoint = (await operator.get(f'/hunts/{second.id}/checkpoint')).json()
                [seen] = [item for item in checkpoint['hypotheses'] if item['id'] == lead['id']]
                assert seen['claimable'] is True and seen['priority_breakdown']

                # blocked: a Hunt that cannot go on releases the lead it holds.
                await angle(second, status='planned', hypothesis_id=lead['id'])
                released = await angle(second, status='blocked', hypothesis_id=lead['id'], blocker='no second login')
                assert released['lead']['steps'] == ['open'] and (await _lead(conn, lead['id']))['claim_owner'] is None

                # A lead of another target, or no lead at all, is refused and nothing is recorded.
                before = await conn.fetchval("SELECT count(*) FROM hunt_coverage_angle_events")
                for bad in (foreign['id'], str(uuid4())):
                    refused = await angle(hunt, expect=422, status='planned', hypothesis_id=bad)
                    assert refused['detail']['error'] == 'coverage_hypothesis_unknown'
                await angle(hunt, expect=422, status='planned', hypothesis_id='not-a-uuid')
                assert await conn.fetchval("SELECT count(*) FROM hunt_coverage_angle_events") == before
                # An angle without a lead is recorded as before and touches no lead.
                plain = await angle(hunt, status='planned', locus={'method': 'GET', 'route': '/api/other'})
                assert plain['angle']['hypothesis_id'] is None and 'lead' not in plain
    asyncio.run(run())


def test_a_refutation_claim_names_its_lead_and_counts_against_it(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://app.leadlink-refute.test')
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                hunt = (await _hunt(operator, target)).hunt
                reader = (await _hunt(operator, target)).hunt
                lead = await _propose(hunt)
                evidence = await _ran(conn, hunt)
                claim = {'kind': 'negative_result', 'negative_state': 'hypothesis_refuted',
                         'title': 'Orders enforce ownership for tenant-b', 'evidence_refs': [evidence],
                         'conditions': {'method': 'GET', 'route': '/api/orders/{id}', 'principals': ['tenant-b'],
                                        'objects': ['order:1'], 'technique': 'http.request'}}

                # Refuting names the lead it is about.
                nameless = await hunt.call('knowledge.record', claim)
                assert nameless.status_code == 422 and 'refutation_names_no_lead' in nameless.text

                recorded = (await hunt.ok('knowledge.record', {
                    **claim, 'subject': {'type': 'hypothesis', 'id': lead['id']}}))['result']
                assert recorded['lead']['counted'] is True and recorded['lead']['status'] == 'open'
                stored = await _lead(conn, lead['id'])
                mine = stored['metadata']['tests'][f'hunt:{hunt.id}']
                # A claim is not proof: the lead is still open, and it now carries one test against it.
                assert stored['status'] == 'open' and stored['version'] == lead['version'] + 1
                assert mine['no_signal_count'] == 1 and mine['refutation_claims'] == [recorded['interpretation']['id']]
                # Another Hunt reads the lead as it stands, without the first Hunt's test text.
                page = (await operator.post(f'/hunts/{reader.id}/query', json={'kind': 'hypotheses'})).json()['rows']
                assert [row['status'] for row in page if row['id'] == lead['id']] == ['open']
    asyncio.run(run())


def test_a_candidate_angle_marks_the_lead_supported_only_through_testing(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://app.leadlink-support.test')
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                hunt = (await _hunt(operator, target)).hunt
                lead = await _propose(hunt)
                bare = await _propose(hunt, dedupe_dimensions={'route': '/api/invoices/{id}', 'method': 'GET'})
                evidence = await _sent(conn, hunt)
                # The link itself, with the angle the ledger would have validated (a candidate angle
                # needs a candidate this Hunt owns, which is the ledger's own rule and test).
                from api.hunt import lead_link
                run_row = dict(await conn.fetchrow("SELECT * FROM hunt_runs WHERE id=$1", UUID(hunt.id)))
                # The module instance the app configured (it may be loaded under either import layout).
                module = next((m for name, m in list(sys.modules.items())
                               if name.endswith('hunt.lead_link') and name != lead_link.__name__), lead_link)

                supported = await module.apply_angle(conn, run_row, UUID(lead['id']), {
                    'status': 'candidate', 'mechanism': 'GET the order as tenant-b',
                    'hypothesis': '200 with tenant-a data', 'evidence_action_ids': [evidence]})
                assert supported['steps'] == ['claimed', 'testing', 'supported'] and supported['status'] == 'supported'
                stored = await _lead(conn, lead['id'])
                assert stored['status'] == 'supported' and stored['claim_owner'] == f'hunt:{hunt.id}'
                assert stored['metadata']['tests'][f'hunt:{hunt.id}']['falsifier'] == 'GET the order as tenant-b'

                # With nothing stated to run or expect, the lead cannot enter testing, so it is held, not supported.
                held = await module.apply_angle(conn, run_row, UUID(bare['id']), {
                    'status': 'candidate', 'mechanism': '', 'hypothesis': '', 'evidence_action_ids': [evidence]})
                assert held['status'] == 'claimed' and held['reason'] == 'falsifier_required'

                # A closed lead is not reopened by an angle.
                await conn.execute("UPDATE hypotheses SET status='dead', claim_owner=NULL WHERE id=$1", UUID(bare['id']))
                closed = await module.apply_angle(conn, run_row, UUID(bare['id']), {'status': 'planned'})
                assert closed == {'hypothesis_id': bare['id'], 'moved': False, 'status': 'dead', 'reason': 'lead_is_closed'}
    asyncio.run(run())


def test_continuing_an_investigation_offers_the_open_leads_last(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            # The report is cached for a few seconds; this test reads it right after writing.
            for name, module in list(sys.modules.items()):
                if name.endswith('hunt.knowledge_continue'):
                    monkeypatch.setattr(module, 'REPORT_CACHE_SECONDS', 0.0)
            target = await _web_target(conn, 'https://app.leadlink-continue.test')
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                hunt = (await _hunt(operator, target)).hunt
                lead = await _propose(hunt)
                held = await _propose(hunt, dedupe_dimensions={'route': '/api/invoices/{id}', 'method': 'GET'})
                await hunt.ok('hypothesis.claim', {'hypothesis_id': held['id'], 'expected_version': held['version']})

                response = await operator.get(f'/targets/{target}/knowledge/continue')
                assert response.status_code == 200, response.text
                report = response.json()
                assert report['next_experiments']['rules'][-1]['rule'] == 'open_lead'
                knowledge = report['knowledge']
                # The claimable lead is offered; the one a Hunt is working is not.
                assert [item['id'] for item in knowledge['open_leads']] == [lead['id']]
                assert knowledge['counts']['open_leads'] == 1 and 'open_next_steps' not in knowledge
                [offer] = [item for item in report['next_experiments']['items'] if item['rule'] == 'open_lead']
                assert offer['capability'] == 'hypothesis.claim' and offer['required_retest'] is False
                assert offer['input'] == {'hypothesis_id': lead['id'], 'expected_version': lead['version']}
                assert offer['basis']['type'] == 'hypothesis' and 'title' not in json.dumps(offer['basis'])
    asyncio.run(run())
