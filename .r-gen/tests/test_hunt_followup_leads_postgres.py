"""Follow-up leads against real PostgreSQL: a verified finding opens leads every Hunt on the target sees.

The actual app, startup migrations, Hunt start, the capability route and the Hunt query route.
Findings inserted directly are fixture rows: what a deterministic proof leaves behind.
"""
import asyncio
import json
from uuid import UUID, uuid4

from httpx import ASGITransport, AsyncClient

from tests.test_interpretations_postgres import _hunt, _web_target
from tests.test_instruction_proposals_postgres import _prepared
from tests.test_target_asset_startup_postgres import startup_database


async def _finding(conn, target, *, cwe, url, verified=True, evidence=None, status='active'):
    finding = uuid4()
    await conn.execute(
        """INSERT INTO findings(id,target_id,fingerprint,title,severity,tool,cwe,url,evidence,status,
                                last_verified_at,last_verification_verdict)
           VALUES($1,$2,$3,'fixture','high','fixture',$4,$5,$6::jsonb,$7,
                  CASE WHEN $8 THEN NOW() END, CASE WHEN $8 THEN 'exploited' END)""",
        finding, UUID(str(target)), f'fp-{finding}', cwe, url, json.dumps(evidence or {}), status, verified)
    return str(finding)


async def _leads(operator, hunt):
    response = await operator.post(f'/hunts/{hunt.id}/query', json={'kind': 'hypotheses', 'limit': 200})
    assert response.status_code == 200, response.text
    return response.json()['rows']


def test_a_verified_finding_opens_leads_once_for_every_hunt_on_the_target(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://app.followup.test')
            other = await _web_target(conn, 'https://other.followup.test')
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                hunt = (await _hunt(operator, target)).hunt
                stranger = (await _hunt(operator, other)).hunt
                assert await _leads(operator, hunt) == []

                ssrf = await _finding(conn, target, cwe='CWE-918', evidence={'method': 'GET'},
                                      url='https://app.followup.test/api/fetch?url=x&token=SECRETVALUE')
                # Not verified, not active, or no class: nothing follows.
                await _finding(conn, target, cwe='CWE-89', url='https://app.followup.test/a', verified=False)
                await _finding(conn, target, cwe='CWE-89', url='https://app.followup.test/b', status='false_positive')
                await _finding(conn, target, cwe='CWE-16', url='https://app.followup.test/c')

                rows = await _leads(operator, hunt)
                [lead] = rows
                assert lead['source'] == 'proof_followup' and lead['family'] == 'ssrf'
                assert lead['derived_from'] == [ssrf] and lead['status'] == 'open'
                assert lead['dedupe_dimensions'] == {
                    'proof_surface': 'ssrf_internal_services', 'route': '/api/fetch', 'method': 'get'}
                assert 'SECRETVALUE' not in json.dumps(rows)

                # Reading again writes nothing: same lead, same version, one endorsement.
                [again] = await _leads(operator, hunt)
                assert (again['id'], again['version']) == (lead['id'], lead['version'])
                assert await conn.fetchval(
                    "SELECT jsonb_array_length(endorsements) FROM hypotheses WHERE id=$1", UUID(lead['id'])) == 1
                # Another target's Hunt sees none of it.
                assert await _leads(operator, stranger) == []

                # A Hunt that starts later finds the lead already on its frontier, and can work it.
                later = (await _hunt(operator, target)).hunt
                checkpoint = (await operator.get(f'/hunts/{later.id}/checkpoint')).json()
                assert lead['id'] in [item['id'] for item in checkpoint['hypotheses']]
                claimed = await later.ok('hypothesis.claim', {
                    'hypothesis_id': lead['id'], 'expected_version': lead['version']})
                assert claimed['result']['hypothesis']['claim']['held_by_this_hunt'] is True

                # An operator closing the lead keeps it closed: the proof does not reopen it.
                await conn.execute("UPDATE hypotheses SET status='dead', claim_owner=NULL WHERE id=$1", UUID(lead['id']))
                assert [row['id'] for row in await _leads(operator, hunt) if row['status'] == 'open'] == []
                assert await conn.fetchval(
                    "SELECT count(*) FROM hypotheses WHERE target_id=$1", UUID(str(target))) == 1
    asyncio.run(run())


def test_a_follow_up_endorses_a_lead_a_hunt_already_wrote_and_survives_its_retraction(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://app.followup-merge.test')
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                hunt = (await _hunt(operator, target)).hunt
                reader = (await _hunt(operator, target)).hunt
                mine = (await hunt.ok('hypothesis.propose', {
                    'family': 'ssrf', 'title': 'My own words', 'confidence': 0.2,
                    'dedupe_dimensions': {'route': '/api/fetch', 'method': 'GET',
                                          'proof_surface': 'ssrf_internal_services'}}))['result']['hypothesis']
                await _finding(conn, target, cwe='CWE-918', evidence={'method': 'GET'},
                               url='https://app.followup-merge.test/api/fetch')

                [lead] = await _leads(operator, reader)
                # The same lead, endorsed: its writer's text, source and confidence stay.
                assert lead['id'] == mine['id'] and lead['title'] == 'My own words'
                assert lead['source'] == 'ai_planner' and lead['confidence'] == 0.2
                assert lead['derived_from'] == [] and await conn.fetchval(
                    "SELECT jsonb_array_length(endorsements) FROM hypotheses WHERE id=$1", UUID(lead['id'])) == 2

                # The writer is retracted: its lead is withheld and closed, and the proof raises the
                # lead again in the server's words.
                retracted = await operator.post(f'/targets/{target}/hunts/{hunt.id}/interpretations/retract',
                                                json={'note': 'This Hunt read a prompt injection'})
                assert retracted.status_code == 200, retracted.text
                rows = [row for row in await _leads(operator, reader) if row['status'] == 'open']
                [fresh] = rows
                assert fresh['id'] != mine['id'] and fresh['source'] == 'proof_followup'
                assert fresh['title'] == 'Internal services reachable through the verified SSRF'
    asyncio.run(run())


def test_starting_hunts_seeds_inventory_leads_once_until_the_inventory_changes(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://app.seed.test')
            await conn.execute(
                """INSERT INTO target_endpoints(target_id, method, path, fingerprint, auth_state)
                   VALUES($1,'GET','/api/orders/123','fp-orders','authenticated')""", UUID(str(target)))

            async def board():
                return await conn.fetch(
                    """SELECT id, version, jsonb_array_length(endorsements) AS endorsements
                       FROM hypotheses WHERE target_id=$1 ORDER BY id""", UUID(str(target)))

            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                assert await board() == []
                first = (await _hunt(operator, target)).hunt
                seeded = await board()
                assert seeded and all(row['endorsements'] == 1 for row in seeded)
                rows = await _leads(operator, first)
                assert {row['source'] for row in rows} == {'app_graph'} and 'bola' in {row['family'] for row in rows}

                # A second start on an unchanged inventory leaves every lead as it was.
                await _hunt(operator, target)
                assert await board() == seeded

                # Re-observing a known route is not a reason to write to the board again.
                await conn.execute(
                    """UPDATE target_endpoints SET updated_at = NOW() + interval '1 minute',
                                                   last_seen_at = NOW() + interval '1 minute' WHERE target_id=$1""",
                    UUID(str(target)))
                await _hunt(operator, target)
                assert await board() == seeded

                # A new route is: the next start refreshes the board and adds its lead.
                await conn.execute(
                    """INSERT INTO target_endpoints(target_id, method, path, fingerprint, auth_state, first_seen_at)
                       VALUES($1,'GET','/api/invoices/9','fp-invoices','authenticated', NOW() + interval '1 minute')""",
                    UUID(str(target)))
                await _hunt(operator, target)
                after = await board()
                assert len(after) > len(seeded)
                assert sorted(row['endorsements'] for row in after if row['id'] in {r['id'] for r in seeded}) == [2] * len(seeded)
    asyncio.run(run())
