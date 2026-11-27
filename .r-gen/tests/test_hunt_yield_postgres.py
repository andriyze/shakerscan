"""Hunt yield against real PostgreSQL: what a target's Hunts spent and what came of it.

The actual app, startup migrations, Hunt start and the operator route. Actions, attributions and
leads inserted directly are fixture rows: what the action ledger, a deterministic verification and
the lead board record.
"""
import asyncio
import json
from uuid import UUID, uuid4

from httpx import ASGITransport, AsyncClient

from tests.test_interpretations_postgres import _hunt, _web_target
from tests.test_instruction_proposals_postgres import _prepared
from tests.test_target_asset_startup_postgres import startup_database


async def _action(conn, hunt, capability, status='completed', requests=0, seconds=0, age=''):
    action = uuid4()
    await conn.execute(
        f"""INSERT INTO hunt_actions(id,hunt_run_id,capability_name,status,result_summary,completed_at)
            VALUES($1,$2,$3,$4,$5::jsonb,NOW() {age})""",
        action, UUID(hunt.id), capability, status,
        json.dumps({'budget_consumed': {'http_requests': requests, 'tool_wall_seconds': seconds}}))
    return action


async def _verified(conn, target, hunt, action):
    finding = uuid4()
    await conn.execute(
        """INSERT INTO findings(id,target_id,fingerprint,title,severity,tool,status,last_verified_at,
                                last_verification_verdict,hunt_run_id)
           VALUES($1,$2,$3,'fixture','high','fixture','active',NOW(),'exploited',$4)""",
        finding, UUID(str(target)), f'fp-{finding}', UUID(hunt.id))
    await conn.execute(
        "INSERT INTO finding_hunt_verifications(finding_id,hunt_run_id,action_id,role) VALUES($1,$2,$3,'owner')",
        finding, UUID(hunt.id), action)


async def _lead(conn, target, source, family, status, derived=False):
    await conn.execute(
        """INSERT INTO hypotheses(target_id,source,family,dedupe_key,status,metadata_json)
           VALUES($1,$2,$3,$4,$5,$6::jsonb)""",
        UUID(str(target)), source, family, f'k-{uuid4()}', status,
        json.dumps({'derived_from': [str(uuid4())]} if derived else {}))


def test_an_operator_reads_spend_and_outcomes_per_capability_and_lead_source(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://app.yield.test')
            other = await _web_target(conn, 'https://other.yield.test')
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                hunt = (await _hunt(operator, target)).hunt
                second = (await _hunt(operator, target)).hunt
                elsewhere = (await _hunt(operator, other)).hunt
                await _action(conn, hunt, 'http.request', requests=40)
                await _action(conn, second, 'http.request', status='failed', requests=10)
                proof = await _action(conn, hunt, 'candidate.verify', requests=20, seconds=30)
                await _verified(conn, target, hunt, proof)
                await _action(conn, hunt, 'candidate.verify', requests=30, seconds=30)
                # Outside the report: unsettled, older than the window, another target.
                await _action(conn, hunt, 'http.request', status='running', requests=999)
                await _action(conn, hunt, 'http.request', requests=999, age="- interval '30 weeks'")
                await _action(conn, elsewhere, 'http.request', requests=999)
                await conn.execute("DELETE FROM hypotheses WHERE target_id=$1", UUID(str(target)))
                for state in ('supported', 'promoted', 'refuted', 'open'):
                    await _lead(conn, target, 'proof_followup', 'ssrf', state, derived=True)
                await _lead(conn, target, 'ai_planner', 'bola', 'refuted')
                await _lead(conn, target, 'ai_planner', 'bola', 'testing')
                await _lead(conn, other, 'ai_planner', 'bola', 'supported')

                response = await operator.get(f'/targets/{target}/knowledge/yield')
                assert response.status_code == 200, response.text
                report = response.json()
                assert report['schema_version'] == 'hunt-yield/v1' and report['actions_truncated'] is False
                verify, request = report['capabilities']
                assert verify == {
                    'capability': 'candidate.verify', 'actions': 2, 'outcomes': {'completed': 2},
                    'http_requests': 50, 'tool_wall_seconds': 60, 'hunts': 1, 'verified_findings': 1,
                    'verified_per_1000_requests': 20.0, 'verified_per_tool_hour': 60.0}
                assert (request['capability'], request['actions'], request['http_requests'], request['hunts']) == (
                    'http.request', 2, 50, 2)
                assert request['outcomes'] == {'completed': 1, 'failed': 1}
                assert request['verified_findings'] == 0 and request['verified_per_tool_hour'] is None

                planner, followup = report['leads']
                assert planner == {'source': 'ai_planner', 'family': 'bola', 'leads': 2,
                                   'by_state': {'refuted': 1, 'testing': 1}, 'settled': 1, 'held': 0,
                                   'held_share_of_settled': 0.0}
                assert (followup['source'], followup['settled'], followup['held'],
                        followup['held_share_of_settled']) == ('proof_followup', 3, 2, 0.6667)
                assert report['derived']['leads'] == 4 and report['derived']['held'] == 2

                assert (await operator.get(f'/targets/{target}/knowledge/yield', params={'weeks': 53})).status_code == 422
                wide = (await operator.get(f'/targets/{target}/knowledge/yield', params={'weeks': 52})).json()
                assert next(row for row in wide['capabilities'] if row['capability'] == 'http.request')['actions'] == 3
    asyncio.run(run())
