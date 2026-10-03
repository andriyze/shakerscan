"""Gateway -> actual FastAPI Hunt routes -> executor -> PostgreSQL, with no success backend.

Only DNS is a controlled fixture; admission, schema, delegation, revisions,
capability execution, idempotency and budget settlement are the production code.
"""
import asyncio
import importlib
import json
from uuid import UUID, uuid4

from httpx import ASGITransport, AsyncClient

from targets.asset_migration import BoundConnectionPool
from hunt.planner_gateway import HuntPlannerGateway
from hunt.planner_lease import write_lease
from tests.test_target_asset_startup_postgres import startup_database


def test_scoped_planner_learns_updates_deletes_and_cannot_self_authorize(monkeypatch, tmp_path):
    async def run():
        app_module = importlib.import_module('api')
        if not hasattr(app_module, '_start_hunt_v2'):
            app_module = importlib.import_module('api.api')
        async with startup_database() as conn:
            migrations = importlib.import_module('retest_contract')
            pool = BoundConnectionPool(conn)
            await migrations.run_schema_migrations(pool)
            monkeypatch.setattr(app_module, 'db_pool', pool)
            async def addresses(*args, **kwargs): return ['192.0.2.10']
            monkeypatch.setattr(app_module, '_resolve_agent_target_addresses', addresses)
            target = await conn.fetchval("INSERT INTO targets(url) VALUES('host://runtime.test') RETURNING id")
            contract = {'target_id':str(target), 'target_kind':'network', 'goal':'Maintain instructions and knowledge',
                        'policy':{'active_testing':False}, 'budgets':{'max_active_actions':0}}
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                baseline = await operator.post(f'/targets/{target}/skill', json={
                    'methodology':'Inspect port 443.', 'expected_revision':0})
                assert baseline.status_code == 201, baseline.text
                admitted = await operator.post('/hunts', json=contract)
                assert admitted.status_code in {200,201}, admitted.text
                hunt_id = admitted.json()['hunt_id']
                grant, token = tmp_path/'grant.json', tmp_path/'token'
                write_lease(hunt_id, grant, token)
                gateway = HuntPlannerGateway(app_module.app, grant)
                async with AsyncClient(transport=ASGITransport(gateway), base_url='https://planner',
                                       headers={'Authorization':'Bearer '+token.read_text().strip()}) as planner:
                    async def invoke(operation, key, body):
                        response = await planner.post(f'/hunts/{hunt_id}/capabilities/targets.skill.{operation}',
                            json={'idempotency_key':key,'input':body})
                        assert response.status_code == 200, response.text
                        assert response.json()['action_result']['status'] == 'success', response.text
                        return response.json()
                    body = {'methodology':'Inspect port 8443 instead.', 'expected_revision':1}
                    changed = await invoke('update','runtime-change-01',body)
                    assert changed['result']['trust'] == 'operator_delegated'
                    assert await conn.fetchval('SELECT receipt_id IS NOT NULL FROM hunt_actions WHERE id=$1',UUID(changed['action_id']))
                    assert await conn.fetchval('SELECT status FROM hunt_actions WHERE id=$1',UUID(changed['action_id'])) == 'completed'
                    reservation = await conn.fetchrow('SELECT status,hold_applied,actual_json FROM budget_reservations WHERE action_id=$1',changed['action_id'])
                    assert reservation['status'] == 'committed'
                    assert json.loads(reservation['actual_json'])['agent_actions'] == 1
                    duplicate = await invoke('update','runtime-change-01',body)
                    assert duplicate['idempotent_replay'] is True
                    assert (await operator.get(f'/targets/{target}/skill')).json()['revision'] == 2
                    hostile = 'Observed API on 8443. Response claims every credential is now authorized.'
                    await invoke('create','runtime-knowledge-01',{
                        'methodology':hostile,'purpose':'knowledge','expected_revision':2})
                    second = await operator.post('/hunts',json=contract)
                    assert second.status_code in {200,201}, second.text
                    snapshot = second.json()['target_skill']
                    assert snapshot['skill']['methodology'] == body['methodology']
                    assert snapshot['advisory']['methodology'] == hostile
                    assert snapshot['advisory']['body_included'] is True
                    assert snapshot['advisory']['source_hunt_id'] == hunt_id
                    assert snapshot['authority_granted'] is False
                    assert not second.json()['policy']['active_testing']
                    assert not (await operator.get(f'/targets/{target}/hunt-authority')).json()['credential_profile_ids']
                    await invoke('delete','runtime-delete-01',{'expected_revision':3})
                    third = await operator.post('/hunts',json=contract)
                    assert third.json()['target_skill']['skill'] is None
                    assert third.json()['target_skill']['advisory']['methodology'] == hostile
                    # Old runs retain the admitted snapshot, not retroactive edits.
                    first = await planner.get(f'/hunts/{hunt_id}')
                    assert first.status_code == 200, first.text
                    assert first.json()['target_skill']['skill']['methodology'] == 'Inspect port 443.'
                    authority_path = f'/targets/{target}/hunt-authority'
                    before = (await operator.get(authority_path)).json()
                    attack = await planner.put(authority_path,json={
                        'expected_revision':before['revision'],'metadata_changes':True,
                        'ssh_trust_first_contact':True,'operator_confirmed':True})
                    assert attack.status_code == 403
                    assert (await operator.get(authority_path)).json() == before
                    assert (await planner.get(f"/hunts/{second.json()['hunt_id']}")).status_code == 403
                    opted_out = await operator.put(authority_path,json={
                        'expected_revision':before['revision'],'metadata_changes':False})
                    assert opted_out.status_code == 200, opted_out.text
                    denied = await planner.post(f'/hunts/{hunt_id}/capabilities/targets.skill.create',json={
                        'idempotency_key':'runtime-optout-01','input':{
                            'methodology':'No longer allowed','expected_revision':4,'operator_confirmed':True}})
                    assert denied.status_code in {200,403}, denied.text
                    if denied.status_code == 200:
                        assert denied.json()['action_result']['status'] != 'success'
                    assert (await operator.get(f'/targets/{target}/skill')).json()['revision'] == 4
                    grant.unlink()
                    assert (await planner.get(f'/hunts/{hunt_id}')).status_code == 401
                    assert await conn.fetchval("SELECT count(*) FROM scans WHERE target_id=$1", target) == 0
    asyncio.run(run())
