"""Target skill API, Hunt execution and admission snapshots against real PostgreSQL."""
import asyncio
import importlib
import json
import os
import uuid

import pytest
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient

from targets import asset_router, skill
from targets.asset_migration import BoundConnectionPool, migrate_target_assets
from tests.test_target_asset_migration_postgres import database
from tests.test_target_asset_startup_postgres import startup_database


def test_target_skill_api_crud_revision_conflicts_and_target_isolation(monkeypatch):
    async def run():
        async with database() as conn:
            first = await conn.fetchval("INSERT INTO targets(url,metadata_json) VALUES('http://first.test','{\"cohort\":\"lab\"}') RETURNING id")
            second = await conn.fetchval("INSERT INTO targets(url) VALUES('http://second.test') RETURNING id")
            monkeypatch.setattr(asset_router, '_pool_provider', lambda: BoundConnectionPool(conn))
            app = FastAPI(); app.include_router(skill.router)
            path = f'/targets/{first}/skill'
            async with AsyncClient(transport=ASGITransport(app), base_url='http://test') as client:
                empty = await client.get(path)
                assert empty.status_code == 200 and empty.json()['skill'] is None
                body = {'methodology':'## Login\nUse the TV profile.\n## Avoid\nDo not reboot.', 'expected_revision':0}
                created = await client.post(path, json=body)
                assert created.status_code == 201, created.text
                assert created.json()['revision'] == 1
                assert (await client.post(path, json={**body,'expected_revision':1})).status_code == 409
                assert (await client.get(f'/targets/{second}/skill')).json()['skill'] is None
                assert (await client.put(path, json=body)).status_code == 409
                updated = await client.put(path, json={**body,'methodology':'## Priorities\nInspect port 8443.', 'expected_revision':1})
                assert updated.status_code == 200 and updated.json()['revision'] == 2
                assert (await client.delete(path, params={'expected_revision':1})).status_code == 409
                deleted = await client.delete(path, params={'expected_revision':2})
                assert deleted.status_code == 200 and deleted.json()['skill'] is None
                assert deleted.json()['revision'] == 3
                # Delete/recreate cannot bring revision 1 back and defeat concurrency checks.
                assert (await client.post(path, json=body)).status_code == 409
                recreated = await client.post(path, json={**body,'expected_revision':3})
                assert recreated.status_code == 201 and recreated.json()['revision'] == 4
                assert (await client.get(path)).json() == recreated.json()
                for invalid in ['', '   ', '\x00', 'x'*(skill.MAX_TARGET_SKILL_CHARACTERS+1)]:
                    assert (await client.put(path, json={**body,'methodology':invalid,'expected_revision':4})).status_code == 422
                assert (await client.get('/targets/not-a-uuid/skill')).status_code == 400
                assert (await client.post(f'/targets/{uuid.uuid4()}/skill', json=body)).status_code == 404
            metadata = json.loads(await conn.fetchval('SELECT metadata_json FROM targets WHERE id=$1',first))
            assert metadata['cohort'] == 'lab'  # Skill edits preserve unrelated target metadata.
    asyncio.run(run())


def test_two_concurrent_editors_cannot_lose_an_update(monkeypatch):
    async def run():
        import asyncpg
        async with database() as conn:
            identifier = await conn.fetchval("INSERT INTO targets(url) VALUES('http://race.test') RETURNING id")
            schema = await conn.fetchval('SELECT current_schema()')
            pool = await asyncpg.create_pool(os.environ['TARGET_ASSET_TEST_DATABASE_URL'],
                min_size=2, max_size=2, server_settings={'search_path':f'{schema},public'})
            try:
                monkeypatch.setattr(asset_router, '_pool_provider', lambda: pool)
                app = FastAPI(); app.include_router(skill.router)
                async with AsyncClient(transport=ASGITransport(app), base_url='http://test') as client:
                    path = f'/targets/{identifier}/skill'
                    assert (await client.post(path, json={'methodology':'Initial', 'expected_revision':0})).status_code == 201
                    responses = await asyncio.gather(*[client.put(path,json={'methodology':text,'expected_revision':1}) for text in ['Editor one','Editor two']])
                    assert sorted(response.status_code for response in responses) == [200,409]
                    winner = next(response.json() for response in responses if response.status_code == 200)
                    assert (await client.get(path)).json() == winner
            finally:
                await pool.close()
    asyncio.run(run())


@pytest.mark.parametrize('kind', ['web','api','network','device'])
def test_hunt_starts_with_snapshot_and_crud_changes_only_future_hunts(monkeypatch, kind):
    async def run():
        from hunt import asset_actions
        from hunt.start_contract import normalize_hunt_start_payload
        from runtime.capability_registry import CAPABILITY_REGISTRY
        from capabilities.inline import ControlPlaneExecutionAdapter
        from hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
        from runtime.models import TargetBinding
        from hunt.run_service import public_hunt_run
        import api as app_module
        if not hasattr(app_module, '_start_hunt_v2'):
            app_module = importlib.import_module('api.api')
        async with (startup_database() if kind == 'network' else database()) as conn:
            device = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('TV','skill.test') RETURNING id")
            origin = await conn.fetchval("INSERT INTO targets(url) VALUES('https://skill.test:8443') RETURNING id")
            if kind == 'network':
                import retest_contract
                await retest_contract.run_schema_migrations(BoundConnectionPool(conn))
            else:
                async with conn.transaction():
                    await migrate_target_assets(conn)
            identifier = origin if kind in {'web','api'} else device
            pool = BoundConnectionPool(conn)
            monkeypatch.setattr(app_module, 'db_pool', pool)
            async def no_credentials(*args, **kwargs): return []
            async def origins(*args, **kwargs): return ['https://skill.test:8443']
            async def collections(*args, **kwargs): return [],[],[]
            async def addresses(*args, **kwargs): return ['192.0.2.10']
            async def knowledge(*args, **kwargs): return {}
            async def approval(*args, **kwargs): return None
            monkeypatch.setattr(app_module, '_validate_hunt_credential_references', no_credentials)
            monkeypatch.setattr(app_module, '_target_web_origins', origins)
            monkeypatch.setattr(app_module, '_generic_collection_refs', collections)
            monkeypatch.setattr(app_module, '_resolve_agent_target_addresses', addresses)
            monkeypatch.setattr(app_module.hunt_prior_knowledge, 'safe_prior_knowledge', knowledge)
            monkeypatch.setattr(app_module, '_require_approval_receipt_if_policy_enabled', approval)
            contract = normalize_hunt_start_payload({'target_id':str(identifier),'target_kind':kind,
                'goal':'Follow the target instructions', 'policy':{'active_testing':False},
                'budgets':{'max_active_actions':0}})
            before = await app_module._start_hunt_v2(contract)
            assert before['target_skill']['skill'] is None
            run_row = dict(await conn.fetchrow('SELECT * FROM hunt_runs WHERE id=$1',uuid.UUID(before['hunt_id'])))
            original_context = run_row['context_pack']
            from targets.hunt_authority import authority_row, save_authority
            owner = await authority_row(conn,identifier)
            await save_authority(conn,owner,{'revision':1,'metadata_changes':True},recorded_by='operator:test')
            values = {'operator_confirmed':True,'methodology':'Login with the TV profile; never reboot.', 'expected_revision':0}
            spec = CAPABILITY_REGISTRY.require('targets.skill.create')
            adapter = ControlPlaneExecutionAdapter(specification=spec,
                operation=lambda:asset_actions.execute_asset_action(pool,run_row,spec.name,values),
                requested_budget={'agent_actions':1,'tool_wall_seconds':5}, redacted_execution={},
                blocked_exceptions=(HTTPException,),conservative_full_budget=True)
            execution = await CapabilityExecutor().execute(CapabilityExecutionContext(specification=spec,
                target=TargetBinding(target_id=str(identifier),target_kind=kind,canonical_host='skill.test'),
                requested_budget={'agent_actions':1,'tool_wall_seconds':5}),adapter,
                heartbeat=lambda:asyncio.sleep(0), cancelled=lambda:False)
            assert execution.status == 'success', execution
            assert 'active_actions' not in execution.actual_budget
            read = await asset_actions.execute_asset_action(pool,run_row,'targets.skill.read',{})
            assert read['revision'] == 1 and read['skill']['methodology'] == values['methodology']
            started = await app_module._start_hunt_v2(contract)
            assert started['target_skill']['skill']['methodology'] == values['methodology']
            assert started['target_skill']['authority_granted'] is False
            assert not started['policy']['active_testing']
            admitted = dict(await conn.fetchrow('SELECT * FROM hunt_runs WHERE id=$1',uuid.UUID(started['hunt_id'])))
            if kind == 'network':
                from runtime.reservation_store import PostgresBudgetReservationStore
                from hunt.interaction_router import router as interaction_router
                await PostgresBudgetReservationStore().ensure_schema(conn)
                api = FastAPI(); api.include_router(interaction_router); api.include_router(app_module.devices_router)
                async with AsyncClient(transport=ASGITransport(api),base_url='http://test') as client:
                    path = f"/hunts/{started['hunt_id']}/capabilities/targets.skill.read"
                    response = await client.post(path,json={'idempotency_key':'target-skill-read-001','input':{}})
                    assert response.status_code == 200, response.text
                    assert response.json()['action_result']['status'] == 'success', response.text
                    assert response.json()['result']['skill']['methodology'] == values['methodology']
                    repeated = await client.post(path,json={'idempotency_key':'target-skill-read-001','input':{}})
                    assert repeated.status_code == 200 and repeated.json()['idempotent_replay'] is True
                    for metadata in [{'notes':'Safe metadata edit'}, None]:
                        response = await client.patch(f'/devices/{device}',json={'metadata_json':metadata})
                        assert response.status_code == 200, response.text
                        assert (await skill.read_target_skill(conn,identifier))['skill']['methodology'] == values['methodology']
                    blocked = await client.patch(f'/devices/{device}',json={'metadata_json':{'target_skill':None}})
                    assert blocked.status_code == 422
            await save_authority(conn,owner,{'revision':2,'metadata_changes':False},recorded_by='operator:test')
            with pytest.raises(HTTPException, match='metadata changes'):
                await asset_actions.execute_asset_action(pool,admitted,'targets.skill.delete',{'expected_revision':1})
            await save_authority(conn,owner,{'revision':3,'metadata_changes':True},recorded_by='operator:test')
            await asset_actions.execute_asset_action(pool,admitted,'targets.skill.update',
                {**values,'methodology':'New priorities','expected_revision':1})
            await asset_actions.execute_asset_action(pool,admitted,'targets.skill.delete',
                {'expected_revision':2,'operator_confirmed':True})
            retained = dict(await conn.fetchrow('SELECT * FROM hunt_runs WHERE id=$1',uuid.UUID(started['hunt_id'])))
            assert retained['context_pack'] == admitted['context_pack']
            assert public_hunt_run(retained)['target_skill']['skill']['methodology'] == values['methodology']
            assert 'methodology' not in public_hunt_run(retained,include_context=False)['target_skill']['skill']
            assert (await app_module._start_hunt_v2(contract))['target_skill']['skill'] is None
            assert await conn.fetchval('SELECT context_pack FROM hunt_runs WHERE id=$1',uuid.UUID(before['hunt_id'])) == original_context
            # A selected target never confers edit access to a different UUID, even on the same host.
            other = origin if identifier == device else device
            assert (await skill.read_target_skill(conn,other))['skill'] is None
    asyncio.run(run())
