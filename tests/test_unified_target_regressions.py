"""Canonical host execution and public credential mutations after real conversion."""
import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from capabilities.network import CapabilityInputError, PortsDiscoverAdapter
from hunt.target_binding import web_hunt_target
from runtime.models import ScanPolicy
from targets.asset_migration import BoundConnectionPool, migrate_target_assets
from targets.asset_inputs_migration import migrate_asset_inputs
from targets.asset_store import public_asset
from tests.test_target_asset_migration_postgres import database
from tests.test_target_asset_inputs_postgres import encryption, prepare
from tests.test_target_asset_startup_postgres import startup_database


@pytest.mark.parametrize('locator,address', [
    ('192.0.2.10','192.0.2.10'), ('tv.test','192.0.2.10'),
    ('[2001:db8::10]','2001:db8::10'),
])
def test_host_hunt_prepares_builtin_naabu_on_frozen_addresses(locator, address):
    target, _ = web_hunt_target(
        {'target_kind':'network','target_id':'tv-target'},
        {'target':{'url':f'host://{locator}','environment':'lab'},
         'authorized_target_addresses':[address]}, {},
    )
    assert not target.allowed_origins  # A host does not establish an HTTP service.
    adapter = PortsDiscoverAdapter()
    args = {'ports':[8008,8009,8060]}
    prepared = adapter.prepare(target=target,args=args,
        policy=ScanPolicy(active_testing=True,network_discovery=True,approval_receipt_id='fixture-approval'))
    assert prepared.adapter_name == 'naabu'
    assert prepared.commands[0].argv[:4] == ('-host',address,'-p','8008,8009,8060')
    assert prepared.estimated_budget['tcp_ports_attempted'] == 3
    with pytest.raises(CapabilityInputError):
        adapter.prepare(target=target,args=args,policy=ScanPolicy())


def test_device_environment_survives_conversion_and_updates():
    async def run():
        async with database() as conn:
            device = await conn.fetchval("INSERT INTO device_targets(name,primary_locator,environment) VALUES('TV','192.0.2.10','lab') RETURNING id")
            async with conn.transaction():
                await migrate_target_assets(conn)
            row = await conn.fetchrow('SELECT * FROM targets WHERE id=$1',device)
            assert public_asset(row)['environment'] == 'lab'
            await conn.execute("UPDATE device_targets SET environment='staging' WHERE id=$1",device)
            row = await conn.fetchrow('SELECT * FROM targets WHERE id=$1',device)
            assert public_asset(row)['environment'] == 'staging'
            await conn.execute("UPDATE targets SET metadata_json=metadata_json || '{\"environment\":\"lab\"}'::jsonb WHERE id=$1",device)
            assert await conn.fetchval('SELECT environment FROM device_targets WHERE id=$1',device) == 'lab'
    asyncio.run(run())


def test_already_converted_database_receives_versioned_compatibility_repair():
    async def run():
        import retest_contract
        from targets.asset_compatibility import MIGRATION
        async with startup_database() as conn:
            owner = await conn.fetchval("INSERT INTO device_targets(name,primary_locator,environment) VALUES('Existing TV','repair.test','lab') RETURNING id")
            await retest_contract.run_schema_migrations(BoundConnectionPool(conn))
            total = await conn.fetchval('SELECT count(*) FROM targets')
            # Early unified builds retained environment only on the device profile.
            await conn.execute("UPDATE targets SET metadata_json=metadata_json-'environment'-'cohort' WHERE id=$1",owner)
            await conn.execute('DELETE FROM app_schema_migrations WHERE name=$1',MIGRATION)
            await retest_contract.run_schema_migrations(BoundConnectionPool(conn))
            assert public_asset(await conn.fetchrow('SELECT * FROM targets WHERE id=$1',owner))['environment'] == 'lab'
            assert await conn.fetchval('SELECT count(*) FROM targets') == total
            assert await conn.fetchval('SELECT count(*) FROM app_schema_migrations WHERE name=$1',MIGRATION) == 1
            await retest_contract.run_schema_migrations(BoundConnectionPool(conn))
            assert await conn.fetchval('SELECT count(*) FROM targets') == total
    asyncio.run(run())


def test_generic_credential_routes_mutate_the_shared_device_profile(monkeypatch):
    secrets = encryption(monkeypatch)
    async def run():
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient
        import credential_api
        from devices.shared_credentials import create_device_profile
        async with database() as conn:
            await prepare(conn)
            device = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('TV','credentials.test') RETURNING id")
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
                row = await create_device_profile(conn,device,SimpleNamespace(
                    auth_kind='web_cookie',secret='review-cookie=value',secondary_secret=None,
                    username=None,login_path=None,name='TV cookie',expires_at=None,port=8008,
                ))
            app = FastAPI()
            app.state.db_pool = BoundConnectionPool(conn)
            app.include_router(credential_api.router)
            endpoint = f"/credential-profiles/{row['id']}"
            async with AsyncClient(transport=ASGITransport(app),base_url='http://test') as client:
                response = await client.patch(endpoint,json={'name':'Renamed','expected_record_version':1})
                assert response.status_code == 200, response.text
                profile = response.json()['profile']
                assert await conn.fetchval('SELECT name FROM device_credential_profiles WHERE id=$1',row['id']) == 'Renamed'
                response = await client.post(endpoint+'/rotate',json={
                    'secret':'new-review-cookie=value','expected_record_version':profile['record_version'],
                })
                assert response.status_code == 200, response.text
                assert 'new-review-cookie' not in response.text
                encrypted = await conn.fetchval('SELECT secret_value FROM device_credential_profiles WHERE id=$1',row['id'])
                assert json.loads(secrets.decrypt_secret(encrypted))['secret'] == 'new-review-cookie=value'
                response = await client.delete(endpoint)
                assert response.status_code == 200, response.text
                assert await conn.fetchval('SELECT is_active FROM device_credential_profiles WHERE id=$1',row['id']) is False
    asyncio.run(run())


@pytest.mark.parametrize('ports', [[0],[65536],[True],['8008'],[1.5],'8008'])
def test_host_port_hints_reject_invalid_values(ports):
    from pydantic import ValidationError
    from targets.asset_router import HostTargetCreate
    with pytest.raises(ValidationError):
        HostTargetCreate(locator='tv.test',port_hints=ports)


def test_registered_hunt_asset_actions_keep_scope_and_share_explicitly(monkeypatch):
    encryption(monkeypatch)
    async def run():
        from fastapi import HTTPException
        from hunt import asset_actions
        from targets import asset_router
        from runtime.capability_registry import CAPABILITY_REGISTRY
        from runtime.credential_store import PostgresCredentialProfileStore
        from runtime.credentials import build_credential_secret, public_credential_configuration
        from devices.shared_collections import save_device_collection
        from hunt.interaction_router import _hunt_bound_collection
        async with database() as conn:
            await prepare(conn)
            home = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('Home','source.test') RETURNING id")
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
            pool = BoundConnectionPool(conn)
            monkeypatch.setattr(asset_router,'_pool_provider',lambda:pool)
            monkeypatch.setattr(asset_actions.request_collection_api,'_pool_provider',lambda:pool)
            run = {'id':uuid.uuid4(),'target_id':home,'device_target_id':home,
                   'target_kind':'device','policy_json':{'active_testing':False}}
            from targets.hunt_authority import authority_row, save_authority, record_collection_share
            # An explicit operator opt-out must override both the default and planner flags.
            await save_authority(conn,await authority_row(conn,home),
                {'revision':0,'metadata_changes':False},recorded_by='operator:fixture')
            for name in asset_actions.NAMES:
                assert CAPABILITY_REGISTRY.require(name).target_kinds == frozenset({'web','api','network','device'})
                if name == 'targets.skill.read':
                    continue
                expected = 'metadata changes' if name.startswith('targets.') else 'no active'
                with pytest.raises(HTTPException,match=expected):
                    await asset_actions.execute_asset_action(pool,run,name,{})
            await save_authority(conn,await authority_row(conn,home),
                {'revision':1,'metadata_changes':True},recorded_by='operator:fixture')
            created = await asset_actions.execute_asset_action(pool,run,'targets.create',
                {'locator':'tv.test','name':'TV','port_hints':[8008,8008,8060],'operator_confirmed':True})
            tv = uuid.UUID(created['id'])
            assert created['testing_authorized'] is False and run['target_id'] == home
            assert json.loads(await conn.fetchval('SELECT metadata_json FROM targets WHERE id=$1',tv))['port_hints'] == [8008,8060]
            with pytest.raises(HTTPException,match='outside the Hunt'):
                await asset_actions.execute_asset_action(pool,run,'targets.update',{'target_id':str(tv),'name':'Wrong','operator_confirmed':True})
            run.update(target_id=tv,device_target_id=None,target_kind='network')
            await save_authority(conn,await authority_row(conn,tv),
                {'revision':1,'metadata_changes':True},recorded_by='operator:fixture')
            from capabilities.inline import ControlPlaneExecutionAdapter
            from hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
            from runtime.models import TargetBinding
            spec = CAPABILITY_REGISTRY.require('targets.update')
            adapter = ControlPlaneExecutionAdapter(specification=spec,
                operation=lambda:asset_actions.execute_asset_action(pool,run,'targets.update',{'name':'Home TV','operator_confirmed':True}),
                requested_budget={'tool_wall_seconds':5,'agent_actions':1},
                redacted_execution={'name':'Home TV','operator_confirmed':True},blocked_exceptions=(HTTPException,),conservative_full_budget=True)
            execution = await CapabilityExecutor().execute(CapabilityExecutionContext(specification=spec,
                target=TargetBinding(target_id=str(tv),target_kind='network',canonical_host='tv.test'),
                requested_budget={'tool_wall_seconds':5,'agent_actions':1}),adapter,
                heartbeat=lambda:asyncio.sleep(0),cancelled=lambda:False)
            assert execution.status == 'success' and execution.observations[0]['kind'] == 'target_management_observation'
            assert execution.actual_budget == {'tool_wall_seconds':5,'agent_actions':1}
            assert await conn.fetchval('SELECT name FROM targets WHERE id=$1',tv) == 'Home TV'
            with pytest.raises(HTTPException,match='no active'):
                await asset_actions.execute_asset_action(pool,run,'credentials.grant',
                    {'profile_id':str(uuid.uuid4()),'operator_confirmed':True})
            run['policy_json'] = {'active_testing':True}
            material = build_credential_secret('bearer_token',secret='fixture-secret')
            profile = await PostgresCredentialProfileStore().create_profile(conn,target_kind='device',target_id=home,
                name='Shared fixture',auth_kind='bearer_token',principal_slot='primary',principal_label=None,
                configuration=public_credential_configuration(json.loads(material)),
                encrypted_secret=asset_actions.credential_api.encrypt_secret(material),
                encrypted_metadata=asset_actions.credential_api.encrypt_secret('{}'),expires_at=None,
                allowed_capabilities=['http.request'],now=datetime.now(timezone.utc))
            await save_authority(conn,await authority_row(conn,tv),
                {'revision':2,'metadata_changes':True,'credential_profile_ids':[str(profile.profile_id)]},recorded_by='operator:fixture')
            grant = await asset_actions.execute_asset_action(pool,run,'credentials.grant',
                {'profile_id':profile.profile_id,'operator_confirmed':True})
            assert grant['secret_values_visible'] is False and 'fixture-secret' not in json.dumps(grant,default=str)
            assert await PostgresCredentialProfileStore().has_active_grant(conn,profile_id=profile.profile_id,target_kind='network',target_id=tv)
            from scanner.scanner_tools.request_collections import validate_request_collection
            payload,summary = validate_request_collection({'info':{'name':'Shared collection'},
                'item':[{'name':'status','request':{'method':'GET','url':'http://source.test/status'}}]})
            collection = await save_device_collection(conn,home,summary=summary,
                encrypted_payload=asset_actions.credential_api.encrypt_secret(json.dumps(payload)))
            await record_collection_share(conn,tv,collection['id'],recorded_by='operator:fixture')
            with pytest.raises(HTTPException):
                await asset_actions.execute_asset_action(pool,run,'collections.bind',{'collection_id':str(collection['id']),
                    'allowed_origins':['https://foreign.test'],'operator_confirmed':True})
            bound = await asset_actions.execute_asset_action(pool,run,'collections.bind',{'collection_id':str(collection['id']),
                'allowed_origins':['http://tv.test:8008'],'operator_confirmed':True})
            binding = bound['binding']
            row = await conn.fetchrow('SELECT * FROM request_collections WHERE id=$1',collection['id'])
            ref = {'collection_id':str(collection['id']),'binding_id':binding['id'],
                   'payload_sha256':row['payload_sha256'],'allowed_origins':['http://tv.test:8008']}
            assert (await _hunt_bound_collection(conn,run,{'request_collections':[ref]},collection['id']))[0]['id'] == collection['id']
            # The broker must honor that exact binding across physical view labels,
            # just as the local replay worker does. Execute its production SQL.
            import ast
            from pathlib import Path
            tree = ast.parse((Path(__file__).resolve().parents[1]/'api/fleet_routes/router.py').read_text())
            handler = next(node for node in tree.body if isinstance(node,ast.AsyncFunctionDef) and node.name == '_broker_private_replay_plan')
            query = next(node.value for node in ast.walk(handler) if isinstance(node,ast.Constant)
                         and isinstance(node.value,str) and 'FROM request_collections c' in node.value)
            selection = uuid.uuid4()
            await conn.execute("UPDATE request_collection_bindings SET target_kind='device' WHERE id=$1",uuid.UUID(binding['id']))
            await conn.execute("""INSERT INTO request_collection_selections(id,collection_id,binding_id,name,replay_policy,selector_json,selection_digest)
                VALUES($1,$2,$3,'fixture','safe_reads','{}',$4)""",selection,collection['id'],uuid.UUID(binding['id']),'a'*64)
            for kind in ('web','api','network','device'):
                assert await conn.fetchrow(query,collection['id'],uuid.UUID(binding['id']),selection,tv,kind)
            assert await conn.fetchrow(query,collection['id'],uuid.UUID(binding['id']),selection,home,'network') is None
            await conn.execute('UPDATE request_collection_bindings SET is_active=false WHERE id=$1',uuid.UUID(binding['id']))
            assert await conn.fetchrow(query,collection['id'],uuid.UUID(binding['id']),selection,tv,'network') is None
            with pytest.raises(HTTPException,match='revoked'):
                await _hunt_bound_collection(conn,run,{'request_collections':[ref]},collection['id'])
    asyncio.run(run())


def test_settled_host_hunt_ports_reach_asset_device_view_and_hunt_query():
    async def run():
        import retest_contract
        from targets.asset_services import asset_service_knowledge
        from exposure.service_knowledge import query_service_knowledge
        from hunt.capability_reservations import terminalize_hunt_capability
        from runtime.budget_reservations import DurableBudgetReservation
        from runtime.reservation_store import PostgresBudgetReservationStore
        async with startup_database() as conn:
            owner = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('TV','tv.test') RETURNING id")
            await retest_contract.run_schema_migrations(BoundConnectionPool(conn))
            now = datetime.now(timezone.utc)
            hunt,action,receipt_id = uuid.uuid4(),uuid.uuid4(),uuid.uuid4()
            context = {'target':{'url':'host://tv.test'},'authorized_target_addresses':['192.0.2.10']}
            await conn.execute("INSERT INTO hunt_runs(id,target_id,target_kind,context_pack,created_at) VALUES($1,$2,'network',$3,$4)",hunt,owner,json.dumps(context),now)
            await conn.execute("INSERT INTO hunt_actions(id,hunt_run_id,capability_name,status) VALUES($1,$2,'ports.discover','running')",action,hunt)
            requested = DurableBudgetReservation.request(owner_kind='hunt',owner_id=str(hunt),capability_name='ports.discover',
                amounts={'tcp_ports_attempted':3},reservation_id=str(uuid.uuid4()),now=now)
            store = PostgresBudgetReservationStore()
            stored = await store.create_requested(conn,action_id=str(action),action_digest='a'*64,record=requested)
            stored = await store.persist_transition(conn,previous=stored,current=stored.record.reserve(now=now,lease_seconds=30),ledger_after_hold={'tcp_ports_attempted':3})
            stored = await store.persist_transition(conn,previous=stored,current=stored.record.start(worker_id='fixture',now=now,lease_seconds=30))
            assert (await asset_service_knowledge(conn,owner))['services'] == []
            terminal,receipt = terminalize_hunt_capability(stored.record,action_digest='a'*64,
                capability_name='ports.discover',adapter_name='naabu',adapter_version='1',target_id=str(owner),target_kind='network',
                capability_input={'ports':[8008,8009,8060]},action_status='partial',actual_budget={'tcp_ports_attempted':3},
                worker_id='fixture',started_at=now.isoformat(),finished_at=(now+timedelta(seconds=1)).isoformat(),receipt_id=str(receipt_id),
                result={'timed_out':True,'receipt_observations':[{'kind':'open_port','address':'192.0.2.10','transport':'tcp','port':8008,'state':'open'}]})
            await store.persist_terminal(conn,previous=stored,terminal=terminal,ledger_after_settlement={'tcp_ports_attempted':3},receipt=receipt)
            await conn.execute("UPDATE hunt_actions SET status='partial',receipt_id=$2 WHERE id=$1",action,receipt_id)
            shared = await asset_service_knowledge(conn,owner)
            assert len(shared['services']) == 1, shared
            assert shared['services'][0]['port'] == 8008
            assert shared['services'][0]['evidence'][0]['hunt_id'] == str(hunt)
            assert shared['services'][0]['observation_status'] == 'partial'
            for device in (False,True):
                query = await query_service_knowledge(conn,target_id=owner,device=device)
                assert query['rows'][0]['id'] == shared['services'][0]['id']
            await conn.execute('DELETE FROM hunt_runs WHERE id=$1',hunt)
            assert (await asset_service_knowledge(conn,owner))['services'] == []
    asyncio.run(run())
