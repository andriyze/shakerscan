"""Audited metadata actions; reuse canonical APIs and never change a Hunt's frozen subject."""
import json
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException

try:
    from runtime.credential_store import PostgresCredentialProfileStore, CredentialStoreError
    from targets.asset_router import persist_host_target, HostTargetCreate
    from targets.skill import read_target_skill, write_target_skill, TargetSkillWrite
    import credential_api
    import request_collection_api
except ModuleNotFoundError:
    from ..runtime.credential_store import PostgresCredentialProfileStore, CredentialStoreError
    from ..targets.asset_router import persist_host_target, HostTargetCreate
    from ..targets.skill import read_target_skill, write_target_skill, TargetSkillWrite
    from .. import credential_api, request_collection_api
try:
    from targets.hunt_authority import require_hunt_delegation, save_authority
except ModuleNotFoundError:
    from ..targets.hunt_authority import require_hunt_delegation, save_authority

NAMES = frozenset({'targets.create','targets.update','credentials.grant','collections.bind',
                   'targets.skill.read','targets.skill.create','targets.skill.update','targets.skill.delete',
                   'targets.actions.read','targets.actions.create','targets.actions.update','targets.actions.delete'})


async def execute_asset_action(pool, run, name, values):
    try:
        result = await _perform_asset_action(pool,run,name,values)
    except ValueError as exc:
        raise HTTPException(422,str(exc)) from exc
    result = json.loads(json.dumps(result,default=str))
    result['observation'] = {'kind':'target_management_observation','capability':name,
                             'subject_target_id':str(run.get('device_target_id') or run['target_id']),
                             'changed_target_id':result.get('id') or result.get('target',{}).get('id') or result.get('target_id'),
                             'skill_revision':result.get('revision'),
                             'skill_body_sha256':(result.get('skill') or {}).get('body_sha256'),
                             'profile_id':values.get('profile_id'),'collection_id':values.get('collection_id'),
                             'secret_values_visible':False}
    return result


async def _perform_asset_action(pool, run, name, values):
    target_id = uuid.UUID(str(run.get('device_target_id') or run['target_id']))
    policy = run.get('policy_json') or {}
    if isinstance(policy,str):
        policy = json.loads(policy)
    if name.startswith('targets.actions.'):
        from targets.actions import read_target_actions, write_target_action, TargetActionWrite, resolve_steps
        async with pool.acquire() as conn, conn.transaction():
            if name == 'targets.actions.read':
                saved = await read_target_actions(conn, target_id)
                if values.get('action_id'):
                    action = next((item for item in saved['actions'] if item['id'] == values['action_id']), None)
                    if action is None:
                        raise HTTPException(404, 'Saved action not found on this target')
                    saved['resolved_steps'] = resolve_steps(action, values.get('parameters'))
                    saved['action'] = action
                return {'ok':True, **saved, 'execution':'Invoke each step through this Hunt’s capabilities with its own idempotency key'}
            await require_hunt_delegation(conn, run, name, values)
            request = TargetActionWrite(**{key:value for key,value in values.items()
                if key in {'name','instructions','steps','parameters','expected_revision'}}) if name != 'targets.actions.delete' else None
            return {'ok':True, **await write_target_action(conn, target_id, name.rsplit('.',1)[-1],
                expected_revision=values['expected_revision'], action_id=values.get('action_id'),
                request=request, source=f"hunt:{run['id']}"), 'hunt_snapshot_unchanged':True}
    if name.startswith('targets.skill.'):
        async with pool.acquire() as conn, conn.transaction():
            if name == 'targets.skill.read':
                return {'ok':True, **await read_target_skill(conn, target_id)}
            _, delegation = await require_hunt_delegation(conn, run, name, values)
            request = TargetSkillWrite(**{key:value for key,value in values.items()
                if key in {'title','methodology','expected_revision','purpose'}}) if name != 'targets.skill.delete' else None
            return {'ok':True, **await write_target_skill(conn, target_id, name.rsplit('.',1)[-1],
                expected_revision=values['expected_revision'], request=request,
                source=f"hunt:{run['id']}", delegation=delegation, purpose=values.get('purpose','instructions')),
                'hunt_snapshot_unchanged':True}
    if name not in {'targets.create', 'targets.update'} and not policy.get('active_testing'):
        raise HTTPException(403,'The Hunt has no active target-management authority')
    if name == 'targets.create':
        async with pool.acquire() as conn, conn.transaction():
            await require_hunt_delegation(conn, run, name, values)
            result = await persist_host_target(conn, HostTargetCreate(**{
                key:value for key,value in values.items() if key in {'locator','name','environment','port_hints'}
            }))
        return {'ok':True,**result,'testing_authorized':False,'hunt_target_unchanged':True}
    if name == 'collections.bind':
        request = request_collection_api.RequestCollectionBindingUpsert(
            target_kind=str(run['target_kind']),target_id=str(target_id),
            allowed_origins=values['allowed_origins'],environment_id=values.get('environment_id'),
            authorize_cross_asset=False,
        )
        return {'ok':True,**await request_collection_api.upsert_request_collection_binding(
            str(values['collection_id']),request), 'hunt_selection_unchanged':True}
    async with pool.acquire() as conn, conn.transaction():
        authority_row, authority = await require_hunt_delegation(conn, run, name, values)
        if name == 'targets.update':
            recipient = uuid.UUID(str(values.get('target_id') or target_id))
            same = await conn.fetchval('SELECT target_asset_access_owner($1)=target_asset_access_owner($2)',target_id,recipient)
            if not same:
                raise HTTPException(403,'Target edit is outside the Hunt asset')
            row = await conn.fetchrow('UPDATE targets SET name=$2,updated_at=NOW() WHERE id=$1 RETURNING id,name',recipient,values['name'])
            return {'ok':True,'target':dict(row),'hunt_target_unchanged':True}
        if name != 'credentials.grant':
            raise HTTPException(422,'Unsupported asset action')
        store = PostgresCredentialProfileStore()
        try:
            profile = await store.get_profile(conn,profile_id=values['profile_id'])
            if credential_api._has_active_capabilities(profile):
                await credential_api._require_active_capability_approval(conn,
                    target_id=target_id,approval_receipt_id=values.get('approval_receipt_id') or policy.get('approval_receipt_id'))
            grant = await store.grant_profile(conn,profile_id=values['profile_id'],
                target_kind=str(run['target_kind']),target_id=target_id,
                granted_by=f"hunt:{run['id']}",now=datetime.now(timezone.utc))
            # Sharing consent is consumed once. Revoking the resulting canonical grant
            # cannot be undone by another Hunt using an old delegation.
            authority['credential_profile_ids'].remove(str(values['profile_id']))
            authority['revision'] += 1
            await save_authority(conn, authority_row, authority, recorded_by=authority['recorded_by'])
        except CredentialStoreError as exc:
            raise HTTPException(422,str(exc)) from exc
        return {'ok':True,'grant':grant,'secret_values_visible':False,'hunt_selection_unchanged':True}
