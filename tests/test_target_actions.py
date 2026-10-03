"""Saved actions persist on one asset and resolve only canonical typed calls."""
import asyncio
from copy import deepcopy
import json
from uuid import uuid4

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from api.targets.actions import TargetActionWrite, read_target_actions, write_target_action, resolve_steps
from api.hunt.asset_actions import execute_asset_action
from tests.test_target_instruction_trust import Connection


class ActionConnection(Connection):
    async def fetchrow(self, query, identifier, *args):
        assert identifier == self.row['id']
        if query.lstrip().startswith('UPDATE targets SET'):
            self.row['metadata_json']['hunt_actions'] = json.loads(args[0])
        return deepcopy(self.row)


def recipe(revision=0, **values):
    return TargetActionWrite(name='Check uptime', steps=[{'capability':'ssh.exec',
        'input':{'command':'uptime','port':2222}}], expected_revision=revision, **values)


def test_crud_revision_target_binding_and_unrelated_metadata():
    async def run():
        conn = ActionConnection(); target = conn.row['id']
        created = await write_target_action(conn, target, 'create', expected_revision=0, request=recipe())
        identifier = created['actions'][0]['id']
        assert created['actions'][0]['target_id'] == str(target)
        frozen = deepcopy(created)
        updated = await write_target_action(conn, target, 'update', action_id=identifier,
            expected_revision=1, request=recipe(1))
        assert updated['actions'][0]['revision'] == 2
        with pytest.raises(HTTPException) as stale:
            await write_target_action(conn, target, 'delete', action_id=identifier, expected_revision=1)
        assert stale.value.status_code == 409
        with pytest.raises(HTTPException) as wrong:
            await write_target_action(conn, target, 'delete', action_id=uuid4(), expected_revision=2)
        assert wrong.value.status_code == 404
        deleted = await write_target_action(conn, target, 'delete', action_id=identifier, expected_revision=2)
        assert deleted['revision'] == 3 and deleted['actions'] == []
        assert frozen['actions'][0]['revision'] == 1
        assert conn.row['metadata_json']['unrelated'] == 'preserve'
    asyncio.run(run())


def test_typed_parameters_are_whole_values_and_never_shell_interpolation():
    action = recipe(parameters={'port':{'type':'integer','default':22}}).model_dump()
    action['steps'][0]['input']['port'] = {'$parameter':'port'}
    resolved = resolve_steps(action, {'port':2222})
    assert resolved[0]['input'] == {'command':'uptime','port':2222}
    for values in ({'port':True}, {'port':'22; id'}, {'port':65536}, {'destination':'other'}):
        with pytest.raises(HTTPException):
            resolve_steps(action, values)
    assert action['steps'][0]['input']['port'] == {'$parameter':'port'}


@pytest.mark.parametrize('capability', ['arbitrary.shell','device.ssh.execute_confirmed','targets.actions.create'])
def test_noncanonical_or_recursive_actions_are_rejected(capability):
    with pytest.raises(ValidationError):
        TargetActionWrite(name='bad', steps=[{'capability':capability,'input':{}}],expected_revision=0)


@pytest.mark.parametrize('inputs', [{'command':'id','password':'secret'},
    {'command':'id','host':'other.test'}, {'command':'id','port':True}])
def test_invalid_or_inline_secret_inputs_fail_before_persistence(inputs):
    async def run():
        conn = ActionConnection()
        request = TargetActionWrite(name='invalid', steps=[{'capability':'ssh.exec','input':inputs}], expected_revision=0)
        with pytest.raises(HTTPException):
            await write_target_action(conn, conn.row['id'], 'create', expected_revision=0, request=request)
        assert (await read_target_actions(conn, conn.row['id']))['revision'] == 0
    asyncio.run(run())


def test_hunt_metadata_crud_obeys_saved_optout_without_requiring_network_authority(monkeypatch):
    from api.hunt import asset_actions
    conn = ActionConnection()
    class Pool:
        def acquire(self): return conn
    permitted = {'value':True}
    async def require(_conn, run, name, values):
        if not permitted['value']:
            raise HTTPException(403,'Metadata edits disabled')
        return {}, {'metadata_changes':True}
    monkeypatch.setattr(asset_actions, 'require_hunt_delegation', require)
    async def run():
        hunt = {'id':uuid4(),'target_id':conn.row['id'],'policy_json':{'active_testing':False}}
        values = recipe().model_dump()
        created = await execute_asset_action(Pool(), hunt, 'targets.actions.create', values)
        assert created['ok'] and created['hunt_snapshot_unchanged']
        assert created['actions'][0]['written_by'] == f"hunt:{hunt['id']}"
        read = await execute_asset_action(Pool(), hunt, 'targets.actions.read',
            {'action_id':created['actions'][0]['id']})
        assert read['resolved_steps'][0]['input']['command'] == 'uptime'
        permitted['value'] = False
        with pytest.raises(HTTPException) as refusal:
            await execute_asset_action(Pool(), hunt, 'targets.actions.delete',
                {'action_id':created['actions'][0]['id'],'expected_revision':1})
        assert refusal.value.status_code == 403
        assert len((await read_target_actions(conn, conn.row['id']))['actions']) == 1
    asyncio.run(run())

