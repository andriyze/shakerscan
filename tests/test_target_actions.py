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


def test_hunt_saved_action_crud_needs_the_instruction_opt_in_and_fails_closed(monkeypatch):
    """Unit fixture: delegation is stubbed. With instruction_changes the write applies; any other
    refusal propagates unchanged (the proposal path is exercised against PostgreSQL in
    tests/test_saved_action_proposals_postgres.py)."""
    from api.hunt import asset_actions
    conn = ActionConnection()
    class Pool:
        def acquire(self): return conn
    refusal = {'value':None}
    async def require(_conn, run, name, values):
        if refusal['value'] is not None:
            raise refusal['value']
        return {}, {'metadata_changes':False,'instruction_changes':True,'revision':3}
    monkeypatch.setattr(asset_actions, 'require_hunt_delegation', require)
    async def run():
        hunt = {'id':uuid4(),'target_id':conn.row['id'],'policy_json':{'active_testing':False}}
        values = recipe().model_dump()
        created = await execute_asset_action(Pool(), hunt, 'targets.actions.create', values)
        assert created['ok'] and created['hunt_snapshot_unchanged'] and created['applied'] is True
        saved = created['actions'][0]
        assert saved['written_by'] == f"hunt:{hunt['id']}"
        assert saved['instruction_authority'] == 'target_instruction_delegation'
        assert saved['origin'] == 'agent_delegated' and saved['delegation_revision'] == 3
        read = await execute_asset_action(Pool(), hunt, 'targets.actions.read',
            {'action_id':saved['id']})
        assert read['resolved_steps'][0]['input']['command'] == 'uptime'
        assert read['action']['trust'] == 'operator_delegated'
        # Any refusal other than the instruction opt-in is never turned into a proposal.
        refusal['value'] = HTTPException(403,'Target edit is outside the Hunt asset')
        with pytest.raises(HTTPException) as refused:
            await execute_asset_action(Pool(), hunt, 'targets.actions.delete',
                {'action_id':saved['id'],'expected_revision':1})
        assert refused.value.status_code == 403
        assert len((await read_target_actions(conn, conn.row['id']))['actions']) == 1
    asyncio.run(run())


@pytest.mark.parametrize('delegation', [None, {}, {'metadata_changes':True}, {'instruction_changes':'true'},
                                        {'instruction_changes':1}, {'instruction_changes':False,'metadata_changes':True}])
@pytest.mark.parametrize('source', ['hunt:00000000-0000-4000-8000-000000000001', '', 'planner:x', None])
def test_a_non_operator_write_without_the_opt_in_is_refused_by_the_write_itself(delegation, source):
    """Defence in depth: even a caller that skips the Hunt delegation check cannot write."""
    async def run():
        conn = ActionConnection()
        with pytest.raises(HTTPException) as refused:
            await write_target_action(conn, conn.row['id'], 'create', expected_revision=0, request=recipe(),
                                      source=source, delegation=delegation)
        assert refused.value.status_code == 403
        assert refused.value.detail['reason_code'] == 'instruction_changes_not_delegated'
        assert (await read_target_actions(conn, conn.row['id']))['actions'] == []
    asyncio.run(run())


def test_operator_writes_are_recorded_as_operator_and_trusted():
    from api.targets.skill_trust import action_trust
    async def run():
        conn = ActionConnection()
        created = await write_target_action(conn, conn.row['id'], 'create', expected_revision=0, request=recipe())
        saved = created['actions'][0]
        assert saved['written_by'] == 'operator:target-action-api' and saved['origin'] == 'operator'
        assert action_trust(saved) == 'operator'
    asyncio.run(run())


@pytest.mark.parametrize('action,trust', [
    ({'written_by':'operator:target-action-api'}, 'operator'),
    ({'written_by':'operator:target-action-api','origin':'agent_unconfirmed'}, 'agent_unconfirmed'),
    ({'written_by':'hunt:x','instruction_authority':'target_instruction_delegation'}, 'operator_delegated'),
    ({'written_by':'hunt:x'}, 'agent_unconfirmed'),
    ({'written_by':'hunt:x','origin':'operator'}, 'agent_unconfirmed'),
    ({'written_by':'hunt:x','instruction_authority':'operator'}, 'agent_unconfirmed'),
    ({'name':'x'}, 'agent_unconfirmed'), ({'written_by':None}, 'agent_unconfirmed'), ({'written_by':'Operator:x'}, 'agent_unconfirmed'),
])
def test_saved_action_trust_is_operator_only_for_operator_writes(action, trust):
    from api.targets.skill_trust import action_trust
    assert action_trust(action) == trust
