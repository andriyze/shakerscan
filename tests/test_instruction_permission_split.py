"""Editing target instructions is its own Hunt permission, off by default (unit fixtures).

The connection here is a labelled double of the two reads ``require_hunt_delegation`` makes; the
PostgreSQL paths are covered in tests/test_instruction_proposals_postgres.py.
"""
import asyncio
import json
import uuid

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from runtime.capability_registry import CAPABILITY_REGISTRY
from targets.hunt_authority import authority_from_row, require_hunt_delegation
from targets.hunt_authority_router import HuntAuthorityWrite


def _row(saved=None, *, url='host://tv.local', active=True):
    metadata = {} if saved is None else {'hunt_authority': {'target_url': url, **saved}}
    return {'id': uuid.uuid4(), 'url': url, 'is_active': active, 'metadata_json': metadata}


class Connection:
    """Fixture: answers the asset-owner lookup and the locked target read."""

    def __init__(self, row):
        self.row = row

    async def fetchval(self, query, *args):
        return self.row['id']

    async def fetchrow(self, query, *args):
        return {**self.row, 'metadata_json': json.dumps(self.row['metadata_json'])}


def _require(row, name, values):
    run = {'id': uuid.uuid4(), 'target_id': row['id']}
    return asyncio.run(require_hunt_delegation(Connection(row), run, name, values))


def test_instruction_changes_default_off_for_new_and_existing_targets():
    assert authority_from_row(_row())['instruction_changes'] is False
    # An existing target whose operator saved metadata delegation keeps that choice untouched,
    # and still has no instruction permission: the setting did not exist when it was saved.
    existing = authority_from_row(_row({'metadata_changes': True, 'revision': 3}))
    assert existing['metadata_changes'] is True and existing['instruction_changes'] is False
    assert existing['revision'] == 3
    assert authority_from_row(_row({'metadata_changes': False, 'revision': 1}))['metadata_changes'] is False


def test_instruction_changes_needs_an_exact_saved_true_on_the_current_asset():
    assert authority_from_row(_row({'instruction_changes': True}))['instruction_changes'] is True
    for wrong in ('true', 1, None, False):
        assert authority_from_row(_row({'instruction_changes': wrong}))['instruction_changes'] is False
    moved = _row({'instruction_changes': True})
    moved['url'] = 'host://other.local'
    assert authority_from_row(moved)['instruction_changes'] is False
    assert authority_from_row(_row({'instruction_changes': True}, active=False))['instruction_changes'] is False


def test_operator_write_defaults_instruction_changes_off_and_takes_only_a_boolean():
    assert HuntAuthorityWrite(expected_revision=0).instruction_changes is False
    assert HuntAuthorityWrite(expected_revision=0, instruction_changes=True).instruction_changes is True
    with pytest.raises(ValidationError):
        HuntAuthorityWrite(expected_revision=0, instruction_changes='true')


@pytest.mark.parametrize('name', ['targets.skill.create', 'targets.skill.update', 'targets.skill.delete'])
@pytest.mark.parametrize('purpose', [None, 'instructions', 'Instructions', 'other'])
def test_saved_metadata_delegation_no_longer_permits_instruction_writes(name, purpose):
    row = _row({'metadata_changes': True, 'revision': 2})
    values = {} if purpose is None else {'purpose': purpose}
    with pytest.raises(HTTPException) as refused:
        _require(row, name, values)
    assert refused.value.status_code == 403
    detail = refused.value.detail
    assert detail['reason_code'] == 'instruction_changes_not_delegated'
    assert detail['propose_with'] == 'targets.skill.propose'
    assert 'targets.skill.propose' in detail['message'] and 'knowledge' in detail['message']


@pytest.mark.parametrize('name', ['targets.skill.create', 'targets.skill.update', 'targets.skill.delete'])
def test_operator_opt_in_permits_instruction_writes_independently_of_metadata(name):
    for metadata in (True, False):
        row = _row({'metadata_changes': metadata, 'instruction_changes': True})
        _, authority = _require(row, name, {})
        assert authority['instruction_changes'] is True


def test_knowledge_and_metadata_writes_still_follow_metadata_delegation():
    row = _row({'metadata_changes': True})
    for name, values in [('targets.skill.create', {'purpose': 'knowledge'}),
                         ('targets.skill.delete', {'purpose': 'knowledge'}), ('targets.update', {'name': 'TV'})]:
        _require(row, name, values)
    _require(_row(), 'targets.skill.update', {'purpose': 'knowledge'})  # default on, as before
    blocked = _row({'metadata_changes': False, 'instruction_changes': True})
    with pytest.raises(HTTPException, match='metadata changes'):
        _require(blocked, 'targets.skill.update', {'purpose': 'knowledge'})


def test_capability_contracts_describe_the_split_and_the_proposal_path():
    purpose = CAPABILITY_REGISTRY.require('targets.skill.create').input_schema['properties']['purpose']['description']
    assert 'instruction_changes' in purpose and 'targets.skill.propose' in purpose
    assert 'delegated CRUD' not in purpose
    for name in ('targets.skill.create', 'targets.skill.update', 'targets.skill.delete'):
        assert 'instruction_changes' in CAPABILITY_REGISTRY.require(name).description
    propose = CAPABILITY_REGISTRY.require('targets.skill.propose')
    assert propose.risk_tier == 'read_only' and propose.hunt_executor == 'inline'
    assert propose.placement_requirements.get('control_plane') is True
    assert not propose.placement_requirements.get('user_confirmation')
    assert set(propose.input_schema['required']) >= {'title', 'methodology', 'reason', 'base_revision'}
    assert propose.target_kinds == frozenset({'web', 'api', 'network', 'device'})
