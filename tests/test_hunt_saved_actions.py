import asyncio
import json
from uuid import uuid4

import pytest

from api.hunt.saved_actions import recipe_steps, retain_hunt_action


def action(name='http.request', values=None, status='completed'):
    return {'id': uuid4(), 'capability_name': name, 'status': status,
            'input_summary': {'input': values or {'method': 'GET', 'path': '/health',
                                                  'origin': 'https://app.test:8443'}}}


def test_recipe_keeps_the_service_port_and_deduplicates_completed_steps():
    first = action()
    steps, parameters, evidence = recipe_steps([first, action(), action(status='partial')])
    assert steps == [{'capability': 'http.request', 'input': first['input_summary']['input']}]
    assert parameters == {} and evidence == [str(first['id'])]


def test_current_sessions_become_required_parameters_and_are_never_saved_as_defaults():
    session = str(uuid4())
    steps, parameters, _ = recipe_steps([action(values={'method': 'GET', 'path': '/account', 'session_ref': session})])
    assert steps[0]['input']['session_ref'] == {'$parameter': 'session_1'}
    assert parameters['session_1']['type'] == 'string'
    assert session not in json.dumps([steps, parameters])


@pytest.mark.parametrize('row', [
    action('findings.create'), action('targets.actions.create'), action('ssh.exec'),
    action(values={'path': '/?key=***'}), action(values={'path': '/', 'body': 'private input'}),
    action(values={'path': '/', 'capture': True}), action(status='failed'),
])
def test_unsettled_control_plane_secret_or_transient_material_is_not_a_recipe(row):
    assert recipe_steps([row]) == ([], {}, [])


def test_recipe_respects_the_existing_sixteen_step_bound():
    rows = [action(values={'method': 'GET', 'path': f'/route-{index}'}) for index in range(30)]
    steps, _, evidence = recipe_steps(rows)
    assert len(steps) == len(evidence) == 16


@pytest.mark.parametrize('summary', ['null', '{broken', [], {'input': []}])
def test_a_malformed_historical_summary_does_not_lose_other_reusable_steps(summary):
    bad = {**action(), 'input_summary': summary}
    good = action()
    steps, _, evidence = recipe_steps([bad, good])
    assert len(steps) == 1 and evidence == [str(good['id'])]


def test_metadata_opt_out_prevents_automatic_saved_action_writes(monkeypatch):
    from targets import hunt_authority
    async def authority(*args, lock=False):
        assert lock is True
        return {'id': uuid4(), 'url': 'host://app.test', 'is_active': True,
                'metadata_json': {'hunt_authority': {'target_url': 'host://app.test',
                                'metadata_changes': False, 'instruction_changes': True}}}
    monkeypatch.setattr(hunt_authority, 'authority_row', authority)
    result = asyncio.run(retain_hunt_action(object(), {'id': uuid4(), 'target_id': uuid4()}))
    assert result == {'status': 'skipped', 'reason': 'target_metadata_changes_disabled'}
