"""Reference-only workflow schemas, encrypted captures and terminal cleanup."""
from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timezone
import json
from types import SimpleNamespace
import uuid

import pytest
import secret_store
from runtime.capability_registry import CAPABILITY_REGISTRY, CapabilityInputContractError
from runtime.hunt_http_exchange import HttpWorkflowExchange, _captured_value
from runtime.hunt_http_exchange_contract import pointer_get, pointer_set
from runtime.models import TargetBinding

HUNT, ACTION = str(uuid.UUID(int=201)), str(uuid.UUID(int=202))
TARGET = TargetBinding(target_id=str(uuid.UUID(int=203)), target_kind='device',
    canonical_host='tv.test', allowed_origins=('http://tv.test:7345',),
    allowed_addresses=('192.0.2.10',), allowed_root_domains=('tv.test',),
    environment='lab', scope_receipt_id=str(uuid.UUID(int=204)))


@pytest.fixture(autouse=True)
def encryption_key(monkeypatch, tmp_path):
    from cryptography.fernet import Fernet
    monkeypatch.setenv('AI_CREDENTIAL_ENC_KEY', Fernet.generate_key().decode())
    monkeypatch.setenv('RESULTS_DIR', str(tmp_path))
    monkeypatch.setattr(secret_store, '_loaded', False)
    monkeypatch.setattr(secret_store, '_fernet', None)


def validate(**inputs):
    return CAPABILITY_REGISTRY.validate_hunt_input('http.request',
        {'method': 'PUT', 'path': '/pair', 'json_body': {'pin': None}, **inputs})


@pytest.mark.parametrize('binding', [
    {}, {'header': 'AUTH'},
    {'source_action_id': 'not-uuid', 'capture_name': 'token', 'header': 'AUTH'},
    {'source_action_id': ACTION, 'header': 'AUTH'},
    {'source_action_id': ACTION, 'capture_name': 'token', 'header': 'AUTH', 'principal': 'primary'},
    {'source_action_id': ACTION, 'capture_name': 'token', 'header': 'AUTH', 'body_pointer': '/pin'},
    {'principal': 'primary', 'body_pointer': '/pin'},
    {'principal': 'primary', 'credential_field': 'secret', 'body_pointer': ''},
    {'profile_id': HUNT, 'credential_field': 'secret', 'body_pointer': '/pin'},
    {'profile_id': HUNT, 'profile_version': 0, 'credential_field': 'secret', 'body_pointer': '/pin'},
    {'profile_id': HUNT, 'profile_version': True, 'credential_field': 'secret', 'body_pointer': '/pin'},
    {'principal': 'primary', 'credential_field': 'secret', 'header': 'Host'},
    {'principal': 'primary', 'credential_field': 'secret', 'header': 'Content-Length'},
    {'principal': 'primary', 'credential_field': 'secret', 'header': 'X-HTTP-Method'},
    {'principal': 'primary', 'credential_field': 'secret', 'header': 'X-Method-Override'},
    {'principal': 'primary', 'credential_field': 'secret', 'header': 'X-Original-URL'},
    {'principal': 'primary', 'credential_field': 'secret', 'header': 'AUTH\r\nHost'},
    {'principal': 'primary', 'credential_field': 'secret', 'header': 'AUTH', 'prefix': 'Bearer\r\n'},
    {'principal': 'primary', 'credential_field': 'secret', 'body_pointer': '/pin', 'prefix': 'x'},
    {'principal': 'primary', 'credential_field': 'secret', 'body_pointer': '/~invalid'},
])
def test_invalid_reference_or_destination_rejected_before_admission(binding):
    with pytest.raises((ValueError, CapabilityInputContractError)):
        validate(request_bindings=[binding])


@pytest.mark.parametrize('captures', [
    [{'name': 'token'}],
    [{'name': 'token', 'json_pointer': '/token', 'header': 'AUTH'}],
    [{'name': 'token', 'json_pointer': '/token'}, {'name': 'token', 'header': 'AUTH'}],
    [{'name': 'token', 'json_pointer': '/~2'}],
    [{'name': 'token', 'json_pointer': 'not-a-pointer'}],
    [{'name': 'token', 'header': 'bad header'}],
])
def test_invalid_capture_schema_rejected(captures):
    with pytest.raises((ValueError, CapabilityInputContractError)):
        validate(capture=captures)


def test_rfc6901_pointers_nested_arrays_escaping_and_invalid_indices():
    body = {'a/b': {'~1': [None]}}
    pointer_set(body, '/a~1b/~01/0', 'value')
    assert pointer_get(body, '/a~1b/~01/0') == 'value'
    for pointer in ('/a~1b/~01/01', '/a~1b/~01/-1', '/a~1b/~01/9'):
        with pytest.raises(ValueError):
            pointer_get(body, pointer)
        with pytest.raises(ValueError):
            pointer_set(body, pointer, 'value')


def test_capture_is_encrypted_bound_and_reusable_on_another_service_of_same_asset():
    state = HttpWorkflowExchange(HUNT, ACTION, TARGET, ({'name': 'token', 'header': 'X-TV-Token'},))
    state.capture_response(SimpleNamespace(status_code=200, headers=lambda: {'x-tv-token': 'not-public'}, body=lambda: b''))
    assert state.encrypted_result.startswith('enc:fernet:')
    assert 'not-public' not in repr(state) + json.dumps(state.public_result()) + state.encrypted_result
    async def scenario():
        async def row(*_):
            return {'private_http_result': state.encrypted_result}
        conn = SimpleNamespace(fetchrow=row)
        value = await _captured_value(conn, run_id=HUNT,
            target=replace(TARGET, allowed_origins=('https://tv.test:7777',)),
            binding={'source_action_id': ACTION, 'capture_name': 'token'})
        assert value == 'not-public'
    asyncio.run(scenario())


@pytest.mark.parametrize('body', [b'{"token":"one","token":"two"}', b'{"token": {"secret":"x"}}',
    b'{"token":NaN}', b'{"token":"' + b'x' * 9000 + b'"}', b'invalid JSON', b'{}'])
def test_bad_capture_does_not_leak_target_data_or_claim_success(body):
    state = HttpWorkflowExchange(HUNT, ACTION, TARGET, ({'name': 'token', 'json_pointer': '/token'},))
    state.capture_response(SimpleNamespace(status_code=200, headers=lambda: {}, body=lambda: body))
    assert state.capture_error == 'http_workflow_capture_incomplete'
    assert state.public_result() == [] and state.encrypted_result is None


@pytest.mark.parametrize('status,completed', [('cancelled', None), ('completed', datetime.now(timezone.utc)),
    ('budget_exhausted', datetime.now(timezone.utc))])
def test_late_worker_never_restores_capture_after_terminal_hunt(status, completed):
    async def scenario():
        writes = []
        async def execute(*args):
            writes.append(args)
        state = HttpWorkflowExchange(HUNT, ACTION, TARGET, ({'name': 'token', 'json_pointer': '/token'},))
        state.capture_response(SimpleNamespace(status_code=200, headers=lambda: {}, body=lambda: b'{"token":"secret"}'))
        assert state.encrypted_result
        await state.persist(SimpleNamespace(execute=execute), run={'status': status, 'completed_at': completed}, status='success')
        assert not writes and not state.public_result() and state.encrypted_result is None
    asyncio.run(scenario())
