"""Real HTTP admission, worker, pinned loopback traffic, vault and reservation ledger.

Database/Redis I/O use transactional doubles. The unchanged production worker
function, schemas, credential resolver, encryption and transport all execute.
The fixture is a synthetic TV protocol, not acceptance on a physical device.
"""
from __future__ import annotations

import ast
import asyncio
from contextlib import AsyncExitStack
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace
from typing import Any, Mapping
import uuid

import pytest
from cryptography.fernet import Fernet

import secret_store
from capabilities.inline import HttpRequestExecutionAdapter
from capabilities.network import CapabilityInputError
from hunt.action_dispatcher import HUNT_ACTION_DISPATCHER
from hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
from hunt.capability_reservations import (
    hunt_capability_action_digest, hunt_capability_lease_seconds, terminalize_hunt_capability,
)
from hunt.target_binding import web_hunt_target
from hunt.worker_accounting import worker_hunt_budget_accounting
from hunt.service_binding import registered_hunt_locator
from runtime.auth_session_store import AuthSessionStoreError
from runtime.budget_reservations import DurableBudgetReservation
from runtime.capability_registry import CAPABILITY_REGISTRY, CapabilityInputContractError
from runtime.credential_refs import CredentialReferenceError
from runtime.credential_resolver import CredentialResolutionError
from runtime.credentials import build_credential_secret, parse_credential_secret, public_credential_configuration
from runtime.models import ScanPolicy, TargetBinding
from runtime.reservation_store import ReservationConflict, ReservationStoreError
from scan.authorization import ActionAuthorityDecision, revalidate_scan_action_authority
# The worker functions exec here resolve these by name, as api/worker.py imports them.
from hunt.dispatch_authority import (  # noqa: F401
    HuntDispatchRejected, dispatch_http_request_authority, dispatch_http_target, dispatch_scope_binding,
    require_dispatchable, settle_rejected_dispatch,
)
from tests.test_hunt_authz_verification_limit import admission, Lifecycle, HUNT, TARGET
from tests.test_hunt_replay_worker_lifecycle import Connection as ReplayConnection, noop

ROOT = Path(__file__).resolve().parents[1]
# The leak checks below look for the PIN in results that also carry random hex digests, UUIDs and
# Fernet (base64url) tokens. A bare four-digit PIN occurs in those by chance (a digest containing
# "b942197d" failed CI); "~" is in none of those alphabets, so a match here is always a real leak.
PIN = '9421~pin'
CHALLENGE = 'fixture-challenge-7283519'
TOKEN = 'fixture-paired-credential-a61e79a0'
PROFILE_ID = uuid.UUID(int=91)


@pytest.fixture(autouse=True)
def encrypted_vault(monkeypatch, tmp_path):
    monkeypatch.setenv('AI_CREDENTIAL_ENC_KEY_FILE', str(tmp_path / 'vault.key'))
    monkeypatch.delenv('AI_CREDENTIAL_ENC_KEY', raising=False)
    monkeypatch.setattr(secret_store, '_loaded', False)
    monkeypatch.setattr(secret_store, '_fernet', None)


class Connection(ReplayConnection):
    def __init__(self, origin):
        super().__init__(kind='device', origin=origin, registered_origin=origin, active_limit=100)
        self.run['policy_json'].update(allow_state_changing_http=True, allowed_capabilities=['http.request'])
        self.run['budget_json'].update(max_state_changing_requests=100, max_device_fragility_points=100)
        self.run['completed_at'] = None
        self.raw_archive = []
        self.cancelled = False
        self.revoked = False
        now = datetime.now(timezone.utc)
        self.profile = {'id': PROFILE_ID, 'target_id': TARGET, 'target_kind': 'device', 'name': 'fixture PIN',
            'auth_kind': 'api_key_header', 'principal_slot': 'service', 'principal_label': 'fixture',
            'configuration_json': public_credential_configuration(parse_credential_secret('api_key_header', build_credential_secret('api_key_header', secret=PIN, header_name='AUTH'))), 'current_version': 1, 'record_version': 1,
            'is_active': True, 'expires_at': None, 'rotated_at': now, 'created_at': now, 'updated_at': now,
            'allowed_capabilities': ['http.request'],
            'encrypted_secret': secret_store.encrypt_secret(build_credential_secret('api_key_header', secret=PIN, header_name='AUTH')),
            'encrypted_metadata': secret_store.encrypt_secret(json.dumps({'schema_version': 'credential-private-metadata/v1'}))}

    async def fetchrow(self, sql, *args):
        if 'FROM credential_profiles p' in sql:
            # The worker lookup takes the consuming target as text: it matches that target's
            # grant row (credential_profile_bindings.binding_id).
            if args != (PROFILE_ID, 'device', str(TARGET)) or not self.profile['is_active']:
                return None
            return dict(self.profile)
        if 'SELECT private_http_result' in sql:
            action = self.actions.get(str(args[0]))
            return action if args[1] == HUNT and action and action['status'] == 'completed' else None
        if 'FROM approval_receipts' in sql:
            row = await super().fetchrow(sql, *args)
            row.update(target_id=TARGET, verdict='allowed', status='revoked' if self.revoked else 'active', revoked_at=None)
            return row
        return await super().fetchrow(sql, *args)

    async def fetch(self, sql, *args):
        # N56: a withholding action is seeded with the values this Hunt already sealed.
        if 'private_http_result IS NOT NULL' in sql:
            assert str(args[0]) == str(HUNT)
            return [action for action in self.actions.values() if action.get('private_http_result')]
        return await super().fetch(sql, *args)

    async def execute(self, sql, *args):
        if 'SET private_http_result=$3' in sql:
            assert args[1] == HUNT
            self.actions[str(args[0])]['private_http_result'] = args[2]
            return 'UPDATE 1'
        return await super().execute(sql, *args)

    def exists(self, key):
        return self.cancelled


async def admit(conn, inputs, key):
    CAPABILITY_REGISTRY.validate_hunt_input('http.request', inputs)
    fn = admission(conn)
    async def approval(*_, **kwargs):
        conn.approvals.append(kwargs['risk_tier'])
        return {'scope_receipt_id': 'scope'}
    fn.__globals__.update(PostgresBudgetReservationStore=lambda: conn.store,
        DurableBudgetReservation=DurableBudgetReservation,
        hunt_capability_action_digest=hunt_capability_action_digest,
        hunt_capability_lease_seconds=hunt_capability_lease_seconds,
        _validate_approval_receipt_for_action=approval,
        require_device_admission=noop, web_hunt_target=web_hunt_target,
        _hunt_managed_principal_reference=lambda *_, **__: None)
    life = Lifecycle('http.request')
    life.specification = CAPABILITY_REGISTRY.require('http.request')
    life.placement = life.specification.hunt_executor
    result = await fn(str(HUNT), 'http.request', SimpleNamespace(input=inputs, idempotency_key=key), life)
    return result


def worker(conn):
    names = {'process_canonical_http_capability_job', '_worker_hunt_ledger_limits',
             '_worker_terminal_network_result', '_revalidate_hunt_action_authority'}
    tree = ast.parse((ROOT / 'api/worker.py').read_text())
    nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in names]
    assert len(nodes) == len(names)
    async def dispatch(**kw):
        return await CapabilityExecutor().execute(CapabilityExecutionContext(
            specification=kw['specification'], target=kw['target'], requested_budget=kw['requested_budget'],
            adapter_managed_cancellation=bool(getattr(kw['adapter'], 'manages_cancellation', False))), kw['adapter'], heartbeat=kw['heartbeat'], cancelled=kw['cancelled'])
    async def archive(_conn, rows, *_):
        conn.raw_archive.extend(deepcopy(rows))
    async def findings(*_, **__):
        return []
    ns = {**globals(), 'db_pool': conn, 'get_redis': lambda: conn,
        'PostgresBudgetReservationStore': lambda: conn.store, 'PostgresAuthSessionStore': SimpleNamespace,
        '_worker_json_object': lambda v: json.loads(v) if isinstance(v, str) else dict(v or {}),
        '_worker_runtime_identity': lambda: 'worker:fixture', '_worker_hunt_web_target': web_hunt_target,
        '_AGENT_TOOL_RESULT_TTL_SECONDS': 60, 'RESULTS_DIR': '/unused',
        'agent_tools': SimpleNamespace(CAPABILITY_REGISTRY=CAPABILITY_REGISTRY),
        'require_worker_device_policy': lambda _, capability=None: None, 'settle_device_traffic': noop,
        '_dispatch_registered_hunt_adapter': dispatch, '_redact_receipt_value': lambda v: v,
        '_record_hunt_network_tool_receipt': noop, 'materialize_verified_hunt_findings': findings,
        'http_archive': SimpleNamespace(hunt_run_call_recorder=lambda *_, **__: (rows := [], rows.append),
                                      archive_hunt_capture=archive)}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[
        ast.ImportFrom(module='__future__', names=[ast.alias(name='annotations')], level=0), *nodes
    ], type_ignores=[])), str(ROOT / 'api/worker.py'), 'exec'), ns)
    return ns['process_canonical_http_capability_job']


async def execute(conn, inputs, key):
    admitted = await admit(conn, inputs, key)
    action_id = admitted['action_id']
    stored = next(row for row in conn.store.rows.values() if row.action_id == action_id)
    job = {'job_id': str(uuid.uuid4()), 'hunt_id': str(HUNT), 'action_id': action_id,
        'budget_reservation_id': stored.record.reservation_id, 'action_digest': stored.action_digest,
        'capability_name': 'http.request', 'capability_input': inputs, 'expected_budget': dict(stored.record.requested)}
    await worker(conn)(job)
    return deepcopy(conn.result), job


async def tv_server(wire, mode='normal'):
    async def serve(reader, writer):
        try:
            headers = await reader.readuntil(b'\r\n\r\n')
            length = re.search(rb'(?im)^content-length: (\d+)', headers)
            body = await reader.readexactly(int(length[1])) if length else b''
            wire.append((headers, body))
            if b'PUT /pairing/start ' in headers:
                document = {'challenge': CHALLENGE} if mode != 'missing' else {}
            elif b'PUT /pairing/pair ' in headers:
                data = json.loads(body)
                assert data == {'challenge': CHALLENGE, 'pin': PIN}
                document = {'auth_token': TOKEN, 'pin_echo': PIN}
            else:
                assert f'AUTH: {TOKEN}'.encode() in headers
                document = {'paired': True, 'echo': TOKEN}
            if mode == 'lost':
                return
            encoded = json.dumps(document).encode()
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: '
                + str(len(encoded)).encode() + b'\r\n\r\n' + encoded)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
    return await asyncio.start_server(serve, '127.0.0.1', 0)


def test_pairing_worker_challenge_pin_token_then_authenticated_request_and_idempotency():
    async def scenario():
        wire = []
        server = await tv_server(wire)
        async with server:
            origin = f'http://fixture.test:{server.sockets[0].getsockname()[1]}'
            conn = Connection(origin)
            start = {'method': 'PUT', 'path': '/pairing/start', 'json_body': {'client': 'fixture'},
                     'capture': [{'name': 'challenge', 'json_pointer': '/challenge'}]}
            first, first_job = await execute(conn, start, 'pair-start')
            assert first['status'] == 'success', first
            source = first['captures'][0]
            # A new PIN profile can be selected after start; no restart or copied secret.
            pair = {'method': 'PUT', 'path': '/pairing/pair', 'json_body': {'challenge': None, 'pin': None},
                'request_bindings': [{**source, 'body_pointer': '/challenge'},
                    {'profile_id': str(PROFILE_ID), 'profile_version': 1, 'credential_field': 'secret', 'body_pointer': '/pin'}],
                'capture': [{'name': 'token', 'json_pointer': '/auth_token'}]}
            paired, pair_job = await execute(conn, pair, 'pair-confirm')
            assert paired['status'] == 'success', paired
            auth = {'method': 'GET', 'path': '/paired-status',
                    'request_bindings': [{**paired['captures'][0], 'header': 'AUTH'}]}
            last, _ = await execute(conn, auth, 'pair-verify')
            assert last['status'] == 'success', last
            assert len(wire) == 3
            assert conn.run['budget_used_json']['state_changing_requests'] == 2
            assert conn.run['budget_used_json']['http_requests'] == 3
            saved_usage = deepcopy(conn.run['budget_used_json'])
            await worker(conn)(pair_job)
            assert conn.result['idempotent_redelivery'], conn.result
            assert conn.result['captures'] == paired['captures']
            assert len(wire) == 3 and conn.run['budget_used_json'] == saved_usage
            # All retained request inputs remain reference-only. Exact traffic is
            # explicitly private archival evidence, not fed to the planner.
            public = json.dumps([first, paired, last, conn.result, start, pair, auth])
            for secret in (PIN, CHALLENGE, TOKEN):
                assert secret not in public
            assert 'body_sha256' not in json.dumps(paired['typed_output'])
            ciphertexts = [a['private_http_result'] for a in conn.actions.values() if a.get('private_http_result')]
            assert len(ciphertexts) == 2 and all(c.startswith('enc:fernet:') for c in ciphertexts)
            assert all(secret not in ''.join(ciphertexts) for secret in (PIN, CHALLENGE, TOKEN))
            assert len(conn.raw_archive) == 3
            assert all(row.record.terminal for row in conn.store.rows.values())
    asyncio.run(scenario())


@pytest.mark.parametrize('mode', ['missing', 'lost'])
def test_sent_write_with_missing_capture_or_lost_response_is_charged_without_retry(mode):
    async def scenario():
        wire = []
        server = await tv_server(wire, mode)
        async with server:
            conn = Connection(f'http://fixture.test:{server.sockets[0].getsockname()[1]}')
            values = {'method': 'PUT', 'path': '/pairing/start', 'capture': [{'name': 'challenge', 'json_pointer': '/challenge'}]}
            result, job = await execute(conn, values, 'failed-capture')
            assert result['status'] == 'failed', result
            assert result['durable_budget_settled'], result
            assert len(wire) == 1 and result['budget_consumed']['state_changing_requests'] == 1
            await worker(conn)(job)
            assert len(wire) == 1 and not conn.result.get('captures')
            assert not any(a.get('private_http_result') for a in conn.actions.values())
    asyncio.run(scenario())


@pytest.mark.parametrize('problem', ['expired', 'different-hunt', 'different-asset', 'tampered', 'rotated-pin', 'revoked-pin'])
def test_stale_pairing_reference_or_changed_pin_never_sends_or_charges_a_write(problem):
    async def scenario():
        wire = []
        server = await tv_server(wire)
        async with server:
            conn = Connection(f'http://fixture.test:{server.sockets[0].getsockname()[1]}')
            first, _ = await execute(conn, {'method': 'PUT', 'path': '/pairing/start',
                'capture': [{'name': 'challenge', 'json_pointer': '/challenge'}]}, 'capture-for-stale-test')
            assert first['status'] == 'success', first
            ref = first['captures'][0]
            row = conn.actions[ref['source_action_id']]
            private = json.loads(secret_store.decrypt_secret(row['private_http_result']))
            if problem == 'expired':
                private['expires_at'] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
            elif problem == 'different-hunt':
                private['hunt_id'] = str(uuid.uuid4())
            elif problem == 'different-asset':
                private['target_digest'] = '0' * 64
            row['private_http_result'] = secret_store.encrypt_secret(json.dumps(private))
            if problem == 'tampered':
                row['private_http_result'] = 'enc:fernet:tampered'
            if problem == 'rotated-pin':
                conn.profile['current_version'] = 2
            if problem == 'revoked-pin':
                conn.profile['is_active'] = False
            pair = {'method': 'PUT', 'path': '/pairing/pair', 'json_body': {'challenge': None, 'pin': None},
                'request_bindings': [{**ref, 'body_pointer': '/challenge'},
                    {'profile_id': str(PROFILE_ID), 'profile_version': 1, 'credential_field': 'secret', 'body_pointer': '/pin'}]}
            result, job = await execute(conn, pair, 'stale-pair-ref')
            assert result['status'] in {'failed', 'blocked'}, result
            assert result['durable_budget_settled'], result
            assert result['budget_consumed'].get('state_changing_requests', 0) == 0
            assert len(wire) == 1
            assert PIN not in json.dumps(result)
            await worker(conn)(job)
            assert len(wire) == 1
    asyncio.run(scenario())


def test_cancelled_before_execution_releases_hold_without_a_pairing_request():
    async def scenario():
        wire = []
        server = await tv_server(wire)
        async with server:
            conn = Connection(f'http://fixture.test:{server.sockets[0].getsockname()[1]}')
            conn.cancelled = True
            result, _ = await execute(conn, {'method': 'PUT', 'path': '/pairing/start'}, 'cancel-before-write')
            assert result['status'] == 'cancelled', result
            assert result['durable_budget_settled'], result
            assert not wire and result['budget_consumed'].get('state_changing_requests', 0) == 0
    asyncio.run(scenario())


@pytest.mark.parametrize('field,value', [('active_testing', False), ('allow_state_changing_http', False)])
def test_unapproved_write_admission_has_no_side_effect(field, value):
    async def scenario():
        from fastapi import HTTPException
        conn = Connection('http://fixture.test:7345')
        conn.run['policy_json'][field] = value
        with pytest.raises(HTTPException):
            await admit(conn, {'method': 'PUT', 'path': '/pairing/start'}, 'not-authorized')
        assert not conn.store.rows and not conn.actions
    asyncio.run(scenario())


def test_pairing_response_header_capture_and_bearer_prefix_round_trip():
    async def scenario():
        wire = []
        async def serve(reader, writer):
            try:
                header = await reader.readuntil(b'\r\n\r\n')
                wire.append(header)
                if b'GET /token ' in header:
                    response = f'HTTP/1.1 200 OK\r\nX-Pairing-Token: {TOKEN}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'.encode()
                else:
                    assert f'Authorization: Bearer {TOKEN}'.encode() in header
                    response = b'HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n'
                writer.write(response)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
        server = await asyncio.start_server(serve, '127.0.0.1', 0)
        async with server:
            conn = Connection(f'http://fixture.test:{server.sockets[0].getsockname()[1]}')
            first, _ = await execute(conn, {'method': 'GET', 'path': '/token',
                'capture': [{'name': 'token', 'header': 'X-Pairing-Token'}]}, 'header-token')
            assert first['status'] == 'success', first
            final, _ = await execute(conn, {'method': 'GET', 'path': '/verify',
                'request_bindings': [{**first['captures'][0], 'header': 'Authorization', 'prefix': 'Bearer '}]}, 'bearer-check')
            assert final['status'] == 'success', final
            assert len(wire) == 2 and TOKEN not in json.dumps([first, final])
            assert conn.run['budget_used_json'].get('state_changing_requests', 0) == 0
            assert conn.raw_archive[-1]['principal_slot'] == 'workflow_binding'
    asyncio.run(scenario())
