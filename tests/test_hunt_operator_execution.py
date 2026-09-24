"""Real admission and loopback target TLS regressions. Synthetic credentials only."""
from __future__ import annotations
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import ssl
import sys
from types import SimpleNamespace
sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parents[1] / 'api')]

import httpx
import pytest
from fastapi import FastAPI
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from api.hunt import run_router
from api.runtime.approval_policy import approval_covers_risk
from capabilities.auth import TargetBoundSessionCredential, establish_target_bound_http_session
from capabilities.http import execute_bound_http_request
from capabilities.browser_login_action import BrowserLoginRuntimeTransport
from runtime.models import TargetBinding
from runtime.pinned_http_replay import PinnedAiohttpReplayTransport
from runtime.credential_resolver import CredentialResolutionError, validate_worker_credential_authority
from scanner.scanner_tools.request_replay import ReplayRequest

PASSWORD = 'synthetic-fixture-password'
COOKIE = 'synthetic-fixture-session'
ID = '11111111-1111-4111-8111-111111111111'


@pytest.mark.parametrize('credentialed', [False, True])
@pytest.mark.parametrize('active', [False, True])
def test_actual_route_reuses_standing_authorization(monkeypatch, credentialed, active):
    calls, admitted = [], []
    async def resolver(target):
        calls.append(target)
        return {'approval_receipt_id': ID, 'scope_receipt_id': 'scope'}
    async def handler(contract):
        admitted.append(contract)
        return {'hunt_id': 'fixture', 'policy': contract.policy.public_dict()}
    monkeypatch.setattr(run_router, '_standing_authorization_resolver', resolver)
    monkeypatch.setattr(run_router, '_start_handler', handler)
    app = FastAPI(); app.include_router(run_router.router)
    async def execute():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://fixture') as client:
            return await client.post('/hunts', json={
                'target_id': ID, 'target_kind': 'network', 'goal': 'Inspect local fixture',
                'policy': {'active_testing': active},
                'credential_refs': {'primary_credential_profile_id': 'profile-1'} if credentialed else {},
            })
    response = asyncio.run(execute())
    assert response.status_code == 200, response.text
    if active or credentialed:
        assert calls == [ID]
        assert admitted[0].policy.approval_receipt_id == ID
        assert admitted[0].policy.authorization_confirmed
    else:
        assert calls == []


@pytest.mark.parametrize('change', [{}, {'status': 'revoked'}, {'target_id': 'different-target'},
                                    {'expires_at': datetime.now(timezone.utc)-timedelta(days=1)},
                                    {'action_name': 'not-standing'}, {'approved_by': None}])
def test_worker_reuses_standing_authority_but_keeps_identity_and_revocation(change):
    row = {'scope_receipt_id': 'scope', 'target_id': ID, 'risk_tier': 'active',
           'action_name': 'target.authorization', 'confirmations': ['confirm_authorized'],
           'approved_by': 'fixture operator', 'denial_reason': None, 'expires_at': None,
           'status': 'active', 'revoked_at': None, 'verdict': 'allowed', **change}
    class Conn:
        async def fetchrow(self, *_): return row
    async def execute():
        return await validate_worker_credential_authority(Conn(), owner_kind='hunt', owner_id='fixture',
            target=TargetBinding(target_id=ID, target_kind='network', canonical_host='fixture.test', scope_receipt_id='scope'),
            approval_receipt_id=ID, scope_receipt_id='scope', action_name='hunt.capability:auth.session.establish')
    assert not approval_covers_risk(row, 'dangerous')
    if change:
        with pytest.raises(CredentialResolutionError): asyncio.run(execute())
    else:
        assert asyncio.run(execute()).approval_validated


def tls_context(tmp_path, defect):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    host = 'wrong-host.test' if defect == 'hostname' else 'fixture.test'
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(days=2))
            .not_valid_after(now-timedelta(days=1) if defect == 'expired' else now+timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path/'cert.pem', tmp_path/'key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert_path, key_path)
    return context


@asynccontextmanager
async def target_server(tmp_path, defect):
    calls = []
    async def handler(reader, writer):
        try:
            head = await reader.readuntil(b'\r\n\r\n')
            method, path, _ = head.split(b'\r\n', 1)[0].decode().split(' ')
            headers = dict(line.decode().split(': ', 1) for line in head.split(b'\r\n')[1:] if b': ' in line)
            body = await reader.readexactly(int(headers.get('Content-Length', '0')))
            calls.append((method, path, headers, body)); status, extra = 200, ''
            if path == '/login' and method == 'GET':
                data = b'<form action="/login" method="post"><input name="username"><input type="password" name="password"></form>'
            elif path == '/login' and method == 'POST':
                assert PASSWORD.encode() in body
                data, extra = b'logged in', f'Set-Cookie: session={COOKIE}; Path=/; HttpOnly\r\n'
            elif path == '/redirect':
                status, data, extra = 302, b'', 'Location: https://another.test/private\r\n'
            else:
                data = b'private-fixture-data'
                if COOKIE not in headers.get('Cookie', ''): status = 401
            writer.write(f'HTTP/1.1 {status} Fixture\r\nContent-Type: text/html\r\nContent-Length: {len(data)}\r\n{extra}Connection: close\r\n\r\n'.encode()+data)
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError): pass
        finally: writer.close()
    server = await asyncio.start_server(handler, '127.0.0.1', 0, ssl=tls_context(tmp_path, defect) if defect != 'http' else None)
    origin = f"{'http' if defect == 'http' else 'https'}://fixture.test:{server.sockets[0].getsockname()[1]}"
    target = TargetBinding(target_id='fixture', target_kind='network', canonical_host='fixture.test',
                           allowed_origins=(origin,), allowed_addresses=('127.0.0.1',), scope_receipt_id='scope')
    try: yield target, origin, calls
    finally:
        server.close(); await server.wait_closed()


@pytest.mark.parametrize('defect', ['self_signed', 'expired', 'hostname', 'http'])
def test_real_authenticated_requests_reach_nonstandard_port(tmp_path, defect):
    async def execute():
        async with target_server(tmp_path, defect) as (target, origin, calls):
            session = await establish_target_bound_http_session(TargetBoundSessionCredential(
                lane='primary', auth_kind='form_login', endpoint_url=origin+'/login', binding_digest='a'*64,
                username='fixture-user', secret=PASSWORD), target=target)
            assert session.established, session.execution_result()
            result = await execute_bound_http_request(origin, {'method': 'GET', 'path': '/private'}, target=target, trusted_headers=session.headers())
            assert result['ok'] and result['response']['status'] == 200
            assert calls[-1][2]['Host'] == origin.split('://')[1]
            assert PASSWORD not in json.dumps(session.execution_result())
            assert COOKIE not in json.dumps(result)
            await execute_bound_http_request(origin, {'method': 'GET', 'path': '/redirect', 'follow_redirects': True}, target=target, trusted_headers=session.headers())
            assert len(calls) == 4
    asyncio.run(execute())


def test_browser_login_and_replay_transports_reach_selfsigned_fixture(tmp_path):
    async def noop(): pass
    async def execute():
        async with target_server(tmp_path, 'self_signed') as (target, origin, calls):
            workflow = SimpleNamespace(origin=origin, submit_url=origin+'/login', max_requests=10, timeout_ms=30000, max_response_bytes=65536)
            transport = BrowserLoginRuntimeTransport(prepared=SimpleNamespace(target=target), workflow=workflow,
                revalidate=noop, heartbeat=noop, cancelled=lambda: False)
            async def headers(): return {'Content-Type': 'application/json'}
            response = await transport(SimpleNamespace(url=origin+'/login', method='POST', all_headers=headers,
                post_data_buffer=json.dumps({'password': PASSWORD}).encode()), 'login')
            assert response.status == 200
            request = ReplayRequest(request_id='fixture', ordinal=1, name='Private', folder='', method='GET', url=origin+'/private',
                headers=(('Cookie', f'session={COOKIE}'),), body=b'', body_mode='none', auth_type='cookie', has_sensitive_material=True)
            result = await PinnedAiohttpReplayTransport().send(request, target=target, timeout_seconds=3, follow_redirects=False)
            assert result.status_code == 200
            strict = await PinnedAiohttpReplayTransport(verify_tls=True).send(request, target=target, timeout_seconds=3, follow_redirects=False)
            assert strict.status_code is None and len(calls) == 2
    asyncio.run(execute())


def test_discovered_service_is_executable_in_the_same_hunt(tmp_path):
    from capabilities.http import resolve_hunt_http_origin
    from runtime.capability_registry import CAPABILITY_REGISTRY
    async def execute():
        async with target_server(tmp_path, 'http') as (target, origin, calls):
            primary = TargetBinding(target_id='fixture', target_kind='network', canonical_host='fixture.test',
                allowed_origins=('https://fixture.test',), allowed_addresses=('127.0.0.1',), scope_receipt_id='scope')
            policy = {'active_testing': True, 'network_discovery': True, 'approval_receipt_id': ID, 'scope_receipt_id': 'scope'}
            args = CAPABILITY_REGISTRY.validate_input('http.request', {'method': 'GET', 'path': '/private', 'origin': origin})
            selected = resolve_hunt_http_origin(primary, origin, policy)
            result = await execute_bound_http_request('https://fixture.test', args, target=selected, trusted_headers={'Cookie': f'session={COOKIE}'})
            assert result['ok'] and result['response']['status'] == 200 and len(calls) == 1
            assert selected.allowed_addresses == primary.allowed_addresses
            # Another port on the same authorized host no longer needs network
            # discovery on top of active testing; only active testing is required.
            still_selected = resolve_hunt_http_origin(primary, origin, {**policy, 'network_discovery': False})
            assert origin in {o for o in still_selected.allowed_origins}
            with pytest.raises(ValueError): resolve_hunt_http_origin(primary, origin, {**policy, 'active_testing': False})
            # A different host is still refused: host pinning is unchanged.
            with pytest.raises(ValueError): resolve_hunt_http_origin(primary, origin.replace('fixture.test', 'another.test'), policy)
    asyncio.run(execute())
