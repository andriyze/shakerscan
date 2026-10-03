"""The shipped API CLI reaches a real TLS listener with only a scoped credential.

This is transport/ingress acceptance against a counting ASGI backend, not a live
vulnerability scan or proof that a deployment's network isolates its operator API.
"""
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import uvicorn

from api.hunt.planner_gateway import HuntPlannerGateway
from api.hunt.planner_lease import write_lease

ROOT = Path(__file__).resolve().parents[1]


def test_real_cli_cannot_self_authorize_but_can_drive_its_hunt(tmp_path):
    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),
            x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
    certificate, private_key = tmp_path/'certificate.pem', tmp_path/'private-key.pem'
    certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private_key.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    private_key.chmod(0o600)
    hunt_id = str(uuid4())
    grant, token_file = tmp_path/'grant.json', tmp_path/'planner-token'
    write_lease(hunt_id, grant, token_file)
    received = []

    async def backend(scope, receive, send):
        message = await receive()
        received.append((scope, message))
        await send({'type':'http.response.start', 'status':200,
                    'headers':[(b'content-type',b'application/json')]})
        await send({'type':'http.response.body', 'body':b'{"status":"success"}'})

    app = HuntPlannerGateway(backend, grant)
    sock = socket.socket(); sock.bind(('127.0.0.1', 0))
    address = f'https://127.0.0.1:{sock.getsockname()[1]}'
    config = uvicorn.Config(app, log_level='critical', access_log=False, lifespan='off', ws='none',
                            ssl_certfile=str(certificate), ssl_keyfile=str(private_key))
    server = uvicorn.Server(config)
    thread = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
    thread.start()
    try:
        deadline = time.monotonic()+5
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started, 'TLS fixture failed to start'
        env = {**os.environ, 'SSL_CERT_FILE':str(certificate),
               'SHAKERSCAN_API_TOKEN_FILE':str(token_file), 'NO_PROXY':'127.0.0.1,localhost',
               'no_proxy':'127.0.0.1,localhost'}
        env.pop('SHAKERSCAN_API_TOKEN', None)

        def call(method, path, body=None, *, authenticated=True):
            child_env = dict(env)
            if not authenticated: child_env.pop('SHAKERSCAN_API_TOKEN_FILE', None)
            args = [sys.executable, str(ROOT/'scripts/api_cli.py'), '--api-url', address, method, path]
            if body is not None: args.append(json.dumps(body))
            result = subprocess.run(args, env=child_env, capture_output=True, text=True, timeout=10)
            assert token_file.read_text().strip() not in result.stdout+result.stderr
            return result

        valid = call('POST', f'/hunts/{hunt_id}/capabilities/targets.skill.update',
            {'idempotency_key':'real-cli-1','input':{'expected_revision':1,'methodology':'Inspect port 8443.'}})
        assert valid.returncode == 0, valid.stdout+valid.stderr
        assert len(received) == 1
        for method, path in [('PUT',f'/targets/{uuid4()}/hunt-authority'),
                             ('POST',f'/hunts/{hunt_id}/budget-amendments'),
                             ('GET',f'/hunts/{uuid4()}')]:
            result = call(method,path,{'operator_confirmed':True} if method != 'GET' else None)
            assert result.returncode == 1
            assert '403' in result.stdout+result.stderr
        no_token = call('GET',f'/hunts/{hunt_id}',authenticated=False)
        assert no_token.returncode == 1 and '401' in no_token.stdout+no_token.stderr
        value = json.loads(grant.read_text()); value['enabled'] = False; grant.write_text(json.dumps(value))
        revoked = call('GET',f'/hunts/{hunt_id}')
        assert revoked.returncode == 1 and '401' in revoked.stdout+revoked.stderr
        assert len(received) == 1
        assert all(name.lower() != b'authorization' for name,_ in received[0][0]['headers'])
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        sock.close()
    assert not thread.is_alive()
