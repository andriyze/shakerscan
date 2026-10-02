#!/usr/bin/env python3
"""Real Hunt/API/worker SSH acceptance on an owned disposable Docker fixture.

Run after ./scanner.sh rebuild. Uses the exact running worker image, synthetic
credentials, and the worker's Docker network. No external target is contacted.
"""
import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tests.e2e import harness as H  # noqa: E402
from tests.e2e.run_external_wire_acceptance import _worker_container  # noqa: E402


def docker(*args):
    return subprocess.check_output(['docker', *args], text=True, timeout=60).strip()


def accepted(path, body):
    code, response = H.post(path, body, timeout=180)
    if code >= 300:
        raise RuntimeError(f'{path} refused ({code}): {response.get("detail")}')
    return response


def action(hunt_id, inputs):
    return accepted(f'/hunts/{hunt_id}/capabilities/ssh.connect', {
        'idempotency_key': 'ssh-acceptance-' + uuid.uuid4().hex, 'input': inputs,
    })


def main():
    H.preflight()
    worker = json.loads(docker('inspect', _worker_container(None)))[0]
    network = next(iter(worker['NetworkSettings']['Networks']))
    name = 'hunt-ssh-fixture-' + uuid.uuid4().hex[:12]
    fixture = ROOT / 'tests/e2e/fixtures/ssh_server.py'
    target_id = profile_id = hunt_id = ''
    try:
        docker('run', '--detach', '--rm', '--name', name,
               '--label', 'com.docker.compose.project=hunt-ssh-fixtures',
               '--label', 'com.docker.compose.service=fixture',
               '--network', network, '--publish', '127.0.0.1::8081',
               '--volume', f'{fixture}:/tmp/ssh-fixture.py:ro',
               '--entrypoint', 'python3', worker['Image'], '/tmp/ssh-fixture.py')
        endpoint = 'http://' + docker('port', name, '8081/tcp')

        def stats():
            with urllib.request.urlopen(endpoint, timeout=3) as response:
                return json.load(response)

        for attempt in range(30):
            try:
                baseline = stats()
                break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError('SSH fixture did not become ready')
        target = accepted('/targets/hosts', {'locator': name, 'name': 'Local SSH acceptance',
            'environment': 'lab', 'approved_by': 'hunt-ssh-acceptance', 'port_hints': [22, 2222]})
        target_id = target['id']
        approval = H.get(f'/targets/{target_id}/authorization')['authorization']['approval_receipt_id']
        profile = accepted('/credential-profiles', {
            'target_kind': 'network', 'target_id': target_id, 'name': 'Synthetic SSH identity',
            'auth_kind': 'ssh_password', 'principal_slot': 'ssh', 'username': 'fixture-operator',
            'secret': 'fixture-only-password', 'allowed_capabilities': ['ssh.connect'],
            'allow_active_capabilities': True, 'approval_receipt_id': approval,
            'created_by': 'hunt-ssh-acceptance',
        })
        profile_id = profile['profile']['id']
        hunt = accepted('/hunts', {
            'schema_version': 'hunt-start/v2', 'target_id': target_id, 'target_kind': 'network',
            'goal': 'Authenticate on standard and operator-advised SSH ports; execute no commands.',
            'budget_profile': 'balanced', 'capabilities': ['ssh.connect'],
            'policy': {'network_discovery': True, 'authorization_confirmed': True},
            'credential_refs': {'ssh_credential_profile_id': profile_id},
        })
        hunt_id = hunt['hunt_id']
        assert hunt['budget']['max_device_fragility_points'] == 0
        assert hunt['capabilities'][0]['name'] == 'ssh.connect'
        for inputs in ({}, {'port': 2222, 'host_key_fingerprint': baseline['host_key_fingerprint']}):
            response = action(hunt_id, inputs)
            assert response['action_result']['status'] == 'success', response['action_result']
            result = response['result']
            assert result['budget_reservation_state'] == 'committed' and result['receipt_id']
            observation = result['typed_output']['records'][0]
            assert observation['authentication_succeeded'] and observation['connection_closed']
            assert observation['commands_executed'] is False
            assert 'fixture-only-password' not in json.dumps(response)
            print(f"PASS stored SSH identity on port {inputs.get('port', 22)}", flush=True)
        successful = stats()
        assert successful['authentication_attempts'] == successful['successful_logins'] == 2
        assert successful['channel_requests'] == 0
        denied = action(hunt_id, {'port': 2222, 'host_key_fingerprint': 'SHA256:' + 'A' * 43})
        assert denied['action_result']['status'] == 'failed'
        assert stats()['authentication_attempts'] == 2
        print('PASS wrong host key blocks identity authentication', flush=True)
        code, _ = H.delete(f'/credential-profiles/{profile_id}/grants/{target_id}')
        assert code < 300
        code, denied = H.post(f'/hunts/{hunt_id}/capabilities/ssh.connect', {
            'idempotency_key': 'ssh-revoked-' + uuid.uuid4().hex,
            'input': {'port': 2222, 'host_key_fingerprint': baseline['host_key_fingerprint']},
        }, timeout=180)
        assert code >= 400 or denied['action_result']['status'] in ('failed', 'blocked')
        assert stats()['authentication_attempts'] == 2
        print('PASS revoked grant blocks identity authentication; no command channels', flush=True)
        return 0
    finally:
        if hunt_id:
            H.post(f'/hunts/{hunt_id}/finish', {'summary': 'Local SSH acceptance finished.', 'next_actions': []})
        if profile_id:
            H.delete(f'/credential-profiles/{profile_id}')
        if target_id:
            H.post(f'/targets/{target_id}/archive', {})
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=30)


if __name__ == '__main__':
    sys.exit(main())
