"""Contracts and lifecycle regressions for direct operator-granted SSH execution."""
import hashlib
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from api.capabilities.ssh_commands import SshCommandAdapter
from api.capabilities.ssh_channel import OutputCapture
from api.capabilities.ssh_transport import SshTransportPool
from api.runtime.models import ScanPolicy, TargetBinding
from api.runtime.ssh_command_contract import command_audit


def prepared(args=None, *, kind='network', capabilities=('ssh.exec',), active=True):
    target = TargetBinding(str(uuid4()), kind, 'fixture.test', allowed_addresses=('192.0.2.1',))
    policy = ScanPolicy(active_testing=active, network_discovery=active, approval_receipt_id='approval')
    profile = {'profile_id':str(uuid4()),'profile_version':1,'principal_slot':'ssh',
               'source':'credential_profiles','auth_kind':'ssh_password',
               'allowed_capabilities':capabilities,'service_port':2222}
    return SshCommandAdapter('ssh.exec').prepare(target=target, args={'command':'id', **(args or {})},
        policy=policy, context={'credential_refs':[profile]})


@pytest.mark.parametrize('kind',['web','api','network','device'])
def test_remote_command_preparation_never_invents_local_argv(kind):
    result = prepared(kind=kind)
    assert result.commands == ()
    assert result.redacted_execution['port'] == 2222
    assert 'command' not in result.redacted_execution
    assert result.redacted_execution['command_sha256'] == hashlib.sha256(b'id').hexdigest()
    assert result.estimated_budget['tcp_ports_attempted'] == 1


def test_authentication_grant_does_not_grant_commands():
    with pytest.raises(ValueError, match='explicit ssh.exec'):
        prepared(capabilities=('ssh.connect',))
    with pytest.raises(ValueError):
        prepared(active=False)


@pytest.mark.parametrize('values', [{'port':True}, {'port':0}, {'port':65536}, {'timeout_seconds':0},
    {'timeout_seconds':301}, {'max_output_bytes':262145}, {'command':''}, {'command':'x\x00'},
    {'command':'é'*8192}, {'cwd':'relative'}, {'session_id':'bogus'}, {'host':'another.test'},
    {'password':'not-an-input'}])
def test_invalid_or_authority_expanding_inputs_rejected(values):
    with pytest.raises(ValueError):
        prepared(values)


def test_reuse_has_no_new_host_or_port_reservation_and_adopts_bound_port_only():
    result = prepared({'session_id':str(uuid4())})
    assert result.redacted_execution['port'] is None
    assert 'hosts_attempted' not in result.estimated_budget
    assert 'tcp_ports_attempted' not in result.estimated_budget
    assert result.estimated_budget['tool_wall_seconds'] == 32


def test_private_command_and_directory_are_not_audit_text():
    result = command_audit({'command':'printf private-value','cwd':'/private/path','port':2222})
    assert 'private-value' not in json.dumps(result) and '/private/path' not in json.dumps(result)
    assert result['port'] == 2222


def test_redaction_handles_split_known_credential_and_terminal_truncation():
    capture = OutputCapture(1024, ('fixture-only-password',))
    capture.append('stdout', b'normal\nfixture-only-')
    assert capture.public()['stdout'] == 'normal\n'
    assert 'fixture-only-' not in capture.public(final=True)['stdout']
    capture.append('stdout', b'password\n')
    assert capture.public()['stdout'] == 'normal\n[REDACTED]\n'
    capture.append('stderr', b'x'*1500)
    assert capture.truncated and capture.public()['output_bytes'] == 1024


def test_failed_cwd_prevents_every_part_of_a_compound_command(tmp_path):
    import subprocess
    from api.capabilities.ssh_channel import run_command
    class Channel:
        closed = False
        def settimeout(self, value): pass
        def shutdown_write(self): pass
        def exec_command(self, command):
            self.completed = subprocess.run(['/bin/sh','-c',command],capture_output=True,timeout=5)
            self.stdout, self.stderr = self.completed.stdout, self.completed.stderr
        def recv_ready(self): return bool(self.stdout)
        def recv_stderr_ready(self): return bool(self.stderr)
        def recv(self, size):
            value,self.stdout = self.stdout[:size],self.stdout[size:];return value
        def recv_stderr(self, size):
            value,self.stderr = self.stderr[:size],self.stderr[size:];return value
        def exit_status_ready(self): return True
        def recv_exit_status(self): return self.completed.returncode
        def close(self): self.closed = True
    def execute(cwd):
        channel = Channel()
        session = SimpleNamespace(transport=SimpleNamespace(open_session=lambda **kwargs:channel,is_active=lambda:True))
        capture = OutputCapture(1024)
        result = run_command(session,{'timeout_seconds':5},command='printf first; printf second',
            cwd=str(cwd),stopped=lambda:False,capture=capture,on_progress=lambda value:None)
        return result,capture.public(final=True)
    result,output = execute(tmp_path/'missing')
    assert result['exit_status'] != 0 and output['stdout'] == ''
    directory = tmp_path/"quoted ' directory";directory.mkdir()
    result,output = execute(directory)
    assert result['exit_status'] == 0 and output['stdout'] == 'firstsecond'


def test_selected_ssh_identity_can_connect_without_discovery_permission():
    from api.capabilities.network_inputs import CapabilityInputError
    target = TargetBinding(str(uuid4()),'network','fixture.test',allowed_addresses=('192.0.2.1',))
    ref = {'profile_id':str(uuid4()),'profile_version':1,'principal_slot':'ssh',
           'source':'credential_profiles','auth_kind':'ssh_password','allowed_capabilities':['ssh.exec']}
    policy = ScanPolicy(active_testing=True,network_discovery=False,approval_receipt_id='approval')
    action = SshCommandAdapter('ssh.exec').prepare(target=target,args={'command':'uptime'},
        policy=policy,context={'credential_refs':[ref]})
    assert action.redacted_execution['port'] == 22
    from api.capabilities.network import network_capability_adapter
    with pytest.raises(CapabilityInputError):
        network_capability_adapter('ports.discover').prepare(target=target,args={'profile':'top100'},policy=policy)


def test_fast_fixture_commands_wait_for_delayed_exec_acknowledgement(monkeypatch,tmp_path):
    import time
    import paramiko
    from tests.ssh_exec_fixture import CommandServer,PASSWORD,USERNAME
    send = paramiko.Transport._send_user_message
    def delayed_ack(transport,message):
        if message.asbytes()[:1] == paramiko.common.cMSG_CHANNEL_SUCCESS:
            time.sleep(0.05)
        return send(transport,message)
    monkeypatch.setattr(paramiko.Transport,'_send_user_message',delayed_ack)
    fixture = CommandServer(tmp_path)
    command = "printf 'fast-output'; exit 7"
    fixture.allow(command)
    client = paramiko.SSHClient()
    client.get_host_keys().add(f'[127.0.0.1]:{fixture.port}',fixture.key.get_name(),fixture.key)
    try:
        client.connect('127.0.0.1',port=fixture.port,username=USERNAME,password=PASSWORD,
            look_for_keys=False,allow_agent=False,timeout=3,auth_timeout=3,banner_timeout=3)
        for _ in range(5):
            stdin,stdout,stderr = client.exec_command(command,timeout=3)
            stdin.close()
            assert stdout.read() == b'fast-output'
            assert stderr.read() == b''
            assert stdout.channel.recv_exit_status() == 7
            stdout.close();stderr.close()
        assert fixture.logins == 1 and fixture.commands == [command]*5
    finally:
        client.close();fixture.close()

def test_transport_is_owned_by_exact_run_target_identity_and_service():
    pool = SshTransportPool()
    binding = (str(uuid4()),'target-digest','192.0.2.1',2222,str(uuid4()),1)
    session, reused = pool.acquire(binding)
    assert not reused
    session.transport = SimpleNamespace(is_active=lambda:True,is_authenticated=lambda:True,close=lambda:None)
    pool.release(session)
    got, reused = pool.acquire((*binding[:3],None,*binding[4:]),session.session_id)
    assert got is session and reused
    pool.release(got)
    for index, value in [(0,str(uuid4())),(1,'other'),(2,'192.0.2.2'),(3,22),(4,str(uuid4())),(5,2)]:
        changed = list(binding); changed[index]=value
        with pytest.raises(ValueError): pool.acquire(tuple(changed),session.session_id)
    with pytest.raises(ValueError): pool.remove(session.session_id,hunt_id=str(uuid4()))
    assert pool.remove(session.session_id,hunt_id=binding[0],target_digest=binding[1])
    with pytest.raises(ValueError): pool.acquire(binding,session.session_id)


def test_ssh_skips_only_http_pacing_not_device_quotas_or_operator_freeze():
    from datetime import datetime, timezone
    from api.hunt.device_traffic import action_device_state
    run = {'context_pack':{'device_policy_state':{'last_request_at':datetime.now(timezone.utc).isoformat()}}}
    action_device_state(run,'ssh.exec').require_admission(request_attempts=1,fragility_cost=1)
    with pytest.raises(ValueError,match='pacing'):
        action_device_state(run,'http.request').require_admission(request_attempts=1)
    run['context_pack']['device_policy_state']['traffic_frozen'] = True
    run['context_pack']['device_policy_state']['freeze_reason'] = 'operator_pause'
    with pytest.raises(ValueError,match='frozen'):
        action_device_state(run,'ssh.exec').require_admission(request_attempts=1)
