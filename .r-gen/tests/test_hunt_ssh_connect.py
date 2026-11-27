"""Stored SSH identities reach the frozen service, never the planner or arbitrary shell."""
import asyncio
import base64
from contextlib import asynccontextmanager
from types import SimpleNamespace
import uuid

import pytest

from api.capabilities.ssh import SshConnectAdapter, SshExecutionAdapter
from api.runtime.models import TargetBinding, ScanPolicy
from tests.test_device_ssh_scanner import _fake_paramiko
from scanner_tools import ssh_scanner

PROFILE = str(uuid.uuid4())
TARGET = uuid.uuid4()
FINGERPRINT = 'SHA256:' + base64.b64encode(b'x'*32).decode().rstrip('=')


@pytest.fixture(autouse=True)
def operator_authorized_first_contact(monkeypatch):
    from api.capabilities import ssh as adapter_module
    async def read(*args): return {'ssh_host_keys':[], 'ssh_trust_first_contact':True}
    async def pin(*args): pass
    monkeypatch.setattr(adapter_module,'read_hunt_authority',read)
    monkeypatch.setattr(adapter_module,'pin_authorized_first_contact',pin)


def prepare(port=None, saved_port=None, kind='network', capabilities=('ssh.connect',)):
    args = {} if port is None else {'port':port}
    ref = {'profile_id':PROFILE,'profile_version':1,'principal_slot':'ssh',
           'auth_kind':'ssh_password','source':'credential_profiles',
           'allowed_capabilities':capabilities,'service_port':saved_port}
    target = TargetBinding(str(TARGET),kind,'fixture.test',allowed_addresses=('192.0.2.10',))
    policy = ScanPolicy(active_testing=True,network_discovery=True,approval_receipt_id='approval')
    return SshConnectAdapter().prepare(target=target,args=args,policy=policy,
                                       context={'credential_refs':[ref]}),target,policy


@pytest.mark.parametrize(('port','saved','expected'),[(None,None,22),(None,2222,2222),(2223,2222,2223)])
@pytest.mark.parametrize('kind',['web','api','network','device'])
def test_preparation_uses_operator_then_saved_then_standard_port(port,saved,expected,kind):
    execution,_,_ = prepare(port,saved,kind)
    assert execution.redacted_execution['port'] == expected
    assert execution.redacted_execution['address'] == '192.0.2.10'
    assert not execution.commands
    assert execution.estimated_budget['tcp_ports_attempted'] == 1
    assert execution.estimated_budget.get('device_fragility_points', 0) == (3 if kind == 'device' else 0)
    # The worker must reconstruct the exact persisted hold; its normalization drops zeroes.
    from api.runtime.budget_reservations import DurableBudgetReservation
    charges = {**execution.estimated_budget, 'agent_actions': 1, 'active_actions': 1}
    reservation = DurableBudgetReservation.request(owner_kind='hunt', owner_id='hunt-fixture',
        capability_name='ssh.connect', amounts=charges)
    assert dict(reservation.requested) == charges


@pytest.mark.parametrize('port',[True,0,65536,'22'])
def test_invalid_ports_are_rejected(port):
    with pytest.raises(ValueError,match='port'):
        prepare(port)


def test_profile_grant_and_frozen_selection_are_required():
    with pytest.raises(ValueError,match='stored SSH'):
        prepare(capabilities=('http.request',))
    execution,target,policy = prepare()
    for key in ('host','commands','password','private_key','profile_id'):
        with pytest.raises(ValueError,match='only'):
            SshConnectAdapter().prepare(target=target,args={key:'arbitrary'},policy=policy,context={})


@pytest.mark.parametrize('kind', ['web', 'api', 'network', 'device'])
def test_authorized_hunt_manifest_admits_ssh_with_target_appropriate_budget(kind):
    from api.hunt.contracts import capability_manifest
    from api.hunt.start_contract import normalize_hunt_start_payload
    contract = normalize_hunt_start_payload({
        'schema_version': 'hunt-start/v2', 'target_id': str(TARGET), 'target_kind': kind,
        'goal': 'Connect with the operator-selected stored SSH identity.', 'budget_profile': 'balanced',
        'policy': {'network_discovery': True, 'authorization_confirmed': True,
                   'approval_receipt_id': 'approval'},
        'credential_refs': {'ssh_credential_profile_id': PROFILE},
    })
    manifest = capability_manifest(contract, credentials_available=True)
    ssh = next(item for item in manifest if item['name'] == 'ssh.connect')
    assert ssh['budget_cost'].get('device_fragility_points', 0) == (3 if kind == 'device' else 0)
    assert ssh['budget_cost']['tcp_ports_attempted'] == 1


def test_zero_device_fragility_still_withholds_ssh_for_devices():
    from api.hunt.contracts import capability_manifest
    from api.hunt.start_contract import normalize_hunt_start_payload
    contract = normalize_hunt_start_payload({
        'schema_version': 'hunt-start/v2', 'target_id': str(TARGET), 'target_kind': 'device',
        'goal': 'No device traffic.', 'budget_profile': 'balanced',
        'budgets': {'max_device_fragility_points': 0},
        'policy': {'network_discovery': True, 'authorization_confirmed': True,
                   'approval_receipt_id': 'approval'},
        'credential_refs': {'ssh_credential_profile_id': PROFILE},
    })
    assert 'ssh.connect' not in {item['name'] for item in capability_manifest(contract, credentials_available=True)}


@pytest.mark.parametrize('port',[22,2222])
@pytest.mark.parametrize('kind',['ssh_password','ssh_private_key','ssh_private_key_with_passphrase'])
@pytest.mark.parametrize('target_kind',['web','api','network','device'])
def test_worker_uses_encrypted_identity_and_real_shared_paramiko_driver(monkeypatch,port,kind,target_kind):
    from api.capabilities import ssh as adapter_module
    from api.hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
    from api.runtime.capability_registry import CAPABILITY_REGISTRY
    calls,events = [],[]
    fake = _fake_paramiko(offered=['password','publickey'])
    monkeypatch.setattr(ssh_scanner,'paramiko',fake,raising=False)
    monkeypatch.setattr(ssh_scanner,'HAS_PARAMIKO',True)
    monkeypatch.setattr(ssh_scanner.socket,'create_connection',lambda address,**kwargs: calls.append(address) or object())
    @asynccontextmanager
    async def acquire():
        yield SimpleNamespace(fetchrow=fetchrow)
    async def fetchrow(*args): return None
    async def load(self,conn,**kwargs):
        events.append(('load',kwargs))
        return SimpleNamespace(metadata=SimpleNamespace(current_version=1,auth_kind=kind),encrypted_secret='ciphertext')
    monkeypatch.setattr(adapter_module.PostgresCredentialProfileStore,'load_for_worker',load)
    monkeypatch.setattr(adapter_module,'decrypt_secret',lambda value: events.append(('decrypt',value)) or 'plaintext-envelope')
    monkeypatch.setattr(adapter_module,'parse_credential_secret',lambda *_: {'username':'operator','secret':'hidden','secondary_secret':'passphrase'})
    async def revalidate(*args,**kwargs): events.append(('authority',None))
    async def heartbeat(): pass
    prepared,target,policy = prepare(port,kind=target_kind)
    adapter = SshExecutionAdapter(prepared=prepared,pool=SimpleNamespace(acquire=acquire),
        run={'target_id':TARGET,'device_target_id':None},target=target,policy=policy,
        target_url='host://fixture.test',revalidate=revalidate)
    result = asyncio.run(CapabilityExecutor().execute(
        CapabilityExecutionContext(specification=CAPABILITY_REGISTRY.require('ssh.connect'),
            target=target,requested_budget={**prepared.estimated_budget,'agent_actions':1,'active_actions':1}),
        adapter,heartbeat=heartbeat,cancelled=lambda: False))
    assert result.status == 'success', result.errors
    assert result.actual_budget['active_actions'] == 1
    assert result.actual_budget['tcp_ports_attempted'] == 1
    if target_kind == 'device':
        assert result.actual_budget['device_fragility_points'] == 3
    else:
        assert 'device_fragility_points' not in result.actual_budget
    assert calls and all(item == ('192.0.2.10',port) for item in calls)
    assert [e[0] for e in events] == ['authority','authority','load','decrypt']
    assert events[2][1] == {'profile_id':PROFILE,'target_kind':target_kind,'target_id':str(TARGET),'capability':'ssh.connect'}
    assert result.observations[-1]['authentication_succeeded'] is True
    assert result.observations[-1]['connection_closed'] is True
    assert result.observations[-1]['commands_executed'] is False
    assert result.observations[-1]['host_key_provenance'] == 'operator_authorized_first_contact'
    assert 'hidden' not in str(result) and 'passphrase' not in str(result)


def test_cancellation_before_start_performs_no_traffic_or_decryption():
    async def heartbeat(): pass
    prepared,target,policy = prepare()
    @asynccontextmanager
    async def acquire():
        yield SimpleNamespace(fetchrow=fetchrow)
    async def fetchrow(*args): return None
    adapter = SshExecutionAdapter(prepared=prepared,pool=SimpleNamespace(acquire=acquire),
        run={'target_id':TARGET,'device_target_id':None},target=target,policy=policy,
        target_url='host://fixture.test',revalidate=None)
    result = asyncio.run(adapter.execute(heartbeat=heartbeat,cancelled=lambda: True))
    assert result.status == 'cancelled'
    assert result.actual_budget['tcp_ports_attempted'] == 0


def test_revoked_authority_prevents_handshake_and_secret_loading(monkeypatch):
    from api.capabilities import ssh as adapter_module
    async def forbidden(*_args,**_kwargs):
        raise AssertionError('Revoked authority must not reach SSH or credential decryption')
    monkeypatch.setattr(ssh_scanner,'ssh_auth_methods',forbidden)
    monkeypatch.setattr(adapter_module.PostgresCredentialProfileStore,'load_for_worker',forbidden)
    @asynccontextmanager
    async def acquire():
        yield object()
    async def revoked(*_args,**_kwargs):
        raise ValueError('revoked')
    async def heartbeat():
        pass
    prepared,target,policy = prepare()
    adapter = SshExecutionAdapter(prepared=prepared,pool=SimpleNamespace(acquire=acquire),
        run={'target_id':TARGET,'device_target_id':None},target=target,policy=policy,
        target_url='host://fixture.test',revalidate=revoked)
    result = asyncio.run(adapter.execute(heartbeat=heartbeat,cancelled=lambda: False))
    assert result.status == 'failed'
    assert result.actual_budget['tcp_ports_attempted'] == 0


def test_midflight_cancellation_drains_driver_and_does_not_authenticate(monkeypatch):
    state = {'cancelled':False,'closed':False}
    async def driver(*_args,**kwargs):
        while not kwargs['cancel_check']():
            await asyncio.sleep(0.01)
        state['closed'] = True
        return {'authentication_error':'cancelled'}
    monkeypatch.setattr(ssh_scanner,'ssh_auth_methods',driver)
    @asynccontextmanager
    async def acquire():
        yield SimpleNamespace(fetchrow=fetchrow)
    async def fetchrow(*_args):
        return None
    async def revalidate(*_args,**_kwargs):
        pass
    async def heartbeat():
        state['cancelled'] = True
    prepared,target,policy = prepare()
    adapter = SshExecutionAdapter(prepared=prepared,pool=SimpleNamespace(acquire=acquire),
        run={'target_id':TARGET,'device_target_id':None},target=target,policy=policy,
        target_url='host://fixture.test',revalidate=revalidate)
    result = asyncio.run(adapter.execute(heartbeat=heartbeat,cancelled=lambda: state['cancelled']))
    assert result.status == 'cancelled' and state['closed']
    assert result.actual_budget['tcp_ports_attempted'] == 1 and not result.observations
