"""Observed or planner-supplied SSH keys cannot authorize credential disclosure."""
import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace

from tests.test_hunt_ssh_connect import prepare, FINGERPRINT, TARGET
from api.capabilities import ssh
from scanner_tools import ssh_scanner


def test_untrusted_key_is_discovery_only_even_when_planner_supplies_fingerprint(monkeypatch):
    calls=[]
    async def read(*args): return {'ssh_host_keys':[], 'ssh_trust_first_contact':False}
    async def driver(*args,**kwargs):
        calls.append(kwargs)
        assert 'credential' not in kwargs
        return {'host_key':{'fingerprint_sha256':FINGERPRINT}}
    async def no_decrypt(*args,**kwargs): raise AssertionError('Untrusted host must not receive credentials')
    monkeypatch.setattr(ssh,'read_hunt_authority',read)
    monkeypatch.setattr(ssh_scanner,'ssh_auth_methods',driver)
    monkeypatch.setattr(ssh.PostgresCredentialProfileStore,'load_for_worker',no_decrypt)
    prepared,target,policy=prepare()
    # A matching planner hint still cannot authorize a password login.
    prepared.redacted_execution['host_key_fingerprint']=FINGERPRINT
    @asynccontextmanager
    async def acquire(): yield object()
    async def revalidate(*args,**kwargs): pass
    async def heartbeat(): pass
    adapter=ssh.SshExecutionAdapter(prepared=prepared,pool=SimpleNamespace(acquire=acquire),
        run={'target_id':TARGET,'device_target_id':None},target=target,policy=policy,
        target_url='host://fixture.test',revalidate=revalidate)
    result=asyncio.run(adapter.execute(heartbeat=heartbeat,cancelled=lambda:False))
    assert result.status == 'failed' and 'not trusted' in result.errors[0]
    assert len(calls)==1
    assert result.observations[0]['authentication_attempted'] is False


def test_planner_cannot_replace_operator_pin(monkeypatch):
    async def read(*args): return {'ssh_host_keys':[{'port':22,'fingerprint':'SHA256:'+'a'*43}], 'ssh_trust_first_contact':True}
    async def no_traffic(*args,**kwargs): raise AssertionError('Pin mismatch must fail before traffic')
    monkeypatch.setattr(ssh,'read_hunt_authority',read)
    monkeypatch.setattr(ssh_scanner,'ssh_auth_methods',no_traffic)
    prepared,target,policy=prepare()
    prepared.redacted_execution['host_key_fingerprint']=FINGERPRINT
    @asynccontextmanager
    async def acquire(): yield object()
    async def revalidate(*args,**kwargs): pass
    async def heartbeat(): pass
    adapter=ssh.SshExecutionAdapter(prepared=prepared,pool=SimpleNamespace(acquire=acquire),
        run={'target_id':TARGET,'device_target_id':None},target=target,policy=policy,
        target_url='host://fixture.test',revalidate=revalidate)
    result=asyncio.run(adapter.execute(heartbeat=heartbeat,cancelled=lambda:False))
    assert result.status=='failed' and result.actual_budget['tcp_ports_attempted']==0
