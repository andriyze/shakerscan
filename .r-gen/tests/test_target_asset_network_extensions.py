"""Coverage settings do not change authority; shared environments stay immutable at dispatch."""
import asyncio
from dataclasses import dataclass
import hashlib
import json
import uuid

import pytest
from fastapi import HTTPException

from scanner.scanner_tools.device_scan_scope import normalize_udp_ports, with_udp_scope
from devices import collection_environments as environments
from devices import network_authorization as authority


@dataclass(frozen=True)
class Profile:
    name: str
    udp_ports: tuple[int, ...]
    safety: str = 'safe_remote'


def test_explicit_udp_scope_replaces_only_the_requested_ports():
    original = Profile('inventory',(53,1900))
    custom = with_udp_scope(original,[161,5683,161])
    assert custom.udp_ports == (161,5683)
    assert custom.name == original.name and custom.safety == original.safety
    assert original.udp_ports == (53,1900)
    assert with_udp_scope(original,None) is original
    assert with_udp_scope(original,[]).udp_ports == ()


@pytest.mark.parametrize('ports', [[0],[65536],[True],['161'],[1.5],list(range(1,1026)), '161,1900'])
def test_invalid_udp_scope_rejected_before_execution(ports):
    with pytest.raises(ValueError): normalize_udp_ports(ports)


class EnvironmentConnection:
    def __init__(self, collection, environment, payload):
        self.collection,self.environment,self.payload=collection,environment,payload
        self.active=True
        self.digest=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    async def fetchrow(self, _sql, environment, collection):
        if not self.active or environment != self.environment or collection != self.collection: return None
        return {'id':environment,'payload_sha256':self.digest,'encrypted_payload':json.dumps(self.payload)}


def test_shared_environment_is_frozen_and_revalidated_without_copying_document(monkeypatch):
    monkeypatch.setattr(environments,'decrypt_secret',lambda value:value)
    async def run():
        collection,environment=uuid.uuid4(),uuid.uuid4()
        conn=EnvironmentConnection(collection,environment,{'values':[{'key':'token','value':'fixture','enabled':True}]})
        refs=await environments.bind_environments(conn,[{'collection_id':str(collection),'document_sha256':'doc-digest'}],{str(collection):str(environment)})
        assert 'fixture' not in json.dumps(refs)
        document={'item':[]}
        hydrated=await environments.hydrate_environment(conn,refs[0],document)
        assert hydrated['environment']==conn.payload and document=={'item':[]}
        conn.digest='rotated'
        with pytest.raises(ValueError,match='changed'):
            await environments.hydrate_environment(conn,refs[0],document)
        conn.active=False
        with pytest.raises(ValueError): await environments.hydrate_environment(conn,refs[0],document)
    asyncio.run(run())


def test_environment_cannot_be_selected_for_another_or_unselected_collection(monkeypatch):
    monkeypatch.setattr(environments,'decrypt_secret',lambda value:value)
    async def run():
        collection,environment,other=uuid.uuid4(),uuid.uuid4(),uuid.uuid4()
        conn=EnvironmentConnection(collection,environment,{})
        with pytest.raises(HTTPException):
            await environments.bind_environments(conn,[{'collection_id':str(collection)}],{str(other):str(environment)})
        with pytest.raises(HTTPException):
            await environments.bind_environments(conn,[{'collection_id':str(other)}],{str(other):str(environment)})
        legacy={'environment':{'values':[]}}
        assert await environments.hydrate_environment(conn,{'collection_id':str(collection)},legacy) is legacy
    asyncio.run(run())


def test_queued_network_authority_is_rechecked_before_dispatch(monkeypatch):
    current={'standing':True,'approval_receipt_id':str(uuid.uuid4()),'approved_by':'fixture'}
    async def read(_conn,_target): return dict(current) if current else None
    monkeypatch.setattr(authority,'current_target_authorization',read)
    async def run():
        owner=str(uuid.uuid4())
        snapshot=await authority.network_authorization_snapshot(None,owner)
        options={'asset_authorization_receipt_id':snapshot['approval_receipt_id']}
        await authority.revalidate_network_authorization(None,owner,options)
        current.clear()
        with pytest.raises(ValueError,match='revoked'):
            await authority.revalidate_network_authorization(None,owner,options)
        await authority.revalidate_network_authorization(None,owner,{'confirm_authorized':True})
    asyncio.run(run())
