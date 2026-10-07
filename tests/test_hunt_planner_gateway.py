"""Exercise the actual ASGI boundary, not assertions about prompt wording."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import time
from uuid import uuid4

import httpx
import pytest

from api.hunt.planner_gateway import HuntPlannerGateway, route_allowed
from api.hunt.planner_lease import PlannerLease, load_lease, write_lease

HUNT = str(uuid4())
TOKEN = 'a' * 43


def record(**changes):
    now = int(time.time())
    return {'schema_version': 'hunt-planner-lease/v1', 'enabled': True,
            'hunt_id': HUNT, 'planner_id': str(uuid4()),
            'token_sha256': hashlib.sha256(TOKEN.encode()).hexdigest(),
            'issued_at': now, 'expires_at': now + 3600, **changes}


def save(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


class Backend:
    def __init__(self):
        self.requests = []

    async def __call__(self, scope, receive, send):
        body = await receive()
        self.requests.append((scope, body))
        await send({'type': 'http.response.start', 'status': 200, 'headers': [(b'content-type', b'application/json')]})
        await send({'type': 'http.response.body', 'body': b'{"status":"success"}'})


@pytest.mark.parametrize('method,path', [
    ('PUT', f'/targets/{uuid4()}/hunt-authority'),
    ('POST', f'/targets/{uuid4()}/authorization'),
    ('PUT', f'/targets/{uuid4()}/skill'),
    ('POST', f'/credential-profiles/{uuid4()}/grants'),
    ('POST', '/hunts'), ('GET', '/hunts'), ('GET', '/scans'),
    ('POST', f'/hunts/{uuid4()}/capabilities/http.request'),
    ('POST', f'/hunts/{HUNT}/budget-amendments'),
    ('POST', f'/hunts/{HUNT}/shell-plans/{uuid4()}/confirm'),
    ('POST', f'/hunts/{HUNT}/authorization-investigations/{uuid4()}/approve'),
    ('GET', f'/hunts/{HUNT}/http-transactions/export'),
    ('POST', f'/hunts/{HUNT}/future-operator-action'),
])
def test_operator_and_other_run_routes_never_reach_backend(tmp_path, method, path):
    grant = tmp_path / 'lease.json'; save(grant, record())
    backend = Backend()
    async def run():
        app = HuntPlannerGateway(backend, grant)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='https://gateway') as client:
            response = await client.request(method, path,
                headers={'Authorization': f'Bearer {TOKEN}', 'X-Operator-Identity': 'operator:admin'},
                json={'operator_confirmed': True, 'metadata_changes': True})
            assert response.status_code == 403
            assert not backend.requests
    asyncio.run(run())


@pytest.mark.parametrize('capability', ['targets.create', 'targets.update', 'targets.skill.create',
    'targets.skill.update', 'targets.skill.delete', 'http.request', 'ssh.connect',
    'collections.replay_active', 'authz.verify', 'credentials.grant'])
def test_existing_capabilities_reach_canonical_runtime_without_new_confirmation(tmp_path, capability):
    grant = tmp_path / 'lease.json'; value = record(); save(grant, value)
    backend = Backend()
    async def run():
        app = HuntPlannerGateway(backend, grant)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='https://gateway') as client:
            body = {'idempotency_key': 'intent-1', 'input': {'origin': 'http://fixture.test:8443'}}
            response = await client.post(f'/hunts/{HUNT}/capabilities/{capability}', json=body,
                headers={'Authorization': f'Bearer {TOKEN}', 'Cookie': 'operator=secret',
                         'X-Shakerscan-Operator': 'admin'})
            assert response.status_code == 200
        scope, message = backend.requests[0]
        assert scope['shakerscan.planner_identity'] == value['planner_id']
        assert scope['shakerscan.planner_hunt_id'] == HUNT
        assert 'shakerscan.operator_identity' not in scope
        assert not any(name.lower() in {b'authorization', b'cookie', b'x-shakerscan-operator'} for name, _ in scope['headers'])
        assert json.loads(message['body']) == body
    asyncio.run(run())


def test_dropping_or_forging_credentials_does_not_fall_back_to_operator(tmp_path):
    grant = tmp_path / 'lease.json'; save(grant, record())
    backend = Backend()
    async def run():
        app = HuntPlannerGateway(backend, grant)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='https://gateway') as client:
            for headers in ({}, {'Authorization':'Bearer '+'b'*43},
                            [('Authorization', f'Bearer {TOKEN}'), ('Authorization', f'Bearer {TOKEN}')]):
                assert (await client.get(f'/hunts/{HUNT}', headers=headers)).status_code == 401
        assert not backend.requests
    asyncio.run(run())


def test_revocation_and_expiry_are_checked_on_every_request(tmp_path):
    grant = tmp_path / 'lease.json'; initial = record(); save(grant, initial)
    backend = Backend()
    async def run():
        app = HuntPlannerGateway(backend, grant)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='https://gateway',
                                     headers={'Authorization':f'Bearer {TOKEN}'}) as client:
            assert (await client.get(f'/hunts/{HUNT}')).status_code == 200
            for value in ({**initial, 'enabled':False}, {**initial, 'issued_at':0, 'expires_at':1}, {}):
                save(grant, value)
                assert (await client.post(f'/hunts/{HUNT}/query', json={})).status_code == 401
            grant.unlink()
            assert (await client.get(f'/hunts/{HUNT}')).status_code == 401
        assert len(backend.requests) == 1
    asyncio.run(run())


def test_revocation_during_body_upload_prevents_dispatch(tmp_path):
    grant = tmp_path / 'lease.json'; initial = record(); save(grant, initial)
    backend = Backend()
    async def body():
        yield b'{'
        save(grant, {**initial, 'enabled':False})
        yield b'}'
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(HuntPlannerGateway(backend, grant)),
                                     base_url='https://gateway', headers={'Authorization':f'Bearer {TOKEN}'}) as client:
            assert (await client.post(f'/hunts/{HUNT}/query', content=body())).status_code == 401
        assert not backend.requests
    asyncio.run(run())


def test_encoding_body_limits_and_remote_plaintext_are_rejected(tmp_path):
    grant = tmp_path / 'lease.json'; save(grant, record())
    backend = Backend()
    async def run():
        app = HuntPlannerGateway(backend, grant)
        transport = httpx.ASGITransport(app, client=('192.0.2.1', 1234))
        async with httpx.AsyncClient(transport=transport, base_url='https://gateway',
                                     headers={'Authorization':f'Bearer {TOKEN}'}) as client:
            assert (await client.get(f'/hunts/{HUNT}/%72ecord')).status_code == 403
            assert (await client.post(f'/hunts/{HUNT}/query', content=b'x'*(1024*1024+1))).status_code == 413
            assert (await client.get(f'http://gateway/hunts/{HUNT}')).status_code == 403
        assert not backend.requests
    asyncio.run(run())


@pytest.mark.parametrize('changes', [{'enabled':False}, {'expires_at':0}, {'issued_at':True},
    {'expires_at':int(time.time())+100000}, {'token_sha256':'not-a-hash'}, {'unexpected':'field'}])
def test_invalid_lease_fails_closed(changes):
    with pytest.raises((ValueError, TypeError)):
        PlannerLease.parse(record(**changes), now=time.time())


def test_lease_creation_uses_distinct_owner_only_files_without_overwrite(tmp_path, capsys):
    grant, token = tmp_path/'grant.json', tmp_path/'token'
    write_lease(HUNT, grant, token)
    assert load_lease(grant).accepts(token.read_text().strip())
    assert grant.stat().st_mode & 0o777 == token.stat().st_mode & 0o777 == 0o600
    assert token.read_text().strip() not in grant.read_text()
    original = grant.read_bytes()
    with pytest.raises(FileExistsError):
        write_lease(HUNT, grant, token)
    assert grant.read_bytes() == original
    new_token = tmp_path/'another-token'
    with pytest.raises(FileExistsError):
        write_lease(HUNT, grant, new_token)
    assert not new_token.exists()
    assert capsys.readouterr().out == ''


def test_world_readable_or_symlink_grants_are_rejected(tmp_path):
    grant = tmp_path/'grant.json'; save(grant, record())
    grant.chmod(0o644)
    with pytest.raises(ValueError): load_lease(grant)
    grant.chmod(0o600)
    link = tmp_path/'link'; link.symlink_to(grant)
    if hasattr(os, 'O_NOFOLLOW'):
        with pytest.raises(OSError): load_lease(link)


DRAFT = 'a' * 64


@pytest.mark.parametrize('method,suffix', [
    ('GET', '/coverage-angles'), ('POST', '/coverage-angles'), ('GET', '/checkpoint'),
    ('POST', '/boundary-discovery'), ('POST', f'/boundary-discovery/{DRAFT}/prepare'),
])
def test_coverage_and_boundary_discovery_routes_reach_only_the_leased_hunt(tmp_path, method, suffix):
    grant = tmp_path / 'lease.json'; save(grant, record())
    backend = Backend()
    async def run():
        app = HuntPlannerGateway(backend, grant)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='https://gateway',
                                     headers={'Authorization': f'Bearer {TOKEN}'}) as client:
            assert (await client.request(method, f'/hunts/{HUNT}{suffix}', json={})).status_code == 200
            other = await client.request(method, f'/hunts/{uuid4()}{suffix}', json={})
            assert other.status_code == 403
        assert [scope['path'] for scope, _ in backend.requests] == [f'/hunts/{HUNT}{suffix}']
    asyncio.run(run())


@pytest.mark.parametrize('method,path', [
    ('POST', f'/hunts/{HUNT}/boundary-discovery/{DRAFT.upper()}/prepare'),
    ('POST', f'/hunts/{HUNT}/boundary-discovery/{DRAFT}/prepare/extra'),
    ('POST', f'/hunts/{HUNT}/boundary-discovery/not-a-draft/prepare'),
    ('POST', f'/ai/targets/{uuid4()}/boundary/verify'),
    ('POST', f'/ai/targets/{uuid4()}/boundary/hypotheses/compile'),
    ('DELETE', f'/hunts/{HUNT}/coverage-angles'),
])
def test_operator_boundary_verification_and_malformed_discovery_routes_stay_closed(method, path):
    assert not route_allowed(method, path, HUNT)


# Steps the Hunt skill assigns to the operator, never to a leased planner.
OPERATOR_ONLY_SKILL_ROUTES = {
    ('POST', '/hunts'),
    ('POST', '/hunts/{hunt_id}/budget-amendments'),
    ('POST', '/hunts/{hunt_id}/shell-plans/{plan_id}/confirm'),
}


def test_every_hunt_route_the_skill_tells_the_planner_to_call_is_delegated():
    import re
    skill = (Path(__file__).resolve().parents[1] / 'skills/hunt/SKILL.md').read_text()
    named = set(re.findall(r'\b(GET|POST|PATCH|DELETE|PUT) (/hunts[A-Za-z0-9_{}/.:-]*)', skill))
    assert ('POST', '/hunts/{hunt_id}/coverage-angles') in named
    assert not re.search(r'\b(?:GET|POST|PUT|PATCH|DELETE) /ai/targets', skill)
    samples = {'{hunt_id}': HUNT, '{candidate_id}': str(uuid4()), '{draft_id}': DRAFT,
               '{skill_id}': 'web-authz', '{capability_name}': 'http.request', '{plan_id}': str(uuid4())}
    for method, template in sorted(named - OPERATOR_ONLY_SKILL_ROUTES):
        path = template
        for placeholder, value in samples.items():
            path = path.replace(placeholder, value)
        assert '{' not in path, template
        assert route_allowed(method, path, HUNT), f'{method} {template}'
    for method, template in OPERATOR_ONLY_SKILL_ROUTES & named:
        path = template.replace('{hunt_id}', HUNT).replace('{plan_id}', str(uuid4()))
        assert not route_allowed(method, path, HUNT)
