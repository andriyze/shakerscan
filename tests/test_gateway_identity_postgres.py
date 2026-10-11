"""The trusted-gateway operator identity end to end against real PostgreSQL: the actual FastAPI app
with its middleware stack, startup migrations and the proposal and Hunt-permission routes.

With SHAKERSCAN_GATEWAY_IDENTITY_KEY set, a request carrying a valid assertion records that person
as proposed_by, decided_by and recorded_by; without one (or with a forged or stale one) the routes
record their own provenance names, as an open-source engine always does.
"""
import asyncio
import importlib
import time

from httpx import ASGITransport, AsyncClient

from tests.test_instruction_proposals_postgres import _prepared
from tests.test_target_asset_startup_postgres import startup_database

KEY = 'g' * 64
CAROL = 'Carol (local:carol)'


def _signed(method, path, operator=CAROL, key=KEY, now=None):
    identity = importlib.import_module('gateway_identity')
    return {'X-ShakerScan-Operator': operator,
            'X-ShakerScan-Operator-Assertion': identity.assertion(key.encode(), method, path, operator, now=now)}


def test_the_gateway_names_the_person_on_proposals_decisions_and_permissions(monkeypatch):
    importlib.import_module('gateway_identity').forget_key()
    monkeypatch.setenv('SHAKERSCAN_GATEWAY_IDENTITY_KEY', KEY)

    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await conn.fetchval("INSERT INTO targets(url) VALUES('host://identity.test') RETURNING id")
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://gateway') as gateway:
                base = f'/targets/{target}/instruction-proposals'
                filed = await gateway.post(base, headers=_signed('POST', base), json={
                    'title': 'A', 'reason': 'r', 'methodology': 'Text A', 'base_revision': 0})
                assert filed.status_code == 201, filed.text
                assert filed.json()['proposed_by'] == f'operator:{CAROL}'
                accept = f"{base}/{filed.json()['id']}/accept"
                accepted = await gateway.post(accept, headers=_signed('POST', accept),
                                              json={'methodology_sha256': filed.json()['methodology_sha256']})
                assert accepted.status_code == 200, accepted.text
                assert accepted.json()['proposal']['decided_by'] == CAROL

                # A forged, a stale and a replayed assertion each fall back to the provenance name.
                second = await gateway.post(base, json={'title': 'B', 'reason': 'r', 'methodology': 'Text B',
                                                        'base_revision': 1})
                assert second.json()['proposed_by'] == 'operator:instruction-proposals-api'
                reject = f"{base}/{second.json()['id']}/reject"
                forged = _signed('POST', reject, key='f' * 64)
                rejected = await gateway.post(reject, headers=forged, json={})
                assert rejected.json()['proposal']['decided_by'] == 'operator:instruction-proposals-api'
                third = await gateway.post(base, json={'title': 'C', 'reason': 'r', 'methodology': 'Text C',
                                                       'base_revision': 1})
                reject = f"{base}/{third.json()['id']}/reject"
                stale = _signed('POST', reject, now=time.time() - 120)
                assert (await gateway.post(reject, headers=stale, json={})).json()['proposal']['decided_by'] \
                    == 'operator:instruction-proposals-api'

                authority = f'/targets/{target}/hunt-authority'
                current = (await gateway.get(authority)).json()
                headers = _signed('PUT', authority)
                saved = await gateway.put(authority, headers=headers, json={
                    'expected_revision': current['revision'], 'instruction_changes': True})
                assert saved.status_code == 200, saved.text
                assert saved.json()['recorded_by'] == CAROL
                replayed = await gateway.put(authority, headers=headers, json={
                    'expected_revision': saved.json()['revision'], 'instruction_changes': False})
                assert replayed.status_code == 200
                assert replayed.json()['recorded_by'] == 'operator:target-permissions-api'

    try:
        asyncio.run(run())
    finally:
        importlib.import_module('gateway_identity').forget_key()


def test_without_the_key_a_signed_request_names_nobody(monkeypatch):
    monkeypatch.delenv('SHAKERSCAN_GATEWAY_IDENTITY_KEY', raising=False)
    importlib.import_module('gateway_identity').forget_key()

    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await conn.fetchval("INSERT INTO targets(url) VALUES('host://no-key.test') RETURNING id")
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://local') as local:
                authority = f'/targets/{target}/hunt-authority'
                current = (await local.get(authority)).json()
                saved = await local.put(authority, headers=_signed('PUT', authority), json={
                    'expected_revision': current['revision'], 'instruction_changes': True})
                assert saved.status_code == 200 and saved.json()['recorded_by'] == 'operator:target-permissions-api'

    asyncio.run(run())
