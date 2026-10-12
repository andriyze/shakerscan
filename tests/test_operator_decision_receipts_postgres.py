"""Real database and operator API tests; no target traffic is executed."""
import asyncio
import hashlib
import json
from uuid import UUID, uuid4

import pytest

from httpx import ASGITransport, AsyncClient

from tests.test_target_asset_startup_postgres import startup_database
from tests.test_instruction_proposals_postgres import _prepared
from tests.test_interpretations_postgres import _fixture_finding, _web_target


def entry(target, kind, **values):
    return {'receipt_id': str(uuid4()), 'target_id': str(target), 'decision': kind, **values}


async def submit_decision(client, path, item, canonical):
    if not canonical:
        return await client.post(path, json=item)
    target, kind = item['target_id'], item['decision']
    prefix = f'/targets/{target}'
    if kind == 'dismiss':
        route = f"{prefix}/findings/{item['subject_id']}/dismiss"
        body = {key: item[key] for key in ('reason', 'note')}
    elif kind == 'confirm':
        route = f'{prefix}/skill/confirm'
        body = {'expected_revision': item['expected_revision'], 'body_sha256': item['text_sha256']}
    elif kind == 'accept':
        route = f"{prefix}/instruction-proposals/{item['subject_id']}/accept"
        body = {'methodology_sha256': item['text_sha256']}
    elif kind == 'release_marker':
        route = f'{prefix}/knowledge/releases'
        body = {'label': item['release_label'], 'released_at': item.get('released_at')}
    else:
        route = f"{prefix}/hunts/{item['subject_id']}/interpretations/retract"
        body = {'note': item['note']}
    return await client.post(route, json=body, headers={'x-shakerscan-decision-id': item['receipt_id']})


@pytest.mark.parametrize("canonical", [False, True])
def test_dismissal_receipt_is_encrypted_and_reversal_is_guarded_and_idempotent(monkeypatch, canonical):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://receipts.test')
            finding = await _fixture_finding(conn, target)
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as client:
                request = entry(target, 'dismiss', subject_id=str(finding), reason='false_positive',
                                note='Human reviewed a harmless fixture')
                path = f'/targets/{target}/knowledge/decisions'
                response = await submit_decision(client, path, request, canonical)
                assert response.status_code == 200, response.text
                receipt = response.json()['decision_receipt']
                assert receipt['decision'] == 'dismiss' and 'false_positive' in receipt['diff']
                ciphertext = await conn.fetchval('SELECT snapshot FROM target_operator_decisions WHERE id=$1',
                                                UUID(receipt['id']))
                assert 'Human reviewed' not in ciphertext and 'false_positive' not in ciphertext
                assert (await submit_decision(client, path, request, canonical)).json()['decision_receipt']['id'] == receipt['id']
                assert await conn.fetchval('SELECT count(*) FROM target_operator_decisions') == 1
                assert await conn.fetchval("SELECT count(*) FROM target_interpretations WHERE finding_id=$1", finding) == 1
                revert = f"{path}/{receipt['id']}/revert"
                assert (await client.post(revert, json={'receipt_sha256': '0'*64})).status_code == 409
                response = await client.post(revert, json={'receipt_sha256': receipt['receipt_sha256']})
                assert response.status_code == 200, response.text
                assert response.json()['state'] == 'reverted'
                assert await conn.fetchval('SELECT status FROM findings WHERE id=$1', finding) == 'active'
                assert await conn.fetchval('SELECT status FROM target_interpretations WHERE finding_id=$1', finding) == 'reopened'
                assert (await client.post(revert, json={'receipt_sha256': receipt['receipt_sha256']})).status_code == 200
    asyncio.run(run())


@pytest.mark.parametrize("canonical", [False, True])
def test_confirm_reversal_returns_agent_text_to_unconfirmed_and_never_authorizes_it(monkeypatch, canonical):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://receipt-unconfirmed.test')
            from tests.test_target_skill_later_engine_records import _document, _saved, HUNT
            document = _document(2, writer=HUNT, authority='target_metadata_delegation',
                                 origin='agent_unconfirmed', text='An agent suggested this instruction')
            document['target_id'] = str(target)
            document['skill_id'] = f'skill.target.{target}'
            await conn.execute('UPDATE targets SET metadata_json=$2::jsonb WHERE id=$1', target,
                               json.dumps({'target_skill': _saved(document)}))
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as client:
                skill_path = f'/targets/{target}/skill'
                original = (await client.get(skill_path)).json()
                assert original['operator_skill'] is None
                path = f'/targets/{target}/knowledge/decisions'
                response = await submit_decision(client, path, entry(target, 'confirm',
                    expected_revision=original['revision'], text_sha256=document['body_sha256']), canonical)
                assert response.status_code == 200, response.text
                receipt = response.json()['decision_receipt']
                assert (await client.get(skill_path)).json()['operator_skill'] is not None
                response = await client.post(f"{path}/{receipt['id']}/revert", json={'receipt_sha256': receipt['receipt_sha256']})
                assert response.status_code == 200, response.text
                restored = (await client.get(skill_path)).json()
                assert restored['operator_skill'] is None and restored['trust'] == 'agent_unconfirmed'
                assert restored['unconfirmed_instructions']['written_by'] == HUNT
                assert restored['unconfirmed_instructions']['body_sha256'] == document['body_sha256']
    asyncio.run(run())


def test_later_edits_and_expiry_prevent_reversal_without_clobbering_state(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://receipt-conflict.test')
            finding = await _fixture_finding(conn, target)
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as client:
                path = f'/targets/{target}/knowledge/decisions'
                response = await client.post(path, json=entry(target, 'dismiss', subject_id=str(finding),
                    reason='accepted_risk', note='Reviewed fixture'))
                assert response.status_code == 200, response.text
                receipt = response.json()['decision_receipt']
                await conn.execute("UPDATE findings SET notes='A later operator edit',updated_at=NOW() WHERE id=$1", finding)
                revert = f"{path}/{receipt['id']}/revert"
                response = await client.post(revert, json={'receipt_sha256': receipt['receipt_sha256']})
                assert response.status_code == 409
                assert await conn.fetchval('SELECT notes FROM findings WHERE id=$1', finding) == 'A later operator edit'
                await conn.execute("UPDATE target_operator_decisions SET created_at=NOW()-INTERVAL '25 hours' WHERE id=$1", UUID(receipt['id']))
                response = await client.post(revert, json={'receipt_sha256': receipt['receipt_sha256']})
                assert response.status_code == 409 and '24-hour' in response.text
    asyncio.run(run())


@pytest.mark.parametrize("canonical", [False, True])
def test_release_marker_reversal_restores_previous_anchor_and_never_deletes_history(monkeypatch, canonical):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://receipt-release.test')
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as client:
                old = (await client.post(f'/targets/{target}/knowledge/releases', json={'label':'v1'})).json()
                bound = {'label':'v2', 'released_at':None}
                request = entry(target, 'release_marker', release_label='v2',
                    text_sha256=hashlib.sha256(json.dumps(bound,sort_keys=True,separators=(',',':')).encode()).hexdigest())
                path = f'/targets/{target}/knowledge/decisions'
                response = await submit_decision(client, path, request, canonical)
                assert response.status_code == (201 if canonical else 200),response.text
                receipt = response.json()['decision_receipt']
                response = await client.post(f"{path}/{receipt['id']}/revert", json={'receipt_sha256':receipt['receipt_sha256']})
                assert response.status_code == 200,response.text
                listed = (await client.get(f'/targets/{target}/knowledge/releases')).json()['releases']
                assert [item['id'] for item in listed] == [old['id']]
                assert await conn.fetchval('SELECT count(*) FROM target_release_markers WHERE target_id=$1',target) == 2
    asyncio.run(run())


@pytest.mark.parametrize("canonical", [False, True])
def test_instruction_reversal_preserves_operator_text_and_advances_revision(monkeypatch, canonical):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://receipt-instructions.test')
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as client:
                skill_path=f'/targets/{target}/skill'
                saved=(await client.post(skill_path,json={'methodology':'Original operator instruction','expected_revision':0})).json()
                proposed=(await client.post(f'/targets/{target}/instruction-proposals',json={
                    'title':'Update','methodology':'New operator instruction','reason':'Reviewed change','base_revision':saved['revision']})).json()
                proposal=proposed
                path=f'/targets/{target}/knowledge/decisions'
                response=await submit_decision(client, path, entry(target,'accept',subject_id=proposal['id'],text_sha256=proposal['methodology_sha256']), canonical)
                assert response.status_code==200,response.text
                receipt=response.json()['decision_receipt']
                after=(await client.get(skill_path)).json()
                assert after['operator_skill']['methodology']=='New operator instruction'
                response=await client.post(f"{path}/{receipt['id']}/revert",json={'receipt_sha256':receipt['receipt_sha256']})
                assert response.status_code==200,response.text
                restored=(await client.get(skill_path)).json()
                assert restored['operator_skill']['methodology']=='Original operator instruction'
                assert restored['revision']>after['revision']
    asyncio.run(run())


def test_instruction_permission_receipt_preserves_ssh_pins_and_other_permissions(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://receipt-permission.test')
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as client:
                path = f'/targets/{target}/hunt-authority'
                current = (await client.get(path)).json()
                values = {'expected_revision': current['revision'], 'instruction_changes': False,
                    'metadata_changes': False, 'ssh_host_keys': [{'port': 22, 'fingerprint': 'SHA256:'+'A'*43}],
                    'ssh_trust_first_contact': False, 'credential_profile_ids': [], 'collection_ids': []}
                saved = await client.put(path, json=values)
                assert saved.status_code == 200, saved.text
                values.update(expected_revision=saved.json()['revision'], instruction_changes=True)
                response = await client.put(path, json=values, headers={'x-shakerscan-decision-id': str(uuid4())})
                assert response.status_code == 200, response.text
                receipt = response.json()['decision_receipt']
                response = await client.post(f"/targets/{target}/knowledge/decisions/{receipt['id']}/revert",
                    json={'receipt_sha256': receipt['receipt_sha256']})
                assert response.status_code == 200, response.text
                restored = (await client.get(path)).json()
                assert restored['instruction_changes'] is False and restored['metadata_changes'] is False
                assert restored['ssh_host_keys'] == saved.json()['ssh_host_keys']
                assert restored['revision'] > saved.json()['revision']
    asyncio.run(run())


def test_planner_cannot_read_apply_or_reverse_operator_receipts(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://receipt-planner.test')
            identifier = uuid4()
            async def planner_app(scope, receive, send):
                scope = {**scope, 'shakerscan.planner_identity': 'planner-fixture'}
                await app_module.app(scope, receive, send)
            async with AsyncClient(transport=ASGITransport(planner_app), base_url='http://planner') as client:
                for method, path, body in (
                    ('GET', '/knowledge/decisions', None),
                    ('GET', f'/targets/{target}/knowledge/decisions/{identifier}', None),
                    ('POST', f'/targets/{target}/knowledge/decisions', entry(target, 'allow_changes', expected_revision=0)),
                    ('POST', f'/targets/{target}/knowledge/decisions/{identifier}/revert', {'receipt_sha256': 'a'*64})):
                    response = await client.request(method, path, json=body)
                    assert response.status_code == 403, response.text
            assert await conn.fetchval('SELECT count(*) FROM target_operator_decisions') == 0
    asyncio.run(run())


@pytest.mark.parametrize("canonical", [False, True])
def test_run_retraction_receipt_restores_quarantine_and_existing_entries_without_losing_history(monkeypatch, canonical):
    async def run():
        from tests.test_interpretations_postgres import _hunt
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await _web_target(conn, 'https://receipt-quarantine.test')
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as client:
                hunt = (await _hunt(client, target)).hunt
                recorded = await hunt.ok('knowledge.record', {'kind': 'note', 'title': 'Run note', 'body': 'Review me'})
                identifier = recorded['result']['interpretation']['id']
                path = f'/targets/{target}/knowledge/decisions'
                response = await submit_decision(client, path, entry(target, 'retract_hunt', subject_id=hunt.id, note='Operator found a poisoned run'), canonical)
                assert response.status_code == 200, response.text
                receipt = response.json()['decision_receipt']
                from hunt.interpretations import hunt_quarantined
                assert await hunt_quarantined(conn, hunt.id)
                response = await client.post(f"{path}/{receipt['id']}/revert", json={'receipt_sha256': receipt['receipt_sha256']})
                assert response.status_code == 200, response.text
                assert not await hunt_quarantined(conn, hunt.id)
                assert await conn.fetchval('SELECT status FROM target_interpretations WHERE id=$1', UUID(identifier)) == 'active'
                assert await conn.fetchval('SELECT count(*) FROM target_operator_decisions') == 1
    asyncio.run(run())
