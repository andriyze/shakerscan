"""Full schema, API admission, finding persistence and completion; no target traffic.

Completed HTTP evidence is inserted as a labelled fixture. Only the per-call approval
validator is doubled; run status, target binding, budgets, ownership, reservations,
receipts, finding writes and saved-action/proposal writes use production code.
"""
import asyncio
import json
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from tests.test_instruction_proposals_postgres import _prepared
from tests.test_target_asset_startup_postgres import startup_database


@pytest.mark.parametrize('locator,service,path', [
    ('host://ports.fixture.test', 'http://ports.fixture.test:8081', '/admin'),
    ('https://ports.fixture.test:8443', 'https://ports.fixture.test:8443', '/admin'),
    ('https://ports.fixture.test', 'https://ports.fixture.test:8443', '/admin'),
])
def test_api_records_nondefault_service_after_execution_budget_exhaustion(monkeypatch, locator, service, path):
    async def scenario():
        async with startup_database() as conn:
            app = await _prepared(conn, monkeypatch)
            async def approval(*args, **kwargs):
                assert kwargs['target_url'] == locator
                assert kwargs['command'].startswith('findings.')
                return {'scope_receipt_id': 'scope-fixture'}
            monkeypatch.setattr(app, '_validate_approval_receipt_for_action', approval)
            target = await conn.fetchval('INSERT INTO targets(url) VALUES($1) RETURNING id', locator)
            receipt = uuid4()
            await conn.execute("INSERT INTO scope_receipts(id,target_id,verdict) VALUES('scope-fixture',$1,'allowed')", target)
            await conn.execute("""INSERT INTO approval_receipts(id,scope_receipt_id,risk_tier,approved_by)
                VALUES($1,'scope-fixture','active','operator:fixture')""", receipt)
            async with AsyncClient(transport=ASGITransport(app.app), base_url='http://operator') as client:
                start = await client.post('/hunts', json={'target_id': str(target),
                    'target_kind': 'network' if locator.startswith('host:') else 'web',
                    'goal': 'Inspect fixture services', 'policy': {'active_testing': False}})
                assert start.status_code in (200, 201), start.text
                hunt = UUID(start.json()['hunt_id'])
                row = await conn.fetchrow('SELECT policy_json,budget_json FROM hunt_runs WHERE id=$1', hunt)
                policy, budget = json.loads(row['policy_json']), json.loads(row['budget_json'])
                policy.update(active_testing=True, approval_receipt_id=str(receipt),
                    scope_receipt_id='scope-fixture', allowed_capabilities=['findings.create'])
                used = {'agent_actions': budget['max_capability_calls'],
                    'active_actions': budget['max_active_actions'], 'http_requests': budget['max_http_requests'],
                    'tool_wall_seconds': budget['max_duration_seconds']}
                await conn.execute("""UPDATE hunt_runs SET policy_json=$2::jsonb, budget_used_json=$3::jsonb,
                    status='budget_exhausted',stop_reason='budget_exhausted:agent_actions' WHERE id=$1""",
                    hunt, json.dumps(policy), json.dumps(used))
                evidence = uuid4()
                inputs = {'method': 'GET', 'origin': service, 'path': path}
                await conn.execute("""INSERT INTO hunt_actions(id,hunt_run_id,capability_name,status,input_summary,completed_at)
                    VALUES($1,$2,'http.request','completed',$3::jsonb,NOW())""", evidence, hunt,
                    json.dumps({'input': inputs}))
                await conn.execute("""INSERT INTO http_transactions(plane,hunt_run_id,hunt_action_id,method,url,status_code)
                    VALUES('hunt',$1,$2,'GET',$3,200)""", hunt, evidence, service + path)
                values = {'title': 'Fixture observation', 'description': 'Unverified fixture evidence.',
                    'severity': 'low', 'path': path, 'evidence_summary': 'A response was observed.',
                    'evidence_action_ids': [str(evidence)]}
                saved = await client.post(f'/hunts/{hunt}/capabilities/findings.create',
                    json={'idempotency_key': 'ports-create-first', 'input': values})
                assert saved.status_code == 200, saved.text
                assert saved.json()['action_result']['status'] == 'success', saved.text
                assert saved.json()['result']['proof_state'] == 'unverified'
                stored = await conn.fetchrow('SELECT url,target_id FROM findings WHERE hunt_run_id=$1', hunt)
                assert stored['url'] == service + path and stored['target_id'] == target
                duplicate = await client.post(f'/hunts/{hunt}/capabilities/findings.create',
                    json={'idempotency_key': 'ports-create-duplicate', 'input': values})
                assert duplicate.status_code == 200, duplicate.text
                assert duplicate.json()['result']['created'] is False
                assert duplicate.json()['result']['evidence_attached'] is True
                assert await conn.fetchval('SELECT count(*) FROM findings WHERE hunt_run_id=$1', hunt) == 1
                row = await conn.fetchrow('SELECT status,budget_used_json FROM hunt_runs WHERE id=$1', hunt)
                assert row['status'] == 'budget_exhausted'
                after = json.loads(row['budget_used_json'])
                # The existing record returned unchanged spent no record unit.
                assert after['candidates'] == 1
                assert all(after[key] == value for key, value in used.items())
                finished = await client.post(f'/hunts/{hunt}/finish', json={'summary': 'Done', 'next_actions': []})
                assert finished.status_code == 200, finished.text
                outcome = finished.json()['final_debrief']['saved_action']
                assert outcome['status'] == 'proposed', outcome
                proposal = await conn.fetchrow('SELECT kind,action_body FROM target_instruction_proposals WHERE id=$1', UUID(outcome['proposal_id']))
                assert proposal['kind'] == 'saved_action'
                assert json.loads(proposal['action_body'])['steps'][0]['input'] == inputs
                retry = await client.post(f'/hunts/{hunt}/finish', json={'summary': 'Done', 'next_actions': []})
                assert retry.status_code == 200 and retry.json()['already_terminal'] is True
                assert await conn.fetchval('SELECT count(*) FROM target_instruction_proposals WHERE hunt_run_id=$1', hunt) == 1
                refused = await client.post(f'/hunts/{hunt}/capabilities/findings.create',
                    json={'idempotency_key': 'ports-after-finish', 'input': values})
                assert refused.status_code == 409
    asyncio.run(scenario())


@pytest.mark.parametrize('delegated,metadata,expected', [(True, True, 'saved'), (False, True, 'proposed'), (True, False, 'skipped')])
def test_finish_retains_actions_using_current_operator_permissions(monkeypatch, delegated, metadata, expected):
    async def scenario():
        async with startup_database() as conn:
            app = await _prepared(conn, monkeypatch)
            from targets.hunt_authority import authority_row, save_authority
            target = await conn.fetchval("INSERT INTO targets(url) VALUES('host://saved.fixture.test') RETURNING id")
            await save_authority(conn, await authority_row(conn, target),
                {'revision': 1, 'metadata_changes': metadata, 'instruction_changes': delegated}, recorded_by='operator:fixture')
            async with AsyncClient(transport=ASGITransport(app.app), base_url='http://operator') as client:
                start = await client.post('/hunts', json={'target_id': str(target), 'target_kind': 'network',
                    'goal': 'Inspect fixture', 'policy': {'active_testing': False}})
                hunt = UUID(start.json()['hunt_id'])
                await conn.execute("""INSERT INTO hunt_actions(hunt_run_id,capability_name,status,input_summary,completed_at)
                    VALUES($1,'http.request','completed',$2::jsonb,NOW())""", hunt,
                    json.dumps({'input': {'method': 'GET', 'path': '/health', 'origin': 'https://saved.fixture.test:8443'}}))
                response = await client.post(f'/hunts/{hunt}/finish', json={'summary': 'Done', 'next_actions': []})
                assert response.status_code == 200, response.text
                result = response.json()['final_debrief']['saved_action']
                assert result['status'] == expected, result
                saved = (await client.get(f'/targets/{target}/actions')).json()
                assert len(saved['actions']) == (1 if expected == 'saved' else 0)
                if expected == 'saved':
                    assert saved['actions'][0]['trust'] == 'operator_delegated'
    asyncio.run(scenario())
