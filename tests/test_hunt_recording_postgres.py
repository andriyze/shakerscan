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
                    scope_receipt_id='scope-fixture', allowed_capabilities=['findings.create', 'findings.update'])
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
                # A write past the per-Hunt byte bound is refused; the Hunt and its ledger are unchanged.
                import importlib
                findings_module = importlib.import_module('hunt.finding_actions')
                stored = await conn.fetchval(findings_module._STORED_FINDING_BYTES_SQL, hunt, None)
                bound = findings_module.MAX_FINDING_BYTES_PER_HUNT
                monkeypatch.setattr(findings_module, 'MAX_FINDING_BYTES_PER_HUNT', int(stored) + 10)
                bounded = await client.post(f'/hunts/{hunt}/capabilities/findings.create',
                    json={'idempotency_key': 'ports-create-bounded', 'input': {**values, 'title': 'Second observation'}})
                assert bounded.status_code == 422 and 'limit per Hunt' in bounded.text, bounded.text
                grown = await client.post(f'/hunts/{hunt}/capabilities/findings.update', json={
                    'idempotency_key': 'ports-update-bounded', 'input': {
                        'finding_id': saved.json()['result']['finding_id'], 'description': 'x' * 5_000,
                        'evidence_action_ids': [str(evidence)]}})
                assert grown.status_code == 422 and 'limit per Hunt' in grown.text, grown.text
                monkeypatch.setattr(findings_module, 'MAX_FINDING_BYTES_PER_HUNT', bound)
                assert await conn.fetchval('SELECT count(*) FROM findings WHERE hunt_run_id=$1', hunt) == 1
                row = await conn.fetchrow('SELECT status,budget_used_json FROM hunt_runs WHERE id=$1', hunt)
                assert row['status'] == 'budget_exhausted'
                after = json.loads(row['budget_used_json'])
                # The existing record returned unchanged spent no record unit.
                assert after['candidates'] == 1
                assert all(after[key] == value for key, value in used.items())
                # A finding created without a path is located on the service its evidence came from.
                unnamed = await client.post(f'/hunts/{hunt}/capabilities/findings.create', json={
                    'idempotency_key': 'ports-create-unnamed',
                    'input': {key: value for key, value in values.items() if key != 'path'} | {'title': 'Unnamed'}})
                assert unnamed.status_code == 200, unnamed.text
                assert await conn.fetchval("SELECT url FROM findings WHERE hunt_run_id=$1 AND title='Unnamed'",
                                           hunt) == service + path
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


async def _finished_hunt(client, conn, target, inputs):
    """Start a Hunt, record completed actions with these inputs (labelled fixtures), finish it."""
    start = await client.post('/hunts', json={'target_id': str(target), 'target_kind': 'network',
        'goal': 'Inspect fixture', 'policy': {'active_testing': False}})
    assert start.status_code in (200, 201), start.text
    hunt = UUID(start.json()['hunt_id'])
    for values in inputs:
        await conn.execute("""INSERT INTO hunt_actions(hunt_run_id,capability_name,status,input_summary,completed_at)
            VALUES($1,$2,'completed',$3::jsonb,NOW())""", hunt, values.pop('capability', 'http.request'),
            json.dumps({'input': values}))
    response = await client.post(f'/hunts/{hunt}/finish', json={'summary': 'Done', 'next_actions': []})
    assert response.status_code == 200, response.text
    return hunt, response.json()['final_debrief']['saved_action']


@pytest.mark.parametrize('delegated,metadata,expected', [(True, True, 'proposed'), (False, True, 'proposed'),
                                                         (True, False, 'skipped')])
def test_finish_only_ever_proposes_reusable_steps(monkeypatch, delegated, metadata, expected):
    """Delegated instruction changes do not let a finish save a recipe; the metadata opt-out
    stops even the proposal."""
    async def scenario():
        async with startup_database() as conn:
            app = await _prepared(conn, monkeypatch)
            from targets.hunt_authority import authority_row, save_authority
            target = await conn.fetchval("INSERT INTO targets(url) VALUES('host://saved.fixture.test') RETURNING id")
            await save_authority(conn, await authority_row(conn, target),
                {'revision': 1, 'metadata_changes': metadata, 'instruction_changes': delegated}, recorded_by='operator:fixture')
            async with AsyncClient(transport=ASGITransport(app.app), base_url='http://operator') as client:
                _hunt, result = await _finished_hunt(client, conn, target, [
                    {'method': 'GET', 'path': '/health', 'origin': 'https://saved.fixture.test:8443'}])
                assert result['status'] == expected, result
                saved = (await client.get(f'/targets/{target}/actions')).json()
                assert saved['actions'] == []
                pending = await conn.fetch("""SELECT proposed_by FROM target_instruction_proposals
                    WHERE target_id=$1 AND status='pending'""", target)
                assert [row['proposed_by'] for row in pending] == (
                    ['hunt:retained-checks'] if expected == 'proposed' else [])
    asyncio.run(scenario())


def test_finishes_share_one_rolling_proposal_outside_the_planner_quota(monkeypatch):
    async def scenario():
        async with startup_database() as conn:
            app = await _prepared(conn, monkeypatch)
            from targets.instruction_proposals import MAX_PENDING_PER_TARGET, _check_pending_quota
            target = await conn.fetchval("INSERT INTO targets(url) VALUES('host://rolling.fixture.test') RETURNING id")
            origin = 'https://rolling.fixture.test'
            async with AsyncClient(transport=ASGITransport(app.app), base_url='http://operator') as client:
                # Planner proposals fill the Hunt pending quota; the finish proposal still files.
                for index in range(MAX_PENDING_PER_TARGET):
                    body = {'name': f'n{index}', 'instructions': '', 'parameters': {}, 'steps': []}
                    await conn.execute("""INSERT INTO target_instruction_proposals(target_id,base_revision,title,
                        methodology,methodology_sha256,reason,proposed_by,kind,action_operation,action_body)
                        VALUES($1,0,'t','m',$2,'r',$3,'saved_action','create',$4::jsonb)""",
                        target, '0' * 64, f'hunt:{UUID(int=7)}', json.dumps(body))
                first, outcome = await _finished_hunt(client, conn, target, [
                    {'method': 'GET', 'path': '/health', 'origin': origin},
                    {'capability': 'web.crawl', 'origin': origin},
                    # Never proposed: masked query values, a header, another host.
                    {'method': 'GET', 'path': '/items?id=%3Credacted%3E', 'origin': origin},
                    {'method': 'GET', 'path': '/debug', 'headers': {'X-Debug-Auth': 'letmein-2026'}},
                    {'method': 'GET', 'path': '/health', 'origin': 'https://other.fixture.test'},
                ])
                assert outcome['status'] == 'proposed' and outcome['step_count'] == 2, outcome
                second, again = await _finished_hunt(client, conn, target, [
                    {'capability': 'web.crawl', 'origin': origin},
                    {'capability': 'javascript.analyze', 'path': '/static/app.js'},
                ])
                assert again['status'] == 'updated' and again['proposal_id'] == outcome['proposal_id'], again
                assert again['step_count'] == 3 and again['added_steps'] == 1
                _third, same = await _finished_hunt(client, conn, target, [
                    {'capability': 'javascript.analyze', 'path': '/static/app.js'}])
                assert same['status'] == 'unchanged' and same['proposal_id'] == outcome['proposal_id'], same
                rows = await conn.fetch("""SELECT * FROM target_instruction_proposals
                    WHERE target_id=$1 AND status='pending' AND proposed_by='hunt:retained-checks'""", target)
                assert len(rows) == 1 and rows[0]['hunt_run_id'] == second
                body = json.loads(rows[0]['action_body'])
                assert [step['capability'] for step in body['steps']] == ['http.request', 'web.crawl', 'javascript.analyze']
                text = json.dumps(body)
                assert 'redacted' not in text and 'letmein' not in text and 'other.fixture' not in text
                # A rejected step is not proposed again; a new one starts the next rolling proposal.
                rejected = await client.post(f"/targets/{target}/instruction-proposals/{outcome['proposal_id']}/reject",
                                             json={'note': 'not these'})
                assert rejected.status_code == 200, rejected.text
                _fourth, fresh = await _finished_hunt(client, conn, target, [
                    {'capability': 'web.crawl', 'origin': origin},
                    {'capability': 'web.content_discover', 'origin': origin, 'wordlist': 'api'}])
                assert fresh['status'] == 'proposed' and fresh['proposal_id'] != outcome['proposal_id'], fresh
                body = json.loads(await conn.fetchval(
                    'SELECT action_body FROM target_instruction_proposals WHERE id=$1', UUID(fresh['proposal_id'])))
                assert [step['capability'] for step in body['steps']] == ['web.content_discover']
                # The planner quota still counts only the planner's own proposals.
                with pytest.raises(Exception) as full:
                    await _check_pending_quota(conn, target, f'hunt:{first}', 'saved_action')
                assert getattr(full.value, 'status_code', None) == 429
                assert (await client.get(f'/targets/{target}/actions')).json()['actions'] == []
    asyncio.run(scenario())


def test_a_pending_retained_proposal_leaves_the_planner_its_whole_quota(monkeypatch):
    """19 planner proposals and the finish's retained one are pending: the planner's 20th still
    files, and only a 21st planner proposal is over the quota."""
    async def scenario():
        async with startup_database() as conn:
            app = await _prepared(conn, monkeypatch)
            from targets.instruction_proposals import MAX_PENDING_PER_TARGET, _check_pending_quota
            target = await conn.fetchval("INSERT INTO targets(url) VALUES('host://quota.fixture.test') RETURNING id")
            planner = f'hunt:{UUID(int=9)}'

            async def planner_proposal(index):
                body = {'name': f'n{index}', 'instructions': '', 'parameters': {}, 'steps': []}
                await conn.execute("""INSERT INTO target_instruction_proposals(target_id,base_revision,title,
                    methodology,methodology_sha256,reason,proposed_by,kind,action_operation,action_body)
                    VALUES($1,0,'t','m',$2,'r',$3,'saved_action','create',$4::jsonb)""",
                    target, '0' * 64, planner, json.dumps(body))
            async with AsyncClient(transport=ASGITransport(app.app), base_url='http://operator') as client:
                for index in range(MAX_PENDING_PER_TARGET - 1):
                    await planner_proposal(index)
                _hunt, outcome = await _finished_hunt(client, conn, target, [
                    {'method': 'GET', 'path': '/health', 'origin': 'https://quota.fixture.test'}])
                assert outcome['status'] == 'proposed', outcome
                await _check_pending_quota(conn, target, planner, 'saved_action')  # the 20th files
                await planner_proposal(MAX_PENDING_PER_TARGET - 1)
                with pytest.raises(Exception) as full:
                    await _check_pending_quota(conn, target, planner, 'saved_action')
                assert getattr(full.value, 'status_code', None) == 429
    asyncio.run(scenario())
