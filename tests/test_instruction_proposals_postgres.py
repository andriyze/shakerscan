"""Instruction permission split, proposals and the startup briefing against real PostgreSQL.

The actual FastAPI app, startup migrations, Hunt admission, capability route and operator routes;
only DNS is a controlled fixture.
"""
import asyncio
import importlib
import json
import sys
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from targets.asset_migration import BoundConnectionPool
from targets.hunt_authority import authority_row, save_authority
from targets.instruction_proposals import INSTRUCTION_PROPOSAL_SCHEMA_SQL, MAX_PENDING_PER_TARGET, MAX_PROPOSALS_PER_HUNT
from tests.test_target_asset_startup_postgres import startup_database

ROOT = Path(__file__).resolve().parents[1]
# Saved and proposed texts are stored trimmed.
BASELINE = '## Scope\nInspect port 443.\n## Avoid\nNever reboot the device.'
PROPOSED = '## Scope\nInspect port 443 and the admin API on 8443.\n## Avoid\nNever reboot the device.'


def _app():
    module = importlib.import_module('api')
    return module if hasattr(module, '_start_hunt_v2') else importlib.import_module('api.api')


async def _prepared(conn, monkeypatch):
    app_module = _app()
    migrations = importlib.import_module('retest_contract')
    pool = BoundConnectionPool(conn)
    await migrations.run_schema_migrations(pool)
    monkeypatch.setattr(app_module, 'db_pool', pool)
    async def addresses(*args, **kwargs): return ['192.0.2.10']
    monkeypatch.setattr(app_module, '_resolve_agent_target_addresses', addresses)
    return app_module


def _contract(target):
    return {'target_id': str(target), 'target_kind': 'network', 'goal': 'Review the admin surface',
            'policy': {'active_testing': False}, 'budgets': {'max_active_actions': 0}}


class Hunt:
    def __init__(self, client, hunt_id):
        self.client, self.id = client, hunt_id
        self.calls = 0

    async def call(self, name, values):
        self.calls += 1
        return await self.client.post(f'/hunts/{self.id}/capabilities/{name}',
                                      json={'idempotency_key': f'proposal-test-{self.calls:03d}', 'input': values})

    async def ok(self, name, values):
        response = await self.call(name, values)
        assert response.status_code == 200, response.text
        assert response.json()['action_result']['status'] == 'success', response.text
        return response.json()


def test_existing_delegation_proposes_instead_and_operators_review_with_revision_checks(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await conn.fetchval("INSERT INTO targets(url) VALUES('host://proposals.test') RETURNING id")
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                skill_path = f'/targets/{target}/skill'
                assert (await operator.post(skill_path, json={'methodology': BASELINE, 'expected_revision': 0})).status_code == 201
                # An operator's choice saved before the split: metadata on, no instruction setting at all.
                await save_authority(conn, await authority_row(conn, target),
                                     {'revision': 1, 'metadata_changes': True}, recorded_by='operator:fixture')
                started = await operator.post('/hunts', json=_contract(target))
                assert started.status_code in {200, 201}, started.text
                briefing = started.json()['briefing']
                assert briefing['instructions']['mode'] == 'full' and briefing['instructions']['text'] == BASELINE
                assert briefing['authority']['target_delegation']['metadata_changes'] is True
                assert briefing['authority']['target_delegation']['instruction_changes'] is False
                assert briefing['proposals']['pending'] == 0 and briefing['live']['included'] is True
                assert 'count' in briefing['knowledge']['counts']['endpoints']
                assert briefing['unresolved']['in_progress_actions'] == 0
                hunt = Hunt(operator, started.json()['hunt_id'])

                # 1. The saved metadata delegation no longer lets the Hunt write instructions.
                refused = await hunt.call('targets.skill.update', {'methodology': PROPOSED, 'expected_revision': 1})
                assert refused.status_code == 403, refused.text
                assert refused.json()['detail']['reason_code'] == 'instruction_changes_not_delegated'
                assert refused.json()['detail']['propose_with'] == 'targets.skill.propose'
                assert (await operator.get(skill_path)).json()['skill']['methodology'] == BASELINE

                # 2. Advisory knowledge still works under metadata delegation.
                learned = await hunt.ok('targets.skill.create', {'methodology': 'Port 8443 answers with a login page.',
                                                                  'purpose': 'knowledge', 'expected_revision': 1})
                evidence = learned['action_id']
                current = (await operator.get(skill_path)).json()
                assert current['revision'] == 2 and current['operator_skill']['methodology'] == BASELINE

                # 3. A proposal must be based on the revision the Hunt read and cite real records.
                proposal = {'title': 'Cover the admin API', 'methodology': PROPOSED,
                            'reason': 'The admin API on 8443 is reachable.', 'base_revision': 1}
                stale_base = await hunt.call('targets.skill.propose', proposal)
                assert stale_base.status_code == 409 and stale_base.json()['detail']['error'] == 'proposal_base_changed'
                unknown = await hunt.call('targets.skill.propose', {**proposal, 'base_revision': 2,
                                                                     'evidence_refs': ['00000000-0000-4000-8000-000000000001']})
                assert unknown.status_code == 422 and unknown.json()['detail']['error'] == 'unknown_evidence_refs'
                filed = await hunt.ok('targets.skill.propose', {**proposal, 'base_revision': 2, 'evidence_refs': [evidence]})
                assert filed['result']['applied'] is False and filed['result']['proposal']['status'] == 'pending'
                first_id = filed['result']['proposal']['id']
                assert 'methodology' not in filed['result']['proposal']
                recorded = await conn.fetchval('SELECT input_summary FROM hunt_actions WHERE id=$1', UUID(filed['action_id']))
                assert PROPOSED not in json.dumps(recorded)  # the action ledger keeps a digest, not the text
                assert (await operator.get(skill_path)).json()['operator_skill']['methodology'] == BASELINE

                # 4. Pending text never reaches a Hunt's instructions, briefing or context.
                read = await operator.get(f'/hunts/{hunt.id}')
                assert read.json()['briefing']['proposals']['pending'] == 1
                assert 'admin API on 8443' not in json.dumps(read.json())
                summary = await operator.post(f'/hunts/{hunt.id}/query', json={'kind': 'summary'})
                assert summary.status_code == 200 and summary.json()['briefing']['proposals']['pending'] == 1
                assert 'admin API on 8443' not in json.dumps(summary.json())
                later = await operator.post('/hunts', json=_contract(target))
                assert later.json()['briefing']['instructions']['text'] == BASELINE
                assert 'admin API on 8443' not in json.dumps(later.json())

                # 5. Operators list proposals with a diff; a direct edit makes this one stale.
                listed = (await operator.get('/instruction-proposals')).json()['proposals']
                assert [item['id'] for item in listed] == [first_id]
                assert listed[0]['stale'] is False and '+Inspect port 443 and the admin API' in listed[0]['diff']['text']
                assert listed[0]['evidence_refs'] == [evidence] and listed[0]['proposed_by'] == f'hunt:{hunt.id}'
                edited = BASELINE + '\n## Credentials\nUse the viewer profile.'
                assert (await operator.put(skill_path, json={'methodology': edited, 'expected_revision': 2})).status_code == 200
                base = f'/targets/{target}/instruction-proposals'
                stale = await operator.post(f'{base}/{first_id}/accept', json={})
                assert stale.status_code == 409 and stale.json()['detail']['error'] == 'proposal_stale'
                assert (await operator.get(skill_path)).json()['operator_skill']['methodology'] == edited
                assert (await operator.get(base)).json()['proposals'][0]['stale'] is True

                # 6. Rebase files the same text against the current revision; accepting it applies it.
                rebased = await operator.post(f'{base}/{first_id}/rebase')
                assert rebased.status_code == 200, rebased.text
                second_id = rebased.json()['proposal']['id']
                assert rebased.json()['proposal']['stale'] is False and rebased.json()['proposal']['base_revision'] == 3
                assert '-## Credentials' in rebased.json()['proposal']['diff']['text']
                old = (await operator.get(base, params={'status': 'superseded'})).json()['proposals']
                assert [item['id'] for item in old] == [first_id]
                accepted = await operator.post(f'{base}/{second_id}/accept', json={'note': 'reviewed'})
                assert accepted.status_code == 200, accepted.text
                applied = (await operator.get(skill_path)).json()
                assert applied['operator_skill']['methodology'] == PROPOSED
                assert applied['operator_skill']['written_by'] == 'operator:instruction-proposal'
                assert applied['trust'] == 'operator' and applied['revision'] == 4
                assert accepted.json()['proposal']['applied_revision'] == 4
                again = await operator.post(f'{base}/{second_id}/accept', json={})
                assert again.status_code == 409 and again.json()['detail']['error'] == 'proposal_not_pending'

                # 7. Advisory knowledge writes share the revision counter but do not make a proposal stale.
                third = await hunt.ok('targets.skill.propose', {**proposal, 'methodology': PROPOSED + '\nPrefer GET.',
                                                                'base_revision': 4})
                await hunt.ok('targets.skill.update', {'methodology': 'Login page is at /admin.', 'purpose': 'knowledge',
                                                       'expected_revision': 4})
                ok = await operator.post(f"{base}/{third['result']['proposal']['id']}/accept", json={})
                assert ok.status_code == 200, ok.text
                assert (await operator.get(skill_path)).json()['operator_skill']['methodology'].endswith('Prefer GET.')

                # 8. Rejecting changes nothing; a Hunt files a bounded number of proposals.
                current = (await operator.get(skill_path)).json()['revision']
                fourth = await hunt.ok('targets.skill.propose', {**proposal, 'base_revision': current})
                rejected = await operator.post(f"{base}/{fourth['result']['proposal']['id']}/reject", json={'note': 'no'})
                assert rejected.status_code == 200 and rejected.json()['proposal']['status'] == 'rejected'
                assert (await operator.get(skill_path)).json()['revision'] == current
                filed_so_far = await conn.fetchval('SELECT count(*) FROM target_instruction_proposals WHERE hunt_run_id=$1 '
                                                   'AND rebased_from IS NULL', UUID(hunt.id))
                for index in range(MAX_PROPOSALS_PER_HUNT - filed_so_far):
                    await hunt.ok('targets.skill.propose', {**proposal, 'methodology': f'{PROPOSED}\nNote {index}.',
                                                            'base_revision': current})
                limited = await hunt.call('targets.skill.propose', {**proposal, 'methodology': PROPOSED + '\nMore.',
                                                                    'base_revision': current})
                assert limited.status_code == 429 and limited.json()['detail']['error'] == 'proposal_limit'
                # Each newer proposal superseded the Hunt's earlier pending one.
                assert len((await operator.get(base)).json()['proposals']) == 1

                # 9. An operator opt-in, through the authenticated operator route, permits direct edits.
                authority = (await operator.get(f'/targets/{target}/hunt-authority')).json()
                assert authority['metadata_changes'] is True and authority['instruction_changes'] is False
                opted = await operator.put(f'/targets/{target}/hunt-authority', json={
                    'expected_revision': authority['revision'], 'metadata_changes': True, 'instruction_changes': True})
                assert opted.status_code == 200 and opted.json()['instruction_changes'] is True
                direct = await hunt.ok('targets.skill.update', {'methodology': 'Directly edited.', 'expected_revision': current})
                assert direct['result']['operator_skill']['instruction_authority'] == 'target_instruction_delegation'
                after = await operator.get(f'/hunts/{hunt.id}')
                assert after.json()['briefing']['authority']['target_delegation'] == {
                    'metadata_changes': True, 'instruction_changes': True, 'shared_credential_profiles': 0,
                    'shared_collections': 0, 'as_of': 'now'}
    asyncio.run(run())


def test_large_instructions_reach_the_agent_through_the_compact_mcp_view(monkeypatch):
    sys.path.insert(0, str(ROOT / 'scripts'))
    import shakerscan_mcp

    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await conn.fetchval("INSERT INTO targets(url) VALUES('host://large.test') RETURNING id")
            sections = ''.join(f'## Área {index}\nNunca reinicie el dispositivo {index}. ' + 'ñ' * 300 + '\n'
                               for index in range(30))
            assert len(sections) < 12_000
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                assert (await operator.post(f'/targets/{target}/skill',
                                            json={'methodology': sections, 'expected_revision': 0})).status_code == 201
                started = await operator.post('/hunts', json=_contract(target))
                assert started.status_code in {200, 201}, started.text
                read = await operator.get(f"/hunts/{started.json()['hunt_id']}")
            for record in (started.json(), read.json()):
                compact = shakerscan_mcp._compact_hunt(record)
                assert 'context_pack' in compact['mcp_view']['omitted']
                assert 'briefing' not in compact['mcp_view']['omitted']
                instructions = compact['briefing']['instructions']
                assert instructions['mode'] == 'outline' and instructions['more_available'] is True
                assert instructions['headings'][:2] == ['## Área 0', '## Área 1'] and len(instructions['headings']) == 30
                assert instructions['leading_text'].startswith('## Área 0')
                assert 'context_pack.target_skill.skill.methodology' in instructions['read_rest']
                assert len(json.dumps(compact['briefing'])) <= shakerscan_mcp.COMPACT_BRIEFING_BYTES
                assert compact['briefing']['objective']['text'] == 'Review the admin surface'
            # The full text is still exactly where the briefing says.
            assert read.json()['context_pack']['target_skill']['skill']['methodology'] == sections.strip()
    asyncio.run(run())


def test_device_hunt_briefing_counts_read_the_device_asset(monkeypatch):
    async def run():
        async with startup_database() as conn:
            device = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('TV','tv.briefing.test') RETURNING id")
            app_module = await _prepared(conn, monkeypatch)
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                started = await operator.post('/hunts', json={**_contract(device), 'target_kind': 'device'})
                assert started.status_code in {200, 201}, started.text
                briefing = started.json()['briefing']
            for section in ('knowledge', 'proposals', 'unresolved'):
                assert briefing[section].get('available') is not False, (section, briefing[section])
            assert set(briefing['knowledge']['counts']) == {'scans', 'findings', 'collections', 'candidates', 'services'}
            assert briefing['instructions']['present'] is False
    asyncio.run(run())


def test_startup_installs_the_proposal_table_idempotently_with_the_init_sql_definition(monkeypatch):
    async def run():
        async with startup_database() as conn:
            await _prepared(conn, monkeypatch)
            await importlib.import_module('retest_contract').run_schema_migrations(BoundConnectionPool(conn))
            columns = {row['column_name'] for row in await conn.fetch(
                "SELECT column_name FROM information_schema.columns WHERE table_name='target_instruction_proposals'")}
            assert {'base_revision', 'base_sha256', 'methodology', 'reason', 'evidence_refs', 'proposed_by',
                    'hunt_run_id', 'status', 'rebased_from', 'applied_revision'} <= columns
            target = await conn.fetchval("INSERT INTO targets(url) VALUES('host://checks.test') RETURNING id")
            for bad in ({'status': 'applied'}, {'proposed_by': 'planner:x'}, {'methodology': ''}):
                values = {'status': 'pending', 'proposed_by': 'hunt:x', 'methodology': 'text', **bad}
                with pytest.raises(Exception, match='check constraint'):
                    await conn.execute("""INSERT INTO target_instruction_proposals(target_id,base_revision,title,
                        methodology,methodology_sha256,reason,proposed_by,status)
                        VALUES($1,0,'t',$2,$3,'r',$4,$5)""", target, values['methodology'], '0' * 64,
                        values['proposed_by'], values['status'])
    asyncio.run(run())
    assert INSTRUCTION_PROPOSAL_SCHEMA_SQL.strip() in (ROOT / 'db/init.sql').read_text()


def test_review_bindings_quotas_and_trust_labels(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await conn.fetchval("INSERT INTO targets(url) VALUES('host://bindings.test') RETURNING id")
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                base = f'/targets/{target}/instruction-proposals'
                # Terminal control sequences can never be stored in a proposal.
                for field in ('title', 'reason', 'methodology'):
                    body = {'title': 't', 'reason': 'r', 'methodology': 'm', 'base_revision': 0, field: 'x\x1b[2Ky'}
                    assert (await operator.post(base, json=body)).status_code == 422
                # Operator proposals share one provenance here, so they never supersede one another.
                first = await operator.post(base, json={'title': 'A', 'reason': 'r', 'methodology': 'Text A', 'base_revision': 0})
                second = await operator.post(base, json={'title': 'B', 'reason': 'r', 'methodology': 'Text B', 'base_revision': 0})
                assert first.status_code == second.status_code == 201, (first.text, second.text)
                assert len((await operator.get(base)).json()['proposals']) == 2
                # Accept binds to the reviewed text.
                mismatch = await operator.post(f"{base}/{first.json()['id']}/accept", json={'methodology_sha256': '0' * 64})
                assert mismatch.status_code == 409 and mismatch.json()['detail']['error'] == 'proposal_text_mismatch'
                reviewed = await operator.post(f"{base}/{first.json()['id']}/accept",
                                               json={'methodology_sha256': first.json()['methodology_sha256']})
                assert reviewed.status_code == 200, reviewed.text
                # Hunts have their own pending quota: they cannot fill the operators' queue.
                for _ in range(MAX_PENDING_PER_TARGET):
                    await conn.execute("""INSERT INTO target_instruction_proposals(target_id,base_revision,title,methodology,
                        methodology_sha256,reason,proposed_by) VALUES($1,1,'t','m',$2,'r',$3)""",
                        target, '0' * 64, f'hunt:{uuid4()}')
                assert (await operator.post(base, json={'title': 'C', 'reason': 'r', 'methodology': 'Text C',
                                                        'base_revision': 1})).status_code == 201
                # Instructions a Hunt wrote are labelled as not operator-reviewed in the briefing.
                await save_authority(conn, await authority_row(conn, target),
                                     {'revision': 1, 'instruction_changes': True}, recorded_by='operator:fixture')
                started = await operator.post('/hunts', json=_contract(target))
                hunt = Hunt(operator, started.json()['hunt_id'])
                await hunt.ok('targets.skill.update', {'methodology': 'Hunt-written guidance.', 'expected_revision': 1})
                await hunt.ok('targets.actions.create', {'name': 'Probe', 'instructions': 'Hunt notes.', 'expected_revision': 0,
                                                         'steps': [{'capability': 'targets.skill.read', 'input': {}}]})
                later = (await operator.post('/hunts', json=_contract(target))).json()
                instructions = later['briefing']['instructions']
                assert instructions['operator_reviewed'] is False and instructions['trust'] == 'operator_delegated'
                assert 'no operator reviewed' in instructions['role']
                actions = later['context_pack']['target_actions']
                assert actions['actions'][0]['trust'] == 'hunt_advisory' and 'not operator instructions' in actions['trust_note']
    asyncio.run(run())
