"""The live Hunt briefing counts against how production stores each record, on real PostgreSQL.

The schema is db/init.sql plus the startup migrations; Hunts start through the actual FastAPI
app. Records are written through their production routes and services: the authorization
investigation routes (propose, skip, approve with the live executor), the Hunt candidate route,
the hypothesis route and the Hunt finding service. Only DNS resolution is a controlled fixture;
captured traffic, credential profiles, authentication sessions and one canonical worker settlement
are fixture rows (a capture would otherwise need a live target and a login), identified as such
where they are inserted. One approval replaces only the executor with one that raises before
admission, the crash the workflow recovers by re-approving the same attempt.
"""
import asyncio
import importlib
import json
import os
import uuid
from contextlib import asynccontextmanager

import pytest
from httpx import ASGITransport, AsyncClient
from targets.asset_migration import BoundConnectionPool

from tests.test_instruction_proposals_postgres import _prepared
from tests.test_target_asset_startup_postgres import startup_database

ORIGIN = 'https://app.briefing.test'


def _web_contract(target, **policy):
    return {'target_id': str(target), 'target_kind': 'web', 'goal': 'Review object access',
            'policy': {'active_testing': False, **policy},
            'budgets': {'max_active_actions': 0, 'max_candidates': 5}}


async def _start(operator, contract):
    started = await operator.post('/hunts', json=contract)
    assert started.status_code in {200, 201}, started.text
    return started.json()


async def _fixture_profile(conn, target, slot):
    """Fixture: a credential profile row; its secret material is never read by these paths."""
    profile = uuid.uuid4()
    await conn.execute(
        """INSERT INTO credential_profiles(id,target_kind,target_id,name,auth_kind,principal_slot,
               configuration_json,rotated_at,created_at,updated_at)
           VALUES($1,'web',$2,$3,'json_login',$4,'{}'::jsonb,NOW(),NOW(),NOW())""",
        profile, target, f'{slot}-{profile}', slot)
    return profile


async def _fixture_session(conn, hunt, target, slot):
    """Fixture: an active Hunt authentication session (metadata only; headers are a placeholder)."""
    session = uuid.uuid4()
    profile = await _fixture_profile(conn, target, slot)
    await conn.execute(
        """INSERT INTO auth_sessions(id,owner_kind,owner_id,target_kind,target_id,target_binding_digest,
               profile_id,profile_version,principal_slot,auth_kind,encrypted_headers,status,
               established_at,expires_at,refresh_after,evidence_receipt_digest,source_action_id)
           VALUES($1,'hunt',$2,'web',$3,$4,$5,1,$6,'json_login','enc:fernet:fixture','active',
               NOW()-interval '1 minute',NOW()+interval '1 day',NOW()+interval '1 hour',$4,$7)""",
        session, hunt, target, 'a' * 64, profile, slot, uuid.uuid4())
    return session


async def _fixture_capture(conn, hunt, path, slot, session):
    """Fixture: one completed same-Hunt http.request action and its captured GET transaction."""
    action = uuid.uuid4()
    await conn.execute(
        """INSERT INTO hunt_actions(id,hunt_run_id,capability_name,status,input_summary,completed_at)
           VALUES($1,$2,'http.request','completed',$3::jsonb,NOW())""",
        action, hunt, json.dumps({'input': {'method': 'GET', 'path': path, 'session_ref': str(session)}}))
    capture = await conn.fetchval(
        """INSERT INTO http_transactions(plane,sequence,hunt_run_id,hunt_action_id,principal_slot,method,url,
               request_body_bytes,status_code,truncated)
           VALUES('hunt',1,$1,$2,$3,'GET',$4,0,200,false) RETURNING id""",
        hunt, action, slot, ORIGIN + path)
    return capture, action


async def _propose(operator, conn, hunt, target, object_id):
    primary = await _fixture_session(conn, hunt, target, 'primary')
    secondary = await _fixture_session(conn, hunt, target, 'secondary')
    capture, _ = await _fixture_capture(conn, hunt, f'/orders/{object_id}', 'primary', primary)
    baseline, _ = await _fixture_capture(conn, hunt, '/orders', 'secondary', secondary)
    response = await operator.post(f'/hunts/{hunt}/authorization-investigations', json={
        'capture_id': str(capture), 'baseline_capture_id': str(baseline),
        'primary_session_ref': str(primary), 'secondary_session_ref': str(secondary)})
    assert response.status_code == 200, response.text
    return response.json()


async def _approve_with_crashing_executor(app_module, operator, conn, hunt, proposal):
    """Approve through the real route and service; the executor fails before canonical admission."""
    from capabilities.authz import _public_proof_url
    from hunt.authorization_router import authorization_service
    from hunt.authorization_service import AuthorizationInvestigationService

    async def crash(*_args):
        raise RuntimeError('worker unavailable before admission')
    app_module.app.dependency_overrides[authorization_service] = lambda: AuthorizationInvestigationService(
        BoundConnectionPool(conn), crash, _public_proof_url)
    try:
        with pytest.raises(RuntimeError, match='before admission'):
            await operator.post(f"/hunts/{hunt}/authorization-investigations/{proposal['proposal_id']}/approve",
                                json={'proposal_digest': proposal['proposal_digest'], 'confirm': True})
    finally:
        app_module.app.dependency_overrides.pop(authorization_service, None)


@asynccontextmanager
async def _fresh_connection(conn):
    """A second connection to the same database: what a restarted process would open."""
    import asyncpg
    fresh = await asyncpg.connect(os.environ['TARGET_ASSET_TEST_DATABASE_URL'],
                                  database=await conn.fetchval('SELECT current_database()'))
    try:
        yield fresh
    finally:
        await fresh.close()


def test_inconclusive_authorization_attempt_is_reported_and_survives_a_restart(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await conn.fetchval("INSERT INTO targets(url) VALUES($1) RETURNING id", ORIGIN)
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                hunt = (await _start(operator, _web_contract(target)))['hunt_id']
                empty = (await operator.get(f'/hunts/{hunt}')).json()['briefing']['unresolved']
                assert empty['authorization_investigations']['open'] == 0, empty
                assert 'inconclusive_experiments' not in empty

                approved = await _propose(operator, conn, hunt, target, '1001')
                waiting = await _propose(operator, conn, hunt, target, '1004')
                pending = await _propose(operator, conn, hunt, target, '1002')
                deferred = await _propose(operator, conn, hunt, target, '1003')
                assert len({approved['proposal_id'], waiting['proposal_id'], pending['proposal_id'],
                            deferred['proposal_id']}) == 4
                # The attempt link is persisted, then the executor fails: never dispatched.
                await _approve_with_crashing_executor(app_module, operator, conn, hunt, approved)
                # The live executor admits the action as awaiting permission (no active testing yet).
                approval = await operator.post(
                    f"/hunts/{hunt}/authorization-investigations/{waiting['proposal_id']}/approve",
                    json={'proposal_digest': waiting['proposal_digest'], 'confirm': True})
                assert approval.status_code == 409, approval.text
                assert approval.json()['detail']['code'] == 'permission_required'
                skipped = await operator.post(
                    f"/hunts/{hunt}/authorization-investigations/{deferred['proposal_id']}/skip")
                assert skipped.status_code == 200, skipped.text

                # The investigation read (the workflow's own projection) says the attempt is open.
                read = (await operator.get(
                    f"/hunts/{hunt}/authorization-investigations/{approved['proposal_id']}")).json()
                assert [a['outcome'] for a in read['attempts']] == ['inconclusive'] and read['settled'] is False
                assert read['attempts'][0]['execution_status'] == 'not_dispatched'
                read = (await operator.get(
                    f"/hunts/{hunt}/authorization-investigations/{waiting['proposal_id']}")).json()
                assert read['attempts'][0]['execution_status'] == 'awaiting_permission' and read['settled'] is False
                assert await conn.fetchval(
                    "SELECT count(*) FROM application_graph_nodes WHERE node_type='experiment'") == 0

                briefing = (await operator.get(f'/hunts/{hunt}')).json()['briefing']['unresolved']
                counts = briefing['authorization_investigations']
                assert counts['inconclusive'] == 1 and counts['awaiting_execution'] == 1, counts
                assert counts['proposed_not_run'] == 1 and counts['deferred'] == 1
                assert counts['open'] == 3 and counts['settled'] == 0 and counts['needs_review'] == 0
                assert briefing['awaiting_permission_actions'] == 1
                assert counts['at_least'] is False

                # A second Hunt on the same target sees the unfinished work in its start response.
                second = await _start(operator, _web_contract(target))
                assert second['briefing']['unresolved']['authorization_investigations']['open'] == 3

            # Restart: a fresh connection and a fresh app binding; nothing is held in memory.
            async with _fresh_connection(conn) as fresh:
                monkeypatch.setattr(app_module, 'db_pool', BoundConnectionPool(fresh))
                async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://restarted') as operator:
                    restarted = (await operator.get(f'/hunts/{hunt}')).json()['briefing']['unresolved']
                assert restarted['authorization_investigations'] == briefing['authorization_investigations']
    asyncio.run(run())


def test_settled_and_inconsistent_investigations_are_classified_without_failing_the_briefing(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await conn.fetchval("INSERT INTO targets(url) VALUES($1) RETURNING id", ORIGIN)
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                hunt = (await _start(operator, _web_contract(target)))['hunt_id']
                refuted = await _propose(operator, conn, hunt, target, '2001')
                tampered = await _propose(operator, conn, hunt, target, '2002')
                await _approve_with_crashing_executor(app_module, operator, conn, hunt, refuted)
                attempt = await conn.fetchval(
                    "SELECT attributes FROM application_graph_nodes WHERE node_type='authorization_attempt'")
                attempt = json.loads(attempt) if isinstance(attempt, str) else attempt
                # Fixture: the canonical worker's settlement of that exact action, an exact-request
                # denial to the secondary principal, which attributed_outcome reads as refuted.
                import hashlib
                await conn.execute(
                    """INSERT INTO hunt_actions(id,hunt_run_id,capability_name,status,input_summary,result_summary,
                           receipt_id,completed_at)
                       VALUES($1,$2,'authz.verify','completed',$3::jsonb,'{}'::jsonb,$4,NOW())""",
                    uuid.UUID(attempt['action_id']), uuid.UUID(hunt),
                    json.dumps({'input_digest': attempt['input_digest'],
                                'idempotency_key_sha256': hashlib.sha256(attempt['idempotency_key'].encode()).hexdigest()}),
                    uuid.uuid4())
                for sequence, slot, status in ((2, 'primary', 200), (3, 'secondary', 403)):
                    await conn.execute(
                        """INSERT INTO http_transactions(plane,sequence,hunt_run_id,hunt_action_id,principal_slot,
                               method,url,request_body_bytes,status_code,truncated)
                           VALUES('hunt',$1,$2,$3,$4,'GET',$5,0,$6,false)""",
                        sequence, uuid.UUID(hunt), uuid.UUID(attempt['action_id']), slot, ORIGIN + '/orders/2001', status)
                read = (await operator.get(
                    f"/hunts/{hunt}/authorization-investigations/{refuted['proposal_id']}")).json()
                assert read['settled'] is True and read['attempts'][-1]['outcome'] == 'refuted'

                # A persisted binding that no longer verifies is counted for review, never raised.
                await conn.execute(
                    """UPDATE application_graph_nodes SET attributes=attributes || '{"route_hint":"changed"}'::jsonb
                       WHERE id=$1""", uuid.UUID(tampered['proposal_id']))
                unresolved = (await operator.get(f'/hunts/{hunt}')).json()['briefing']['unresolved']
                counts = unresolved['authorization_investigations']
                assert counts['settled'] == 1 and counts['needs_review'] == 1 and counts['open'] == 0, counts
    asyncio.run(run())


def test_device_asset_briefing_counts_investigations_on_its_service_members(monkeypatch):
    async def run():
        async with startup_database() as conn:
            device = await conn.fetchval(
                "INSERT INTO device_targets(name,primary_locator) VALUES('Router','app.briefing.test') RETURNING id")
            app_module = await _prepared(conn, monkeypatch)
            # A web origin on the same host becomes a service member of the host asset.
            service = await conn.fetchval("INSERT INTO targets(url) VALUES($1) RETURNING id", ORIGIN)
            assert await conn.fetchval('SELECT asset_owner_id FROM targets WHERE id=$1', service) == device
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                web_hunt = (await _start(operator, _web_contract(service)))['hunt_id']
                await _propose(operator, conn, web_hunt, service, '3001')
                started = await _start(operator, {**_web_contract(device), 'target_kind': 'device'})
                counts = started['briefing']['unresolved']['authorization_investigations']
                assert counts['proposed_not_run'] == 1 and counts['open'] == 1, counts
                # The web service Hunt counts only its own service.
                web = (await operator.get(f'/hunts/{web_hunt}')).json()['briefing']['unresolved']
                assert web['authorization_investigations']['open'] == 1
    asyncio.run(run())


def test_candidate_hypothesis_and_finding_counts_match_production_writes(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            investigation_candidates = importlib.import_module('investigation_candidates')
            finding_actions = importlib.import_module('hunt.finding_actions')
            # The open/settled vocabulary the briefing uses is exactly the stored one.
            definition = await conn.fetchval(
                """SELECT pg_get_constraintdef(oid) FROM pg_constraint
                   WHERE conname='investigation_candidates_status_check'""")
            stored = {value for value in ('new', 'verification_queued', 'verifying', 'verified', 'refuted',
                                          'inconclusive', 'blocked', 'expired') if f"'{value}'" in definition}
            assert len(stored) == 8 and investigation_candidates.TERMINAL_STATUSES == {'verified', 'refuted', 'expired'}

            target = await conn.fetchval("INSERT INTO targets(url) VALUES($1) RETURNING id", ORIGIN)
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                hunt = (await _start(operator, _web_contract(target)))['hunt_id']
                session = await _fixture_session(conn, uuid.UUID(hunt), target, 'primary')
                _, evidence = await _fixture_capture(conn, uuid.UUID(hunt), '/orders/7', 'primary', session)
                created = []
                for title in ('Order read without ownership check', 'Order export leaks totals'):
                    response = await operator.post(f'/hunts/{hunt}/candidates', json={
                        'family': 'idor', 'locus': {'path': '/orders/' + title.split()[1].lower()}, 'title': title,
                        'claim': 'A secondary principal read an order.', 'evidence_refs': [str(evidence)]})
                    assert response.status_code == 200, response.text
                    created.append(response.json()['candidate'])
                await investigation_candidates.expire_candidate_for_hunt(
                    conn, hunt_run_id=hunt, candidate_id=created[1]['id'], created_by=f'hunt_v2:{hunt}')
                hypothesis = await operator.post('/arsenal/hypotheses', json={
                    'source': 'manual', 'family': 'idor', 'dedupe_key': 'orders-ownership',
                    'target_id': str(target), 'title': 'Orders lack ownership checks'})
                assert hypothesis.status_code == 200, hypothesis.text
                await finding_actions.create_hunt_finding(
                    BoundConnectionPool(conn), hunt_id=hunt, action_id=uuid.uuid4(),
                    values={'title': 'Order IDOR', 'description': 'Cross-principal read.', 'severity': 'high',
                            'evidence_summary': 'Captured read.', 'evidence_action_ids': [str(evidence)]})

                briefing = (await operator.get(f'/hunts/{hunt}')).json()['briefing']
                assert briefing['unresolved']['open_candidates'] == {'count': 1, 'at_least': False,
                                                                     'by_status': {'new': 1}}
                counts = briefing['knowledge']['counts']
                assert counts['candidates']['count'] == 2  # knowledge counts every stored candidate
                assert counts['hypotheses']['count'] == 1
                assert counts['findings']['count'] == 1
                assert 'coverage' not in briefing
    asyncio.run(run())


def test_device_hunt_finding_and_candidate_counts_read_the_host_asset(monkeypatch):
    async def run():
        async with startup_database() as conn:
            device = await conn.fetchval(
                "INSERT INTO device_targets(name,primary_locator) VALUES('Camera','cam.briefing.test') RETURNING id")
            app_module = await _prepared(conn, monkeypatch)
            investigation_candidates = importlib.import_module('investigation_candidates')
            finding_actions = importlib.import_module('hunt.finding_actions')
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                started = await _start(operator, {**_web_contract(device), 'target_kind': 'device'})
                hunt = started['hunt_id']
                # Fixture: a completed same-Hunt action the candidate and finding cite as evidence.
                evidence = uuid.uuid4()
                await conn.execute(
                    """INSERT INTO hunt_actions(id,hunt_run_id,capability_name,status,completed_at)
                       VALUES($1,$2,'http.request','completed',NOW())""", evidence, uuid.UUID(hunt))
                await conn.execute(
                    """INSERT INTO http_transactions(plane,sequence,hunt_run_id,hunt_action_id,method,url,
                           request_body_bytes,status_code,truncated)
                       VALUES('hunt',1,$1,$2,'GET','http://cam.briefing.test:8080/',0,200,false)""",
                    uuid.UUID(hunt), evidence)
                # The real Hunt candidate route; a device Hunt's run row carries the device id in both
                # columns, and the route names it only as the device identifier.
                response = await operator.post(f'/hunts/{hunt}/candidates', json={
                    'family': 'default-credentials', 'locus': {'port': 8080}, 'title': 'Default admin login',
                    'claim': 'The admin page accepted a default login.', 'evidence_refs': [str(evidence)]})
                assert response.status_code in {200, 201}, response.text
                assert await conn.fetchval(
                    'SELECT target_id FROM investigation_candidates WHERE hunt_run_id=$1', uuid.UUID(hunt)) == device
                await finding_actions.create_hunt_finding(
                    BoundConnectionPool(conn), hunt_id=hunt, action_id=uuid.uuid4(),
                    values={'title': 'Default credentials', 'description': 'Admin login accepted.',
                            'severity': 'high', 'evidence_summary': 'Captured login.',
                            'evidence_action_ids': [str(evidence)]})
                stored = await conn.fetchrow(
                    'SELECT target_id, device_target_id FROM findings WHERE hunt_run_id=$1', uuid.UUID(hunt))
                assert stored['device_target_id'] == device and stored['target_id'] == device
                briefing = (await operator.get(f'/hunts/{hunt}')).json()['briefing']
                assert briefing['unresolved']['open_candidates']['count'] == 1
                assert briefing['knowledge']['counts']['candidates']['count'] == 1
                assert briefing['knowledge']['counts']['findings']['count'] == 1
                assert investigation_candidates.TERMINAL_STATUSES.isdisjoint(
                    briefing['unresolved']['open_candidates']['by_status'])
    asyncio.run(run())


def test_bounded_counts_report_at_least(monkeypatch):
    async def run():
        async with startup_database() as conn:
            app_module = await _prepared(conn, monkeypatch)
            target = await conn.fetchval("INSERT INTO targets(url) VALUES($1) RETURNING id", ORIGIN)
            async with AsyncClient(transport=ASGITransport(app_module.app), base_url='http://operator') as operator:
                hunt = (await _start(operator, _web_contract(target)))['hunt_id']
                # Fixture: more proposal nodes than are examined; their bindings are not valid, so
                # each examined one is counted for review and the total is reported as a bound.
                await conn.execute(
                    """INSERT INTO application_graph_nodes(target_id,node_type,node_key,attributes)
                       SELECT $1,'authorization_proposal','authz:fixture:'||n,
                              jsonb_build_object('hunt_id',$2::text) FROM generate_series(1,1001) n""",
                    target, hunt)
                counts = (await operator.get(f'/hunts/{hunt}')).json()['briefing']['unresolved'][
                    'authorization_investigations']
                assert counts['at_least'] is True and counts['needs_review'] == 1000 and counts['open'] == 0
    asyncio.run(run())
