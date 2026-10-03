"""Actual API -> durable Redis queue -> production worker -> real SSH commands.

Uses an isolated PostgreSQL database and dedicated Redis DB. No external targets,
model calls, mocked command results or device inventory operations are involved.
"""
import asyncio
import importlib
import json
import io
import os
from pathlib import Path
import socket
import ssl
import platform
import time
from uuid import UUID, uuid4

import pytest

from tests.test_target_asset_startup_postgres import startup_database
from tests.test_target_asset_inputs_postgres import encryption
from tests.ssh_exec_fixture import CommandServer, HttpLogFixture, PASSWORD, USERNAME, tls_material


@pytest.mark.parametrize(('kind','auth_kind'), [('network','ssh_password'),('device','ssh_password'),
    ('network','ssh_private_key'),('network','ssh_private_key_with_passphrase')])
def test_hunt_direct_ssh_reuses_streams_cancels_and_revalidates(monkeypatch, tmp_path, kind, auth_kind):
    async def scenario():
        import asyncpg
        import httpx
        import redis
        import uvicorn
        from targets.asset_migration import BoundConnectionPool
        from hunt.ssh_worker_lifecycle import maintain_ssh_sessions
        from hunt.ssh_routing import worker_queue, session_key
        from capabilities.ssh_transport import SSH_TRANSPORTS
        from job_queue import lease_job, acknowledge_lease
        from hunt import agent_job_concurrency
        dsn = os.environ.get('SSH_TEST_REDIS_URL')
        if not dsn:
            pytest.skip('SSH_TEST_REDIS_URL is not configured')
        r = redis.Redis.from_url(dsn, decode_responses=True)
        assert r.connection_pool.connection_kwargs.get('db') == 15
        r.flushdb()
        SSH_TRANSPORTS.close_all()
        # Earlier migration tests may cache an unavailable key; isolate both secret-store imports.
        encryption(monkeypatch)
        app_module = importlib.import_module('api')
        if not hasattr(app_module, '_start_hunt_v2'):
            app_module = importlib.import_module('api.api')
        worker = importlib.import_module('worker')
        fixture = CommandServer(tmp_path)
        http_fixture=HttpLogFixture(tmp_path)
        credential_secret, passphrase = PASSWORD, None
        if auth_kind != 'ssh_password':
            import paramiko
            client_key = paramiko.RSAKey.generate(2048)
            fixture.public_keys.add(client_key.asbytes())
            passphrase = 'fixture-key-passphrase' if auth_kind.endswith('with_passphrase') else None
            pem = io.StringIO();client_key.write_private_key(pem,password=passphrase)
            credential_secret=pem.getvalue()
        fixture.allow('id -un', 'uname -s', "printf 'out\\n'; printf 'err\\n' >&2; exit 7",
            "printf 'first\\n'; sleep 2; printf 'last\\n'", 'sleep 20', "printf '%02048d' 0",'tail -n 0 -f web.log')
        owner = 'fixture-agent-worker-' + uuid4().hex
        recorded_queues = []
        worker_errors = []
        timing = {}
        async with startup_database() as conn:
            await importlib.import_module('retest_contract').run_schema_migrations(BoundConnectionPool(conn))
            database = await conn.fetchval('SELECT current_database()')
            pool = await asyncpg.create_pool(os.environ['TARGET_ASSET_TEST_DATABASE_URL'], database=database,
                                             min_size=2,max_size=8)
            monkeypatch.setattr(app_module,'db_pool',pool)
            monkeypatch.setattr(app_module.app.state,'db_pool',pool,raising=False)
            monkeypatch.setattr(worker,'db_pool',pool)
            monkeypatch.setattr(app_module,'get_redis',lambda:r)
            monkeypatch.setattr(worker,'get_redis',lambda:r)
            monkeypatch.setattr(worker,'_worker_runtime_identity',lambda:owner)
            async def addresses(*args, **kwargs): return ['127.0.0.1']
            monkeypatch.setattr(app_module,'_resolve_agent_target_addresses',addresses)
            base_queue = worker.AGENT_TOOL_QUEUE_NAME
            maintenance = asyncio.create_task(maintain_ssh_sessions(r,pool,owner))
            stopped = asyncio.Event()

            async def execute_job(redis_client,lease,job):
                try:
                    if job['type']=='canonical_network_capability':
                        await worker.process_canonical_network_capability_job(job)
                    else:
                        assert job['type']=='canonical_http_capability'
                        await worker.process_canonical_http_capability_job(job)
                except BaseException as exc:
                    if not isinstance(exc,asyncio.CancelledError): worker_errors.append(repr(exc))
                    raise
            monkeypatch.setattr(worker,'process_job',lambda job:execute_job(r,None,job))
            async def consume():
                while not stopped.is_set():
                    lease = await agent_job_concurrency.lease_when_ready(lambda:lease_job(r,
                        [worker_queue(base_queue,owner),base_queue],consumer_name=owner,
                        block_ms=100,visibility_timeout_ms=600000),enabled=True)
                    if lease is None:
                        continue
                    try:
                        job = json.loads(lease.payload)
                        assert job['type'] in {'canonical_network_capability','canonical_http_capability'}
                        recorded_queues.append(lease.queue_name)
                        if job['capability_name'] == 'ssh.exec':
                            assert set(job['capability_input']) == {'encrypted_ssh_input'}
                            assert 'id -un' not in json.dumps(job)
                        await agent_job_concurrency.dispatch(r,lease,job,execute=worker._run_job_under_lease,enabled=True)
                    except BaseException as exc:
                        worker_errors.append(repr(exc))
                        raise

            consumer = asyncio.create_task(consume())
            sock = socket.socket();sock.bind(('127.0.0.1',0))
            base_url = 'http://127.0.0.1:'+str(sock.getsockname()[1])
            server = uvicorn.Server(uvicorn.Config(app_module.app, lifespan='off',ws='none',
                log_level='critical',access_log=False,timeout_graceful_shutdown=3))
            serving = asyncio.create_task(server.serve(sockets=[sock]))
            gateway_server = gateway_serving = gateway_sock = planner = watch = None
            try:
                for _ in range(100):
                    if server.started: break
                    await asyncio.sleep(0.02)
                assert server.started
                async with httpx.AsyncClient(base_url=base_url,timeout=50) as client:
                    async def request(method,path,body=None):
                        response = await client.request(method,path,json=body)
                        assert response.status_code < 300, (path,response.status_code,response.text)
                        return response.json()
                    target = await request('POST','/targets/hosts',{'locator':'127.0.0.1','name':'Local command fixture',
                        'environment':'lab','approved_by':'ssh-runtime-fixture','port_hints':[fixture.port]})
                    target_id = target['id']
                    if kind == 'device':
                        device_view = await request('POST', f'/targets/{target_id}/device-profile', {})
                        assert device_view['device_id'] == target_id
                    approval = (await request('GET',f'/targets/{target_id}/authorization'))['authorization']['approval_receipt_id']
                    await request('PUT',f'/targets/{target_id}/hunt-authority',{'expected_revision':0,
                        'ssh_host_keys':[{'port':fixture.port,'fingerprint':fixture.fingerprint}]})
                    home = await request('POST','/targets/hosts',{'locator':'127.0.0.2','name':'Credential home',
                        'environment':'lab','approved_by':'ssh-runtime-fixture'})
                    home_approval=(await request('GET',f"/targets/{home['id']}/authorization"))['authorization']['approval_receipt_id']
                    profile = (await request('POST','/credential-profiles',{'target_kind':kind,'target_id':home['id'],
                        'name':'Command identity','auth_kind':auth_kind,'principal_slot':'ssh','username':USERNAME,
                        'secret':credential_secret,'secondary_secret':passphrase,'allowed_capabilities':['ssh.exec'],
                        'allow_active_capabilities':True,'approval_receipt_id':home_approval,
                        'created_by':'ssh-runtime-fixture'}))['profile']['id']
                    await request('POST',f'/credential-profiles/{profile}/grants',{'target_kind':kind,
                        'target_id':target_id,'approval_receipt_id':approval,'granted_by':'ssh-runtime-fixture'})
                    hunt = await request('POST','/hunts',{'schema_version':'hunt-start/v2','target_id':target_id,
                        'target_kind':kind,'goal':'Run explicitly authorized SSH fixture commands directly',
                        'budget_profile':'thorough','capabilities':['ssh.exec','ssh.close','http.request'],
                        'policy':{'active_testing':True,'network_discovery':False,'authorization_confirmed':True},
                        'credential_refs':{'ssh_credential_profile_id':profile}})
                    hunt_id=hunt['hunt_id']
                    from hunt.planner_gateway import HuntPlannerGateway
                    from hunt.planner_lease import write_lease
                    grant_file, token_file = tmp_path/'planner-grant',tmp_path/'planner-token'
                    write_lease(hunt_id,grant_file,token_file)
                    cert,private=tls_material(tmp_path)
                    gateway_sock=socket.socket();gateway_sock.bind(('127.0.0.1',0))
                    gateway_url='https://127.0.0.1:'+str(gateway_sock.getsockname()[1])
                    gateway_server=uvicorn.Server(uvicorn.Config(HuntPlannerGateway(app_module.app,grant_file),
                        lifespan='off',ws='none',log_level='critical',access_log=False,timeout_graceful_shutdown=3,
                        ssl_certfile=str(cert),ssl_keyfile=str(private)))
                    gateway_serving=asyncio.create_task(gateway_server.serve(sockets=[gateway_sock]))
                    for _ in range(100):
                        if gateway_server.started: break
                        await asyncio.sleep(0.02)
                    assert gateway_server.started
                    planner=httpx.AsyncClient(base_url=gateway_url,timeout=50,
                        verify=ssl.create_default_context(cafile=str(cert)),
                        headers={'Authorization':'Bearer '+token_file.read_text().strip()})
                    endpoint=f'/hunts/{hunt_id}/capabilities/ssh.exec'
                    async def execute(command, **kwargs):
                        key=kwargs.pop('key','command-'+uuid4().hex)
                        response=await planner.post(endpoint,json={'idempotency_key':key,'input':{'command':command,**kwargs}})
                        assert response.status_code==200,(response.status_code,response.text)
                        return response.json()
                    def observation(value):
                        assert value['result']['receipt_id'], value
                        return next(item for item in value['result']['typed_output']['records'] if item['kind']=='ssh_command_observation')
                    started=time.monotonic()
                    first=await execute('id -un',port=fixture.port,key='same-command-id-001')
                    timing['first_command_seconds']=time.monotonic()-started
                    assert first['action_result']['status']=='success',first
                    one=observation(first)
                    assert one['exit_status']==0 and one['stdout'].strip()
                    session=one['session_id']
                    assert fixture.logins==1 and fixture.commands==['id -un']
                    duplicate=await execute('id -un',port=fixture.port,key='same-command-id-001')
                    assert duplicate['idempotent_replay'] is True and len(fixture.commands)==1
                    started=time.monotonic()
                    second=await execute('uname -s',session_id=session)
                    timing['reused_command_seconds']=time.monotonic()-started
                    two=observation(second)
                    assert second['action_result']['status']=='success',second
                    assert two['stdout'].strip()==platform.system() and two['connection_reused'] is True
                    assert fixture.logins==1 and recorded_queues[-1]==worker_queue(base_queue,owner)
                    assert two['host_key_fingerprint']==fixture.fingerprint
                    assert (await conn.fetchval('SELECT status FROM hunt_actions WHERE id=$1',UUID(second['action_id'])))=='completed'
                    settled=await conn.fetchrow('SELECT status,actual_json FROM budget_reservations WHERE action_id=$1',second['action_id'])
                    assert settled['status']=='committed'
                    assert json.loads(settled['actual_json']).get('tcp_ports_attempted',0)==0
                    nonzero=await execute("printf 'out\\n'; printf 'err\\n' >&2; exit 7",session_id=session)
                    assert nonzero['action_result']['status']=='success',nonzero
                    assert observation(nonzero)['exit_status']==7 and observation(nonzero)['stderr']=='err\n'
                    started=time.monotonic();first_output=None;final=None;event=''
                    async with planner.stream('POST',f'/hunts/{hunt_id}/ssh/exec',json={
                        'idempotency_key':'stream-command-001','input':{'command':"printf 'first\\n'; sleep 2; printf 'last\\n'",'session_id':session}}) as response:
                        assert response.status_code==200
                        async for line in response.aiter_lines():
                            if line.startswith('event: '): event=line[7:]
                            if line.startswith('data: '):
                                data=json.loads(line[6:])
                                if event=='output' and data.get('stdout')=='first\n' and first_output is None:
                                    first_output=time.monotonic()-started
                                if event=='result': final=data
                    timing['first_output_seconds']=first_output
                    timing['stream_completion_seconds']=time.monotonic()-started
                    assert first_output is not None and first_output < 1.8, timing
                    assert final['action_result']['status']=='success' and observation(final)['stdout']=='first\nlast\n',final
                    assert fixture.logins==1
                    watch=asyncio.create_task(execute('tail -n 0 -f web.log',session_id=session,timeout_seconds=5,key='watch-external-001'))
                    for _ in range(100):
                        if fixture.commands[-1]=='tail -n 0 -f web.log': break
                        await asyncio.sleep(0.05)
                    assert fixture.commands[-1]=='tail -n 0 -f web.log'
                    # Give the native tail process time to seek to the end before
                    # the external check appends a line. SSH must remain running.
                    await asyncio.sleep(0.2)
                    external_started=time.monotonic()
                    external=await planner.post(f'/hunts/{hunt_id}/capabilities/http.request',json={
                        'idempotency_key':'external-with-ssh-001','input':{
                            'method':'GET','origin':f'http://127.0.0.1:{http_fixture.port}','path':'/fixture-check'}})
                    assert external.status_code==200,external.text
                    assert external.json()['action_result']['status']=='success',external.text
                    assert not watch.done(),'External check waited for SSH to finish'
                    timing['external_check_during_ssh_seconds']=time.monotonic()-external_started
                    watched=await watch
                    assert 'external-request /fixture-check' in observation(watched)['stdout'],watched
                    assert observation(watched)['connection_closed'] is True
                    restored=await execute('id -un',port=fixture.port)
                    session=observation(restored)['session_id']
                    long_key='cancel-command-001'
                    from uuid import uuid5
                    action_id=str(uuid5(UUID(hunt_id),'hunt-capability:'+long_key))
                    pending=asyncio.create_task(execute('sleep 20',session_id=session,key=long_key))
                    for _ in range(100):
                        if fixture.commands[-1]=='sleep 20': break
                        await asyncio.sleep(0.05)
                    assert fixture.commands[-1]=='sleep 20'
                    cancelled=await request('POST',f'/hunts/{hunt_id}/ssh/actions/{action_id}/cancel')
                    assert cancelled['cancellation_requested'] is True
                    result=await asyncio.wait_for(pending,5)
                    assert result['action_result']['status']=='cancelled',result
                    assert observation(result)['remote_termination_confirmed'] is False
                    assert not r.exists(session_key(session))
                    for _ in range(100):
                        if not fixture.running: break
                        await asyncio.sleep(0.02)
                    assert not fixture.running
                    timed=await execute('sleep 20',port=fixture.port,timeout_seconds=1)
                    assert timed['action_result']['status']=='partial',timed
                    assert observation(timed)['timed_out'] and observation(timed)['execution_uncertain']
                    capped=await execute("printf '%02048d' 0",port=fixture.port,max_output_bytes=1024)
                    assert capped['action_result']['status']=='partial',capped
                    assert observation(capped)['output_bytes']==1024 and observation(capped)['output_truncated'],observation(capped)
                    fresh=await execute('uname -s',port=fixture.port)
                    assert fresh['action_result']['status']=='success',fresh
                    fresh_session=observation(fresh)['session_id']
                    closed=await planner.post(f'/hunts/{hunt_id}/capabilities/ssh.close',json={
                        'idempotency_key':'close-session-001','input':{'session_id':fresh_session}})
                    assert closed.status_code==200 and closed.json()['action_result']['status']=='success',closed.text
                    assert not r.exists(session_key(fresh_session))
                    fresh=await execute('uname -s',port=fixture.port)
                    fresh_session=observation(fresh)['session_id']
                    before_commands=len(fixture.commands)
                    await request('PUT',f'/targets/{target_id}/hunt-authority',{'expected_revision':1,
                        'ssh_host_keys':[{'port':fixture.port,'fingerprint':'SHA256:'+'A'*43}]})
                    rejected=await execute('id -un',session_id=fresh_session)
                    assert rejected['action_result']['status']!='success' and len(fixture.commands)==before_commands,rejected
                    await request('PUT',f'/targets/{target_id}/hunt-authority',{'expected_revision':2,
                        'ssh_host_keys':[{'port':fixture.port,'fingerprint':fixture.fingerprint}]})
                    fresh=await execute('uname -s',port=fixture.port)
                    fresh_session=observation(fresh)['session_id']
                    before_commands=len(fixture.commands)
                    await request('DELETE',f'/credential-profiles/{profile}/grants/{target_id}')
                    denied=await planner.post(endpoint,json={'idempotency_key':'revoked-command-001',
                        'input':{'command':'id -un','session_id':fresh_session}})
                    assert denied.status_code >= 400 or denied.json()['action_result']['status'] != 'success',denied.text
                    assert len(fixture.commands)==before_commands
                    assert (await planner.put(f'/targets/{target_id}/hunt-authority',json={'expected_revision':3})).status_code==403
                    assert PASSWORD not in json.dumps([first,second,nonzero,final,result,timed,capped,rejected])
                    assert await conn.fetchval('SELECT count(*) FROM scans WHERE target_id=$1',UUID(target_id))==0
                    assert not worker_errors,worker_errors
                    timing['successful_authentications']=fixture.logins
                    timing['command_channels']=len(fixture.commands)
                    timing['inventory_scans']=0
                    dest=Path(os.environ.get('SSH_TIMING_OUTPUT_DIR',str(tmp_path)))
                    dest.mkdir(parents=True,exist_ok=True)
                    (dest/f'ssh-{kind}-{auth_kind}-timings.json').write_text(json.dumps(timing,indent=2)+'\n')
            finally:
                if watch is not None:
                    watch.cancel();await asyncio.gather(watch,return_exceptions=True)
                if planner:
                    await planner.aclose()
                if gateway_server:
                    gateway_server.should_exit=True
                    await asyncio.wait_for(gateway_serving,10)
                    gateway_sock.close()
                stopped.set()
                consumer.cancel();maintenance.cancel();server.should_exit=True
                await asyncio.gather(consumer,maintenance,return_exceptions=True)
                await agent_job_concurrency.close()
                await asyncio.wait_for(serving,10)
                sock.close()
                fixture.close()
                http_fixture.close()
                SSH_TRANSPORTS.close_all()
                r.flushdb();r.close()
                await pool.close()
    asyncio.run(scenario())
