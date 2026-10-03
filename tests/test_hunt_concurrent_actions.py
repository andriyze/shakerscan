"""SSH watches and external checks share the canonical leased worker path."""
import asyncio
import pytest
from api.hunt import agent_job_concurrency as jobs
from api.hunt.device_traffic import require_device_admission
from api.hunt.device_traffic import record_device_traffic
import json


def test_ssh_and_external_check_execute_together_and_shutdown_drains_leases():
    async def run():
        started=[];ended=[];blocked=asyncio.Event()
        async def execute(redis,lease,job):
            started.append(job['capability_name'])
            try: await blocked.wait()
            finally: ended.append(job['capability_name'])
        await jobs.dispatch(None,None,{'capability_name':'ssh.exec'},execute=execute,enabled=True)
        await jobs.dispatch(None,None,{'capability_name':'templates.scan'},execute=execute,enabled=True)
        await asyncio.sleep(0)
        assert started==['ssh.exec','templates.scan']
        assert not ended
        await jobs.close()
        assert set(ended)==set(started) and not jobs._tasks
    asyncio.run(run())


def test_ssh_settlement_consumes_quotas_without_delaying_external_request_lane():
    class Conn:
        async def execute(self,sql,identifier,context): self.context=json.loads(context)
    async def run():
        conn=Conn()
        hunt={'id':'hunt','device_target_id':'asset','context_pack':{'device_policy_state':{
            'last_request_at':'2026-01-01T00:00:00+00:00','requests_used':2,'fragility_used':2}}}
        await record_device_traffic(conn,hunt,1,status='completed',health_observed=False,capability_name='ssh.exec')
        state=conn.context['device_policy_state']
        assert state['last_request_at']=='2026-01-01T00:00:00+00:00'
        assert state['requests_used']==3 and state['fragility_used']==3
    asyncio.run(run())


def test_worker_concurrency_is_bounded_and_ordinary_scan_workers_remain_serial():
    async def run():
        active=maximum=0;release=asyncio.Event();done=[]
        async def execute(redis,lease,job):
            nonlocal active,maximum
            active+=1;maximum=max(maximum,active)
            try: await release.wait()
            finally: active-=1;done.append(job)
        for index in range(jobs.MAX_CONCURRENT_AGENT_JOBS):
            await jobs.dispatch(None,None,index,execute=execute,enabled=True)
        await asyncio.sleep(0)
        waiting=asyncio.create_task(jobs.dispatch(None,None,'last',execute=execute,enabled=True))
        leased=[]
        def lease(): leased.append('leased');return 'lease'
        waiting_lease=asyncio.create_task(jobs.lease_when_ready(lease,enabled=True))
        await asyncio.sleep(0)
        assert not waiting.done() and not leased and maximum==jobs.MAX_CONCURRENT_AGENT_JOBS
        release.set();await waiting;await jobs.close()
        assert await waiting_lease=='lease' and leased==['leased']
        assert maximum<=jobs.MAX_CONCURRENT_AGENT_JOBS
        release.clear()
        ordinary=asyncio.create_task(jobs.dispatch(None,None,'scan',execute=execute,enabled=False))
        await asyncio.sleep(0)
        assert not ordinary.done()
        release.set();await ordinary
    asyncio.run(run())


@pytest.mark.parametrize('incoming,existing,allowed',[
    ('ssh.exec','http.request',True),('http.request','ssh.exec',True),
    ('ssh.exec','ssh.exec',False),('http.request','ports.discover',False)])
def test_device_ssh_and_external_lanes_keep_daily_budget_and_health_checks(incoming,existing,allowed):
    class Conn:
        async def execute(self,*args): pass
        async def fetchval(self,sql,*args):
            if 'SELECT EXISTS' in sql:
                # Exercise the SQL lane predicate with the real bound parameter.
                assert "r.capability_name='ssh.exec'" in sql and "$2='ssh.exec'" in sql
                return (existing=='ssh.exec')==(args[1]=='ssh.exec')
            return 0
    async def run():
        hunt={'device_target_id':'fixture','context_pack':{'device_policy_state':{}}}
        if allowed:
            await require_device_admission(Conn(),hunt,fragility=1,requests=1,capability_name=incoming)
        else:
            with pytest.raises(ValueError,match='in flight'):
                await require_device_admission(Conn(),hunt,fragility=1,requests=1,capability_name=incoming)
        if allowed:
            hunt['context_pack']['device_policy_state']={'traffic_frozen':True,'freeze_reason':'operator_pause'}
            with pytest.raises(ValueError,match='frozen'):
                await require_device_admission(Conn(),hunt,fragility=1,requests=1,capability_name=incoming)
    asyncio.run(run())
