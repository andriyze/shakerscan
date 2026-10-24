"""SSH watches and external checks share the canonical leased worker path."""
import asyncio
import pytest
from fastapi import HTTPException
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


# --- Long actions leave the last slot to short work --------------------------------------------
#
# The worker runs three leased jobs at once. Once an MCP call answered outcome=running instead of
# holding the agent's step, an agent could keep three long actions in flight (two sqli.verify of
# 1,200 s and an xss.verify): they took all three slots, and every short call it made meanwhile
# (http.request, artifact.inspect: the API waits for its timeout plus 30 s) timed out in the queue.
# A long job now takes one of at most two long slots; one leased while both are taken waits in its
# leased execution without holding the slot short work runs in. Unit fixtures: the queue and the
# job handlers are doubles; the scheduler is the worker's own.

def _job(label, name):
    job_type = ("canonical_http_capability" if name in {"http.request", "artifact.inspect"}
                else "canonical_scanner_capability")
    return {"label": label, "type": job_type, "capability_name": name}


def _bounded(scenario):
    """Run a scheduler scenario for at most 10 s: a scheduler that stops leasing fails the test
    instead of hanging it, and the scheduler's state is cleared whatever happened."""
    async def run():
        try:
            await asyncio.wait_for(scenario(), 10)
        finally:
            await jobs.close()
    asyncio.run(run())


class Jobs:
    """Leases and dispatches jobs as the worker loop does; each job's work runs until released."""

    def __init__(self):
        self.started, self.release, self.leased = [], {}, []

    async def execute(self, redis, lease, job):
        async def work(job):
            self.started.append(job["label"])
            self.release[job["label"]] = gate = asyncio.Event()
            await gate.wait()
        await jobs.in_lane(job, work)

    async def lease_and_dispatch(self, job):
        await jobs.lease_when_ready(lambda: self.leased.append(job["label"]), enabled=True)
        await jobs.dispatch(None, None, job, execute=self.execute, enabled=True)
        await asyncio.sleep(0.02)


def test_long_actions_take_two_slots_and_a_short_call_runs_beside_them():
    async def run():
        queue = Jobs()
        for label, name in (("long-1", "sqli.verify"), ("long-2", "templates.scan"), ("long-3", "xss.verify")):
            await queue.lease_and_dispatch(_job(label, name))
        # The third long job waits for a long slot, and does not hold the slot short work needs.
        assert queue.started == ["long-1", "long-2"] and jobs._waiting == 1
        await asyncio.wait_for(queue.lease_and_dispatch(_job("short-1", "http.request")), 1)
        assert queue.started[-1] == "short-1"
        # All three slots work now, so the worker leases nothing more.
        blocked = asyncio.create_task(jobs.lease_when_ready(lambda: queue.leased.append("next"), enabled=True))
        await asyncio.sleep(0.02)
        assert not blocked.done()
        # A long slot frees: the waiting long job takes it, and the slots stay full.
        queue.release["long-1"].set()
        await asyncio.sleep(0.02)
        assert queue.started[-1] == "long-3" and jobs._waiting == 0 and jobs._long_running == 2
        assert not blocked.done()
        queue.release["short-1"].set()
        await asyncio.wait_for(blocked, 1)
        for gate in queue.release.values():
            gate.set()
        await jobs.close()
        assert queue.leased == ["long-1", "long-2", "long-3", "short-1", "next"]
    _bounded(run)


def test_short_work_may_use_every_slot_and_long_work_never_more_than_two():
    async def run():
        queue = Jobs()
        for index in range(3):
            await queue.lease_and_dispatch(_job(f"short-{index}", "artifact.inspect"))
        assert queue.started == ["short-0", "short-1", "short-2"] and jobs._waiting == 0
        blocked = asyncio.create_task(jobs.lease_when_ready(lambda: None, enabled=True))
        await asyncio.sleep(0.02)
        assert not blocked.done()
        for gate in queue.release.values():
            gate.set()
        await asyncio.wait_for(blocked, 1)
        await jobs.close()
        queue = Jobs()
        for index in range(5):
            await queue.lease_and_dispatch(_job(f"long-{index}", "sqli.verify"))
        assert queue.started == ["long-0", "long-1"] and jobs._waiting == 3
        await jobs.close()
        assert (jobs._waiting, jobs._long_running, jobs._tasks) == (0, 0, set())
    _bounded(run)


def test_waiting_long_jobs_are_bounded():
    async def run():
        queue = Jobs()
        for index in range(jobs.MAX_CONCURRENT_LONG_AGENT_JOBS + jobs.MAX_WAITING_LONG_AGENT_JOBS):
            await queue.lease_and_dispatch(_job(f"long-{index}", "templates.scan"))
        assert jobs._waiting == jobs.MAX_WAITING_LONG_AGENT_JOBS
        # With that many waiting the worker stops leasing until one of them starts.
        blocked = asyncio.create_task(jobs.lease_when_ready(lambda: None, enabled=True))
        await asyncio.sleep(0.02)
        assert not blocked.done()
        queue.release["long-0"].set()
        await asyncio.wait_for(blocked, 1)
        await jobs.close()
    _bounded(run)


@pytest.mark.parametrize("job,long", [
    (_job("a", "sqli.verify"), True), (_job("b", "xss.verify"), True),
    (_job("c", "templates.scan"), True), (_job("d", "http.request"), False),
    (_job("e", "artifact.inspect"), False),
    ({"type": "canonical_network_capability", "capability_name": "ports.discover"}, True),
    ({"type": "canonical_browser_capability", "capability_name": "browser.login_check"}, True),
    ({"type": "canonical_browser_capability", "capability_name": "browser.navigate"}, False),
    # 75 s: settles within the MCP hold, so it may share any slot.
    ({"type": "canonical_scanner_capability", "capability_name": "web.crawl"}, False),
    # An SSH command runs on the worker that holds its session and never waits for a slot.
    ({"type": "canonical_network_capability", "capability_name": "ssh.exec"}, False),
    ({"type": "request_collection_replay", "capability_name": "collections.replay_active"}, False),
    ({"type": "agent_scanner_tool", "timeout_ms": 300_000}, True),
    ({"type": "agent_scanner_tool", "timeout_ms": 30_000}, False),
    ({"type": "authentication_validation"}, False),
])
def test_which_jobs_are_long(job, long):
    assert jobs.long_job(job) is long


def test_the_long_capabilities_are_the_worker_actions_that_can_outlast_the_mcp_hold():
    assert jobs.long_capabilities() == {
        "browser.login_check", "ports.discover", "service.nse_check", "sqli.verify",
        "subdomains.discover", "templates.scan", "web.browser_crawl", "xss.verify",
    }


# --- Admission keeps one Hunt within the long slots ---------------------------------------------

class ReservationRows:
    """Unit fixture: answers admission's in-flight query from fixed rows, keeping its arguments."""

    def __init__(self, rows):
        self.rows, self.queries = rows, []

    async def fetch(self, sql, *args):
        self.queries.append((sql, args))
        return self.rows


def test_a_hunts_third_long_action_is_refused_without_anything_reserved_or_recorded():
    rows = [{"capability_name": "sqli.verify", "action_id": "a1"},
            {"capability_name": "templates.scan", "action_id": "a2"}]
    conn = ReservationRows(rows)
    with pytest.raises(HTTPException) as refused:
        asyncio.run(jobs.require_long_action_slot(conn, {"id": "hunt-1"}, "xss.verify"))
    assert refused.value.status_code == 429 and refused.value.headers == {"Retry-After": "60"}
    detail = refused.value.detail
    assert detail["reason_code"] == "long_actions_in_flight"
    assert detail["in_flight"] == [{"capability_name": "sqli.verify", "action_id": "a1"},
                                   {"capability_name": "templates.scan", "action_id": "a2"}]
    assert "same idempotency_key" in detail["message"] and "http.request" in detail["message"]
    # "Not now": nothing is recorded under the key, so the same call is sent again later.
    assert not refused.value.recorded and refused.value.kind is None
    ((sql, args),) = conn.queries
    assert args[0] == "hunt-1" and set(args[1]) == jobs.long_capabilities()
    assert "status IN ('reserved','running')" in sql and "lease_expires_at > NOW()" in sql
    assert "owner_kind='hunt'" in sql


def test_a_hunt_below_the_long_slots_and_any_short_call_are_admitted():
    one = ReservationRows([{"capability_name": "sqli.verify", "action_id": "a1"}])
    asyncio.run(jobs.require_long_action_slot(one, {"id": "hunt-1"}, "sqli.verify"))
    full = ReservationRows([{"capability_name": "sqli.verify", "action_id": "a1"},
                            {"capability_name": "sqli.verify", "action_id": "a2"}])
    for name in ("http.request", "artifact.inspect", "web.crawl", "candidate.verify", "ssh.exec"):
        asyncio.run(jobs.require_long_action_slot(full, {"id": "hunt-1"}, name))
    assert full.queries == []  # a short call never even counts


def test_hunt_admission_refuses_a_third_long_action_before_reserving_it(monkeypatch):
    """The real admission loop (the AST harness of test_hunt_authz_verification_limit) asks for a
    long slot before it reserves anything."""
    from tests import test_hunt_sqli_verify_input as sqli

    stores = []

    class TwoInFlight(sqli.AdmissionStore):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.long_in_flight = [{"capability_name": "sqli.verify", "action_id": "a1"},
                                   {"capability_name": "xss.verify", "action_id": "a2"}]
            stores.append(self)

    monkeypatch.setattr(sqli, "AdmissionStore", TwoInFlight)
    with pytest.raises(HTTPException) as refused:
        sqli._admit("/reports?filter=x")
    assert refused.value.status_code == 429
    assert refused.value.detail["reason_code"] == "long_actions_in_flight"
    (store,) = stores
    assert store.actions == {} and "verifications" in store.run["budget_used_json"]
    assert store.run["budget_used_json"] == {"verifications": 0}
    store.long_in_flight = store.long_in_flight[:1]
    monkeypatch.setattr(sqli, "AdmissionStore", lambda: store)
    admitted, reserved = sqli._admit("/reports?filter=x")
    assert len(admitted.actions) == 1 and reserved[0]["tool_wall_seconds"] == 1_200
