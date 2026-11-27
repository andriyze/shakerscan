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
# (http.request, artifact.inspect) timed out in the queue. A long job (a reserved wall over a
# minute) now takes one of at most two long slots; one leased while both are taken waits in its
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
    # 75 s: longer than a short call queued behind it in the slot left to short work could wait.
    ({"type": "canonical_scanner_capability", "capability_name": "web.crawl"}, True),
    ({"type": "canonical_scanner_capability", "capability_name": "web.content_discover"}, True),
    # A service fingerprint reserves 120 s per address (nmap's host timeout), 240 s on a dual-stack
    # host; the registry's 90 s already makes it long, and its payload's reserved wall says so too.
    ({"type": "canonical_network_capability", "capability_name": "service.fingerprint",
      "expected_budget": {"tool_wall_seconds": 240}}, True),
    ({"type": "canonical_network_capability", "capability_name": "service.fingerprint"}, True),
    # 60 s: still short work.
    ({"type": "canonical_http_capability", "capability_name": "authz.verify",
      "expected_budget": {"tool_wall_seconds": 60}}, False),
    # A call is long by the wall admission reserved for it, whatever the registry says.
    ({"type": "canonical_scanner_capability", "capability_name": "web.probe"}, False),
    ({"type": "canonical_scanner_capability", "capability_name": "web.probe",
      "reserved_wall_seconds": 120}, True),
    ({"type": "canonical_http_capability", "capability_name": "http.request",
      "expected_budget": {"tool_wall_seconds": 61}}, True),
    # A malformed reserved wall is no wall: the registry's decides.
    ({"type": "canonical_scanner_capability", "capability_name": "web.probe",
      "reserved_wall_seconds": True}, False),
    ({"type": "canonical_scanner_capability", "capability_name": "web.probe",
      "reserved_wall_seconds": "600"}, False),
    ({"type": "canonical_scanner_capability", "capability_name": "web.probe",
      "reserved_wall_seconds": float("nan"), "expected_budget": []}, False),
    # An SSH command runs on the worker that holds its session and never waits for a slot.
    ({"type": "canonical_network_capability", "capability_name": "ssh.exec",
      "expected_budget": {"tool_wall_seconds": 332}}, False),
    ({"type": "request_collection_replay", "capability_name": "collections.replay_active"}, False),
    ({"type": "agent_scanner_tool", "timeout_ms": 300_000}, True),
    ({"type": "agent_scanner_tool", "timeout_ms": 30_000}, False),
    ({"type": "authentication_validation"}, False),
])
def test_which_jobs_are_long(job, long):
    assert jobs.long_job(job) is long


def test_the_long_capabilities_are_the_worker_actions_whose_registry_wall_exceeds_a_minute():
    assert jobs.LONG_ACTION_WALL_SECONDS == 60
    assert jobs.long_capabilities() == {
        "browser.login_check", "ports.discover", "service.fingerprint", "service.nse_check",
        "sqli.verify", "subdomains.discover", "templates.scan", "web.browser_crawl",
        "web.content_discover", "web.crawl", "xss.verify",
    }
    assert jobs.long_capabilities() < jobs.slot_capabilities()
    assert not jobs.slot_capabilities() & {"ssh.connect", "ssh.exec", "ssh.close", "candidate.verify"}


def test_a_short_call_queued_behind_one_short_action_still_starts_within_its_reservation_lease():
    """Short work shares the slot long actions leave, so a short call may wait for one short
    action there. A worker refuses a job whose reservation lease ran out before it started, so
    every short action's lease must outlast the longest short action ahead of it, with room for
    the queue's own delay."""
    from api.hunt.capability_reservations import hunt_capability_lease_seconds
    from api.runtime.capability_registry import CAPABILITY_REGISTRY

    short = sorted(jobs.slot_capabilities() - jobs.long_capabilities())
    assert {"http.request", "artifact.inspect", "javascript.analyze", "authz.verify",
            "browser.navigate", "web.probe"} <= set(short)
    for name in short:
        lease = hunt_capability_lease_seconds(CAPABILITY_REGISTRY.require(name).budget_cost)
        assert lease - jobs.LONG_ACTION_WALL_SECONDS >= 30, (name, lease)


def test_a_dual_stack_service_fingerprint_beside_two_long_actions_leaves_short_calls_a_slot():
    """A service fingerprint reserves 240 s on a dual-stack host. Counted as short, it took the
    slot left to short work beside two long actions, and an http.request queued behind it waited
    for the fingerprint to end."""
    async def run():
        queue = Jobs()
        for label, name in (("long-1", "sqli.verify"), ("long-2", "xss.verify")):
            await queue.lease_and_dispatch(_job(label, name))
        await queue.lease_and_dispatch({
            "label": "fingerprint", "type": "canonical_network_capability",
            "capability_name": "service.fingerprint", "expected_budget": {"tool_wall_seconds": 240}})
        assert queue.started == ["long-1", "long-2"] and jobs._waiting == 1
        await asyncio.wait_for(queue.lease_and_dispatch(_job("short", "http.request")), 1)
        assert queue.started[-1] == "short"
        for gate in queue.release.values():
            gate.set()
        await jobs.close()
    _bounded(run)


def test_the_worker_loop_leases_a_short_job_right_after_dispatching_a_long_one_that_waits():
    """The worker loop (worker.async_main) leases again as soon as dispatch returns, before the
    job it dispatched has run at all: on a single host nothing in between yields. A third long job
    has therefore not started waiting for a long slot when the next lease checks for a free slot,
    and only its wake when it does start waiting lets the loop lease the short job queued behind
    it. This loop has the worker's shape: lease, dispatch, lease, with nothing in between."""
    queued = [_job("long-1", "sqli.verify"), _job("long-2", "templates.scan"),
              _job("long-3", "xss.verify"), _job("short", "http.request")]
    started, gates = [], {}

    async def execute(redis, lease, job):
        async def work(job):
            started.append(job["label"])
            gates[job["label"]] = gate = asyncio.Event()
            await gate.wait()
        await jobs.in_lane(job, work)

    async def loop():
        while queued:
            job = await jobs.lease_when_ready(lambda: queued.pop(0), enabled=True)
            await jobs.dispatch(None, None, job, execute=execute, enabled=True)

    async def run():
        worker_loop = asyncio.create_task(loop())
        try:
            for _ in range(200):
                if "short" in started:
                    break
                await asyncio.sleep(0.005)
            assert started == ["long-1", "long-2", "short"] and jobs._waiting == 1
        finally:
            for gate in gates.values():
                gate.set()
            worker_loop.cancel()
            await asyncio.gather(worker_loop, return_exceptions=True)
    _bounded(run)


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
    assert args[0] == "hunt-1" and set(args[1]) == jobs.slot_capabilities()
    # A live reservation counts as long by its capability or by the wall it reserved.
    assert set(args[2]) == jobs.long_capabilities() and args[3] == jobs.LONG_ACTION_WALL_SECONDS
    assert "(requested_json->>'tool_wall_seconds')::numeric > $4" in sql
    assert "status IN ('reserved','running')" in sql and "lease_expires_at > NOW()" in sql
    assert "owner_kind='hunt'" in sql


def test_a_hunt_below_the_long_slots_and_any_short_call_are_admitted():
    one = ReservationRows([{"capability_name": "sqli.verify", "action_id": "a1"}])
    asyncio.run(jobs.require_long_action_slot(one, {"id": "hunt-1"}, "sqli.verify"))
    full = ReservationRows([{"capability_name": "sqli.verify", "action_id": "a1"},
                            {"capability_name": "sqli.verify", "action_id": "a2"}])
    for name, wall in (("http.request", 15), ("artifact.inspect", 30), ("authz.verify", 60),
                       ("browser.navigate", 30), ("candidate.verify", 180), ("ssh.exec", 332)):
        asyncio.run(jobs.require_long_action_slot(full, {"id": "hunt-1"}, name, wall))
    assert full.queries == []  # a short call never even counts
    # A call is long by the wall it reserves: a crawl, a fingerprint, or any worker action held
    # longer than a minute.
    for name, wall in (("web.crawl", 75), ("service.fingerprint", 240), ("web.probe", 120)):
        with pytest.raises(HTTPException) as refused:
            asyncio.run(jobs.require_long_action_slot(full, {"id": "hunt-1"}, name, wall))
        assert refused.value.detail["reason_code"] == "long_actions_in_flight"


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


def test_admission_classifies_the_call_by_the_wall_it_is_about_to_reserve():
    """Structural pin for a unit run: the admission loop hands its own reserved wall to the long
    slot check (tests/test_hunt_long_actions_postgres.py runs admission on PostgreSQL)."""
    import ast
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "api/hunt/interaction_router.py").read_text()
    lifecycle = next(node for node in ast.walk(ast.parse(source))
                     if isinstance(node, ast.AsyncFunctionDef)
                     and node.name == "_execute_hunt_capability_lifecycle")
    (check,) = [call for call in ast.walk(lifecycle) if isinstance(call, ast.Call)
                and getattr(call.func, "id", None) == "require_long_action_slot"]
    assert ast.unparse(check) == (
        "require_long_action_slot(conn, run, name, charges.get('tool_wall_seconds'), "
        "workers=live_agent_tool_workers(get_redis))")



# --- Lanes: short calls are leased whatever long work is queued ---------------------------------
#
# Owner decision E: three local slots, two long actions running and eight long jobs waiting used to
# stop the worker leasing anything, short calls included, until one of the waiting started. Short
# calls now have a lane of their own, leased first and always while a slot is free. Unit fixtures:
# the queues are lists keyed by lane, leased in the order the worker asks for them.

BASE = "agent_tool_jobs"


class Lanes:
    """The agent-tool queue and its short lane (unit fixture): ``lease(keys)`` takes the first job
    of the first non-empty queue in ``keys``, as ``job_queue.lease_job`` probes them in order."""

    def __init__(self):
        self.queues = {jobs.short_lane(BASE): [], BASE: []}
        self.asked: list[list[str]] = []

    def enqueue(self, job):
        self.queues[jobs.lane_queue(BASE, job)].append(job)

    def lease(self, keys):
        self.asked.append(list(keys))
        for key in keys:
            if self.queues.get(key):
                return self.queues[key].pop(0)
        return None


def test_a_short_call_is_queued_on_its_own_lane_and_a_long_action_on_the_agent_tool_queue():
    short = jobs.short_lane(BASE)
    assert short == "agent_tool_jobs:short"
    assert jobs.lane_queue(BASE, _job("s", "http.request")) == short
    assert jobs.lane_queue(BASE, _job("a", "artifact.inspect")) == short
    assert jobs.lane_queue(BASE, {"type": "canonical_browser_capability", "capability_name": "browser.navigate"}) == short
    assert jobs.lane_queue(BASE, _job("l", "sqli.verify")) == BASE
    assert jobs.lane_queue(BASE, {"type": "canonical_scanner_capability", "capability_name": "web.probe",
                                  "reserved_wall_seconds": 120}) == BASE
    # Other agent-tool jobs (a replay, a legacy scanner) keep the agent-tool queue.
    assert jobs.lane_queue(BASE, {"type": "request_collection_replay"}) == BASE
    assert jobs.lane_queue(BASE, {"type": "agent_scanner_tool", "timeout_ms": 1_000}) == BASE


def test_the_agent_tool_worker_polls_the_short_lane_first():
    from api.worker_queue_policy import base_worker_queue_keys

    assert base_worker_queue_keys(
        device_only=False, agent_tool_only=True, device_queue_enabled=False, scan_queue="scan_jobs",
        retest_queue="retest_jobs", broker_queue="broker_ingest_jobs", device_queue="device_jobs",
        agent_tool_queue=BASE,
    ) == ["agent_tool_jobs:short", BASE]


def test_short_calls_are_leased_under_a_long_backlog():
    """Twelve long actions queued, then short calls: two long run, eight wait (the cap), and the
    worker still leases every short call as a slot frees, while the rest of the long backlog
    stays queued until a waiting one starts."""
    lanes = Lanes()
    started, gates = [], {}
    for index in range(12):
        lanes.enqueue(_job(f"long-{index}", "templates.scan"))

    async def execute(redis, lease, job):
        async def work(job):
            started.append(job["label"])
            gates[job["label"]] = gate = asyncio.Event()
            await gate.wait()
        await jobs.in_lane(job, work)

    async def worker():
        keys = [jobs.short_lane(BASE), BASE]
        while True:
            job = await jobs.lease_by_lane(lambda names: lanes.lease(names), keys, base_queue=BASE, enabled=True)
            if job is None:
                await asyncio.sleep(0.005)
                continue
            await jobs.dispatch(None, None, job, execute=execute, enabled=True)

    async def until(condition):
        for _ in range(400):
            if condition():
                return
            await asyncio.sleep(0.005)
        raise AssertionError(f"not reached: started={started} waiting={jobs._waiting}")

    async def run():
        loop = asyncio.create_task(worker())
        try:
            await until(lambda: jobs._waiting == jobs.MAX_WAITING_LONG_AGENT_JOBS)
            assert started == ["long-0", "long-1"]
            assert len(lanes.queues[BASE]) == 12 - 2 - jobs.MAX_WAITING_LONG_AGENT_JOBS
            # At the cap the worker asks the short lane only.
            await until(lambda: lanes.asked and lanes.asked[-1] == [jobs.short_lane(BASE)])
            for index in range(3):
                lanes.enqueue(_job(f"short-{index}", "http.request"))
                await until(lambda index=index: f"short-{index}" in started)
                gates[f"short-{index}"].set()
            # The long backlog has not moved meanwhile.
            assert len(lanes.queues[BASE]) == 12 - 2 - jobs.MAX_WAITING_LONG_AGENT_JOBS
            # A long slot frees: a waiting one starts, and the worker takes long work again.
            gates["long-0"].set()
            await until(lambda: sum(label.startswith("long-") for label in started) == 3
                        and len(lanes.queues[BASE]) == 1)
        finally:
            for gate in gates.values():
                gate.set()
            loop.cancel()
            with pytest.raises(asyncio.CancelledError):
                await loop
    _bounded(run)


def test_without_lanes_a_long_backlog_stopped_short_calls():
    """The behaviour the lanes replace, kept as the control: one queue, leased in order, stops at
    the waiting cap and never reaches a short call behind the backlog."""
    queued = [_job(f"long-{index}", "templates.scan") for index in range(12)] + [_job("short", "http.request")]
    started, gates = [], {}

    async def execute(redis, lease, job):
        async def work(job):
            started.append(job["label"])
            gates[job["label"]] = gate = asyncio.Event()
            await gate.wait()
        await jobs.in_lane(job, work)

    async def worker():
        while queued:
            job = await jobs.lease_when_ready(lambda: queued.pop(0), enabled=True)
            await jobs.dispatch(None, None, job, execute=execute, enabled=True)

    async def run():
        loop = asyncio.create_task(worker())
        try:
            await asyncio.sleep(0.2)
            assert "short" not in started and jobs._waiting == jobs.MAX_WAITING_LONG_AGENT_JOBS
        finally:
            for gate in gates.values():
                gate.set()
            loop.cancel()
            with pytest.raises(asyncio.CancelledError):
                await loop
    _bounded(run)


@pytest.mark.parametrize("workers,allowed", [(0, 2), (1, 2), (2, 4), (3, 6), (8, 16), (50, 16)])
def test_a_hunts_long_actions_scale_with_the_live_workers(workers, allowed):
    assert jobs.long_actions_per_hunt(workers) == allowed
    in_flight = [{"capability_name": "sqli.verify", "action_id": f"a{index}"} for index in range(allowed - 1)]
    asyncio.run(jobs.require_long_action_slot(ReservationRows(in_flight), {"id": "h"}, "sqli.verify",
                                              workers=workers))
    full = ReservationRows([*in_flight, {"capability_name": "xss.verify", "action_id": "last"}])
    with pytest.raises(HTTPException) as refused:
        asyncio.run(jobs.require_long_action_slot(full, {"id": "h"}, "sqli.verify", workers=workers))
    assert refused.value.detail["max_long_actions_in_flight"] == allowed


def test_live_agent_tool_workers_counts_fresh_reports_only():
    from datetime import datetime, timedelta, timezone

    now = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)

    def report(age):
        return json.dumps({"reported_at": (now - timedelta(seconds=age)).isoformat()})

    class Registry:
        def __init__(self, reports):
            self.reports = reports

        def hgetall(self, key):
            assert key == jobs.AGENT_TOOL_WORKER_REGISTRY_KEY
            return self.reports

    fresh = {b"w1": report(10).encode(), "w2": report(100), "w3": report(500), "w4": "not json",
             "w5": json.dumps({"reported_at": None})}
    assert jobs.live_agent_tool_workers(Registry(fresh), now=now.timestamp()) == 2
    assert jobs.live_agent_tool_workers(Registry({}), now=now.timestamp()) == 1
    assert jobs.live_agent_tool_workers(None) == 1  # no registry to read: one worker
