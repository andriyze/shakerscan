"""SQLi candidates of one slice run concurrently inside its reservation and pacing contract.

Soak scan 44e393ba (Balanced, honey at ~3.4 s per response) verified its four SQLi candidates
one request at a time, one candidate at a time: 731 requests over 2,580 tool-wall seconds while
the slice's pacing contract allowed about three times that rate, and the Scan's 3,600-second
limit stopped it with no verdict. These tests pin the bounded concurrency that fills that idle
time: the slot bound, the shared request gate that keeps the aggregate rate at the slice's
ceiling, the hold lent before any traffic, cancellation of every running candidate, per-technique
checkpoints and resume, and accounting that settles each candidate exactly once.

The process runner is a fake: every sqlmap stage is a pending call the test releases explicitly,
and "time" is the event loop yielding, never a sleep.
"""

from __future__ import annotations

import asyncio
import dataclasses
import uuid

import pytest

import scan.action_adapter as action_adapter_module
import scan.sqli_concurrency as sqli_concurrency
from hunt.capability_executor import CapabilityAdapterResult
from pinned_socks_proxy import PinnedSocksProxy
from runtime.models import ScanPolicy
from scan.action_plan import ScanActionPlan
from scan.sqli_concurrency import (
    CANDIDATE_CONCURRENCY_ARG,
    RequestRateGate,
    concurrent_slot_count,
    planned_candidate_concurrency,
    slice_rate_ceiling,
)
from scan.external_process import batch_attempt_floor
from scan.sqli_stages import STAGE_RECORD_KIND, stage_attempt_id
from scan.verification_extension import EXTENDS_ARG
from scan.work_manifests import build_candidate_manifest, build_endpoint_manifest
from tests.test_scan_action_adapter import TARGET, Backend, _action as plan_action, _lease, _noop
from tests.test_pinned_socks_proxy import _socks_connect

# honey's measured response time, and what each technique's negative verdict costs.
LATENCY = 3.4
NEGATIVE_VERDICT = {"U": 53, "B": 87, "E": 144, "T": 189}
# Six candidates at about 1,800 s each: enough wall for every negative verdict on honey.
SLICE = {"http_requests": 20_000, "tool_wall_seconds": 10_800}
QUERY_FLOOR = batch_attempt_floor("sqli.verify_batch")
BODY_FLOOR = batch_attempt_floor("sqli.verify_batch", body_candidate=True)


# --- unit: the bound, the ceiling and the gate ----------------------------------------------


def test_the_slots_are_bounded_by_the_profile_and_sized_by_the_pacing_contract():
    # The planner's bound is the Scan's worker ceiling, never above the process cap.
    assert planned_candidate_concurrency(4) == 4      # balanced
    assert planned_candidate_concurrency(8) == 4      # thorough: capped
    assert planned_candidate_concurrency(1) == 1      # force_single_worker
    # A Balanced body slice: one attempt, 480 mutations over 420 s, paced with the headroom.
    body = {"http_requests": 800, "state_changing_requests": 480, "tool_wall_seconds": 420}
    ceiling = slice_rate_ceiling(body, candidates=1, floors=[BODY_FLOOR])
    assert ceiling == pytest.approx(0.9 * 480 / 420)
    # Soak 0eb39a8a's Thorough slice: four candidates in 1,600 / 480 / 720. Its first body
    # attempt alone was paced at its floor's rate, so concurrency may not exceed that, and a
    # candidate running alone is not slowed below it.
    thorough = {"http_requests": 1_600, "state_changing_requests": 480, "tool_wall_seconds": 720}
    assert slice_rate_ceiling(
        thorough, candidates=4, floors=[QUERY_FLOOR, BODY_FLOOR],
    ) == pytest.approx(0.9 * max(400 / 180, 480 / 420))
    assert slice_rate_ceiling(
        thorough, candidates=4, floors=[BODY_FLOOR],
    ) == pytest.approx(0.9 * 480 / 420)
    # On honey one sqlmap candidate sends at most 1 / (3.4 + 0.05) a second: three fit.
    assert concurrent_slot_count(bound=4, rate_ceiling=ceiling, latency_seconds=LATENCY) == 3
    assert 3 / (LATENCY + 0.05) <= ceiling
    # A fast target: one candidate already reaches the ceiling, so nothing runs beside it.
    assert concurrent_slot_count(bound=4, rate_ceiling=ceiling, latency_seconds=0.1) == 1
    # Nothing measured yet, or a plan without the bound: one at a time, as before.
    assert concurrent_slot_count(bound=4, rate_ceiling=ceiling, latency_seconds=None) == 1
    assert concurrent_slot_count(bound=1, rate_ceiling=50.0, latency_seconds=LATENCY) == 1


def test_the_gate_spaces_every_concurrent_request_start_by_the_rate_ceiling():
    now = [0.0]
    starts: list[float] = []

    async def sleep(seconds: float) -> None:
        # A virtual clock: the caller resumes exactly at its start time.
        await asyncio.sleep(0)
        starts.append(now[0] + seconds)

    gate = RequestRateGate(2.0, clock=lambda: now[0], sleep=sleep)

    async def request() -> None:
        before = len(starts)
        await gate()
        if len(starts) == before:
            starts.append(now[0])

    async def scenario() -> None:
        await asyncio.gather(*(request() for _ in range(9)))

    asyncio.run(scenario())

    assert gate.admitted == 9
    ordered = sorted(starts)
    assert all(b - a >= 0.5 - 1e-9 for a, b in zip(ordered, ordered[1:]))
    # Over any window the aggregate is at most rate x window + the first request.
    assert ordered[-1] - ordered[0] >= (9 - 1) / 2.0 - 1e-9


def test_the_pinned_transport_waits_for_the_gate_before_each_target_connection():
    async def scenario() -> None:
        async def echo(reader, writer):
            await reader.read()
            writer.close()

        try:
            upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        except PermissionError:
            pytest.skip("the unit-test sandbox forbids loopback listeners")
        port = upstream.sockets[0].getsockname()[1]
        opened, reached = asyncio.Event(), asyncio.Event()
        calls = []

        async def admit() -> None:
            calls.append(len(calls))
            reached.set()
            await opened.wait()

        async with PinnedSocksProxy(
            hostname="owned.local", pinned_address="127.0.0.1", port=port,
            max_connections=5, admit=admit,
        ) as proxy:
            pending = asyncio.ensure_future(_socks_connect(proxy.proxy_url, "owned.local", port))
            await asyncio.wait_for(reached.wait(), timeout=5)
            # The connection is held at the gate: nothing reached the target yet.
            assert calls == [0]
            assert proxy.upstream_connection_attempts == 0
            opened.set()
            _reader, writer, code = await asyncio.wait_for(pending, timeout=5)
            assert code == 0
            assert proxy.upstream_connection_attempts == 1
            assert proxy.admitted_connections == 1
            writer.close()
        upstream.close()
        await upstream.wait_closed()

    asyncio.run(scenario())


# --- the adapter: a slice of candidates against a controllable fake sqlmap ------------------


def _manifests(scan_id: str, paths: tuple[str, ...]):
    endpoints = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [
                {
                    "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
                    "normalized_path": path, "concrete_path": path, "query_keys": ["q"],
                    "source": "web.crawl",
                }
                for path in paths
            ],
        },
        source_action_ids=("discover.web_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.web_crawl",), maximum=20,
    )
    return endpoints, candidates


def _plan(scan_id, endpoints, candidates, count, rounds, *, bound=4):
    args = {
        "candidate_manifest_ref": candidates.reference().canonical_dict(),
        "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
        "slice": {"start": 0, "count": count},
        "profile": "thorough_batch_v1", "proof_policy": "deterministic_differential_required",
        CANDIDATE_CONCURRENCY_ARG: bound,
    }
    actions = []
    for ordinal, (action_id, extends) in enumerate(rounds):
        actions.append(dataclasses.replace(
            plan_action(
                action_id, "sqli.verify_batch", ordinal,
                capability_args={**args, **({EXTENDS_ARG: extends} if extends else {})},
            ),
            requested_budget=dict(SLICE), action_digest=None,
        ))
    return ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=tuple(actions),
    )


def _measured_on_target(backend: Backend, action_id: str) -> None:
    """A stage another candidate finished on this target: its response time is known."""
    other = "f" * 64
    backend.attempts.setdefault(action_id, {})[stage_attempt_id(other, "U")] = {
        "attempt_id": stage_attempt_id(other, "U"), "candidate_id": "elsewhere",
        "status": "success", "timed_out": False,
        "budget_consumed": {"http_requests": 50, "tool_wall_seconds": int(50 * (LATENCY + 0.05))},
        "observations": ({"kind": STAGE_RECORD_KIND, "technique": "U", "delay_ms": 50},),
    }


class FakeSqlmap:
    """Every stage call waits until the test releases it; the fake records what ran when."""

    def __init__(self, *, cancelled=lambda: False, wall_killed=frozenset()):
        # A virtual clock: a stage that finishes moves it to its start plus the wall it took,
        # so concurrent stages overlap exactly as the slice's elapsed accounting sees them.
        self.now = [0.0]
        self.pending: list[tuple[asyncio.Event, dict]] = []
        self.running = 0
        self.peak = 0
        self.calls: list[dict] = []
        self.events: list[tuple[str, str]] = []
        self.gates: set[int] = set()
        self.cancelled = cancelled
        self.wall_killed = set(wall_killed)
        self.aborted = 0
        self.concurrent_holds: list[dict[str, int]] = []
        self._active: dict[int, dict[str, int]] = {}

    async def execute(self, context, adapter, **_kwargs):
        payload = adapter._process_payload
        path = payload["execution_target"].split("app.example.test", 1)[1].split("?")[0]
        technique = payload["scanner_options"]["technique"]
        budget = dict(context.requested_budget)
        gate = payload.get("_request_gate")
        if gate is not None:
            self.gates.add(id(gate))
        call = {"path": path, "technique": technique, "budget": budget, "gate": gate}
        self.calls.append(call)
        self.events.append(("stage", path))
        self.running += 1
        self.peak = max(self.peak, self.running)
        key = id(call)
        self._active[key] = budget
        total = {}
        for hold in self._active.values():
            for name, amount in hold.items():
                total[name] = total.get(name, 0) + amount
        self.concurrent_holds.append(total)
        release = asyncio.Event()
        self.pending.append((release, call))
        started = self.now[0]
        try:
            await release.wait()
        except asyncio.CancelledError:
            self.aborted += 1
            raise
        finally:
            self.running -= 1
            self._active.pop(key, None)
        if self.cancelled():
            return CapabilityAdapterResult(
                status="cancelled", errors=("cancelled",),
                actual_budget={"http_requests": 3, "tool_wall_seconds": 10},
                execution_started=True, parser_version="sqlmap-output/v1",
            )
        wall = int(budget["tool_wall_seconds"])
        need = NEGATIVE_VERDICT[technique]
        if (path, technique) in self.wall_killed:
            # Interrupted half-way through the stage at the target's rate (the worker was
            # stopped): it settles no verdict, and its own rate says the stage fits a resume.
            sent = need // 2
            took = int(sent * (LATENCY + 0.05))
            self.now[0] = max(self.now[0], started + took)
            return CapabilityAdapterResult(
                status="partial", partial=True, timed_out=True, errors=("timeout",),
                actual_budget={"http_requests": sent, "tool_wall_seconds": took},
                execution_started=True, parser_version="sqlmap-output/v1",
            )
        if int(need * (LATENCY + 0.05)) > wall or need > int(budget["http_requests"]):
            sent = int(wall / (LATENCY + 0.05))
            self.now[0] = max(self.now[0], started + wall)
            return CapabilityAdapterResult(
                status="partial", partial=True, timed_out=True, errors=("timeout",),
                actual_budget={"http_requests": sent, "tool_wall_seconds": wall},
                execution_started=True, parser_version="sqlmap-output/v1",
            )
        self.now[0] = max(self.now[0], started + int(need * (LATENCY + 0.05)))
        return CapabilityAdapterResult(
            status="success",
            actual_budget={"http_requests": need, "tool_wall_seconds": int(need * (LATENCY + 0.05))},
            execution_started=True, parser_version="sqlmap-output/v1",
        )


async def _quiesce() -> None:
    for _ in range(200):
        await asyncio.sleep(0)


def _dispatcher(plan, backend, *, cancelled=lambda: False, gate_enforced=True):
    async def process_runner(*_args, **_kwargs):
        raise AssertionError("the fake executor replaces the process runner")

    if gate_enforced:
        process_runner.enforces_request_gate = True
    return action_adapter_module.DatabaseNeutralScanActionDispatcher(
        target_url="https://app.example.test/", options={}, target=TARGET,
        policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
        scan_id=plan.scan_id, job_id="job-1", worker_id="broker:worker-1", plan=plan,
        backend=backend, process_runner=process_runner, cancelled=cancelled,
    )


async def _drive(
    dispatcher, plan, action, fake, *, release_together=False, release_reversed=False,
    on_step=None,
):
    task = asyncio.ensure_future(dispatcher(action, _lease(plan, action), _noop))
    while not task.done():
        await _quiesce()
        if on_step is not None and on_step(fake, task):
            await _quiesce()
        if task.done():
            break
        if not fake.pending:
            continue
        releasing = list(fake.pending) if release_together else [fake.pending[0]]
        if release_reversed and all(call["technique"] == "T" for _event, call in releasing):
            # The last technique: the candidates finish in the reverse of their slice order.
            releasing.reverse()
        for item in releasing:
            fake.pending.remove(item)
            item[0].set()
    return await task


def _receipt_for(monkeypatch, paths, *, bound=4, measured=True, gate_enforced=True, **drive):
    scan_id = str(uuid.uuid4())
    endpoints, candidates = _manifests(scan_id, paths)
    plan = _plan(scan_id, endpoints, candidates, len(paths), (("verify.sqli.r01", None),), bound=bound)
    backend = Backend(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates})
    if measured:
        _measured_on_target(backend, "verify.sqli.r01")
    fake = drive.pop("fake", None) or FakeSqlmap()
    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", fake.execute)
    monkeypatch.setattr(sqli_concurrency, "elapsed_clock", lambda: fake.now[0])
    dispatcher = _dispatcher(plan, backend, gate_enforced=gate_enforced, **drive.pop("dispatch", {}))
    receipt = asyncio.run(_drive(dispatcher, plan, plan.actions[0], fake, **drive))
    return receipt, fake, backend, plan


PATHS = tuple(f"/c{index}" for index in range(6))


def test_candidates_run_concurrently_up_to_the_bound_through_one_gate(monkeypatch):
    receipt, fake, _backend, _plan_ = _receipt_for(monkeypatch, PATHS)

    assert fake.peak == 4, "four of six candidates at once, never more"
    assert receipt.status == "success"
    # One gate for the whole slice, at the slice's pacing ceiling, handed to every process.
    assert len(fake.gates) == 1
    gate = fake.calls[0]["gate"]
    assert gate.rate_per_second == pytest.approx(
        slice_rate_ceiling(SLICE, candidates=len(PATHS), floors=[QUERY_FLOOR]),
    )
    # That is the rate one candidate of this slice was paced at when they ran one at a time.
    assert gate.rate_per_second == pytest.approx(0.9 * (20_000 // 6) / (10_800 // 6))
    # The candidates the slots allow stay inside that ceiling at the measured response time.
    assert fake.peak / (LATENCY + 0.05) <= gate.rate_per_second
    concurrency = receipt.redacted_execution["candidate_concurrency"]
    assert concurrency["bound"] == 4 and concurrency["peak"] == 4
    # Every candidate reached its verdict, cheapest technique first.
    for path in PATHS:
        assert [call["technique"] for call in fake.calls if call["path"] == path] == list("UBET")


def test_a_plan_without_the_bound_or_a_runner_without_the_gate_runs_one_at_a_time(monkeypatch):
    receipt, fake, _backend, _plan_ = _receipt_for(monkeypatch, PATHS[:3], bound=1)
    assert fake.peak == 1 and fake.gates == set()
    assert receipt.status == "success"

    receipt, fake, _backend, _plan_ = _receipt_for(monkeypatch, PATHS[:3], gate_enforced=False)
    assert fake.peak == 1 and fake.gates == set()


def test_one_candidate_runs_until_the_target_response_time_is_measured(monkeypatch):
    def first_step(fake, _task):
        if not hasattr(fake, "first_seen"):
            fake.first_seen = fake.running
        return False

    fake = FakeSqlmap()
    receipt, fake, _backend, _plan_ = _receipt_for(
        monkeypatch, PATHS[:4], measured=False, fake=fake, on_step=first_step,
    )
    assert fake.first_seen == 1, "nothing measured: one candidate"
    assert fake.peak == 4, "the first stage measured the target, the slots opened"
    assert receipt.status == "success"


def test_every_candidate_hold_is_lent_before_it_sends_anything(monkeypatch):
    lent = []
    original = sqli_concurrency.SliceHolds.lend

    def lend(self, key, hold, consumed):
        original(self, key, hold, consumed)
        lent.append(dict(hold))
        fake.events.append(("lend", str(len(lent))))

    monkeypatch.setattr(sqli_concurrency.SliceHolds, "lend", lend)
    fake = FakeSqlmap()
    receipt, fake, _backend, _plan_ = _receipt_for(monkeypatch, PATHS, fake=fake)

    assert receipt.status == "success"
    assert len(lent) == len(PATHS)
    # Each candidate's first stage comes after a hold was lent for it.
    stages_seen = lends_seen = 0
    first_stage = set()
    for kind, value in fake.events:
        if kind == "lend":
            lends_seen += 1
        elif value not in first_stage:
            first_stage.add(value)
            stages_seen += 1
            assert stages_seen <= lends_seen
    # What concurrent candidates held at once never exceeded the slice's reservation. Tool
    # wall is elapsed time (soak N40): candidates running at once hold the same seconds, so it
    # is each hold, not their sum, that stays inside the slice's wall.
    for total in fake.concurrent_holds:
        for name, amount in total.items():
            if name not in sqli_concurrency.ELAPSED_DIMENSIONS:
                assert amount <= SLICE[name]
    assert all(
        30 <= hold["tool_wall_seconds"] <= SLICE["tool_wall_seconds"] for hold in lent
    )


def test_cancellation_stops_every_running_candidate_and_starts_no_other(monkeypatch):
    stop = {"now": False}

    def cancel_when_full(fake, _task):
        if fake.running == 4 and not stop["now"]:
            stop["now"] = True
            fake.started_before_cancel = len(fake.calls)
        return False

    fake = FakeSqlmap(cancelled=lambda: stop["now"])
    receipt, fake, backend, plan = _receipt_for(
        monkeypatch, PATHS, fake=fake, on_step=cancel_when_full,
        release_together=True, dispatch={"cancelled": lambda: stop["now"]},
    )

    assert receipt.status == "cancelled"
    assert len(fake.calls) == fake.started_before_cancel == 4, "no candidate started after cancel"
    attempts = [item for item in receipt.observations if item.get("kind") == "candidate_attempt"]
    assert {item["status"] for item in attempts} == {"cancelled"} and len(attempts) == 4
    # A cancelled stage is not a verdict: nothing is checkpointed as finished.
    finished = [
        item for item in backend.attempts.get(plan.actions[0].action_id, {}).values()
        if item.get("status") == "success" and item.get("candidate_id") != "elsewhere"
    ]
    assert finished == []


def test_a_cancelled_action_abandons_every_running_candidate(monkeypatch):
    scan_id = str(uuid.uuid4())
    endpoints, candidates = _manifests(scan_id, PATHS)
    plan = _plan(scan_id, endpoints, candidates, len(PATHS), (("verify.sqli.r01", None),))
    backend = Backend(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates})
    _measured_on_target(backend, "verify.sqli.r01")
    fake = FakeSqlmap()
    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", fake.execute)
    dispatcher = _dispatcher(plan, backend)

    async def scenario() -> None:
        task = asyncio.ensure_future(dispatcher(plan.actions[0], _lease(plan, plan.actions[0]), _noop))
        await _quiesce()
        assert fake.running == 4
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert fake.running == 0

    asyncio.run(scenario())
    assert fake.aborted == 4


def test_concurrent_finishes_settle_each_candidate_once_and_match_its_traffic(monkeypatch):
    receipt, fake, backend, plan = _receipt_for(
        monkeypatch, PATHS, release_together=True, release_reversed=True,
    )

    assert fake.peak == 4, "the candidates finished concurrently"
    sent = sum(NEGATIVE_VERDICT.values()) * len(PATHS)
    per_candidate = sum(int(need * (LATENCY + 0.05)) for need in NEGATIVE_VERDICT.values())
    assert receipt.budget_consumed["http_requests"] == sent
    # Tool wall is the slice's elapsed time (soak N40): four candidates side by side, then the
    # last two -- two turns of one candidate's wall, not six candidates' process seconds.
    assert receipt.budget_consumed["tool_wall_seconds"] == 2 * per_candidate
    assert receipt.budget_consumed["tool_wall_seconds"] < per_candidate * len(PATHS)
    assert receipt.redacted_execution["attempted_count"] == len(PATHS)
    attempts = [item for item in receipt.observations if item.get("kind") == "candidate_attempt"]
    assert len(attempts) == len(PATHS)
    assert len({item["candidate_id"] for item in attempts}) == len(PATHS)
    # Records keep the slice's order although the candidates finished in reverse.
    urls = [
        item["url"].split("app.example.test", 1)[1].split("?")[0]
        for item in receipt.observations if item.get("kind") == STAGE_RECORD_KIND
    ]
    slice_order = list(dict.fromkeys(call["path"] for call in fake.calls))
    assert sorted(slice_order) == list(PATHS)
    assert list(dict.fromkeys(urls)) == slice_order
    stored = backend.attempts[plan.actions[0].action_id]
    stage_ids = {
        stage_attempt_id(attempt["attempt_id"], technique)
        for attempt in attempts for technique in NEGATIVE_VERDICT
    }
    # One checkpoint per technique per candidate: none lost, none written twice.
    assert stage_ids <= set(stored)
    assert len([key for key in stored if key in stage_ids]) == 4 * len(PATHS)
    candidate_checkpoints = [item for item in stored.values() if item["attempt_id"] in {
        attempt["attempt_id"] for attempt in attempts
    }]
    assert len(candidate_checkpoints) == len(PATHS)


def test_a_wall_killed_candidate_is_not_counted_as_tested(monkeypatch):
    fake = FakeSqlmap(wall_killed={("/c2", "E")})
    receipt, fake, _backend, _plan_ = _receipt_for(monkeypatch, PATHS[:4], fake=fake)

    assert fake.peak == 4
    assert receipt.status == "partial"
    assert receipt.timed_out is True
    attempts = {
        item["candidate_id"]: item for item in receipt.observations
        if item.get("kind") == "candidate_attempt"
    }
    killed = [item for item in attempts.values() if item["status"] != "success"]
    assert len(killed) == 1 and killed[0]["status"] == "partial"
    assert sum(1 for item in attempts.values() if item["status"] == "success") == 3


def test_checkpoints_and_resume_stay_per_technique_under_concurrency(monkeypatch):
    scan_id = str(uuid.uuid4())
    paths = ("/c0", "/c1", "/slow")
    endpoints, candidates = _manifests(scan_id, paths)
    plan = _plan(scan_id, endpoints, candidates, 3, (
        ("verify.sqli.r01", None), ("verify.sqli.r01.ext.r02", "verify.sqli.r01"),
    ))
    backend = Backend(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates})
    _measured_on_target(backend, "verify.sqli.r01")
    first = FakeSqlmap(wall_killed={("/slow", "E")})
    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", first.execute)
    dispatcher = _dispatcher(plan, backend)
    slice_receipt = asyncio.run(_drive(dispatcher, plan, plan.actions[0], first))
    assert first.peak == 3 and slice_receipt.timed_out is True

    second = FakeSqlmap()
    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", second.execute)
    extension = asyncio.run(_drive(dispatcher, plan, plan.actions[1], second))

    # The finished candidates are carried; the slow one resumes at the interrupted technique,
    # and the techniques it finished concurrently with the others are never re-sent.
    assert [(call["path"], call["technique"]) for call in second.calls] == [
        ("/slow", "E"), ("/slow", "T"),
    ]
    assert extension.status == "success"
    assert extension.redacted_execution["carried_count"] == 2


@pytest.mark.parametrize(("profile", "advanced", "expected"), [
    ("balanced", None, 4),
    ("thorough", None, 4),
    ("fast", None, 2),
    ("balanced", {"force_single_worker": True}, 1),
])
def test_every_sqli_slice_records_the_scan_worker_ceiling(profile, advanced, expected):
    from runtime.models import TargetBinding
    from scan.action_plan import ScanActionPlanCompiler
    from scan.contracts import resolve_scan_contract

    contract = resolve_scan_contract(
        budget_profile=profile,
        policy={
            "preset": "custom", "active_testing": True,
            "include_families": ["recon", "sqli"],
            "exclude_families": [
                "nuclei_passive", "nuclei_active", "xss", "bola",
                "sensitive_exposure", "nosqli", "authz_surface",
            ],
        },
        advanced=advanced,
        approval_receipt_id="11111111-1111-4111-8111-111111111111",
    )
    plan = ScanActionPlanCompiler().compile(
        scan_id=str(uuid.UUID("10000000-0000-4000-8000-000000000001")),
        execution_plan=contract.execution_plan,
        target_binding=TargetBinding(
            target_id="t1", target_kind="web", canonical_host="example.test",
            allowed_origins=("https://example.test",), allowed_addresses=("192.0.2.10",),
            allowed_root_domains=("example.test",),
        ),
    )
    slices = [action for action in plan.actions if action.capability_name == "sqli.verify_batch"]
    assert slices
    assert {action.capability_args[CANDIDATE_CONCURRENCY_ARG] for action in slices} == {expected}
