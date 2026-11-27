"""Root-domain hourly test ledger (api/domain_rate.py).

Ledger scenarios run against the unit-test mirror in ``tests/domain_rate_fake.py`` and, when
``SHAKERSCAN_TEST_REDIS_URL`` points at a disposable Redis (for example
``docker run --rm -p 16379:6379 redis:7.4-alpine`` then ``redis://127.0.0.1:16379/15``), against the
real Lua scripts, so the mirror cannot drift from the scripts it stands in for.
"""

from __future__ import annotations

import asyncio
import os
import sys
import types
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import domain_rate as dr  # noqa: E402
from tests.domain_rate_fake import DomainRateLedgerFake  # noqa: E402


class _RealRedis:
    """Real Redis with a controllable view of expiry: ``advance`` ages every entry instead."""

    def __init__(self, client):
        self.client = client

    def eval(self, *args):
        return self.client.eval(*args)

    def advance(self, seconds: float) -> None:
        for key in self.client.scan_iter(match=f"{dr._LEDGER_PREFIX}:*:expiry"):
            for member, score in self.client.zrange(key, 0, -1, withscores=True):
                self.client.zadd(key, {member: score - seconds * 1000})

    def entries(self, root_domain: str) -> dict[str, int]:
        raw = self.client.hgetall(dr.ledger_keys(root_domain)[1])
        return {k.decode(): int(v) for k, v in raw.items() if int(v) > 0}


def _backends():
    params = [pytest.param("fake", id="mirror")]
    params.append(pytest.param("redis", id="real-redis", marks=pytest.mark.skipif(
        not os.environ.get("SHAKERSCAN_TEST_REDIS_URL"),
        reason="set SHAKERSCAN_TEST_REDIS_URL to a disposable Redis to run the Lua itself",
    )))
    return params


@pytest.fixture(params=_backends())
def ledger(request):
    if request.param == "fake":
        return DomainRateLedgerFake()
    import importlib

    # Other suite modules install a ``redis`` stub; load the real client without disturbing them.
    stub = sys.modules.pop("redis", None)
    try:
        redis_lib = importlib.import_module("redis")
    finally:
        if stub is not None and not hasattr(stub, "Redis"):
            sys.modules["redis"] = stub
    client = redis_lib.Redis.from_url(os.environ["SHAKERSCAN_TEST_REDIS_URL"])
    for key in client.scan_iter(match=f"{dr._LEDGER_PREFIX}:*"):
        client.delete(key)
    return _RealRedis(client)


def _root() -> str:
    return f"{uuid.uuid4().hex[:8]}.example"


def test_reserve_clamps_to_headroom_and_tops_up_the_same_entry(ledger):
    root = _root()
    assert dr.reserve(ledger, root, entry_id="a", requested=600, headroom=1000) == (600, 600)
    assert dr.reserve(ledger, root, entry_id="b", requested=600, headroom=1000) == (400, 1000)
    # Re-reserving an entry is idempotent: it never takes a second hold.
    assert dr.reserve(ledger, root, entry_id="b", requested=600, headroom=1000) == (400, 1000)
    assert dr.reserve(ledger, root, entry_id="c", requested=1, headroom=1000) == (0, 1000)
    assert dr.usage(ledger, root) == 1000


def test_all_or_nothing_never_grants_a_partial_hold(ledger):
    root = _root()
    dr.reserve(ledger, root, entry_id="a", requested=95, headroom=100)
    assert dr.reserve(ledger, root, entry_id="shard", requested=10, headroom=100, all_or_nothing=True)[0] == 0
    assert dr.reserve(ledger, root, entry_id="shard", requested=5, headroom=100, all_or_nothing=True)[0] == 5


def test_operator_work_is_recorded_without_limit_and_background_backs_off(ledger):
    root = _root()
    held, total = dr.reserve(ledger, root, entry_id="op", requested=2500, headroom=1000, enforce=False)
    assert (held, total) == (2500, 2500)
    assert dr.reserve(ledger, root, entry_id="asm", requested=50, headroom=1000)[0] == 0


def test_settle_releases_the_unused_remainder_and_records_use_once(ledger):
    root = _root()
    dr.reserve(ledger, root, entry_id="scan", requested=600, headroom=1000)
    assert dr.settle(ledger, root, entry_id="scan", consumed=100) == (600, 100)
    assert dr.usage(ledger, root) == 100
    # A repeated settlement (retry, second scope) neither adds nor re-counts.
    assert dr.settle(ledger, root, entry_id="scan", consumed=None) == (0, 100)
    assert dr.settle(ledger, root, entry_id="scan", consumed=100) == (0, 100)
    assert dr.usage(ledger, root) == 100
    ledger.advance(50 * 60)
    assert dr.settle(ledger, root, entry_id="scan", consumed=100) == (0, 100)
    ledger.advance(11 * 60)
    assert dr.usage(ledger, root) == 0
    assert dr.settle(ledger, root, entry_id="scan", consumed=100) == (0, 0)
    assert dr.usage(ledger, root) == 0
    assert dr.reserve(ledger, root, entry_id="next", requested=900, headroom=1000)[0] == 900


def test_settle_of_an_unmeasured_run_keeps_what_it_held(ledger):
    root = _root()
    dr.reserve(ledger, root, entry_id="crashed", requested=300, headroom=1000)
    assert dr.settle(ledger, root, entry_id="crashed", consumed=None) == (300, 300)
    assert dr.usage(ledger, root) == 300


def test_preexecution_release_allows_the_same_waiting_scan_to_retry(ledger):
    root = _root()
    assert dr.reserve(ledger, root, entry_id="scan", requested=100, headroom=100)[0] == 100
    assert dr.settle(ledger, root, entry_id="scan", consumed=0, finalized=False) == (100, 0)
    assert dr.reserve(ledger, root, entry_id="scan", requested=100, headroom=100)[0] == 100
    assert dr.settle(ledger, root, entry_id="scan", consumed=40) == (100, 40)
    assert dr.usage(ledger, root) == 40


def test_abandoned_hold_expires_on_its_own(ledger):
    root = _root()
    dr.reserve(ledger, root, entry_id="lost-worker", requested=1000, headroom=1000)
    assert dr.reserve(ledger, root, entry_id="asm", requested=1, headroom=1000)[0] == 0
    ledger.advance(dr.HOLD_TTL_SECONDS + 1)
    assert dr.usage(ledger, root) == 0
    assert dr.reserve(ledger, root, entry_id="asm", requested=1, headroom=1000)[0] == 1


def test_busy_domain_decays_entry_by_entry(ledger):
    # The old counter refreshed one TTL on every grant, so steady traffic never let it decay.
    root = _root()
    dr.reserve(ledger, root, entry_id="a", requested=600, headroom=1000)
    dr.settle(ledger, root, entry_id="a", consumed=600)
    ledger.advance(50 * 60)
    dr.reserve(ledger, root, entry_id="b", requested=400, headroom=1000)
    dr.settle(ledger, root, entry_id="b", consumed=400)
    assert dr.usage(ledger, root) == 1000
    ledger.advance(11 * 60)
    assert dr.usage(ledger, root) == 400
    assert ledger.entries(root)["c:b"] == 400
    assert "c:a" not in ledger.entries(root)


def test_completed_asm_work_is_counted_once_not_in_both_windows(ledger):
    # ASM stamps tested endpoints in target_endpoints (the database window) and settles its hold
    # with only the unstamped remainder, so 50 tested endpoints cost 50, not 100.
    root = _root()
    dr.reserve(ledger, root, entry_id="batch", requested=50, headroom=100)
    dr.settle(ledger, root, entry_id="batch", consumed=0)
    decision = dr.admit(ledger, root_domain=root, cap=100, db_used=50, entry_id="next",
                        amount=50, work=dr.WORK_BACKGROUND)
    assert decision["granted"] == 50 and decision["limited"] is False


def test_ledger_state_reports_individual_expiries_for_resume_estimates(ledger):
    root = _root()
    dr.reserve(ledger, root, entry_id="a", requested=10, headroom=100)
    now_ms, total, schedule = dr.ledger_state(ledger, root)
    assert total == 10
    assert len(schedule) == 1
    assert schedule[0][1] == 10
    assert abs(schedule[0][0] - (now_ms + dr.HOLD_TTL_SECONDS * 1000)) < 5000


def test_redis_failure_fails_closed_for_background_and_open_for_operator():
    class Broken:
        def eval(self, *_args):
            raise ConnectionError("redis down")

    assert dr.reserve(Broken(), "example.com", entry_id="bg", requested=5, headroom=10) == (0, None)
    assert dr.reserve(Broken(), "example.com", entry_id="op", requested=5, headroom=10,
                      enforce=False) == (5, None)


def test_work_classification():
    assert dr.work_class({}) == dr.WORK_OPERATOR
    assert dr.work_class({"budget_profile": "fast"}) == dr.WORK_OPERATOR
    assert dr.work_class({"admission_origin": "schedule"}) == dr.WORK_BACKGROUND
    assert dr.work_class({"run_kind": "asm_batch"}) == dr.WORK_BACKGROUND
    assert dr.work_class({"run_kind": "asm_recon"}) == dr.WORK_BACKGROUND
    assert dr.work_class({"admission_origin": "operator-says-schedule"}) == dr.WORK_OPERATOR


def test_planned_endpoints_are_endpoints_never_http_requests():
    admission = types.SimpleNamespace(plan=types.SimpleNamespace(
        budget=types.SimpleNamespace(max_http_requests=10_000, max_endpoints=2_500),
        policy=types.SimpleNamespace(active_testing=True),
    ))

    def prepare(options):
        return dict(options), admission

    def dast(_options):
        return True

    assert dr.planned_endpoints({"request_budget_mode": "enforce"}, prepare=prepare, is_dast=dast) == 2_500
    assert dr.planned_endpoints({"custom_endpoints": ["GET /a", "GET /b"]}, prepare=prepare, is_dast=dast) == 2
    admission.plan.policy.active_testing = False
    assert dr.planned_endpoints({}, prepare=prepare, is_dast=dast) == 0


def test_settlement_scope_settles_however_the_job_ends():
    ledger = DomainRateLedgerFake()
    root = "example.com"

    async def job(outcome):
        dr.reserve(ledger, root, entry_id=outcome, requested=100, headroom=10_000)
        dr.track(root, outcome)
        if outcome == "never-started":
            return
        dr.mark_executing(outcome)
        if outcome == "measured":
            dr.measure(outcome, 7)
        if outcome == "failed":
            raise RuntimeError("scanner crashed")
        if outcome == "cancelled":
            raise asyncio.CancelledError()

    async def run(outcome):
        with dr.settlement_scope(lambda: ledger):
            await job(outcome)

    asyncio.run(run("never-started"))
    asyncio.run(run("measured"))
    with pytest.raises(RuntimeError):
        asyncio.run(run("failed"))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(run("cancelled"))
    assert {key: value for key, value in ledger.entries(root).items() if value > 0} == {
        # never-started released everything; measured recorded exactly 7; a failed or
        # cancelled run with no measurement keeps what it held (it may have sent traffic).
        "c:measured": 7, "c:failed": 100, "c:cancelled": 100,
    }


def test_waiting_record_and_public_view_explain_the_wait():
    decision = {"root_domain": "ukrtampa.com", "cap": 1000, "used": 0, "reserved": 1000,
                "requested": 10_000, "work_class": dr.WORK_BACKGROUND,
                "resume_at": "2026-09-27T16:40:00Z"}
    record = dr.waiting_record(decision, wait_cycles=3, since="2026-09-27T15:55:00Z")
    assert record["state"] == "waiting"
    assert record["resume_estimate"] == "2026-09-27T16:40:00Z"
    assert "ukrtampa.com's hourly test budget" in record["reason"]
    assert dr.public_view(record, status="queued")["state"] == "waiting"
    # Once the Scan runs, an old wait is history, not a current reason.
    assert dr.public_view(record, status="running")["state"] == "waited"
    assert dr.public_view({}, status="queued") is None
    assert dr.public_view('{"state": "admitted"}', status="running") == {"state": "admitted"}


def test_whole_or_nothing_work_requires_its_full_plan_to_fit_the_hourly_cap(ledger):
    root = _root()
    decision = dr.admit(ledger, root_domain=root, cap=1000, db_used=0, entry_id="scheduled",
                        amount=10_000, work=dr.WORK_BACKGROUND, all_or_nothing=True)
    assert decision["granted"] == 0 and decision["unadmittable"] is True
    assert decision["held"] == 0
    assert "Lower the Scan's max_endpoints" in dr.unadmittable_record(decision)["reason"]
    admitted = dr.admit(ledger, root_domain=root, cap=1000, db_used=0, entry_id="within-cap",
                        amount=1000, work=dr.WORK_BACKGROUND, all_or_nothing=True)
    assert admitted["granted"] == 1000 and admitted["held"] == 1000
    blocked = dr.admit(ledger, root_domain=root, cap=1000, db_used=0, entry_id="next",
                       amount=5, work=dr.WORK_BACKGROUND, all_or_nothing=True)
    assert blocked["granted"] == 0 and blocked["limited"] is True


def test_asm_reduction_is_recorded_in_metadata_and_coverage():
    reduction = dr.reduction_record({
        "granted": 20, "requested": 50, "root_domain": "ukrtampa.com", "cap": 1000,
    })
    assert reduction["dimension"] == "claimed_endpoints"
    assert "20 of 50" in reduction["reason"]
    result = {"scan_metadata": {"budget_used": {"http_requests": 3}},
              "coverage": {"status": "complete", "reasons": []}}
    dr.annotate_result(result, reduction)
    assert result["scan_metadata"]["domain_rate_reduction"] == reduction
    assert result["scan_metadata"]["budget_used"] == {"http_requests": 3}
    assert result["coverage"]["reasons"] == [reduction["reason"]]
    untouched = {"coverage": {"status": "complete", "reasons": []}}
    dr.annotate_result(untouched, None)
    assert untouched == {"coverage": {"status": "complete", "reasons": []}}


def test_tested_endpoints_reads_the_scanner_coverage_contract():
    assert dr.tested_endpoints({"coverage": {"active_execution": {"endpoints_tested": 42}}}) == 42
    assert dr.tested_endpoints({"coverage": {"active_execution": None}}) == 0
    assert dr.tested_endpoints({"error": "boom"}) is None


def test_resume_estimate_combines_database_window_and_ledger_expiries():
    ledger = DomainRateLedgerFake()
    root = "example.com"
    dr.reserve(ledger, root, entry_id="hold", requested=400, headroom=1000)

    class Conn:
        async def fetch(self, _query, *_args):
            # 600 endpoints stamped by ASM that leave the window 20 minutes from now.
            return [{"frees_at": ledger.now_ms + 20 * 60_000, "units": 600}]

    decision = {"root_domain": root, "cap": 1000, "requested": 50}
    estimate = asyncio.run(dr.resume_estimate(Conn(), ledger, decision))
    assert estimate == dr._iso(ledger.now_ms + 20 * 60_000)
    decision["all_or_nothing"] = True
    decision["requested"] = 700
    assert asyncio.run(dr.resume_estimate(Conn(), ledger, decision)) == dr._iso(
        ledger.now_ms + dr.HOLD_TTL_SECONDS * 1000
    )
