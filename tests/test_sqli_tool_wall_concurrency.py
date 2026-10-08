"""Concurrent SQLi candidates are charged the slice's elapsed tool wall, not a sum (soak N40).

Thorough scan 43b9a549 (honey, four SQLi candidates, state-changing allowed) ran two sqlmap
candidates side by side in every extension and charged each process its own seconds: 2,666
tool-wall seconds accounted in 1,349 s real per extension, 8,081 s accounted against about
4,089 s real for the lane. The plan's 10,800 s tool wall ran out at 77 of its 180 minutes, 43%
of its duration, with 3 of 4 candidates unfinished and 25,295 HTTP requests unused.

The budget contract keeps each profile's ``max_tool_wall_seconds`` at or below its
``max_duration_seconds`` (equal on Balanced and Thorough) for an orchestrator that runs one
action at a time, so tool wall is
elapsed time: a slice is charged the union of the intervals in which any candidate ran, and
candidates that run together share the slice's remaining wall rather than splitting it.

The sqlmap processes are the fake of tests/test_sqli_concurrent_candidates.py: every stage is
released by the test, and time is a virtual clock the fake advances by each stage's wall.
"""

from __future__ import annotations

import asyncio
import dataclasses
import uuid

import pytest

import scan.action_adapter as action_adapter_module
import scan.sqli_concurrency as sqli_concurrency
from scan.action_plan import ScanActionPlan
from scan.sqli_concurrency import CANDIDATE_CONCURRENCY_ARG, ConcurrentCandidates, SliceHolds

from tests.test_scan_action_adapter import TARGET, Backend, _action as plan_action
from tests.test_sqli_concurrent_candidates import (
    LATENCY,
    NEGATIVE_VERDICT,
    FakeSqlmap,
    _dispatcher,
    _drive,
    _manifests,
    _measured_on_target,
)

# One honey candidate's negative verdict, every technique: 182 + 300 + 496 + 652 s.
PER_CANDIDATE = sum(int(need * (LATENCY + 0.05)) for need in NEGATIVE_VERDICT.values())
PATHS = ("/c0", "/c1", "/c2", "/c3")


def test_the_slice_is_charged_the_union_of_its_running_intervals():
    now = [0.0]
    candidates = ConcurrentCandidates(
        {"http_requests": 100, "tool_wall_seconds": 100},
        bound=2, rate_ceiling=10.0, latency_seconds=1.0, clock=lambda: now[0],
    )
    releases = {key: asyncio.Event() for key in ("a", "b")}

    async def scenario() -> None:
        for key, hold in (("a", 60), ("b", 60)):
            async def work(key=key) -> None:
                await releases[key].wait()
            candidates.launch(key, {"http_requests": 40, "tool_wall_seconds": hold}, {}, work)
        await asyncio.sleep(0)
        # Both hold 60 s of a 100 s slice at once: requests are lent away, wall is not.
        assert candidates.holds.available({}) == {"http_requests": 20, "tool_wall_seconds": 100}
        now[0] = 30.0
        releases["a"].set()
        await candidates.wait()
        now[0] = 50.0
        assert candidates.busy_seconds() == pytest.approx(50.0)
        releases["b"].set()
        await candidates.finish()

    asyncio.run(scenario())
    # Two candidates ran 30 s and 50 s side by side: 50 s of the slice, not 80.
    assert candidates.busy_seconds() == pytest.approx(50.0)
    assert candidates.wall_shares(4) == 2 and candidates.wall_shares(1) == 1


def test_an_elapsed_dimension_is_never_lent_away():
    holds = SliceHolds({"http_requests": 10, "tool_wall_seconds": 10})
    holds.lend("a", {"http_requests": 6, "tool_wall_seconds": 10}, {})
    with pytest.raises(ValueError):
        holds.lend("b", {"http_requests": 6, "tool_wall_seconds": 1}, {})
    holds.lend("b", {"http_requests": 4, "tool_wall_seconds": 10}, {})
    assert holds.available({"tool_wall_seconds": 3}) == {"http_requests": 0, "tool_wall_seconds": 7}


def _run_slice(monkeypatch, *, wall: int):
    scan_id = str(uuid.uuid4())
    endpoints, candidates = _manifests(scan_id, PATHS)
    action = dataclasses.replace(
        plan_action(
            "verify.sqli.r01", "sqli.verify_batch", 0,
            capability_args={
                "candidate_manifest_ref": candidates.reference().canonical_dict(),
                "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
                "slice": {"start": 0, "count": len(PATHS)},
                "profile": "thorough_batch_v1",
                "proof_policy": "deterministic_differential_required",
                # Two at a time, as every Thorough extension of 43b9a549 ran.
                CANDIDATE_CONCURRENCY_ARG: 2,
            },
        ),
        requested_budget={"http_requests": 20_000, "tool_wall_seconds": wall},
        action_digest=None,
    )
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(action,),
    )
    backend = Backend(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates})
    _measured_on_target(backend, action.action_id)
    fake = FakeSqlmap()
    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", fake.execute)
    monkeypatch.setattr(sqli_concurrency, "elapsed_clock", lambda: fake.now[0], raising=False)
    receipt = asyncio.run(_drive(_dispatcher(plan, backend), plan, action, fake, release_together=True))
    return receipt, fake


def test_concurrent_candidates_finish_inside_a_wall_their_process_seconds_exceed(monkeypatch):
    """Four honey candidates need 4 x 1,630 = 6,520 process seconds. Two at a time they need
    3,260 s of the slice. A 3,400 s slice funds all four verdicts; charged per process, each
    candidate was cut to 3,400 / 4 = 850 s and every one was wall-killed at its third
    technique."""
    receipt, fake = _run_slice(monkeypatch, wall=3_400)

    assert fake.peak == 2
    attempts = [item for item in receipt.observations if item.get("kind") == "candidate_attempt"]
    assert sorted(item["status"] for item in attempts) == ["success"] * len(PATHS)
    for path in PATHS:
        assert [call["technique"] for call in fake.calls if call["path"] == path] == list("UBET")
    assert receipt.status == "success"
    # Charged the slice's elapsed time: two turns of one candidate's wall.
    assert receipt.budget_consumed["tool_wall_seconds"] == 2 * PER_CANDIDATE
    assert receipt.budget_consumed["tool_wall_seconds"] <= 3_400 < len(PATHS) * PER_CANDIDATE
    # The requests are still every request sent, summed.
    assert receipt.budget_consumed["http_requests"] == sum(NEGATIVE_VERDICT.values()) * len(PATHS)


def test_the_thorough_plan_math_of_43b9a549():
    """The arithmetic the fix is sized for, from the soak's own numbers."""
    plan_wall, other_lanes = 10_800, 8_672 - 8_081
    extension_wall, concurrency = 2_700, 2
    sqli_real = 584 + 1_349 + 1_256 + 900          # 4,089 s of elapsed SQLi time
    sqli_process = 8_081                            # what the per-process charge billed
    # Per-process: the plan is spent at 8,672 s and no 2,700 s extension fits the 2,128 left.
    assert plan_wall - (other_lanes + sqli_process) < extension_wall
    # Elapsed: the same work is billed 4,089 s, leaving room for two more full extensions.
    left = plan_wall - (other_lanes + sqli_real)
    assert left == 6_120 and left // extension_wall == 2
    # Each funds two candidates side by side: 10,800 more sqlmap process seconds, against the
    # 8,081 that already took one of four candidates to a verdict.
    assert 2 * extension_wall * concurrency == 10_800
