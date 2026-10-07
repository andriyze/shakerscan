"""A required passive-pack batch finishes over a slow endpoint, and says so truthfully when not.

Soak 2026-10-07 (146b6c03 Balanced, da4c0531 Thorough): the required `passive.templates.r01`
batch settled `timed_out` with 126/126 (175/175) requests charged in 88 of 216 (118 of 300)
seconds, keeping every honey grade starred. The checkpoints show what happened: every
endpoint was attempted and charged the pack's seven requests (its TLS traffic has no wire
count), the fast endpoints finished in ~3 s, and the slow AI endpoint -- seven sequential
GETs at ~3.7 s, which take ~23 s in the scanner image against a 3-second origin -- was
wall-killed at its even-split 12-13 s share with no output. Its empty-timeout retry then
found the request hold spent, so the endpoint stayed unexamined and the batch blamed the
wall. The transport never stopped anything (`connection_limit_exceeded` never fired), which
is why the request-ceiling reason added by PR #337 never appeared.
"""

from __future__ import annotations

import asyncio
import dataclasses
import uuid

from hunt.capability_executor import CapabilityAdapterResult
from runtime.models import ScanPolicy
import scan.action_adapter as action_adapter_module
from scan.action_plan import ScanActionPlan, passive_batch_request_hold
from scan.capability_result import CapabilityResultReason, CapabilityResultStatus
from scan.execution_backend import PostgresScanExecutionBackend
from scan.work_manifests import (
    build_canonical_passive_nuclei_template_manifest,
    build_endpoint_manifest,
)
from tests.test_scan_action_adapter import TARGET, Backend, _action, _dispatcher, _lease, _noop

PACK = 7
SLOW_PACK_SECONDS = 26  # seven GETs at ~3.7 s


def _batch(paths, budget):
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [
                {
                    "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
                    "normalized_path": path, "concrete_path": path, "query_keys": [],
                    "source": "web.crawl",
                }
                for path in paths
            ],
        },
        source_action_ids=("discover.web_crawl",),
    )
    templates = build_canonical_passive_nuclei_template_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
    )
    action = dataclasses.replace(
        _action(
            "passive.templates.r01", "templates.passive_batch", 0,
            capability_args={
                "target_manifest_ref": endpoints.reference().canonical_dict(),
                "template_manifest_ref": templates.reference().canonical_dict(),
                "slice": {"start": 0, "count": len(paths)},
                "profile": "balanced_batch_v1",
            },
        ),
        requested_budget=dict(budget), action_digest=None,
    )
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(action,),
    )
    backend = Backend(manifests={
        endpoints.manifest_id: endpoints, templates.manifest_id: templates,
    })
    return plan, action, backend


def _pack_attempt(path, granted, *, slow_paths):
    """The worker's result for one pack attempt, charged the pack's full seven requests."""
    needed = SLOW_PACK_SECONDS if path in slow_paths else 3
    wall = int(granted["tool_wall_seconds"])
    if wall < needed:
        return CapabilityAdapterResult(
            status="partial", timed_out=True, partial=True, errors=("timeout",),
            actual_budget={"http_requests": PACK, "tool_wall_seconds": wall},
            execution_started=True, parser_version="nuclei-jsonl/v1",
        )
    return CapabilityAdapterResult(
        status="success",
        observations=({
            "kind": "template_match", "template_id": "http-missing-security-headers",
            "severity": "info", "matched_at": f"https://app.example.test{path}",
        },),
        actual_budget={"http_requests": PACK, "tool_wall_seconds": needed},
        execution_started=True, parser_version="nuclei-jsonl/v1",
    )


def _run(
    monkeypatch, paths, budget, *, slow_paths=frozenset(), stalls_once=frozenset(),
    slow_position=None,
):
    plan, action, backend = _batch(paths, budget)
    calls: list[tuple[str, int]] = []
    slow_paths = set(slow_paths)

    async def execute(_self, context, adapter, **_kwargs):
        path = adapter._process_payload["execution_target"].split("app.example.test", 1)[1]
        granted = dict(context.requested_budget)
        if slow_position is not None and len(calls) == slow_position:
            # The endpoint attempted at this position (in the manifest's own order) is slow.
            slow_paths.add(path)
        calls.append((path, int(granted["tool_wall_seconds"])))
        if path in stalls_once and [seen for seen, _ in calls].count(path) == 1:
            # A host hiccup: the first attempt reports nothing before its wall.
            return _pack_attempt(path, {**granted, "tool_wall_seconds": 0}, slow_paths={path})
        return _pack_attempt(path, granted, slow_paths=slow_paths)

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    dispatcher = _dispatcher(plan, backend, policy=ScanPolicy())
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    return receipt, calls


def _outcome(receipt):
    backend = object.__new__(PostgresScanExecutionBackend)
    return backend._receipt_outcome(receipt)


SOAK_PATHS = tuple(f"/route-{index:02d}" for index in range(18))


def test_a_slow_endpoint_takes_the_wall_fast_endpoints_left_and_the_baseline_completes(monkeypatch):
    # 146b6c03's slice: 18 endpoints, 216 s; the 4th endpoint attempted is the slow one.
    budget = {"http_requests": passive_batch_request_hold(18), "tool_wall_seconds": 216}
    receipt, calls = _run(monkeypatch, SOAK_PATHS, budget, slow_position=3)

    slow = calls[3][0]
    slow_walls = [wall for path, wall in calls if path == slow]
    assert slow_walls[0] >= SLOW_PACK_SECONDS, slow_walls
    # Every later endpoint still had at least its planned 12-second share.
    assert min(wall for path, wall in calls if path != slow) >= 216 // 18
    assert receipt.status == "success" and receipt.timed_out is False
    assert receipt.redacted_execution["unexamined_count"] == 0
    assert all(int(receipt.budget_consumed[name]) <= limit for name, limit in budget.items())


def test_the_slice_holds_requests_for_a_retry_and_a_wall_killed_endpoint_recovers(monkeypatch):
    # An endpoint whose first attempt reported nothing before its wall is retried once from
    # what the slice has left. Charged seven requests per attempt, the retry needs requests
    # the slice now holds for it.
    paths = ("/slow", "/a", "/b", "/c")
    budget = {"http_requests": passive_batch_request_hold(4), "tool_wall_seconds": 48}
    assert budget["http_requests"] == PACK * 6
    receipt, calls = _run(monkeypatch, paths, budget, stalls_once={"/slow"})

    assert [path for path, _ in calls].count("/slow") == 2
    assert receipt.status == "success" and receipt.timed_out is False
    assert receipt.redacted_execution["recovered_count"] == 1
    assert all(int(receipt.budget_consumed[name]) <= limit for name, limit in budget.items())


def test_a_retry_the_request_hold_cannot_fund_names_the_request_ceiling(monkeypatch):
    # The pre-fix slice held exactly the pack per endpoint: every attempt spent its seven,
    # so the retry was unfundable. That is a request-ceiling stop, not a timeout.
    paths = ("/slow", "/a", "/b", "/c")
    budget = {"http_requests": PACK * 4, "tool_wall_seconds": 48}
    receipt, calls = _run(monkeypatch, paths, budget, stalls_once={"/slow"})

    assert [path for path, _ in calls].count("/slow") == 1
    assert receipt.status == "partial"
    assert receipt.redacted_execution["unexamined_count"] == 1
    assert receipt.errors[0] == "http_request_budget_exhausted"
    assert "timeout" in receipt.errors, "the wall-killed attempt stays visible"
    assert _outcome(receipt) == (
        CapabilityResultStatus.PARTIAL,
        CapabilityResultReason.HTTP_REQUEST_BUDGET_EXHAUSTED,
    )


def test_planned_passive_slices_hold_retry_headroom():
    # One retry per two endpoints (soak e5264021: a slice of seven had two slow endpoints).
    assert passive_batch_request_hold(18) == PACK * (18 + 9)
    assert passive_batch_request_hold(25) == PACK * (25 + 12)
    assert passive_batch_request_hold(7) == PACK * (7 + 3)
    assert passive_batch_request_hold(4) == PACK * 6
    assert passive_batch_request_hold(3) == PACK * 3
    # The single-route admission slice keeps exactly the pack (tight parallel children).
    assert passive_batch_request_hold(1) == PACK
