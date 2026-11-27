"""Passive templates over slow endpoints: sized by measured latency, named when they cannot finish.

Soak e5264021 (Balanced honey, soak N32): 5 of 28 passive-pack attempts on honey's AI
endpoints were wall-killed at about 12 s. `passive.templates.r01` ended 140/154 HTTP in
171/216 s and `.001.r01` 56/56 in 73/84 s, both `timed_out`, so nuclei_passive was partial and
the grade starred. Three things kept the endpoints unexamined:

- every later attempt was still reserved the planned 12-second share although the fast
  endpoints had each finished in about three, so a slow endpoint met early got 12 s;
- an attempt the wall cut off after the pack's first template had matched was not retried
  (only an attempt with no output was), so the endpoint stayed half-examined;
- the slice held one retry's requests per four endpoints, and `.001` had two slow ones.

Where an endpoint still cannot finish inside the batch's wall, the batch now says
`slow_endpoints` and names each one, instead of a generic timeout.
"""

from __future__ import annotations

import asyncio

from hunt.capability_executor import CapabilityAdapterResult
from runtime.models import ScanPolicy
import scan.action_adapter as action_adapter_module
from scan.action_plan import passive_batch_request_hold
from scan.capability_result import CapabilityResultReason, CapabilityResultStatus
from tests.test_passive_batch_slow_endpoint import PACK, _batch, _outcome
from tests.test_scan_action_adapter import _dispatcher, _lease, _noop

# An AI endpoint answering in 3-5 s: seven sequential GETs plus nuclei start-up.
SLOW_PACK_SECONDS = 33
FAST_PACK_SECONDS = 3


def _match(path):
    return {
        "kind": "template_match", "template_id": "http-missing-security-headers",
        "severity": "info", "matched_at": f"https://app.example.test{path}",
    }


def _run(monkeypatch, paths, budget, slow_positions):
    """Run one batch; the endpoints attempted at ``slow_positions`` (in the batch's own
    attempt order) answer slowly."""
    plan, action, backend = _batch(paths, budget)
    calls: list[tuple[str, int]] = []
    slow_paths: set[str] = set()

    async def execute(_self, context, adapter, **_kwargs):
        path = adapter._process_payload["execution_target"].split("app.example.test", 1)[1]
        wall = int(dict(context.requested_budget)["tool_wall_seconds"])
        if len(calls) in slow_positions:
            slow_paths.add(path)
        calls.append((path, wall))
        needed = SLOW_PACK_SECONDS if path in slow_paths else FAST_PACK_SECONDS
        if wall < needed:
            # The first template answered before the wall: the attempt has output, but the
            # pack did not finish on this endpoint.
            return CapabilityAdapterResult(
                status="partial", timed_out=True, partial=True, errors=("timeout",),
                observations=(_match(path),),
                actual_budget={"http_requests": PACK, "tool_wall_seconds": wall},
                execution_started=True, parser_version="nuclei-jsonl/v1",
            )
        return CapabilityAdapterResult(
            status="success", observations=(_match(path),),
            actual_budget={"http_requests": PACK, "tool_wall_seconds": needed},
            execution_started=True, parser_version="nuclei-jsonl/v1",
        )

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    dispatcher = _dispatcher(plan, backend, policy=ScanPolicy())
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    return receipt, calls, slow_paths


def test_the_required_batch_finishes_slow_endpoints_met_early(monkeypatch):
    # r01's shape: 18 endpoints, 216 s; slow AI endpoints are attempted 1st, 2nd and 6th.
    paths = tuple(f"/route-{index:02d}" for index in range(18))
    budget = {"http_requests": passive_batch_request_hold(18), "tool_wall_seconds": 216}
    receipt, calls, _slow = _run(monkeypatch, paths, budget, {0, 1, 5})
    order = [path for path, _ in calls]

    assert receipt.status == "success", receipt.errors
    assert receipt.timed_out is False
    # The 6th endpoint is met after fast ones measured the pack at ~3 s, so it is not
    # reserved down to the planned 12 s; the two met before any measurement are retried.
    assert calls[5][1] >= SLOW_PACK_SECONDS
    assert calls[0][1] == calls[1][1] == 216 // 18
    assert order.count(order[0]) == 2 and order.count(order[1]) == 2
    assert receipt.redacted_execution["recovered_count"] == 2
    # A recovered endpoint's matches come from its finished retry only, not twice.
    matches = [item for item in receipt.observations if item.get("kind") == "template_match"]
    assert len(matches) == len(paths)
    assert all(int(receipt.budget_consumed[name]) <= limit for name, limit in budget.items())


def test_an_endpoint_the_wall_cannot_finish_is_named_not_a_generic_timeout(monkeypatch):
    # .001.r01's shape: 7 endpoints, 84 s; two slow ones need 66 s between them, and the
    # one met first has already spent its 12 s share before anything was measured.
    paths = ("/api/v1/chat", "/a", "/b", "/api/v1/rag/documents", "/c", "/d", "/e")
    budget = {"http_requests": passive_batch_request_hold(7), "tool_wall_seconds": 84}
    receipt, calls, _slow = _run(monkeypatch, paths, budget, {0, 3})
    first = calls[0][0]

    assert receipt.status == "partial"
    assert receipt.timed_out is True, "the wall-killed attempts stay visible"
    assert receipt.errors[0] == "slow_endpoints"
    assert _outcome(receipt) == (
        CapabilityResultStatus.PARTIAL, CapabilityResultReason.SLOW_ENDPOINTS,
    )
    named = [item for item in receipt.observations if item.get("kind") == "template_slow_endpoint"]
    assert [item["url"] for item in named] == [f"https://app.example.test{first}"]
    assert named[0]["first_attempt_wall_seconds"] == 12
    assert 12 < named[0]["retry_wall_seconds"] < SLOW_PACK_SECONDS
    assert receipt.redacted_execution["slow_endpoint_count"] == 1
    # The other slow endpoint was sized from the measured latency and finished.
    assert calls[3][1] >= SLOW_PACK_SECONDS
    assert all(int(receipt.budget_consumed[name]) <= limit for name, limit in budget.items())
