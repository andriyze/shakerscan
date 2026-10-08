"""Exposure probes wait a realistic time, retry a timeout, and report what never answered (N37).

Soak scan 47449681 gave every exposure probe ``wall / http allowance`` = 154 s / 180 = 0.86 s.
``/.env`` is the first seed and carries the connection set-up: it timed out at 859 ms (a later
probe of the same batch took 920 ms), was checkpointed ``success / not_proven``, never retried,
and family coverage said ``sensitive_exposure complete`` while the verified ``.env`` finding was
lost. b723d50d lost ``/.env.local`` the same way.

The latency fixture below is a fake transport: each path answers after a configured latency, and
a request whose timeout is shorter than that latency times out, as the pinned transport does.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import replace
from types import SimpleNamespace

import scan.action_adapter as action_adapter_module
from runtime.models import ScanPolicy
from runtime.request_replay_executor import ReplayTransportResult
from scan.action_plan import ScanActionPlan

from tests.test_exposure_probe_batch_controls import DOTENV, _manifest
from tests.test_scan_action_adapter import Backend, _action, _dispatcher, _lease, _noop

ORIGIN = "https://app.example.test"
# The contract's floor and ceiling (capabilities.exposure_probe), stated here so the batch tests
# below also run, and fail, against a build that predates them.
EXPOSURE_PROBE_TIMEOUT_FLOOR_SECONDS = 5.0
EXPOSURE_PROBE_TIMEOUT_CEILING_SECONDS = 15.0


class _LatencyTransport:
    """Answers each URL after ``latency(url, attempt)`` seconds, or times out first."""

    def __init__(self, latency, answer):
        self.latency = latency
        self.answer = answer
        self.sent: list[tuple[str, float]] = []

    async def send(self, request, *, target, timeout_seconds, follow_redirects):
        attempt = sum(1 for url, _ in self.sent if url == request.url)
        self.sent.append((request.url, float(timeout_seconds)))
        latency = self.latency(request.url, attempt)
        if latency > timeout_seconds:
            return ReplayTransportResult(
                status_code=None, connected_address="192.0.2.10", final_url=request.url,
                elapsed_ms=int(timeout_seconds * 1000), error_code="timeout", timed_out=True,
            )
        status, body = self.answer(request.url)
        return ReplayTransportResult(
            status_code=status, connected_address="192.0.2.10", final_url=request.url,
            response_headers={"Content-Type": "text/plain"}, response_body=body,
            elapsed_ms=max(1, int(latency * 1000)),
        )


def _answer(url):
    return (200, DOTENV) if url == f"{ORIGIN}/.env" else (404, b"not found")


def _run(monkeypatch, latency, *, wall=180, clock=None):
    scan_id = str(uuid.uuid4())
    manifest = _manifest(scan_id, ("/app",))
    transport = _LatencyTransport(latency, _answer)
    monkeypatch.setattr(action_adapter_module, "PinnedAiohttpReplayTransport", lambda **_: transport)
    if clock is not None:
        monkeypatch.setattr(action_adapter_module, "time", SimpleNamespace(monotonic=clock))
    action = _action(
        "verify.exposure", "exposure.verify_batch", 0,
        capability_args={
            "endpoint_manifest_ref": manifest.reference().canonical_dict(),
            "slice": {"start": 0, "count": 100},
            "profile": "balanced",
            "proof_policy": "deterministic_proof_contract_required",
        },
    )
    # The soak batch's allowance: wall / http = 154 / 180 = 0.86 s per probe before the fix.
    action = replace(
        action, requested_budget={"http_requests": 180, "tool_wall_seconds": wall}, action_digest=None,
    )
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=action.target_binding_digest, actions=(action,))
    backend = Backend(manifests={manifest.manifest_id: manifest})
    dispatcher = _dispatcher(plan, backend, policy=ScanPolicy())
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    return receipt, transport


def test_the_timeout_is_sized_from_measured_latency_within_the_wall():
    from capabilities import exposure_probe
    from capabilities.exposure_probe import exposure_probe_timeout

    assert exposure_probe.EXPOSURE_PROBE_TIMEOUT_FLOOR_SECONDS == EXPOSURE_PROBE_TIMEOUT_FLOOR_SECONDS
    assert exposure_probe.EXPOSURE_PROBE_TIMEOUT_CEILING_SECONDS == (
        EXPOSURE_PROBE_TIMEOUT_CEILING_SECONDS
    )
    assert exposure_probe_timeout(measured_ms=[], remaining_wall_seconds=150) == (
        EXPOSURE_PROBE_TIMEOUT_FLOOR_SECONDS
    )
    # The latency fixture of honey: 200 ms files, 920 ms first byte, 3.4 s AI endpoints.
    assert exposure_probe_timeout(measured_ms=[200, 920], remaining_wall_seconds=150) == 5.0
    assert exposure_probe_timeout(measured_ms=[200, 920, 3400], remaining_wall_seconds=150) == 13.6
    assert exposure_probe_timeout(measured_ms=[9000], remaining_wall_seconds=150) == (
        EXPOSURE_PROBE_TIMEOUT_CEILING_SECONDS
    )
    assert exposure_probe_timeout(measured_ms=[200], remaining_wall_seconds=150, retry=True) == (
        EXPOSURE_PROBE_TIMEOUT_CEILING_SECONDS
    )
    # Never past what the batch's wall has left.
    assert exposure_probe_timeout(measured_ms=[3400], remaining_wall_seconds=2.5) == 2.5


def test_a_first_probe_slower_than_wall_over_allowance_still_verifies(monkeypatch):
    """/.env answers in 0.9 s (connection set-up); wall / allowance would have allowed 0.86 s."""
    def latency(url, _attempt):
        return 0.9 if url == f"{ORIGIN}/.env" else 0.2

    receipt, transport = _run(monkeypatch, latency, wall=154)
    first_url, first_timeout = transport.sent[0]
    assert first_url == f"{ORIGIN}/.env"
    assert first_timeout >= EXPOSURE_PROBE_TIMEOUT_FLOOR_SECONDS
    verified = [
        item for item in receipt.observations
        if item.get("kind") == "sensitive_exposure_proof" and item.get("proof_state") == "verified"
    ]
    assert [item["request_url"] for item in verified] == [f"{ORIGIN}/.env"]
    assert receipt.status == "success"


def test_a_timed_out_probe_is_retried_once_inside_the_batch(monkeypatch):
    def latency(url, attempt):
        # Unanswered on the first try, answered on the retry.
        return 30.0 if url == f"{ORIGIN}/.env" and attempt == 0 else 0.2

    receipt, transport = _run(monkeypatch, latency)
    env = [timeout for url, timeout in transport.sent if url == f"{ORIGIN}/.env"]
    assert len(env) == 2
    assert env[1] == EXPOSURE_PROBE_TIMEOUT_CEILING_SECONDS
    assert any(
        item.get("kind") == "sensitive_exposure_proof" and item.get("proof_state") == "verified"
        for item in receipt.observations
    )
    assert receipt.status == "success"
    assert receipt.redacted_execution["retried_count"] == 1
    assert receipt.redacted_execution["timed_out_count"] == 0


def test_a_probe_that_still_times_out_is_a_named_gap_never_not_proven(monkeypatch):
    def latency(url, _attempt):
        return 60.0 if url == f"{ORIGIN}/.env" else 0.2

    receipt, transport = _run(monkeypatch, latency)
    assert [url for url, _ in transport.sent].count(f"{ORIGIN}/.env") == 2  # once, retried once
    assert receipt.status == "partial" and receipt.partial is True
    assert receipt.errors[0] == "slow_endpoints"
    gaps = [item for item in receipt.observations if item.get("kind") == "exposure_probe_timeout"]
    assert [item["url"] for item in gaps] == [f"{ORIGIN}/.env"]
    attempts = [
        item for item in receipt.observations
        if item.get("kind") == "candidate_attempt" and item.get("status") != "success"
    ]
    assert len(attempts) == 1
    assert attempts[0]["status"] == "timed_out" and attempts[0]["proof_state"] != "not_proven"


def test_the_batch_stops_at_its_wall_and_says_so(monkeypatch):
    now = [0.0]

    def clock():
        return now[0]

    def latency(url, _attempt):
        now[0] += 10.0  # every answer takes ten seconds of the batch's wall
        return 0.2

    receipt, transport = _run(monkeypatch, latency, wall=40, clock=clock)
    assert receipt.status == "partial" and receipt.timed_out is True
    assert receipt.errors[0] == "timed_out"
    assert receipt.redacted_execution["unattempted_count"] > 0
    assert len(transport.sent) <= 4
