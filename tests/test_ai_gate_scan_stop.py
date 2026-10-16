"""An AI target scan stops on its stop check and keeps what its finished probes found.

``ConversationRunner`` polls the run's stop check (a user cancel or a withdrawn target
authorization) before each probe and each further turn; a stopped run sends nothing more to the
target, not even session cleanup, and checkpoints each probe's findings as they are found.
``run_ai_target_scan`` then returns the partial report without judge calls. The conversation
target and the probe conversations are fixtures: no target is contacted.
"""
from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from ai_gate.budget import RequestBudget, TokenBudget  # noqa: E402
from ai_gate.runner import ConversationRunner, PackRunResult  # noqa: E402
import ai_gate_scan  # noqa: E402


class _Session:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


_AIOHTTP = types.SimpleNamespace(
    ClientTimeout=lambda **_kwargs: None, ClientSession=lambda **_kwargs: _Session(),
)


class _Target:
    method = "POST"

    def __init__(self):
        self.finalized: list[str] = []

    async def finalize_session(self, _session, session_id):
        self.finalized.append(session_id)


def _probes(count: int) -> tuple[Probe, ...]:
    template = next(iter(ai_gate_scan.plan_probe_pack(
        "shaker-ai-smoke", "smoke", {}, production_mode=False).probes))
    return tuple(replace(template, id=f"{template.id}-{index}") for index in range(count))


def _runner(target, *, cancelled, checkpoint):
    return ConversationRunner(
        aiohttp_module=_AIOHTTP, target=target, token_budget=TokenBudget(None),
        request_budget=RequestBudget(None), metadata_json={},
        analyze_probe=lambda *_a, **_k: [], classify_response=lambda *_a, **_k: [],
        cancelled=cancelled, on_probe_findings=checkpoint.extend,
    )


def test_a_stopped_runner_sends_no_further_probe_and_checkpoints_what_it_found(monkeypatch):
    target = _Target()
    stop = {"now": False}
    checkpoint: list = []
    runner = _runner(target, cancelled=lambda: stop["now"], checkpoint=checkpoint)
    ran: list[str] = []

    async def conversation(_session, probe, _session_id):
        ran.append(probe.id)
        stop["now"] = True  # the stop arrives while the first probe runs
        return ({"probe_id": probe.id}, [{"title": f"found by {probe.id}"}], [], 1, 0, False)

    monkeypatch.setattr(runner, "_run_probe_conversation", conversation)
    probes = _probes(3)
    result = asyncio.run(runner.run_probe_pack(probes, max_requests=3, per_request_delay=0))

    assert ran == [probes[0].id]
    assert result.stopped_by_cancellation is True
    assert result.findings == [{"title": f"found by {probes[0].id}"}]
    assert checkpoint == [{"title": f"found by {probes[0].id}"}]
    # A stopped run sends nothing more to the target, not even session cleanup.
    assert target.finalized == []


def test_a_runner_that_is_not_stopped_runs_every_probe_and_cleans_up(monkeypatch):
    target = _Target()
    checkpoint: list = []
    runner = _runner(target, cancelled=lambda: False, checkpoint=checkpoint)

    async def conversation(_session, probe, _session_id):
        return ({"probe_id": probe.id}, [], [], 1, 0, False)

    monkeypatch.setattr(runner, "_run_probe_conversation", conversation)
    result = asyncio.run(runner.run_probe_pack(_probes(3), max_requests=3, per_request_delay=0))
    assert len(result.transcripts) == 3 and result.stopped_by_cancellation is False
    assert target.finalized and checkpoint == []


def test_a_stopped_ai_target_scan_returns_its_partial_findings_without_judging(monkeypatch):
    calls = {"runs": 0, "judged": 0}

    class FixtureRunner:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        async def run_probe_pack(self, probes, *, max_requests, per_request_delay):
            calls["runs"] += 1
            self.kwargs["on_probe_findings"]([{"title": "checkpointed"}])
            return PackRunResult(
                transcripts=[{"probe_id": probes[0].id}],
                findings=[{"title": "prompt leakage", "severity": "high", "type": "prompt_leakage"}],
                errors=[], successful_requests=1, stopped_by_rate_limit=False,
                stopped_by_request_budget=False, stopped_by_cancellation=True,
            )

    async def judge(*_args, **_kwargs):
        calls["judged"] += 1
        raise AssertionError("a stopped run makes no judge call")

    monkeypatch.setattr(ai_gate_scan, "ConversationRunner", FixtureRunner)
    monkeypatch.setattr(ai_gate_scan, "_semantic_judge_probe_transcripts", judge)
    monkeypatch.setattr(ai_gate_scan, "_rubric_judge_findings", judge)
    checkpoint: dict = {}
    result = asyncio.run(ai_gate_scan.run_ai_target_scan(
        "http://model.fixture.test/v1/chat",
        {"ai_target": {"target_type": "api_chat", "endpoint_url": "http://model.fixture.test/v1/chat",
                       "request_template": {"message": "{{prompt}}"},
                       "metadata_json": {"ai_judge_enabled": True}},
         "ai_scan_profile": "standard"},
        cancelled=lambda: True, checkpoint=checkpoint,
    ))
    assert calls == {"runs": 1, "judged": 0}
    assert [item["title"] for item in result["findings"]][:1] == ["prompt leakage"]
    assert result["ai_gate"]["usage"]["stopped_by_cancellation"] is True
    assert result["ai_gate"]["execution_plan"]["stopped"]["executed_probes"] == 1
    assert checkpoint == {"findings": [{"title": "checkpointed"}]}
    # A run stopped hard (no report) keeps the checkpoint, analysed and redacted as a report's.
    kept = ai_gate_scan.kept_checkpoint_findings(checkpoint)
    assert [item["title"] for item in kept] == ["checkpointed"]
    assert ai_gate_scan.kept_checkpoint_findings({}) == []
