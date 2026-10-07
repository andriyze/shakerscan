"""SQLi verification resumes stage by stage instead of restarting sqlmap (soak N3, 2026-10-07).

On honey (~3.7 s per response) no SQLi verification ever finished: 146b6c03 sent 110 requests
in its 420-second slice and 230 in the 900-second extension, da4c0531 160 and then 745 over
four candidates, and every extension restarted sqlmap at its first payload. sqlmap's session
keeps found injections, not negative payloads, so its own resume cannot help; a technique
(``--technique X``) is the unit whose verdict is final. These tests pin the stage runner, the
pacing that stops adding a full delay on top of a measured response time, the extension chain
that continues a candidate, and the finalizer that reads the chain's newest outcome.
"""

from __future__ import annotations

import asyncio
import dataclasses
import uuid
from types import SimpleNamespace

import pytest

import agent_tools
import scan.action_adapter as action_adapter_module
from hunt.capability_executor import CapabilityAdapterResult
from runtime.models import ScanPolicy
from scan.action_plan import ScanActionPlan
from scan.external_process import paced_request_delay
from scan.sqli_stages import (
    SQLI_TECHNIQUE_STAGES,
    STAGE_RECORD_KIND,
    prior_stages,
    run_staged_sqli_attempt,
    stage_attempt_id,
)
from scan.verification_extension import (
    EXTENDS_ARG,
    extension_lineage,
    superseding_results,
)
from scan.work_manifests import build_candidate_manifest, build_endpoint_manifest
from tests.test_scan_action_adapter import TARGET, Backend, _action as plan_action, _dispatcher, _lease, _noop

CANDIDATE = "a" * 64
# Requests sqlmap needs for a negative verdict per technique at level 2 / risk 2, measured in
# the scanner image against a non-injectable JSON field.
NEGATIVE_VERDICT = {"B": 87, "E": 144, "U": 53, "T": 189}


def _stage_result(technique, budget, *, seconds_per_request=3.7, finding=False):
    """A sqlmap stage: finishes if its wall covers the technique, else is wall-killed."""
    need = NEGATIVE_VERDICT[technique]
    wall = int(budget["tool_wall_seconds"])
    affordable = int(wall / seconds_per_request)
    if finding:
        return SimpleNamespace(
            status="success", timed_out=False, errors=(),
            actual_budget={"http_requests": 20, "tool_wall_seconds": int(20 * seconds_per_request)},
            observations=({"kind": "sqli_finding", "param": "message", "proof_state": "candidate"},),
        )
    if affordable >= need:
        return SimpleNamespace(
            status="success", timed_out=False, errors=(), observations=(),
            actual_budget={"http_requests": need, "tool_wall_seconds": int(need * seconds_per_request)},
        )
    return SimpleNamespace(
        status="partial", timed_out=True, errors=("timeout",), observations=(),
        actual_budget={"http_requests": affordable, "tool_wall_seconds": wall},
    )


def _run(budget, *, prior=None, finding_at=None, seconds_per_request=3.7):
    calls, checkpoints = [], []

    async def run_stage(technique, stage_budget, latency):
        calls.append((technique, dict(stage_budget), latency))
        return _stage_result(
            technique, stage_budget, seconds_per_request=seconds_per_request,
            finding=technique == finding_at,
        )

    async def checkpoint(item):
        checkpoints.append(dict(item))

    outcome = asyncio.run(run_staged_sqli_attempt(
        candidate_attempt_id=CANDIDATE, candidate_id="cand-1", budget=budget,
        prior=prior or prior_stages((), CANDIDATE), own_action_id="verify.sqli.r01.ext.r02",
        run_stage=run_stage, checkpoint=checkpoint, cancelled=lambda: False,
    ))
    return outcome, calls, checkpoints


def test_stages_run_most_likely_to_prove_first_and_each_is_checkpointed():
    budget = {"http_requests": 1_000, "state_changing_requests": 1_000, "tool_wall_seconds": 3_000}
    outcome, calls, checkpoints = _run(budget)

    assert SQLI_TECHNIQUE_STAGES == ("B", "E", "U", "T")
    assert [technique for technique, _, _ in calls] == ["B", "E", "U", "T"]
    assert outcome.status == "success" and outcome.timed_out is False
    assert [item["attempt_id"] for item in checkpoints] == [
        stage_attempt_id(CANDIDATE, technique) for technique in "BEUT"
    ]
    assert outcome.actual_budget["http_requests"] == sum(NEGATIVE_VERDICT.values())
    # Each stage holds what the candidate has left; no ceiling grows.
    assert calls[1][1]["http_requests"] == 1_000 - NEGATIVE_VERDICT["B"]


def test_a_proven_stage_ends_the_candidate():
    budget = {"http_requests": 1_000, "tool_wall_seconds": 3_000}
    outcome, calls, _ = _run(budget, finding_at="B")

    assert [technique for technique, _, _ in calls] == ["B"]
    assert outcome.status == "success"
    assert any(item.get("kind") == "sqli_finding" for item in outcome.observations)


def test_the_soak_slice_finishes_boolean_and_is_stopped_inside_error_based():
    # 146b6c03's slice: one body candidate, 480 requests / 420 s at ~3.7 s per response.
    budget = {"http_requests": 480, "state_changing_requests": 480, "tool_wall_seconds": 420}
    outcome, calls, checkpoints = _run(budget)

    assert [technique for technique, _, _ in calls] == ["B", "E"]
    assert outcome.status == "partial" and outcome.timed_out is True
    finished = [item for item in checkpoints if item["status"] == "success"]
    assert [item["attempt_id"] for item in finished] == [stage_attempt_id(CANDIDATE, "B")]
    # The wall-killed stage is checkpointed too, so the next attempt knows its wall.
    assert checkpoints[-1]["timed_out"] is True


def test_an_extension_continues_at_the_first_unfinished_stage():
    slice_budget = {"http_requests": 480, "state_changing_requests": 480, "tool_wall_seconds": 420}
    _, _, slice_checkpoints = _run(slice_budget)
    prior = prior_stages(
        [("verify.sqli.r01.ext.r02", ()), ("verify.sqli.r01", slice_checkpoints)], CANDIDATE,
    )
    assert set(prior.finished) == {"B"} and "E" in prior.wall_killed

    extension = {"http_requests": 1_714, "state_changing_requests": 1_028, "tool_wall_seconds": 900}
    outcome, calls, _ = _run(extension, prior=prior)

    assert [technique for technique, _, _ in calls][0] == "E", "boolean is never re-sent"
    carried = [
        item for item in outcome.observations
        if item.get("kind") == STAGE_RECORD_KIND and item.get("carried_from")
    ]
    assert [(item["technique"], item["carried_from"]) for item in carried] == [
        ("B", "verify.sqli.r01"),
    ]
    # The measured response time paces the next stage instead of a fresh full delay.
    assert calls[0][2] > 2.5


def test_a_stage_is_not_rerun_on_a_hold_no_larger_than_the_one_it_ran_out_of():
    killed = {
        "attempt_id": stage_attempt_id(CANDIDATE, "B"), "candidate_id": "cand-1",
        "status": "partial", "timed_out": True,
        "budget_consumed": {"http_requests": 80, "tool_wall_seconds": 400},
        "observations": ({"kind": STAGE_RECORD_KIND, "technique": "B", "delay_ms": 1_000},),
    }
    prior = prior_stages([("verify.sqli.r01", (killed,))], CANDIDATE)
    outcome, calls, _ = _run({"http_requests": 500, "tool_wall_seconds": 300}, prior=prior)

    assert calls == []
    assert outcome.status == "partial"
    assert outcome.timed_out is False, "nothing new was interrupted, so nothing to extend"


def test_a_spent_request_hold_stops_the_candidate_at_the_request_ceiling():
    outcome, calls, _ = _run({"http_requests": 87, "tool_wall_seconds": 3_000})

    assert [technique for technique, _, _ in calls] == ["B"]
    assert outcome.status == "partial"
    assert "connection_limit_exceeded" in outcome.errors


def test_a_measured_response_time_shortens_the_pacing_delay_but_not_the_ceiling():
    plain = paced_request_delay(1_028, 900, minimum_seconds=0.05)
    measured = paced_request_delay(1_028, 900, minimum_seconds=0.05, latency_seconds=2.9)

    assert plain == pytest.approx((900 / (1_028 * 0.9), 1_028))
    assert measured[0] < plain[0] and measured[0] >= 0.05
    assert measured[1] == plain[1] == 1_028
    # At the soak's ~2.9 s response time the paced rate still stays under the hold.
    assert 900 / (2.9 + measured[0]) < 1_028


def test_the_worker_plan_confines_sqlmap_to_one_technique_and_paces_by_the_measurement():
    reserved = {"http_requests": 1_028, "state_changing_requests": 1_028, "tool_wall_seconds": 900}

    def plan(options):
        return agent_tools.build_enforced_scanner_plan(
            "sqlmap", "https://app.example.test/api/v1/chat", options,
            reserved_budget=reserved, pinned_address="192.0.2.20",
            pinned_proxy_url="socks5://127.0.0.1:43123",
            runtime_paths={"sqlmap_output_dir": "/tmp/sqlmap-worker-owned"},
        )

    plain = plan({"_batch_attempt": True})
    staged = plan({"_batch_attempt": True, "technique": "E", "_measured_latency_seconds": 2.9})

    assert plain.argv[plain.argv.index("--technique") + 1] == "BEUT"
    assert staged.argv[staged.argv.index("--technique") + 1] == "E"
    assert float(staged.argv[staged.argv.index("--delay") + 1]) < float(
        plain.argv[plain.argv.index("--delay") + 1]
    )
    assert staged.hard_budget_dict == plain.hard_budget_dict
    assert staged.budget_proof["inputs"]["techniques"] == "E"
    assert "_measured_latency_seconds" not in " ".join(staged.argv)
    # An unknown technique cannot widen the test; a bogus measurement fails closed.
    assert plan({"_batch_attempt": True, "technique": "BEUTSQ"}).argv[
        plain.argv.index("--technique") + 1
    ] == "BEUT"
    with pytest.raises(agent_tools.AgentToolError):
        plan({"_batch_attempt": True, "_measured_latency_seconds": 1_000})


def _chain():
    args = {"slice": {"start": 0, "count": 1}}
    return SimpleNamespace(actions=(
        SimpleNamespace(action_id="verify.sqli.r01", capability_args=dict(args)),
        SimpleNamespace(
            action_id="verify.sqli.r01.ext.r02",
            capability_args={**args, EXTENDS_ARG: "verify.sqli.r01"},
        ),
        SimpleNamespace(
            action_id="verify.sqli.r01.ext.r02.ext.r03",
            capability_args={**args, EXTENDS_ARG: "verify.sqli.r01.ext.r02"},
        ),
    ))


def test_the_slice_and_every_extension_are_covered_by_the_newest_outcome():
    plan = _chain()
    results = {action.action_id: action.action_id for action in plan.actions}

    superseded = superseding_results(plan.actions, results)
    assert superseded == {
        "verify.sqli.r01": "verify.sqli.r01.ext.r02.ext.r03",
        "verify.sqli.r01.ext.r02": "verify.sqli.r01.ext.r02.ext.r03",
    }
    assert extension_lineage(plan.actions[-1], plan) == (
        "verify.sqli.r01.ext.r02", "verify.sqli.r01",
    )


def test_a_chained_extension_carries_candidates_settled_two_rounds_back(monkeypatch):
    """A candidate the slice finished is carried by the first extension without a checkpoint
    of its own; the second extension must still carry it rather than re-run it."""
    scan_id = str(uuid.uuid4())
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
                for path in ("/fast", "/slow")
            ],
        },
        source_action_ids=("discover.web_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.web_crawl",), maximum=10,
    )
    args = {
        "candidate_manifest_ref": candidates.reference().canonical_dict(),
        "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
        "slice": {"start": 0, "count": 2},
        "profile": "balanced_batch_v1", "proof_policy": "deterministic_differential_required",
    }
    actions = []
    for ordinal, (action_id, extends, budget) in enumerate((
        ("verify.sqli.r01", None, {"http_requests": 800, "tool_wall_seconds": 420}),
        ("verify.sqli.r01.ext.r02", "verify.sqli.r01", {"http_requests": 1_714, "tool_wall_seconds": 900}),
        ("verify.sqli.r01.ext.r02.ext.r03", "verify.sqli.r01.ext.r02", {"http_requests": 1_714, "tool_wall_seconds": 900}),
    )):
        actions.append(dataclasses.replace(
            plan_action(
                action_id, "sqli.verify_batch", ordinal,
                capability_args={**args, **({EXTENDS_ARG: extends} if extends else {})},
            ),
            requested_budget=budget, action_digest=None,
        ))
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=tuple(actions),
    )
    calls = []

    async def execute(_self, context, adapter, **_kwargs):
        target = adapter._process_payload["execution_target"]
        technique = adapter._process_payload["scanner_options"]["technique"]
        calls.append((target.split("app.example.test", 1)[1].split("?")[0], technique))
        wall = int(context.requested_budget["tool_wall_seconds"])
        if "/slow" in target and technique == "T" and wall < 600:
            return CapabilityAdapterResult(
                status="partial", partial=True, timed_out=True, errors=("timeout",),
                actual_budget={"http_requests": 50, "tool_wall_seconds": wall},
                execution_started=True, parser_version="sqlmap-output/v1",
            )
        return CapabilityAdapterResult(
            status="success", actual_budget={"http_requests": 20, "tool_wall_seconds": 30},
            execution_started=True, parser_version="sqlmap-output/v1",
        )

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    backend = Backend(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates})
    dispatcher = _dispatcher(
        plan, backend, policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
    )
    receipts = []
    for action in actions:
        receipts.append(asyncio.run(dispatcher(action, _lease(plan, action), _noop)))

    by_round = {}
    for receipt, action in zip(receipts, actions):
        by_round[action.action_id] = receipt
    fast_runs = [call for call in calls if call[0] == "/fast"]
    slow_runs = [call for call in calls if call[0] == "/slow"]
    assert fast_runs == [("/fast", technique) for technique in "BEUT"], "verified once, carried after"
    # The slow candidate's finished stages are never re-sent; only its time stage is resumed.
    assert [technique for _, technique in slow_runs].count("B") == 1
    assert [technique for _, technique in slow_runs].count("E") == 1
    final = receipts[-1]
    assert final.redacted_execution["carried_count"] == 1
    assert final.redacted_execution["technique_stages"]["stages_carried"] >= 3


def test_a_new_candidate_is_paced_by_what_another_candidate_measured_on_the_target():
    # da4c0531's extension started two never-attempted body candidates at the blind 1.67 s
    # delay on top of honey's ~2.9 s responses; a sibling had already measured them.
    sibling = "b" * 64
    measured = {
        "attempt_id": stage_attempt_id(sibling, "B"), "candidate_id": "cand-2",
        "status": "success", "timed_out": False,
        "budget_consumed": {"http_requests": 87, "tool_wall_seconds": 332},
        "observations": ({"kind": STAGE_RECORD_KIND, "technique": "B", "delay_ms": 972},),
    }
    prior = prior_stages([("verify.sqli.r01", (measured,))], CANDIDATE)

    assert prior.finished == {}
    assert prior.latency_seconds == pytest.approx(332 / 87 - 0.972)
