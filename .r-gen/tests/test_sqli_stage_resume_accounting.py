"""A SQLi stage resumed inside the same action is charged; one carried from an earlier action is not.

Audit L001. ``run_staged_sqli_attempt`` restored the observations of stages the same action had
already finished but not their cost, and gave the next stage the candidate's whole budget. An
action resumed after a crash (its stage checkpoints written, its candidate checkpoint not) then
reported less than it sent and could send more than its reservation held. Production settles an
expired action instead of replaying it (``_recover_expired_action``), so this was latent; the
batch's candidate-level replay is a supported, tested contract, and the stage resume is its
finer-grained counterpart, so it is made to charge the same way.

A stage carried from an earlier, already settled action (a verification extension) was charged
on that action's receipt and must stay free. Unit fixture: sqlmap stages are scripted results.
"""

from __future__ import annotations

import asyncio
import dataclasses
from types import SimpleNamespace
import uuid

import scan.action_adapter as action_adapter_module
from hunt.capability_executor import CapabilityAdapterResult
from runtime.models import ScanPolicy
from scan.action_plan import ScanActionPlan
from scan.sqli_stages import (
    STAGE_RECORD_KIND,
    prior_stages,
    run_staged_sqli_attempt,
    stage_attempt_id,
)
from scan.work_manifests import build_candidate_manifest, build_endpoint_manifest
from tests.test_scan_action_adapter import TARGET, Backend, _action, _dispatcher, _lease, _noop

CANDIDATE = "c" * 64
OWN = "verify.sqli.r01"
EARLIER = "verify.sqli.r00"
UNION_SPEND = {"http_requests": 53, "tool_wall_seconds": 196}


def _finished_union(candidate_attempt_id=CANDIDATE, candidate_id="cand-1"):
    return {
        "attempt_id": stage_attempt_id(candidate_attempt_id, "U"), "candidate_id": candidate_id,
        "status": "success", "timed_out": False, "budget_consumed": dict(UNION_SPEND),
        "observations": ({
            "kind": STAGE_RECORD_KIND, "technique": "U", "status": "success",
            "timed_out": False, "budget_consumed": dict(UNION_SPEND), "delay_ms": 50,
        },),
        "errors": (), "proof_state": "unproven",
    }


def _run(source):
    calls = []

    async def run_stage(technique, budget, _latency):
        calls.append((technique, dict(budget)))
        return SimpleNamespace(
            status="success", timed_out=False, errors=(), observations=(),
            actual_budget={"http_requests": 10, "tool_wall_seconds": 1},
        )

    async def checkpoint(_item):
        return None

    outcome = asyncio.run(run_staged_sqli_attempt(
        candidate_attempt_id=CANDIDATE, candidate_id="cand-1",
        budget={"http_requests": 480, "tool_wall_seconds": 420},
        prior=prior_stages([(source, (_finished_union(),))], CANDIDATE),
        own_action_id=OWN, run_stage=run_stage, checkpoint=checkpoint,
        cancelled=lambda: False,
    ))
    return outcome, calls


def test_a_same_action_resume_charges_the_stages_it_already_ran():
    outcome, calls = _run(OWN)

    assert [technique for technique, _ in calls] == ["B", "E", "T"], "UNION is not re-sent"
    # The next stage holds only what the candidate's budget has left after UNION.
    assert calls[0][1] == {"http_requests": 480 - 53, "tool_wall_seconds": 420 - 196}
    # The attempt reports UNION's spend with the three stages it ran here.
    assert dict(outcome.actual_budget) == {"http_requests": 53 + 30, "tool_wall_seconds": 196 + 3}
    assert outcome.status == "success"
    # Its records are this action's evidence.
    assert any(
        item.get("kind") == STAGE_RECORD_KIND and item.get("technique") == "U"
        and "carried_from" not in item
        for item in outcome.observations
    )


def test_a_stage_carried_from_an_earlier_action_is_not_charged_again():
    outcome, calls = _run(EARLIER)

    assert [technique for technique, _ in calls] == ["B", "E", "T"]
    assert calls[0][1] == {"http_requests": 480, "tool_wall_seconds": 420}
    assert dict(outcome.actual_budget) == {"http_requests": 30, "tool_wall_seconds": 3}
    carried = [item for item in outcome.observations if item.get("carried_from")]
    assert [(item["technique"], item["carried_from"]) for item in carried] == [("U", EARLIER)]


def test_a_same_action_resume_that_spent_the_budget_runs_nothing_more():
    async def never(*_args):
        raise AssertionError("no stage may run on a spent budget")

    async def checkpoint(_item):
        return None

    spent = dict(_finished_union(), budget_consumed={"http_requests": 480, "tool_wall_seconds": 196})
    outcome = asyncio.run(run_staged_sqli_attempt(
        candidate_attempt_id=CANDIDATE, candidate_id="cand-1",
        budget={"http_requests": 480, "tool_wall_seconds": 420},
        prior=prior_stages([(OWN, (spent,))], CANDIDATE),
        own_action_id=OWN, run_stage=never, checkpoint=checkpoint, cancelled=lambda: False,
    ))
    assert outcome.status == "partial"
    assert outcome.actual_budget["http_requests"] == 480
    assert "connection_limit_exceeded" in outcome.errors


def _plan():
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [{
                "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
                "normalized_path": "/search", "concrete_path": "/search", "query_keys": ["q"],
                "source": "web.crawl",
            }],
        },
        source_action_ids=("discover.web_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.web_crawl",), maximum=10,
    )
    action = dataclasses.replace(
        _action(OWN, "sqli.verify_batch", 0, capability_args={
            "candidate_manifest_ref": candidates.reference().canonical_dict(),
            "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
            "slice": {"start": 0, "count": 1},
            "profile": "balanced_batch_v1", "proof_policy": "deterministic_differential_required",
        }),
        requested_budget={"http_requests": 800, "tool_wall_seconds": 420}, action_digest=None,
    )
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(action,),
    )
    backend = Backend(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates})
    return plan, plan.actions[0], backend


def test_a_batch_resumed_after_a_crash_reports_what_its_earlier_stages_sent(monkeypatch):
    plan, action, backend = _plan()
    granted = []

    async def execute(_self, context, adapter, **_kwargs):
        granted.append((
            adapter._process_payload["scanner_options"]["technique"],
            dict(context.requested_budget),
        ))
        return CapabilityAdapterResult(
            status="success", actual_budget={"http_requests": 10, "tool_wall_seconds": 1},
            execution_started=True, parser_version="sqlmap-output/v1",
        )

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    dispatcher = _dispatcher(
        plan, backend, policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
    )
    # The first run is interrupted after UNION's checkpoint, before the candidate's.
    first = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    candidate_checkpoint = next(
        item for item in backend.attempts[action.action_id].values()
        if any(record.get("kind") == "candidate_attempt" for record in item["observations"])
    )
    stage_checkpoints = {
        key: value for key, value in backend.attempts[action.action_id].items()
        if key != candidate_checkpoint["attempt_id"]
    }
    union_id = stage_attempt_id(candidate_checkpoint["attempt_id"], "U")
    backend.attempts[action.action_id] = {union_id: stage_checkpoints[union_id]}
    granted.clear()

    resumed = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert [technique for technique, _ in granted] == ["B", "E", "T"]
    # The four stages are charged once each, exactly as an uninterrupted run reported them.
    assert dict(resumed.budget_consumed) == dict(first.budget_consumed) == {
        "http_requests": 40, "tool_wall_seconds": 4,
    }
