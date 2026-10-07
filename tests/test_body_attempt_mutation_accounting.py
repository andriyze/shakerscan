"""A body attempt is charged the mutations it sent, and a slice holds one per body slot.

Soak scan 2c637857 (Balanced, standard active, two declared POST endpoints): `verify.xss`
ended partial / insufficient_plan_budget with state-changing 240 of 240 consumed after six
HTTP requests. The scanner adapter settled a body attempt's mutation dimension at its whole
hold whatever the wire showed, and the planner reserved a single body-attempt hold per
slice even though the slice could hold two body candidates. The first dalfox attempt sent
six requests and was charged 240 mutations; the second body candidate was never funded.
"""

from __future__ import annotations

import asyncio
import dataclasses
import uuid

from capabilities.scanner import ScannerExecutionAdapter
from hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import ScanPolicy
from scan.action_plan import ScanActionPlan, batch_profile_shape
from scan.external_process import batch_attempt_floor
from scan.work_manifests import build_candidate_manifest, build_endpoint_manifest
from tests.test_scan_action_adapter import TARGET, Backend, _action, _dispatcher, _lease, _noop


def _enforcement(tool, parser, hard):
    return {
        "schema_version": "external-process-enforcement/v1",
        "tool_name": tool,
        "process_plan_digest": "a" * 64,
        "hard_budget": dict(hard),
        "accounting_mode": "conservative",
        "proof_method": "rate_time_upper_bound",
        "parser_version": parser,
    }


def _runner(tool, parser, *, sent=None, sent_by_call=None):
    calls: list[dict] = []

    async def process_runner(payload, *, heartbeat):
        reserved = dict(payload["_reserved_budget"])
        calls.append(reserved)
        count = sent_by_call[len(calls) - 1] if sent_by_call else sent
        return {
            "status": "success",
            "elapsed_seconds": 10,
            "typed_output": {"parser": parser, "records": [], "errors": []},
            "settlement": (
                {"mode": "exact", "actual": count, "observed_minimum": count}
                if count is not None
                else {"mode": "unavailable", "actual": None, "observed_minimum": 0}
            ),
            "process_enforcement": _enforcement(tool, parser, {
                name: reserved[name] for name in ("http_requests", "tool_wall_seconds")
            }),
        }

    return process_runner, calls


def _body_attempt(capability, tool, parser, requested, *, sent):
    runner, _calls = _runner(tool, parser, sent=sent)
    spec = CAPABILITY_REGISTRY.require(capability)
    adapter = ScannerExecutionAdapter(
        specification=spec,
        process_payload={"tool_name": tool, "scanner_options": {
            "method": "POST", "body_field_names": ["message"], "injection_field": "message",
        }},
        process_runner=runner,
        requested_budget=requested,
        redacted_execution={"capability_name": capability},
    )
    return asyncio.run(CapabilityExecutor().execute(
        CapabilityExecutionContext(
            specification=spec, target=TARGET, requested_budget=requested,
        ),
        adapter,
        heartbeat=lambda: asyncio.sleep(0),
        cancelled=lambda: False,
    ))


def test_a_measured_body_attempt_is_charged_the_mutations_it_sent():
    requested = {"http_requests": 240, "state_changing_requests": 240, "tool_wall_seconds": 120}
    result = _body_attempt("xss.verify", "dalfox", "dalfox-jsonl/v1", requested, sent=6)

    assert result.actual_budget["http_requests"] == 6
    assert result.actual_budget["state_changing_requests"] == 6, (
        "six requests are at most six mutations, not the 240 hold"
    )


def test_an_unmeasured_body_attempt_still_keeps_its_whole_hold():
    requested = {"http_requests": 480, "state_changing_requests": 480, "tool_wall_seconds": 420}
    result = _body_attempt("sqli.verify", "sqlmap", "sqlmap-output/v1", requested, sent=None)

    assert result.actual_budget["http_requests"] == 480
    assert result.actual_budget["state_changing_requests"] == 480


def test_a_slice_holds_a_mutation_floor_for_every_body_slot_it_can_fund():
    for profile in ("balanced", "thorough", "deep"):
        for capability in ("xss.verify_batch", "sqli.verify_batch"):
            size, budget = batch_profile_shape(
                profile, capability, allow_state_changing_http=True,
            )
            body = batch_attempt_floor(capability, body_candidate=True)
            slots = min(
                [size] + [
                    budget[name] // amount for name, amount in body.items()
                    if name != "state_changing_requests"
                ]
            )
            assert slots >= 1
            assert budget["state_changing_requests"] >= body["state_changing_requests"] * slots, (
                profile, capability,
            )
    # The soak shape: a balanced XSS slice of two can fund two body attempts.
    size, budget = batch_profile_shape("balanced", "xss.verify_batch", allow_state_changing_http=True)
    assert size == 2 and budget["state_changing_requests"] == 480
    # Without state-changing authority nothing about the mutation hold changes.
    _size, query_only = batch_profile_shape("balanced", "xss.verify_batch")
    assert query_only["state_changing_requests"] == 240


def _two_body_candidate_batch(requested):
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id,
        target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [
                {
                    "method": "POST", "scheme": "https", "host": "app.example.test", "port": 443,
                    "normalized_path": path, "concrete_path": path, "query_keys": [],
                    "content_type": "application/json", "body_field_names": ["message"],
                    "source": "inputs.custom_endpoints",
                }
                for path in ("/api/v1/agent/run", "/api/v1/support/message")
            ],
        },
        source_action_ids=("discover.web_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.web_crawl",), maximum=10,
        allow_state_changing_http=True,
    )
    assert len(candidates.entries) == 2
    assert all(entry.get("body_field_names") for entry in candidates.entries)
    action = dataclasses.replace(
        _action(
            "verify.xss.r01", "xss.verify_batch", 0,
            capability_args={
                "candidate_manifest_ref": candidates.reference().canonical_dict(),
                "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
                "slice": {"start": 0, "count": 2},
                "profile": "balanced_batch_v1",
                "proof_policy": "deterministic_proof_contract_required",
            },
        ),
        requested_budget=dict(requested),
        action_digest=None,
    )
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(action,),
    )
    backend = Backend(manifests={
        endpoints.manifest_id: endpoints, candidates.manifest_id: candidates,
    })
    dispatcher = _dispatcher(plan, backend, policy=ScanPolicy(
        active_testing=True, allow_state_changing_http=True, approval_receipt_id="approval-1",
    ))
    runner, calls = _runner("dalfox", "dalfox-jsonl/v1", sent=6)
    dispatcher.process_runner = runner
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    return receipt, calls


def test_the_soak_slice_funds_both_body_candidates():
    _size, shape = batch_profile_shape("balanced", "xss.verify_batch", allow_state_changing_http=True)
    receipt, calls = _two_body_candidate_batch(shape)

    assert len(calls) == 2, "the second body candidate must get its real allowance"
    assert receipt.status == "success"
    assert receipt.redacted_execution["unattempted_count"] == 0
    assert receipt.budget_consumed["state_changing_requests"] == 12


def test_an_unfunded_body_candidate_names_the_mutation_allowance():
    # The pre-fix single hold: even settled exactly, 234 left cannot fund a 240 floor.
    receipt, calls = _two_body_candidate_batch(
        {"http_requests": 1400, "state_changing_requests": 240, "tool_wall_seconds": 400},
    )

    assert len(calls) == 1
    assert receipt.status == "partial"
    assert receipt.errors[0] == "state_changing_budget_exhausted"
    assert receipt.budget_consumed["state_changing_requests"] == 6
