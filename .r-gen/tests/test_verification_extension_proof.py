"""A proof escalation behind a verification extension proves what the extension found.

The extension planner skipped any proof action whose earlier run succeeded. That success
covered only the candidates its verifiers had signalled before the wall killed one of them;
candidates the extension then signalled got no proof, whatever budget remained. A proof
re-planned behind an extension also depended on the extensions alone, so it dropped the
signals of the verifier slices that were not extended.

The proof is now re-planned whenever a verifier it depended on was extended. It reads
signals from every slice the original read plus the extensions, and carries every
candidate the original already took to a verdict, so no candidate is proven twice.
"""

from __future__ import annotations

import asyncio
import uuid

from hunt.capability_executor import CapabilityAdapterResult
from runtime.models import ScanPolicy
import scan.action_adapter as action_adapter_module
from scan.action_plan import ScanActionPlan
from scan.verification_extension import (
    EXTENDS_ARG,
    SIGNAL_SOURCES_ARG,
    plan_verification_extensions,
)
from scan.work_manifests import build_candidate_manifest, build_endpoint_manifest
from tests.test_scan_action_adapter import TARGET, Backend, _action, _dispatcher, _lease, _noop
from tests.test_verification_extension import BALANCED, ROOMY, _plan, _settled
from tests.test_verification_extension import _action as _planned

PROOF_HOLD = {"http_requests": 16, "state_changing_requests": 16, "tool_wall_seconds": 24}


def _two_slices_and_proof():
    sibling = _planned("verify.sqli.r01", "sqli.verify_batch")
    starved = _planned("verify.sqli.001.r01", "sqli.verify_batch")
    prove = _planned(
        "prove.sqli.r01", "sqli.prove_batch", stage="prove_candidates",
        dependencies=("verify.sqli.r01", "verify.sqli.001.r01"),
        args={"slice": {"start": 0, "count": 3}, "continuation_work_key": "prove.sqli"},
    )
    return sibling, starved, prove


def _replanned(proof_status):
    sibling, starved, prove = _two_slices_and_proof()
    return plan_verification_extensions(
        parent_plan=_plan(sibling, starved, prove),
        parent_results={
            "verify.sqli.r01": _settled("success"),
            "verify.sqli.001.r01": _settled("timed_out"),
            "prove.sqli.r01": _settled(
                proof_status, reserved=PROOF_HOLD, consumed={name: 1 for name in PROOF_HOLD},
            ),
        },
        profile_limits=BALANCED, residual=ROOMY,
    )


def test_a_successful_proof_is_replanned_behind_the_extension():
    planned = _replanned("success")

    assert [item["action_id"] for item in planned] == [
        "verify.sqli.001.r01.ext", "prove.sqli.r01.ext",
    ]
    proof = planned[1]
    assert proof["dependencies"] == ("verify.sqli.001.r01.ext",)
    assert proof["capability_args"][EXTENDS_ARG] == "prove.sqli.r01"
    # Signals from every slice the original read, not only the extended one.
    assert proof["capability_args"][SIGNAL_SOURCES_ARG] == [
        "verify.sqli.r01", "verify.sqli.001.r01",
    ]
    assert proof["budget"] == PROOF_HOLD


def test_a_proof_with_no_extended_verifier_is_left_alone():
    sibling, starved, prove = _two_slices_and_proof()
    planned = plan_verification_extensions(
        parent_plan=_plan(sibling, starved, prove),
        parent_results={
            "verify.sqli.r01": _settled("success"),
            "verify.sqli.001.r01": _settled("success"),
            "prove.sqli.r01": _settled("success", reserved=PROOF_HOLD),
        },
        profile_limits=BALANCED, residual=ROOMY,
    )

    assert planned == ()


# --- the re-planned proof at execution ------------------------------------------------------


def _manifests(scan_id):
    endpoints = build_endpoint_manifest(
        scan_id=scan_id,
        target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [
                {"method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
                 "normalized_path": path, "concrete_path": path,
                 "query_keys": [key], "source": "web.crawl"}
                for path, key in (("/one", "id"), ("/two", "product"), ("/three", "q"))
            ],
        },
        source_action_ids=("discover.web_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.web_crawl",), maximum=10,
    )
    assert len(candidates.entries) == 3
    return endpoints, candidates


def _signal(candidate_id, **extra):
    return {
        "kind": "candidate_attempt", "candidate_id": candidate_id,
        "proof_state": "suspected", **extra,
    }


def _run_replanned_proof(monkeypatch, *, original_proved):
    scan_id = str(uuid.uuid4())
    endpoints, candidates = _manifests(scan_id)
    by_path = {entry["canonical_path"]: entry["candidate_id"] for entry in candidates.entries}
    proof_args = {
        "candidate_manifest_ref": candidates.reference().canonical_dict(),
        "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
        "slice": {"start": 0, "count": 3},
    }
    sibling = _action("verify.sqli.r01", "sqli.verify_batch", 0)
    starved = _action("verify.sqli.001.r01", "sqli.verify_batch", 1)
    original = _action(
        "prove.sqli.r01", "sqli.prove_batch", 2, capability_args=proof_args,
        dependencies=(sibling.action_id, starved.action_id),
    )
    extension = _action("verify.sqli.001.r01.ext.r02", "sqli.verify_batch", 3)
    replanned = _action(
        "prove.sqli.r01.ext.r02", "sqli.prove_batch", 4,
        capability_args={
            **proof_args, EXTENDS_ARG: original.action_id,
            SIGNAL_SOURCES_ARG: [sibling.action_id, starved.action_id],
        },
        dependencies=(extension.action_id,),
    )
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64, target_binding_digest=TARGET.digest,
        actions=(sibling, starved, original, extension, replanned),
    )
    backend = Backend(
        manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates},
        observations={
            # The sibling signalled /one; the starved slice signalled /two before the wall.
            sibling.action_id: (_signal(by_path["/one"]),),
            starved.action_id: (_signal(by_path["/two"]),),
            # The extension carried /two's finished record and newly signalled /three.
            extension.action_id: (
                _signal(by_path["/two"], carried_from=starved.action_id),
                _signal(by_path["/three"]),
            ),
        },
    )
    executed: list[str] = []

    async def execute(_self, context, adapter, **_kwargs):
        executed.append(adapter.request.url.split("app.example.test", 1)[1].split("?")[0])
        return CapabilityAdapterResult(
            status="success",
            actual_budget={name: 1 for name in context.requested_budget},
            observations=({"kind": "sqli_proof", "proof_state": "not_proven",
                           "finding_verdict": "not_proven", "proof_contract": None},),
            execution_started=True, parser_version="sqli-proof/v1",
        )

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    dispatcher = _dispatcher(
        plan, backend, policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
    )
    if original_proved:
        asyncio.run(dispatcher(original, _lease(plan, original), _noop))
        assert sorted(executed) == ["/one", "/two"]
        executed.clear()
    receipt = asyncio.run(dispatcher(replanned, _lease(plan, replanned), _noop))
    return receipt, executed


def test_the_replanned_proof_proves_only_the_new_candidate(monkeypatch):
    receipt, executed = _run_replanned_proof(monkeypatch, original_proved=True)

    assert executed == ["/three"], "already-proven candidates must not be proven twice"
    assert receipt.status == "success"
    assert receipt.redacted_execution["carried_count"] == 2
    assert receipt.redacted_execution["attempted_count"] == 3
    carried = [item for item in receipt.observations if item.get("carried_from")]
    assert {item["carried_from"] for item in carried} == {"prove.sqli.r01"}


def test_the_replanned_proof_keeps_the_siblings_signals(monkeypatch):
    receipt, executed = _run_replanned_proof(monkeypatch, original_proved=False)

    assert sorted(executed) == ["/one", "/three", "/two"]
    assert receipt.status == "success"


def test_the_round_compiler_admits_the_replanned_proof_behind_the_extension():
    from dataclasses import replace

    from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus
    from api.scan.continuation_rounds import compile_next_continuation
    from tests.test_continuation_rounds import _settle_round_fixture, _shared_round_fixture
    from tests.test_scan_orchestrator import _result

    fixture = _shared_round_fixture(endpoint_count=4)
    _settle_round_fixture(fixture)
    first = compile_next_continuation(**fixture, revision_number=1)
    fixture["parent_plan"] = first.plan
    verify = next(action for action in first.plan.actions if action.action_id == "verify.xss.r01")
    proof = next(action for action in first.plan.actions if action.action_id == "prove.xss.r01")
    fixture["parent_results"][verify.action_id] = replace(
        _result(verify, status=CapabilityResultStatus.TIMED_OUT, reason=CapabilityResultReason.TIMED_OUT),
        budget_consumed={
            "http_requests": max(1, verify.requested_budget["http_requests"] // 10),
            "tool_wall_seconds": verify.requested_budget["tool_wall_seconds"],
        },
        result_digest=None,
    )
    # The first round's proof succeeded over what the verifier signalled before the wall.
    _settle_round_fixture(fixture)
    assert fixture["parent_results"][proof.action_id].status is CapabilityResultStatus.SUCCESS

    second = compile_next_continuation(**fixture, revision_number=2)

    appended = {action.action_id: action for action in second.plan.actions[len(first.plan.actions):]}
    replanned = appended["prove.xss.r01.ext.r02"]
    assert replanned.dependencies == ("verify.xss.r01.ext.r02",)
    assert replanned.capability_args[EXTENDS_ARG] == proof.action_id
    assert tuple(replanned.capability_args[SIGNAL_SOURCES_ARG]) == tuple(proof.dependencies)
