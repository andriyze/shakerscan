"""Behavioral contract for the offline AI Boundary regression handoff."""
from __future__ import annotations

from uuid import UUID

import pytest

from api.ai_gate.boundary.contract import ContractError, canonical_hash
from api.ai_gate.boundary.hypothesis import compile_boundary_hypothesis, materialize_boundary_contract
from api.ai_gate.boundary.regression import (
    build_boundary_regression_artifact, evaluate_boundary_regression_artifact,
)
from api.ai_targets import router as target_router
from fastapi import HTTPException


TARGET = str(UUID(int=1))
SOURCE = str(UUID(int=2))
LATER = str(UUID(int=3))


def _proposal_and_base(*, with_digest=True):
    owner = {"role": "owner", "subject": "owner-subject", "tenant": "tenant-a", "resource_id": "order-a"}
    attacker = {"role": "attacker", "subject": "attacker-subject", "tenant": "tenant-b", "resource_id": "order-b"}
    proposal = compile_boundary_hypothesis({
        "version": 1, "hypothesis_id": "hunt-boundary-read", "kind": "cross_tenant_read",
        "owner": owner, "attacker": attacker,
        "provenance": [{
            "kind": "hunt_candidate", "id": "candidate-1",
            **({"evidence_sha256": "a" * 64} if with_digest else {}),
        }],
    })
    base = {
        "version": 1, "name": "regression-boundary", "owner": owner, "attacker": attacker,
        "identity": {"path": "/identity", "subject_field": "subject", "tenant_field": "tenant"},
        "resource": {"path": "/orders/{{resource_id}}", "id_field": "id", "owner_field": "owner",
                     "tenant_field": "tenant", "marker_field": "marker"},
        "response_path": "answer",
    }
    return proposal, base


def _scan(scan_id=SOURCE, *, state="passed", time="2026-09-25T12:00:00+00:00"):
    proposal, base = _proposal_and_base()
    digest = materialize_boundary_contract(proposal, boundary_base=base)["boundary_contract_sha256"]
    boundary = {
        "schema_version": "ai-boundary/v6", "contract_sha256": digest,
        "state": state, "coverage_complete": True, "errors": [], "violations": [],
        "controls": [{"name": name, "passed": True} for name in (
            "backend_denies_cross_customer_read", "permitted_chat_works:owner",
            "permitted_chat_works:attacker",
        )],
    }
    return {
        "id": scan_id, "ai_target_id": TARGET, "status": "completed", "run_kind": "ai_api",
        "created_at": time,
        "options": {"ai_probe_pack": "shaker-ai-boundary", "ai_environment": "staging",
                    "ai_scan_profile": "standard"},
        "result": {"ai_gate": {"boundary": boundary}, "findings": []},
    }


def _artifact(source=None):
    proposal, base = _proposal_and_base()
    return build_boundary_regression_artifact(
        proposal=proposal, boundary_base=base, target_id=TARGET,
        source_scan=source or _scan(),
    )


def _later(**kwargs):
    return _scan(LATER, time="2026-09-26T12:00:00+00:00", **kwargs)


def test_passed_source_exports_replay_request_and_later_passes_without_proof_promotion():
    artifact = _artifact()
    assert artifact["verify_request"]["environment"] == "staging"
    assert artifact["approval_receipt_included"] is False
    assert artifact["execution_enabled"] is False
    outcome = evaluate_boundary_regression_artifact(artifact, scan=_later())
    assert outcome["status"] == "pass"
    assert outcome["promotion_authority"] is False


def test_failed_source_requires_matching_deterministic_proof():
    source = _scan(state="failed")
    with pytest.raises(ContractError, match="lacks_deterministic_proof"):
        _artifact(source)
    digest = source["result"]["ai_gate"]["boundary"]["contract_sha256"]
    source["result"]["findings"] = [{
        "verified": True, "proof_state": "exploited",
        "evidence": {"contract_sha256": digest},
        "proof_contract_v2": {"verdict": "verified", "predicate": {"satisfied": True}},
    }]
    assert _artifact(source)["source_boundary_state"] == "failed"


@pytest.mark.parametrize("change,code", [
    (lambda s: s.update(status="running"), "scan_incomplete"),
    (lambda s: s.update(ai_target_id=str(UUID(int=9))), "scan_target_mismatch"),
    (lambda s: s["result"]["ai_gate"]["boundary"].update(coverage_complete=False), "source_incomplete"),
    (lambda s: s["result"]["ai_gate"]["boundary"]["controls"].pop(), "legitimate_control_failed"),
    (lambda s: s["result"]["ai_gate"]["boundary"].update(contract_sha256="sha256:wrong"), "contract_mismatch"),
])
def test_source_rejects_unsafe_or_unmatched_scan(change, code):
    source = _scan()
    change(source)
    with pytest.raises(ContractError, match=code):
        _artifact(source)


def test_later_failed_control_or_violation_fails_and_incomplete_is_inconclusive():
    artifact = _artifact()
    later = _later()
    later["result"]["ai_gate"]["boundary"]["controls"][0]["passed"] = False
    assert evaluate_boundary_regression_artifact(artifact, scan=later)["status"] == "fail"
    later = _later()
    later["result"]["ai_gate"]["boundary"].update(state="failed", violations=[{"path": "read"}])
    assert evaluate_boundary_regression_artifact(artifact, scan=later)["status"] == "fail"
    later = _later()
    later["result"]["ai_gate"]["boundary"].update(coverage_complete=False, errors=["timeout"])
    assert evaluate_boundary_regression_artifact(artifact, scan=later)["status"] == "inconclusive"


def test_later_scan_must_follow_source_and_match_profile():
    artifact = _artifact()
    with pytest.raises(ContractError, match="requires_later_scan"):
        evaluate_boundary_regression_artifact(artifact, scan=_scan())
    later = _later()
    later["options"]["ai_environment"] = "preview"
    with pytest.raises(ContractError, match="run_profile_mismatch"):
        evaluate_boundary_regression_artifact(artifact, scan=later)


def test_artifact_digest_and_required_control_policy_cannot_be_weakened():
    artifact = _artifact()
    artifact["acceptance"]["required_legitimate_controls"].pop()
    with pytest.raises(ContractError, match="artifact_digest_mismatch"):
        evaluate_boundary_regression_artifact(artifact, scan=_later())
    artifact["artifact_sha256"] = canonical_hash({k: v for k, v in artifact.items() if k != "artifact_sha256"})
    with pytest.raises(ContractError, match="artifact_controls_invalid"):
        evaluate_boundary_regression_artifact(artifact, scan=_later())


def test_export_rejects_ignored_payload_fields_and_allows_hunt_provenance_without_digest():
    proposal, base = _proposal_and_base()
    proposal["approval_receipt_id"] = "receipt-that-must-not-be-exported"
    with pytest.raises(ContractError, match="proposal_extra_or_missing_fields"):
        build_boundary_regression_artifact(
            proposal=proposal, boundary_base=base, target_id=TARGET, source_scan=_scan(),
        )
    proposal, base = _proposal_and_base(with_digest=False)
    assert build_boundary_regression_artifact(
        proposal=proposal, boundary_base=base, target_id=TARGET, source_scan=_scan(),
    )["approval_receipt_included"] is False


@pytest.mark.asyncio
async def test_api_loads_both_scans_by_target_in_read_only_snapshot(monkeypatch):
    class DB:
        readonly = []
        lookups = []

        def acquire(self):
            return self

        def transaction(self, **kwargs):
            self.readonly.append(kwargs)
            return self

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

        async def fetchrow(self, query, scan_id, target_id):
            self.lookups.append((query, scan_id, target_id))
            if target_id != UUID(TARGET):
                return None
            if str(scan_id) == SOURCE:
                return _scan()
            if str(scan_id) == LATER:
                return _later()
            return None

    db = DB()
    monkeypatch.setattr(target_router, "_pool", lambda: db)
    proposal, base = _proposal_and_base()
    export = target_router.AIBoundaryRegressionExportRequest(
        proposal=proposal, boundary_base=base, source_scan_id=SOURCE,
    )
    artifact = await target_router.export_ai_boundary_regression(TARGET, export)
    request = target_router.AIBoundaryRegressionEvaluateRequest(artifact=artifact, scan_id=LATER)
    result = await target_router.evaluate_ai_boundary_regression(TARGET, request)
    assert result["status"] == "pass"
    assert len(db.lookups) == 3
    assert all("ai_target_id=$2" in query and target == UUID(TARGET) for query, _, target in db.lookups)
    assert db.readonly == [
        {"isolation": "repeatable_read", "readonly": True},
        {"isolation": "repeatable_read", "readonly": True},
    ]
    with pytest.raises(HTTPException) as exc:
        await target_router.export_ai_boundary_regression(str(UUID(int=9)), export)
    assert exc.value.status_code == 404
