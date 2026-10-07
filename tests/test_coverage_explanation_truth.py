"""What the Coverage tab says about a Scan must be what happened in it (soak 2026-10-07).

* N10: 146b6c03's XSS verifier attempted its only candidate and SQLi ran for 22 minutes, yet the
  assurance gaps read "active verification never ran; planned candidates were not attempted".
  Only proof escalation earned the verification credit, and a proof escalation that correctly
  had nothing to escalate (skipped, not applicable) counted its slice as unattempted work.
* N20: 6d25cc89 reported top-level ``coverage: complete`` over a required passive family left
  ``partial`` with 36 manifest entries never scheduled.
* N22: a not-examined run still showed "Examination strength 64/100".
"""

from __future__ import annotations

import dataclasses
import hashlib
import uuid

from api.runtime.observation_manifests import ObservationManifest
from api.scan.action_plan import ScanActionPlan
from api.scan.assessment import withhold_unexamined_grade
from api.scan.capability_result import (
    CapabilityResultReason,
    CapabilityResultReference,
    CapabilityResultStatus,
)
from api.scan.finalizer import finalize_scan_report
from tests.test_scan_orchestrator import SCAN_ID, _action, _result


def _with_observations(action, count, *, status=CapabilityResultStatus.SUCCESS):
    content = b"{}\n" * count
    manifest = ObservationManifest(
        manifest_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"coverage-truth:{action.action_id}")),
        owner_id=SCAN_ID,
        action_id=action.action_id,
        capability_name=action.capability_name,
        output_schema=action.output_schema,
        observation_count=count,
        content_sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        object_key=f"scans/{SCAN_ID}/{action.action_id}.jsonl",
    ).reference()
    base = _result(action, status=status)
    return CapabilityResultReference(**{
        **base.digest_material(),
        "receipt_ref": base.receipt_ref,
        "observation_manifest_ref": manifest,
    })


def _batch(action_id, ordinal, capability_name, *, count=1, dependencies=()):
    return dataclasses.replace(
        _action(action_id, ordinal, capability_name=capability_name, dependencies=dependencies),
        capability_args={"slice": {"start": 0, "count": count}, "manifest_entries": count},
        action_digest=None,
    )


def _attempt(action_id, status="success"):
    return {
        "kind": "candidate_attempt", "attempt_id": hashlib.sha256(action_id.encode()).hexdigest(),
        "candidate_id": "cand-1", "family": "xss", "status": status, "proof_state": "unproven",
    }


def _xss_report():
    """XSS attempted its one candidate; nothing was eligible for browser proof."""
    verify = _batch("verify.xss.r01", 0, "xss.verify_batch")
    prove = _batch(
        "prove.xss.r01", 1, "xss.browser_prove_batch", dependencies=(verify.action_id,),
    )
    final = _action("finalize.report", 2, dependencies=(verify.action_id, prove.action_id))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64, target_binding_digest="a" * 64,
        actions=(verify, prove, final),
    )
    results = {
        verify.action_id: _with_observations(verify, 1),
        prove.action_id: _result(
            prove, status=CapabilityResultStatus.SKIPPED,
            reason=CapabilityResultReason.NOT_APPLICABLE,
        ),
    }
    return finalize_scan_report(
        plan=plan, target_url="https://app.example.test", action_results=results,
        observations={verify.action_id: (_attempt(verify.action_id),)},
    )


def test_an_attempted_xss_candidate_is_active_verification_that_ran():
    report = _xss_report()
    gaps = report["result"]["assurance_gaps"]

    assert "active_verification_attempted" not in gaps
    assert report["result"]["assurance_components"]["active_verification_attempted"]["value"] == 1.0


def test_a_proof_escalation_with_nothing_to_escalate_left_no_candidate_unattempted():
    report = _xss_report()
    proof = report["coverage"]["candidate_coverage"]["xss_browser_proof"]

    assert proof["planned_candidates"] == 0 and proof["unattempted_candidates"] == 0
    assert "candidates_attempted" not in report["result"]["assurance_gaps"]


def test_a_family_that_left_entries_unscheduled_keeps_the_scan_coverage_partial():
    def ref(digest, entries):
        return {
            "kind": "endpoint", "manifest_digest": digest * 64, "entry_count": entries,
            "manifest_id": str(uuid.uuid4()), "schema_version": "x", "status": "complete",
            "content_schema": "x",
        }

    baseline = _action("baseline.http", 0)
    passive = dataclasses.replace(
        _action("passive.templates", 1, capability_name="templates.passive_batch"),
        capability_args={
            "slice": {"start": 0, "count": 2}, "manifest_entries": 3,
            "target_manifest_ref": ref("b", 3),
        },
        action_digest=None,
    )
    final = _action(
        "finalize.report", 2, dependencies=(baseline.action_id, passive.action_id),
    )
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64, target_binding_digest="a" * 64,
        actions=(baseline, passive, final),
    )
    results = {
        action.action_id: _result(action, status=CapabilityResultStatus.SUCCESS)
        for action in (baseline, passive)
    }
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results=results, observations={},
    )

    assert report["coverage"]["selected_family_gaps"] == ["nuclei_passive"]
    assert report["coverage"]["status"] == "partial"
    assert "selected_family_incomplete" in report["coverage"]["reasons"]
    assert report["scan_metadata"]["status"] == "partial"


def test_a_run_that_did_not_examine_the_application_has_no_examination_strength():
    report = {
        "result": {
            "risk_assessment_state": "not_examined", "application_observed": False,
            "score": 100, "grade": "A", "assurance_score": 64, "assurance_band": "limited",
            "assurance_gaps": ["authenticated_coverage"],
        },
        "coverage": {},
    }

    assert withhold_unexamined_grade(report) is True
    assert report["result"]["assurance_score"] == 0
    assert report["result"]["assurance_band"] == "none"
    assert report["result"]["assurance_gaps"] == [
        "application_not_observed", "authenticated_coverage",
    ]
