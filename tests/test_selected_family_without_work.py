"""A selected check family is planned when it has candidates, and reported when it has none.

Soak c4f1cf2e (honey.shakerscan.com, Balanced, policy active_testing with include_families
recon, nuclei_passive, xss, sqli, sensitive_exposure) planned only the passive template
batches and the exposure verifier. Its request carried no custom endpoints, discovery found no
route with a query parameter or an id-like path segment, and the two body endpoints it found
were withheld because allow_state_changing_http was off: the candidate manifest was empty, so
planning no XSS/SQLi verifier was correct. The comparison scan e5264021 planned both lanes only
because its request seeded `GET /api/v1/rag/documents?q=`.

What was wrong is the report: xss and sqli vanished from `family_coverage` and the Scan read
`coverage: complete` with no reason, as if they had never been selected.

Unit fixtures: synthetic TargetBinding and manifests built offline, no live Scan.
"""

from __future__ import annotations

SOAK_FAMILIES = ["recon", "nuclei_passive", "xss", "sqli", "sensitive_exposure"]
# The routes discovery found on the honeypot: no query key, no id-like segment, and one
# JSON-body API that only state-changing authority may test.
HONEY_SURFACE = [
    "GET /", "GET /.env", "GET /.git/config", "GET /swagger.json", "GET /health",
    "GET /chat", "GET /rag", "GET /phpinfo.php", "GET /backup.sql", "GET /web.config",
    'POST /api/v1/copilot/chat json:{"message":""}',
]
QUERY_ROUTES = ["GET /api/v1/rag/documents?q=", "GET /search?q=x"]


def _first_round(custom_endpoints, *, include_finalizer=False):
    from api.scan.admission_actions import _compile_scan_admission_action_authority
    from api.scan.continuation_rounds import compile_continuation_round
    from api.scan.contracts import resolve_scan_contract
    from api.scan.work_manifests import build_canonical_scan_nuclei_template_manifest
    from tests.test_continuation_rounds import _settle_round_fixture
    from tests.test_scan_continuation import _target
    from tests.test_scan_orchestrator import SCAN_ID

    target = _target()
    contract = resolve_scan_contract(budget_profile="balanced", policy={
        "active_testing": True, "include_families": SOAK_FAMILIES, "exclude_families": [],
    })
    assert list(contract.execution_plan.resolved_families) == SOAK_FAMILIES
    template = build_canonical_scan_nuclei_template_manifest(
        scan_id=SCAN_ID, target_binding_digest=target.digest, include_active=False,
    )
    parent, allocation = _compile_scan_admission_action_authority(
        scan_id=SCAN_ID, scan_contract=contract, target_binding=target,
        template_manifest_ref=template.reference().canonical_dict(),
    )
    fixture = {
        "parent_plan": parent, "allocation": allocation, "parent_results": {},
        "execution_plan": contract.execution_plan, "target": target,
        "target_url": "https://app.example.test", "observations": {}, "request_manifests": (),
        "options": {
            "template_manifest_ref": template.reference().canonical_dict(),
            "custom_endpoints": list(custom_endpoints),
        },
    }
    _settle_round_fixture(fixture)
    prepared = compile_continuation_round(
        **fixture, revision_number=1,
        include_finalizer=include_finalizer, finalize_only=False,
    )
    return parent, prepared, fixture


def test_the_soak_policy_plans_xss_and_sqli_lanes_when_candidates_exist():
    parent, first, _fixture = _first_round(HONEY_SURFACE + QUERY_ROUTES)
    appended = {action.capability_name for action in first.plan.actions[len(parent.actions):]}

    # sensitive_exposure in the policy (#346) and the SQLi concurrency/stage-fit work (#345)
    # leave the injection lanes in place beside the exposure verifier.
    assert {"xss.verify_batch", "sqli.verify_batch", "exposure.verify_batch"} <= appended


def test_without_a_query_or_path_candidate_no_injection_lane_is_planned():
    parent, first, _fixture = _first_round(HONEY_SURFACE)
    appended = {action.capability_name for action in first.plan.actions[len(parent.actions):]}
    candidates = [
        item for item in first.revision.work_manifest_references if item["kind"] == "candidate"
    ]

    assert not appended & {"xss.verify_batch", "sqli.verify_batch"}
    assert [item["entry_count"] for item in candidates] == [0]


def _finalized(*, custom_endpoints, resolved_families=SOAK_FAMILIES, manifests=()):
    import hashlib

    from api.scan.finalizer import finalize_scan_report
    from tests.test_scan_finalizer import _result_with_observation_count

    parent, final_round, fixture = _first_round(custom_endpoints, include_finalizer=True)
    results = dict(fixture["parent_results"])
    observations = {}
    for action in final_round.plan.actions[len(parent.actions):]:
        if action.action_id == "finalize.report":
            continue
        # Every planned batch attempts its whole slice, as the soak's passive and exposure
        # batches did, so only the unplanned families can differ from complete.
        count = min(
            int(action.capability_args["slice"]["count"]),
            int(action.capability_args.get("manifest_entries", 10**6)),
        )
        observations[action.action_id] = tuple({
            "kind": "candidate_attempt", "status": "success",
            "attempt_id": hashlib.sha256(f"{action.action_id}:{index}".encode()).hexdigest(),
        } for index in range(count))
        results[action.action_id] = _result_with_observation_count(action, count)
    return finalize_scan_report(
        plan=final_round.plan, plan_revision=final_round.revision,
        target_url="https://app.example.test",
        action_results=results, observations=observations,
        resolved_families=resolved_families,
        work_manifest_references=tuple(manifests),
    )


def _family(report, name):
    rows = [row for row in report["coverage"]["family_coverage"] if row["family"] == name]
    assert rows, f"selected family {name} is missing from family_coverage"
    return rows[0]


def test_a_selected_family_with_no_candidates_is_reported_not_omitted():
    report = _finalized(custom_endpoints=HONEY_SURFACE)
    coverage = report["coverage"]

    for name in ("xss", "sqli"):
        row = _family(report, name)
        assert row["selected"] is True
        assert row["batch_actions"] == 0
        assert row["planned_candidates"] == row["attempted_candidates"] == 0
        assert row["manifest_candidates"] == 0
        assert row["reason"] == "no_candidates"
        assert row["coverage_status"] == "complete"
    # The c4f1cf2e shape: every planned batch finished. Nothing to test is a settled outcome,
    # so the Scan stays complete, but it says so instead of reading a bare "complete".
    assert coverage["status"] == "complete"
    assert coverage["reasons"] == ["selected_family_no_candidates"]
    assert "xss" not in coverage["selected_family_gaps"]
    # recon is discovery, not a check family with a verifier row.
    assert "recon" not in {row["family"] for row in coverage["family_coverage"]}


def test_a_selected_family_with_candidates_but_no_action_is_a_coverage_gap():
    candidate_manifest = {
        "kind": "candidate", "status": "complete", "entry_count": 3,
        "manifest_id": "0" * 8 + "-0000-5000-8000-" + "0" * 12,
        "manifest_digest": "c" * 64, "content_schema": "candidate-manifest/v1",
        "schema_version": "scan-work-manifest-reference/v1",
    }
    report = _finalized(custom_endpoints=HONEY_SURFACE, manifests=(candidate_manifest,))
    coverage = report["coverage"]

    for name in ("xss", "sqli"):
        row = _family(report, name)
        assert row["coverage_status"] == "partial"
        assert row["reason"] == "not_planned"
        assert row["unscheduled_candidates"] == 3
        assert name in coverage["selected_family_gaps"]
    assert coverage["status"] == "partial"
    assert "selected_family_incomplete" in coverage["reasons"]
    assert coverage["grade_reliability"]["reliable"] is False


def test_a_caller_without_the_execution_plan_adds_no_family_row():
    # The offline report rebuild passes no resolved families; its digest must not move.
    report = _finalized(custom_endpoints=HONEY_SURFACE, resolved_families=None)
    families = {row["family"] for row in report["coverage"]["family_coverage"]}
    assert not families & {"xss", "sqli"}


def test_a_shard_that_planned_no_action_for_a_family_does_not_fail_the_merged_family():
    from collections import Counter

    from api.scan.parallel_compiler import _reconciled_family_coverage

    base = {
        "family": "xss", "selected": True, "required": True, "coverage_status": "complete",
        "reason": None, "batch_actions": 0, "planned_candidates": 0, "attempted_candidates": 0,
    }
    ran_elsewhere = _reconciled_family_coverage({
        **base, "batch_actions": 2, "planned_candidates": 4, "attempted_candidates": 4,
        "_unplanned_children": Counter({"not_planned": 1}),
    })
    assert ran_elsewhere["coverage_status"] == "complete"
    assert ran_elsewhere["reason"] is None
    assert "_unplanned_children" not in ran_elsewhere

    empty = _reconciled_family_coverage({
        **base, "_unplanned_children": Counter({"not_planned": 1, "no_candidates": 1}),
    })
    assert (empty["coverage_status"], empty["reason"]) == ("complete", "no_candidates")

    never = _reconciled_family_coverage({**base, "_unplanned_children": Counter({"not_planned": 2})})
    assert (never["coverage_status"], never["reason"]) == ("partial", "not_planned")


def test_the_new_coverage_reason_has_an_operator_label():
    from api.scan.explanation import _REASON_LABELS

    assert "no candidate" in _REASON_LABELS["selected_family_no_candidates"]
