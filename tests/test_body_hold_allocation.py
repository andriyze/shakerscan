"""A verifier slice holds mutation allowance only for the body candidates it holds.

Holding one body-attempt allowance for every slot a slice could hold -- whatever the slice
held -- reserved 2,880 of a thorough Scan's 6,000 mutations for two XSS slices of query
candidates. Active templates, which hold a mutation for every request, then fit one slice
in the whole Scan instead of six, and a lowered mutation ceiling cut the verifier slices
themselves. Once the round's candidates are materialized, a slice holds the body floor for
each body candidate in it that its own holds can fund, and a lane with no body candidate
left is shaped exactly as it is without mutation authority.
"""

from __future__ import annotations

from collections import Counter

APPROVAL = "11111111-1111-4111-8111-111111111111"


def _rounds(profile, endpoints, *, families=None, advanced=None, rounds=8):
    from api.scan.admission_actions import _compile_scan_admission_action_authority
    from api.scan.contracts import resolve_scan_contract
    from api.scan.continuation_rounds import compile_next_continuation
    from api.scan.work_manifests import build_canonical_scan_nuclei_template_manifest
    from tests.test_continuation_rounds import _settle_round_fixture
    from tests.test_scan_continuation import _target
    from tests.test_scan_orchestrator import SCAN_ID

    policy = {"active_testing": True, "allow_state_changing_http": True}
    policy.update(
        {"preset": "custom", "include_families": list(families)} if families
        else {"preset": "standard_active"}
    )
    target = _target()
    contract = resolve_scan_contract(
        budget_profile=profile, policy=policy, advanced=advanced,
        approval_receipt_id=APPROVAL,
    )
    template = build_canonical_scan_nuclei_template_manifest(
        scan_id=SCAN_ID, target_binding_digest=target.digest,
        include_active="nuclei_active" in contract.execution_plan.resolved_families,
    )
    template_ref = template.reference().canonical_dict()
    parent, allocation = _compile_scan_admission_action_authority(
        scan_id=SCAN_ID, scan_contract=contract, target_binding=target,
        template_manifest_ref=template_ref,
    )
    fixture = dict(
        parent_plan=parent, allocation=allocation, parent_results={},
        execution_plan=contract.execution_plan, target=target,
        target_url="https://app.example.test", observations={}, request_manifests=(),
        options={
            "template_manifest_ref": template_ref, "custom_endpoints": list(endpoints),
            "scan_policy": {"allow_state_changing_http": True},
        },
    )
    appended_by_round = []
    for number in range(1, rounds + 1):
        _settle_round_fixture(fixture)
        prepared = compile_next_continuation(**fixture, revision_number=number)
        appended = prepared.plan.actions[len(fixture["parent_plan"].actions):]
        appended_by_round.append(appended)
        fixture["parent_plan"] = prepared.plan
        if any(action.action_id == "finalize.report" for action in appended):
            break
    return appended_by_round


def _covered(appended_by_round):
    covered = Counter()
    for appended in appended_by_round:
        for action in appended:
            raw = action.capability_args.get("slice")
            if raw:
                covered[action.capability_name] += int(raw["count"])
    return covered


QUERY_ONLY = [f"GET /p{index}?q=1&id=2" for index in range(200)]


def test_a_slice_of_query_candidates_holds_no_mutation_allowance():
    first = _rounds("thorough", QUERY_ONLY, rounds=1)[0]
    verifiers = [
        action for action in first
        if action.capability_name in {"xss.verify_batch", "sqli.verify_batch"}
    ]

    assert verifiers
    assert all(
        int(action.requested_budget.get("state_changing_requests", 0)) == 0
        for action in verifiers
    )


def test_active_templates_are_not_starved_by_holds_for_absent_body_candidates():
    covered = _covered(_rounds(
        "thorough", QUERY_ONLY,
        families=["recon", "nuclei_passive", "nuclei_active", "xss", "sqli"],
    ))

    # Every discovered endpoint (and the origin) reaches the active pack, as it did before
    # verifier slices held a mutation allowance per slot.
    assert covered["templates.active_batch"] == len(QUERY_ONLY) + 1
    assert covered["xss.verify_batch"] >= 96 and covered["sqli.verify_batch"] >= 128


def test_a_lowered_mutation_ceiling_does_not_cut_query_verifier_slices():
    covered = _covered(_rounds(
        "thorough", QUERY_ONLY, advanced={"max_state_changing_requests": 2000},
    ))

    assert covered["xss.verify_batch"] >= 96
    assert covered["sqli.verify_batch"] >= 128


def test_body_candidates_still_get_one_allowance_each():
    from api.scan.external_process import batch_attempt_floor

    bodies = [
        'POST /api/v1/agent/run json:{"message":"hello"}',
        'POST /api/v1/support/message json:{"message":"hello"}',
    ]
    first = _rounds("balanced", bodies, rounds=1)[0]
    xss = [action for action in first if action.capability_name == "xss.verify_batch"]
    floor = batch_attempt_floor("xss.verify_batch", body_candidate=True)

    assert xss
    held = sum(int(action.requested_budget.get("state_changing_requests", 0)) for action in xss)
    assert held >= floor["state_changing_requests"] * 2, (
        [dict(action.requested_budget) for action in xss]
    )
