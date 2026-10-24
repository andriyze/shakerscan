"""The standard active set keeps the active templates on thorough and deep only where they admit.

The active-template sweep holds 4,000 requests (and as many mutations with state-changing HTTP)
at admission, so a Scan whose operator lowered its request or mutation ceiling far enough is
refused at submission if the set still names them. The preset keeps them down to its floors
(``standard_active_template_floors``: twice the request hold, a quarter above the mutation hold)
and drops them below. Every ceiling at which it keeps them is admitted by the real admission
compile, with two sign-in profiles; naming ``nuclei_active`` adds them at any ceiling and
admission then decides, as before.
"""
from __future__ import annotations

import pytest

from api.scan.admission_actions import _compile_scan_admission_action_authority
from api.scan.contracts import BUDGET_PROFILES, resolve_scan_contract
from api.scan.work_manifests import build_canonical_scan_nuclei_template_manifest
from tests.test_scan_continuation import SCAN_ID, _target

HTTP = (8_000, 8_001, 10_000, 20_000, 59_999, 60_000, 100_000, 149_999)
MUTATIONS = (4_000, 4_999, 5_000, 5_001, 5_999, 6_000, 7_999, 8_000, 10_000, 14_999)
SIGN_INS = (
    {"profile_id": "profile-1", "scan_lane": "primary", "profile_version": 1, "auth_kind": "form_login"},
    {"profile_id": "profile-2", "scan_lane": "secondary", "profile_version": 1, "auth_kind": "form_login"},
)


def _admit(contract) -> None:
    target = _target()
    template = build_canonical_scan_nuclei_template_manifest(
        scan_id=SCAN_ID, target_binding_digest=target.digest,
        include_active="nuclei_active" in contract.execution_plan.resolved_families,
    )
    _compile_scan_admission_action_authority(
        scan_id=SCAN_ID, scan_contract=contract, target_binding=target, credential_refs=SIGN_INS,
        template_manifest_ref=template.reference().canonical_dict(),
    )


def _cases(profile):
    budget = BUDGET_PROFILES[profile]
    for value in HTTP:
        if value <= budget.max_http_requests:
            yield False, {"max_http_requests": value}
            yield True, {"max_http_requests": value}
    for value in MUTATIONS:
        if value <= budget.max_state_changing_requests:
            yield True, {"max_state_changing_requests": value}


@pytest.mark.parametrize("profile", ["thorough", "deep"])
def test_every_lowered_ceiling_that_keeps_the_active_templates_is_admitted(profile):
    kept = 0
    for state_changing, advanced in _cases(profile):
        contract = resolve_scan_contract(
            budget_profile=profile,
            policy={"active_testing": True, "allow_state_changing_http": state_changing},
            advanced=advanced, approval_receipt_id="approval-1",
        )
        if "nuclei_active" not in contract.execution_plan.resolved_families:
            continue
        kept += 1
        _admit(contract)  # raises when admission refuses the sweep
    assert kept >= 10


@pytest.mark.parametrize("profile", ["thorough", "deep"])
def test_the_profile_defaults_admit_the_active_templates(profile):
    for state_changing in (False, True):
        contract = resolve_scan_contract(
            budget_profile=profile,
            policy={"active_testing": True, "allow_state_changing_http": state_changing},
            approval_receipt_id="approval-1",
        )
        assert "nuclei_active" in contract.execution_plan.resolved_families
        _admit(contract)


@pytest.mark.parametrize("profile", ["thorough", "deep"])
def test_a_mutation_ceiling_lowered_toward_the_floor_keeps_what_the_profiles_own_runs(profile):
    """thorough's own mutation ceiling (6,000) runs the sweep, so lowering it by any amount down to
    the floor keeps the sweep too, and is admitted."""
    mutations = BUDGET_PROFILES[profile].max_state_changing_requests
    for value in (mutations, mutations - 1, 5_999, 5_001, 5_000):
        contract = resolve_scan_contract(
            budget_profile=profile,
            policy={"active_testing": True, "allow_state_changing_http": True},
            advanced={"max_state_changing_requests": value}, approval_receipt_id="approval-1",
        )
        assert "nuclei_active" in contract.execution_plan.resolved_families, value
        _admit(contract)


def test_every_floor_is_under_the_ceilings_of_the_profiles_that_add_the_templates():
    """A floor above a profile's own ceiling would drop the sweep at a ceiling lowered by one from
    the profile's own, which runs it."""
    from api.scan.contracts import SCAN_FAMILY_PRESET_PROFILE_ADDITIONS, standard_active_template_floors

    floors = standard_active_template_floors(state_changing_allowed=True)
    profiles = [profile for profile, families in SCAN_FAMILY_PRESET_PROFILE_ADDITIONS["standard_active"].items()
                if "nuclei_active" in families]
    assert sorted(profiles) == ["deep", "thorough"]
    for profile in profiles:
        for name, floor in floors.items():
            assert floor < int(getattr(BUDGET_PROFILES[profile], name)), (profile, name, floor)
