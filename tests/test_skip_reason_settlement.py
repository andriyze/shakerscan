"""A skipped receipt settles not_applicable only for a reason that means "nothing to do".

An adapter that skips because a prerequisite was missing (no canonical origin, no
authenticated principal, a private request it could not read) did not find an empty surface.
Settling every unknown skip reason as not_applicable let such a skip read as a family that had
nothing to examine. Unit-test fixtures over the pure receipt mapping.
"""

from __future__ import annotations

import pytest

from scan.capability_result import CapabilityResultReason, CapabilityResultStatus
from scan.execution_backend import PostgresScanExecutionBackend
from tests.toplevel_scan_fixtures import baseline_plan as _plan
from tests.toplevel_scan_fixtures import receipt as _receipt


def _outcome(errors):
    action = _plan().actions[0]
    backend = object.__new__(PostgresScanExecutionBackend)  # the pure receipt mapping only
    return backend._receipt_outcome(_receipt(action, status="skipped", errors=errors))


@pytest.mark.parametrize("errors", [
    ("not_applicable",),
    # A proof with no candidate signal to escalate: nothing was eligible.
    ("no_xss_candidate_observation",),
    ("no_sqli_candidate_observation",),
])
def test_a_skip_with_nothing_to_do_is_not_applicable(errors):
    assert _outcome(errors) == (
        CapabilityResultStatus.SKIPPED, CapabilityResultReason.NOT_APPLICABLE,
    )


@pytest.mark.parametrize("errors", [
    ("no_canonical_origin",),
    ("origin_unreachable",),
    ("no_primary_principal",),
    ("credential_session_unavailable",),
    ("private_request_unavailable",),
    ("state_changing_authority_missing",),
    ("nuclei_template_index_unavailable",),
    ("something_new",),
    (),
])
def test_a_skip_for_a_missing_prerequisite_is_not_not_applicable(errors):
    assert _outcome(errors) == (
        CapabilityResultStatus.SKIPPED, CapabilityResultReason.PREREQUISITE_UNAVAILABLE,
    )


@pytest.mark.parametrize("errors, reason", [
    (("manifest_unavailable",), CapabilityResultReason.MANIFEST_UNAVAILABLE),
    (("authentication_uncertain",), CapabilityResultReason.AUTHENTICATION_UNCERTAIN),
    (("dependency_incomplete",), CapabilityResultReason.DEPENDENCY_INCOMPLETE),
])
def test_a_skip_with_a_stable_reason_keeps_it(errors, reason):
    assert _outcome(errors) == (CapabilityResultStatus.SKIPPED, reason)


@pytest.mark.parametrize("errors", [
    ("no_eligible_nuclei_templates",),
    ("verify_checks_excluded",),
    ("verify_checks_need_oob_interaction",),
])
def test_a_template_selection_that_left_nothing_to_run_has_its_own_reason(errors):
    """The Scan's template policy (or the checks a verify Scan named) left no template to run:
    not an empty surface and not a missing prerequisite."""
    assert _outcome(errors) == (
        CapabilityResultStatus.SKIPPED, CapabilityResultReason.NUCLEI_SELECTION_EMPTY,
    )
