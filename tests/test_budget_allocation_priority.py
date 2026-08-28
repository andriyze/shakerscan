"""Deterministic proof must outrank broad template breadth for the same budget.

`_ACTIVE_VERIFIER_CAPABILITIES` was written by hand when only the sqli/xss/authz
verifiers existed and never grew with the family set. The exposure, nosqli and
authz_surface verifiers -- all three belonging to REQUIRED families -- therefore landed
in the catch-all tier, the same one as optional passive template batches. Ties there
break on `action_id`, so on Juice Shop `passive.templates.001` was funded ahead of
`verify.exposure.001` by nothing but alphabetical order: 102 of 210 exposure candidates
went unattempted and the grade came back unreliable.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from runtime.capability_registry import CAPABILITY_REGISTRY  # noqa: E402
from scan.budget_allocator import (  # noqa: E402
    _ACTIVE_VERIFIER_CAPABILITIES,
    _NON_SCAN_VERIFIER_CAPABILITIES,
    _TEMPLATE_BREADTH_CAPABILITIES,
    _VERIFIER_NAME_SUFFIXES,
    _allocation_priority,
)


class _Action:
    """The two fields `_allocation_priority` reads, plus the flags it checks."""

    def __init__(self, action_id, capability_name, required=False, supporting=False):
        self.action_id = action_id
        self.capability_name = capability_name
        self.required = required
        self.supporting = supporting


def _registry_names():
    return {str(getattr(spec, "name", spec)) for spec in CAPABILITY_REGISTRY.list()}


def test_every_registry_verifier_is_ranked_as_a_verifier():
    expected = {
        name for name in _registry_names()
        if name.endswith(_VERIFIER_NAME_SUFFIXES)
        and name not in _NON_SCAN_VERIFIER_CAPABILITIES
    }
    assert expected, "no verifier capabilities found -- the suffix list drifted"
    assert _ACTIVE_VERIFIER_CAPABILITIES == expected


def test_the_families_that_were_missing_are_covered():
    for name in (
        "exposure.verify_batch", "nosqli.verify_batch", "authz_surface.verify_batch",
    ):
        assert name in _ACTIVE_VERIFIER_CAPABILITIES, name


def test_verification_outranks_template_breadth():
    verifier = _Action("verify.exposure.001", "exposure.verify_batch")
    templates = _Action("passive.templates.001", "templates.passive_batch")
    assert _allocation_priority(verifier) < _allocation_priority(templates), (
        "optional proof must be funded before optional breadth"
    )


def test_every_template_capability_is_ranked_as_breadth():
    template_names = {name for name in _registry_names() if name.startswith("templates.")}
    assert template_names <= _TEMPLATE_BREADTH_CAPABILITIES, (
        f"template capabilities left in the catch-all tier: "
        f"{sorted(template_names - _TEMPLATE_BREADTH_CAPABILITIES)}"
    )


def test_required_and_mandatory_precedence_is_unchanged():
    mandatory = _Action("baseline.http", "http.request", required=True)
    required = _Action("verify.exposure", "exposure.verify_batch", required=True)
    supporting = _Action("discover.web_crawl", "web.crawl", supporting=True)
    optional_verifier = _Action("verify.exposure.001", "exposure.verify_batch")
    order = [mandatory, required, supporting, optional_verifier]
    priorities = [_allocation_priority(action) for action in order]
    assert priorities == sorted(priorities), priorities
    assert priorities[0] == 0


def test_non_scan_verifiers_stay_out_of_the_scan_tier():
    for name in _NON_SCAN_VERIFIER_CAPABILITIES:
        assert name not in _ACTIVE_VERIFIER_CAPABILITIES
