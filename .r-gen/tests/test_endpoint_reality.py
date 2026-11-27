"""The reality classifier must abstain wherever the observation cannot decide.

Each abstention below corresponds to a measured failure of the previous boolean approach: a real
protected route and a wordlist guess returning an identical auth response, and a POST-only route
demoted because it was probed with GET.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from runtime.endpoint_reality import (  # noqa: E402
    PHANTOM,
    REAL,
    UNKNOWN,
    classify_endpoint_reality as classify,
)

NOT_FOUND = [("500", 2478)]


def test_a_response_unlike_the_control_is_real():
    verdict = classify(probe_status="200", probe_size=16563, signatures=NOT_FOUND)
    assert verdict.outcome == REAL and verdict.reason == "distinct_from_not_found"


def test_a_response_matching_the_control_is_phantom():
    verdict = classify(probe_status="500", probe_size=2432, signatures=NOT_FOUND)
    assert verdict.outcome == PHANTOM and verdict.reason == "matches_not_found_signature"


def test_a_literal_404_is_phantom_but_says_why():
    # Kept explicit: HTTP permits 404 for an existing forbidden resource.
    verdict = classify(probe_status="404", probe_size=9, signatures=NOT_FOUND)
    assert verdict.outcome == PHANTOM and verdict.reason == "literal_not_found"


def test_an_auth_masked_prefix_is_undecidable_not_phantom():
    """The measured failure: real protected routes and wordlist guesses both answered 401/83.

    A boolean classifier called these phantoms and would have demoted real endpoints.
    """
    verdict = classify(probe_status="401", probe_size=83, signatures=[("401", 83)])
    assert verdict.outcome == UNKNOWN and verdict.reason == "auth_masks_existence"


def test_a_route_declared_for_another_verb_is_not_judged_by_a_get_probe():
    """The measured harm: a real POST-only login route answered GET with the not-found shape."""
    verdict = classify(
        probe_status="500", probe_size=2432, signatures=NOT_FOUND,
        probed_method="GET", declared_method="POST",
    )
    assert verdict.outcome == UNKNOWN and verdict.reason == "probed_method_differs"


def test_a_missing_control_yields_unknown():
    verdict = classify(probe_status="200", probe_size=120, signatures=[])
    assert verdict.outcome == UNKNOWN and verdict.reason == "no_control"


def test_an_unmeasurable_size_yields_unknown_not_a_match():
    # A non-auth status so this isolates the size rule; an auth status abstains earlier for
    # the stronger reason that the middleware masks existence.
    for probe_size, control in ((-1, [("500", 2478)]), (2432, [("500", -1)])):
        verdict = classify(probe_status="500", probe_size=probe_size, signatures=control)
        assert verdict.outcome == UNKNOWN and verdict.reason == "control_size_unknown"


def test_auth_masking_takes_precedence_over_the_size_rule():
    """Both abstain, but the auth reason is the one an operator needs to see."""
    verdict = classify(probe_status="401", probe_size=-1, signatures=[("401", 83)])
    assert verdict.outcome == UNKNOWN and verdict.reason == "auth_masks_existence"


def test_an_inconclusive_probe_yields_unknown():
    for status in ("ERR", "", "0"):
        assert classify(probe_status=status, probe_size=-1, signatures=NOT_FOUND).outcome == UNKNOWN


def test_unknown_is_never_reported_as_decided():
    assert classify(probe_status="ERR", probe_size=-1, signatures=NOT_FOUND).decided is False
    assert classify(probe_status="200", probe_size=16563, signatures=NOT_FOUND).decided is True


def test_a_fragment_route_is_never_judged_from_an_http_probe():
    """The server returns the app shell for every fragment, so the probe necessarily matches
    the not-found control. Calling that a phantom would discard the DOM surface."""
    verdict = classify(
        probe_status="200", probe_size=9903, signatures=[("200", 9903)], path="/#/search",
    )
    assert verdict.outcome == UNKNOWN and verdict.reason == "client_side_route"
