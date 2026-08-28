"""A Hunt E2E check must probe a route its target actually serves.

H-16 asserts a Hunt candidate becomes a deterministically verified finding, and H-17
asserts a candidate without sensitive evidence is not promoted. Both probe
`/leaked-cloud-credentials` and `/public-service-directory`, which exist only in
`tests/e2e/fixtures/fixtures_server.py`. CI points the Hunt area at Juice Shop, so the
positive case probed a 404 and could never verify -- and the negative case passed for the
wrong reason, because nothing was promoted when nothing was found.

A check that cannot fail for the right reason is worse than no check.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tests" / "e2e" / "run_e2e.py"
FIXTURES = ROOT / "tests" / "e2e" / "fixtures" / "fixtures_server.py"
SOURCE = RUNNER.read_text(encoding="utf-8")


def _fixture_only_routes():
    """Routes the fixture server serves and a general web target would not."""
    served = set(re.findall(r'p == "(/[a-z0-9\-/]+)"', FIXTURES.read_text(encoding="utf-8")))
    return {route for route in served if route in SOURCE}


def test_the_verification_pair_runs_against_the_fixture_target():
    assert "/leaked-cloud-credentials" in SOURCE
    block = SOURCE[SOURCE.index("Verify an anonymous credential exposure end to end.") - 900:]
    block = block[:block.index("H-17") if "H-17" in block else len(block)]
    assert "_hunt_fixture_authority()" in block, (
        "the verification Hunt is not bound to the fixture server that serves its routes"
    )
    assert "verify_target_id" in block


def test_no_fixture_only_route_is_probed_against_the_configured_hunt_target():
    """The Hunt target is operator-configurable; fixture routes are not on it.

    Traced through the Hunt each route is probed under rather than a fixed window of
    surrounding text -- a negative control can sit well after the binding that governs it.
    """
    fixture_targets = set(
        re.findall(r"(\w+), \w+, \w+ = _hunt_fixture_authority\(", SOURCE)
    )
    assert fixture_targets, "no fixture-bound Hunt authority found"

    starts = [
        (match.start(), match.group(1))
        for match in re.finditer(r"_hunt_start_payload\(\s*\n\s*(\w+),", SOURCE)
    ]
    assert starts, "no Hunt start payloads found -- the guard would pass vacuously"

    routes = _fixture_only_routes()
    assert routes, "no fixture-only routes found -- the guard would pass vacuously"
    for route in sorted(routes):
        index = SOURCE.index(f'"{route}"')
        governing = [(pos, var) for pos, var in starts if pos < index]
        assert governing, f"{route} is probed before any Hunt is started"
        _, target_var = governing[-1]
        assert target_var in fixture_targets, (
            f"{route} is probed under a Hunt bound to {target_var!r}, which is not the "
            "fixture target that serves it"
        )
