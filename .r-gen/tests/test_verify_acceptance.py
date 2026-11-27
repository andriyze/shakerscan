"""Re-derivable acceptance CI check (Wave 7).

Asserts that recomputing each benchmark app's scorecard from the committed raw artifact matches the
committed oracle (``acceptance.json``) — the stored verdict is never trusted, it is re-derived, and
this fails on drift (an artifact or scorer change that isn't re-pinned via ``--update``).
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import verify_acceptance as va  # noqa: E402


def _apps_with_samples():
    for app, fixture_stem in va.APPS.items():
        if os.path.exists(va._report_path(app)):
            yield app, fixture_stem


def test_recompute_matches_committed_oracle():
    checked = 0
    for app, fixture_stem in _apps_with_samples():
        oracle_path = va._oracle_path(app)
        assert os.path.exists(oracle_path), f"missing acceptance oracle for {app} (run verify_acceptance.py --update)"
        with open(oracle_path) as fh:
            oracle = json.load(fh)
        metrics = va.recompute(app, fixture_stem)
        assert metrics == oracle, f"acceptance drift for {app}: {metrics} != {oracle}"
        checked += 1
    assert checked > 0, "no committed benchmark samples found to re-derive"


def test_recompute_is_deterministic():
    for app, fixture_stem in _apps_with_samples():
        assert va.recompute(app, fixture_stem) == va.recompute(app, fixture_stem)


def test_oracle_records_verified_counts_are_ints():
    for app, _ in _apps_with_samples():
        with open(va._oracle_path(app)) as fh:
            oracle = json.load(fh)
        assert isinstance(oracle["verified_high_critical"], int)
        assert isinstance(oracle["gates"], dict) and oracle["gates"]
