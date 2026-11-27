"""One resolved budget contract, consumed not re-resolved (docs §4).

The budget is resolved once at submission and stamped into
options['resolved_budget']; runtime paths must CONSUME that exact object instead
of re-deriving it (which is how a path silently re-clamped a raised budget).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from constants import resolve_scan_budget, resolve_or_consume_budget  # noqa: E402


def test_submission_budget_is_stamped_with_provenance():
    b = resolve_scan_budget("smart", "thorough")
    assert b.get("budget_source") == "resolved"
    assert b.get("max_duration_minutes") is not None


def test_consume_prefers_the_stamped_contract():
    # A scan stamped at submission with a raised duration; a runtime path must use
    # THAT value, not re-derive a smaller default.
    stamped = resolve_scan_budget("standard", "balanced")
    stamped["max_duration_minutes"] = 999
    stamped["budget_source"] = "submission"
    options = {"resolved_budget": stamped, "budget_profile": "balanced"}
    consumed = resolve_or_consume_budget("standard", options=options)
    assert consumed is stamped  # the exact same object, not a copy/re-resolve
    assert consumed["max_duration_minutes"] == 999


def test_consume_falls_back_when_no_stamp():
    # Legacy/older scan with no stamped budget -> resolve fresh.
    consumed = resolve_or_consume_budget("standard", options={"budget_profile": "balanced"})
    assert consumed["max_duration_minutes"] is not None
    assert consumed["budget_source"] == "resolved"


def test_consume_ignores_malformed_stamp():
    # A non-dict / incomplete stamp must not be trusted as the contract.
    for bad in (None, "x", {}, {"budget_profile": "balanced"}):
        consumed = resolve_or_consume_budget("standard", options={"resolved_budget": bad})
        assert isinstance(consumed, dict)
        assert consumed.get("max_duration_minutes") is not None


def test_consume_without_options_resolves():
    consumed = resolve_or_consume_budget("quick")
    assert consumed["scan_type"] == "quick"
    assert consumed["max_duration_minutes"] is not None
