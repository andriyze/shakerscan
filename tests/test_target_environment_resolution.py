"""One environment per target, resolved the same way everywhere.

Review finding R2. Creation stored the operator's choice as `metadata.cohort` and passed it
straight to authorization, while the authorization helper read `metadata.environment` and
defaulted to production. Two consequences:

Case A, add-now/authorize-later: a target saved as Lab authorized under a Lab evaluation at
creation and a Production one when authorized afterwards, so the same row could be admitted and
then refused.

Case B, reuse: web targets are host-level, so a second request for the same host reuses the
existing row. The response reported the stored Production cohort while the authorization took
Lab from the incoming request -- a Production record carrying authority granted under a Lab
evaluation, with nothing saved to say so.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from target_authorization import effective_target_environment  # noqa: E402


def test_a_stored_cohort_is_the_targets_environment():
    """Case A: authorizing later must reach the same verdict as authorizing at creation."""
    assert effective_target_environment({"cohort": "lab"}) == "lab"
    assert effective_target_environment({"cohort": "staging"}) == "staging"


def test_an_explicit_environment_wins_over_a_cohort():
    """`environment` is the older, explicitly-set field; a cohort is a presentation label."""
    assert effective_target_environment({"environment": "production", "cohort": "lab"}) == "production"


def test_an_unclassified_cohort_is_not_an_environment():
    assert effective_target_environment({"cohort": "unclassified"}) == "production"
    assert effective_target_environment({}) == "production"
    assert effective_target_environment(None) == "production"


def test_a_caller_may_request_one_explicitly():
    assert effective_target_environment({"cohort": "lab"}, requested="production") == "production"
    assert effective_target_environment({}, requested="lab") == "lab"


def test_creation_and_later_authorization_agree_on_the_same_row():
    """The two paths that disagreed: one-step creation, and authorize-later."""
    stored = {"cohort": "lab"}
    at_creation = effective_target_environment(stored, requested="lab")
    afterwards = effective_target_environment(stored, requested=None)
    assert at_creation == afterwards == "lab"


def test_reuse_keeps_the_existing_environment_rather_than_the_new_request():
    """Case B. A request choosing Lab must not authorize an existing Production row as Lab."""
    existing = {"cohort": "production"}
    # `created` is False for a reused row, so the incoming cohort is not forwarded.
    assert effective_target_environment(existing, requested=None) == "production"


def test_the_creation_path_only_forwards_a_cohort_for_a_new_row():
    router = (ROOT / "api" / "targets" / "router.py").read_text(encoding="utf-8")
    start = router.index("authorized_by = getattr(request, \"authorized_by\", None)")
    block = router[start:start + 1200]
    assert "effective_target_environment" in block, (
        "creation still resolves the authorization environment its own way"
    )
    assert "if row['created']" in block, (
        "the incoming cohort is forwarded even when an existing target was reused, so a request "
        "can authorize a Production row under a Lab evaluation"
    )


def test_authorization_uses_the_shared_resolver():
    canonical = (ROOT / "api" / "target_authorization.py").read_text(encoding="utf-8")
    assert "env = effective_target_environment(metadata, requested=environment)" in canonical
    assert 'metadata.get("environment") if isinstance(metadata, dict) else ""' not in canonical, (
        "the old inline fallback is back; it ignores a stored cohort"
    )
