"""Unit tests for the pure hypothesis lifecycle state machine (api/hypothesis_lifecycle.py)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

import hypothesis_lifecycle as lc  # noqa: E402


def test_self_test():
    lc._self_test()


def test_terminal_and_actionable_sets():
    for s in ("refuted", "promoted", "dead"):
        assert lc.is_terminal(s)
        assert not lc.is_actionable(s)
    for s in ("blocked", "exhausted"):
        assert not lc.is_terminal(s)
        assert not lc.is_actionable(s)  # parked, not claimable
    for s in ("open", "claimed", "testing", "supported"):
        assert lc.is_actionable(s)


def test_legal_edges():
    assert lc.can_transition("open", "claimed")
    assert lc.can_transition("claimed", "testing")
    assert lc.can_transition("testing", "supported")
    assert lc.can_transition("supported", "promoted")
    assert lc.can_transition("blocked", "open")
    assert lc.can_transition("exhausted", "open")


def test_illegal_edges():
    assert not lc.can_transition("open", "promoted")
    assert not lc.can_transition("refuted", "open")
    assert not lc.can_transition("promoted", "open")
    assert not lc.can_transition("dead", "open")


def test_testing_requires_falsifier():
    ok, reason = lc.evaluate_transition("claimed", "testing", next_test_action={})
    assert not ok and reason == "testing_requires_falsifier_and_expected_signal"
    ok, reason = lc.evaluate_transition("claimed", "testing", metadata={"falsifier": "x"})
    assert not ok  # falsifier without expected_signal is insufficient
    ok, reason = lc.evaluate_transition(
        "claimed", "testing", metadata={"falsifier": "x", "expected_signal": "y"}
    )
    assert ok and reason is None


def test_noop_and_unknown():
    assert lc.evaluate_transition("open", "open") == (False, "no_op_transition")
    assert lc.evaluate_transition("open", "bogus") == (False, "unknown_target_state")
    assert lc.evaluate_transition("bogus", "open") == (False, "unknown_source_state")


def test_refuting_target_is_a_legal_edge_here():
    # The deterministic refuted_by requirement is layered by the caller (adjudicate); the
    # lifecycle only certifies the edge is legal.
    assert lc.evaluate_transition("testing", "refuted") == (True, None)
    assert "refuted" in lc.REFUTING_TARGETS
    assert "dead" in lc.REFUTING_TARGETS


def test_all_states_covered_by_transition_table():
    assert set(lc.TRANSITIONS) == set(lc.STATES)
