"""Pure hypothesis-lifecycle state machine (Wave 4).

No engine imports — pure functions so the transition rules can be host-tested and shared. The full
lifecycle from the plan doc is:

    open -> claimed -> testing -> supported -> promoted
                          |          |
                          v          v
                     refuted / blocked / exhausted / dead

Rules the machine enforces (the deterministic half of "planners propose, ShakerScan enforces"):
- only legal edges may be taken;
- a hypothesis may not enter ``testing`` without a falsifier AND an expected signal
  (the planner cannot skip required falsifiers);
- a ``refuted`` transition needs a deterministic ``refuted_by`` reference — enforced via
  ``adjudicate.require_deterministic_refutation`` at the call site (the negative gate);
- terminal states are closed; ``blocked``/``exhausted`` are reopenable only through an explicit
  versioned transition back to ``open``.
"""

from __future__ import annotations

from typing import Any

LIFECYCLE_VERSION = "hypothesis-lifecycle-2026-07-12.v1"

STATES: frozenset[str] = frozenset(
    {"open", "claimed", "testing", "supported", "refuted", "blocked", "exhausted", "promoted", "dead"}
)

# Fully closed — no further work is scheduled and the lead cannot be claimed.
TERMINAL: frozenset[str] = frozenset({"refuted", "promoted", "dead"})
# Not actionable right now (closed OR parked), so not claimable and not promotable.
INACTIVE: frozenset[str] = TERMINAL | frozenset({"blocked", "exhausted"})

# Legal directed edges. Reopening a parked lead (blocked/exhausted -> open) is the explicit
# versioned transition the plan requires; a truly terminal lead has no outgoing edges.
TRANSITIONS: dict[str, frozenset[str]] = {
    "open": frozenset({"claimed", "blocked", "dead"}),
    "claimed": frozenset({"testing", "open", "blocked", "dead"}),
    "testing": frozenset({"supported", "refuted", "blocked", "exhausted", "open"}),
    "supported": frozenset({"promoted", "refuted", "testing", "blocked", "exhausted"}),
    "blocked": frozenset({"open", "dead", "exhausted"}),
    "exhausted": frozenset({"open", "dead"}),
    "refuted": frozenset(),
    "promoted": frozenset(),
    "dead": frozenset(),
}

# Transitions whose target dismisses/closes a lead as not-a-bug; these require a deterministic
# ``refuted_by`` reference (checked by the caller via adjudicate.require_deterministic_refutation).
REFUTING_TARGETS: frozenset[str] = frozenset({"refuted", "dead"})


def is_terminal(status: Any) -> bool:
    return str(status or "").strip().lower() in TERMINAL


def is_actionable(status: Any) -> bool:
    """Claimable / promotable states — i.e. not closed and not parked."""
    return str(status or "").strip().lower() not in INACTIVE


def can_transition(frm: Any, to: Any) -> bool:
    return str(to or "").strip().lower() in TRANSITIONS.get(str(frm or "").strip().lower(), frozenset())


def has_falsifier(next_test_action: Any, metadata: Any) -> bool:
    """True iff a non-empty falsifier AND expected signal are present in either the planned next
    action or the hypothesis metadata (wherever the planner recorded them)."""
    merged: dict[str, Any] = {}
    for source in (metadata, next_test_action):
        if isinstance(source, dict):
            merged.update(source)
    falsifier = str(merged.get("falsifier") or "").strip()
    expected = str(merged.get("expected_signal") or merged.get("expected") or "").strip()
    return bool(falsifier) and bool(expected)


def evaluate_transition(
    frm: Any,
    to: Any,
    *,
    next_test_action: Any = None,
    metadata: Any = None,
) -> tuple[bool, str | None]:
    """Deterministic gate for a lifecycle transition (excluding the refuted_by check, which the
    caller enforces with adjudicate.require_deterministic_refutation). Returns ``(ok, reason)``.
    """
    frm_n = str(frm or "").strip().lower()
    to_n = str(to or "").strip().lower()
    if to_n not in STATES:
        return False, "unknown_target_state"
    if frm_n not in STATES:
        return False, "unknown_source_state"
    if frm_n == to_n:
        return False, "no_op_transition"
    if not can_transition(frm_n, to_n):
        return False, f"illegal_transition:{frm_n}->{to_n}"
    if to_n == "testing" and not has_falsifier(next_test_action, metadata):
        return False, "testing_requires_falsifier_and_expected_signal"
    return True, None


def _self_test() -> None:
    assert is_terminal("refuted") and is_terminal("promoted") and is_terminal("dead")
    assert not is_terminal("blocked") and not is_terminal("exhausted") and not is_terminal("open")
    assert not is_actionable("blocked") and not is_actionable("exhausted")
    assert is_actionable("open") and is_actionable("supported")

    # Legal / illegal edges.
    assert can_transition("open", "claimed") and not can_transition("open", "promoted")
    assert can_transition("supported", "promoted")
    assert not can_transition("refuted", "open")  # terminal, no outgoing
    assert can_transition("blocked", "open") and can_transition("exhausted", "open")  # reopen

    # Falsifier gate on -> testing.
    ok, reason = evaluate_transition("claimed", "testing", next_test_action={})
    assert ok is False and reason == "testing_requires_falsifier_and_expected_signal"
    ok, reason = evaluate_transition(
        "claimed", "testing", next_test_action={"falsifier": "control 403 stays 403", "expected_signal": "owner flips"}
    )
    assert ok is True and reason is None

    # Illegal / no-op / unknown.
    assert evaluate_transition("open", "promoted")[0] is False
    assert evaluate_transition("open", "open") == (False, "no_op_transition")
    assert evaluate_transition("open", "bogus") == (False, "unknown_target_state")

    # A legal dismissal edge is permitted here; the deterministic refuted_by check is layered on
    # top by the caller.
    assert evaluate_transition("testing", "refuted") == (True, None)

    print("hypothesis_lifecycle self-test OK")


if __name__ == "__main__":
    _self_test()
