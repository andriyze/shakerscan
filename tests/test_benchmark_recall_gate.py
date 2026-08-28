"""A benchmark must fail when it misses most of its answer key.

`min_verified_high_critical` counts verified findings, not answer-key coverage. A scan reporting 13
verified High/Critical findings passed that gate while matching only 4 of 9 expectations, so the
scorecard's own `expected_recall` was computed and then never gated on. The fixtures state the
intended bar in a comment -- "min_verified_high_critical: 6 # >=70% of the ~9 reliably-achievable
here" -- so the threshold is the project's documented intent, made enforceable.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "benchmarks"


def _benchmark():
    path = ROOT / "scripts" / "benchmark_targets.py"
    spec = importlib.util.spec_from_file_location("benchmark_recall_gate_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


benchmark = _benchmark()


def _card(recall):
    return {
        "expected_recall": recall,
        "verified_high_critical": 13,
        "false_positive_risk": 0.0,
        "grade_reliable": True,
        "verified_high_critical_families": ["sqli"],
        "browser_proven_high_critical_families": ["xss"],
        "family_attempt_failures": [],
    }


def _gates(**overrides):
    gates = {"min_expected_recall": 0.67}
    gates.update(overrides)
    return {"gates": gates, "expected": []}


def _result(card, fixture):
    return {entry["gate"]: entry for entry in benchmark.apply_gates(card, fixture)}


def test_a_scan_that_misses_most_of_the_answer_key_fails():
    card = _card(0.44)
    gates = _result(card, _gates())
    assert gates["min_expected_recall"]["pass"] is False
    assert "0.44" in gates["min_expected_recall"]["detail"]


def test_meeting_the_threshold_passes():
    card = _card(0.67)
    assert _result(card, _gates())["min_expected_recall"]["pass"] is True


def test_a_high_finding_count_cannot_substitute_for_recall():
    # The exact hole: thirteen verified findings, four of nine expectations matched.
    card = _card(0.44)
    gates = _result(card, _gates(min_verified_high_critical=6))
    assert gates["min_verified_high_critical"]["pass"] is True
    assert gates["min_expected_recall"]["pass"] is False


def test_a_missing_recall_measurement_fails_closed():
    # No recall computed means the scorecard cannot show it met the bar.
    card = _card(None)
    assert _result(card, _gates())["min_expected_recall"]["pass"] is False


def test_fixtures_with_an_answer_key_declare_a_recall_threshold():
    # A fixture that lists expectations but gates none of them measures nothing.
    for path in sorted(FIXTURES.glob("*.yaml")):
        fixture = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not fixture.get("expected"):
            continue
        gates = fixture.get("gates") or {}
        assert "min_expected_recall" in gates, f"{path.name} has an answer key but no recall gate"
        threshold = gates["min_expected_recall"]
        assert isinstance(threshold, (int, float)) and 0 < threshold <= 1, path.name


def test_the_benchmark_grants_the_authority_its_answer_key_requires():
    """`nosqli-reviews` is in the answer key and nosqli probes mutate by design.

    Without `allow_state_changing_http` the plan grants zero state_changing_requests and admission
    rejects the whole submission -- the benchmark could not submit a scan at all, and the
    expectation it was measuring against was structurally unreachable. Request-body injection
    candidates need the same authority.
    """
    import importlib.util, sys as _sys
    from pathlib import Path as _Path
    import inspect

    spec = importlib.util.spec_from_file_location(
        "benchmark_submit_under_test", _Path(__file__).resolve().parents[1] / "scripts" / "benchmark_targets.py")
    module = importlib.util.module_from_spec(spec)
    _sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    source = inspect.getsource(module.submit_target)
    assert '"allow_state_changing_http": True' in source
    assert '"nosqli"' in source, "the answer key expects nosqli, so the family must be selected"


# --- Declared gaps, not a lowered number ------------------------------------------------------
# Shipping what the engine proves does not mean pretending the answer key is smaller. The
# expectations still describe what a competent DAST should find; the classes not yet reachable are
# named, so the benchmark stays a regression detector at the level actually shipped.

def _card_with(missed_ids, **extra):
    card = _card(0.44)
    card["expected_missed"] = [{"id": item} for item in missed_ids]
    card.update(extra)
    return card


def _gaps_fixture(*ids, recall=0.4):
    return {
        "gates": {
            "min_expected_recall": recall,
            "known_expectation_gaps": [{"id": item, "reason": "not yet reachable"} for item in ids],
        },
        "expected": [],
    }


def test_a_declared_gap_does_not_fail_the_gate():
    card = _card_with(["sqli-login", "xss-dom-search"])
    gates = _result(card, _gaps_fixture("sqli-login", "xss-dom-search"))
    assert gates["no_undeclared_expectation_misses"]["pass"] is True


def test_an_undeclared_miss_still_fails():
    # The point of the list: a class that used to be found and now is not must still fail.
    card = _card_with(["sqli-login", "sqli-search"])
    gates = _result(card, _gaps_fixture("sqli-login"))
    entry = gates["no_undeclared_expectation_misses"]
    assert entry["pass"] is False
    assert "sqli-search" in entry["detail"]


def test_closing_a_gap_is_recorded_not_penalised():
    card = _card_with(["sqli-login"])
    _result(card, _gaps_fixture("sqli-login", "xss-dom-search"))
    assert card["closed_expectation_gaps"] == ["xss-dom-search"]


def test_the_recall_gate_still_applies_alongside_declared_gaps():
    # Declaring every expectation a gap must not make the benchmark unconditionally green.
    card = _card_with(["a", "b"])
    card["expected_recall"] = 0.1
    gates = _result(card, _gaps_fixture("a", "b", recall=0.4))
    assert gates["no_undeclared_expectation_misses"]["pass"] is True
    assert gates["min_expected_recall"]["pass"] is False


def test_every_declared_gap_states_why_and_is_a_real_expectation():
    import yaml

    for path in sorted(FIXTURES.glob("*.yaml")):
        fixture = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        gaps = (fixture.get("gates") or {}).get("known_expectation_gaps") or []
        expected_ids = {str(item.get("id")) for item in fixture.get("expected") or []}
        for gap in gaps:
            assert isinstance(gap, dict), f"{path.name}: a gap must record its reason"
            assert gap.get("reason"), f"{path.name}: {gap.get('id')} has no reason"
            assert str(gap.get("id")) in expected_ids, (
                f"{path.name}: {gap.get('id')} is not an expectation in this fixture"
            )


def test_the_reliable_grade_gate_defaults_strict():
    # A fixture that says nothing must still require a reliable grade; only an explicit opt-out
    # turns it into a recorded value.
    strict = _result(_card(0.9), {"gates": {}, "expected": []})
    assert "grade_reliable" in strict

    card = _card(0.9)
    card["grade_reliable"] = False
    assert _result(card, {"gates": {}, "expected": []})["grade_reliable"]["pass"] is False

    relaxed = _result(card, {"gates": {"require_reliable_grade": False}, "expected": []})
    assert "grade_reliable" not in relaxed
    # Still reported, so an opt-out cannot hide the value.
    assert "grade_reliable=False" in relaxed["grade_reliable_recorded"]["detail"]


def test_bfla_is_only_selected_when_two_principals_exist():
    """A cross-principal differential cannot run with one principal.

    Selecting it anyway guarantees zero attempts, which then fails the mandatory family-attempt
    gate for a reason that has nothing to do with the engine -- exactly what the tracked scorecard
    reported as `zero-attempt families: authz_surface`.
    """
    import importlib.util, inspect, sys as _sys
    from pathlib import Path as _Path

    spec = importlib.util.spec_from_file_location(
        "benchmark_authz_under_test",
        _Path(__file__).resolve().parents[1] / "scripts" / "benchmark_targets.py")
    module = importlib.util.module_from_spec(spec)
    _sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    source = inspect.getsource(module.submit_target)
    assert "if len(minted_tokens) >= 2:" in source
    assert 'include_families.append("authz_surface")' in source
