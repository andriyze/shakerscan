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
