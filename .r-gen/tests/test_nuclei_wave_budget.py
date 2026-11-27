import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools.nuclei import (  # noqa: E402
    WaveBudget,
    YieldMetrics,
    adjust_next_wave_budget,
)


def test_zero_yield_collapses_next_wave_to_minimum_budget():
    next_budget = adjust_next_wave_budget(
        YieldMetrics(findings_count=0, duration_seconds=45),
        WaveBudget.wave2(),
        signals={},
    )

    assert next_budget.max_duration == WaveBudget.wave2().min_duration


def test_high_yield_still_extends_next_wave_budget():
    next_budget = adjust_next_wave_budget(
        YieldMetrics(findings_count=4, duration_seconds=60),
        WaveBudget.wave2(),
        signals={},
    )

    assert next_budget.max_duration > WaveBudget.wave2().max_duration
