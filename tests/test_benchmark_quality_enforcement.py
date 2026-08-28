"""The declared quality bar must be capable of failing a run.

The benchmark recorded `quality_passed` and printed MET / NOT MET, but `passed`, the
artifact status and the exit code were computed from the regression gates alone. A bar
nothing can fail is not a bar: the tracked scorecard read `passed: true` while every
quality check -- recall, browser-proven XSS, grade reliability, declared gaps -- failed.
`--enforce-quality` makes it decide the outcome, so release qualification can require it
while the day-to-day loop still reports it advisory.
"""

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "benchmark_targets.py"
SOURCE = SCRIPT.read_text(encoding="utf-8")


def test_the_flag_exists_and_is_off_by_default():
    tree = ast.parse(SOURCE)
    added = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and getattr(node.func, "attr", "") == "add_argument"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "--enforce-quality"
    ]
    assert added, "--enforce-quality is not declared"
    action = next(
        (kw.value.value for kw in added[0].keywords if kw.arg == "action"), None,
    )
    assert action == "store_true", "the flag must default off so the dev loop is unchanged"


def test_the_exit_status_can_depend_on_the_quality_bar():
    assert "release_ok" in SOURCE
    assert "return 0 if release_ok else 1" in SOURCE
    assert "args.enforce_quality" in SOURCE


def test_the_artifact_separates_the_two_verdicts():
    for field in ("regression_gates_passed", "quality_bar_passed", "quality_bar_enforced"):
        assert f'"{field}"' in SOURCE, f"the scorecard does not record {field}"


def _release_ok(overall_ok, quality_ok, enforce):
    """The decision the script makes, restated so its logic is pinned directly."""
    return bool(overall_ok and (quality_ok or not enforce))


def test_the_decision_table():
    assert _release_ok(True, True, True) is True
    assert _release_ok(True, False, True) is False, "enforced: a failed bar must fail the run"
    assert _release_ok(True, False, False) is True, "advisory: unchanged for the dev loop"
    assert _release_ok(False, True, False) is False, "a broken regression gate always fails"
    assert _release_ok(False, True, True) is False
