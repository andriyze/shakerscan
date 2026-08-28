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


def test_the_artifact_separates_the_verdicts():
    for field in (
        "regression_gates_passed",
        "quality_bar_passed",
        "quality_bar_enforced_subset_passed",
        "quality_bar_enforced",
    ):
        assert f'"{field}"' in SOURCE, f"the scorecard does not record {field}"


def test_only_the_named_subset_is_binding():
    """The full bar stays reported; `enforced` names what decides the outcome."""
    assert "quality_enforced_passed" in SOURCE
    assert "quality_enforced_gates" in SOURCE
    # The exit decision must read the enforced subset, never the whole bar.
    decision = SOURCE[SOURCE.index("quality_ok = all("):]
    assert "quality_enforced_passed" in decision[:300]


def test_an_unknown_enforced_name_is_rejected():
    """A typo in `enforced` must fail loudly, not silently enforce nothing."""
    assert "names checks that do not exist" in SOURCE


def test_the_juice_shop_bar_enforces_grade_reliability_only():
    import yaml
    bar = yaml.safe_load(
        (ROOT / "tests/fixtures/benchmarks/juice_shop.yaml").read_text()
    )["quality_bar"]
    # The declared standard is unchanged -- only which parts are binding today.
    assert bar["min_expected_recall"] == 0.67
    assert bar["require_browser_proven_xss"] is True
    assert bar["enforced"] == ["quality:grade_reliable"]


def _release_ok(overall_ok, quality_ok, enforce):
    """The decision the script makes, restated so its logic is pinned directly."""
    return bool(overall_ok and (quality_ok or not enforce))


def test_the_decision_table():
    assert _release_ok(True, True, True) is True
    assert _release_ok(True, False, True) is False, "enforced: a failed bar must fail the run"
    assert _release_ok(True, False, False) is True, "advisory: unchanged for the dev loop"
    assert _release_ok(False, True, False) is False, "a broken regression gate always fails"
    assert _release_ok(False, True, True) is False


def test_release_qualification_measures_recall():
    """The E2E gate proved the stack ran; nothing measured what the scanner found.

    `expected_recall` existed only in whatever local run someone remembered to do, so no
    release artifact carried the single number that says how much of the answer key the
    engine reaches. The E2E job already stands up Juice Shop and the fleet, so the
    measurement belongs there.
    """
    workflow = (ROOT / ".github" / "workflows" / "e2e.yml").read_text(encoding="utf-8")
    assert "scripts/benchmark_targets.py juice_shop" in workflow
    assert "--enforce-quality" in workflow, (
        "release qualification must fail on the enforced subset, not merely report it"
    )
    assert "artifacts/dast-recall.json" in workflow
    # The scorecard has to leave the runner, or the measurement dies with the job.
    upload = workflow[workflow.index("Upload exact-SHA E2E scorecard"):]
    assert "artifacts/dast-recall.json" in upload


def test_the_benchmark_is_not_in_the_build_test_loop():
    """It needs a live target and a uniform fleet, and takes ~20 minutes.

    Keeping it out of the fast loop is deliberate: it also keeps the pressure to fit the
    benchmark low, which is the failure mode a DAST answer key invites.
    """
    for name in ("v2-contracts.yml", "e2e-pr.yml", "commit-policy.yml"):
        path = ROOT / ".github" / "workflows" / name
        if not path.exists():
            continue
        assert "benchmark_targets" not in path.read_text(encoding="utf-8"), name


def test_an_unknown_grade_reliability_does_not_pass():
    """`is not False` let a scorecard with no recorded value satisfy the check.

    A benchmark run that never captured `grade_reliable` produced None, which is not
    False, so the reliability gate passed on absent evidence. Unknown is not reliable.
    """
    assert "card.get(\"grade_reliable\") is True" in SOURCE
    assert "card.get(\"grade_reliable\") is not False" not in SOURCE
