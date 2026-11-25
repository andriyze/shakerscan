"""The detection scorecard reads benchmark runs and fails a comparison when proven recall falls."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "detection_scorecard", ROOT / "scripts" / "detection_scorecard.py",
)
scorecard = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(scorecard)


def _run(tmp_path, name, cards):
    path = tmp_path / name
    path.write_text(json.dumps({"targets": cards}), encoding="utf-8")
    return str(path)


def _card(target, found, missed, *, unproven=(), verified=0, suspected=0, families=()):
    return {
        "target": target,
        "expected_found": [{"id": item} for item in found],
        "expected_missed": [{"id": item} for item in missed],
        "expected_detected_unproven": [{"id": item} for item in unproven],
        "verified_high_critical": verified, "suspected_high_critical": suspected,
        "attempted_families": list(families),
    }


def test_a_run_is_summarized_from_proven_entries_only(tmp_path, capsys):
    run = _run(tmp_path, "now.json", [
        _card("juice_shop", ["sqli-search"], ["sqli-login", "xss-dom"], unproven=["xss-dom"],
              verified=2, suspected=1, families=["xss", "sqli"]),
    ])
    assert scorecard.main([run]) == 0
    out = capsys.readouterr().out
    assert "| juice_shop | 1 / 3 | 0.33 | 1 | 2 | 1 | sqli, xss |" in out
    assert "REGRESSION" not in out


def test_a_comparison_fails_when_proven_recall_falls_and_names_what_was_lost(tmp_path, capsys):
    before = _run(tmp_path, "before.json", [
        _card("juice_shop", ["sqli-search", "xss-dom"], ["sqli-login"]),
        _card("honey", ["env"], []),
    ])
    after = _run(tmp_path, "after.json", [
        _card("juice_shop", ["sqli-search"], ["sqli-login", "xss-dom"]),
        _card("honey", ["env"], []),
    ])
    assert scorecard.main([after, "--baseline", before]) == 1
    out = capsys.readouterr().out
    assert "REGRESSION juice_shop: proven fell from 2 to 1 of 3 (now missed: xss-dom)" in out
    assert "REGRESSION honey" not in out
    # More proven, or the same, is not a regression.
    assert scorecard.main([before, "--baseline", after]) == 0


def test_an_entry_lost_behind_an_unchanged_count_is_a_regression(tmp_path, capsys):
    before = _run(tmp_path, "before.json", [_card("juice_shop", ["sqli-search"], ["xss-dom"])])
    after = _run(tmp_path, "after.json", [_card("juice_shop", ["xss-dom"], ["sqli-search"])])
    assert scorecard.main([after, "--baseline", before]) == 1
    assert "REGRESSION juice_shop: no longer proven: sqli-search" in capsys.readouterr().out


def test_a_missing_or_failed_target_is_a_regression_not_a_pass(tmp_path, capsys):
    before = _run(tmp_path, "before.json", [_card("crapi", ["bola"], []), _card("honey", ["env"], [])])
    after = _run(tmp_path, "after.json", [{"target": "crapi", "error": "scan timed out", "passed": False}])
    assert scorecard.main([after, "--baseline", before, "--json"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert sorted(result["regressions"]) == [
        "crapi: the run failed (scan timed out)",
        "honey: scored in the baseline, missing from this run",
    ]
    assert result["targets"]["crapi"]["recall"] is None


def test_a_file_that_is_not_a_run_is_refused(tmp_path, capsys):
    path = tmp_path / "other.json"
    path.write_text("{}", encoding="utf-8")
    assert scorecard.main([str(path)]) == 2
    assert "not a benchmark run" in capsys.readouterr().err
