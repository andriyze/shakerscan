"""A SQLi retest of a point sqlmap marked in a path segment declines instead of probing it.

sqlmap names a path-segment injection point ``#1*`` and stores the URL with the marker
(``/products/1*``). The retest prover injects only query and form parameters, so replaying that
point would request the starred URL with a parameter the application never reads. Fixtures only.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from retest_contract import build_replay_commands, path_segment_retest_result

API = Path(__file__).resolve().parents[1] / "api"
MARKED = {"finding_type": "sqli", "original_url": "http://shop.fixture.invalid/products/1*", "param": "#1*"}


def test_a_path_marked_sqli_point_is_inconclusive_and_keeps_the_manual_replay():
    commands = build_replay_commands(MARKED)
    result = path_segment_retest_result(MARKED, commands)
    assert result is not None
    assert (result["status"], result["result_status"], result["verdict"]) == ("completed", "inconclusive", "inconclusive")
    assert result["confidence"] is None and result["proof"] is None and result["retryable"] is False
    assert "stays open" in result["verdict_reason"] and "#1*" in result["verdict_reason"]
    assert result["artifacts"]["skipped_reason"] == "path_segment_injection_point"
    # The replay commands for a manual check show the unmarked URL and the marked segment.
    assert result["replay_commands"] == commands
    assert all("1*" not in command for command in commands)


@pytest.mark.parametrize("inputs", [
    {"finding_type": "sqli", "original_url": "http://shop.fixture.invalid/products?id=1", "param": "id"},
    {"finding_type": "sqli", "original_url": "http://shop.fixture.invalid/products/1*", "param": "#1"},
    {"finding_type": "xss", "original_url": "http://shop.fixture.invalid/search/1*", "param": "#1*"},
    {"finding_type": "sqli", "original_url": "http://shop.fixture.invalid/products/1*", "param": ""},
])
def test_ordinary_points_and_other_types_still_run_the_prover(inputs):
    assert path_segment_retest_result(inputs, []) is None


def test_the_worker_declines_before_it_picks_a_url_or_calls_a_prover():
    tree = ast.parse((API / "worker.py").read_text(encoding="utf-8"))
    run = next(node for node in ast.walk(tree)
               if isinstance(node, ast.AsyncFunctionDef) and node.name == "run_finding_retest")
    calls = [(node.lineno, ast.unparse(node.func)) for node in ast.walk(run) if isinstance(node, ast.Call)]
    declined = min(line for line, name in calls if name == "path_segment_retest_result")
    picked = min(node.lineno for node in ast.walk(run) if isinstance(node, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == "test_url" for t in node.targets))
    probes = [line for line, name in calls if name.startswith("poe.") or "prove_" in name]
    assert declined < picked
    assert probes and declined < min(probes)
