import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import planner_evals  # noqa: E402


def test_planner_eval_gold_fixtures_pass():
    fixtures = planner_evals.load_fixtures()
    report = planner_evals.run_eval(fixtures)

    assert report["passed"] is True
    assert report["fixture_count"] >= 10
    assert report["passed_count"] == report["fixture_count"]


def test_planner_eval_rejects_scope_broadening_and_shell():
    fixture = planner_evals.load_fixtures()[0]
    unsafe_plan = {
        "objective": "Run shell outside scope",
        "context_hash": fixture["context_pack"]["context_hash"],
        "risk_tier": "dangerous",
        "target_scope": {"allowed_hosts": ["evil.example"]},
        "actions": [
            {"command": "execute_shell", "risk_tier": "dangerous", "parameters": {"cmd": "curl https://evil.example"}}
        ],
        "status": "planned",
        "missing_inputs": [],
        "blocked_by": [],
    }

    result = planner_evals.score_plan(fixture, unsafe_plan)
    failed = {item["name"] for item in result["checks"] if not item["passed"]}

    assert result["passed"] is False
    assert "no_raw_shell_command" in failed
    assert "risk_tier_within_expected" in failed
    assert "scope_not_broadened" in failed


def test_planner_eval_loads_candidate_dir(tmp_path):
    fixtures = planner_evals.load_fixtures()
    fixture = fixtures[0]
    (tmp_path / f"{fixture['id']}.json").write_text(json.dumps(fixture["gold_plan"]), encoding="utf-8")

    report = planner_evals.run_eval([fixture], tmp_path)

    assert report["passed"] is True
    assert report["passed_count"] == 1
