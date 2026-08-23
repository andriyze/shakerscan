from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RULESET = ROOT / ".github" / "rulesets" / "v2.json"
CODEOWNERS = ROOT / ".github" / "CODEOWNERS"


def test_v2_ruleset_requires_review_linear_history_and_all_runtime_checks():
    payload = json.loads(RULESET.read_text(encoding="utf-8"))

    assert payload["enforcement"] == "active"
    assert payload["conditions"]["ref_name"]["include"] == ["refs/heads/v2"]
    rules = {rule["type"]: rule for rule in payload["rules"]}
    assert {"deletion", "non_fast_forward", "required_linear_history"} <= set(rules)

    reviews = rules["pull_request"]["parameters"]
    assert reviews["required_approving_review_count"] >= 1
    assert reviews["require_code_owner_review"] is True
    assert reviews["require_last_push_approval"] is True
    assert reviews["required_review_thread_resolution"] is True

    required = {
        check["context"]
        for check in rules["required_status_checks"]["parameters"]["required_status_checks"]
    }
    assert required == {
        "contracts",
        "complete-python",
        "images-api-ui",
        "commit-policy",
        "smoke",
    }


def test_v2_execution_boundary_requires_code_owner_review():
    text = CODEOWNERS.read_text(encoding="utf-8")
    for path in (
        "/api/capabilities/",
        "/api/runtime/",
        "/api/scan/",
        "/api/hunt/",
        "/api/agent_tools.py",
        "/api/worker.py",
        "/api/broker_worker.py",
        "/api/broker_worker_v2.py",
        "/api/parallel_scan.py",
        "/scanner/scanner.py",
        "/scanner/scanner_tools/request_meter.py",
        "/db/",
    ):
        assert f"{path} @andriyze" in text
