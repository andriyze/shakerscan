import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RULESET = ROOT / ".github" / "rulesets" / "main.json"


def _module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ruleset_tool = _module("apply_main_ruleset_under_test", "scripts/apply_main_ruleset.py")


def _committed() -> dict:
    return json.loads(RULESET.read_text(encoding="utf-8"))


def _rules(document: dict) -> dict:
    return {rule["type"]: rule.get("parameters") or {} for rule in document["rules"]}


def test_main_ruleset_requires_pr_linear_history_and_every_pre_merge_gate():
    document = _committed()
    assert document["enforcement"] == "active"
    assert document["conditions"]["ref_name"]["include"] == ["refs/heads/main"]
    assert document["bypass_actors"] == []
    rules = _rules(document)
    assert {"deletion", "non_fast_forward", "required_linear_history", "pull_request",
            "required_status_checks"} <= set(rules)
    assert rules["pull_request"]["required_review_thread_resolution"] is True
    checks = rules["required_status_checks"]
    assert checks["strict_required_status_checks_policy"] is True
    contexts = {check["context"] for check in checks["required_status_checks"]}
    # Every job that is required must exist as a workflow job id that reports on every PR.
    assert contexts == {"commit-policy", "python-suite", "smoke"}
    workflows = ROOT / ".github" / "workflows"
    assert "  commit-policy:\n" in (workflows / "commit-policy.yml").read_text(encoding="utf-8")
    assert "  python-suite:\n" in (workflows / "python-suite.yml").read_text(encoding="utf-8")
    assert "  smoke:\n" in (workflows / "e2e-pr.yml").read_text(encoding="utf-8")


def test_a_deletion_only_live_ruleset_is_reported_as_under_protection():
    live = [{
        "name": "basic-protection", "target": "branch", "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "bypass_actors": [],
        "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}],
    }]
    problems = ruleset_tool.missing_protections(_committed(), live)
    assert any("required_linear_history" in problem for problem in problems)
    assert any("pull_request" in problem for problem in problems)
    assert any("required_status_checks" in problem for problem in problems)


def test_a_partial_required_check_set_names_the_missing_gates():
    committed = _committed()
    partial = json.loads(json.dumps(committed))
    for rule in partial["rules"]:
        if rule["type"] == "required_status_checks":
            rule["parameters"]["required_status_checks"] = [{"context": "commit-policy"}]
            rule["parameters"]["strict_required_status_checks_policy"] = False
    problems = ruleset_tool.missing_protections(committed, [partial])
    assert any("python-suite" in problem and "smoke" in problem for problem in problems)
    assert any("up to date" in problem for problem in problems)


def test_the_committed_ruleset_satisfies_itself_and_bypass_actors_are_flagged():
    committed = _committed()
    assert ruleset_tool.missing_protections(committed, [committed]) == []
    with_bypass = {**committed, "bypass_actors": [{"actor_id": 1, "actor_type": "Integration"}]}
    assert any("bypass" in problem for problem in ruleset_tool.missing_protections(committed, [with_bypass]))
    inactive = {**committed, "enforcement": "disabled"}
    assert ruleset_tool.missing_protections(committed, [inactive]) == [
        "no active branch ruleset covers refs/heads/main"
    ]


def test_worker_only_status_does_not_report_missing_local_api_as_failure():
    script = (ROOT / "scanner.sh").read_text(encoding="utf-8")
    body = script.split("show_status() {", 1)[1].split("\n}", 1)[0]
    assert "Fleet broker worker node" in body
    assert "Local API/UI: not installed" in body
    assert body.index("Fleet broker worker node") < body.index("api_probe_url")


def test_release_process_documents_build_promote_stable_order():
    text = (ROOT / "docs" / "release-process.md").read_text(encoding="utf-8")
    optional = "## 2. Optional physical support-boundary acceptance"
    assert text.index("## 1. Freeze and build") < text.index(optional)
    assert text.index(optional) < text.index("## 3. Publish")
    assert text.index("## 3. Publish") < text.index("## 4. Public smoke")
