"""Every gate a benchmark fixture declares must be evaluated -- or the run must fail.

honey.yaml declared ``min_categories_found`` and ``require_no_unproven_critical`` and crapi.yaml
declared ``bola_blocked_reason_if_single_user``, but no code read any of them: the scorecard
reported a pass against gates that were never checked. They are implemented here, and an unknown
gate or quality-bar key now fails the run instead of being skipped.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "benchmarks"


def _benchmark():
    path = ROOT / "scripts" / "benchmark_targets.py"
    spec = importlib.util.spec_from_file_location("benchmark_declared_gates_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


benchmark = _benchmark()


def _gates(card, fixture):
    return {entry["gate"]: entry for entry in benchmark.apply_gates(card, fixture)}


def _finding(identifier, title, url, severity, verified):
    return {"id": identifier, "title": title, "url": url, "severity": severity, "verified": verified}


HONEY_EXPECTED = [
    {"id": "data-exposure", "family": "sensitive_exposure", "route": "/api",
     "min_severity": "high", "proof": "deterministic"},
    {"id": "webhook-bypass", "family": "webhook", "route": "/webhook",
     "min_severity": "high", "proof": "deterministic"},
    {"id": "approval-bypass", "family": "approval", "route": "/approve",
     "min_severity": "high", "proof": "deterministic"},
    {"id": "path-traversal", "family": "path_traversal", "route": "/file",
     "min_severity": "high", "proof": "deterministic"},
]


def _honey_fixture(**gates):
    return {"name": "honey", "expected": HONEY_EXPECTED, "gates": gates}


# --- min_categories_found --------------------------------------------------------------------

def test_categories_found_counts_answer_key_families_found_with_proof():
    report = {"findings": [
        _finding("f1", "Sensitive exposure: secret file", "https://h.test/api/env", "high", True),
        _finding("f2", "Webhook allowlist bypass", "https://h.test/webhook", "high", True),
        # Detected but unproven: not a found category.
        _finding("f3", "Path traversal", "https://h.test/file?name=", "high", False),
    ]}
    card = benchmark.collect_scorecard(report, _honey_fixture(min_categories_found=3))

    assert card["expected_categories"] == [
        "approval", "path_traversal", "sensitive_exposure", "webhook",
    ]
    assert card["expected_categories_found"] == ["sensitive_exposure", "webhook"]
    gate = _gates(card, _honey_fixture(min_categories_found=3))["min_categories_found"]
    assert gate["pass"] is False
    assert gate["detail"].startswith("2 >= 3")


def test_categories_found_passes_at_the_threshold():
    report = {"findings": [
        _finding("f1", "Sensitive exposure: secret file", "https://h.test/api/env", "high", True),
        _finding("f2", "Webhook allowlist bypass", "https://h.test/webhook", "high", True),
        _finding("f3", "Path traversal", "https://h.test/file?name=", "critical", True),
    ]}
    fixture = _honey_fixture(min_categories_found=3)
    card = benchmark.collect_scorecard(report, fixture)
    assert _gates(card, fixture)["min_categories_found"]["pass"] is True


def test_categories_found_fails_closed_when_not_measured():
    gate = _gates({"family_attempt_failures": []}, _honey_fixture(min_categories_found=1))
    assert gate["min_categories_found"]["pass"] is False
    assert "not measured" in gate["min_categories_found"]["detail"]


def test_two_found_expectations_of_one_family_are_one_category():
    fixture = {
        "expected": [
            {"id": "a", "family": "sensitive_exposure", "route": "/metrics", "proof": "verified"},
            {"id": "b", "family": "sensitive_exposure", "route": "/ftp", "proof": "verified"},
        ],
        "gates": {"min_categories_found": 2},
    }
    card = benchmark.collect_scorecard({"findings": [
        _finding("f1", "Sensitive exposure: metrics", "https://j.test/metrics", "high", True),
        _finding("f2", "Sensitive exposure: directory listing", "https://j.test/ftp", "high", True),
    ]}, fixture)
    assert card["expected_recall"] == 1.0
    assert _gates(card, fixture)["min_categories_found"]["pass"] is False


# --- require_no_unproven_critical ------------------------------------------------------------

def test_an_unproven_critical_finding_fails_the_gate():
    fixture = _honey_fixture(require_no_unproven_critical=True)
    card = benchmark.collect_scorecard({"findings": [
        _finding("f1", "Remote code execution", "https://h.test/run", "critical", False),
        _finding("f2", "Sensitive exposure: secret file", "https://h.test/api/env", "critical", True),
        # Unproven high is a different gate's business (max_unverified_high_ratio).
        _finding("f3", "Open redirect", "https://h.test/go", "high", False),
    ]}, fixture)

    assert card["unproven_critical"] == 1
    gate = _gates(card, fixture)["require_no_unproven_critical"]
    assert gate["pass"] is False
    assert "Remote code execution" in gate["detail"]


def test_proven_criticals_pass_the_gate():
    fixture = _honey_fixture(require_no_unproven_critical=True)
    card = benchmark.collect_scorecard({"findings": [
        _finding("f2", "Sensitive exposure: secret file", "https://h.test/api/env", "critical", True),
        _finding("f3", "Open redirect", "https://h.test/go", "high", False),
    ]}, fixture)
    assert _gates(card, fixture)["require_no_unproven_critical"]["pass"] is True


def test_an_unmeasured_critical_count_is_not_zero():
    fixture = _honey_fixture(require_no_unproven_critical=True)
    assert _gates({}, fixture)["require_no_unproven_critical"]["pass"] is False


def test_a_false_requirement_is_not_evaluated():
    fixture = _honey_fixture(require_no_unproven_critical=False)
    assert "require_no_unproven_critical" not in _gates({"unproven_critical": 3}, fixture)


# --- bola_blocked_reason_if_single_user ------------------------------------------------------

CRAPI_EXPECTED = [
    {"id": "bola-orders", "family": "bola", "route": "/workshop/api/shop/orders",
     "min_severity": "high", "proof": "verified"},
]


def _crapi_fixture():
    return {
        "name": "crapi", "target_url": "http://crapi.test",
        "auth": {"user1_login": {}, "user2_login": {}, "requires_two_users": True},
        "expected": CRAPI_EXPECTED,
        "gates": {"bola_blocked_reason_if_single_user": True},
    }


def test_a_single_user_run_must_name_the_missing_principal():
    fixture = _crapi_fixture()
    card = benchmark.collect_scorecard(
        {"findings": [], "smart_coverage": {"auth_states_tested": ["user1"]}}, fixture,
    )
    followup = card["benchmark_followups"][0]
    assert "missing_second_principal" in followup["blocked_by"]
    assert _gates(card, fixture)["bola_blocked_reason_if_single_user"]["pass"] is True


def test_a_single_user_run_that_credits_bola_fails():
    fixture = _crapi_fixture()
    card = benchmark.collect_scorecard({
        "findings": [_finding(
            "f1", "BOLA: object authorization bypass", "http://crapi.test/workshop/api/shop/orders/1",
            "high", True,
        )],
        "smart_coverage": {"auth_states_tested": ["user1"]},
    }, fixture)
    assert [item["id"] for item in card["expected_found"]] == ["bola-orders"]
    gate = _gates(card, fixture)["bola_blocked_reason_if_single_user"]
    assert gate["pass"] is False
    assert "credited=['bola-orders']" in gate["detail"]


def test_a_single_user_miss_without_the_blocked_reason_fails():
    fixture = _crapi_fixture()
    card = benchmark.collect_scorecard(
        {"findings": [], "smart_coverage": {"auth_states_tested": ["user1"]}}, fixture,
    )
    card["benchmark_followups"][0]["blocked_by"] = []
    gate = _gates(card, fixture)["bola_blocked_reason_if_single_user"]
    assert gate["pass"] is False
    assert "missing blocked reason=['bola-orders']" in gate["detail"]


def test_a_two_principal_run_is_not_single_user():
    fixture = _crapi_fixture()
    card = benchmark.collect_scorecard(
        {"findings": [], "smart_coverage": {"auth_states_tested": ["user1", "user2"]}}, fixture,
    )
    assert _gates(card, fixture)["bola_blocked_reason_if_single_user"]["pass"] is True


# --- unknown keys fail loudly ----------------------------------------------------------------

def test_an_unknown_gate_key_fails_the_run():
    gates = _gates({"family_attempt_failures": []}, {"gates": {"min_categories_fuond": 3}})
    assert gates["fixture_gates_recognised"]["pass"] is False
    assert "min_categories_fuond" in gates["fixture_gates_recognised"]["detail"]


def test_an_unknown_quality_bar_key_fails_the_bar():
    card = {"expected_recall": 1.0}
    results = benchmark.apply_quality_bar(
        card, {"quality_bar": {"min_expected_recall": 0.5, "require_verified_xss": True}},
    )
    failed = {item["gate"] for item in results if not item["pass"]}
    assert failed == {"quality:fixture_keys_recognised"}
    assert card["quality_passed"] is False
    assert card["quality_release_contract"]["valid"] is False


def test_fixture_problems_names_every_unimplemented_declaration():
    problems = benchmark.fixture_problems({
        "gates": {"min_expected_recall": 0.5, "made_up_gate": True},
        "quality_bar": {"enforced": [], "made_up_bar": 1},
    })
    assert problems == [
        "unimplemented gate key(s): made_up_gate",
        "unimplemented quality_bar key(s): made_up_bar",
    ]


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("*.yaml")), ids=lambda p: p.stem)
def test_every_committed_fixture_is_fully_evaluable(path):
    fixture = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    assert benchmark.fixture_problems(fixture) == []
    # And every declared gate produces a check: none is silently skipped.
    names = {item["gate"] for item in benchmark.apply_gates({
        "expected_recall": 0.0, "verified_high_critical": 0, "false_positive_risk": 0.0,
        "family_attempt_failures": [], "expected_categories_found": [], "unproven_critical": 0,
    }, fixture)}
    # Gates whose check carries a different name than the key that declares it.
    check_names = {
        "require_reliable_grade": ("grade_reliable", "grade_reliable_recorded"),
        "known_expectation_gaps": ("no_undeclared_expectation_misses",),
        "require_auth_workflow_ready": ("auth_workflow_ready",),
    }
    for key, value in (fixture.get("gates") or {}).items():
        if value is False and key != "require_reliable_grade":
            continue
        expected_names = check_names.get(key, (key,))
        assert names & set(expected_names), f"{path.name} declares {key} but no check evaluated it"


def test_main_aborts_on_an_unimplemented_gate_before_contacting_the_server(
    monkeypatch, tmp_path, capsys,
):
    (tmp_path / "typo.yaml").write_text(
        "target_url: http://t.test\nexpected: []\ngates:\n  min_expected_recal: 0.5\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(benchmark, "FIXTURE_DIR", str(tmp_path))

    def contacted(*_args, **_kwargs):
        raise AssertionError("the server must not be contacted for an unevaluable fixture")

    monkeypatch.setattr(benchmark, "check_fleet", contacted)
    monkeypatch.setattr(benchmark, "submit_target", contacted)
    monkeypatch.setattr(sys, "argv", ["benchmark_targets.py", "typo"])

    assert benchmark.main() == 2
    assert "min_expected_recal" in capsys.readouterr().err
