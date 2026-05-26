import importlib.util
import json
import sys
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parent / "benchmark" / "run_benchmarks.py"
SPEC = importlib.util.spec_from_file_location("run_benchmarks", MODULE_PATH)
run_benchmarks = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(run_benchmarks)


def test_benchmark_requires_and_forbids_specific_findings():
    report = {
        "findings": [
            {
                "tool": "exposed_files",
                "title": "Exposed file: id_rsa",
                "severity": "critical",
                "verified": True,
                "evidence": {"url": "https://example.test/id_rsa"},
            },
            {
                "tool": "graphql_vulnerability",
                "title": "GraphQL Vulnerability: introspection_enabled",
                "severity": "medium",
                "verified": True,
                "evidence": {"url": "https://example.test/graphql"},
            },
        ],
        "quality_metrics": {"quality_score": 90},
    }
    config = {
        "assertions": {
            "require_findings": [
                {
                    "tool": "exposed_files",
                    "title_contains": "id_rsa",
                    "min_severity": "critical",
                    "verified": True,
                },
                {
                    "tool": "graphql_vulnerability",
                    "title_regex": "introspection",
                    "url_contains": "/graphql",
                    "verified": True,
                },
            ],
            "forbid_findings": [
                {"title_contains": "Prototype pollution"},
                {"tool": "ssti"},
            ],
            "min_verified_high_or_critical": 1,
            "max_findings_by_tool": {"exposed_files": 1},
        }
    }

    ok, failures, warnings, _ = run_benchmarks._check_benchmark("unit", report, config, strict=True)

    assert ok is True
    assert failures == []
    assert warnings == []


def test_benchmark_fails_missing_required_and_forbidden_findings():
    report = {
        "findings": [
            {
                "tool": "client_side",
                "title": "Potential prototype pollution sink",
                "severity": "high",
                "verified": False,
            }
        ]
    }
    config = {
        "assertions": {
            "require_findings": [{"tool": "exposed_files", "title_contains": "id_rsa"}],
            "forbid_findings": [{"title_contains": "prototype pollution"}],
            "max_low_confidence_ratio": 0.0,
        }
    }

    ok, failures, _, _ = run_benchmarks._check_benchmark("unit", report, config, strict=True)

    assert ok is False
    assert any("required finding missing" in failure for failure in failures)
    assert any("forbidden finding present" in failure for failure in failures)


def test_benchmark_tracks_expected_recall():
    report = {
        "findings": [
            {
                "tool": "smart_sqli",
                "title": "SQL Injection (postgresql - boolean)",
                "severity": "critical",
                "verified": True,
            },
            {
                "tool": "exposed_files",
                "title": "Exposed file: .env",
                "severity": "high",
                "verified": True,
            },
        ]
    }
    config = {
        "assertions": {
            "expected_findings": [
                {"tool": "smart_sqli", "title_contains": "SQL Injection", "verified": True},
                {"tool": "active_xss", "title_contains": "XSS", "verified": True},
            ],
            "min_expected_recall": 0.5,
            "min_expected_findings_found": 1,
        }
    }

    ok, failures, _, metrics = run_benchmarks._check_benchmark("unit", report, config, strict=True)

    assert ok is True
    assert failures == []
    assert metrics["expected_findings_found"] == 1
    assert metrics["expected_findings_total"] == 2
    assert metrics["expected_recall"] == 0.5


def test_benchmark_fails_expected_recall_regression():
    report = {"findings": []}
    config = {
        "assertions": {
            "expected_findings": [
                {"tool": "smart_sqli", "title_contains": "SQL Injection"},
                {"tool": "active_xss", "title_contains": "XSS"},
            ],
            "min_expected_recall": 0.5,
        }
    }

    ok, failures, _, metrics = run_benchmarks._check_benchmark("unit", report, config, strict=True)

    assert ok is False
    assert metrics["expected_recall"] == 0.0
    assert any("expected_recall" in failure for failure in failures)


def test_benchmark_cli_filters_by_name(tmp_path, monkeypatch, capsys):
    report = {
        "findings": [
            {
                "tool": "smart_sqli",
                "title": "SQL Injection",
                "severity": "high",
                "verified": True,
            }
        ],
        "quality_metrics": {"quality_score": 80},
    }
    one_result = tmp_path / "one.json"
    two_result = tmp_path / "two.json"
    one_result.write_text(json.dumps(report))
    two_result.write_text(json.dumps({"findings": []}))
    config = {
        "benchmarks": [
            {
                "name": "one",
                "result_path": str(one_result),
                "assertions": {"min_total_findings": 1},
            },
            {
                "name": "two",
                "result_path": str(two_result),
                "assertions": {"min_total_findings": 1},
            },
        ]
    }
    config_path = tmp_path / "benchmarks.json"
    config_path.write_text(json.dumps(config))

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_benchmarks.py",
            "--benchmarks",
            str(config_path),
            "--benchmark",
            "one",
        ],
    )

    assert run_benchmarks.main() == 0
    captured = capsys.readouterr()
    assert "[one] PASS" in captured.out
    assert "[two]" not in captured.out
