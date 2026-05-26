import importlib.util
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
