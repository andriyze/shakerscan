import json
import sys
from pathlib import Path


SCANNER_DIR = Path(__file__).resolve().parents[1] / "scanner"
if str(SCANNER_DIR) not in sys.path:
    sys.path.insert(0, str(SCANNER_DIR))

from scanner_tools.benchmark_summary import (  # noqa: E402
    build_benchmark_summary,
    compare_benchmark_summaries,
)


def test_benchmark_summary_tracks_attempts_params_and_misses():
    report = {
        "discovery": {
            "har_discovery": {"stats": {"unique_endpoints": 3}},
        },
        "active_checks": {
            "active_endpoints_discovered_by_source": {"har_discovery": 2, "manual": 1},
            "endpoint_attempts": [
                {
                    "custom_endpoint": 'GET /api/orders?id=1',
                    "family": "bola",
                    "auth_state": "user1",
                    "status": "completed",
                    "attempted_params_count": 1,
                    "completed_params_count": 1,
                    "proof_type": "authz_diff",
                },
                {
                    "custom_endpoint": 'PATCH /api/profile json:{"email":"a@example.test"}',
                    "family": "authz",
                    "auth_state": "user2",
                    "status": "completed",
                    "attempted_params_count": 2,
                    "completed_params_count": 2,
                },
            ],
        },
        "findings": [
            {
                "tool": "smart_bola",
                "title": "BOLA: User2 can read User1 order",
                "severity": "high",
                "verified": True,
                "evidence": {"proof_type": "authz_diff"},
            }
        ],
    }

    summary = build_benchmark_summary(
        report,
        profile="crapi",
        base_url="https://crapi.test",
        expected={
            "families": {
                "bola": {"min_severity": "high", "min_confirmed": 1},
                "sqli": {"min_severity": "high", "min_confirmed": 1},
            },
            "auth_states": ["user1", "user2"],
        },
    )

    assert summary["discovery"]["endpoints_by_source"]["har_discovery"] == 2
    assert summary["discovery"]["endpoints_by_source"]["har"] == 3
    assert summary["attempts"]["by_auth_state_family_status"]["user1|bola|completed"] == 1
    assert summary["attempts"]["by_auth_state_family_status"]["user2|authz|completed"] == 1
    assert summary["parameters"]["attempted_by_location"]["query"] == 1
    assert summary["parameters"]["attempted_by_location"]["json"] == 2
    assert summary["findings"]["confirmed_by_family_severity"]["bola|high"] == 1
    assert summary["misses"] == [
        {
            "family": "sqli",
            "expected_min_confirmed": 1,
            "expected_min_severity": "high",
            "confirmed": 0,
            "attempted": 0,
            "likely_root_cause": "family_not_attempted",
        }
    ]


def test_benchmark_summary_records_proof_and_severity_gaps():
    report = {
        "findings": [
            {"tool": "smart_sqli", "title": "SQLi", "severity": "high", "verified": False},
            {
                "tool": "smart_auth",
                "title": "Authz issue",
                "severity": "medium",
                "evidence": {"severity_rationale": "Unauthorized access to sensitive user object"},
            },
        ]
    }

    summary = build_benchmark_summary(report, expected={"families": {"sqli": {"min_confirmed": 1}}})

    assert summary["proof_or_severity_gaps"][0]["reason"] == "high_or_critical_without_deterministic_proof"
    assert summary["proof_or_severity_gaps"][1]["severity_rationale"] == "Unauthorized access to sensitive user object"
    assert summary["misses"][0]["family"] == "sqli"
    assert summary["misses"][0]["likely_root_cause"] == "family_not_attempted"


def test_benchmark_summary_counts_smart_authz_as_authz():
    summary = build_benchmark_summary(
        {
            "findings": [
                {
                    "tool": "smart_authz",
                    "title": "Cross-principal replay",
                    "severity": "high",
                    "verified": True,
                    "evidence": {"proof_type": "cross_principal_replay"},
                }
            ]
        },
        expected={"families": {"authz": {"min_severity": "high", "min_confirmed": 1}}},
    )

    assert summary["findings"]["confirmed_by_family_severity"]["authz|high"] == 1
    assert summary["misses"] == []


def test_benchmark_compare_reports_confirmed_delta():
    baseline = build_benchmark_summary({"findings": []})
    candidate = build_benchmark_summary({
        "findings": [
            {"tool": "smart_sqli", "title": "SQLi", "severity": "critical", "verified": True}
        ]
    })

    comparison = compare_benchmark_summaries(baseline, candidate)

    assert comparison["baseline_confirmed_high_or_critical"] == 0
    assert comparison["candidate_confirmed_high_or_critical"] == 1
    assert comparison["confirmed_high_or_critical_delta"] == 1


def test_benchmark_cli_outputs_summary(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"findings": []}))
    out = tmp_path / "summary.json"

    import importlib.util

    module_path = Path(__file__).resolve().parent / "benchmark" / "analyze_dast_benchmark.py"
    spec = importlib.util.spec_from_file_location("analyze_dast_benchmark", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)

    old_argv = sys.argv
    try:
        sys.argv = [
            "analyze_dast_benchmark.py",
            "--profile",
            "generic",
            "--result",
            str(report),
            "--expect-family",
            "sqli:high:1",
            "--out",
            str(out),
        ]
        assert module.main() == 0
    finally:
        sys.argv = old_argv

    summary = json.loads(out.read_text())
    assert summary["misses"][0]["family"] == "sqli"
