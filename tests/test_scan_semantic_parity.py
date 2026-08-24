from __future__ import annotations

from copy import deepcopy

from api.scan.parity import (
    build_scan_semantic_parity_artifact,
    compare_scan_semantic_parity,
    parity_artifact_is_truthful,
)
from scripts import scan_semantic_parity


def _explanation(*, backend: str = "local", worker_id: str = "worker-1"):
    return {
        "plan_revision": {"revision": 1, "continuation_plan_digest": "a" * 64},
        "actions": [{
            "action_id": "baseline.http",
            "ordinal": 0,
            "stage": "deterministic_baseline",
            "capability_name": "http.request",
            "dependencies": [],
            "required": True,
            "supporting": False,
            "status": "success",
            "reason_code": None,
            "output_schema": "http-observation/v1",
            "placement": {"backend": backend, "worker_id": worker_id},
            "budget": {
                "reserved": {"tool_wall_seconds": 15, "http_requests": 1},
                "consumed": {"tool_wall_seconds": 1, "http_requests": 1},
            },
            "receipt": {
                "receipt_id": "runtime-only",
                "parser_version": "http-observation/v1",
                "started_at": "2026-08-24T01:00:00Z",
                "finished_at": "2026-08-24T01:00:01Z",
            },
            "observation": {
                "manifest_id": "runtime-only",
                "manifest_digest": "b" * 64,
                "count": 1,
            },
        }],
        "coverage": {
            "status": "complete",
            "optional_gaps": [],
            "active_zero_attempt_actions": [],
            "grade_reliability": {"reliable": True, "reasons": []},
        },
    }


def test_semantic_artifact_omits_allowed_runtime_differences():
    local = build_scan_semantic_parity_artifact(
        _explanation(),
        ({"fingerprint": "ABC", "title": "Example"},),
    )
    broker = build_scan_semantic_parity_artifact(
        _explanation(backend="broker", worker_id="broker:node-a:container-1"),
        ({"fingerprint": "abc", "title": "Example"},),
    )

    comparison = compare_scan_semantic_parity({"local": local, "broker": broker})

    assert local["semantic_digest"] == broker["semantic_digest"]
    assert comparison["consistent"] is True
    assert "worker-1" not in str(local)
    assert "runtime-only" not in str(local)


def test_semantic_parity_detects_policy_coverage_and_schema_differences():
    local = build_scan_semantic_parity_artifact(_explanation())
    changed = _explanation(backend="broker")
    changed["actions"][0]["output_schema"] = "wrong/v1"
    changed["coverage"]["grade_reliability"] = {
        "reliable": False,
        "reasons": ["placement_unavailable"],
    }
    broker = build_scan_semantic_parity_artifact(changed)

    comparison = compare_scan_semantic_parity({"local": local, "broker": broker})

    assert comparison["consistent"] is False
    paths = {
        difference["path"]
        for difference in comparison["comparisons"][0]["differences"]
    }
    assert "$.actions[0].output_schema" in paths
    assert "$.coverage.grade_reliability.reliable" in paths


def test_missing_required_placement_cannot_produce_clean_artifact():
    explanation = deepcopy(_explanation(backend="broker"))
    explanation["actions"][0]["status"] = "blocked"
    explanation["actions"][0]["reason_code"] = "placement_unavailable"
    artifact = build_scan_semantic_parity_artifact(explanation)

    assert parity_artifact_is_truthful(artifact) is False

    explanation["coverage"] = {
        "status": "failed",
        "grade_reliability": {
            "reliable": False,
            "reasons": ["placement_unavailable"],
        },
    }
    truthful = build_scan_semantic_parity_artifact(explanation)
    assert parity_artifact_is_truthful(truthful) is True


def test_finding_identity_fallback_is_stable_across_scan_rows():
    first = build_scan_semantic_parity_artifact(
        _explanation(),
        ({
            "tool": "Nuclei", "category": "headers",
            "url": "https://app.example.test/", "title": "Missing CSP",
        },),
    )
    second = build_scan_semantic_parity_artifact(
        _explanation(backend="broker"),
        ({
            "tool": "nuclei", "category": "headers",
            "url": "https://app.example.test/", "title": "missing csp",
        },),
    )

    assert first["finding_identities"] == second["finding_identities"]


def test_release_comparator_cli_requires_all_three_real_placements(monkeypatch, capsys):
    artifact = build_scan_semantic_parity_artifact(_explanation())
    requested = []

    def fetch(url):
        requested.append(url)
        return deepcopy(artifact)

    monkeypatch.setattr(scan_semantic_parity, "_fetch_json", fetch)
    code = scan_semantic_parity.main([
        "--api-url", "https://scanner.example.test/",
        "--local", "local-id",
        "--broker", "broker-id",
        "--parallel", "parallel-id",
        "--json",
    ])

    assert code == 0
    assert requested == [
        "https://scanner.example.test/scans/local-id/parity-artifact",
        "https://scanner.example.test/scans/broker-id/parity-artifact",
        "https://scanner.example.test/scans/parallel-id/parity-artifact",
    ]
    receipt = __import__("json").loads(capsys.readouterr().out)
    assert receipt["consistent"] is True
    assert receipt["truthful"] is True
