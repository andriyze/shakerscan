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


def _explanation_with_actions(actions):
    return {
        "plan_revision": {"revision": 1, "continuation_plan_digest": None},
        "actions": actions,
        "coverage": {
            "status": "complete",
            "optional_gaps": [],
            "active_zero_attempt_actions": [],
            "grade_reliability": {"reliable": True, "reasons": []},
        },
    }


def _verify_action(*, ordinal, observation_count, budget):
    return {
        "action_id": "verify.xss.00000",
        "ordinal": ordinal,
        "stage": "verify_candidates",
        "capability_name": "xss.verify_batch",
        "dependencies": [],
        "required": True,
        "supporting": False,
        "budget": {"reserved": {"http_requests": budget}},
        "status": "success",
        "reason_code": None,
        "output_schema": "candidate-attempt/v1",
        "receipt": {"parser_version": "dalfox/1"},
        "observation": {"count": observation_count},
    }


def test_fan_out_occurrences_are_not_semantic_drift():
    """One logical action may run as several occurrences under fan-out.

    The comparator walked an ordered action array position by position, so a
    parallel run that split one logical action into two occurrences reported an
    extra array element as a semantic difference -- even though the same work
    manifest entries were covered exactly once, the same statuses resulted, and
    the same total budget was reserved. That made the gate fail for the topology
    it exists to qualify.
    """
    local = build_scan_semantic_parity_artifact(
        _explanation_with_actions([
            _verify_action(ordinal=0, observation_count=4, budget=40),
        ]),
    )
    parallel = build_scan_semantic_parity_artifact(
        _explanation_with_actions([
            _verify_action(ordinal=0, observation_count=2, budget=20),
            _verify_action(ordinal=1, observation_count=2, budget=20),
        ]),
    )

    comparison = compare_scan_semantic_parity({"local": local, "parallel": parallel})
    assert comparison["consistent"] is True, comparison["comparisons"]


def test_missing_logical_action_is_still_drift():
    """Normalizing occurrences must not hide genuinely absent work."""
    local = build_scan_semantic_parity_artifact(
        _explanation_with_actions([
            _verify_action(ordinal=0, observation_count=4, budget=40),
        ]),
    )
    parallel = build_scan_semantic_parity_artifact(_explanation_with_actions([]))
    comparison = compare_scan_semantic_parity({"local": local, "parallel": parallel})
    assert comparison["consistent"] is False


def test_different_total_work_is_still_drift():
    """Occurrence-normalized totals must still catch duplicated or lost work."""
    local = build_scan_semantic_parity_artifact(
        _explanation_with_actions([
            _verify_action(ordinal=0, observation_count=4, budget=40),
        ]),
    )
    parallel = build_scan_semantic_parity_artifact(
        _explanation_with_actions([
            _verify_action(ordinal=0, observation_count=4, budget=20),
            _verify_action(ordinal=1, observation_count=4, budget=20),
        ]),
    )
    comparison = compare_scan_semantic_parity({"local": local, "parallel": parallel})
    assert comparison["consistent"] is False


def test_truthfulness_still_catches_a_failed_required_action():
    """Aggregating occurrences must not weaken the truthfulness guard.

    The guard reads each action's terminal state; folding occurrences into a
    status set would silently pass a failed required action if it only looked at
    the first one.
    """
    def artifact(*statuses):
        return build_scan_semantic_parity_artifact(_explanation_with_actions([
            dict(_verify_action(ordinal=index, observation_count=1, budget=10),
                 status=status)
            for index, status in enumerate(statuses)
        ]))

    assert parity_artifact_is_truthful(artifact("success")) is True
    assert parity_artifact_is_truthful(artifact("failed")) is False
    # One healthy occurrence must not launder a failed sibling occurrence.
    assert parity_artifact_is_truthful(artifact("success", "failed")) is False


def test_occurrence_counts_are_recorded_as_provenance_only():
    single = build_scan_semantic_parity_artifact(_explanation_with_actions([
        _verify_action(ordinal=0, observation_count=4, budget=40),
    ]))
    split = build_scan_semantic_parity_artifact(_explanation_with_actions([
        _verify_action(ordinal=0, observation_count=2, budget=20),
        _verify_action(ordinal=1, observation_count=2, budget=20),
    ]))
    assert single["provenance"]["action_occurrences"]["verify.xss.00000"] == 1
    assert split["provenance"]["action_occurrences"]["verify.xss.00000"] == 2
    # ...and the placement difference does not reach the compared body.
    assert compare_scan_semantic_parity(
        {"local": single, "parallel": split},
    )["consistent"] is True
