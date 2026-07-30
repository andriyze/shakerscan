from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from model_intake_runner_evaluation import derive_embedding_evaluation  # noqa: E402


def _payload(status="PASS"):
    digest = "a" * 64
    return {
        "evidence_type": "runtime_execution",
        "status": status,
        "submission_id": "3a361d68-708d-4f20-9261-a09ded671626",
        "deployment_bundle_sha256": digest,
        "model_artifact_sha256": "b" * 64,
        "repository_snapshot_sha256": "c" * 64,
        "custom_code_sha256": None,
        "tokenizer_sha256": "5" * 64,
        "configuration_sha256": "6" * 64,
        "runtime_image_digest": "sha256:" + "d" * 64,
        "loader_profile_sha256": "e" * 64,
        "started_at": "2026-07-30T00:00:00+00:00",
        "finished_at": "2026-07-30T00:01:00+00:00",
        "expires_at": "2026-08-06T00:01:00+00:00",
        "observations": {
            "observations_generated_by_runner": True,
            "embedding_known_answers_status": "PASS",
            "embedding_output_sha256": "f" * 64,
            "embedding_shape": [2, 768],
            "benchmark_dataset_sha256": "1" * 64,
            "thresholds_sha256": "2" * 64,
            "network_egress_blocked": True,
            "network_telemetry": {
                "complete": True,
                "attempt_count": 0,
                "overflowed": False,
                "lost_events": 0,
                "telemetry_sha256": "3" * 64,
            },
            "resource_limits_enforced": True,
            "resource_telemetry": {"complete": True, "limits_sha256": "4" * 64},
        },
    }


def test_verified_runtime_measurements_derive_pass_evaluation_without_vectors():
    report = derive_embedding_evaluation(_payload(), "9" * 64)
    assert report["status"] == "PASS"
    assert report["provenance_class"] == "GENERATED_EVALUATION"
    assert report["embedding_shape"] == [2, 768]
    assert report["benchmark_dataset_sha256"] == "1" * 64
    assert "vector" not in str(report).lower()
    assert len(report["evidence_sha256"]) == 64


def test_nonpass_or_incomplete_runtime_cannot_derive_pass_evaluation():
    payload = _payload("FAIL")
    payload["observations"]["network_telemetry"]["attempt_count"] = 1
    payload["observations"]["embedding_known_answers_status"] = "NOT_CONFIGURED"
    report = derive_embedding_evaluation(payload, "9" * 64)
    assert report["status"] == "FAIL"
    assert set(report["blockers"]) >= {"runtime_pass", "known_answer_pass", "network_quiet"}


def test_non_runtime_receipt_is_rejected():
    payload = _payload()
    payload["evidence_type"] = "conversion_equivalence"
    try:
        derive_embedding_evaluation(payload, "9" * 64)
    except ValueError as exc:
        assert "runtime_execution" in str(exc)
    else:
        raise AssertionError("conversion receipt must not become embedding evaluation")
