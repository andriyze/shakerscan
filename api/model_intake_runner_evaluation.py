"""Derive bounded embedding-evaluation evidence from a verified runtime receipt."""

from __future__ import annotations

import hashlib
import json
from typing import Any


SCHEMA = "model-intake-runner-embedding-evaluation/v1"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def derive_embedding_evaluation(runtime_payload: dict[str, Any], source_payload_sha256: str) -> dict[str, Any]:
    if runtime_payload.get("evidence_type") != "runtime_execution":
        raise ValueError("embedding evaluation requires verified runtime_execution evidence")
    observations = runtime_payload.get("observations") if isinstance(runtime_payload.get("observations"), dict) else {}
    network = observations.get("network_telemetry") if isinstance(observations.get("network_telemetry"), dict) else {}
    resource = observations.get("resource_telemetry") if isinstance(observations.get("resource_telemetry"), dict) else {}
    blockers: list[str] = []
    evaluation_required = {
        "runner_generated": observations.get("observations_generated_by_runner") is True,
        "known_answer_pass": observations.get("embedding_known_answers_status") == "PASS",
        "embedding_output_digest": bool(observations.get("embedding_output_sha256")),
        "embedding_shape": (
            isinstance(observations.get("embedding_shape"), list)
            and len(observations["embedding_shape"]) == 2
            and all(isinstance(item, int) and item > 0 for item in observations["embedding_shape"])
        ),
        "benchmark_dataset_digest": bool(observations.get("benchmark_dataset_sha256")),
        "thresholds_digest": bool(observations.get("thresholds_sha256")),
        "resources_measured": observations.get("resource_limits_enforced") is True and resource.get("complete") is True,
    }
    containment_required = {
        "runtime_pass": runtime_payload.get("status") == "PASS",
        "network_quiet": (
            observations.get("network_egress_blocked") is True
            and network.get("complete") is True
            and network.get("attempt_count") == 0
            and network.get("overflowed") is False
            and network.get("lost_events") == 0
        ),
    }
    blockers.extend(name for name, passed in evaluation_required.items() if not passed)
    containment_blockers = [name for name, passed in containment_required.items() if not passed]
    report = {
        "schema_version": SCHEMA,
        "provenance_class": "GENERATED_EVALUATION",
        "source_evidence_type": "runtime_execution",
        "source_payload_sha256": source_payload_sha256,
        "submission_id": runtime_payload.get("submission_id"),
        "deployment_bundle_sha256": runtime_payload.get("deployment_bundle_sha256"),
        "model_artifact_sha256": runtime_payload.get("model_artifact_sha256"),
        "repository_snapshot_sha256": runtime_payload.get("repository_snapshot_sha256"),
        "custom_code_sha256": runtime_payload.get("custom_code_sha256"),
        "tokenizer_sha256": runtime_payload.get("tokenizer_sha256"),
        "configuration_sha256": runtime_payload.get("configuration_sha256"),
        "runtime_image_digest": runtime_payload.get("runtime_image_digest"),
        "loader_profile_sha256": runtime_payload.get("loader_profile_sha256"),
        "benchmark_dataset_sha256": observations.get("benchmark_dataset_sha256"),
        "thresholds_sha256": observations.get("thresholds_sha256"),
        "embedding_output_sha256": observations.get("embedding_output_sha256"),
        "embedding_shape": observations.get("embedding_shape"),
        "resource_limits_sha256": resource.get("limits_sha256"),
        "network_telemetry_sha256": network.get("telemetry_sha256"),
        # Runtime containment is intentionally reported separately. A framework
        # socket attempt must block admission through runtime/network controls,
        # but it must not falsely say that known-answer embedding checks failed.
        "security_status": "PASS" if not blockers else "FAIL",
        "quality_status": "KNOWN_ANSWER_PASS" if not blockers else "INCOMPLETE",
        "containment_status": "PASS" if not containment_blockers else "FAIL",
        "status": "PASS" if not blockers else "FAIL",
        "blockers": blockers,
        "containment_blockers": containment_blockers,
        "started_at": runtime_payload.get("started_at"),
        "finished_at": runtime_payload.get("finished_at"),
        "expires_at": runtime_payload.get("expires_at"),
    }
    report["evidence_sha256"] = _sha(report)
    return report


__all__ = ["SCHEMA", "derive_embedding_evaluation"]
