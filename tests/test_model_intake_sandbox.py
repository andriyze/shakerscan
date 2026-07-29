import hashlib
import json
import os
import time

from scanner.scanner_tools import model_intake_sandbox as sandbox


def _safetensors():
    header = json.dumps({"weight": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
    return len(header).to_bytes(8, "little") + header + b"\0\0\0\0"


def test_sandbox_inspects_digest_bound_safetensors_without_importing_code(tmp_path, monkeypatch):
    artifact = tmp_path / "model.safetensors"
    artifact.write_bytes(_safetensors())
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    monkeypatch.setattr(sandbox, "_network_probe", lambda: {"network_mode": "none", "blocked": True, "outbound_probes": []})

    result = sandbox.inspect_quarantine_object(artifact, artifact.name, expected_digest=digest)

    assert result["status"] == "PASS"
    assert result["subject"]["digest"] == f"sha256:{digest}"
    assert result["inspection"]["tensor_count"] == 1
    assert len(result["evidence_sha256"]) == 64


def test_sandbox_blocks_pickle_loading_by_policy(tmp_path, monkeypatch):
    artifact = tmp_path / "model.pkl"
    artifact.write_bytes(b"pickle")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    monkeypatch.setattr(sandbox, "_network_probe", lambda: {"network_mode": "none", "blocked": True, "outbound_probes": []})

    result = sandbox.inspect_quarantine_object(artifact, artifact.name, expected_digest=digest)

    assert result["status"] == "BLOCKED_BY_POLICY"


def test_sandbox_file_queue_resolves_only_content_addressed_objects(tmp_path, monkeypatch):
    queue = tmp_path / "queue"
    quarantine = tmp_path / "quarantine"
    payload = _safetensors()
    digest = hashlib.sha256(payload).hexdigest()
    artifact = quarantine / "sha256" / digest[:2] / digest
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(payload)
    requests = queue / "requests"
    requests.mkdir(parents=True)
    request = requests / "request.json"
    request.write_text(json.dumps({
        "request_id": "request",
        "request_nonce": "n" * 32,
        "digest": digest,
        "filename": "model.safetensors",
        "timeout_seconds": 5,
    }), encoding="utf-8")
    monkeypatch.setattr(sandbox, "_network_probe", lambda: {"network_mode": "none", "blocked": True, "outbound_probes": []})

    assert sandbox.process_pending_once(queue, quarantine) == 1
    result = json.loads((queue / "responses" / "request.json").read_text("utf-8"))
    assert result["status"] == "PASS"
    assert result["request_binding"] == sandbox._request_binding("request", "n" * 32)
    evidence = dict(result)
    evidence.pop("evidence_sha256")
    assert result["evidence_sha256"] == sandbox._sha256_json(evidence)


def test_sandbox_client_rejects_unbound_or_tampered_pass_response():
    digest = "a" * 64
    response = sandbox._attach_evidence_digest({
        "schema_version": sandbox.SCHEMA_VERSION,
        "provenance_class": "shakerscan_generated",
        "status": "PASS",
        "request_binding": sandbox._request_binding("request", "n" * 32),
        "subject": {"digest": f"sha256:{digest}", "filename": "model.safetensors"},
        "isolation": {
            "network": {"network_mode": "none", "blocked": False},
            "uid": 1000,
            "read_only_rootfs_declared": True,
            "no_new_privileges_declared": True,
            "credentials_present": False,
        },
    })

    result = sandbox._validate_sandbox_response(
        response,
        request_id="request",
        request_nonce="n" * 32,
        digest=digest,
        filename="model.safetensors",
    )

    assert result["status"] == "CRASHED"
    assert result["error"] == "sandbox_response_validation_failed"
    assert result["validation_errors"] == ["no_egress_not_proven"]


def test_sandbox_client_accepts_only_digest_bound_hardened_evidence():
    digest = "a" * 64
    response = sandbox._attach_evidence_digest({
        "schema_version": sandbox.SCHEMA_VERSION,
        "provenance_class": "shakerscan_generated",
        "status": "PASS",
        "request_binding": sandbox._request_binding("request", "n" * 32),
        "subject": {"digest": f"sha256:{digest}", "filename": "model.safetensors"},
        "isolation": {
            "network": {"network_mode": "none", "blocked": True},
            "uid": 1000,
            "read_only_rootfs_declared": True,
            "no_new_privileges_declared": True,
            "credentials_present": False,
        },
    })

    result = sandbox._validate_sandbox_response(
        response,
        request_id="request",
        request_nonce="n" * 32,
        digest=digest,
        filename="model.safetensors",
    )

    assert result is response


def test_sandbox_client_fails_fast_when_service_is_absent(tmp_path):
    started = time.monotonic()
    result = sandbox.request_sandbox_analysis("a" * 64, "model.safetensors", queue_root=tmp_path, timeout_seconds=30)

    assert result["status"] == "UNSUPPORTED"
    assert time.monotonic() - started < 1
