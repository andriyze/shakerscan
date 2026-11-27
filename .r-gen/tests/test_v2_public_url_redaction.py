from __future__ import annotations

import json
import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner.manifests import DiscoveryRecoverySink, EndpointManifest, normalize_endpoint
from scanner_tools.url_redaction import redact_client_route, redact_path, redact_url


def test_redact_url_removes_query_userinfo_and_secret_path_segments():
    secret = "AbCdEf0123456789AbCdEf0123456789"
    value = redact_url(f"https://user:pass@example.test/reset/{secret}?signature=wire-secret")
    assert "user" not in value
    assert "pass" not in value
    assert secret not in value
    assert "wire-secret" not in value
    assert "/reset/<redacted>" in value
    assert "signature=%3Credacted%3E" in value


def test_client_route_keeps_only_route_shape_and_field_names():
    proof = "https://app.test/#/search?q=%3Csvg%20onload%3Dalert(1)%3E&sort=recent"

    assert redact_client_route(proof) == "/search?q=&sort="
    assert redact_client_route("https://app.test/#/<svg/onload=alert(1)>") is None
    assert redact_client_route("https://app.test/#//evil.test/path") is None


def test_recovery_manifest_never_persists_or_fans_out_secret_bearing_paths(tmp_path):
    secret = "AbCdEf0123456789AbCdEf0123456789"
    checkpoint = tmp_path / "checkpoint.json"
    sidecar = tmp_path / "manifest.json"
    sink = DiscoveryRecoverySink(
        manifest_path=sidecar,
        checkpoint_path=checkpoint,
        flush_seconds=0,
        flush_new_endpoints=1,
    )
    manifest = EndpointManifest(recovery_sink=sink, auto_persist=False)
    manifest.start_producer("katana")
    sensitive = normalize_endpoint(
        method="GET",
        url=f"https://example.test/reset/{secret}?signature=wire-secret",
        source="katana",
    )
    ordinary = normalize_endpoint(
        method="GET",
        url="https://example.test/api/orders/42?include=items",
        source="katana",
    )
    manifest.add("katana", sensitive)
    manifest.add("katana", ordinary)
    manifest.finish_producer("katana", status="timed_out", reason="soft_deadline")
    manifest.finalize()

    serialized = json.dumps(manifest.to_dict(), sort_keys=True)
    checkpoint_payload = json.loads(checkpoint.read_text())
    checkpoint_text = json.dumps(checkpoint_payload, sort_keys=True)
    assert secret not in serialized
    assert secret not in checkpoint_text
    assert "wire-secret" not in serialized
    assert "wire-secret" not in checkpoint_text
    assert checkpoint_payload["report"]["active_checks"]["active_worklist"] == [
        "GET /api/orders/42?include=1"
    ]
    metadata = checkpoint_payload["report"]["scan_metadata"]
    assert metadata["sensitive_paths_excluded_from_fanout"] == 1
    assert metadata["unsafe_methods_excluded_from_fanout"] == 0


def test_redact_path_keeps_useful_route_shape():
    assert redact_path("/api/orders/42") == "/api/orders/42"
    assert redact_path("/verify/token-value-12345678901234567890") == "/verify/<redacted>"
