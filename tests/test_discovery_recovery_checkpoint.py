from __future__ import annotations

import json

from scanner.manifests import (
    DiscoveryRecoverySink,
    EndpointManifest,
    normalize_endpoint,
)


def _manifest(tmp_path):
    checkpoint = tmp_path / "scan_checkpoint.json"
    sidecar = tmp_path / "endpoint_manifest.json"
    sink = DiscoveryRecoverySink(
        manifest_path=sidecar,
        checkpoint_path=checkpoint,
        flush_seconds=999,
        flush_new_endpoints=50,
    )
    return EndpointManifest(recovery_sink=sink), checkpoint, sidecar


def test_manifest_checkpoint_preserves_endpoint_shape_without_query_secrets(tmp_path):
    manifest, checkpoint, sidecar = _manifest(tmp_path)
    manifest.start_producer("katana")
    manifest.add("katana", normalize_endpoint(
        method="GET",
        url="https://example.test/search?q=private-value&token=do-not-store",
        source="katana",
    ))
    manifest.add("katana", normalize_endpoint(
        method="POST",
        url="https://example.test/orders?customer=secret-customer",
        source="katana",
    ))
    manifest.finish_producer("katana", status="timed_out", reason="soft_deadline")
    manifest.finalize()

    stored_manifest = json.loads(sidecar.read_text())
    recovered = json.loads(checkpoint.read_text())
    serialized = json.dumps({"manifest": stored_manifest, "checkpoint": recovered})

    assert stored_manifest["status"] == "partial"
    assert stored_manifest["endpoint_count"] == 2
    assert "private-value" not in serialized
    assert "do-not-store" not in serialized
    assert "secret-customer" not in serialized
    assert "q=1" in serialized and "token=1" in serialized

    report = recovered["report"]
    assert report["active_checks"]["active_worklist"] == ["GET /search?q=1&token=1"]
    assert report["scan_metadata"]["timed_out"] is True
    assert report["scan_metadata"]["unsafe_methods_excluded_from_fanout"] == 1


def test_recovery_checkpoint_never_overwrites_a_richer_scanner_checkpoint(tmp_path):
    manifest, checkpoint, sidecar = _manifest(tmp_path)
    richer = {
        "phase": "baseline",
        "partial": True,
        "report": {"findings": [{"id": "real-finding"}]},
    }
    checkpoint.write_text(json.dumps(richer))

    manifest.start_producer("seed")
    manifest.add("seed", normalize_endpoint(
        method="GET", url="https://example.test/", source="seed",
    ))
    manifest.finish_producer("seed")
    manifest.finalize()

    assert json.loads(checkpoint.read_text()) == richer
    assert json.loads(sidecar.read_text())["endpoint_count"] == 1


def test_cancelled_manifest_cannot_supply_parent_fanout_work(tmp_path):
    manifest, checkpoint, _sidecar = _manifest(tmp_path)
    manifest.start_producer("katana")
    manifest.add("katana", normalize_endpoint(
        method="GET", url="https://example.test/admin", source="katana",
    ))
    manifest.finish_producer("katana", status="cancelled", reason="user_cancelled")
    manifest.finalize(cancelled=True)

    recovered = json.loads(checkpoint.read_text())
    report = recovered["report"]
    assert recovered["partial"] is False
    assert report["scan_metadata"]["status"] == "cancelled"
    assert report["active_checks"]["active_worklist"] == []
    assert report["discovery"]["katana_sample"] == []


def test_environment_auto_persistence_uses_existing_worker_checkpoint_channel(tmp_path, monkeypatch):
    checkpoint = tmp_path / "worker_checkpoint.json"
    monkeypatch.setenv("SCAN_CHECKPOINT_FILE", str(checkpoint))
    monkeypatch.delenv("SHAKERSCAN_ENDPOINT_MANIFEST_FILE", raising=False)
    monkeypatch.delenv("SHAKERSCAN_DISABLE_DISCOVERY_RECOVERY", raising=False)

    manifest = EndpointManifest()
    manifest.start_producer("seed")
    manifest.add("seed", normalize_endpoint(
        method="HEAD", url="https://example.test/health", source="seed",
    ))
    manifest.finish_producer("seed")

    assert checkpoint.exists()
    assert (tmp_path / "worker_checkpoint.json.endpoint-manifest.json").exists()
    recovered = json.loads(checkpoint.read_text())
    assert recovered["checkpoint_kind"] == "endpoint_manifest_recovery/v1"
    assert recovered["report"]["active_checks"]["active_worklist"] == ["HEAD /health"]


def test_query_parameter_names_participate_in_endpoint_identity():
    manifest = EndpointManifest(auto_persist=False)
    manifest.start_producer("crawl")
    assert manifest.add("crawl", normalize_endpoint(
        method="GET", url="https://example.test/items?id=1", source="crawl",
    )) is True
    assert manifest.add("crawl", normalize_endpoint(
        method="GET", url="https://example.test/items?slug=secret", source="crawl",
    )) is True
    assert manifest.add("crawl", normalize_endpoint(
        method="GET", url="https://example.test/items?id=other-secret", source="crawl",
    )) is False
