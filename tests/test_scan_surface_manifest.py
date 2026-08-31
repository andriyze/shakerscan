from __future__ import annotations

import json

from api.runtime.models import TargetBinding
from api.scan.surface_manifest import build_scan_surface_manifest
from api.scan.work_manifests import build_candidate_manifest, build_endpoint_manifest


TARGET = TargetBinding(
    target_id="target-1",
    target_kind="web",
    canonical_host="app.example.test",
    allowed_origins=("https://app.example.test",),
    allowed_addresses=("192.0.2.10",),
    allowed_root_domains=("example.test",),
)


def _summary(status: str, observations: list[dict] | None = None) -> dict:
    return {
        "status": status,
        "observations": list(observations or []),
    }


def test_surface_manifest_unifies_producers_and_redacts_values():
    secret = "worker-private-query-value"
    manifest = build_scan_surface_manifest(
        target_url=f"https://app.example.test/start?tenant={secret}",
        target=TARGET,
        options={
            "custom_endpoints": [
                f"GET /api/orders?owner={secret}",
                "POST /api/orders",
            ],
        },
        collection_replay=_summary("success", [{
            "kind": "request_replay",
            "method": "GET",
            "redacted_url": "https://app.example.test/replayed?token=%3Credacted%3E",
            "final_url": "https://app.example.test/replayed?token=%3Credacted%3E",
        }]),
        probe=_summary("success", [{
            "kind": "http_fingerprint",
            "url": "https://app.example.test/start",
        }]),
        crawl=_summary("success", [{
            "kind": "discovered_route",
            "method": "GET",
            "url": "https://app.example.test/api/orders?owner=%3Credacted%3E",
        }]),
        content=_summary("success", [{
            "kind": "content_discovery",
            "url": "https://app.example.test/admin",
        }]),
        subdomains=_summary("success", [{
            "kind": "subdomain", "host": "api.example.test",
        }]),
        max_endpoints=20,
    )

    encoded = json.dumps(manifest, sort_keys=True)
    assert manifest["schema_version"] == "endpoint-manifest/v1"
    assert manifest["status"] == "complete"
    assert manifest["endpoint_count"] == 7
    assert set(manifest["producers"]) == {
        "seed", "known_endpoints", "collections.replay", "web.probe",
        "web.crawl", "web.browser_crawl", "web.content_discover",
        "subdomains.discover",
    }
    assert secret not in encoded
    assert "owner" in encoded
    assert "tenant" in encoded


def test_surface_manifest_marks_out_of_scope_or_truncated_output_partial():
    manifest = build_scan_surface_manifest(
        target_url="https://app.example.test",
        target=TARGET,
        options={"custom_endpoints": ["GET /one", "GET /two"]},
        collection_replay=_summary("skipped"),
        probe=_summary("success"),
        crawl=_summary("success", [{
            "kind": "discovered_route",
            "method": "GET",
            "url": "https://evil.example/escape",
        }]),
        content=_summary("skipped"),
        subdomains=_summary("success", [{
            "kind": "subdomain", "host": "outside.invalid",
        }]),
        max_endpoints=2,
    )

    assert manifest["status"] == "partial"
    assert manifest["endpoint_count"] == 2
    assert manifest["producers"]["known_endpoints"]["status"] == "partial"
    assert manifest["producers"]["web.crawl"]["status"] == "partial"
    assert manifest["producers"]["subdomains.discover"]["status"] == "partial"
    assert "out_of_scope_observations" in (
        manifest["producers"]["web.crawl"]["reason"] or ""
    )


def test_browser_observed_post_body_shape_survives_without_values():
    secret = "browser-private-password"
    manifest = build_scan_surface_manifest(
        target_url="https://app.example.test",
        target=TARGET,
        options={},
        collection_replay=_summary("skipped"),
        probe=_summary("success"),
        crawl=_summary("success"),
        browser=_summary("success", [{
            "kind": "discovered_route",
            "method": "POST",
            "url": "https://app.example.test/rest/user/login",
            "content_type": "application/json",
            "body_field_names": ["email", "password"],
            "discarded_example_value": secret,
        }]),
        content=_summary("skipped"),
        subdomains=_summary("skipped"),
        max_endpoints=20,
    )

    login = next(
        item for item in manifest["endpoints"]
        if item["method"] == "POST" and item["concrete_path"] == "/rest/user/login"
    )
    assert login["content_type"] == "application/json"
    assert login["body_field_names"] == ["email", "password"]
    assert secret not in json.dumps(manifest, sort_keys=True)

    endpoints = build_endpoint_manifest(
        scan_id="10000000-0000-4000-8000-000000000001",
        target_binding_digest=TARGET.digest,
        surface_manifest=manifest,
        source_action_ids=("discover.browser_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoints,
        source_action_ids=("discover.browser_crawl",),
        maximum=50,
        allow_state_changing_http=True,
    )
    assert len(candidates.entries) == 1
    assert candidates.entries[0]["method"] == "POST"
    assert candidates.entries[0]["content_type"] == "application/json"
    assert list(candidates.entries[0]["body_field_names"]) == ["email", "password"]
