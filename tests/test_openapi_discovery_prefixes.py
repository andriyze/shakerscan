"""Tests for service-prefix-aware OpenAPI/Swagger discovery.

crAPI-style microservice apps mount their spec under a service prefix
(``/identity/v3/api-docs``) and split the API across several per-service specs.
A root-only, first-hit probe misses them, so authenticated API routes are never
enumerated and the detectors never run on them. These tests pin the prefix probe
and cross-spec aggregation.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

import scanner_tools.discovery as discovery  # noqa: E402


def test_api_path_prefixes_extracts_service_mounts():
    prefixes = discovery._api_path_prefixes(
        [
            "GET /workshop/api/shop/orders",
            "POST /community/api/v2/coupon/validate-coupon",
            "GET /identity/api/v2/vehicle/vehicles",
            "/workshop/api/other",  # duplicate service -> counted once
            "GET /static/app.js",  # non-service asset -> skipped
            "http://host:8888/identity/x",  # full URL accepted, dedup
        ]
    )
    assert prefixes == ["/workshop", "/community", "/identity"]


def test_discover_openapi_probes_service_prefixes_and_aggregates(monkeypatch):
    # No root spec exists; each service exposes its own spec (crAPI shape).
    specs = {
        "http://t/identity/v3/api-docs": {
            "url": "http://t/identity/v3/api-docs",
            "version": "3.0",
            "endpoints": [{"method": "GET", "path": "/identity/api/v2/vehicle/{id}/location"}],
            "endpoint_count": 1,
            "auth_schemes": ["bearer"],
        },
        "http://t/workshop/v3/api-docs": {
            "url": "http://t/workshop/v3/api-docs",
            "version": "3.0",
            "endpoints": [{"method": "GET", "path": "/workshop/api/shop/orders/{id}"}],
            "endpoint_count": 1,
            "auth_schemes": ["bearer"],
        },
    }
    calls: list[str] = []

    async def fake_fetch(url, auth_session=None):
        calls.append(url)
        return specs.get(url)

    monkeypatch.setattr(discovery, "fetch_openapi_schema", fake_fetch)

    result = asyncio.run(
        discovery.discover_openapi_schema(
            "http://t/",
            auth_session=None,
            # raw endpoint strings -> prefixes derived internally
            extra_prefixes=[
                "GET /identity/api/v2/vehicle/vehicles",
                "GET /workshop/api/shop/orders",
            ],
        )
    )

    assert result is not None
    paths = {e["path"] for e in result["endpoints"]}
    # Endpoints aggregated across BOTH service specs (root-only finds neither).
    assert "/identity/api/v2/vehicle/{id}/location" in paths
    assert "/workshop/api/shop/orders/{id}" in paths
    assert set(result["schema_urls"]) == set(specs.keys())
    # It actually probed the service-prefixed spec paths.
    assert "http://t/identity/v3/api-docs" in calls
    assert "http://t/workshop/v3/api-docs" in calls


def test_discover_openapi_returns_none_when_no_spec(monkeypatch):
    async def fake_fetch(url, auth_session=None):
        return None

    monkeypatch.setattr(discovery, "fetch_openapi_schema", fake_fetch)
    result = asyncio.run(
        discovery.discover_openapi_schema("http://t/", extra_prefixes=["/identity"])
    )
    assert result is None
