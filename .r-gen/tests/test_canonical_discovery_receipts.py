import asyncio

from scanner.scanner_tools import discovery


def test_canonical_discovery_assembles_receipts_without_network(monkeypatch):
    async def fail_network(*args, **kwargs):
        raise AssertionError("canonical discovery assembly must not use the network")

    monkeypatch.setattr(discovery, "detect_spa_catch_all", fail_network)
    monkeypatch.setattr(discovery, "run", fail_network)

    result = asyncio.run(discovery.enhanced_url_discovery(
        "https://example.test/",
        budget={
            "canonical_receipts_only": True,
            "max_urls": 10,
            "canonical_katana_observations": [
                {
                    "method": "GET",
                    "url": "https://example.test/api/orders?id=1",
                },
                {
                    "method": "POST",
                    "url": "https://example.test/api/orders",
                },
                {
                    "method": "GET",
                    "url": "https://outside.test/ignored",
                },
            ],
            "canonical_ffuf_observations": [
                {"url": "https://example.test/admin"},
            ],
        },
    ))

    assert result["canonical_receipts_only"] is True
    assert result["all_urls"] == [
        "https://example.test/api/orders?id=1",
        "https://example.test/api/orders",
        "https://example.test/",
        "https://example.test/admin",
    ]
    assert result["api_endpoints"] == [
        "https://example.test/api/orders?id=1",
        "https://example.test/api/orders",
    ]
    assert result["discovered_params"] == {
        "https://example.test/api/orders?id=1": ["id"],
    }
    assert "https://outside.test/ignored" not in result["all_urls"]
    assert result["endpoint_manifest"]["status"] == "complete"
