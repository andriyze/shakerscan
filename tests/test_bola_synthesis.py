"""Test BOLA collection URL synthesis."""
from scanner.scanner_tools.access_control_checks import (
    synthesize_resource_urls_from_collections,
    synthesize_query_urls_from_param_endpoints,
)


def test_synthesize_from_collection():
    urls = ['http://localhost:3000/api/BasketItems/']
    result = synthesize_resource_urls_from_collections(urls)
    assert 'http://localhost:3000/api/BasketItems/1' in result
    assert len(result) == 5


def test_skip_urls_with_existing_ids():
    urls = ['http://localhost:3000/api/BasketItems/5']
    result = synthesize_resource_urls_from_collections(urls)
    assert len(result) == 0


def test_skip_excluded_paths():
    urls = ['http://localhost:3000/api/docs']
    result = synthesize_resource_urls_from_collections(urls)
    assert len(result) == 0


def test_synthesize_query_from_params():
    param_endpoints = [{
        "url": "http://localhost:3000/api/v3/mechanic/mechanic_report",
        "params": ["id"],
    }]
    result = synthesize_query_urls_from_param_endpoints(
        base_url="http://localhost:3000",
        param_endpoints=param_endpoints,
        max_endpoints=1,
    )
    assert "http://localhost:3000/api/v3/mechanic/mechanic_report?id=1" in result


def test_skip_non_id_params():
    param_endpoints = [{
        "url": "http://localhost:3000/api/v3/search",
        "params": ["q"],
    }]
    result = synthesize_query_urls_from_param_endpoints(
        base_url="http://localhost:3000",
        param_endpoints=param_endpoints,
        max_endpoints=1,
    )
    assert result == []
