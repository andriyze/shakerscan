from scanner.scanner_tools.hash_routes import build_hash_route_active_endpoints


def test_hash_route_active_builder_uses_spa_hints_and_common_search_route():
    endpoints = build_hash_route_active_endpoints(
        "http://host.docker.internal:3001",
        [
            "#/login",
            "/#/score-board",
            "Acknowledgements: /#/score-board\nHiring: /#/jobs",
            "http://host.docker.internal:3001/#/search?q=apple",
            "https://external.example/#/search?q=skip",
        ],
    )

    urls = [endpoint["url"] for endpoint in endpoints]

    assert "http://host.docker.internal:3001/#/search?q=apple" in urls
    assert "http://host.docker.internal:3001/#/search?q=test" in urls
    assert not any("external.example" in url for url in urls)
    assert all(endpoint["source"] == "hash_route" for endpoint in endpoints)
    assert all(endpoint["method"] == "GET" for endpoint in endpoints)
    assert all(endpoint["params"] for endpoint in endpoints)


def test_hash_route_active_builder_stays_empty_without_hash_route_hint():
    endpoints = build_hash_route_active_endpoints(
        "https://example.test",
        ["https://example.test/search?q=test", "/login", "plain text"],
    )

    assert endpoints == []
