from scanner.scanner_tools.active_prioritization import (
    active_endpoint_score,
    prioritize_active_endpoints,
)


def test_prioritization_prefers_classic_vuln_routes_over_catalog_options():
    endpoints = [
        {
            "url": "https://honey.test/api/ai-redteam/oauth.token",
            "method": "POST",
            "body_params": ["email", "username", "password", "token"],
            "source": "options",
        },
        {
            "url": "https://honey.test/api/ai-redteam/OAuth/scope/consent/schema",
            "method": "PUT",
            "body_params": ["email", "username", "password", "token"],
            "source": "options",
        },
        {
            "url": "https://honey.test/api/sqli_auth_bypass",
            "method": "POST",
            "body_params": ["email", "username", "password"],
            "source": "openapi",
        },
        {
            "url": "https://honey.test/search",
            "method": "GET",
            "params": ["q"],
            "source": "openapi",
        },
        {
            "url": "https://honey.test/api/upload",
            "method": "POST",
            "body_params": ["file", "name"],
            "source": "openapi",
        },
        {
            "url": "https://honey.test/api/auth/login",
            "method": "POST",
            "body_params": ["email", "password"],
            "source": "common",
        },
    ]

    selected = prioritize_active_endpoints(endpoints, budget=3)
    selected_urls = [endpoint["url"] for endpoint in selected]

    assert "https://honey.test/api/sqli_auth_bypass" in selected_urls
    assert "https://honey.test/search" in selected_urls
    assert "https://honey.test/api/upload" in selected_urls
    assert not any("/api/ai-redteam/" in url for url in selected_urls)


def test_options_routes_still_sort_when_no_better_candidates_exist():
    endpoints = [
        {
            "url": "https://example.test/api/docs",
            "method": "POST",
            "body_params": ["id"],
            "source": "options",
        },
        {
            "url": "https://example.test/api/users",
            "method": "POST",
            "body_params": ["id", "email"],
            "source": "options",
        },
    ]

    selected = prioritize_active_endpoints(endpoints, budget=1)

    assert selected[0]["url"] == "https://example.test/api/users"
    assert active_endpoint_score(selected[0]) > active_endpoint_score(endpoints[0])


def test_hash_routes_survive_tight_active_budget_for_dom_xss():
    endpoints = [
        {
            "url": "https://example.test/api/ai-redteam/scenarios",
            "method": "GET",
            "params": ["id"],
            "source": "options",
        },
        {
            "url": "https://example.test/api/docs",
            "method": "GET",
            "params": ["id"],
            "source": "options",
        },
        {
            "url": "https://example.test/#/search?q=test",
            "method": "GET",
            "params": ["q"],
            "source": "hash_route",
        },
    ]

    selected = prioritize_active_endpoints(endpoints, budget=1)

    assert selected[0]["source"] == "hash_route"
    assert selected[0]["url"] == "https://example.test/#/search?q=test"
