import os
import sys


_SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))
if _SCANNER_DIR not in sys.path:
    sys.path.insert(0, _SCANNER_DIR)

from scanner_tools.active_prioritization import (  # noqa: E402
    _path_has_object_id_segment,
    active_endpoint_score,
    prioritize_active_endpoints,
    should_generate_synthetic_active_candidates,
    synthetic_active_candidate_cap,
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


def test_synthetic_candidate_generation_requires_signal_and_is_capped():
    assert should_generate_synthetic_active_candidates(
        api_hint=False,
        observed_candidate_count=0,
        max_active=50,
    ) is False
    assert should_generate_synthetic_active_candidates(
        api_hint=True,
        observed_candidate_count=50,
        max_active=50,
    ) is False
    assert should_generate_synthetic_active_candidates(
        api_hint=True,
        observed_candidate_count=10,
        max_active=50,
    ) is True

    assert synthetic_active_candidate_cap(50) == 24
    assert synthetic_active_candidate_cap(12) == 6
    assert synthetic_active_candidate_cap(50, explicit=True) == 48


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


def test_one_slot_budget_keeps_top_endpoint_when_body_endpoint_exists():
    endpoints = [
        {
            "url": "https://example.test/#/search?q=test",
            "method": "GET",
            "params": ["q"],
            "source": "hash_route",
        },
        {
            "url": "https://example.test/rest/user/login",
            "method": "POST",
            "body_params": ["email", "password"],
            "source": "options",
        },
    ]

    selected = prioritize_active_endpoints(endpoints, budget=1)

    assert active_endpoint_score(endpoints[0]) > active_endpoint_score(endpoints[1])
    assert selected == [endpoints[0]]


def test_budget_reserves_slots_for_post_body_endpoints():
    # Many high-scoring observed GET routes + a real (synthetic-sourced) POST login
    # buried among POST phantoms. Pure top-by-score would select all GET; the
    # reservation must still pull the real request-body endpoint into the budget.
    endpoints = []
    for i in range(60):
        endpoints.append({
            "url": f"https://t.test/rest/item{i}?id=1", "method": "GET",
            "params": ["id"], "source": "har_discovery",
        })
    endpoints.append({
        "url": "https://t.test/rest/user/login", "method": "POST",
        "body_params": ["email", "password"], "source": "options",
    })
    for i in range(40):
        endpoints.append({
            "url": f"https://t.test/api/Thing{i}s/x", "method": "POST",
            "body_params": ["id", "limit", "offset", "page"], "source": "options",
        })

    selected = prioritize_active_endpoints(endpoints, budget=10)
    methods = [e["method"] for e in selected]
    # ~40% of the budget reserved for request-body endpoints, not 100% GET
    assert methods.count("POST") >= 4
    # the real login body endpoint is now selected for active testing
    assert any("/rest/user/login" in e["url"] for e in selected)


def test_budget_without_body_endpoints_is_unaffected():
    endpoints = [
        {"url": f"https://t.test/g{i}?id=1", "method": "GET", "params": ["id"], "source": "har_discovery"}
        for i in range(10)
    ]
    selected = prioritize_active_endpoints(endpoints, budget=3)
    assert len(selected) == 3
    assert all(e["method"] == "GET" for e in selected)


def test_param_maps_are_scored_like_param_lists():
    endpoints = [
        {
            "url": "https://example.test/rest/products/search",
            "method": "GET",
            "params": {"q": "apple", "limit": 10},
            "source": "openapi",
        },
        {
            "url": "https://example.test/rest/products",
            "method": "GET",
            "params": ["page"],
            "source": "openapi",
        },
    ]

    selected = prioritize_active_endpoints(endpoints, budget=1)

    assert selected[0]["url"] == "https://example.test/rest/products/search"


def test_static_discovery_paths_do_not_crowd_out_app_routes():
    endpoints = [
        {
            "url": "https://example.test/.well-known/security.txt/auth/login",
            "method": "POST",
            "body_params": ["email", "password", "token"],
            "source": "options",
        },
        {
            "url": "https://example.test/rest/user/login",
            "method": "POST",
            "body_params": ["email", "password"],
            "source": "options",
        },
        {
            "url": "https://example.test/socket.io/?token=abc",
            "method": "GET",
            "params": ["token"],
            "source": "har_discovery",
        },
        {
            "url": "https://example.test/rest/products/search?q=test",
            "method": "GET",
            "params": ["q"],
            "source": "har_discovery",
        },
    ]

    selected = prioritize_active_endpoints(endpoints, budget=2)
    selected_urls = [endpoint["url"] for endpoint in selected]

    assert "https://example.test/rest/user/login" in selected_urls
    assert "https://example.test/rest/products/search?q=test" in selected_urls
    assert "https://example.test/.well-known/security.txt/auth/login" not in selected_urls
    assert "https://example.test/socket.io/?token=abc" not in selected_urls


def test_object_id_segment_detection():
    assert _path_has_object_id_segment("/api/orders/42")
    assert _path_has_object_id_segment("/identity/api/v2/vehicle/{vehicleId}/location")
    assert _path_has_object_id_segment("/users/:id")
    assert _path_has_object_id_segment("/docs/507f1f77bcf86cd799439011")  # mongo ObjectId
    assert _path_has_object_id_segment("/x/123e4567-e89b-12d3-a456-426614174000")  # uuid
    # plain word/listing/version segments must NOT look like object ids
    assert not _path_has_object_id_segment("/api/orders/all")
    assert not _path_has_object_id_segment("/rest/products/search")
    assert not _path_has_object_id_segment("/api/v2/users")
    assert not _path_has_object_id_segment("/")


def test_object_id_consumer_routes_win_budget_over_generic_routes():
    endpoints = [
        {"url": "https://t.test/api/status", "method": "GET", "source": "har_discovery"},
        {"url": "https://t.test/identity/api/v2/vehicle/{vehicleId}/location",
         "method": "GET", "source": "har_discovery"},
        {"url": "https://t.test/api/orders/42", "method": "GET", "source": "har_discovery"},
    ]
    selected_urls = [e["url"] for e in prioritize_active_endpoints(endpoints, budget=2)]
    assert "https://t.test/identity/api/v2/vehicle/{vehicleId}/location" in selected_urls
    assert "https://t.test/api/orders/42" in selected_urls
    assert "https://t.test/api/status" not in selected_urls


def test_state_changing_method_on_object_route_scores_higher():
    read_obj = {"url": "https://t.test/api/orders/42", "method": "GET", "source": "openapi"}
    delete_obj = {"url": "https://t.test/api/orders/42", "method": "DELETE", "source": "openapi"}
    # a DELETE on an object route (BOLA-write) must outrank reading the same object
    assert active_endpoint_score(delete_obj) > active_endpoint_score(read_obj)
    # and an object route must outrank the same route without an id segment
    no_id = {"url": "https://t.test/api/orders", "method": "GET", "source": "openapi"}
    assert active_endpoint_score(read_obj) > active_endpoint_score(no_id)


def test_family_route_boost_raises_family_relevant_routes():
    login = {"url": "https://t/x/login", "method": "POST", "body_params": ["password"], "source": "options"}
    review = {"url": "https://t/x/review", "method": "POST", "body_params": ["comment"], "source": "options"}
    # SQLi lane boosts login (token + injectable body); XSS lane boosts review (sink + reflected param)
    assert active_endpoint_score(login, family="sqli") > active_endpoint_score(login)
    assert active_endpoint_score(review, family="xss") > active_endpoint_score(review)
    # cross-family: login is not an XSS sink and password isn't reflected -> no XSS boost
    assert active_endpoint_score(login, family="xss") == active_endpoint_score(login)
    # family=None / "all" leaves the score unchanged (back-compat)
    assert active_endpoint_score(review, family=None) == active_endpoint_score(review, family="all")


def test_sqli_family_boosts_benchmark_workflow_body_routes():
    coupon = {
        "url": "https://t/community/api/v2/coupon",
        "method": "POST",
        "body_params": ["coupon_code", "code"],
        "source": "options",
    }
    review = {
        "url": "https://t/rest/products/reviews",
        "method": "PATCH",
        "body_params": ["message", "rating"],
        "source": "options",
    }

    assert active_endpoint_score(coupon, family="sqli") > active_endpoint_score(coupon)
    assert active_endpoint_score(review, family="sqli") > active_endpoint_score(review)


def test_family_ordering_prefers_family_routes_under_budget():
    search = {"url": "https://t/api/items/filter", "method": "GET", "params": ["sort"], "source": "options"}
    comment = {"url": "https://t/api/items/comment", "method": "POST", "body_params": ["text"], "source": "options"}
    sqli_first = prioritize_active_endpoints([comment, search], budget=1, family="sqli")[0]["url"]
    xss_first = prioritize_active_endpoints([search, comment], budget=1, family="xss")[0]["url"]
    assert sqli_first.endswith("/filter")    # SQLi favors filter/sort
    assert xss_first.endswith("/comment")    # XSS favors comment/text
