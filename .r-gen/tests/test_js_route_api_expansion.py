import sys
import time
from pathlib import Path

_SCANNER_DIR = Path(__file__).resolve().parents[1] / "scanner"
if str(_SCANNER_DIR) not in sys.path:
    sys.path.insert(0, str(_SCANNER_DIR))

from scanner_tools.discovery import (
    expand_frontend_route_api_candidates,
    extract_frontend_http_client_bases,
    extract_frontend_http_requests,
    extract_frontend_route_fragments,
    _js_object_keys,
)


# crAPI-specific service mounts that must NOT be fabricated from a route noun. Prepending
# these product-specific prefixes only produces valid routes on crAPI and inflates its
# benchmark without generalizing (universal-engine rule: ship techniques, not app facts).
_FABRICATED_SERVICE_MOUNTS = {
    "/identity/api/v2/user/dashboard",
    "/identity/api/v2/vehicle/vehicles",
    "/community/api/v2/community/posts",
    "/workshop/api/shop/orders",
    "/community/api/v2/coupon/validate-coupon",
    "/community/api/v2/coupon",
    "/workshop/api/mechanic/service_requests",
    "/workshop/api/past-orders",
}


def test_preserves_frontend_routes_without_fabricating_service_mounts():
    routes = [
        "/v2/user/dashboard",
        "/v2/vehicle/vehicles",
        "/shop/orders",
        "/api/v2/coupon/validate-coupon",
        "/coupon",
        "/mechanic/service_requests",
        "/past-orders",
    ]
    expanded = set(expand_frontend_route_api_candidates(routes))

    # Originals are preserved as candidates (probe what the bundle actually references).
    for route in routes:
        assert route in expanded, route
    # No hardcoded per-product service prefix is invented.
    assert expanded & _FABRICATED_SERVICE_MOUNTS == set()


def test_expands_discovered_api_bases_without_dropping_originals():
    # The ONLY service-prefix composition is via bases discovered in the same bundle.
    expanded = expand_frontend_route_api_candidates(
        ["/v2/users", "api/orders"],
        discovered_api_bases=["/tenant-a"],
    )

    assert "/v2/users" in expanded
    assert "/api/orders" in expanded
    assert "/tenant-a/v2/users" in expanded
    assert "/tenant-a/api/orders" in expanded


def test_extracts_only_generic_versioned_route_fragments():
    bundle = """
    const sg={
      GET_USER:"/v2/user/dashboard",
      GET_VEHICLES:"/v2/vehicle/vehicles",
      GET_ORDERS:"/shop/orders",
      VALIDATE_COUPON:"/api/v2/coupon/validate-coupon",
      COUPON:"/coupon",
      GET_SERVICE:"/mechanic/service_requests",
      GET_PAST:"/past-orders"
    };
    function run(){return og+sg.GET_USER+ig+sg.GET_ORDERS}
    """

    fragments = set(extract_frontend_route_fragments(bundle))
    expanded = set(expand_frontend_route_api_candidates(list(fragments)))

    # Generic versioned literals remain visible without product-noun filters.
    assert "/v2/user/dashboard" in fragments
    assert "/api/v2/coupon/validate-coupon" in fragments
    assert "/shop/orders" not in fragments
    assert "/coupon" not in fragments
    # But expansion never invents the crAPI service-mounted variants.
    assert expanded & _FABRICATED_SERVICE_MOUNTS == set()
    # Extracted versioned fragments remain probeable candidates.
    for fragment in fragments:
        assert fragment in expanded


def test_extracts_method_and_body_shape_from_static_frontend_http_calls():
    bundle = """
      const api = axios.create({baseURL: '/'});
      axios.post('/api/search', {query: term, filters: {category: selected}});
      api.patch(`/v1/orders/${orderId}`, {status: nextStatus, note});
      axios.get('/api/products', {params: {q: search, category: selected}});
      fetch('/api/profile', {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({displayName: name, preferences: prefs})
      });
    """

    requests = extract_frontend_http_requests(bundle)
    by_request = {(item["method"], item["url"]): item for item in requests}

    assert by_request[("POST", "/api/search")]["body_params"] == ["query", "filters"]
    assert by_request[("PATCH", "/v1/orders/{orderId}")]["body_params"] == ["status", "note"]
    assert by_request[("GET", "/api/products")]["params"] == ["q", "category"]
    assert by_request[("PUT", "/api/profile")]["body_params"] == ["displayName", "preferences"]


def test_ignores_verb_calls_on_objects_not_proven_to_be_http_clients():
    bundle = """
      queue.post('/topic/orders', {payload: value});
      cache.get('/internal/key');
      const api = axios.create({baseURL: '/api'});
      api.post('/orders', {productId: id});
    """

    requests = extract_frontend_http_requests(bundle)

    assert requests == [{
        "url": "/api/orders",
        "method": "POST",
        "source": "js_bundle_analysis",
        "body_params": ["productId"],
        "content_type": "application/json",
    }]


def test_js_object_key_extraction_is_bounded_and_linear():
    object_text = "{" + ",".join(f"key{index}:1" for index in range(8_000)) + "}"

    started = time.perf_counter()
    keys = _js_object_keys(object_text)
    elapsed = time.perf_counter() - started

    assert keys == [f"key{index}" for index in range(30)]
    assert elapsed < 1.0


def test_route_literals_do_not_gain_fabricated_http_methods():
    bundle = """
      const couponRoute = '/api/v2/coupon';
      const routes = ['/orders', '/search', '/reviews'];
    """

    assert extract_frontend_http_requests(bundle) == []


def test_binds_relative_calls_to_their_configured_http_client_base():
    bundle = """
      const identityApi = axios.create({baseURL: '/identity/api/v2'});
      let ordersApi = axios.create({timeout: 5000, baseURL: '/workshop/api'});
      identityApi.get('/vehicle/vehicles', {params: {page: currentPage}});
      ordersApi.post('/shop/orders', {productId: product.id, quantity: count});
      axios.post('/api/session', {token: sessionToken});
    """

    assert extract_frontend_http_client_bases(bundle) == {
        "identityApi": "/identity/api/v2",
        "ordersApi": "/workshop/api",
    }
    requests = extract_frontend_http_requests(bundle)
    by_request = {(item["method"], item["url"]): item for item in requests}

    assert by_request[("GET", "/identity/api/v2/vehicle/vehicles")]["params"] == ["page"]
    assert by_request[("POST", "/workshop/api/shop/orders")]["body_params"] == [
        "productId",
        "quantity",
    ]
    assert by_request[("POST", "/api/session")]["body_params"] == ["token"]


def test_extracts_config_style_frontend_requests():
    bundle = """
      const reportsApi = axios.create({baseURL: '/api/v3'});
      reportsApi.request({
        method: 'POST',
        url: '/reports/search',
        data: {query: text, filters: selectedFilters},
        params: {locale: currentLocale}
      });
      axios({method: 'PATCH', url: '/api/profile', data: {displayName: name}});
      unrelated({url: '/route-only', data: {value: x}});
    """

    requests = extract_frontend_http_requests(bundle)
    by_request = {(item["method"], item["url"]): item for item in requests}

    report_request = by_request[("POST", "/api/v3/reports/search")]
    assert report_request["body_params"] == ["query", "filters"]
    assert report_request["params"] == ["locale"]
    assert by_request[("PATCH", "/api/profile")]["body_params"] == ["displayName"]
    assert not any(item["url"] == "/route-only" for item in requests)
