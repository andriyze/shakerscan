import sys
from pathlib import Path

_SCANNER_DIR = Path(__file__).resolve().parents[1] / "scanner"
if str(_SCANNER_DIR) not in sys.path:
    sys.path.insert(0, str(_SCANNER_DIR))

from scanner_tools.discovery import expand_frontend_route_api_candidates, extract_frontend_route_fragments


def test_expands_crapi_style_frontend_routes_to_service_api_candidates():
    expanded = set(
        expand_frontend_route_api_candidates(
            [
                "/v2/user/dashboard",
                "/v2/vehicle/vehicles",
                "/v2/community/posts",
                "/shop/orders",
                "/api/shop/orders/all",
                "/api/shop/orders/<orderId>",
                "/mechanic/service_requests",
                "/orders",
                "/past-orders",
            ]
        )
    )

    assert "/identity/api/v2/user/dashboard" in expanded
    assert "/identity/api/v2/vehicle/vehicles" in expanded
    assert "/community/api/v2/community/posts" in expanded
    assert "/workshop/api/shop/orders" in expanded
    assert "/workshop/api/shop/orders/all" in expanded
    assert "/workshop/api/shop/orders/<orderId>" in expanded
    assert "/workshop/api/mechanic/service_requests" in expanded
    assert "/workshop/api/orders" in expanded
    assert "/workshop/api/past-orders" in expanded


def test_expands_discovered_api_bases_without_dropping_originals():
    expanded = expand_frontend_route_api_candidates(
        ["/v2/users", "api/orders"],
        discovered_api_bases=["/tenant-a"],
    )

    assert "/v2/users" in expanded
    assert "/api/orders" in expanded
    assert "/tenant-a/v2/users" in expanded
    assert "/tenant-a/api/orders" in expanded


def test_extracts_minified_crapi_style_route_fragments():
    bundle = """
    const sg={
      GET_USER:"/v2/user/dashboard",
      GET_VEHICLES:"/v2/vehicle/vehicles",
      GET_POSTS:"/v2/community/posts/<postId>",
      GET_ORDERS:"/shop/orders",
      GET_ORDERS_REAL:"api/shop/orders/all",
      GET_ORDER_BY_ID:"api/shop/orders/<orderId>",
      GET_SERVICE:"/mechanic/service_requests",
      GET_PAST:"/past-orders"
    };
    function run(){return og+sg.GET_USER+ig+sg.GET_ORDERS}
    """

    fragments = set(extract_frontend_route_fragments(bundle))
    expanded = set(expand_frontend_route_api_candidates(list(fragments)))

    assert "/v2/user/dashboard" in fragments
    assert "/v2/vehicle/vehicles" in fragments
    assert "/v2/community/posts/<postId>" in fragments
    assert "/shop/orders" in fragments
    assert "/mechanic/service_requests" in fragments
    assert "/past-orders" in fragments
    assert "/identity/api/v2/user/dashboard" in expanded
    assert "/identity/api/v2/vehicle/vehicles" in expanded
    assert "/community/api/v2/community/posts/<postId>" in expanded
    assert "/workshop/api/shop/orders" in expanded
    assert "/workshop/api/shop/orders/all" in expanded
    assert "/workshop/api/shop/orders/<orderId>" in expanded
    assert "/workshop/api/mechanic/service_requests" in expanded
    assert "/workshop/api/past-orders" in expanded
