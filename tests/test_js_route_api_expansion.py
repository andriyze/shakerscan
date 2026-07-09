import sys
from pathlib import Path

_SCANNER_DIR = Path(__file__).resolve().parents[1] / "scanner"
if str(_SCANNER_DIR) not in sys.path:
    sys.path.insert(0, str(_SCANNER_DIR))

from scanner_tools.discovery import expand_frontend_route_api_candidates, extract_frontend_route_fragments


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


def test_extracts_route_fragments_but_does_not_fabricate_service_mounts():
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

    # Extraction still recovers the real route fragments present in the bundle.
    assert "/v2/user/dashboard" in fragments
    assert "/shop/orders" in fragments
    assert "/coupon" in fragments
    # But expansion never invents the crAPI service-mounted variants.
    assert expanded & _FABRICATED_SERVICE_MOUNTS == set()
    # The extracted fragments themselves remain probeable candidates.
    for fragment in fragments:
        assert fragment in expanded
