import sys
from pathlib import Path

_SCANNER_DIR = Path(__file__).resolve().parents[1] / "scanner"
if str(_SCANNER_DIR) not in sys.path:
    sys.path.insert(0, str(_SCANNER_DIR))

from scanner_tools.discovery import expand_frontend_route_api_candidates


def test_expands_crapi_style_frontend_routes_to_service_api_candidates():
    expanded = set(
        expand_frontend_route_api_candidates(
            [
                "/v2/user/dashboard",
                "/v2/vehicle/vehicles",
                "/v2/community/posts",
                "/shop/orders",
                "/mechanic/service_requests",
            ]
        )
    )

    assert "/identity/api/v2/user/dashboard" in expanded
    assert "/identity/api/v2/vehicle/vehicles" in expanded
    assert "/community/api/v2/community/posts" in expanded
    assert "/workshop/api/shop/orders" in expanded
    assert "/workshop/api/mechanic/service_requests" in expanded


def test_expands_discovered_api_bases_without_dropping_originals():
    expanded = expand_frontend_route_api_candidates(
        ["/v2/users", "api/orders"],
        discovered_api_bases=["/tenant-a"],
    )

    assert "/v2/users" in expanded
    assert "/api/orders" in expanded
    assert "/tenant-a/v2/users" in expanded
    assert "/tenant-a/api/orders" in expanded
