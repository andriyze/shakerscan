import os
import sys


_SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))
if _SCANNER_DIR not in sys.path:
    sys.path.insert(0, _SCANNER_DIR)

from scanner_tools.resource_propagation import (  # noqa: E402
    enrich_endpoints_with_resource_ids,
)


def _urls_by_source(endpoints, source):
    return [e["url"] for e in endpoints if e.get("source") == source]


def test_real_uuid_is_propagated_to_placeholder_subresource_route():
    uuid = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
    endpoints = [
        {"url": f"/identity/api/v2/vehicle/{uuid}", "method": "GET", "source": "har"},
        {"url": "/identity/api/v2/vehicle/1/location", "method": "GET", "source": "openapi"},
    ]
    out = enrich_endpoints_with_resource_ids(endpoints)
    propagated = _urls_by_source(out, "resource_id_propagation")
    # the vehicle's real id reaches the location sub-resource of the placeholder route
    assert f"/identity/api/v2/vehicle/{uuid}/location" in propagated


def test_real_numeric_id_is_propagated_to_write_method():
    endpoints = [
        {"url": "/api/orders/1337", "method": "GET", "source": "har"},
        {"url": "/api/orders/1", "method": "PUT", "source": "openapi", "body_params": ["status"]},
    ]
    out = enrich_endpoints_with_resource_ids(endpoints)
    put_variants = [e for e in out if e.get("source") == "resource_id_propagation" and e["method"] == "PUT"]
    assert any(e["url"] == "/api/orders/1337" for e in put_variants)
    # body shape is preserved on the propagated write route
    assert all(e.get("body_params") == ["status"] for e in put_variants)


def test_placeholder_one_is_never_propagated_outward():
    # only the bare "1" placeholder is observed -> nothing to propagate
    endpoints = [
        {"url": "/api/orders/1", "method": "GET", "source": "openapi"},
        {"url": "/api/orders/1", "method": "DELETE", "source": "openapi"},
    ]
    out = enrich_endpoints_with_resource_ids(endpoints)
    assert _urls_by_source(out, "resource_id_propagation") == []


def test_existing_routes_are_not_duplicated():
    endpoints = [
        {"url": "/api/orders/42", "method": "GET", "source": "har"},
        {"url": "/api/orders/99", "method": "GET", "source": "har"},
    ]
    out = enrich_endpoints_with_resource_ids(endpoints)
    urls = [(e["method"], e["url"]) for e in out]
    # GET /api/orders/42 and /99 already exist; no duplicate GET variants added
    assert urls.count(("GET", "/api/orders/42")) == 1
    assert urls.count(("GET", "/api/orders/99")) == 1


def test_routes_without_id_segments_are_untouched():
    endpoints = [
        {"url": "/api/products/search", "method": "GET", "params": ["q"], "source": "har"},
        {"url": "/rest/user/login", "method": "POST", "body_params": ["email"], "source": "openapi"},
    ]
    out = enrich_endpoints_with_resource_ids(endpoints)
    assert len(out) == len(endpoints)
    assert _urls_by_source(out, "resource_id_propagation") == []


def test_propagation_respects_per_resource_and_total_caps():
    endpoints = [
        {"url": f"/api/orders/{1000 + i}", "method": "GET", "source": "har"}
        for i in range(6)
    ] + [{"url": "/api/orders/1/refund", "method": "POST", "source": "openapi"}]
    out = enrich_endpoints_with_resource_ids(endpoints, max_extra_per_resource=2)
    refund_variants = [
        e for e in out
        if e.get("source") == "resource_id_propagation" and e["url"].endswith("/refund")
    ]
    # the refund route gets at most max_extra_per_resource real ids
    assert len(refund_variants) == 2


def test_query_string_is_preserved_on_propagated_routes():
    endpoints = [
        {"url": "/api/orders/55", "method": "GET", "source": "har"},
        {"url": "/api/orders/1/items?expand=true", "method": "GET", "source": "openapi"},
    ]
    out = enrich_endpoints_with_resource_ids(endpoints)
    propagated = _urls_by_source(out, "resource_id_propagation")
    assert "/api/orders/55/items?expand=true" in propagated
