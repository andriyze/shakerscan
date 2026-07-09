import json
import os
import sys
import importlib.util


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

_SCANNER_FILE = os.path.join(os.path.dirname(__file__), "..", "scanner", "scanner.py")
_SPEC = importlib.util.spec_from_file_location("scanner_entrypoint", _SCANNER_FILE)
scanner_module = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(scanner_module)


def test_active_worklist_preserves_json_body_shape():
    worklist = scanner_module._serialize_active_worklist([
        {
            "method": "POST",
            "url": "/api/orders",
            "body_params": ["user.id", "qty"],
            "body_template": {"user": {"id": 1}, "qty": 2},
            "content_type": "application/json",
        }
    ])

    assert worklist == ['POST /api/orders json:{"user":{"id":1},"qty":2}']


def test_active_worklist_uses_safe_json_seeds_for_login_fields():
    worklist = scanner_module._serialize_active_worklist([
        {
            "method": "POST",
            "url": "/rest/user/login",
            "body_params": ["email", "username", "password"],
            "content_type": "application/json",
        }
    ])

    assert worklist == [
        'POST /rest/user/login json:{"email":"test@example.com","username":"testuser","password":"TestPass123!"}'
    ]


def test_active_worklist_preserves_form_body_shape():
    worklist = scanner_module._serialize_active_worklist([
        {
            "method": "POST",
            "url": "/login",
            "body_params": ["email", "password"],
            "content_type": "application/x-www-form-urlencoded",
        }
    ])

    assert worklist == ["POST /login form:email=1&password=1"]


def test_synthetic_body_reconstructs_array_of_objects():
    # _flatten_json_keys emits a list-of-objects as the list key + element keys,
    # e.g. {"orders": [{"id": 1}]} -> ["orders", "orders.id"]. Rebuild as a list.
    template = scanner_module._synthetic_json_template_from_params(
        ["orders", "orders.id", "orders.name", "user.email"]
    )
    assert isinstance(template["orders"], list)
    assert template["orders"] and isinstance(template["orders"][0], dict)
    assert set(template["orders"][0].keys()) == {"id", "name"}
    assert template["orders"][0]["id"] == 1            # id -> numeric seed
    assert isinstance(template["user"], dict)          # pure nested dict stays a dict
    assert template["user"]["email"] == "test@example.com"


def test_active_worklist_reconstructs_array_body_from_params():
    worklist = scanner_module._serialize_active_worklist([
        {
            "method": "POST",
            "url": "/api/basket/checkout",
            "body_params": ["items", "items.id", "items.qty"],
            "content_type": "application/json",
        }
    ])
    assert len(worklist) == 1
    entry = worklist[0]
    assert entry.startswith("POST /api/basket/checkout json:")
    payload = json.loads(entry.split("json:", 1)[1])
    assert isinstance(payload["items"], list)
    assert payload["items"][0]["id"] == 1
    assert "qty" in payload["items"][0]


def test_lookup_routes_are_preserved_for_path_value_active_testing():
    endpoints = scanner_module._path_value_lookup_active_endpoints(
        "http://shop.test",
        [
            "http://shop.test/rest/track-order",
            "http://shop.test/rest/track-order?id=1",
            "http://shop.test/rest/products/reviews",
            "http://shop.test/assets/app.js",
            "http://evil.test/rest/track-order",
            "/api/orders/status",
        ],
    )

    assert endpoints == [
        {
            "url": "http://shop.test/rest/track-order",
            "method": "GET",
            "params": [],
            "source": "discovered_lookup",
        },
        {
            "url": "http://shop.test/api/orders/status",
            "method": "GET",
            "params": [],
            "source": "discovered_lookup",
        },
    ]


def test_frontend_http_requests_become_same_origin_active_endpoints():
    endpoints = scanner_module._frontend_http_active_endpoints(
        "https://app.example.test",
        {
            "request_endpoints": [
                {
                    "url": "/api/search",
                    "method": "POST",
                    "body_params": ["query", "filters"],
                    "body_required_params": ["query"],
                    "content_type": "application/json",
                },
                {"url": "/api/products?q=seed", "method": "GET", "params": ["q"]},
                {"url": "https://other.example.test/api/admin", "method": "GET"},
            ]
        },
    )

    assert endpoints == [
        {
            "url": "https://app.example.test/api/search",
            "method": "POST",
            "source": "js_bundle_analysis",
            "body_params": ["query", "filters"],
            "body_required_params": ["query"],
            "content_type": "application/json",
        },
        {
            "url": "https://app.example.test/api/products?q=seed",
            "method": "GET",
            "source": "js_bundle_analysis",
            "params": ["q"],
        },
    ]
