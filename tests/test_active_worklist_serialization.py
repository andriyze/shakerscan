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
