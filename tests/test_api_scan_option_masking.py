import os
import sys
import types


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace())
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *args, **kwargs: None))

if "fastapi" not in sys.modules:
    fastapi_mod = types.ModuleType("fastapi")

    class _FakeFastAPI:
        def __init__(self, *args, **kwargs):
            pass

        def add_middleware(self, *args, **kwargs):
            return None

        def _decorator(self, *args, **kwargs):
            def wrapper(fn):
                return fn
            return wrapper

        get = post = patch = put = delete = on_event = _decorator

    class _FakeHTTPException(Exception):
        def __init__(self, status_code: int = 500, detail=None):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    def _fake_query(default=None, **kwargs):
        return default

    fastapi_mod.FastAPI = _FakeFastAPI
    fastapi_mod.HTTPException = _FakeHTTPException
    fastapi_mod.Query = _fake_query
    sys.modules["fastapi"] = fastapi_mod

    middleware_mod = types.ModuleType("fastapi.middleware")
    cors_mod = types.ModuleType("fastapi.middleware.cors")

    class _FakeCORSMiddleware:
        pass

    cors_mod.CORSMiddleware = _FakeCORSMiddleware
    sys.modules["fastapi.middleware"] = middleware_mod
    sys.modules["fastapi.middleware.cors"] = cors_mod

    responses_mod = types.ModuleType("fastapi.responses")

    class _FakeResponse:
        def __init__(self, content=None, status_code=200, headers=None):
            self.content = content
            self.status_code = status_code
            self.headers = headers or {}

    responses_mod.Response = _FakeResponse
    sys.modules["fastapi.responses"] = responses_mod

import api as api_module  # noqa: E402


def test_sanitize_scan_options_masks_sensitive_keys():
    options = {
        "scan_type": "smart",
        "auth_header": "Bearer token1",
        "auth_cookies": "session=abc",
        "user2_header": "Bearer token2",
        "user2_cookies": "session=def",
        "auth_headers_json": "{\"X-API-Key\":\"secret\"}",
        "auth_scenario_json": "{\"steps\":[]}",
        "login_password": "password123",
        "ai_api_key": "sk-test",
        "non_sensitive": "keep-me",
    }

    sanitized = api_module._sanitize_scan_options(options)

    assert sanitized["scan_type"] == "smart"
    assert sanitized["non_sensitive"] == "keep-me"
    assert sanitized["auth_header"] == "***"
    assert sanitized["auth_cookies"] == "***"
    assert sanitized["user2_header"] == "***"
    assert sanitized["user2_cookies"] == "***"
    assert sanitized["auth_headers_json"] == "***"
    assert sanitized["auth_scenario_json"] == "***"
    assert sanitized["login_password"] == "***"
    assert sanitized["ai_api_key"] == "***"


def test_sanitize_scan_options_decodes_json_string():
    raw = "{\"scan_type\":\"smart\",\"auth_header\":\"Bearer token\"}"
    sanitized = api_module._sanitize_scan_options(raw)
    assert sanitized["scan_type"] == "smart"
    assert sanitized["auth_header"] == "***"
