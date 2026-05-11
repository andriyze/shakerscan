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


def test_ai_demo_target_detection_handles_new_and_legacy_targets():
    assert api_module._is_ai_demo_target_row({
        "name": "Honey demo mcp.unsafe.oauth_audience_wildcard.v1",
        "endpoint_url": "https://honey.example/api/v1/mcp/trace",
        "metadata_json": {"shakerscan_demo": True},
    })
    assert api_module._is_ai_demo_target_row({
        "name": "Local Honey calibration mcp.safe.oauth_audience_pkce_rejection.v1 local-honey-1",
        "endpoint_url": "http://host.docker.internal:18080/api/v1/mcp/trace?calibration_run=local-honey-1",
        "metadata_json": {},
    })
    assert api_module._is_ai_demo_target_row({
        "name": "Local MCP OAuth calibration",
        "endpoint_url": "http://host.docker.internal:18080/mcp/oauth/token",
        "metadata_json": {},
    })
    assert not api_module._is_ai_demo_target_row({
        "name": "Support bot staging",
        "endpoint_url": "https://example.com/api/chat",
        "metadata_json": {},
    })


def test_demo_target_url_rewrites_base_and_adds_calibration_query():
    rewritten = api_module._demo_target_url(
        "https://honey.shakerscan.com/api/v1/mcp/trace?existing=1",
        "http://host.docker.internal:18080/",
        "demo-123",
        "mcp.unsafe.oauth_audience_wildcard.v1",
    )

    assert rewritten.startswith("http://host.docker.internal:18080/api/v1/mcp/trace?")
    assert "existing=1" in rewritten
    assert "calibration_run=demo-123" in rewritten
    assert "calibration_scenario=mcp.unsafe.oauth_audience_wildcard.v1" in rewritten


def test_demo_request_template_preserves_mcp_shape_and_injects_prompt():
    template = {"jsonrpc": "2.0", "id": "fixed", "method": "tools/list", "params": {"scenario_id": "x"}}
    rewritten = api_module._demo_request_template_with_prompt(template, "mcp")

    assert rewritten["id"] == "fixed"
    assert rewritten["params"]["scenario_id"] == "x"
    assert rewritten["params"]["prompt"] == "{{prompt}}"
    assert "prompt" not in template["params"]


def test_sanitize_ai_settings_includes_demo_fields():
    settings = api_module._sanitize_ai_settings_response({
        "demo_mode_enabled": True,
        "demo_honey_public_url": "https://honey.example",
        "demo_honey_scanner_url": "http://host.docker.internal:18080",
    })

    assert settings["demo_mode_enabled"] is True
    assert settings["demo_honey_public_url"] == "https://honey.example"
    assert settings["demo_honey_scanner_url"] == "http://host.docker.internal:18080"


def test_sanitize_ai_settings_leaves_demo_urls_empty_by_default():
    settings = api_module._sanitize_ai_settings_response({})

    assert settings["demo_mode_enabled"] is False
    assert settings["demo_honey_public_url"] == ""
    assert settings["demo_honey_scanner_url"] == ""
    assert api_module._normalize_demo_base_url("") == ""
