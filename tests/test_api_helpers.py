"""Unit tests for small helpers in api/api.py.

These cover the env-var coercer, the pagination → COUNT(*) rewriter, and the
JSON-decode helper that have grown enough surface to be worth pinning.
"""

import os
import sys
import types


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
# api/api.py imports asyncpg/redis/fastapi at module load; stub the ones
# missing in the test environment. Stubs mirror tests/test_api_scan_option_masking.py.
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

sys.path.pop(0)


# ----- _int_env -----------------------------------------------------------

def test_int_env_returns_default_when_unset(monkeypatch):
    monkeypatch.delenv("X_NOT_SET", raising=False)
    assert api_module._int_env("X_NOT_SET", 42) == 42


def test_int_env_returns_default_on_blank(monkeypatch):
    monkeypatch.setenv("X_BLANK", "")
    assert api_module._int_env("X_BLANK", 42) == 42


def test_int_env_returns_default_on_garbage(monkeypatch):
    monkeypatch.setenv("X_GARBAGE", "not-an-int")
    assert api_module._int_env("X_GARBAGE", 42) == 42


def test_int_env_parses_value(monkeypatch):
    monkeypatch.setenv("X_OK", "17")
    assert api_module._int_env("X_OK", 42) == 17


# ----- _strip_pagination_for_count ---------------------------------------

def test_strip_pagination_for_count_drops_order_limit_offset():
    query = (
        "SELECT f.*, COUNT(*) OVER() AS total_count\n"
        "FROM findings f\n"
        "WHERE 1=1 AND f.severity = $1\n"
        "ORDER BY f.last_seen_at DESC NULLS LAST\n"
        "LIMIT $2 OFFSET $3"
    )
    params = ["high", 100, 0]

    count_sql, count_params = api_module._strip_pagination_for_count(query, params)

    # SELECT is rewritten to COUNT(*) and the FROM/WHERE survive.
    assert count_sql.startswith("SELECT COUNT(*) FROM findings")
    assert "ORDER BY" not in count_sql
    assert "LIMIT" not in count_sql
    assert "OFFSET" not in count_sql
    # Last two params (the LIMIT and OFFSET placeholders) are dropped.
    assert count_params == ["high"]


def test_strip_pagination_for_count_preserves_filter_params():
    query = (
        "SELECT f.*, COUNT(*) OVER() AS total_count "
        "FROM findings f WHERE f.status = $1 AND f.target_id = $2 "
        "ORDER BY f.severity LIMIT $3 OFFSET $4"
    )
    params = ["active", "uuid-1", 50, 100]

    count_sql, count_params = api_module._strip_pagination_for_count(query, params)

    assert "$1" in count_sql
    assert "$2" in count_sql
    assert count_params == ["active", "uuid-1"]


# ----- _decode_json_value -------------------------------------------------

def test_decode_json_value_handles_string_json():
    assert api_module._decode_json_value('{"a": 1, "b": [2, 3]}') == {"a": 1, "b": [2, 3]}


def test_decode_json_value_passes_dict_through():
    payload = {"already": "decoded"}
    assert api_module._decode_json_value(payload) is payload


def test_decode_json_value_passes_non_json_string_through():
    # Strings that don't look like JSON return as-is rather than raising.
    assert api_module._decode_json_value("just a string") == "just a string"


def test_decode_json_value_handles_none():
    assert api_module._decode_json_value(None) is None
