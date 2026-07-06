"""Malformed UUIDs in path/query values should be client errors, but unrelated
internal ValueErrors should remain server bugs."""
import asyncio
import json
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))


class _BodyJSONResponse:
    def __init__(self, content=None, status_code=200, headers=None, media_type=None):
        self.content = content
        self.status_code = status_code
        self.headers = headers or {}
        self.media_type = media_type
        if isinstance(content, (bytes, bytearray)):
            self.body = bytes(content)
        elif isinstance(content, str):
            self.body = content.encode("utf-8")
        else:
            self.body = json.dumps(content).encode("utf-8")


def _response_has_body(response_cls) -> bool:
    try:
        return hasattr(response_cls({"detail": "x"}), "body")
    except Exception:
        return False


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

        get = post = patch = put = delete = on_event = exception_handler = _decorator

    class _FakeHTTPException(Exception):
        def __init__(self, status_code: int = 500, detail=None):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    fastapi_mod.FastAPI = _FakeFastAPI
    fastapi_mod.HTTPException = _FakeHTTPException
    fastapi_mod.Query = lambda default=None, **kwargs: default
    fastapi_mod.Request = object
    sys.modules["fastapi"] = fastapi_mod

    middleware_mod = types.ModuleType("fastapi.middleware")
    cors_mod = types.ModuleType("fastapi.middleware.cors")
    cors_mod.CORSMiddleware = type("_FakeCORSMiddleware", (), {})
    sys.modules["fastapi.middleware"] = middleware_mod
    sys.modules["fastapi.middleware.cors"] = cors_mod

    responses_mod = types.ModuleType("fastapi.responses")
    responses_mod.Response = _BodyJSONResponse
    responses_mod.JSONResponse = _BodyJSONResponse
    sys.modules["fastapi.responses"] = responses_mod

responses_mod = sys.modules.get("fastapi.responses")
if responses_mod is not None:
    if not _response_has_body(responses_mod.JSONResponse):
        responses_mod.JSONResponse = _BodyJSONResponse

try:
    from starlette.requests import Request
except ModuleNotFoundError:
    class Request:
        def __init__(self, scope, receive):
            self.scope = scope
            self.receive = receive
            self.method = scope.get("method", "")
            self.url = types.SimpleNamespace(path=scope.get("path", ""))

import api  # noqa: E402

if "fastapi.responses" in sys.modules:
    response_cls = sys.modules["fastapi.responses"].JSONResponse
    if not _response_has_body(response_cls):
        sys.modules["fastapi.responses"].JSONResponse = _BodyJSONResponse
        api.JSONResponse = _BodyJSONResponse
    else:
        api.JSONResponse = response_cls


async def _empty_receive():
    return {"type": "http.request", "body": b"", "more_body": False}


def _request(path="/targets/not-a-uuid"):
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "headers": [],
            "query_string": b"",
            "server": ("testserver", 80),
            "scheme": "http",
            "client": ("testclient", 123),
        },
        _empty_receive,
    )


def test_uuid_value_errors_return_400():
    response = asyncio.run(
        api._value_error_handler(
            _request(),
            ValueError("badly formed hexadecimal UUID string"),
        )
    )

    assert response.status_code == 400
    assert json.loads(response.body) == {"detail": "Invalid request parameter"}


def test_non_uuid_value_errors_are_not_masked_as_bad_requests():
    with pytest.raises(ValueError, match="internal invariant failed"):
        asyncio.run(
            api._value_error_handler(
                _request("/internal"),
                ValueError("internal invariant failed"),
            )
        )
