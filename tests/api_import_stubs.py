"""Shared compatibility stubs for importing api.py without FastAPI installed."""

from __future__ import annotations

import sys
import types


def install_fastapi_exception_stubs() -> None:
    fastapi = sys.modules.get("fastapi")
    if fastapi is None or hasattr(fastapi, "__path__"):
        return

    exceptions = types.ModuleType("fastapi.exceptions")

    class RequestValidationError(Exception):
        def __init__(self, errors=None):
            super().__init__("request validation failed")
            self._errors = list(errors or [])

        def errors(self):
            return list(self._errors)

    handlers = types.ModuleType("fastapi.exception_handlers")

    class APIRouter:
        def __init__(self, *args, **kwargs):
            pass

        def _decorator(self, *args, **kwargs):
            def wrapper(fn):
                return fn
            return wrapper

        get = post = patch = put = delete = _decorator

    class Response:
        def __init__(self, content=None, status_code=200, headers=None, media_type=None):
            self.content = content
            self.status_code = status_code
            self.headers = headers or {}
            self.media_type = media_type
            self.body = str(content if content is not None else "").encode("utf-8")

    async def request_validation_exception_handler(_request, _exc):
        return None

    exceptions.RequestValidationError = RequestValidationError
    handlers.request_validation_exception_handler = request_validation_exception_handler
    if not hasattr(fastapi, "APIRouter"):
        fastapi.APIRouter = APIRouter
    if not hasattr(fastapi, "status"):
        fastapi.status = types.SimpleNamespace(
            HTTP_201_CREATED=201,
            HTTP_503_SERVICE_UNAVAILABLE=503,
        )
    fastapi_app = getattr(fastapi, "FastAPI", None)
    if fastapi_app is not None and not hasattr(fastapi_app, "include_router"):
        fastapi_app.include_router = lambda self, *_args, **_kwargs: None
    if fastapi_app is not None and not hasattr(fastapi_app, "exception_handler"):
        def exception_handler(self, *_args, **_kwargs):
            def wrapper(fn):
                return fn
            return wrapper
        fastapi_app.exception_handler = exception_handler
    responses = sys.modules.setdefault("fastapi.responses", types.ModuleType("fastapi.responses"))
    if not hasattr(responses, "Response"):
        responses.Response = Response
    if not hasattr(responses, "JSONResponse"):
        responses.JSONResponse = Response
    sys.modules.setdefault("fastapi.exceptions", exceptions)
    sys.modules.setdefault("fastapi.exception_handlers", handlers)
