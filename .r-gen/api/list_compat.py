"""How a reworked list endpoint serves both list/v1 and its deprecated legacy shape.

An endpoint that existed before 2.11 keeps its path and its legacy response for the 2.11.x line
(``LEGACY_LIST_CONTRACT`` in ``public_api_contract.py``). A request opts into the list/v1
envelope (``list_contract.py``) by sending any of ``cursor``, ``count``, ``fields`` or ``since``;
a first page sends ``count=none`` (or ``estimate``/``exact``). Every other request gets the legacy
response, marked ``Deprecation: true``.

The opt-in rides on query parameters, not on a new path, so the Enterprise gateway's path
allowlist admits it unchanged; an older engine ignores the unknown parameters and answers in the
legacy shape, which a client recognises by the missing ``items`` key.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import HTTPException

try:
    from list_contract import MAX_LIMIT, CountMode, Page, page_params
except ModuleNotFoundError:  # package import layout
    from .list_contract import MAX_LIMIT, CountMode, Page, page_params

LIST_V1_OPT_IN = ("cursor", "count", "fields", "since")
DEPRECATION_HEADERS = {"Deprecation": "true"}


def direct(value: Any) -> Any:
    """A parameter's value, or its declared default when a route is called in-process (tests and
    internal adapters pass only the arguments they use; FastAPI's ``Query`` marker remains)."""
    if type(value).__module__ == "fastapi.params" and hasattr(value, "default"):
        return value.default
    return value


def wants_list_v1(*, cursor: str | None, count: str | None, fields: str | None,
                  since: datetime | None) -> bool:
    return any(direct(value) is not None for value in (cursor, count, fields, since))


def v1_page(*, limit: int | None, cursor: str | None, sort: str | None, fields: str | None,
            count: CountMode | None, since: datetime | None, default_limit: int = 50) -> Page:
    """A list/v1 ``Page`` from query values an endpoint declared itself (it also serves legacy)."""
    chosen = default_limit if limit is None else int(limit)
    if not 1 <= chosen <= MAX_LIMIT:
        raise HTTPException(status_code=422, detail={
            "error": "invalid_limit", "message": f"list/v1 limit must be between 1 and {MAX_LIMIT}",
        })
    return page_params(limit=chosen, cursor=cursor, sort=sort, fields=fields,
                       count=count or "none", since=since)


def mark_deprecated(response: Any) -> None:
    """Flag a legacy-shape list response (RFC 9745 ``Deprecation``)."""
    if response is not None:
        for name, value in DEPRECATION_HEADERS.items():
            response.headers[name] = value


__all__ = ["DEPRECATION_HEADERS", "LIST_V1_OPT_IN", "direct", "mark_deprecated", "v1_page", "wants_list_v1"]
