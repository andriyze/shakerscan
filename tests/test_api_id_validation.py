"""Malformed UUIDs in path/query values should be client errors, but unrelated
internal ValueErrors should remain server bugs."""
import asyncio
import json
import os
import sys

import pytest
from starlette.requests import Request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
import api  # noqa: E402


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
