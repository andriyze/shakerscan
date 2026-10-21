"""A query parameter used as its own value (``?<token>``) is masked like any query value.

The display redactor removes every query value but kept each name, so a URL that carries a
credential as a bare query key (``?eyJ...`` or a random 32-character token) showed it in a
capture's request list and in replay plans and receipts. Ordinary names stay as they were.
"""
from __future__ import annotations

import os
import sys
import urllib.parse

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import request_replay, v2_request_replay_hardening  # noqa: E402
from scanner_tools.device_request_formats import redact_captured_url  # noqa: E402
from scanner_tools.url_redaction import redact_url  # noqa: E402

# Unit fixtures shaped like a JWT and a random API token; neither is a real credential.
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlX3ZhbHVlXzEyMw"
RANDOM = "Zx9Qp2Lm7Rt4Wv8Yb3Nc5Kd1Hf6Gj0Ts"

DISPLAYS = {
    "redact_url": redact_url,
    "redact_captured_url": redact_captured_url,
    "v2 replay plan": v2_request_replay_hardening._redacted_url,
    "replay receipt": request_replay._redacted_url,
}


@pytest.mark.parametrize("display", DISPLAYS.values(), ids=DISPLAYS.keys())
@pytest.mark.parametrize("query", [
    JWT, RANDOM, f"{JWT}&page=2", f"page=2&{RANDOM}", f"{RANDOM}=1", urllib.parse.quote(JWT, safe=""),
])
def test_token_used_as_a_query_name_is_masked(display, query):
    shown = display(f"https://app.example/api/items?{query}")
    assert JWT not in shown and RANDOM not in shown
    assert JWT not in urllib.parse.unquote(shown) and RANDOM not in urllib.parse.unquote(shown)
    assert "redacted" in shown


@pytest.mark.parametrize("display", [redact_captured_url, v2_request_replay_hardening._redacted_url])
def test_bare_credential_named_parameter_is_masked_in_capture_and_plan_views(display):
    shown = display("https://app.example/api?access_token&page=2")
    assert "access_token" not in shown and "page=" in shown


def _previous(url: str) -> str:
    """The query the display redactor showed for ordinary names before this change."""
    query = urllib.parse.urlsplit(url).query
    return urllib.parse.urlencode([
        (name[:200], "<redacted>") for name, _ in urllib.parse.parse_qsl(query, keep_blank_values=True)
    ])


@pytest.mark.parametrize("query", [
    "q=books&page=2&sort",
    "名前=値&café&naïve=1",
    "%E2%9C%93=1&a%20b=2&a+b=3&%25=4",
    "debug&verbose&x=",
    "x" * 5000 + "=1",
    "&".join(f"field{index}=value{index}" for index in range(2000)),
    "ProductCategory12=1&2026-10-20=x&report.pdf",
    "q=1&&&q=2&=empty-name",
])
def test_ordinary_query_names_are_shown_as_before(query):
    url = f"https://app.example/search?{query}"
    expected = _previous(url)
    shown_query = urllib.parse.urlsplit(redact_url(url, max_length=1 << 22)).query
    assert shown_query == expected
    captured_query = urllib.parse.urlsplit(redact_captured_url(url)).query
    assert expected.startswith(captured_query) or captured_query == expected
