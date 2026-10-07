"""The known-endpoint syntax the New Scan form documents must reach every Scan stage as a body.

The form's placeholder is ``POST /api/login username,password``. Only ``json:``/``form:`` were
understood by the Scan surface manifest, so the soak scan 146b6c03 stored
``POST /api/v1/agent/run task`` as the route ``/api/v1/agent/run task`` with no body fields and
built no candidate from it. Submission now normalizes every declared line to the canonical
``json:``/query form and refuses a line it cannot read instead of storing it as path text.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scanner"))

from request_models import ScanPublicCompatibilityOptions  # noqa: E402
from scan.known_endpoints import KnownEndpointSyntaxError, normalize_known_endpoint  # noqa: E402
from scan.surface_manifest import _known_endpoint_url  # noqa: E402

ORIGIN = "https://target.test"


@pytest.mark.parametrize(("line", "expected"), [
    ("GET /api/users", "GET /api/users"),
    ("/api/health", "GET /api/health"),
    ("post /api/login username,password", 'POST /api/login json:{"username":"","password":""}'),
    ("POST /api/v1/agent/run task", 'POST /api/v1/agent/run json:{"task":""}'),
    ("POST /api/login username=alice, password", 'POST /api/login json:{"username":"alice","password":""}'),
    ('POST /api/search json:{"query": "test"}', 'POST /api/search json:{"query":"test"}'),
    ("POST /api/login form:user=a&pass=b", "POST /api/login form:user=a&pass=b"),
    ("GET /api/users id,name", "GET /api/users?id=&name="),
    ("GET /api/users?id=1 id,page", "GET /api/users?id=1&page="),
    ("GET https://target.test/a", "GET https://target.test/a"),
])
def test_documented_lines_normalize_to_the_canonical_form(line, expected):
    assert normalize_known_endpoint(line) == expected


@pytest.mark.parametrize("line", [
    "POST",
    "POST api/login",
    "POST //evil.test/x",
    "POST /api/login json:{not json",
    'POST /api/login json:"text"',
    "POST /api/login form:",
    "POST /api/login user name!",
    "POST /api/login <script>",
])
def test_unreadable_lines_are_refused(line):
    with pytest.raises(KnownEndpointSyntaxError):
        normalize_known_endpoint(line)


def test_submission_stores_the_canonical_form():
    options = ScanPublicCompatibilityOptions(custom_endpoints=[
        "GET /api/users", "  ", "POST /api/login username,password",
    ])
    assert options.custom_endpoints == [
        "GET /api/users", 'POST /api/login json:{"username":"","password":""}',
    ]


def test_submission_refuses_an_unreadable_line_without_echoing_it():
    with pytest.raises(ValidationError) as caught:
        ScanPublicCompatibilityOptions(custom_endpoints=["GET /ok", "POST /x?token=SECRET1 user name!"])
    message = str(caught.value).split("[type=")[0]
    assert "known endpoint 2" in message
    assert "SECRET1" not in message


def test_the_documented_form_produces_body_fields_not_a_path():
    parsed = _known_endpoint_url("POST /api/v1/agent/run task", origin=ORIGIN)
    assert parsed is not None
    method, url, content_type, fields = parsed
    assert (method, url) == ("POST", "https://target.test/api/v1/agent/run")
    assert content_type == "application/json"
    assert fields == ["task"]
