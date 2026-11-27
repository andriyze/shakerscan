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


# --- N54: a form login seed is form-encoded; masking is display-only ---------------------------
# Plan-DAST main673 seeded ``POST /hub/login username,password`` for honey's HTML sign-in form
# (``method=post action=/hub/login``). The field list became a JSON body, so the form was probed
# as a JSON API, and the scan record showed the empty password as ``"***"``. ``form:`` read only a
# query string: ``form:username,password`` was refused and ``form:username=,password=`` became one
# field named ``username``.

@pytest.mark.parametrize("line", [
    "POST /hub/login form:username,password",
    "POST /hub/login form:username=,password=",
    "POST /hub/login form:username password",
    "POST /hub/login form:username=&password=",
])
def test_a_form_field_list_is_a_form_body(line):
    assert normalize_known_endpoint(line) == "POST /hub/login form:username=&password="


@pytest.mark.parametrize(("line", "expected"), [
    ("POST /s form:user=alice, pass=b", "POST /s form:user=alice&pass=b"),
    ("POST /s form:q=a,b", "POST /s form:q=a,b"),
    ("POST /s form:q=hello world", "POST /s form:q=hello world"),
])
def test_form_values_keep_their_meaning(line, expected):
    assert normalize_known_endpoint(line) == expected


def _sent(line: str):
    """The request a body candidate built from one submitted seed line actually sends."""
    import scan.action_adapter as adapter

    stored = ScanPublicCompatibilityOptions(custom_endpoints=[line]).custom_endpoints[0]
    method, url, content_type, fields = _known_endpoint_url(stored, origin=ORIGIN)
    resolved = {
        "method": method, "url": url, "content_type": content_type,
        "field_name": fields[0], "body_field_names": fields,
    }
    original = adapter.execution_request_for_manifest_candidate
    adapter.execution_request_for_manifest_candidate = lambda *args, **kwargs: resolved
    try:
        request = adapter.proof_request_for_candidate(
            object(), object(), 0, request_id="r", ordinal=0, name="n", headers=(),
            authenticated=False,
        )
    finally:
        adapter.execution_request_for_manifest_candidate = original
    return stored, request


def test_a_form_login_seed_is_sent_form_encoded_with_its_fields():
    import urllib.parse as parse

    stored, request = _sent("POST /hub/login form:username,password")
    assert request.method == "POST"
    assert request.url == "https://target.test/hub/login"
    assert ("Content-Type", "application/x-www-form-urlencoded") in request.headers
    assert [name for name, _ in parse.parse_qsl(request.body.decode())] == [
        "password", "username",
    ]
    assert b"***" not in request.body


def test_a_json_seed_still_sends_json():
    import json

    stored, request = _sent("POST /api/login username,password")
    assert stored == 'POST /api/login json:{"username":"","password":""}'
    assert ("Content-Type", "application/json") in request.headers
    assert set(json.loads(request.body.decode())) == {"username", "password"}
    assert b"***" not in request.body


def test_masking_is_display_only_and_never_invents_a_value():
    from redaction import redact_scan_options

    stored = ScanPublicCompatibilityOptions(custom_endpoints=[
        "POST /api/login username,password",
        "POST /hub/login form:username,password",
        "POST /api/login username=alice,password=Hunter2x",
    ]).custom_endpoints
    # The stored seed keeps what was entered; nothing in it is a mask.
    assert stored[2] == 'POST /api/login json:{"username":"alice","password":"Hunter2x"}'
    assert not any("***" in line for line in stored)
    shown = redact_scan_options({"custom_endpoints": list(stored)})["custom_endpoints"]
    # An empty password is shown empty, not as a value that was withheld ...
    assert shown[0] == 'POST /api/login json:{"username":"","password":""}'
    assert shown[1] == "POST /hub/login form:username=&password="
    # ... and a real one is withheld from the display only.
    assert "Hunter2x" not in shown[2] and '"password":"***"' in shown[2]
