"""Tests for the Continuous ASM endpoint inventory pure helpers (docs §16)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import asm_inventory as a  # noqa: E402


def test_normalize_path_templates_volatile_ids():
    assert a.normalize_path("/users/42") == "/users/{id}"
    assert a.normalize_path("/u/550e8400-e29b-41d4-a716-446655440000/x") == "/u/{uuid}/x"
    assert a.normalize_path("/blob/0123456789abcdef0123456789abcdef") == "/blob/{hash}"
    assert a.normalize_path("/rest/products/search") == "/rest/products/search"


def test_parse_worklist_entry_shapes():
    assert a.parse_worklist_entry("GET /rest/products/1?q=x&id=2") == ("GET", "/rest/products/1", "id,q")
    assert a.parse_worklist_entry("POST /login form:email=1&password=1") == ("POST", "/login", "email,password")
    assert a.parse_worklist_entry('POST /api json:{"a":1,"b":2}') == ("POST", "/api", "a,b")
    assert a.parse_worklist_entry("/ftp") == ("GET", "/ftp", "")
    assert a.parse_worklist_entry("GET rel/path") == ("GET", "/rel/path", "")
    assert a.parse_worklist_entry("") is None
    assert a.parse_worklist_entry(None) is None


def test_fingerprint_collapses_volatile_ids():
    f1 = a.endpoint_fingerprint("GET", "/users/42", "id")
    f2 = a.endpoint_fingerprint("GET", "/users/43", "id")
    assert f1 == f2  # same logical endpoint
    # method, path, and param set all matter
    assert a.endpoint_fingerprint("POST", "/users/42", "id") != f1
    assert a.endpoint_fingerprint("GET", "/orders/42", "id") != f1
    assert a.endpoint_fingerprint("GET", "/users/42", "id,extra") != f1


def test_priority_score_ranks_high_value_and_params():
    admin = a.priority_score("POST", "/admin/login", "user,pass")
    static = a.priority_score("GET", "/assets/style.css", "")
    api_param = a.priority_score("GET", "/api/items", "id")
    assert admin > api_param > static
    assert admin == 10 + 20 + 15 + 5  # high-value + param + write method


def test_to_custom_endpoint_roundtrips_params():
    assert a.to_custom_endpoint("POST", "/login", "email,password") == "POST /login?email=1&password=1"
    assert a.to_custom_endpoint("GET", "/ftp", "") == "GET /ftp"


def test_normalize_worklist_dedupes_by_fingerprint():
    wl = ["GET /a/1?x=1", "GET /a/2?x=1", "GET /b", "GET /b", 123, None]
    out = a.normalize_worklist(wl)
    # /a/1 and /a/2 collapse (same fingerprint); /b dedupes; non-strings dropped
    assert out == [("GET", "/a/1", "x"), ("GET", "/b", "")]


def test_normalize_worklist_respects_limit():
    wl = [f"GET /e{i}?x=1" for i in range(100)]
    assert len(a.normalize_worklist(wl, limit=10)) == 10
