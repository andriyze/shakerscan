"""Behavioral regressions for the post-2.0 API-description audit."""
from __future__ import annotations

import copy
import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from api.capabilities.spec_ingest import discovered_route_records, ingest_spec_bodies, spec_endpoints

ORIGIN = "https://api.example.test"


def _spec():
    return {"openapi": "3.0.3", "paths": {"/users": {"get": {}}}}


@pytest.mark.parametrize("server", ["/api/v1", ORIGIN + "/api/v1", ORIGIN + ":443/api/v1"])
def test_server_base_path_is_not_lost(server):
    spec = _spec()
    spec["servers"] = [{"url": server}]
    assert discovered_route_records(spec, origin=ORIGIN)[0]["url"] == ORIGIN + "/api/v1/users"


def test_swagger_base_path_is_preserved():
    spec = {"swagger": "2.0", "basePath": "/api/v1", "paths": {"/users": {"get": {}}}}
    assert discovered_route_records(spec, origin=ORIGIN)[0]["url"] == ORIGIN + "/api/v1/users"


def test_operation_then_path_then_root_server_precedence():
    spec = _spec()
    spec["servers"] = [{"url": "/root"}]
    spec["paths"]["/users"]["servers"] = [{"url": "/path"}]
    spec["paths"]["/users"]["post"] = {"servers": [{"url": "/operation"}]}
    assert {(r["method"], r["url"]) for r in discovered_route_records(spec, origin=ORIGIN)} == {
        ("GET", ORIGIN + "/path/users"), ("POST", ORIGIN + "/operation/users"),
    }


def test_relative_server_uses_document_url_and_default_variables():
    spec = _spec()
    spec["servers"] = [{"url": "../api/{version}", "variables": {"version": {"default": "v1"}}}]
    records = ingest_spec_bodies([(ORIGIN + "/docs/openapi.json", json.dumps(spec).encode(), None)], origin=ORIGIN)
    assert records[0]["url"] == ORIGIN + "/api/v1/users"


@pytest.mark.parametrize("server", ["https://other.test/v1", "//other.test/v1", "http://api.example.test/v1", "https://secret@api.example.test/v1"])
def test_foreign_origin_scheme_and_userinfo_are_not_remapped(server):
    spec = _spec()
    spec["servers"] = [{"url": server}]
    issues = []
    assert discovered_route_records(spec, origin=ORIGIN, issues=issues) == []
    assert issues == ["spec_off_origin_server"]
    assert "secret" not in str(issues)


@pytest.mark.parametrize("path", ["//other.test/a", "/%2e%2e/a", "/a\\b", "/a?x=1", "/a#x"])
def test_ambiguous_operation_path_is_reported_not_executed(path):
    spec = {"openapi": "3.0.3", "paths": {path: {"get": {}}}}
    issues = []
    assert discovered_route_records(spec, origin=ORIGIN, issues=issues) == []
    assert "spec_invalid_operation_path" in issues


def test_referenced_body_and_parameters_equal_inline_shapes():
    body = {"content": {"application/json": {"schema": {"properties": {"email": {}, "password": {}}}}}}
    parameter = {"name": "q", "in": "query"}
    inline = {"openapi": "3.0.3", "paths": {"/login": {"post": {"requestBody": body, "parameters": [parameter]}}}}
    refs = copy.deepcopy(inline)
    refs["paths"]["/login"]["post"] = {
        "requestBody": {"$ref": "#/components/requestBodies/Login~1Admin"},
        "parameters": [{"$ref": "#/components/parameters/Search"}],
    }
    refs["components"] = {"requestBodies": {"Login/Admin": body}, "parameters": {"Search": parameter}}
    assert spec_endpoints(refs) == spec_endpoints(inline)


def test_path_item_ref_and_schema_ref_chains():
    spec = {"openapi": "3.1.0", "paths": {"/login": {"$ref": "#/components/pathItems/Login"}}, "components": {
        "pathItems": {"Login": {"post": {"requestBody": {"$ref": "#/components/requestBodies/Login"}}}},
        "requestBodies": {"Login": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/A"}}}}},
        "schemas": {"A": {"$ref": "#/components/schemas/B"}, "B": {"properties": {"name": {}}}},
    }}
    assert spec_endpoints(spec)[0]["body_field_names"] == ["name"]


@pytest.mark.parametrize("ref", ["#/missing", "https://secret.other/schema.json#/Body", "#/components/requestBodies/Cycle"])
def test_unsupported_refs_are_explicit_and_bounded(ref):
    spec = {"openapi": "3.0.3", "paths": {"/login": {"post": {"requestBody": {"$ref": ref}}}},
            "components": {"requestBodies": {"Cycle": {"$ref": "#/components/requestBodies/Cycle"}}}}
    issues = []
    routes = discovered_route_records(spec, origin=ORIGIN, issues=issues)
    assert routes[0]["url"] == ORIGIN + "/login"
    assert issues and "secret" not in str(issues)


@pytest.mark.parametrize("content_type", ["application/x-www-form-urlencoded", "multipart/form-data"])
def test_swagger_form_fields_use_consumes(content_type):
    spec = {"swagger": "2.0", "consumes": ["application/json"], "parameters": {"Email": {"in": "formData", "name": "email", "type": "string"}},
            "paths": {"/login": {"post": {"consumes": [content_type], "parameters": [
                {"$ref": "#/parameters/Email"}, {"in": "formData", "name": "password", "type": "string"},
            ]}}}}
    route = spec_endpoints(spec)[0]
    assert route["content_type"] == content_type
    assert route["body_field_names"] == ["email", "password"]


def test_actual_http_requests_hit_prefixed_handler_only():
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            self.send_response(200 if self.path == "/api/v1/users" else 404)
            self.end_headers()
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f"http://127.0.0.1:{server.server_port}"
        spec = _spec()
        spec["servers"] = [{"url": "/api/v1"}]
        for route in discovered_route_records(spec, origin=origin):
            with urllib.request.urlopen(route["url"], timeout=3) as response:
                assert response.status == 200
        assert seen == ["/api/v1/users"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
