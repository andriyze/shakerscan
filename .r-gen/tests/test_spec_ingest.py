from __future__ import annotations

import json

from capabilities.spec_ingest import (
    discovered_route_records,
    ingest_spec_bodies,
    is_openapi_document,
    parse_spec_document,
    spec_endpoints,
)


def test_openapi_3_query_and_json_body_fields_are_extracted():
    spec = {
        "openapi": "3.0.1",
        "paths": {
            "/search": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
            "/login": {"post": {"requestBody": {"content": {"application/json": {
                "schema": {"type": "object", "properties": {"email": {}, "password": {}}}}}}}},
        },
    }
    by_route = {(e["method"], e["path"]): e for e in spec_endpoints(spec)}
    assert by_route[("GET", "/search")]["query_parameter_names"] == ["q"]
    login = by_route[("POST", "/login")]
    assert login["body_field_names"] == ["email", "password"]
    assert login["content_type"] == "application/json"


def test_swagger_2_body_parameter_and_ref_resolution():
    spec = {
        "swagger": "2.0",
        "paths": {"/orders": {"post": {"parameters": [
            {"in": "body", "schema": {"$ref": "#/definitions/Order"}},
            {"in": "query", "name": "dryRun"},
        ]}}},
        "definitions": {"Order": {"properties": {"item": {}, "qty": {}}}},
    }
    order = spec_endpoints(spec)[0]
    assert order["method"] == "POST"
    assert order["body_field_names"] == ["item", "qty"]
    assert order["query_parameter_names"] == ["dryRun"]


def test_recursive_ref_terminates():
    spec = {
        "openapi": "3.0.0",
        "paths": {"/n": {"post": {"requestBody": {"content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/Node"}}}}}}},
        "components": {"schemas": {"Node": {
            "properties": {"value": {}, "next": {"$ref": "#/components/schemas/Node"}}}}},
    }
    assert spec_endpoints(spec)[0]["body_field_names"] == ["value", "next"]


def test_path_templates_become_addressable_and_url_uses_the_bound_origin():
    spec = {"openapi": "3.0.0", "paths": {
        "/rest/products/{id}/reviews": {"get": {}},
    }, "servers": [{"url": "https://elsewhere.example"}]}
    issues = []
    assert discovered_route_records(spec, origin="https://app.example.test", issues=issues) == []
    assert issues == ["spec_off_origin_server"]
    spec["servers"] = [{"url": "https://app.example.test/api/v1"}]
    records = discovered_route_records(spec, origin="https://app.example.test")
    assert records[0]["url"] == "https://app.example.test/api/v1/rest/products/1/reviews"


def test_non_spec_documents_yield_nothing():
    assert is_openapi_document({"hello": "world"}) is False
    assert parse_spec_document(b"<html>swagger ui</html>") is None
    assert spec_endpoints({"paths": {"/x": {"get": {}}}}) == []  # no openapi/swagger version


def test_yaml_spec_is_parsed():
    body = b"openapi: 3.0.0\npaths:\n  /a:\n    get:\n      parameters:\n        - name: x\n          in: query\n"
    spec = parse_spec_document(body, content_type="application/yaml")
    assert spec is not None
    assert spec_endpoints(spec)[0]["query_parameter_names"] == ["x"]


def test_multiple_specs_aggregate_and_dedupe_preferring_the_body_shape():
    thin = json.dumps({"openapi": "3.0.0", "paths": {"/a": {"post": {}}}}).encode()
    rich = json.dumps({"openapi": "3.0.0", "paths": {"/a": {"post": {"requestBody": {
        "content": {"application/json": {"schema": {"properties": {"f": {}}}}}}}}}}).encode()
    routes = ingest_spec_bodies(
        [("u1", thin, "application/json"), ("u2", rich, "application/json")],
        origin="https://app.example.test",
    )
    assert len(routes) == 1
    assert routes[0]["body_field_names"] == ["f"]
