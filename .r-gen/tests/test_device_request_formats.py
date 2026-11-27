import asyncio
import base64
import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import device_request_formats, device_web  # noqa: E402


def _har():
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "Browser"},
            "entries": [
                {
                    "pageref": "TV controls",
                    "request": {
                        "method": "POST",
                        "url": "https://192.0.2.10:3001/api/apps?serial=private-value",
                        "headers": [{"name": "Authorization", "value": "Bearer captured-secret"}],
                        "cookies": [{"name": "sid", "value": "cookie-secret"}],
                        "postData": {"mimeType": "application/json", "text": '{"app":"netflix"}'},
                    },
                    "response": {"content": {"text": "captured-response-must-not-be-replayed"}},
                }
            ],
        }
    }


def _openapi():
    return {
        "openapi": "3.0.3",
        "info": {"title": "TV API", "version": "1"},
        "servers": [{"url": "https://192.0.2.10:3001"}],
        "paths": {
            "/apps/{id}": {
                "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer", "example": 7}}],
                "get": {
                    "summary": "Get app",
                    "parameters": [{"name": "details", "in": "query", "schema": {"type": "boolean"}}],
                    "security": [{"deviceKey": []}],
                },
                "post": {
                    "summary": "Start app",
                    "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/App"}}}},
                },
            }
        },
        "components": {
            "securitySchemes": {"deviceKey": {"type": "apiKey", "in": "header", "name": "X-Device-Key"}},
            "schemas": {"App": {"type": "object", "properties": {"name": {"type": "string", "example": "Netflix"}}}},
        },
    }


def test_har_summary_redacts_values_and_worker_ignores_captured_response():
    payload, summary = device_request_formats.validate_request_document(_har())
    request = device_request_formats.resolve_imported_requests(payload)[0]

    assert summary["format"] == "har"
    assert summary["har_version"] == "1.2"
    assert summary["port_hints"] == [3001]
    assert "private-value" not in str(summary)
    assert "captured-secret" not in str(summary)
    assert request["headers"]["Authorization"] == "Bearer captured-secret"
    assert request["headers"]["Cookie"] == "sid=cookie-secret"
    assert request["body"] == b'{"app":"netflix"}'
    assert "captured-response-must-not-be-replayed" not in str(request)


def test_har_requires_12_and_rejects_environment():
    bad = _har()
    bad["log"]["version"] = "1.1"
    with pytest.raises(device_request_formats.RequestImportError, match="HAR 1.2"):
        device_request_formats.validate_request_document(bad)
    with pytest.raises(device_request_formats.RequestImportError, match="only for Postman"):
        device_request_formats.validate_request_document(_har(), {"values": []})


def test_har_preserves_repeated_headers_and_decodes_bounded_binary_request_body():
    document = _har()
    request = document["log"]["entries"][0]["request"]
    request["headers"] = [
        {"name": "X-Trace", "value": "first"},
        {"name": "X-Trace", "value": "second"},
        {"name": "Content-Type", "value": "application/octet-stream"},
    ]
    request["cookies"] = []
    body = b"\x00\xff\x10binary"
    request["postData"] = {
        "mimeType": "application/octet-stream",
        "encoding": "base64",
        "text": base64.b64encode(body).decode("ascii"),
    }

    payload, _summary = device_request_formats.validate_request_document(document)
    resolved = device_request_formats.resolve_imported_requests(payload)[0]

    assert resolved["header_items"] == [
        ("X-Trace", "first"),
        ("X-Trace", "second"),
        ("Content-Type", "application/octet-stream"),
    ]
    assert resolved["body"] == body
    assert resolved["error"] is None


def test_openapi_generates_bounded_examples_and_preserves_state_gate_metadata():
    payload, summary = device_request_formats.validate_request_document(_openapi())
    requests = device_request_formats.resolve_imported_requests(payload)

    assert summary["format"] == "openapi"
    assert summary["spec_version"] == "3.0.3"
    assert summary["methods"] == {"GET": 1, "POST": 1}
    assert summary["safe_request_count"] == 1
    assert summary["state_changing_request_count"] == 1
    assert requests[0]["url"] == "https://192.0.2.10:3001/apps/7?details=True"
    assert requests[0]["auth_type"] == "declared:deviceKey"
    assert requests[1]["body"] == b'{"name":"Netflix"}'
    assert requests[1]["headers"]["Content-Type"] == "application/json"
    assert requests[1]["auth_type"] == "none"


def test_swagger_2_server_and_body_generation():
    swagger = {
        "swagger": "2.0",
        "info": {"title": "Legacy TV", "version": "1"},
        "schemes": ["https"],
        "host": "192.0.2.10:7345",
        "basePath": "/v1",
        "paths": {"/volume": {"put": {"parameters": [{"name": "body", "in": "body", "schema": {"type": "object", "properties": {"level": {"type": "integer", "default": 10}}}}]}}},
    }
    payload, summary = device_request_formats.validate_request_document(swagger)
    request = device_request_formats.resolve_imported_requests(payload)[0]

    assert summary["spec_version"] == "2.0"
    assert summary["port_hints"] == [7345]
    assert request["url"] == "https://192.0.2.10:7345/v1/volume"
    assert request["body"] == b'{"level":10}'


def test_openapi_never_fetches_external_refs_and_accepts_device_base_override():
    document = _openapi()
    document["paths"]["/external"] = {"get": {"parameters": [{"$ref": "https://evil.example/parameter.json"}]}}
    payload, summary = device_request_formats.validate_request_document(
        document, import_format="openapi", base_url="https://192.0.2.10:9443/device-api",
    )
    requests = device_request_formats.resolve_imported_requests(payload)

    assert summary["external_refs_ignored"] == 1
    assert summary["port_hints"] == [9443]
    assert all(item["url"].startswith("https://192.0.2.10:9443/device-api/") for item in requests)


def test_har_and_openapi_import_caps_follow_the_2000_request_limit():
    assert device_request_formats.MAX_REQUESTS == 2000
    har = {"log": {"version": "1.2", "entries": [
        {"request": {"method": "GET", "url": f"https://192.0.2.10:3001/api/{index}"}}
        for index in range(device_request_formats.MAX_REQUESTS)
    ]}}
    payload, summary = device_request_formats.validate_request_document(har)
    assert summary["request_count"] == device_request_formats.MAX_REQUESTS
    assert len(device_request_formats.resolve_imported_requests(payload)) == device_request_formats.MAX_REQUESTS

    har["log"]["entries"].append({"request": {"method": "GET", "url": "https://192.0.2.10:3001/extra"}})
    with pytest.raises(device_request_formats.RequestImportError, match="request limit"):
        device_request_formats.validate_request_document(har)

    openapi = {
        "openapi": "3.0.3",
        "info": {"title": "Wide TV API", "version": "1"},
        "servers": [{"url": "https://192.0.2.10:3001"}],
        "paths": {f"/p{index}": {"get": {}} for index in range(device_request_formats.MAX_REQUESTS + 1)},
    }
    with pytest.raises(device_request_formats.RequestImportError, match="operation limit"):
        device_request_formats.validate_request_document(openapi)


def test_har_replay_stays_pinned_and_inherits_bound_web_credential(monkeypatch):
    calls = []

    async def fake_request(**kwargs):
        calls.append(kwargs)
        return {"status": 200, "headers": {}, "body": b"ok", "truncated": False, "elapsed_ms": 1.0}

    monkeypatch.setattr(device_web, "_request", fake_request)
    async def trusted_tls(**_kwargs):
        return {"trusted": True, "verification_error": None}
    monkeypatch.setattr(device_web, "_assess_tls_trust", trusted_tls)
    document = _har()
    document["log"]["entries"][0]["request"]["method"] = "GET"
    document["log"]["entries"][0]["request"]["headers"] = []
    document["log"]["entries"][0]["request"]["cookies"] = []
    payload, _summary = device_request_formats.validate_request_document(document)
    result = asyncio.run(device_web.run_pinned_device_web_scan(
        {"origin": "https://192.0.2.10:3001", "connect_address": "192.0.2.10", "port": 3001},
        profile="quick",
        credential={"auth_kind": "web_authorization_header", "secret": "Bearer bound-secret"},
        request_collections=[{"collection_id": "har1", "name": "Browser", "payload": payload}],
        default_origin=True,
    ))

    assert result["device_web"]["imported_requests"]["executed"] == 1
    imported_call = next(item for item in calls if item.get("path", "").startswith("/api/apps"))
    assert imported_call["connect_address"] == "192.0.2.10"
    assert imported_call["headers"]["Authorization"] == "Bearer bound-secret"
    assert "bound-secret" not in str(result)
