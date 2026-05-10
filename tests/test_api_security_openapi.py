import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import discovery


def test_api_security_test_parses_openapi_operations(monkeypatch):
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Honey API", "version": "1.0.0"},
        "paths": {
            "/api/logs": {
                "get": {
                    "parameters": [
                        {"name": "token", "in": "query", "schema": {"type": "string"}},
                    ],
                },
            },
            "/api/upload": {
                "post": {
                    "requestBody": {
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "file": {"type": "string", "format": "binary"},
                                    },
                                    "required": ["file"],
                                },
                            },
                        },
                    },
                },
            },
            "/login": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/x-www-form-urlencoded": {
                                "schema": {
                                    "allOf": [
                                        {"$ref": "#/components/schemas/LoginForm"},
                                    ],
                                },
                            },
                        },
                    },
                },
            },
        },
        "components": {
            "schemas": {
                "LoginForm": {
                    "type": "object",
                    "properties": {
                        "username": {"type": "string", "default": ""},
                        "password": {"type": "string", "default": ""},
                    },
                    "required": ["username", "password"],
                },
            },
        },
    }

    async def fake_run(cmd, timeout=None):
        _ = timeout
        url = cmd[-1]
        if url.endswith("/openapi.json"):
            return json.dumps(spec) + "\n200", "", 0
        return '{"error":"not found"}\n404', "", 0

    monkeypatch.setattr(discovery, "run", fake_run)

    result = asyncio.run(discovery.api_security_test("https://honey.example"))

    assert result["api_type"] == "openapi"
    assert result["openapi"]["endpoint_count"] == 3
    assert "GET /api/logs" in result["endpoints_discovered"]
    assert "POST /api/upload" in result["endpoints_discovered"]
    login_endpoint = next(ep for ep in result["openapi"]["endpoints"] if ep["path"] == "/login")
    assert login_endpoint["body_params"] == ["username", "password"]
    assert login_endpoint["body_required_params"] == ["username", "password"]
    assert not any(
        finding["type"] == "sensitive_data_exposure" and finding["endpoint"] == "/openapi.json"
        for finding in result["vulnerabilities"]
    )
