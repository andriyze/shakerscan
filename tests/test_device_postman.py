import asyncio
import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import device_postman, device_web  # noqa: E402


def _collection():
    return {
        "info": {"name": "TV API", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "variable": [{"key": "baseUrl", "value": "https://192.0.2.10:3001"}],
        "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{token}}"}]},
        "item": [
            {"name": "Status", "request": {"method": "GET", "url": "{{baseUrl}}/api/status?serial=secret"}},
            {"name": "Rename", "request": {"method": "POST", "url": "{{baseUrl}}/api/name", "body": {"mode": "raw", "raw": '{"name":"Living room"}', "options": {"raw": {"language": "json"}}}}},
        ],
        "event": [{"listen": "prerequest", "script": {"exec": ["throw new Error('never')"]}}],
    }


def test_postman_summary_redacts_values_and_counts_ignored_scripts():
    payload, summary = device_postman.validate_and_summarize(
        _collection(),
        {"name": "TV", "values": [{"key": "token", "value": "top-secret-token", "enabled": True}]},
    )
    assert payload["collection"]["info"]["name"] == "TV API"
    assert summary["request_count"] == 2
    assert summary["safe_request_count"] == 1
    assert summary["state_changing_request_count"] == 1
    assert summary["scripts_ignored"] == 1
    assert summary["port_hints"] == [3001]
    assert "secret" not in summary["requests"][0]["url"]
    assert "top-secret-token" not in str(summary)


def test_postman_resolution_hydrates_auth_only_in_private_worker_payload():
    payload, _ = device_postman.validate_and_summarize(
        _collection(),
        {"values": [{"key": "token", "value": "top-secret-token"}]},
    )
    requests = device_postman.resolve_requests(payload)
    assert requests[0]["url"] == "https://192.0.2.10:3001/api/status?serial=secret"
    assert requests[0]["headers"]["Authorization"] == "Bearer top-secret-token"
    assert requests[1]["body"] == b'{"name":"Living room"}'


def test_postman_request_inherit_uses_collection_auth_and_text_multipart():
    collection = {
        "info": {"name": "Inherited auth"},
        "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{token}}"}]},
        "item": [{
            "name": "Submit",
            "request": {
                "method": "POST",
                "url": "https://192.0.2.10:3001/submit",
                "auth": {"type": "inherit"},
                "body": {"mode": "formdata", "formdata": [{"key": "room", "value": "living room", "type": "text"}]},
            },
        }],
    }
    payload, _ = device_postman.validate_and_summarize(collection, {"values": [{"key": "token", "value": "secret-token"}]})
    request = device_postman.resolve_requests(payload)[0]

    assert request["headers"]["Authorization"] == "Bearer secret-token"
    assert request["headers"]["Content-Type"].startswith("multipart/form-data; boundary=")
    assert b'name="room"' in request["body"]
    assert b"living room" in request["body"]


def test_postman_resolution_honors_nested_and_path_variables():
    collection = {
        "info": {"name": "Path variables"},
        "variable": [
            {"key": "host", "value": "192.0.2.9"},
            {"key": "base", "value": "https://{{host}}:7345"},
        ],
        "item": [{
            "name": "Device",
            "request": {
                "method": "GET",
                "url": {
                    "raw": "{{base}}/api/devices/:deviceId",
                    "variable": [{"key": "deviceId", "value": "living room/1"}],
                },
            },
        }],
    }
    payload, summary = device_postman.validate_and_summarize(collection)
    request = device_postman.resolve_requests(payload)[0]

    assert request["url"] == "https://192.0.2.9:7345/api/devices/living%20room%2F1"
    assert request["unresolved_variables"] == []
    assert summary["port_hints"] == [7345]


def test_postman_rejects_empty_and_oversized_request_inventories():
    with pytest.raises(device_postman.PostmanCollectionError, match="contains no requests"):
        device_postman.validate_and_summarize({"info": {"name": "Empty"}, "item": []})
    collection = {"info": {"name": "Large"}, "item": [
        {"name": str(index), "request": {"method": "GET", "url": f"http://tv/{index}"}}
        for index in range(device_postman.MAX_REQUESTS + 1)
    ]}
    with pytest.raises(device_postman.PostmanCollectionError, match="request limit"):
        device_postman.validate_and_summarize(collection)


def test_postman_request_cap_boundary_is_2000():
    assert device_postman.MAX_REQUESTS == 2000
    collection = {"info": {"name": "Boundary"}, "item": [
        {"name": str(index), "request": {"method": "GET", "url": f"http://tv/{index}"}}
        for index in range(device_postman.MAX_REQUESTS)
    ]}
    payload, summary = device_postman.validate_and_summarize(collection)
    assert summary["request_count"] == device_postman.MAX_REQUESTS
    assert len(device_postman.resolve_requests(payload)) == device_postman.MAX_REQUESTS


def test_imported_requests_are_pinned_skip_mutations_and_never_follow_external_hosts(monkeypatch):
    calls = []

    async def fake_request(**kwargs):
        calls.append(kwargs)
        return {"status": 200, "headers": {"content-type": "application/json"}, "body": b'{"ok":true}', "truncated": False, "elapsed_ms": 1.0}

    monkeypatch.setattr(device_web, "_request", fake_request)
    async def trusted_tls(**_kwargs):
        return {"trusted": True, "verification_error": None}
    monkeypatch.setattr(device_web, "_assess_tls_trust", trusted_tls)
    payload, _ = device_postman.validate_and_summarize(
        _collection(), {"values": [{"key": "token", "value": "top-secret-token"}]},
    )
    result = asyncio.run(device_web.run_pinned_device_web_scan({
        "origin": "https://192.0.2.10:3001",
        "connect_address": "192.0.2.10",
        "port": 3001,
        "host_header": "192.0.2.10:3001",
    }, profile="quick", request_collections=[{"collection_id": "c1", "name": "TV API", "payload": payload}], default_origin=True))
    imported = result["device_web"]["imported_requests"]
    assert imported["executed"] == 1
    assert any(row["reason"] == "state_changing_request_not_confirmed" for row in imported["skipped_requests"])
    assert all(call["connect_address"] == "192.0.2.10" for call in calls)
    assert "top-secret-token" not in str(result)


def test_external_collection_host_is_blocked(monkeypatch):
    calls = []

    async def forbidden(**kwargs):
        calls.append(kwargs)
        if kwargs.get("path") == "/api":
            raise AssertionError("external request must not execute")
        return {"status": 200, "headers": {}, "body": b"", "truncated": False, "elapsed_ms": 1.0}

    monkeypatch.setattr(device_web, "_request", forbidden)
    collection = {"info": {"name": "External"}, "item": [{"name": "No", "request": {"method": "GET", "url": "https://evil.example/api"}}]}
    payload, _ = device_postman.validate_and_summarize(collection)
    result = asyncio.run(device_web.run_pinned_device_web_scan({
        "origin": "https://192.0.2.10:3001", "connect_address": "192.0.2.10", "port": 3001,
    }, profile="quick", request_collections=[{"collection_id": "c1", "payload": payload}], default_origin=True))
    assert result["device_web"]["imported_requests"]["executed"] == 0
    assert result["device_web"]["imported_requests"]["skipped_requests"][0]["reason"] == "external_host_blocked"
    assert all(call.get("path") != "/api" for call in calls)


def test_state_changing_authority_is_visible_in_child_provenance(monkeypatch):
    async def fake_request(**_kwargs):
        return {"status": 204, "headers": {}, "body": b"", "truncated": False, "elapsed_ms": 1.0}

    monkeypatch.setattr(device_web, "_request", fake_request)
    collection = {
        "info": {"name": "Mutation"},
        "item": [{"name": "Update", "request": {"method": "PATCH", "url": "https://192.0.2.10:3001/api/name"}}],
    }
    payload, _ = device_postman.validate_and_summarize(collection)
    result = asyncio.run(device_web.run_pinned_device_web_scan({
        "origin": "https://192.0.2.10:3001", "connect_address": "192.0.2.10", "port": 3001,
    }, profile="quick", request_collections=[{"collection_id": "c1", "payload": payload}],
       allow_state_changing_requests=True, default_origin=True))

    assert result["device_web"]["imported_requests"]["executed"] == 1
    assert result["scan_metadata"]["active_testing"] is True
    assert result["scan_metadata"]["state_changing_requests_authorized"] is True


def test_untrusted_tls_withholds_imported_secrets_until_operator_override(monkeypatch):
    calls = []

    async def fake_request(**kwargs):
        calls.append(kwargs)
        return {"status": 200, "headers": {}, "body": b"ok", "truncated": False, "elapsed_ms": 1.0}

    async def untrusted_tls(**_kwargs):
        return {"trusted": False, "verification_error": "self-signed certificate"}

    monkeypatch.setattr(device_web, "_request", fake_request)
    monkeypatch.setattr(device_web, "_assess_tls_trust", untrusted_tls)
    payload, _ = device_postman.validate_and_summarize(
        _collection(), {"values": [{"key": "token", "value": "top-secret-token"}]},
    )
    origin = {"origin": "https://192.0.2.10:3001", "connect_address": "192.0.2.10", "port": 3001}
    bound = [{"collection_id": "c1", "payload": payload}]

    withheld = asyncio.run(device_web.run_pinned_device_web_scan(
        origin, profile="quick", request_collections=bound, default_origin=True,
    ))
    assert withheld["device_web"]["imported_requests"]["executed"] == 0
    assert any(
        item["reason"] == "untrusted_tls_credentials_not_confirmed"
        for item in withheld["device_web"]["imported_requests"]["skipped_requests"]
    )
    assert not any(call.get("path", "").startswith("/api/status") for call in calls)

    calls.clear()
    allowed = asyncio.run(device_web.run_pinned_device_web_scan(
        origin, profile="quick", request_collections=bound, default_origin=True,
        allow_untrusted_tls_credentials=True,
    ))
    assert allowed["device_web"]["imported_requests"]["executed"] == 1
    assert any(item["title"] == "Sensitive API request sent over unverified TLS" for item in allowed["findings"])
    assert any(call.get("path", "").startswith("/api/status") for call in calls)


def test_postman_redacts_secret_path_segments_names_and_bounds_expansion():
    secret = "aabbccddeeff00112233445566778899"
    collection = {
        "info": {"name": "Path secrets"},
        "item": [{
            "name": f"Request {secret}",
            "request": {"method": "GET", "url": f"https://tv.local/api/token/{secret}"},
        }],
    }
    _payload, summary = device_postman.validate_and_summarize(collection)
    assert secret not in str(summary)
    assert "<redacted>" in summary["requests"][0]["url"]

    expanding = {
        "info": {"name": "Expansion"},
        "variable": [
            {"key": "seed", "value": "x" * 200_000},
            {"key": "double", "value": "{{seed}}{{seed}}{{seed}}"},
        ],
        "item": [{"name": "Status", "request": {"method": "GET", "url": "http://tv/{{double}}"}}],
    }
    with pytest.raises(device_postman.PostmanCollectionError, match="size limit"):
        device_postman.validate_and_summarize(expanding)


def test_non_ascii_request_ids_match_preview_and_worker_resolution():
    collection = {
        "info": {"name": "Unicode"},
        "item": [{"name": "Télécommande", "request": {"method": "GET", "url": "http://tv.local/état"}}],
    }
    payload, summary = device_postman.validate_and_summarize(collection)
    assert summary["requests"][0]["id"] == device_postman.resolve_requests(payload)[0]["id"]


def test_postman_preserves_repeated_query_and_header_values_for_exact_replay():
    collection = {
        "info": {"name": "Repeated wire fields"},
        "item": [{
            "name": "Repeated",
            "request": {
                "method": "GET",
                "url": "https://tv.local/items?tag=one&tag=two&empty=",
                "header": [
                    {"key": "X-Trace", "value": "first"},
                    {"key": "X-Trace", "value": "second"},
                ],
            },
        }],
    }

    payload, _summary = device_postman.validate_and_summarize(collection)
    request = device_postman.resolve_requests(payload)[0]

    assert request["url"].endswith("?tag=one&tag=two&empty=")
    assert request["header_items"] == [
        ("X-Trace", "first"),
        ("X-Trace", "second"),
    ]
    # Compatibility consumers still see the final value, but the replay plan
    # consumes ``header_items`` as the authoritative ordered representation.
    assert request["headers"]["X-Trace"] == "second"


def test_postman_preserves_urlencoded_json_graphql_and_multipart_wire_modes():
    collection = {
        "info": {"name": "Body modes"},
        "item": [
            {"name": "Form", "request": {
                "method": "POST", "url": "https://tv.local/form",
                "body": {"mode": "urlencoded", "urlencoded": [
                    {"key": "tag", "value": "one"},
                    {"key": "tag", "value": "two"},
                ]},
            }},
            {"name": "JSON", "request": {
                "method": "POST", "url": "https://tv.local/json",
                "body": {"mode": "raw", "raw": '{"exact":true}',
                         "options": {"raw": {"language": "json"}}},
            }},
            {"name": "GraphQL", "request": {
                "method": "POST", "url": "https://tv.local/graphql",
                "body": {"mode": "graphql", "graphql": {
                    "query": "query Q($id: ID!) { item(id: $id) { id } }",
                    "variables": '{"id":"7"}',
                }},
            }},
            {"name": "Multipart", "request": {
                "method": "POST", "url": "https://tv.local/multipart",
                "body": {"mode": "formdata", "formdata": [
                    {"key": "note", "value": "exact", "type": "text"},
                ]},
            }},
        ],
    }

    payload, _summary = device_postman.validate_and_summarize(collection)
    form, json_request, graphql, multipart = device_postman.resolve_requests(payload)

    assert form["body"] == b"tag=one&tag=two"
    assert form["body_mode"] == "application/x-www-form-urlencoded"
    assert json_request["body"] == b'{"exact":true}'
    assert json_request["body_mode"] == "application/json"
    assert graphql["body"] == (
        b'{"query":"query Q($id: ID!) { item(id: $id) { id } }",'
        b'"variables":{"id":"7"}}'
    )
    assert graphql["body_mode"] == "application/json"
    assert multipart["body_mode"].startswith("multipart/form-data; boundary=")
    assert b'name="note"' in multipart["body"]
