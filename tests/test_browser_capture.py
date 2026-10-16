"""Browser capture without a database: the flow contract, scope, caps, masking and the batch
body limit. Unit fixtures only; tests/test_browser_capture_postgres.py runs the routes."""
from __future__ import annotations

import asyncio
import base64
import json

import pytest
from pydantic import ValidationError

from api.capture.flows import (
    MAX_FLOWS_PER_BATCH,
    MAX_RESPONSE_BODY_BYTES,
    MAX_SCRIPT_BODY_BYTES,
    CaptureBatch,
    CaptureCreate,
    CaptureFlow,
    bounded_body,
    capture_limits,
    flow_origin,
    flow_tags,
    har_entry,
    in_scope,
    public_capture_state,
)
from api.public_api_contract import CAPTURE_BATCH_BODY_LIMIT, PublicV2BodyLimitMiddleware
from scanner.scanner_tools.device_request_formats import _resolve_har
from scanner.scanner_tools.request_collections import index_appended_har_entries

ORIGINS = ["https://app.example.test"]


@pytest.mark.parametrize(("url", "origin"), [
    ("https://APP.example.test:443/a?b=c", "https://app.example.test"),
    ("https://user:pw@app.example.test/", "https://app.example.test"),
    ("wss://app.example.test/socket", "https://app.example.test"),
    ("http://app.example.test:8080/", "http://app.example.test:8080"),
    ("data:text/plain,hi", None),
    ("blob:https://app.example.test/1", None),
    ("https://[::1]:8443/x", "https://[::1]:8443"),
])
def test_flow_origin(url, origin):
    assert flow_origin(url) == origin


@pytest.mark.parametrize(("url", "inside"), [
    ("https://app.example.test/api", True),
    ("wss://app.example.test/ws", True),
    ("http://app.example.test/api", False),          # another scheme
    ("https://app.example.test:8443/api", False),    # another port
    ("https://evil.example.test/api", False),
    ("https://app.example.test.evil.test/api", False),
    ("not a url", False),
])
def test_scope_is_the_exact_binding_origin(url, inside):
    assert in_scope(url, ORIGINS) is inside


def test_batch_contract_bounds():
    with pytest.raises(ValidationError):
        CaptureBatch(seq=0)
    with pytest.raises(ValidationError):
        CaptureBatch.model_validate({"seq": 1, "flows": [{"method": "GET", "url": "https://a"}] * (MAX_FLOWS_PER_BATCH + 1)})
    with pytest.raises(ValidationError):
        CaptureBatch.model_validate({"seq": 1, "flows": [{"method": "GET", "url": "https://a", "extra": 1}]})
    with pytest.raises(ValidationError):
        CaptureFlow(method="GET", url="https://a", websocket_frames=[{"direction": "sent"}] * 51)
    with pytest.raises(ValidationError):
        CaptureCreate(target_id="x", target_url="https://a")
    with pytest.raises(ValidationError):
        CaptureCreate()
    assert capture_limits()["max_batch_bytes"] == CAPTURE_BATCH_BODY_LIMIT == 16 * 1024 * 1024


def test_bodies_are_cut_to_their_caps_with_a_flag():
    assert bounded_body("abc", None, 10) == ("abc", None, False, 3)
    text, encoding, cut, size = bounded_body("é" * 10, None, 5)
    assert (text, encoding, cut, size) == ("éé", None, True, 20)
    raw = bytes(range(256)) * 4
    text, encoding, cut, size = bounded_body(base64.b64encode(raw).decode(), "base64", 100)
    assert base64.b64decode(text) == raw[:100] and encoding == "base64" and cut and size == 1024
    assert bounded_body("%%%not base64", "base64", 10) == (None, None, True, 0)


def test_script_bodies_have_the_lower_cap():
    script = CaptureFlow(method="GET", url="https://app.example.test/app.js", resource_type="Script",
                         response_body="x" * (MAX_SCRIPT_BODY_BYTES + 10))
    page = CaptureFlow(method="GET", url="https://app.example.test/", resource_type="Document",
                       response_body="x" * (MAX_SCRIPT_BODY_BYTES + 10))
    script_entry, _ = har_entry(script)
    page_entry, _ = har_entry(page)
    assert len(script_entry["response"]["content"]["text"]) == MAX_SCRIPT_BODY_BYTES
    assert script_entry["_responseBodyTruncated"] is True
    assert len(page_entry["response"]["content"]["text"]) == MAX_SCRIPT_BODY_BYTES + 10
    assert MAX_SCRIPT_BODY_BYTES < MAX_RESPONSE_BODY_BYTES


SECRETS = ("sid-secret-cookie", "eyJhbGciOiJIUzI1NiJ9.payload.sig", "hunter2-password", "tok-in-query-123")


def _secret_flow(**overrides):
    values = {
        "method": "post", "url": f"wss://app.example.test/api/login?access_token={SECRETS[3]}&q=1",
        "resource_type": "WebSocket", "status": 101,
        "request_headers": [{"name": "Cookie", "value": f"sid={SECRETS[0]}"},
                            {"name": "Authorization", "value": f"Bearer {SECRETS[1]}"},
                            {"name": ":authority", "value": "app.example.test"},
                            {"name": "Content-Type", "value": "application/json"}],
        "request_body": json.dumps({"email": "a@example.test", "password": SECRETS[2]}),
        "response_headers": [{"name": "Set-Cookie", "value": f"sid={SECRETS[0]}"}],
        "websocket_frames": [{"direction": "sent", "preview": "hello"}],
    }
    values.update(overrides)
    return CaptureFlow.model_validate(values)


def test_har_entry_keeps_values_for_the_encrypted_document_only():
    entry, size = har_entry(_secret_flow())
    assert entry["request"]["url"].startswith("https://app.example.test/api/login")
    assert entry["request"]["method"] == "POST"
    assert [h["name"] for h in entry["request"]["headers"]] == ["Cookie", "Authorization", "Content-Type"]
    assert entry["_webSocketMessages"][0] == {"type": "send", "time": 0.0, "opcode": 1, "data": "hello", "_truncated": False}
    assert SECRETS[0] in json.dumps(entry) and size > 0
    assert flow_tags(_secret_flow()) == ["capture", "resource:websocket", "status:101"]


def test_metadata_only_entries_withhold_credential_headers_and_bodies():
    entry, size = har_entry(_secret_flow(), metadata_only=True)
    text = json.dumps(entry)
    assert SECRETS[0] not in text and SECRETS[1] not in text and SECRETS[2] not in text
    assert entry["_bodiesDropped"] and "postData" not in entry["request"]
    assert "_webSocketMessages" not in entry and size < 2_000


def test_index_rows_carry_no_secret_value_and_match_worker_request_ids():
    flows = [_secret_flow(), _secret_flow(url="https://app.example.test/api/items/42?page=2", method="GET",
                                         request_body=None, resource_type="Fetch", status=200)]
    entries = [har_entry(flow)[0] for flow in flows]
    rows = index_appended_har_entries(entries, start_index=7, tags=[flow_tags(flow) for flow in flows])
    text = json.dumps(rows)
    assert not [secret for secret in SECRETS if secret in text]
    assert [row["ordinal"] for row in rows] == [7, 8]
    assert rows[0]["body_field_names"] == ["email", "password"]
    assert rows[0]["name"] == "POST /api/login" and rows[1]["safe_method"] is True
    assert "access_token=%3Credacted%3E" in rows[0]["redacted_url"]
    # The whole document resolves to the same ids at the same positions.
    document = {"log": {"entries": [{"request": {"method": "GET", "url": "https://x/"}}] * 7 + entries}}
    resolved = _resolve_har(document)
    assert [item["id"] for item in resolved[7:]] == [row["request_id"] for row in rows]


def test_public_capture_state_is_counts_only():
    state = {"capture": {"schema": "browser-capture/v1", "state": "open", "last_seq": 3,
                         "allowed_origins": ORIGINS, "created_by": "someone", "unknown": "x"}}
    public = public_capture_state(state)
    assert public["state"] == "open" and public["idle_close_seconds"] == 1800
    assert "created_by" not in public and "unknown" not in public
    assert public_capture_state({"capture": {"schema": "other"}}) is None


@pytest.mark.parametrize(("path", "limit"), [
    ("/request-collections/abc/capture-batches", CAPTURE_BATCH_BODY_LIMIT),
    ("/request-collections", 64 * 1024 * 1024),
])
def test_an_oversized_batch_is_refused_with_413_before_parsing(path, limit):
    reached = []

    async def app(scope, receive, send):
        reached.append(True)

    sent = []

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {"type": "http", "method": "POST", "path": path,
             "headers": [(b"content-length", str(limit + 1).encode())]}
    asyncio.run(PublicV2BodyLimitMiddleware(app)(scope, receive, send))
    assert sent[0]["status"] == 413 and not reached
    assert json.loads(sent[1]["body"])["detail"]["max_bytes"] == limit


def test_a_failed_idle_close_does_not_stop_the_maintenance_tick(capsys):
    from api.capture.store import close_idle_captures

    class BrokenPool:
        def acquire(self):
            raise RuntimeError("database unavailable: secret-ish detail")

    assert asyncio.run(close_idle_captures(BrokenPool())) == 0
    out = capsys.readouterr().out
    assert "idle close failed: RuntimeError" in out and "secret-ish" not in out
