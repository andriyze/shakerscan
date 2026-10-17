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
    ("https://user:pw@app.example.test/", None),           # userinfo: refused, not stripped
    ("https://app.example.test\\@evil.example/", None),     # backslash in the authority
    ("https://app.example.test\\.evil.example/", None),
    ("https://app.example.test/a\\b", "https://app.example.test"),  # in the path: fine
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


def _capture_payload(entries):
    return {"format": "capture", "document": {"log": {"version": "1.2", "entries": entries}}}


def test_a_capture_replay_never_carries_a_recorded_credential():
    """Every replay consumer resolves through resolve_imported_requests: a capture's cookies,
    authorization, API-key and CSRF headers (and a ;jsessionid path parameter) never leave it."""
    from scanner.scanner_tools.device_request_formats import resolve_imported_requests
    from scanner.scanner_tools.request_collections import RequestSelector, select_requests

    flow = _secret_flow(
        url="https://app.example.test/app;jsessionid=JSESSION-SECRET/items",
        request_headers=[
            {"name": "Cookie", "value": f"sid={SECRETS[0]}"},
            {"name": "Authorization", "value": f"Bearer {SECRETS[1]}"},
            {"name": "Proxy-Authorization", "value": "Basic cHJveHktc2VjcmV0"},
            {"name": "X-API-Key", "value": "api-key-secret"},
            {"name": "X-CSRF-Token", "value": "csrf-secret"},
            {"name": "X-XSRF-TOKEN", "value": "xsrf-secret"},
            {"name": "Accept", "value": "application/json"},
        ],
    )
    entry, _size = har_entry(flow)
    entry["request"]["cookies"] = [{"name": "other", "value": "cookie-array-secret"}]
    payload = _capture_payload([entry])
    recorded = ("JSESSION-SECRET", SECRETS[0], SECRETS[1], "cHJveHktc2VjcmV0", "api-key-secret",
                "csrf-secret", "xsrf-secret", "cookie-array-secret")
    for requests in (resolve_imported_requests(payload),
                     select_requests(payload, RequestSelector(safe_methods_only=False))):
        (request,) = requests
        text = json.dumps({key: value for key, value in request.items() if key != "body"})
        assert not [value for value in recorded if value in text]
        assert set(request["headers"]) == {"Accept", "Content-Type"}
        assert request["auth_type"] == "none" and request["has_sensitive_material"] is False
        assert request["url"] == "https://app.example.test/app/items"
        assert set(request["captured_credentials_withheld"]) >= {
            "cookie", "authorization", "proxy-authorization", "x-api-key", "x-csrf-token", "x-xsrf-token",
        }
        # The password typed into the recorded login form is emptied; other fields stay.
        assert json.loads(request["body"]) == {"email": "a@example.test", "password": ""}
        assert request["captured_body_fields_withheld"] == ["password"]
    form = har_entry(_secret_flow(
        request_headers=[{"name": "Content-Type", "value": "application/x-www-form-urlencoded"},
                         {"name": "Content-Length", "value": "99"}],
        request_body=f"user=alice&pass_token={SECRETS[3]}&passwd={SECRETS[2]}",
    ))[0]
    (resolved_form,) = resolve_imported_requests(_capture_payload([form]))
    assert resolved_form["body"] == b"user=alice&pass_token=&passwd="
    assert "Content-Length" not in resolved_form["headers"]
    # The same document imported as an ordinary HAR is replayed as the operator supplied it.
    har = resolve_imported_requests({"format": "har", "document": payload["document"]})
    assert har[0]["headers"]["Cookie"] == f"sid={SECRETS[0]}"


def test_the_document_cap_counts_stored_bytes_not_characters():
    small = har_entry(_secret_flow(request_body=None, websocket_frames=[]))[1]
    nul_heavy = har_entry(_secret_flow(request_body="\x00" * 10_000, websocket_frames=[]))[1]
    # A NUL is one character but six bytes (\u0000) in the stored JSON.
    assert nul_heavy - small >= 60_000
    entry, size = har_entry(_secret_flow(request_body="é" * 1_000, websocket_frames=[]))
    from api.capture.flows import stored_size
    assert size == stored_size(entry) + 1


def test_a_lone_surrogate_is_a_validation_error_not_a_server_error():
    with pytest.raises(ValidationError):
        CaptureBatch.model_validate({"seq": 1, "flows": [{"method": "GET", "url": "https://app.example.test/\ud800"}]})
    with pytest.raises(ValidationError):
        CaptureBatch.model_validate({"seq": 1, "flows": [{
            "method": "GET", "url": "https://app.example.test/",
            "request_headers": [{"name": "X", "value": "\udfff"}]}]})
    with pytest.raises(ValidationError):
        CaptureCreate.model_validate({"target_url": "https://app.example.test/", "name": "a\ud83d"})
    assert CaptureBatch.model_validate({"seq": 1, "flows": [{"method": "GET", "url": "https://app.example.test/\U0001F600"}]})


def test_a_batch_digest_ignores_drop_counts_and_follows_the_flows():
    flows = [{"method": "GET", "url": "https://app.example.test/a"}]
    first = CaptureBatch.model_validate({"seq": 3, "flows": flows, "client_dropped": {"assets": 1}})
    retry = CaptureBatch.model_validate({"seq": 3, "flows": flows, "client_dropped": {"assets": 9}})
    other = CaptureBatch.model_validate({"seq": 3, "flows": [{"method": "GET", "url": "https://app.example.test/b"}]})
    assert first.digest() == retry.digest() != other.digest()


def test_an_open_capture_is_refused_for_selection_with_a_clear_409():
    from fastapi import HTTPException

    from api.capture.store import refuse_open_capture

    refuse_open_capture(None)
    refuse_open_capture({"format": "har", "metadata_json": {}})
    refuse_open_capture({"format": "capture", "capture_state": "closed"})
    for row in ({"id": "c1", "format": "capture", "capture_state": "open"},
                {"id": "c1", "format": "capture", "metadata_json": json.dumps({"capture": {"state": "open"}})}):
        with pytest.raises(HTTPException) as refused:
            refuse_open_capture(row)
        assert refused.value.status_code == 409
        assert refused.value.detail["error"] == "capture_open"
        assert "close it first" in refused.value.detail["message"]


@pytest.mark.parametrize(("query", "kept", "withheld"), [
    ("token=t0k3nValue&page=2", "page=2", ["token"]),
    ("access_token=abc&api_key=k&sig=s&session=x&code=c&auth=a&q=shoes",
     "q=shoes", ["access_token", "api_key", "sig", "session", "code", "auth"]),
    ("next=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl&lang=en", "lang=en", ["next"]),
    ("ref=Zx9Qp2Lm7Rt4Wv8Yb3Nc&sort=name", "sort=name", ["ref"]),
    ("id=0123456789abcdef0123456789abcdef&view=full", "view=full", ["id"]),
    ("page=2&sort=price", "page=2&sort=price", []),
])
def test_a_capture_replay_withholds_credential_query_parameters(query, kept, withheld):
    from scanner.scanner_tools.device_request_formats import resolve_imported_requests
    from scanner.scanner_tools.request_replay import build_selected_replay_plan
    from scanner.scanner_tools.request_collections import RequestSelector

    entry = har_entry(CaptureFlow.model_validate(
        {"method": "GET", "url": f"https://app.example.test/api/items?{query}"}))[0]
    payload = _capture_payload([entry])
    (request,) = resolve_imported_requests(payload)
    assert request["url"] == "https://app.example.test/api/items" + (f"?{kept}" if kept else "")
    assert request["captured_query_parameters_withheld"] == withheld
    assert request["captured_withheld"] == [f"query:{name}" for name in withheld]
    plan = build_selected_replay_plan(
        payload, RequestSelector(safe_methods_only=False), allowed_origins=["https://app.example.test"])
    (public,) = plan.public_dict()["requests"]
    if withheld:
        assert public["captured_withheld"] == [f"query:{name}" for name in withheld]
    else:
        assert "captured_withheld" not in public
    # An ordinary HAR import keeps its query exactly.
    (har,) = resolve_imported_requests({"format": "har", "document": payload["document"]})
    assert har["url"].endswith(f"?{query}")


def test_the_replay_plan_names_every_withheld_credential():
    from scanner.scanner_tools.request_collections import RequestSelector
    from scanner.scanner_tools.request_replay import ReplayAuthorization, build_selected_replay_plan

    entry = har_entry(_secret_flow(url=f"https://app.example.test/api/login?access_token={SECRETS[3]}",
                                   websocket_frames=[]))[0]
    plan = build_selected_replay_plan(
        _capture_payload([entry]), RequestSelector(safe_methods_only=False),
        allowed_origins=["https://app.example.test"],
        authorization=ReplayAuthorization(safe_authentication_only=True))
    (public,) = plan.public_dict()["requests"]
    assert set(public["captured_withheld"]) == {
        "header:cookie", "header:authorization", "query:access_token", "body:password"}
    assert SECRETS[3] not in json.dumps(plan.requests[0].wire_dict(), default=str)


def _replayed_body(body, content_type):
    from scanner.scanner_tools.device_request_formats import resolve_imported_requests

    entry = har_entry(CaptureFlow.model_validate({
        "method": "POST", "url": "https://app.example.test/login", "request_body": body,
        "request_headers": [{"name": "Content-Type", "value": content_type}],
    }))[0]
    (request,) = resolve_imported_requests(_capture_payload([entry]))
    return request["body"], request["captured_body_fields_withheld"]


@pytest.mark.parametrize(("body", "content_type", "expected", "withheld"), [
    ("user=alice&pass=hunter2&pwd=hunter3", "application/x-www-form-urlencoded",
     b"user=alice&pass=&pwd=", ["pass", "pwd"]),
    ("user=alice&new_pin=1234&compass=north", "application/x-www-form-urlencoded",
     b"user=alice&new_pin=&compass=north", ["new_pin"]),
    (json.dumps({"login": {"user": "alice", "pass": "hunter2"}}), "application/json",
     {"login": {"user": "alice", "pass": ""}}, ["pass"]),
    (json.dumps({"passwords": ["hunter2", "hunter3"], "otp": 123456, "spinner": "x"}), "application/json",
     {"passwords": ["", ""], "otp": "", "spinner": "x"}, ["otp", "passwords"]),
    (json.dumps({"credentials": {"secret": {"value": "hunter2"}}}), "application/json",
     {"credentials": {"secret": {"value": ""}}}, ["credentials"]),
    ("passphrase=correct horse", "text/plain", b"", ["*"]),        # unparsed, names a secret
    ("{not json but password=hunter2", "application/json", b"", ["*"]),
    ("hello world", "text/plain", b"hello world", []),
])
def test_a_capture_replay_empties_every_recorded_password_shape(body, content_type, expected, withheld):
    replayed, names = _replayed_body(body, content_type)
    assert names == withheld
    assert (json.loads(replayed) if isinstance(expected, dict) else replayed) == expected
    assert b"hunter2" not in replayed and b"hunter3" not in replayed


def test_a_capture_replay_empties_secret_multipart_parts():
    boundary = "----WebKitFormBoundaryX1"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\nalice\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n"
            f"--{boundary}--\r\n")
    replayed, names = _replayed_body(body, f"multipart/form-data; boundary={boundary}")
    assert names == ["password"] and b"hunter2" not in replayed and b"alice" in replayed
    assert replayed.count(boundary.encode()) == 3
    broken, broken_names = _replayed_body("--x\r\nname=\"password\" hunter2", "multipart/form-data; boundary=x")
    assert broken == b"" and broken_names == ["*"]


def test_signature_headers_and_bare_token_parameters_are_withheld():
    from scanner.scanner_tools.device_request_formats import resolve_imported_requests

    entry = har_entry(CaptureFlow.model_validate({
        "method": "GET",
        "url": "https://app.example.test/hook?eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl&view=1",
        "request_headers": [{"name": "X-Signature", "value": "sig-secret"},
                            {"name": "X-Hub-Signature-256", "value": "sha256=hub-secret"},
                            {"name": "Accept", "value": "*/*"}],
    }))[0]
    (request,) = resolve_imported_requests(_capture_payload([entry]))
    assert set(request["headers"]) == {"Accept"}
    assert request["url"] == "https://app.example.test/hook?view=1"


def test_a_capture_relabelled_as_har_is_still_stripped():
    """The log keeps its capture marker through re-validation as HAR."""
    from api.capture.flows import empty_capture_document
    from scanner.scanner_tools.device_request_formats import resolve_imported_requests

    document = empty_capture_document()["document"]
    document["log"]["entries"].append(har_entry(_secret_flow(websocket_frames=[]))[0])
    (request,) = resolve_imported_requests({"format": "har", "document": document})
    assert "Cookie" not in request["headers"] and "Authorization" not in request["headers"]
    assert request["captured_withheld"]


def test_device_scans_refuse_an_open_capture():
    from fastapi import HTTPException

    from api.devices import router as devices_router

    class Conn:
        def __init__(self, state):
            self.state = state

        async def fetch(self, sql, *args):
            if "device_request_collections" in sql:
                return [{"id": args[1][0], "name": "Walk", "format": "capture", "document_sha256": "a" * 64,
                         "summary_json": {}}]
            return [{"id": args[0][0], "format": "capture", "capture_state": self.state}]

    collection = "8f0d1f60-49c2-4d39-9d7f-4b7a1b0e3c11"
    device = "1f0d1f60-49c2-4d39-9d7f-4b7a1b0e3c11"
    import uuid
    with pytest.raises(HTTPException) as refused:
        asyncio.run(devices_router._validate_device_request_collection_refs(Conn("open"), uuid.UUID(device), [collection]))
    assert refused.value.status_code == 409 and refused.value.detail["error"] == "capture_open"
    refs = asyncio.run(devices_router._validate_device_request_collection_refs(Conn("closed"), uuid.UUID(device), [collection]))
    assert refs[0]["collection_id"] == collection


def test_assembly_peak_memory_is_bounded(monkeypatch):
    """Closing assembles the batches by splicing their canonical texts: no parse, one serialized
    text, and the digest is hashed piece by piece. With identity crypto (here) the peak stays
    under 4x the document. Measured with real Fernet for a 20,000-flow, 52 MiB document: peak
    ~455 MiB traced (8.7x), most of it the copies Fernet makes inside encrypt_secret (encode,
    padding, ciphertext, base64, decode), which this change does not touch."""
    import tracemalloc

    from api.capture import store

    monkeypatch.setattr(store, "decrypt_secret", lambda value: value[len("enc:fernet:"):])
    monkeypatch.setattr(store, "encrypt_secret", lambda text: "enc:fernet:" + text)
    flows = [CaptureFlow.model_validate({"method": "GET", "url": f"https://app.example.test/p/{n}",
                                         "response_body": "x" * 2_000}) for n in range(2_000)]
    entries = [har_entry(flow)[0] for flow in flows]
    batches = [store._encrypt_text(store._canonical(entries[i:i + 50])) for i in range(0, len(entries), 50)]
    document_bytes = sum(len(batch) for batch in batches)
    tracemalloc.start()
    encrypted, digest = store._assemble(batches)
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    payload = json.loads(encrypted[len("enc:fernet:"):])
    assert len(payload["document"]["log"]["entries"]) == 2_000
    assert digest == store._digest(payload)  # the digest every consumer recomputes
    assert peak < 4 * document_bytes, (peak, document_bytes)


class _FinalizeConn:
    async def fetch(self, sql, *args):
        return []

    async def fetchrow(self, sql, *args):
        return {"id": args[0]}

    async def execute(self, sql, *args):
        return "UPDATE 0"


def test_two_concurrent_closes_never_assemble_at_once(monkeypatch):
    """One assembly per API process: the second close waits for the first, a close that would
    wait too long answers 503 with Retry-After, and the idle close never queues."""
    import time as _time

    from api.capture import store

    active = {"now": 0, "max": 0}

    def slow_assemble(batches):
        active["now"] += 1
        active["max"] = max(active["max"], active["now"])
        _time.sleep(0.2)
        active["now"] -= 1
        return "enc:fernet:x", "0" * 64

    monkeypatch.setattr(store, "_assemble", slow_assemble)

    def close(reason, wait=None):
        state = {"state": "open"}
        return store._finalize(_FinalizeConn(), {"id": reason, "db_now": __import__("datetime").datetime.now()},
                               {"capture": state}, state, reason=reason, wait_seconds=wait)

    async def scenario():
        both = await asyncio.gather(close("client"), close("deactivated"))
        assert len(both) == 2 and active["max"] == 1
        first = asyncio.create_task(close("client"))
        await asyncio.sleep(0.05)
        results = await asyncio.gather(close("idle", wait=0), close("client", wait=0.05), return_exceptions=True)
        await first
        return results

    idle, waited = asyncio.run(scenario())
    assert active["max"] == 1
    for refused in (idle, waited):
        assert isinstance(refused, store.AssemblyBusy) and refused.status_code == 503
        assert refused.headers["Retry-After"] == str(store.ASSEMBLY_RETRY_AFTER_SECONDS)
        assert refused.detail["error"] == "capture_assembly_busy"
