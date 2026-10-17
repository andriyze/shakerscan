"""`shakerscan record` without a browser: CDP events to flows, filtering, batching and retried
upload. Unit fixtures: CDP events and the capture API are scripted. The last test records a
tiny local app in headless Chromium when Playwright and its browser are installed."""

from __future__ import annotations

import argparse
import base64
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client" / "src"))

from shakerscan import _capture, cli, record  # noqa: E402
from shakerscan._capture import (  # noqa: E402
    Batcher,
    CaptureStopped,
    CaptureUploader,
    CdpFlowRecorder,
    UploadError,
    cap_body,
    classify,
    origin_of,
)

ORIGINS = ["https://app.example.test"]


def sent(recorder, request_id, url, *, method="GET", kind="XHR", post=None, has_post=False, redirect=None, ts=1.0):
    request = {"url": url, "method": method, "headers": {"Accept": "*/*"}}
    if post is not None:
        request["postData"] = post
    if has_post:
        request["hasPostData"] = True
    params = {"requestId": request_id, "request": request, "type": kind, "timestamp": ts, "wallTime": 1_760_000_000.5}
    if redirect:
        params["redirectResponse"] = redirect
    return recorder.handle("Network.requestWillBeSent", params)


def test_a_request_becomes_one_flow_with_wire_headers_and_bodies():
    recorder = CdpFlowRecorder()
    assert sent(recorder, "1", "https://app.example.test/api/login#frag", method="POST",
                post='{"username":"a","password":"p"}') == []
    recorder.handle("Network.requestWillBeSentExtraInfo", {"requestId": "1", "headers": {
        "Cookie": "sid=abc", ":authority": "app.example.test", "Content-Type": "application/json"}})
    recorder.handle("Network.responseReceivedExtraInfo", {"requestId": "1", "headers": {"Set-Cookie": "a=1\nb=2"}})
    recorder.handle("Network.responseReceived", {"requestId": "1", "type": "Fetch", "response": {
        "status": 200, "statusText": "OK", "mimeType": "application/json", "headers": {"content-type": "x"}}})
    assert recorder.handle("Network.loadingFinished", {"requestId": "1", "timestamp": 1.25}) == [("fetch", "1", False)]
    flow = recorder.complete("1", body='{"ok":true}')
    assert flow["url"] == "https://app.example.test/api/login" and flow["method"] == "POST"
    assert flow["resource_type"] == "fetch" and flow["status"] == 200 and flow["duration_ms"] == 250.0
    assert {"name": "Cookie", "value": "sid=abc"} in flow["request_headers"]
    assert not any(h["name"].startswith(":") for h in flow["request_headers"])
    assert [h["value"] for h in flow["response_headers"]] == ["a=1", "b=2"]
    assert flow["request_body"] == '{"username":"a","password":"p"}' and flow["response_body"] == '{"ok":true}'
    assert flow["started_at"].startswith("2025-10-09T") and recorder.pending == {}


def test_redirect_hops_post_data_failures_and_drain():
    recorder = CdpFlowRecorder()
    sent(recorder, "r", "https://app.example.test/old", kind="Document")
    actions = sent(recorder, "r", "https://app.example.test/new", kind="Document",
                   redirect={"status": 302, "statusText": "Found", "headers": {"Location": "/new"}})
    assert actions[0][0] == "flow" and actions[0][1]["status"] == 302 and actions[0][1]["url"].endswith("/old")
    sent(recorder, "p", "https://app.example.test/upload", method="POST", has_post=True)
    recorder.handle("Network.responseReceived", {"requestId": "p", "response": {"status": 201}})
    assert recorder.handle("Network.loadingFinished", {"requestId": "p"}) == [("fetch", "p", True)]
    assert recorder.complete("p", post_data="a=1")["request_body"] == "a=1"
    sent(recorder, "f", "https://app.example.test/blocked")
    failed = recorder.handle("Network.loadingFailed", {"requestId": "f", "errorText": "net::ERR_BLOCKED"})
    assert failed[0][1]["url"].endswith("/blocked") and "status" not in failed[0][1]
    recorder.handle("Network.responseReceived", {"requestId": "r", "response": {"status": 200}})
    sent(recorder, "never", "https://app.example.test/hang")
    drained = recorder.drain()
    assert [flow["url"] for flow in drained] == ["https://app.example.test/new"]
    assert recorder.dropped_unfinished == 1


def test_websocket_frames_are_capped_and_previewed():
    recorder = CdpFlowRecorder()
    recorder.handle("Network.webSocketCreated", {"requestId": "w", "url": "wss://app.example.test/socket"})
    recorder.handle("Network.webSocketWillSendHandshakeRequest", {"requestId": "w", "request": {"headers": {"Cookie": "s=1"}}})
    recorder.handle("Network.webSocketHandshakeResponseReceived", {"requestId": "w", "response": {"status": 101}})
    for index in range(60):
        recorder.handle("Network.webSocketFrameSent" if index % 2 else "Network.webSocketFrameReceived",
                        {"requestId": "w", "timestamp": float(index), "response": {"opcode": 1, "payloadData": "é" * 3000}})
    [(kind, flow)] = recorder.handle("Network.webSocketClosed", {"requestId": "w"})
    assert kind == "flow" and flow["status"] == 101 and len(flow["websocket_frames"]) == 50
    frame = flow["websocket_frames"][0]
    assert frame["direction"] == "received" and frame["truncated"] and len(frame["preview"].encode()) <= 4096
    assert classify(flow, ORIGINS, include_assets=False) == "upload"


def test_pending_requests_are_bounded(monkeypatch):
    monkeypatch.setattr(_capture, "MAX_PENDING_REQUESTS", 3)
    recorder = CdpFlowRecorder()
    for index in range(5):
        sent(recorder, str(index), f"https://app.example.test/{index}")
    assert list(recorder.pending) == ["2", "3", "4"] and recorder.dropped_unfinished == 2


@pytest.mark.parametrize(("flow", "verdict"), [
    ({"url": "https://app.example.test/api", "resource_type": "xhr"}, "upload"),
    ({"url": "https://APP.example.test:443/app.js", "resource_type": "script"}, "upload"),
    ({"url": "https://app.example.test/logo.png", "resource_type": "image"}, "asset"),
    ({"url": "https://app.example.test/x", "resource_type": "other", "response_mime_type": "text/css"}, "asset"),
    ({"url": "https://app.example.test/f.woff2", "resource_type": "font"}, "asset"),
    ({"url": "https://cdn.example.test/lib.js", "resource_type": "script"}, "out_of_scope"),
    ({"url": "http://app.example.test/api", "resource_type": "xhr"}, "out_of_scope"),
    ({"url": "data:image/png;base64,AA", "resource_type": "image"}, "out_of_scope"),
])
def test_classify(flow, verdict):
    assert classify(flow, ORIGINS, include_assets=False) == verdict


def test_include_assets_keeps_in_scope_assets_only():
    image = {"url": "https://app.example.test/logo.png", "resource_type": "image"}
    assert classify(image, ORIGINS, include_assets=True) == "upload"
    assert classify({**image, "url": "https://cdn.example.test/logo.png"}, ORIGINS, include_assets=True) == "out_of_scope"
    assert origin_of("wss://App.example.test:443/s") == "https://app.example.test"


def test_bodies_are_capped_and_scripts_have_the_lower_cap():
    assert cap_body("x" * 10, base64_encoded=False, cap=4) == ("xxxx", None, True)
    binary = bytes(range(200, 256)) * 10
    text, encoding, cut = cap_body(base64.b64encode(binary).decode(), base64_encoded=True, cap=16)
    assert encoding == "base64" and base64.b64decode(text) == binary[:16] and cut
    recorder = CdpFlowRecorder({"max_script_body_bytes": 8, "max_response_body_bytes": 32})
    for request_id, kind in (("s", "Script"), ("d", "Document")):
        sent(recorder, request_id, "https://app.example.test/" + request_id, kind=kind)
        recorder.handle("Network.responseReceived", {"requestId": request_id, "response": {"status": 200}})
    assert len(recorder.complete("s", body="y" * 100)["response_body"]) == 8
    assert len(recorder.complete("d", body="y" * 100)["response_body"]) == 32


def test_batcher_releases_by_count_age_and_encoded_size():
    batcher = Batcher(max_flows=3, max_seconds=2.0, max_bytes=200_000)
    for index in range(4):
        batcher.add({"url": f"https://a/{index}"}, now=0.0)
    assert [len(batch) for batch in batcher.take(0.5)] == [3]
    assert not batcher.due(1.0) and batcher.due(2.0)
    assert [len(batch) for batch in batcher.take(2.0)] == [1]
    sized = Batcher(max_flows=50, max_bytes=_capture.BATCH_ENVELOPE_BYTES + 3_000)
    for _ in range(3):
        sized.add({"response_body": "z" * 1_200}, now=0.0)
    batches = sized.take(0.0, force=True)
    assert [len(batch) for batch in batches] == [2, 1]
    assert all(_capture.encoded_size({"seq": 1, "flows": batch}) < 3_000 + _capture.BATCH_ENVELOPE_BYTES
               for batch in batches)


class FakeCaptureServer:
    """Applies batches by seq like the engine; can lose an answer after applying."""

    def __init__(self, failures=()):
        self.applied: dict[int, list] = {}
        self.failures = list(failures)
        self.calls: list[int] = []
        self.closed = False

    def post(self, path, payload, *, body=None):
        if body is not None:
            assert json.loads(body) == payload  # the bytes sent are the payload
        seq = payload["seq"]
        self.calls.append(seq)
        failure = self.failures.pop(0) if self.failures else None
        if failure == "refuse":
            raise UploadError("closed", status=409, detail={"detail": {"error": "capture_closed", "closed_reason": "idle"}})
        if failure == "before":
            raise UploadError("no answer")
        if seq in self.applied:
            return {"status": "duplicate", "accepted": 0, "capture": {"flow_count": self._count()}}
        assert seq == len(self.applied) + 1, "a batch overtook an unacknowledged one"
        self.applied[seq] = payload["flows"]
        if failure == "after":
            raise UploadError("answer lost", status=502)
        return {"status": "applied", "accepted": len(payload["flows"]), "capture": {"flow_count": self._count()}}

    def _count(self):
        return sum(len(flows) for flows in self.applied.values())


def test_uploader_retries_without_losing_or_duplicating_a_batch():
    server = FakeCaptureServer(failures=["before", "after", None, None])
    sleeps = []
    uploader = CaptureUploader(server.post, "c-1", sleep=sleeps.append)
    uploader.enqueue([{"url": "1"}])
    uploader.enqueue([{"url": "2"}, {"url": "3"}])
    assert uploader.send() is True
    assert server.calls == [1, 1, 1, 2] and sleeps == [0.5, 1]
    assert {seq: len(flows) for seq, flows in server.applied.items()} == {1: 1, 2: 2}
    assert uploader.last_capture == {"flow_count": 3} and uploader.totals.retries == 2


def test_a_batch_that_never_gets_an_answer_stays_first_with_its_seq():
    server = FakeCaptureServer(failures=["before"] * 3)
    uploader = CaptureUploader(server.post, "c-1", sleep=lambda _s: None, attempts=3)
    uploader.enqueue([{"url": "1"}])
    uploader.enqueue([{"url": "2"}])
    assert uploader.send() is False and [seq for seq, _ in uploader.queue] == [1, 2]
    assert uploader.send() is True and list(server.applied) == [1, 2]


def test_a_refusal_stops_the_upload():
    uploader = CaptureUploader(FakeCaptureServer(failures=["refuse"]).post, "c-1", sleep=lambda _s: None)
    uploader.enqueue([])
    with pytest.raises(CaptureStopped, match="closed this capture \\(idle\\)"):
        uploader.send()


class FakeApi:
    def __init__(self):
        self.server = FakeCaptureServer()
        self.payloads = []

    def post(self, path, payload, *, body=None):
        self.payloads.append((path, payload))
        return self.server.post(path, payload, body=body)


CAPTURE = {"id": "c-1", "name": "Walk", "target_id": "t-1", "target_url": "https://app.example.test/",
           "allowed_origins": ORIGINS, "limits": {"max_batch_bytes": 1_000_000}}


def test_recording_filters_batches_keeps_alive_and_reports(monkeypatch):
    api = FakeApi()
    recording = record.Recording(CAPTURE, api, include_assets=False)
    monkeypatch.setattr(record.time, "monotonic", lambda: 0.0)
    recording.last_upload = 0.0
    for flow in ({"method": "GET", "url": "https://app.example.test/api/a?x=1", "resource_type": "xhr"},
                 {"method": "GET", "url": "https://other.example.test/", "resource_type": "document"},
                 {"method": "GET", "url": "https://app.example.test/a.png", "resource_type": "image"}):
        recording.offer(flow, 0.0)
    recording.pump(0.5)
    assert api.payloads == []  # not yet due
    recording.pump(2.5)
    path, payload = api.payloads[0]
    assert path == "/request-collections/c-1/capture-batches" and payload["seq"] == 1
    assert [flow["url"] for flow in payload["flows"]] == ["https://app.example.test/api/a?x=1"]
    assert payload["client_dropped"] == {"out_of_scope": 1, "assets": 1}
    recording.pump(2.5 + record.KEEPALIVE_SECONDS)
    assert api.payloads[-1][1] == {"seq": 2, "flows": [], "client_dropped": {"out_of_scope": 1, "assets": 1}}
    assert recording.finish() is True
    result = record.summary(CAPTURE, recording, {"capture": {"flow_count": 1, "endpoint_count": 1}},
                            complete=True, reason="browser closed")
    assert result["flows"]["uploaded"] == 1 and result["flows"]["dropped_assets"] == 1
    assert result["next"]["scan"] == "shakerscan scan https://app.example.test/ --collection-selection c-1"
    text = record.render(result)
    assert "1 requests uploaded" in text and "never become a credential" in text
    # Not closed: no Scan or Hunt is suggested before the close that makes the capture usable.
    still_open = record.summary(CAPTURE, recording, None, complete=True, reason="browser closed")
    assert set(still_open["next"]) == {"close", "read"}
    assert still_open["next"]["close"] == "shakerscan api POST '/request-collections/c-1/capture-close'"
    assert "close it before a Scan or Hunt" in record.render(still_open)


def test_the_api_client_never_sends_a_token_over_plain_http_to_another_host():
    with pytest.raises(record.RecordError, match="plain http"):
        record.ApiClient("http://scanner.example.test:8080", "secret")
    record.ApiClient("http://127.0.0.1:8080", "secret")
    record.ApiClient("https://scanner.example.test", "secret")


def _args(**values):
    base = {"target": "https://app.example.test", "name": None, "start_url": None, "include_assets": False,
            "json": True, "headless": True, "script": None, "timeout": None, "url": None, "token_file": None}
    return argparse.Namespace(**{**base, **values})


def test_missing_playwright_names_the_install_commands(monkeypatch):
    monkeypatch.setattr(record.importlib.util, "find_spec", lambda name: None)
    with pytest.raises(record.RecordError) as caught:
        record.cmd_record(_args(), base_url="http://127.0.0.1:1", token=None)
    assert "shakerscan[record]" in str(caught.value) and "playwright install chromium" in str(caught.value)


def test_the_script_hook_is_for_tests_only(monkeypatch):
    monkeypatch.delenv(record.TEST_HOOKS_ENV, raising=False)
    with pytest.raises(record.RecordError, match="test hook"):
        record.cmd_record(_args(script="x.py"), base_url="http://127.0.0.1:1", token=None)
    parser = cli.build_parser()
    assert "--script" not in parser._subparsers._group_actions[0].choices["record"].format_help()
    assert "record" in cli.CLIENT_COMMANDS and "record" in cli.COMMANDS


# --- end to end, in a real headless Chromium -----------------------------------------------------

def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as playwright:
            return Path(playwright.chromium.executable_path).exists()
    except Exception:
        return False


APP_PAGE = b"""<!doctype html><html><head><link rel="stylesheet" href="/style.css"></head><body>
<img src="/logo.png"><img src="http://OTHER/pixel.png">
<form id="login"><input name="username"><input name="password" type="password"></form>
<script src="/app.js"></script></body></html>"""


class _App(BaseHTTPRequestHandler):
    other = ""

    def log_message(self, *args):
        pass

    def _send(self, status, body, kind, headers=()):
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self._send(200, APP_PAGE.replace(b"OTHER", self.other.encode()), "text/html")
        elif self.path == "/app.js":
            self._send(200, b"window.loaded = true;", "application/javascript")
        elif self.path == "/style.css":
            self._send(200, b"body{}", "text/css")
        elif self.path.startswith("/api/me"):
            self._send(200, b'{"user":"alice"}', "application/json")
        else:
            self._send(200, b"\x89PNG", "image/png")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self._send(200, b'{"ok":true}', "application/json", [("Set-Cookie", "sid=session-cookie-value; Path=/")])


class _CaptureApi(BaseHTTPRequestHandler):
    """The three capture routes, applying batches by seq like the engine."""

    state: dict = {}

    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        state = self.state
        if self.path == "/request-collections/captures":
            state["created"] = body
            answer = {"id": "cap-1", "name": "e2e", "target_id": "t-1", "target_url": state["app"] + "/",
                      "allowed_origins": [state["app"]], "limits": {"max_batch_bytes": 16 * 1024 * 1024}}
        elif self.path.endswith("/capture-batches"):
            assert body["seq"] == len(state["batches"]) + 1
            state["batches"].append(body)
            flows = sum(len(batch["flows"]) for batch in state["batches"])
            answer = {"status": "applied", "accepted": len(body["flows"]), "capture": {"flow_count": flows}}
        else:
            state["closed"] = body
            flows = sum(len(batch["flows"]) for batch in state["batches"])
            answer = {"status": "closed", "capture": {"state": "closed", "flow_count": flows, "endpoint_count": 4}}
        data = json.dumps(answer).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


LOGIN_SCRIPT = """
def run(page):
    page.wait_for_load_state("load")
    page.fill("input[name=username]", "alice")
    page.fill("input[name=password]", "hunter2-password")
    page.evaluate('''async () => {
        await fetch("/api/login", {method: "POST", headers: {"Content-Type": "application/json"},
            body: JSON.stringify({username: "alice", password: "hunter2-password"})});
        await fetch("/api/me?token=abc123");
    }''')
"""


@pytest.mark.skipif(not _chromium_available(), reason="Playwright with Chromium is not installed")
def test_record_a_local_app_headless_and_upload_it(tmp_path, monkeypatch, capsys):
    other, other_url = _serve(_App)
    _App.other = other_url.removeprefix("http://")
    app, app_url = _serve(_App)
    _CaptureApi.state = {"app": app_url, "batches": []}
    api, api_url = _serve(_CaptureApi)
    script = tmp_path / "login.py"
    script.write_text(LOGIN_SCRIPT)
    monkeypatch.setenv(record.TEST_HOOKS_ENV, "1")
    monkeypatch.setenv("SHAKERSCAN_CONFIG_DIR", str(tmp_path / "config"))
    for name in ("SHAKERSCAN_API_TOKEN", "SHAKERSCAN_API_TOKEN_FILE"):
        monkeypatch.delenv(name, raising=False)
    try:
        code = cli.main(["record", "--url", api_url, app_url, "--json", "--headless", "--script", str(script)])
    finally:
        for server in (other, app, api):
            server.shutdown()
    result = json.loads(capsys.readouterr().out)
    flows = [flow for batch in _CaptureApi.state["batches"] for flow in batch["flows"]]
    paths = sorted({(flow["method"], flow["url"].removeprefix(app_url)) for flow in flows})
    assert code == 0 and result["state"] == "closed" and result["capture_id"] == "cap-1"
    assert _CaptureApi.state["created"]["target_url"] == app_url
    assert ("GET", "/") in paths and ("POST", "/api/login") in paths and ("GET", "/api/me?token=abc123") in paths
    assert ("GET", "/app.js") in paths                       # scripts are kept
    assert not [path for _method, path in paths if path.endswith((".png", ".css"))]   # assets dropped
    assert all(flow["url"].startswith(app_url) for flow in flows)                       # scope
    login = next(flow for flow in flows if flow["url"].endswith("/api/login"))
    assert "hunter2-password" in login["request_body"] and login["status"] == 200
    assert any(h["name"].lower() == "set-cookie" for h in login["response_headers"])
    assert result["flows"]["dropped_out_of_scope"] >= 1 and result["flows"]["dropped_assets"] >= 2
    assert result["flows"]["uploaded"] == len(flows)
    assert _CaptureApi.state["closed"]["client_dropped"]["assets"] >= 2
    assert "hunter2-password" not in json.dumps(result)



@pytest.mark.parametrize("connected", [True, False])
def test_closing_the_browser_window_ends_the_recording(monkeypatch, connected):
    # Lab 2.11.0 candidate 8dcd692b, headed: closing the window raised TargetClosedError out of
    # the wait, so no summary was printed and the capture stayed open until the idle close.
    import types

    class TargetClosedError(Exception):
        pass

    class Page:
        def __init__(self):
            self.closed = False

        def is_closed(self):
            return self.closed

        def goto(self, *_args, **_kwargs):
            return None

        def wait_for_timeout(self, _ms):
            self.closed = True
            raise TargetClosedError("Target page, context or browser has been closed")

    page = Page()
    closed = []
    context = types.SimpleNamespace(
        pages=[page], new_page=lambda: page, on=lambda *_args: None, close=lambda: closed.append("context"),
    )
    browser = types.SimpleNamespace(
        new_context=lambda: context, is_connected=lambda: connected, close=lambda: closed.append("browser"),
    )

    class Playwright:
        chromium = types.SimpleNamespace(launch=lambda **_kwargs: browser)

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.Error = TargetClosedError
    sync_api.sync_playwright = Playwright
    monkeypatch.setitem(sys.modules, "playwright", types.ModuleType("playwright"))
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)
    monkeypatch.setattr(record, "_attach", lambda *_args: None)
    monkeypatch.setattr(record, "_process", lambda *_args: None)
    recording = types.SimpleNamespace(stopped=None, limits=None, unfinished=0, pump=lambda _now: None)
    reason = record.run_browser(recording, "https://app.example.test/", headless=False, script=None)
    assert reason == "browser closed" and closed == ["context", "browser"]


@pytest.mark.parametrize(("status", "detail"), [(405, {"detail": "Method Not Allowed"}), (404, {"detail": "Not Found"})])
def test_an_engine_without_captures_is_named(status, detail):
    class OldEngine:
        def request(self, *args, **kwargs):
            raise UploadError("no route", status=status, detail=detail)

    with pytest.raises(record.RecordError, match="older than 2.11"):
        record.create_capture(OldEngine(), "https://app.example.test", None)


def test_a_batch_is_measured_as_the_bytes_that_are_sent():
    """Non-ASCII bodies: ensure_ascii would send 2-6x the bytes measured; the uploader sends the
    measured UTF-8 bytes themselves."""
    sent = []

    class Wire:
        def post(self, path, payload, *, body=None):
            sent.append(body)
            return {"status": "applied", "accepted": len(payload["flows"])}

    cap = _capture.BATCH_ENVELOPE_BYTES + 20_000
    batcher = Batcher(max_flows=50, max_bytes=cap)
    for _ in range(6):
        batcher.add({"url": "https://a/", "response_body": "ж€😀" * 1_000}, now=0.0)
    uploader = CaptureUploader(Wire().post, "c-1", sleep=lambda _s: None, max_bytes=cap)
    for flows in batcher.take(0.0, force=True):
        uploader.enqueue(flows)
    assert uploader.send() is True
    assert len(sent) > 1 and all(len(body) <= cap for body in sent)
    assert all(body == _capture.encode_json(json.loads(body)) for body in sent)
    assert "ж€😀".encode() in sent[0]  # UTF-8, not \u escapes


def test_a_413_splits_the_batch_and_keeps_every_flow_in_order():
    applied = {}

    class GatewayCap:
        limit = 1_500

        def post(self, path, payload, *, body=None):
            if len(body) > self.limit:
                raise UploadError("too large", status=413)
            assert payload["seq"] == len(applied) + 1
            applied[payload["seq"]] = [flow["url"] for flow in payload["flows"]]
            return {"status": "applied", "accepted": len(payload["flows"])}

    uploader = CaptureUploader(GatewayCap().post, "c-1", sleep=lambda _s: None)
    uploader.enqueue([{"url": f"https://a/{n}", "response_body": "x" * 300} for n in range(8)])
    uploader.enqueue([{"url": "https://a/last"}])
    huge = {"url": "https://a/huge", "response_body": "y" * 5_000}
    uploader.enqueue([huge])
    assert uploader.send() is True and uploader.totals.splits >= 1
    urls = [url for seq in sorted(applied) for url in applied[seq]]
    assert urls == [f"https://a/{n}" for n in range(8)] + ["https://a/last", "https://a/huge"]
    assert uploader.totals.bodies_withheld == 1 and uploader.totals.too_large == 0
    assert uploader.next_seq == max(applied) + 1


def test_a_flow_too_large_even_without_bodies_is_counted_not_lost_silently():
    class Tiny:
        def post(self, path, payload, *, body=None):
            if payload["flows"]:
                raise UploadError("too large", status=413)
            return {"status": "applied", "accepted": 0}

    uploader = CaptureUploader(Tiny().post, "c-1", sleep=lambda _s: None)
    uploader.enqueue([{"url": "https://a/" + "p" * 100}])
    assert uploader.send() is True
    assert uploader.totals.too_large == 1


def test_lone_surrogates_are_replaced_before_measuring_and_sending():
    flow = {"url": "https://a/", "response_body": "ok\ud800end", "request_headers": [{"name": "X", "value": "\udfff"}]}
    body = _capture.encode_json({"seq": 1, "flows": [flow]})
    decoded = json.loads(body.decode("utf-8"))
    assert decoded["flows"][0]["response_body"] == "ok\ufffdend"
    batcher = Batcher()
    batcher.add(flow, now=0.0)
    (batch,) = batcher.take(0.0, force=True)
    assert batch[0]["request_headers"][0]["value"] == "\ufffd"


@pytest.mark.parametrize("status", [400, 403, 404, 409, 422])
def test_a_4xx_answer_is_not_retried(status):
    calls = []

    def post(path, payload, *, body=None):
        calls.append(payload["seq"])
        raise UploadError("refused", status=status, detail={"detail": {"error": "capture_seq_gap", "expected_seq": 4}})

    uploader = CaptureUploader(post, "c-1", sleep=lambda _s: None)
    uploader.enqueue([])
    with pytest.raises(CaptureStopped):
        uploader.send()
    assert calls == [1]


def test_stale_profile_directories_are_removed(tmp_path):
    old = tmp_path / "shakerscan-record-old"
    old.mkdir()
    (old / "Cookies").write_text("sid=secret")
    fresh = tmp_path / "shakerscan-record-fresh"
    fresh.mkdir()
    other = tmp_path / "unrelated"
    other.mkdir()
    import os
    os.utime(old, (1_000, 1_000))
    assert record.remove_stale_profiles(str(tmp_path), now=1_000 + record.STALE_PROFILE_SECONDS + 1) == 1
    assert not old.exists() and other.exists()
    assert record.remove_stale_profiles(str(tmp_path)) == 0 and fresh.exists()


def test_close_waits_out_a_busy_server_then_succeeds():
    sleeps, calls = [], []

    class Busy:
        def post(self, path, payload, *, body=None):
            calls.append(path)
            if len(calls) < 3:
                raise UploadError("busy", status=503, retry_after=7.0)
            return {"status": "closed", "capture": {"state": "closed"}}

    answer = record.close_capture(Busy(), "c/1", {"assets": 1}, sleep=sleeps.append)
    assert answer["status"] == "closed" and sleeps == [7.0, 7.0]
    assert calls[0] == "/request-collections/c%2F1/capture-close"


def test_close_does_not_retry_a_refusal():
    class Refuses:
        def post(self, path, payload, *, body=None):
            raise UploadError("forbidden", status=403)

    with pytest.raises(UploadError):
        record.close_capture(Refuses(), "c-1", {}, sleep=lambda _s: pytest.fail("retried a 403"))
