"""``shakerscan record``: browse a target in a recorded browser; the server keeps what you did.

The client opens Chromium with a fresh profile, records the page's traffic through the Chrome
DevTools Protocol (no proxy, no certificate), keeps the requests of the capture's allowed origins
and uploads them in batches to a browser capture on the connected instance. The capture is a
request collection: Scans and Hunts use it like an imported HAR, and an agent can read it while
it grows (``shakerscan_captures``). Closing the browser or Ctrl-C uploads what is left and closes
the capture; if the client dies, the server closes it after 30 idle minutes.

Playwright is an optional dependency (``shakerscan[record]``); the pure event handling lives in
``_capture`` and is tested without a browser.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import runpy
import shlex
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Mapping
from typing import Any

from ._capture import (
    Batcher,
    CaptureStopped,
    CaptureUploader,
    CdpFlowRecorder,
    UploadError,
    classify,
    effective_limits,
    endpoint_key,
)

TEST_HOOKS_ENV = "SHAKERSCAN_RECORD_TEST_HOOKS"
KEEPALIVE_SECONDS = 300.0
TICK_MS = 250
FINAL_ATTEMPTS = 8


class RecordError(Exception):
    """A refusal ``record`` explains and exits on."""


def playwright_missing_message() -> str:
    python = shlex.quote(sys.executable)
    return (
        "shakerscan record needs Playwright, an optional part of the client. Install it with one of:\n"
        "  pipx install --force 'shakerscan[record]'      (or: pipx inject shakerscan playwright)\n"
        f"  {python} -m pip install playwright\n"
        "then download its browser once:\n"
        f"  {python} -m playwright install chromium"
    )


def add_parser(commands: Any, connection: Any) -> None:
    record = commands.add_parser(
        "record",
        help="open a recorded browser on a target and keep its in-scope traffic as a browser capture "
             "(needs shakerscan[record])",
    )
    connection(record)
    record.add_argument("target", help="target id, or a URL whose origin names exactly one target")
    record.add_argument("--name", help="capture name (default: 'Browser capture <time>')")
    record.add_argument("--start-url", help="first page to open (default: the target's URL)")
    record.add_argument("--include-assets", action="store_true",
                        help="also keep images, fonts, media and stylesheets (dropped by default)")
    record.add_argument("--json", action="store_true", help="print the summary as JSON")
    # For tests and acceptance only: no window, and a script that drives the page.
    record.add_argument("--headless", action="store_true", help=argparse.SUPPRESS)
    record.add_argument("--script", help=argparse.SUPPRESS)


class ApiClient:
    """JSON over the client's connection; a token goes only to https or a loopback address."""

    def __init__(self, base_url: str, token: str | None, *, timeout: float = 60.0, opener: Any = None) -> None:
        parts = urllib.parse.urlsplit(base_url)
        loopback = (parts.hostname or "") in {"localhost", "127.0.0.1", "::1"}
        if token and parts.scheme != "https" and not loopback:
            raise RecordError("refusing to send the API token over plain http; connect over https")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.opener = opener or urllib.request.build_opener()

    def request(self, method: str, path: str, payload: Mapping[str, Any] | None = None, *,
                headers: Mapping[str, str] | None = None) -> dict[str, Any]:
        data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(self.base_url + path, data=data, method=method, headers={
            "Accept": "application/json",
            **({"Content-Type": "application/json"} if data is not None else {}),
            **({"Authorization": "Bearer " + self.token} if self.token else {}),
            **dict(headers or {}),
        })
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            raw = exc.read(64 * 1024)
            exc.close()
            try:
                detail = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                detail = None
            raise UploadError(f"{method} {path} answered {exc.code}", status=exc.code, detail=detail) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise UploadError(f"{method} {path} got no answer: {getattr(exc, 'reason', exc)}") from None
        try:
            answer = json.loads(body.decode("utf-8")) if body else {}
        except (UnicodeDecodeError, ValueError):
            raise UploadError(f"{method} {path} answered with something that is not JSON", status=502) from None
        return answer if isinstance(answer, dict) else {}

    def post(self, path: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        return self.request("POST", path, payload)


def _message(exc: UploadError) -> str:
    detail = exc.detail.get("detail") if isinstance(exc.detail, Mapping) else None
    if isinstance(detail, Mapping):
        detail = detail.get("message") or detail.get("error")
    return f"{exc}: {detail}" if detail else str(exc)


def create_capture(api: ApiClient, target: str, name: str | None) -> dict[str, Any]:
    body: dict[str, Any] = {"name": name} if name else {}
    try:
        body["target_id"] = str(uuid.UUID(target))
    except ValueError:
        if not target.startswith(("http://", "https://")):
            raise RecordError("the target is a target id or an http(s) URL") from None
        body["target_url"] = target
    try:
        # A retried create (lost answer) replays the first one instead of opening a second capture.
        return api.request("POST", "/request-collections/captures", body,
                           headers={"Idempotency-Key": f"record-{uuid.uuid4().hex}"})
    except UploadError as exc:
        if exc.status == 404 and isinstance(exc.detail, Mapping) and exc.detail.get("detail") == "Not Found":
            raise RecordError("this instance has no browser capture (it is older than 2.11)") from None
        raise RecordError(f"could not open a capture: {_message(exc)}") from None


class Recording:
    """Recorder state between the browser and the uploader (the I/O-free part of the loop)."""

    def __init__(self, capture: Mapping[str, Any], api: ApiClient, *, include_assets: bool,
                 sleep: Any = time.sleep) -> None:
        self.capture_id = str(capture["id"])
        self.allowed_origins = [str(item) for item in capture.get("allowed_origins") or []]
        self.limits = effective_limits(capture.get("limits"))
        self.include_assets = include_assets
        self.batcher = Batcher(max_flows=min(50, self.limits["max_flows_per_batch"]),
                               max_bytes=self.limits["max_batch_bytes"])
        self.uploader = CaptureUploader(api.post, self.capture_id, sleep=sleep, attempts=1)
        self.dropped = {"out_of_scope": 0, "assets": 0}
        self.endpoints: set[str] = set()
        self.unfinished = 0
        self.last_upload = time.monotonic()
        self.retry_at = 0.0
        self.failures = 0
        self.stopped: str | None = None

    def offer(self, flow: Mapping[str, Any] | None, now: float) -> None:
        if flow is None:
            return
        verdict = classify(flow, self.allowed_origins, include_assets=self.include_assets)
        if verdict == "out_of_scope":
            self.dropped["out_of_scope"] += 1
        elif verdict == "asset":
            self.dropped["assets"] += 1
        else:
            self.endpoints.add(endpoint_key(flow))
            self.batcher.add(dict(flow), now)

    def pump(self, now: float, *, force: bool = False) -> None:
        """Queue due batches and send them; a failed send is retried on a later tick with backoff."""
        if self.stopped:
            return
        for flows in self.batcher.take(now, force=force):
            self.uploader.enqueue(flows)
        if not self.uploader.queue and now - self.last_upload >= KEEPALIVE_SECONDS:
            self.uploader.enqueue([])  # keeps an open capture from the idle close
        if not self.uploader.queue or now < self.retry_at:
            return
        try:
            sent = self.uploader.send(self.dropped)
        except CaptureStopped as exc:
            self.stopped = str(exc)
            return
        if sent:
            self.last_upload, self.failures = now, 0
        else:
            self.failures += 1
            self.retry_at = now + min(30.0, 0.5 * 2 ** min(self.failures, 6))

    def finish(self) -> bool:
        """Upload everything left, retrying harder than a tick does. True when nothing is lost."""
        if self.stopped:
            return False
        for flows in self.batcher.take(time.monotonic(), force=True):
            self.uploader.enqueue(flows)
        try:
            return self.uploader.send(self.dropped, attempts=FINAL_ATTEMPTS)
        except CaptureStopped as exc:
            self.stopped = str(exc)
            return False


def _attach(context: Any, page: Any, sessions: list[tuple[Any, CdpFlowRecorder, list]], limits: Mapping[str, int]) -> None:
    session = context.new_cdp_session(page)
    recorder = CdpFlowRecorder(limits)
    events: list[tuple[str, dict]] = []
    for name in (
        "requestWillBeSent", "requestWillBeSentExtraInfo", "responseReceived", "responseReceivedExtraInfo",
        "loadingFinished", "loadingFailed", "webSocketCreated", "webSocketWillSendHandshakeRequest",
        "webSocketHandshakeResponseReceived", "webSocketFrameSent", "webSocketFrameReceived", "webSocketClosed",
    ):
        method = f"Network.{name}"
        # Handlers only queue: bodies are fetched from the main loop, outside event dispatch.
        session.on(method, lambda params, method=method: events.append((method, params)))
    session.send("Network.enable", {"maxTotalBufferSize": 64 * 1024 * 1024, "maxResourceBufferSize": 8 * 1024 * 1024})
    sessions.append((session, recorder, events))


def _process(sessions: list[tuple[Any, CdpFlowRecorder, list]], recording: Recording) -> None:
    for session, recorder, events in sessions:
        while events:
            method, params = events.pop(0)
            for action in recorder.handle(method, params):
                if action[0] == "flow":
                    recording.offer(action[1], time.monotonic())
                    continue
                request_id, wants_post = action[1], action[2]
                body = post_data = None
                encoded = False
                try:
                    fetched = session.send("Network.getResponseBody", {"requestId": request_id})
                    body, encoded = fetched.get("body"), bool(fetched.get("base64Encoded"))
                except Exception:  # evicted, a redirect or no body: the flow keeps its metadata
                    pass
                if wants_post:
                    try:
                        post_data = session.send("Network.getRequestPostData", {"requestId": request_id}).get("postData")
                    except Exception:
                        pass
                recording.offer(recorder.complete(request_id, body=body, base64_encoded=encoded,
                                                  post_data=post_data), time.monotonic())


def run_browser(recording: Recording, start_url: str, *, headless: bool, script: str | None) -> str:
    """Record until the browser closes, Ctrl-C, or the test script returns; the reason it ended."""
    from playwright.sync_api import sync_playwright

    sessions: list[tuple[Any, CdpFlowRecorder, list]] = []
    reason = "browser closed"
    with tempfile.TemporaryDirectory(prefix="shakerscan-record-") as profile, sync_playwright() as playwright:
        context = playwright.chromium.launch_persistent_context(
            profile, headless=headless, args=["--disable-quic", "--no-first-run", "--no-default-browser-check"],
        )
        try:
            page = context.pages[0] if context.pages else context.new_page()
            _attach(context, page, sessions, recording.limits)
            context.on("page", lambda new_page: _attach(context, new_page, sessions, recording.limits))
            page.goto(start_url, wait_until="commit")
            if script:
                runpy.run_path(script)["run"](page)
                page.wait_for_timeout(1_000)
                reason = "script finished"
            while not script:
                if recording.stopped:
                    reason = recording.stopped
                    break
                live = [item for item in context.pages if not item.is_closed()]
                if not live:
                    break
                live[0].wait_for_timeout(TICK_MS)
                _process(sessions, recording)
                recording.pump(time.monotonic())
        except KeyboardInterrupt:
            reason = "interrupted"
        finally:
            _process(sessions, recording)
            for _session, recorder, _events in sessions:
                for flow in recorder.drain():
                    recording.offer(flow, time.monotonic())
                recording.unfinished += recorder.dropped_unfinished
            try:
                context.close()
            except Exception:
                pass
    return reason


def summary(capture: Mapping[str, Any], recording: Recording, closed: Mapping[str, Any] | None,
            *, complete: bool, reason: str) -> dict[str, Any]:
    state = (closed or {}).get("capture") or recording.uploader.last_capture or {}
    target_id = str(capture.get("target_id") or "")
    target_url = str(capture.get("target_url") or "")
    totals = recording.uploader.totals
    return {
        "capture_id": recording.capture_id,
        "name": capture.get("name"),
        "target_id": target_id,
        "allowed_origins": recording.allowed_origins,
        "state": "closed" if closed else "open",
        "ended": reason,
        "complete": complete,
        "flows": {
            # The server's count: an acknowledged retry reports no new flows of its own.
            "uploaded": int(state.get("flow_count") if state.get("flow_count") is not None else totals.accepted),
            "refused_by_server": totals.refused_out_of_scope + totals.refused_over_limit,
            "dropped_out_of_scope": recording.dropped["out_of_scope"],
            "dropped_assets": recording.dropped["assets"],
            "bodies_dropped": int(state.get("bodies_dropped") or totals.bodies_dropped),
            "unfinished": recording.unfinished,
            "not_uploaded": sum(len(flows) for _seq, flows in recording.uploader.queue),
        },
        "endpoints": int(state.get("endpoint_count") or len(recording.endpoints)),
        "stopped": recording.stopped,
        "next": {
            "scan": f"shakerscan scan {shlex.quote(target_url)} --collection-selection {recording.capture_id}",
            "hunt": f"shakerscan hunt start --target-id {target_id} --collection-id {recording.capture_id}",
            "read": f"shakerscan api GET '/request-collections/{recording.capture_id}/requests?since_seq=0'",
        },
    }


def render(result: Mapping[str, Any]) -> str:
    flows = result["flows"]
    lines = [
        f"Browser capture {result['name']} ({result['capture_id']}): {result['state']}, ended: {result['ended']}",
        f"  in scope ({', '.join(result['allowed_origins'])}): {flows['uploaded']} requests uploaded, "
        f"{result['endpoints']} endpoints",
        f"  dropped before upload: {flows['dropped_out_of_scope']} out of scope, {flows['dropped_assets']} assets "
        "(--include-assets keeps them)",
    ]
    if flows["refused_by_server"]:
        lines.append(f"  refused by the server: {flows['refused_by_server']} (scope or the capture's limits)")
    if flows["bodies_dropped"]:
        lines.append(f"  {flows['bodies_dropped']} requests kept without bodies: the capture document reached its size limit")
    if flows["unfinished"]:
        lines.append(f"  {flows['unfinished']} requests never finished and were not kept")
    if flows["not_uploaded"] or not result["complete"]:
        lines.append(f"  NOT uploaded: {flows['not_uploaded']} requests (the server did not answer)"
                     + (f"; {result['stopped']}" if result.get("stopped") else ""))
    lines += [
        "  Cookie, authorization and password values stay in the encrypted capture; every view is masked,",
        "  and they never become a credential: Scans and Hunts sign in with the target's credential profiles.",
        "Next:",
        f"  scan:  {result['next']['scan']}",
        f"  hunt:  {result['next']['hunt']}",
        f"  read:  {result['next']['read']}",
    ]
    return "\n".join(lines)


def cmd_record(args: argparse.Namespace, *, base_url: str, token: str | None) -> int:
    script = args.script
    if script and os.environ.get(TEST_HOOKS_ENV) != "1":
        raise RecordError("--script is a test hook; it needs SHAKERSCAN_RECORD_TEST_HOOKS=1")
    if importlib.util.find_spec("playwright") is None:
        raise RecordError(playwright_missing_message())
    api = ApiClient(base_url, token, timeout=float(args.timeout or 60.0))
    capture = create_capture(api, args.target, args.name)
    recording = Recording(capture, api, include_assets=args.include_assets)
    start_url = args.start_url or str(capture.get("target_url") or "")
    if not args.json:
        sys.stderr.write(
            f"Recording {', '.join(recording.allowed_origins)} into {capture.get('name')} ({recording.capture_id}).\n"
            "Browse and sign in as you need; close the browser or press Ctrl-C to finish.\n")
    try:
        reason = run_browser(recording, start_url, headless=bool(args.headless or script), script=script)
    except KeyboardInterrupt:
        reason = "interrupted"
    complete = recording.finish()
    closed = None
    if complete:
        try:
            closed = api.post(f"/request-collections/{urllib.parse.quote(recording.capture_id, safe='')}/capture-close",
                              {"client_dropped": recording.dropped})
        except UploadError as exc:
            sys.stderr.write(f"shakerscan: could not close the capture ({_message(exc)}); "
                             "the server closes it after 30 idle minutes\n")
    result = summary(capture, recording, closed, complete=complete, reason=reason)
    sys.stdout.write((json.dumps(result, indent=2, sort_keys=True) if args.json else render(result)) + "\n")
    return 0 if complete else 1


__all__ = ["ApiClient", "RecordError", "Recording", "add_parser", "cmd_record", "render", "summary"]
