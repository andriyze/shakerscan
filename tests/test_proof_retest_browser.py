"""A verified browser XSS finding is retested by the oracle that proved it, in a real browser.

The browser proof's payload sets an attribute on the page's root element and logs a marker named
after its candidate; it proves execution only when that attribute holds the marker, or a console
or dialog message is exactly the marker. The retest must judge the same way, or "likely fixed"
and "still vulnerable" would come from a different check than the one that found the finding:

* a page that silences the console but still runs the payload is still vulnerable (the attribute);
* a fixed page that escapes the input and logs it, or raises its own dialog, is not reproduced;
* a page behind a sign-in is retested with the Scan's session, which reaches only its origin.

It also must not depend on what ran before it in the process: a Scan's browser proof in an earlier
event loop, another retest in the same loop (a worker's), or a browser that stopped answering, also
once the retest's context is open.

The pages are a local fixture server (unit fixtures); the retest is the real ``run_proof_retest``
with the real proof module, its HTTP client and its headless browser, except where a stand-in
Playwright (a unit fixture) never answers.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import hashlib
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import threading
import time
from typing import Any, Callable
import urllib.parse
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

pytest.importorskip("playwright.async_api")

from capabilities.xss_proof_payload import xss_proof_marker, xss_proof_payload  # noqa: E402
from retest_contract import infer_retest_inputs  # noqa: E402

CANDIDATE = "c3d1f0a9b8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a3928170615243"
SESSION = "session=retest-fixture"
OFF_ORIGIN_HITS: list[str] = []
# A retest takes about 4 s here (a browser launch, the baseline request, the payload page).
HANG_LIMIT_SECONDS = 90.0


class _Pages(BaseHTTPRequestHandler):
    """Search pages, each a different state of the same fix (unit fixture)."""

    off_origin = ""

    def log_message(self, *_args):
        return None

    def _send(self, status: int, body: str, headers: tuple[tuple[str, str], ...] = ()) -> None:
        data = body.encode()
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        if not any(name.lower() == "content-type" for name, _value in headers):
            self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802 - http.server API
        parsed = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(parsed.query)).get("q", "")
        logged = json.dumps(q).replace("<", "\\u003c")
        if parsed.path == "/vuln":
            return self._send(200, f"<html><body><h1>Results for {q}</h1></body></html>")
        if parsed.path == "/quiet":
            # A production build that silences the console and still reflects the input.
            return self._send(200, "<html><head><script>console.log=function(){};</script></head>"
                                   f"<body><h1>Results for {q}</h1></body></html>")
        if parsed.path == "/fixed":
            # Fixed: the input is escaped, and the page logs the search term as a string.
            return self._send(200, f"<html><body><h1>Results for {html.escape(q)}</h1>"
                                   f"<script>console.log('search:', {logged});</script></body></html>")
        if parsed.path == "/fixed-noisy":
            # Fixed, and the page shows its own dialog and logs words the old check looked for.
            return self._send(200, f"<html><body><h1>Results for {html.escape(q)}</h1><script>"
                                   "console.log('xss filter active: alert( blocked');"
                                   "alert('Welcome back');</script></body></html>")
        if parsed.path == "/private":
            if SESSION not in str(self.headers.get("Cookie") or ""):
                return self._send(302, "", (("Location", "/login"),))
            # The page also loads an image from another site, which the proof never requests.
            return self._send(200, f"<html><body><img src='{self.off_origin}/pixel'>"
                                   f"<h1>Results for {q}</h1></body></html>")
        if parsed.path == "/login":
            return self._send(200, "<form><input name=user><input type=password name=pass></form>")
        # An application whose sink is in its own same-origin script (query -> innerHTML), in the
        # states a retest may meet it in: running, fixed, or not running whole.
        if parsed.path in _APP_PAGES:
            script, attrs = _APP_PAGES[parsed.path]
            return self._send(200, f"<html><body><h1>Search</h1><div id=r></div>"
                                   f"<script {attrs} src='{script}'></script></body></html>")
        if parsed.path in _APP_SCRIPTS:
            status, body, delay = _APP_SCRIPTS[parsed.path]
            time.sleep(delay)
            return self._send(status, body, (("Content-Type", "application/javascript"),))
        if parsed.path == "/api/search":  # the data call the app's sink waits for, down
            return self._send(503, json.dumps({"error": "unavailable"}))
        if parsed.path == "/refl/search":  # server-side reflection, no application script
            return self._send(200, f"<html><body><h1>Results for {q}</h1></body></html>")
        if parsed.path == "/refl/x":  # the payload's own <img src=x>, answered late under load
            time.sleep(3.0)
            return self._send(404, "not found")
        if parsed.path == "/fixed-image":  # fixed, and a decorative image is missing
            return self._send(200, f"<html><body><img src='/missing.png'><h1>Results for {html.escape(q)}</h1>"
                                   "</body></html>")
        if parsed.path == "/fixed-analytics":  # fixed, and loads another site's script (blocked)
            return self._send(200, f"<html><body><script src='{self.off_origin}/analytics.js'></script>"
                                   f"<h1>Results for {html.escape(q)}</h1></body></html>")
        return self._send(404, "not found")


_VULNERABLE_JS = "document.getElementById('r').innerHTML = new URLSearchParams(location.search).get('q') || '';"
_FIXED_JS = "document.getElementById('r').textContent = new URLSearchParams(location.search).get('q') || '';"
_API_JS = ("fetch('/api/search' + location.search).then(r => r.json())"
           ".then(d => { document.getElementById('r').innerHTML = d.echo; });")
_APP_PAGES = {
    "/dom": ("/app.js", ""), "/dom-fixed": ("/app-fixed.js", ""), "/dom-503": ("/app-503.js", ""),
    "/dom-404": ("/app-404.js", ""), "/dom-429": ("/app-429.js", ""), "/dom-api503": ("/app-api.js", ""),
    "/dom-slow": ("/app-slow.js", "async"),
}
_APP_SCRIPTS = {  # path: (status, body, seconds before answering)
    "/app.js": (200, _VULNERABLE_JS, 0.0), "/app-fixed.js": (200, _FIXED_JS, 0.0),
    "/app-503.js": (503, "Service Unavailable", 0.0), "/app-404.js": (404, "not found", 0.0),
    "/app-429.js": (429, "Too Many Requests", 0.0), "/app-api.js": (200, _API_JS, 0.0),
    "/app-slow.js": (200, _VULNERABLE_JS, 3.0),
}


class _OffOrigin(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return None

    def do_GET(self):  # noqa: N802 - http.server API
        OFF_ORIGIN_HITS.append(self.path)
        self.send_response(204)
        self.end_headers()


@pytest.fixture
def pages():
    if shutil.which("curl") is None:
        pytest.skip("the retest's HTTP client is curl")
    off = ThreadingHTTPServer(("127.0.0.1", 0), _OffOrigin)
    handler = type("Pages", (_Pages,), {"off_origin": f"http://localhost:{off.server_address[1]}"})
    servers = [ThreadingHTTPServer(("127.0.0.1", 0), handler), off]
    OFF_ORIGIN_HITS.clear()
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{servers[0].server_address[1]}"
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


def _verification(origin: str, path: str, *, auth_context: dict | None = None) -> dict:
    """A retest row joined with its verified browser XSS finding, as the Scan stores it."""
    stored = f"{origin}{path}?q=%3Credacted%3E"
    payload = xss_proof_payload(CANDIDATE)
    evidence = {
        "parameter_name": "q", "injection_location": "query", "candidate_id": CANDIDATE,
        "payload_sha256": hashlib.sha256(payload.encode()).hexdigest(),
        "request_url": stored, "related_request_urls": [stored], "proof_state": "verified",
        "execution_sink": {"signal": "console", "location": "query", "parameter": "q"},
    }
    return {
        "id": uuid.uuid4(), "finding_id": uuid.uuid4(), "tool": "shakerscan_browser_proof",
        "title": "Verified cross-site scripting", "finding_type": "xss", "target_url": origin,
        "original_url": stored, "finding_url": stored, "evidence": json.dumps(evidence),
        "source_scan_target_url": origin, "source_scan_type": "full",
        "source_scan_options": {"exploit_depth": True},
        "auth_context": json.dumps(auth_context) if auth_context else None,
    }


def _retest(monkeypatch, verification: dict) -> dict:
    from scanner_tools import proof_of_exploit
    from worker_handlers.proof_replay import run_proof_retest

    monkeypatch.setattr(proof_of_exploit, "_poe_config",
                        dataclasses.replace(proof_of_exploit._poe_config, rate_limit_ms=0, enable_headless_xss=True))

    async def run() -> dict:
        # The proof module keeps a browser for this event loop and closes it when the loop ends.
        return await run_proof_retest(
            verification, infer_retest_inputs(verification), poe=proof_of_exploit,
            replay_commands=[], ladder=[], cancelled=lambda: False)

    return asyncio.run(run())


@pytest.mark.parametrize("path,verdict,technique", [
    ("/vuln", "exploited", "headless_xss_console"),
    # The console is silenced, the payload still runs: the attribute holds the marker.
    ("/quiet", "exploited", "headless_xss_dom"),
    # Escaped: the page logs the input as text, which is not the marker.
    ("/fixed", "likely_fixed", None),
    # Escaped: the page's own dialog and log lines are not the marker.
    ("/fixed-noisy", "likely_fixed", None),
])
def test_the_retest_judges_the_page_by_the_browser_proofs_own_oracle(monkeypatch, pages, path, verdict, technique):
    result = _retest(monkeypatch, _verification(pages, path))
    assert result["verdict"] == verdict, result["verdict_reason"]
    assert result["artifacts"]["check"] == "xss.browser_prove_batch"
    assert (result["proof"] or {}).get("technique") == technique
    if verdict == "likely_fixed":
        assert result["verdict_reason"] == (
            "The check that proved the finding sent the same request again and did not reproduce it.")


def test_the_retest_uses_the_scans_session_and_only_on_the_findings_origin(monkeypatch, pages):
    signed_out = _retest(monkeypatch, _verification(pages, "/private"))
    assert signed_out["verdict"] == "inconclusive"
    assert "asked for credentials" in signed_out["verdict_reason"]
    signed_in = _retest(monkeypatch, _verification(pages, "/private", auth_context={"auth_cookies": SESSION}))
    assert signed_in["verdict"] == "exploited", signed_in["verdict_reason"]
    assert signed_in["proof"]["blocked_requests"] >= 1
    assert OFF_ORIGIN_HITS == []


@pytest.mark.parametrize("path,verdict", [
    ("/dom", "exploited"),          # the application's script runs the payload
    ("/dom-fixed", "likely_fixed"),  # fixed: the script writes text
    # Fixed: a missing decorative image, and another site's script the proof blocks, do not
    # stop a negative answer.
    ("/fixed-image", "likely_fixed"),
    ("/fixed-analytics", "likely_fixed"),
])
def test_a_page_that_ran_as_proved_gets_a_verdict(monkeypatch, pages, path, verdict):
    result = _retest(monkeypatch, _verification(pages, path))
    assert result["verdict"] == verdict, result["verdict_reason"]


@pytest.mark.parametrize("path,shown", [
    ("/dom-503", "answered HTTP 503"),
    ("/dom-404", "answered HTTP 404"),   # a rolling deploy: the bundle is not there yet
    ("/dom-429", "answered HTTP 429"),   # rate limiting
    ("/dom-api503", "answered HTTP 503"),  # the script loads; the call its sink needs fails
])
def test_a_page_whose_own_scripts_or_calls_failed_is_inconclusive(monkeypatch, pages, path, shown):
    result = _retest(monkeypatch, _verification(pages, path))
    assert (result["verdict"], result["result_status"]) == ("inconclusive", "inconclusive"), result["verdict_reason"]
    assert shown in result["verdict_reason"]
    assert "did not run as it did when the finding was proved" in result["verdict_reason"]
    assert result["proof"]["page_incomplete"]["failed"]


@pytest.mark.parametrize("path", ["/dom-slow", "/refl/search"])
def test_a_page_still_loading_after_the_settle_is_never_likely_fixed(monkeypatch, pages, path):
    """A script slower than the settle, or the payload's own image answered late: the retest
    waits for them within the proof's page timeout, and the payload then runs."""
    result = _retest(monkeypatch, _verification(pages, path))
    assert result["verdict"] != "likely_fixed", result["verdict_reason"]
    assert result["verdict"] == "exploited", result["verdict_reason"]


def test_the_marker_is_the_one_the_browser_proof_looks_for():
    payload = xss_proof_payload(CANDIDATE)
    marker = xss_proof_marker(CANDIDATE)
    assert f"setAttribute('data-shakerscan-proof','{marker}')" in payload
    assert f"console.log('{marker}')" in payload


# --- What ran before the retest must not matter ----------------------------------------------------


def _finishes(work: Callable[[], Any], *, seconds: float = HANG_LIMIT_SECONDS) -> Any:
    """``work()``'s result, run on a thread of its own: a hang fails the test, not the run."""
    box: dict[str, Any] = {}

    def run() -> None:
        try:
            box["result"] = work()
        except BaseException as exc:  # noqa: BLE001 - re-raised on the test's thread
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True, name="retest-case")
    thread.start()
    thread.join(seconds)
    if thread.is_alive():
        pytest.fail(f"still waiting after {seconds:.0f} s: the retest hung")
    if "error" in box:
        raise box["error"]
    return box["result"]


def test_a_retest_after_a_scans_browser_proof_in_an_earlier_event_loop(monkeypatch, pages):
    """The order that hung: a Scan's browser proof ran in one event loop and left its browser, as
    ``tests/test_active_checks.py``'s POST-body XSS check does, then the retest ran in the next."""
    from scanner_tools import active_checks, proof_of_exploit

    async def the_scans_client(command, *args, **kwargs):  # the page echoes the field (unit fixture)
        body = json.loads(command[command.index("-d") + 1])
        return f"<html><body>{body.get('message')}</body></html>", "", 0

    monkeypatch.setattr(active_checks, "run", the_scans_client)
    monkeypatch.setattr(proof_of_exploit, "_poe_config",
                        dataclasses.replace(proof_of_exploit._poe_config, enable_headless_xss=True))
    endpoint = {"url": "https://example.test/contact", "method": "POST", "content_type": "application/json",
                "body_params": ["message"], "body_template": {"message": "hello"}}

    def work() -> tuple[dict, dict]:
        scan = asyncio.run(active_checks.smart_xss_test(
            "https://example.test", [endpoint], max_seconds=10, max_params_per_endpoint=1))
        return scan, _retest(monkeypatch, _verification(pages, "/vuln"))

    scan, retest = _finishes(work)
    finding = scan["findings"][0]
    assert finding["browser_proof_attempted"] is True
    assert finding["browser_proof"]["technique"].startswith("headless_xss_response_"), finding["evidence"]
    assert retest["verdict"] == "exploited", retest["verdict_reason"]
    assert retest["proof"]["technique"] == "headless_xss_console"


def test_a_workers_event_loop_runs_retest_after_retest_with_its_browser(monkeypatch, pages):
    """A worker keeps one event loop for its life: each retest in it judges its own page."""
    from scanner_tools import proof_of_exploit
    from worker_handlers.proof_replay import run_proof_retest

    monkeypatch.setattr(proof_of_exploit, "_poe_config",
                        dataclasses.replace(proof_of_exploit._poe_config, rate_limit_ms=0, enable_headless_xss=True))

    async def worker() -> list[dict]:
        verdicts = []
        for path in ("/vuln", "/fixed", "/quiet"):
            verification = _verification(pages, path)
            verdicts.append(await run_proof_retest(
                verification, infer_retest_inputs(verification), poe=proof_of_exploit,
                replay_commands=[], ladder=[], cancelled=lambda: False))
        return verdicts

    results = _finishes(lambda: asyncio.run(worker()), seconds=2 * HANG_LIMIT_SECONDS)
    assert [result["verdict"] for result in results] == ["exploited", "likely_fixed", "exploited"]


async def _never() -> None:
    await asyncio.get_running_loop().create_future()


class _UnansweringBrowser:
    """Says it is connected, and never answers at ``hangs_at``: opening a context, routing its
    requests, or opening a page; nor does it ever close a context (unit fixture)."""

    def __init__(self, hangs_at: str):
        self.hangs_at = hangs_at

    def is_connected(self) -> bool:
        return True

    async def new_context(self, **_options):
        if self.hangs_at == "new_context":
            await _never()
        return _UnansweringContext(self)

    async def close(self):
        await _never()


class _UnansweringContext:
    def __init__(self, browser: _UnansweringBrowser):
        self.browser = browser

    async def route(self, _pattern, _handler):
        if self.browser.hangs_at == "route":
            await _never()

    async def new_page(self):
        await _never()

    async def close(self):
        await _never()


class _StandInPlaywright:
    """``async_playwright()`` that launches only unanswering browsers (unit fixture)."""

    def __init__(self, hangs_at: str):
        self.chromium = self
        self.hangs_at = hangs_at
        self.launches = 0

    def __call__(self):
        return self

    async def start(self):
        return self

    async def launch(self, **_options):
        self.launches += 1
        return _UnansweringBrowser(self.hangs_at)

    async def stop(self):
        return None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None


@pytest.mark.parametrize("hangs_at", ["new_context", "route", "new_page"])
def test_a_browser_that_does_not_answer_leaves_the_retest_inconclusive(monkeypatch, pages, hangs_at):
    import playwright.async_api as playwright_api
    from scanner_tools import proof_of_exploit

    fake = _StandInPlaywright(hangs_at)
    monkeypatch.setattr(playwright_api, "async_playwright", fake)
    for name in ("BROWSER_LAUNCH_TIMEOUT_SECONDS", "BROWSER_HANDOFF_TIMEOUT_SECONDS", "BROWSER_CLOSE_TIMEOUT_SECONDS"):
        monkeypatch.setattr(proof_of_exploit, name, 0.5, raising=False)

    started = time.monotonic()
    result = _finishes(lambda: _retest(monkeypatch, _verification(pages, "/vuln")), seconds=30)
    assert time.monotonic() - started < 30
    assert fake.launches >= 1
    assert result["verdict"] == "inconclusive"
    assert result["result_status"] == "inconclusive"
    assert "did not answer" in result["verdict_reason"]
    assert "stays open" in result["verdict_reason"]


# --- A real headless Chromium that stops answering in the middle of a retest ----------------------


def _live_descendants() -> dict[int, str]:
    """``{pid: command}`` of the processes still running (not zombies) that descend from this test
    process."""
    lister = subprocess.Popen(["ps", "-A", "-o", "pid=,ppid=,stat=,comm="], stdout=subprocess.PIPE, text=True)
    out, _ = lister.communicate(timeout=30)
    children: dict[int, list[tuple[int, str]]] = {}
    for line in out.splitlines():
        fields = line.split(None, 3)
        if len(fields) == 4 and not fields[2].startswith("Z"):
            children.setdefault(int(fields[1]), []).append((int(fields[0]), fields[3]))
    found: dict[int, str] = {}
    todo = [os.getpid()]
    while todo:
        for child, command in children.get(todo.pop(), ()):
            if child not in found and child != lister.pid:
                found[child] = command
                todo.append(child)
    return found


@pytest.mark.skipif(not hasattr(signal, "SIGSTOP"), reason="stopping a process needs POSIX signals")
@pytest.mark.parametrize("stops_before", ["context", "page"])
def test_a_real_browser_that_stops_answering_mid_retest_leaves_it_inconclusive(monkeypatch, pages, stops_before):
    """Chromium is stopped (SIGSTOP) right before the retest opens its context, or its page. The
    retest is inconclusive within its bounds, although Playwright's driver takes longer than the
    close bound to give up on a stopped Chromium; and the next retest in the same worker loop
    launches another browser and proves the finding."""
    from scanner_tools import proof_of_exploit
    from worker_handlers.proof_replay import run_proof_retest

    monkeypatch.setattr(proof_of_exploit, "_poe_config",
                        dataclasses.replace(proof_of_exploit._poe_config, rate_limit_ms=0, enable_headless_xss=True))
    # A shorter handoff keeps the case short; closing keeps its production bound.
    monkeypatch.setattr(proof_of_exploit, "BROWSER_HANDOFF_TIMEOUT_SECONDS", 5.0)
    bound_seconds = proof_of_exploit.BROWSER_HANDOFF_TIMEOUT_SECONDS + proof_of_exploit.BROWSER_CLOSE_TIMEOUT_SECONDS
    before = set(_live_descendants())
    stopped: list[int] = []
    drivers: list[Any] = []

    def stop_chromium() -> None:
        entry = proof_of_exploit._loop_browsers[asyncio.get_running_loop()]
        drivers.append(proof_of_exploit._driver_process(entry.starter))
        for pid, command in _live_descendants().items():
            if pid not in before and "chrom" in command.lower():
                os.kill(pid, signal.SIGSTOP)
                stopped.append(pid)

    def end_stopped() -> None:
        for pid in stopped:
            for sig in (signal.SIGCONT, signal.SIGKILL):
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, sig)

    open_context, open_page = proof_of_exploit.proof_browser_context, proof_of_exploit.proof_browser_page

    async def context_once_stopped(url, **options):
        if stops_before == "context" and not stopped:
            stop_chromium()
        return await open_context(url, **options)

    async def page_once_stopped(context, **options):
        if stops_before == "page" and not stopped:
            stop_chromium()
        return await open_page(context, **options)

    monkeypatch.setattr(proof_of_exploit, "proof_browser_context", context_once_stopped)
    monkeypatch.setattr(proof_of_exploit, "proof_browser_page", page_once_stopped)

    async def retest() -> tuple[dict, float]:
        verification = _verification(pages, "/vuln")
        started = time.monotonic()
        result = await run_proof_retest(
            verification, infer_retest_inputs(verification), poe=proof_of_exploit,
            replay_commands=[], ladder=[], cancelled=lambda: False)
        return result, time.monotonic() - started

    async def worker() -> list[tuple[dict, float]]:
        first = await retest()
        # The stopped browser is no longer needed: end it and its driver while this loop runs, so
        # nothing of it is left for the garbage collector to close on a closed loop.
        end_stopped()
        for driver in drivers:
            if driver is not None and driver.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    driver.kill()
                await asyncio.wait_for(driver.wait(), 30)
        return [first, await retest()]

    try:
        (first, first_seconds), (second, _) = _finishes(lambda: asyncio.run(worker()))
    finally:
        end_stopped()
    assert stopped, "no Chromium process to stop"
    assert first["verdict"] == "inconclusive", first["verdict_reason"]
    assert "did not answer" in first["verdict_reason"]
    assert first_seconds < bound_seconds + 15  # a browser launch and the baseline request
    assert second["verdict"] == "exploited", second["verdict_reason"]
    assert second["proof"]["technique"] == "headless_xss_console"


@pytest.mark.skipif(not hasattr(signal, "SIGSTOP"), reason="stopping a process needs POSIX signals")
def test_a_retest_cancelled_while_its_stopped_browser_is_let_go_still_ends(monkeypatch, pages):
    """Chromium is stopped (SIGSTOP) right before the retest opens its page, and the retest is
    cancelled (an authorization hard stop, a lost lease, a worker shutdown) while its browser is
    being let go, before the close bound runs out. The cancelled retest ends at once instead of
    waiting forever on the let-go browser's connection; and the next retest in the same worker loop
    launches another browser and proves the finding."""
    from scanner_tools import proof_of_exploit
    from worker_handlers.proof_replay import run_proof_retest

    monkeypatch.setattr(proof_of_exploit, "_poe_config",
                        dataclasses.replace(proof_of_exploit._poe_config, rate_limit_ms=0, enable_headless_xss=True))
    # A shorter handoff keeps the case short; closing keeps its production bound.
    monkeypatch.setattr(proof_of_exploit, "BROWSER_HANDOFF_TIMEOUT_SECONDS", 5.0)
    before = set(_live_descendants())
    stopped: list[int] = []
    drivers: list[Any] = []
    entries: list[Any] = []

    def stop_chromium() -> None:
        entry = proof_of_exploit._loop_browsers[asyncio.get_running_loop()]
        entries.append(entry)
        drivers.append(proof_of_exploit._driver_process(entry.starter))
        for pid, command in _live_descendants().items():
            if pid not in before and "chrom" in command.lower():
                os.kill(pid, signal.SIGSTOP)
                stopped.append(pid)

    def end_stopped() -> None:
        for pid in stopped:
            for sig in (signal.SIGCONT, signal.SIGKILL):
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, sig)

    open_page = proof_of_exploit.proof_browser_page

    async def page_once_stopped(context, **options):
        if not stopped:
            stop_chromium()
        return await open_page(context, **options)

    monkeypatch.setattr(proof_of_exploit, "proof_browser_page", page_once_stopped)

    async def retest() -> dict:
        verification = _verification(pages, "/vuln")
        return await run_proof_retest(
            verification, infer_retest_inputs(verification), poe=proof_of_exploit,
            replay_commands=[], ladder=[], cancelled=lambda: False)

    async def until_let_go() -> None:
        # The let-go starts by forgetting the browser, then stops its Playwright.
        while not entries or entries[0].browser is not None:
            await asyncio.sleep(0.05)

    async def worker() -> tuple[asyncio.Task, float | None, dict]:
        loop = asyncio.get_running_loop()
        first = loop.create_task(retest())
        await asyncio.wait_for(until_let_go(), 60)
        # Inside the stop of the let-go browser: its driver needs about 20 s to give up on a stopped
        # Chromium, so the close bound has not run out yet.
        await asyncio.sleep(2.0)
        first.cancel()
        cancelled_at = loop.time()
        done, _ = await asyncio.wait({first}, timeout=3 * proof_of_exploit.BROWSER_CLOSE_TIMEOUT_SECONDS)
        ended_after = loop.time() - cancelled_at if done else None
        # The stopped browser is no longer needed: end it and its driver while this loop runs, so
        # nothing of it is left for the garbage collector to close on a closed loop.
        end_stopped()
        for driver in drivers:
            if driver is not None and driver.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    driver.kill()
                await asyncio.wait_for(driver.wait(), 30)
        return first, ended_after, await retest()

    try:
        first, ended_after, second = _finishes(lambda: asyncio.run(worker()))
    finally:
        end_stopped()
    assert stopped, "no Chromium process to stop"
    assert ended_after is not None, "the cancelled retest was still running 30 s after its cancel"
    assert ended_after < 5.0
    assert first.cancelled()
    assert second["verdict"] == "exploited", second["verdict_reason"]
    assert second["proof"]["technique"] == "headless_xss_console"
