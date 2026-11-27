"""The headless proof browser belongs to the event loop that started it.

Playwright's connection to its browser is bound to the event loop that started it. From any other
loop (a second ``asyncio.run`` in the same process, or a loop on another thread) a call on it waits
for an answer that is never delivered, and nothing times out. The proof module keeps one browser
between proofs, so:

* a second event loop, on the same thread or on another one, gets a browser of its own and proves
  exactly as the first did, also while the first loop is still running;
* one loop reuses its browser from proof to proof (a long-lived worker's case);
* the browser a loop started is closed when that loop ends, so nothing it started keeps running;
* a browser that does not answer, at launch or when a proof opens its page, fails the proof within
  a bound instead of holding it forever.

A hang must show as a failure, not as a stalled run: every case runs on a thread of its own and
fails when it has not finished within ``HANG_LIMIT_SECONDS``.

The pages are a local fixture server (unit fixtures) and the browser is the real headless Chromium,
except in the last cases, where a stand-in Playwright (a unit fixture) never answers.
"""

from __future__ import annotations

import asyncio
import dataclasses
import gc
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Any, Callable
import urllib.parse

import pytest

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

playwright_api = pytest.importorskip("playwright.async_api")

from capabilities.xss_proof_payload import xss_proof_payload  # noqa: E402

CANDIDATE = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
PAYLOAD = xss_proof_payload(CANDIDATE)
# One browser launch and two proofs take about 6 s on a loaded test host.
HANG_LIMIT_SECONDS = 90.0
# The stand-in browser's bounds, and how long a bounded failure may take in all.
SHORT_BOUND_SECONDS = 0.5
BOUNDED_FAILURE_SECONDS = 30.0


class _Page(BaseHTTPRequestHandler):
    """A search page that reflects its query unescaped (unit fixture)."""

    def log_message(self, *_args):
        return None

    def do_GET(self):  # noqa: N802 - http.server API
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query)).get("q", "")
        data = f"<html><body><h1>Results for {q}</h1></body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def page_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Page)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/search"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def poe(monkeypatch):
    from scanner_tools import proof_of_exploit

    monkeypatch.setattr(proof_of_exploit, "_poe_config", dataclasses.replace(
        proof_of_exploit._poe_config, rate_limit_ms=0, enable_headless_xss=True))
    return proof_of_exploit


def _finishes(work: Callable[[], Any], *, seconds: float = HANG_LIMIT_SECONDS) -> Any:
    """``work()``'s result, run on a thread of its own: a hang fails the test, not the run."""
    box: dict[str, Any] = {}

    def run() -> None:
        try:
            box["result"] = work()
        except BaseException as exc:  # noqa: BLE001 - re-raised on the test's thread
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True, name="proof-browser-case")
    thread.start()
    thread.join(seconds)
    if thread.is_alive():
        pytest.fail(f"still waiting after {seconds:.0f} s: the browser proof hung")
    if "error" in box:
        raise box["error"]
    return box["result"]


def _on_new_thread(work: Callable[[], Any]) -> Any:
    """``work()``'s result, run on a new thread (the caller's ``_finishes`` bounds it)."""
    box: dict[str, Any] = {}

    def run() -> None:
        try:
            box["result"] = work()
        except BaseException as exc:  # noqa: BLE001 - re-raised on the caller's thread
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join()
    if "error" in box:
        raise box["error"]
    return box["result"]


async def _prove(poe, url: str) -> dict:
    """One Scan browser proof of the page's query parameter, in the running loop."""
    return (await poe.prove_xss_headless(url, "q", PAYLOAD)).to_dict()


def _assert_proved(proof: dict) -> None:
    assert proof["proven"] is True, proof
    assert proof["technique"] == "headless_xss_console", proof


def _live_descendants() -> set[int]:
    """Processes still running (not zombies) that descend from this test process."""
    lister = subprocess.Popen(["ps", "-A", "-o", "pid=,ppid=,stat="], stdout=subprocess.PIPE, text=True)
    out, _ = lister.communicate(timeout=30)
    children: dict[int, list[int]] = {}
    for line in out.splitlines():
        fields = line.split()
        if len(fields) >= 3 and not fields[2].startswith("Z"):
            children.setdefault(int(fields[1]), []).append(int(fields[0]))
    found: set[int] = set()
    todo = [os.getpid()]
    while todo:
        for child in children.get(todo.pop(), ()):
            if child not in found and child != lister.pid:
                found.add(child)
                todo.append(child)
    return found


def _assert_nothing_left(before: set[int], *, seconds: float = 30.0) -> None:
    """Every process the proofs started (Playwright's driver, Chromium) has exited."""
    deadline = time.monotonic() + seconds
    left = _live_descendants() - before
    while left and time.monotonic() < deadline:
        time.sleep(0.2)
        left = _live_descendants() - before
    assert not left, f"{len(left)} processes the proofs started still run after their event loop ended"


def test_a_second_asyncio_run_on_the_same_thread_gets_a_working_browser(poe, page_url):
    before = _live_descendants()
    first, second = _finishes(lambda: [asyncio.run(_prove(poe, page_url)) for _ in range(2)])
    _assert_proved(first)
    _assert_proved(second)
    _assert_nothing_left(before)


def test_proofs_on_two_threads_one_after_the_other_each_get_a_working_browser(poe, page_url):
    before = _live_descendants()
    first, second = _finishes(lambda: [
        _on_new_thread(lambda: asyncio.run(_prove(poe, page_url))) for _ in range(2)])
    _assert_proved(first)
    _assert_proved(second)
    _assert_nothing_left(before)


def test_a_proof_on_another_thread_while_the_first_loop_still_runs(poe, page_url):
    """The first loop keeps its browser while a loop on another thread proves with its own."""
    before = _live_descendants()

    def work() -> dict:
        results: dict[str, dict] = {}
        proved_once = threading.Event()
        release = threading.Event()

        async def first() -> None:
            results["first"] = await _prove(poe, page_url)
            proved_once.set()
            while not release.is_set():  # this loop, and its browser, stay up meanwhile
                await asyncio.sleep(0.05)
            results["first, again"] = await _prove(poe, page_url)

        first_thread = threading.Thread(target=lambda: asyncio.run(first()), daemon=True)
        first_thread.start()
        proved_once.wait()
        try:
            results["other thread"] = _on_new_thread(lambda: asyncio.run(_prove(poe, page_url)))
        finally:
            release.set()
        first_thread.join()
        return results

    results = _finishes(work)
    assert set(results) == {"first", "other thread", "first, again"}
    for proof in results.values():
        _assert_proved(proof)
    _assert_nothing_left(before)


def test_a_loop_run_again_from_another_thread_starts_a_browser_of_its_own_there(poe, page_url):
    """A browser is handed back only on the thread that started it, even within one loop."""
    before = _live_descendants()

    async def proof_and_browser() -> tuple[dict, Any]:
        return await _prove(poe, page_url), await poe._get_browser()

    def work() -> tuple[dict, dict, bool]:
        runner = asyncio.Runner()
        try:
            first, first_browser = _on_new_thread(lambda: runner.run(proof_and_browser()))
            second, second_browser = _on_new_thread(lambda: runner.run(proof_and_browser()))
        finally:
            _on_new_thread(runner.close)  # as asyncio.run ends a loop: its tasks are cancelled
        return first, second, first_browser is second_browser

    first, second, same_browser = _finishes(work)
    _assert_proved(first)
    _assert_proved(second)
    assert same_browser is False
    _assert_nothing_left(before)


def test_one_event_loop_reuses_its_browser_from_proof_to_proof(poe, page_url):
    """A long-lived worker's loop launches the browser once and proves with it each time."""

    async def work() -> tuple[bool, dict, dict]:
        first = await _prove(poe, page_url)
        browser = await poe._get_browser()
        second = await _prove(poe, page_url)
        return browser is await poe._get_browser(), first, second

    reused, first, second = _finishes(lambda: asyncio.run(work()))
    assert reused is True
    _assert_proved(first)
    _assert_proved(second)


def test_proofs_that_start_together_in_one_loop_launch_one_browser(poe, page_url):
    before = _live_descendants()

    async def work() -> tuple[bool, list[dict]]:
        browsers = await asyncio.gather(poe._get_browser(), poe._get_browser())
        proofs = await asyncio.gather(_prove(poe, page_url), _prove(poe, page_url))
        return browsers[0] is browsers[1] is await poe._get_browser(), proofs

    one_browser, proofs = _finishes(lambda: asyncio.run(work()))
    assert one_browser is True
    for proof in proofs:
        _assert_proved(proof)
    _assert_nothing_left(before)


def test_a_browser_that_disconnected_is_replaced_and_its_driver_stopped(poe, page_url):
    before = _live_descendants()

    async def work() -> tuple[bool, dict]:
        first = await poe._get_browser()
        await first.close()  # Chromium went away; its Playwright driver did not
        second = await poe._get_browser()
        return second is not first and second.is_connected(), await _prove(poe, page_url)

    replaced, proof = _finishes(lambda: asyncio.run(work()))
    assert replaced is True
    _assert_proved(proof)
    _assert_nothing_left(before)


def test_the_browser_a_loop_started_is_closed_when_the_loop_ends(poe, page_url):
    """And its driver has exited before the loop closed: nothing of it is left for the garbage
    collector to close on a closed loop ("Event loop is closed")."""
    before = _live_descendants()
    unraisable: list[str] = []
    hook = sys.unraisablehook
    sys.unraisablehook = lambda report: unraisable.append(f"{report.exc_type.__name__}: {report.exc_value}")
    try:
        _assert_proved(_finishes(lambda: asyncio.run(_prove(poe, page_url))))
        gc.collect()
    finally:
        sys.unraisablehook = hook
    assert unraisable == []
    _assert_nothing_left(before)


# --- A browser that does not answer (stand-in Playwright, unit fixtures) ---------------------------


async def _never() -> None:
    await asyncio.get_running_loop().create_future()


class _UnansweringBrowser:
    """Says it is connected, and never answers at ``hangs_at``: opening a context or a page in one
    (unit fixture)."""

    def __init__(self, log: list[str], hangs_at: str):
        self.log, self.hangs_at = log, hangs_at

    def is_connected(self) -> bool:
        return True

    async def new_context(self, **_options):
        self.log.append("new_context")
        if self.hangs_at == "new_context":
            await _never()
        return _UnansweringContext(self)

    async def close(self):
        self.log.append("browser.close")
        await _never()


class _UnansweringContext:
    def __init__(self, browser: _UnansweringBrowser):
        self.browser = browser

    async def route(self, _pattern, _handler):
        self.browser.log.append("route")

    async def new_page(self):
        self.browser.log.append("new_page")
        await _never()

    async def close(self):
        self.browser.log.append("context.close")


class _StandInPlaywright:
    """``async_playwright()`` whose browsers never answer; or which never starts (unit fixture)."""

    def __init__(self, *, starts: bool = True, hangs_at: str = "new_context"):
        self.starts, self.hangs_at = starts, hangs_at
        self.log: list[str] = []
        self.chromium = self

    def __call__(self):
        return self

    async def start(self):
        self.log.append("start")
        if not self.starts:
            await _never()
        return self

    async def launch(self, **_options):
        self.log.append("launch")
        return _UnansweringBrowser(self.log, self.hangs_at)

    async def stop(self):
        self.log.append("stop")

    async def __aenter__(self):
        return await self.start()

    async def __aexit__(self, *_args):
        await self.stop()


@pytest.fixture
def stand_in(monkeypatch, poe):
    def install(**options) -> _StandInPlaywright:
        fake = _StandInPlaywright(**options)
        monkeypatch.setattr(playwright_api, "async_playwright", fake)
        for name in ("BROWSER_LAUNCH_TIMEOUT_SECONDS", "BROWSER_HANDOFF_TIMEOUT_SECONDS",
                     "BROWSER_CLOSE_TIMEOUT_SECONDS"):
            monkeypatch.setattr(poe, name, SHORT_BOUND_SECONDS, raising=False)
        return fake
    return install


@pytest.mark.parametrize("hangs_at", ["new_context", "new_page"])
def test_a_browser_that_does_not_answer_fails_the_proof_and_is_replaced(poe, stand_in, hangs_at):
    fake = stand_in(hangs_at=hangs_at)

    async def work() -> list[dict]:
        page = await poe.prove_xss_headless("http://127.0.0.1:9/search", "q", PAYLOAD)
        rendered = await poe.prove_xss_response_headless(f"<html><body>{PAYLOAD}</body></html>", PAYLOAD)
        return [page.to_dict(), rendered.to_dict()]

    started = time.monotonic()
    proofs = _finishes(lambda: asyncio.run(work()), seconds=BOUNDED_FAILURE_SECONDS)
    assert time.monotonic() - started < BOUNDED_FAILURE_SECONDS
    assert [proof["proven"] for proof in proofs] == [False, False]
    # Each proof found the browser unanswering; it was let go and the next proof launched another.
    assert fake.log.count(hangs_at) == 2
    launches = [index for index, call in enumerate(fake.log) if call == "launch"]
    assert len(launches) == 2
    assert "stop" in fake.log[launches[0]:launches[1]]


def test_a_session_proof_whose_browser_does_not_answer_leaves_no_proxy_listening(poe, stand_in, monkeypatch):
    """A proof with session headers opens a confined context behind a local proxy; when the browser
    never opens that context, the proxy stops with the attempt."""
    from scanner_tools import destination_guard

    started: list = []
    start = destination_guard.GuardProxy.start

    async def recorded_start(self):
        started.append(self)
        return await start(self)

    monkeypatch.setattr(destination_guard.GuardProxy, "start", recorded_start)
    stand_in(hangs_at="new_context")

    proof = _finishes(lambda: asyncio.run(poe.prove_xss_headless(
        "http://127.0.0.1:9/search", "q", PAYLOAD, headers={"X-API-Key": "fixture-session"})),
        seconds=BOUNDED_FAILURE_SECONDS)
    assert proof.proven is False
    assert started, "the confined context's proxy never started"
    assert [proxy.server for proxy in started] == [None] * len(started)


def test_a_browser_that_never_starts_fails_the_proof_within_the_bound(poe, stand_in):
    fake = stand_in(starts=False)

    async def work() -> tuple[bool, dict, dict, Any]:
        available = await poe.headless_browser_available()
        page = await poe.prove_xss_headless("http://127.0.0.1:9/search", "q", PAYLOAD)
        rendered = await poe.prove_xss_response_headless(f"<html><body>{PAYLOAD}</body></html>", PAYLOAD)
        context = await poe.proof_browser_context("http://127.0.0.1:9/search")
        return available, page.to_dict(), rendered.to_dict(), context

    available, page, rendered, context = _finishes(lambda: asyncio.run(work()), seconds=BOUNDED_FAILURE_SECONDS)
    assert available is False
    assert page["proven"] is False and rendered["proven"] is False
    assert context is None
    assert "launch" not in fake.log
