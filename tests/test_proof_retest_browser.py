"""A verified browser XSS finding is retested by the oracle that proved it, in a real browser.

The browser proof's payload sets an attribute on the page's root element and logs a marker named
after its candidate; it proves execution only when that attribute holds the marker, or a console
or dialog message is exactly the marker. The retest must judge the same way, or "likely fixed"
and "still vulnerable" would come from a different check than the one that found the finding:

* a page that silences the console but still runs the payload is still vulnerable (the attribute);
* a fixed page that escapes the input and logs it, or raises its own dialog, is not reproduced;
* a page behind a sign-in is retested with the Scan's session, which reaches only its origin.

The pages are a local fixture server (unit fixtures); the retest is the real ``run_proof_retest``
with the real proof module, its HTTP client and its headless browser.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import sys
import threading
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
        return self._send(404, "not found")


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
        try:
            return await run_proof_retest(
                verification, infer_retest_inputs(verification), poe=proof_of_exploit,
                replay_commands=[], ladder=[], cancelled=lambda: False)
        finally:
            # The proof keeps one browser per event loop; close it with this loop.
            browser, playwright = proof_of_exploit._browser_instance, proof_of_exploit._playwright_instance
            proof_of_exploit._browser_instance = proof_of_exploit._playwright_instance = None
            if browser is not None:
                await browser.close()
            if playwright is not None:
                await playwright.stop()

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


def test_the_marker_is_the_one_the_browser_proof_looks_for():
    payload = xss_proof_payload(CANDIDATE)
    marker = xss_proof_marker(CANDIDATE)
    assert f"setAttribute('data-shakerscan-proof','{marker}')" in payload
    assert f"console.log('{marker}')" in payload
