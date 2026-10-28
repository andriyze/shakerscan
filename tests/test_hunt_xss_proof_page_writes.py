"""A read-only XSS proof refuses every write; only a refused write that carried the payload
leaves the negative result incomplete. The page's own writes (socket polling, telemetry)
are outside the attempt, like off-origin subresources.

A fragment proof of a single-page application (``/#/search?query=test``) ran every same-origin
read and came back not proven, but the page's own Engine.IO long-polling POSTs
(``/socket.io/?EIO=...&transport=polling``, no payload) were refused during the settle, and the
Hunt reported the proof partial with ``browser_request_blocked:state_changing_method``. A page
that polls or sends telemetry could never get a complete negative. Unit fixtures: the browser is
a scripted double.
"""
from __future__ import annotations

import asyncio
import sys
import types
import urllib.parse

import pytest

from runtime.models import TargetBinding
from hunt.capability_executor import CapabilityAdapterResult
from hunt.fragment_xss_proof import (
    _normalize_hunt_browser_xss_result,
    hunt_browser_xss_proof_adapter,
)


def _browser_module():
    from hunt import fragment_xss_proof

    return sys.modules[fragment_xss_proof.XSSBrowserProofAdapter.__module__]


def _result(*, reasons, payload_write_blocked, proofs=1):
    proof = {"kind": "xss_browser_proof", "proof_state": "not_proven"}
    if payload_write_blocked is not None:
        proof["payload_write_blocked"] = payload_write_blocked
    return CapabilityAdapterResult(
        status="success",
        observations=(*([proof] * proofs), *({
            "kind": "browser_request_blocked", "reason": reason, "method": "POST",
            "url": "https://app.example.test/socket.io/",
        } for reason in reasons)),
        actual_budget={"browser_actions": 2, "http_requests": 3},
        execution_started=True,
        parser_version="xss-browser-proof/v1",
    )


def test_page_initiated_writes_do_not_make_a_negative_partial():
    result = _normalize_hunt_browser_xss_result(_result(
        reasons=("cross_origin", "state_changing_method"), payload_write_blocked=False,
    ))
    assert (result.status, result.partial, result.errors) == ("success", False, ())


@pytest.mark.parametrize("flag", [True, None])
def test_blocked_payload_write_or_unknown_stays_partial(flag):
    result = _normalize_hunt_browser_xss_result(_result(
        reasons=("state_changing_method",), payload_write_blocked=flag,
    ))
    assert result.status == "partial" and result.partial is True
    assert result.errors == ("browser_request_blocked:state_changing_method",)


def test_every_proof_must_say_no_refused_write_carried_its_payload():
    clear = {"kind": "xss_browser_proof", "proof_state": "not_proven", "payload_write_blocked": False}
    for other in ({**clear, "payload_write_blocked": True}, {"kind": "xss_browser_proof"}):
        result = _normalize_hunt_browser_xss_result(CapabilityAdapterResult(
            status="success",
            observations=(clear, other, {"kind": "browser_request_blocked",
                                         "reason": "state_changing_method"}),
            actual_budget={"browser_actions": 2}, execution_started=True,
            parser_version="xss-browser-proof/v1",
        ))
        assert result.status == "partial", other
    assert _normalize_hunt_browser_xss_result(_result(
        reasons=("state_changing_method",), payload_write_blocked=False, proofs=2,
    )).status == "success"
    # No proof observation at all: nothing says the writes were the page's own.
    assert _normalize_hunt_browser_xss_result(CapabilityAdapterResult(
        status="success", observations=({"kind": "browser_request_blocked", "reason": "state_changing_method"},),
        actual_budget={"browser_actions": 2}, execution_started=True, parser_version="xss-browser-proof/v1",
    )).status == "partial"


def test_page_writes_do_not_hide_an_exhausted_request_budget():
    result = _normalize_hunt_browser_xss_result(_result(
        reasons=("state_changing_method", "request_budget_exhausted"),
        payload_write_blocked=False,
    ))
    assert result.status == "partial"
    assert result.errors == ("browser_request_blocked:request_budget_exhausted",)


def _run_proof(
    monkeypatch, *, write_carries_payload: bool, status: int = 200,
    execution_target: str = "https://app.example.test/#/search?q=seed",
    deep_domxss: bool = False,
):
    class FakePinnedProxy:
        def __init__(self, **_kwargs):
            self.socket_factory = types.SimpleNamespace(policy_receipt={})
            self.address_attempts = {"192.0.2.10": 1}
            self.address_connections = {"192.0.2.10": 1}
            self.proxy_url = "socks5://127.0.0.1:41000"

        async def start(self): return self
        async def close(self): return None

    # The browser module the Hunt prover runs in, whichever import layout loaded it.
    monkeypatch.setattr(_browser_module(), "PinnedSocksProxy", FakePinnedProxy)
    sent, aborted = [], []

    class FakeRequest:
        def __init__(self, method, url, body=None):
            self.method, self.url, self.post_data_buffer = method, url, body
            self.headers = {}

    class FakeRoute:
        def __init__(self, request): self.request = request
        async def abort(self, _reason): aborted.append(self.request.method)
        async def continue_(self, **_kw): sent.append(self.request.method)

    class FakeResponse:
        def __init__(self, url):
            self.url, self.status, self.headers = url, status, {"content-type": "text/html"}
            self.request = FakeRequest("GET", url)

    class FakePage:
        def __init__(self, marker): self.url, self._marker, self.route = "about:blank", marker, None
        def on(self, *_a): return None
        async def goto(self, url, **_kw):
            await self.route(FakeRoute(FakeRequest("GET", url)))
            # socket.io long polling sends its packets upstream with POST.
            await self.route(FakeRoute(FakeRequest(
                "POST", "https://app.example.test/socket.io/?EIO=4&transport=polling", b"40",
            )))
            if write_carries_payload:
                await self.route(FakeRoute(FakeRequest(
                    "POST", "https://app.example.test/api/search",
                    ('{"q":"%s"}' % self._marker).encode(),
                )))
            self.url = url
            return FakeResponse(url)
        async def get_attribute(self, *_a): return None

    class FakeContext:
        def __init__(self, page): self._page = page
        async def route(self, _pattern, handler): self._page.route = handler
        def on(self, *_a): return None
        async def add_init_script(self, _s): return None
        async def new_page(self): return self._page
        async def close(self): return None

    target = TargetBinding(
        target_id="target-1", target_kind="web", canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",), allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
    )
    adapter = hunt_browser_xss_proof_adapter(
        capability_name="xss.verify", spec=None, target=target,
        execution_target=execution_target, action_id="action-1", deep_domxss=deep_domxss,
    )
    page = FakePage(adapter.prepared.marker)

    class FakeBrowser:
        version = "fake/1"
        async def new_context(self, **_kw): return FakeContext(page)
        async def close(self): return None

    class FakeChromium:
        async def launch(self, **_kw): return FakeBrowser()

    class FakePlaywright:
        chromium = FakeChromium()
        async def stop(self): return None

    class FakeStarter:
        async def start(self): return FakePlaywright()

    async_api = types.ModuleType("playwright.async_api")
    async_api.TimeoutError = type("FakePlaywrightTimeout", (Exception,), {})
    async_api.async_playwright = lambda: FakeStarter()
    package = types.ModuleType("playwright")
    package.async_api = async_api
    monkeypatch.setitem(sys.modules, "playwright", package)
    monkeypatch.setitem(sys.modules, "playwright.async_api", async_api)
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)

    async def heartbeat(): return None
    result = asyncio.run(adapter.execute(heartbeat=heartbeat, cancelled=lambda: False))
    return result, sent, aborted


_real_sleep = asyncio.sleep


async def _no_sleep(_seconds, *a, **kw):
    await _real_sleep(0)


def test_background_socket_poll_is_refused_and_negative_is_complete(monkeypatch):
    result, sent, aborted = _run_proof(monkeypatch, write_carries_payload=False)
    assert sent == ["GET"] and aborted == ["POST"]  # still read-only
    proof = next(o for o in result.observations if o.get("kind") == "xss_browser_proof")
    assert proof["proof_state"] == "not_proven"
    assert proof["payload_write_blocked"] is False
    assert (result.status, result.partial, result.errors) == ("success", False, ())


def test_refused_write_carrying_the_payload_keeps_the_negative_partial(monkeypatch):
    result, sent, aborted = _run_proof(monkeypatch, write_carries_payload=True)
    assert sent == ["GET"] and aborted == ["POST", "POST"]
    proof = next(o for o in result.observations if o.get("kind") == "xss_browser_proof")
    assert proof["payload_write_blocked"] is True
    assert result.status == "partial"
    assert "browser_request_blocked:state_changing_method" in result.errors



@pytest.mark.parametrize("status", [503, 429, 404, 500])
def test_a_fragment_proof_page_the_service_did_not_serve_settles_partial(monkeypatch, status):
    """``xss.verify``'s browser proof is the Scan's adapter: a client route whose page the service
    answered with 503, 429, a missing page or a server error (the server never saw the fragment's
    payload) is no verdict, and the Hunt's own normalization keeps it partial."""
    result, sent, _aborted = _run_proof(monkeypatch, write_carries_payload=False, status=status)
    assert sent == ["GET"]
    proof = next(o for o in result.observations if o.get("kind") == "xss_browser_proof")
    assert proof["injection_location"] == "fragment"
    assert (proof["proof_state"], proof["inconclusive_reason"]) == ("not_proven", "target_unavailable")
    assert (result.status, result.partial) == ("partial", True)
    assert result.errors == (f"target_unavailable:{status}",)


@pytest.mark.parametrize("status, partial", [(503, True), (429, True), (404, False), (500, False)])
def test_a_deep_query_proof_reads_only_a_service_refusal_as_no_verdict(monkeypatch, status, partial):
    """An explicit deep query proof sends its payload to the server, which may answer that payload
    itself with 404 or 500: there only 408, 429, 502-504 (or no answer) leave the attempt partial."""
    result, sent, _aborted = _run_proof(
        monkeypatch, write_carries_payload=False, status=status,
        execution_target="https://app.example.test/search?q=seed", deep_domxss=True,
    )
    assert sent == ["GET"]
    proof = next(o for o in result.observations if o.get("kind") == "xss_browser_proof")
    assert proof["injection_location"] == "query"
    assert proof["proof_state"] == "not_proven"
    if partial:
        assert (result.status, result.errors) == ("partial", (f"target_unavailable:{status}",))
        assert proof["inconclusive_reason"] == "target_unavailable"
    else:
        assert (result.status, result.partial, result.errors) == ("success", False, ())
        assert "inconclusive_reason" not in proof

class _Request:
    def __init__(self, url, body=b"", unreadable=False):
        self.url, self._body, self._unreadable = url, body, unreadable

    @property
    def post_data_buffer(self):
        if self._unreadable:
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "fixture")
        return self._body


MARKER = "shakerscan_xss_0123abcd-ef0"
PAYLOAD = (
    '<img src=x onerror="document.documentElement.setAttribute(\'data-shakerscan-proof\','
    f"'{MARKER}');console.log('{MARKER}')\">"
)


def _carries(url, body=b"", **kwargs):
    return _browser_module()._carries_marker(_Request(url, body, **kwargs), MARKER)


def test_the_marker_is_found_as_text_in_a_url_form_or_json_write():
    assert _carries(f"https://a.test/api?q=%3Cimg%20{MARKER}%3E")
    assert _carries("https://a.test/api", ('{"q":"<img %s>"}' % MARKER).encode())
    assert _carries("https://a.test/api", f"q=%3Cimg+{MARKER}%3E".encode())
    assert _carries("https://a.test/api", urllib.parse.quote(urllib.parse.quote(PAYLOAD)).encode())


def _every_byte_encoded(text):
    return "".join(f"%{byte:02X}" for byte in text.encode())


def test_the_marker_is_found_when_every_byte_of_the_write_is_percent_encoded():
    # An encoder that escapes every byte (and the browser's own encoding of that, once more).
    encoded = _every_byte_encoded(PAYLOAD)
    assert MARKER not in encoded
    assert _carries(f"https://a.test/api?d={encoded}")
    assert _carries("https://a.test/api", encoded.encode())
    assert _carries("https://a.test/api", urllib.parse.quote(encoded).encode())
    utf16 = PAYLOAD.encode("utf-16-le").decode("latin-1")
    assert _carries("https://a.test/api", _every_byte_encoded(utf16).encode())


@pytest.mark.parametrize("prefix", ["", "a", "ab", "abc", '{"state":"'])
def test_the_marker_is_found_when_the_page_base64_encodes_what_it_writes(prefix):
    import base64

    for encode in (base64.b64encode, base64.urlsafe_b64encode):
        encoded = encode((prefix + PAYLOAD).encode())
        assert _carries("https://a.test/api", encoded), (prefix, encode)
        assert _carries("https://a.test/api", b'{"blob":"' + encoded + b'"}')
        assert _carries("https://a.test/api", b"blob=" + urllib.parse.quote(encoded).encode())
        assert _carries(f"https://a.test/api?s={urllib.parse.quote(encoded.decode())}")
    # A JSON serializer that escapes "/" in the base64 text: the marker's runs never hold one.
    assert _carries("https://a.test/api", base64.b64encode((prefix + PAYLOAD).encode()).replace(b"/", b"\\/"))


def test_the_marker_is_found_in_hex_utf16_and_compressed_writes():
    import gzip
    import zlib

    raw = (MARKER + PAYLOAD).encode()
    assert _carries("https://a.test/api", raw.hex().encode())
    assert _carries("https://a.test/api", PAYLOAD.encode("utf-16-le"))
    assert _carries("https://a.test/api", PAYLOAD.encode("utf-16-be"))
    assert _carries("https://a.test/api", gzip.compress(raw))
    assert _carries("https://a.test/api", zlib.compress(raw))
    deflate = zlib.compressobj(wbits=-15)
    assert _carries("https://a.test/api", deflate.compress(raw) + deflate.flush())


def test_a_page_write_without_the_marker_is_the_pages_own():
    assert not _carries("https://a.test/socket.io/?EIO=4&transport=polling", b"40")
    assert not _carries("https://a.test/socket.io/?EIO=4&transport=polling&sid=Zx9Qp2", b"2")
    assert not _carries("https://a.test/telemetry", None)
    assert not _carries("https://a.test/telemetry", b'{"event":"view","path":"/#/search"}')
    import gzip

    assert not _carries("https://a.test/telemetry", gzip.compress(b'{"event":"view"}'))


def test_a_write_the_proof_cannot_read_counts_as_carrying_the_payload():
    # A body the proof cannot read, or one larger than it searches, is not evidence of a
    # page-only write.
    assert _carries("https://a.test/api", unreadable=True)
    window = _browser_module()._MARKER_SEARCH_BYTES
    assert _carries("https://a.test/api", b"x" * (window + 1))
    assert not _carries("https://a.test/api", b"x" * window)
