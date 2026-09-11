"""Local wire tests for the browser action's existing pinned transport boundary."""
import asyncio
from dataclasses import replace
import ssl

import pytest

from runtime.models import TargetBinding
from runtime.pinned_http_replay import PinnedAiohttpReplayTransport
from runtime.request_replay_executor import ReplayExecutionError, MAX_REPLAY_RESPONSE_BODY_BYTES
from scanner.scanner_tools.request_replay import ReplayRequest
from scanner.scanner_tools import browser_profile as bp


async def send_fixture(chunks, *, headers=b"", strict=False, declared_length=None):
    async def serve(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            size = sum(len(x) for x in chunks) if declared_length is None else declared_length
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(size).encode() + b"\r\n" + headers + b"Connection: close\r\n\r\n")
            await writer.drain()
            for chunk in chunks:
                writer.write(chunk)
                await writer.drain()
                await asyncio.sleep(0.01)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    origin = f"http://browser-fixture.test:{server.sockets[0].getsockname()[1]}"
    target = TargetBinding(target_id="synthetic-target", target_kind="web",
                          canonical_host="browser-fixture.test", allowed_origins=(origin,),
                          allowed_addresses=("127.0.0.1",))
    request = ReplayRequest("fixture", 1, "fixture", "", "GET", origin + "/", (), b"", "raw", "none", False)
    try:
        return await PinnedAiohttpReplayTransport(verify_tls=True, reject_duplicate_response_headers=strict).send(
            request, target=target, timeout_seconds=2, follow_redirects=False)
    finally:
        server.close()
        await server.wait_closed()


def test_chunked_delivery_is_read_to_eof_instead_of_silently_truncated():
    result = asyncio.run(send_fixture([b"first", b"second", b"third"]))
    assert result.response_body == b"firstsecondthird"
    assert result.connected_address == "127.0.0.1"


@pytest.mark.parametrize("headers", [
    b"Set-Cookie: a=synthetic\r\nSet-Cookie: b=synthetic\r\n",
    b"Location: /one\r\nlocation: /two\r\n",
])
def test_strict_browser_response_rejects_lossy_repeated_headers(headers):
    with pytest.raises(ReplayExecutionError, match="repeated headers"):
        asyncio.run(send_fixture([b"synthetic"], headers=headers, strict=True))


def test_oversized_body_fails_instead_of_returning_partial_html():
    with pytest.raises(ReplayExecutionError, match="capture limit"):
        asyncio.run(send_fixture([b"x" * (MAX_REPLAY_RESPONSE_BODY_BYTES + 1)], strict=True))


def test_truncated_response_is_not_reported_as_completed():
    result = asyncio.run(send_fixture([b"short"], declared_length=100))
    assert result.error_code == "transport_error"
    assert result.status_code is None


def test_profile_cookies_have_bounded_restart_persistence(monkeypatch):
    monkeypatch.setattr(bp.time, "time", lambda: 1000)
    cookies = bp._cookies("session=synthetic; marker=", origin="https://browser-fixture.test")
    assert {item["name"]: item["value"] for item in cookies} == {"session": "synthetic", "marker": ""}
    assert all(item["expires"] == 1000 + bp.BROWSER_PROFILE_COOKIE_TTL_SECONDS for item in cookies)
    assert all(item["secure"] for item in cookies)
