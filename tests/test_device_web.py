import asyncio
import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import device_web  # noqa: E402


class _Reader:
    def __init__(self):
        self.remaining = b""

    async def readuntil(self, _separator):
        return b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

    async def readexactly(self, count):
        data, self.remaining = self.remaining[:count], self.remaining[count:]
        return data

    async def readline(self):
        return b"0\r\n"

    async def read(self, _limit):
        return b""


class _Writer:
    def __init__(self):
        self.data = b""

    def write(self, data):
        self.data += data

    async def drain(self):
        return None

    def close(self):
        return None

    async def wait_closed(self):
        return None


def test_device_web_connects_to_pinned_address_with_registered_host_and_sni(monkeypatch):
    calls = []
    writers = []

    async def fake_open_connection(host, port, **kwargs):
        writer = _Writer()
        calls.append((host, port, kwargs.get("server_hostname")))
        writers.append(writer)
        return _Reader(), writer

    monkeypatch.setattr(device_web.asyncio, "open_connection", fake_open_connection)
    result = asyncio.run(device_web.run_pinned_device_web_scan({
        "origin": "https://tv.example.test:8443",
        "connect_address": "192.0.2.10",
        "port": 8443,
        "host_header": "tv.example.test:8443",
    }, profile="quick"))

    assert calls == [("192.0.2.10", 8443, "tv.example.test")]
    assert b"Host: tv.example.test:8443\r\n" in writers[0].data
    assert result["http"]["remote_ip"] == "192.0.2.10"
    assert result["scan_metadata"]["pinned_destination"] is True


def test_device_web_cancellation_interrupts_an_inflight_request(monkeypatch):
    async def slow_request(**_kwargs):
        await asyncio.sleep(30)
        return {}

    checks = 0

    async def cancelled():
        nonlocal checks
        checks += 1
        return checks >= 2

    monkeypatch.setattr(device_web, "_request", slow_request)
    result = asyncio.run(device_web.run_pinned_device_web_scan({
        "origin": "http://tv.example.test:8008",
        "connect_address": "192.0.2.10",
        "port": 8008,
        "host_header": "tv.example.test:8008",
    }, profile="quick", cancel_check=cancelled))
    assert result["error"] == "Cancelled by user"


def test_device_web_finishes_content_length_response_without_waiting_for_server_close(monkeypatch):
    class KeepAliveReader:
        async def readuntil(self, _separator):
            return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\n"

        async def readexactly(self, count):
            assert count == 2
            return b"OK"

    async def fake_open_connection(*_args, **_kwargs):
        return KeepAliveReader(), _Writer()

    monkeypatch.setattr(device_web.asyncio, "open_connection", fake_open_connection)
    result = asyncio.run(device_web.run_pinned_device_web_scan({
        "origin": "https://192.0.2.10:3001",
        "connect_address": "192.0.2.10",
        "port": 3001,
    }, profile="quick"))
    assert result["http"]["status_code"] == 200
    assert result["device_web"]["observations"][0]["body_bytes"] == 2


def test_public_response_headers_redact_redirect_secrets_and_auth_challenges():
    public = device_web._public_response_headers({
        "location": "https://device.test/callback?token=secret-token",
        "www-authenticate": 'Digest realm="device", nonce="secret-nonce"',
        "set-cookie": "session=secret-cookie; Secure",
    })

    assert "secret-token" not in public["location"]
    assert "%3Credacted%3E" in public["location"]
    assert "www-authenticate" not in public
    assert public["set-cookie"] == "<redacted>"
