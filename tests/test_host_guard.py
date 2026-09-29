"""DNS rebinding cannot read the tokenless API through a foreign host name."""

from __future__ import annotations

import asyncio

import pytest

import host_guard
from host_guard import TrustedHostGuardMiddleware, host_is_allowed


async def _drive(app, scope):
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    return sent


async def _ok_app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def _scope(host: str, *, extra: list[tuple[bytes, bytes]] | None = None, kind: str = "http"):
    headers = [(b"host", host.encode("latin-1"))] if host else []
    return {"type": kind, "method": "GET", "path": "/findings", "headers": headers + (extra or [])}


@pytest.mark.parametrize(
    "host",
    [
        "", "localhost:8080", "127.0.0.1:8080", "[::1]:8080", "192.168.1.50:8080",
        "100.100.100.100:8080", "api:8080", "worker", "ui.localhost:3000", "shaker.local:8080",
        "nas.lan", "box.home.arpa", "engine.internal:8080", "vps.tail1234.ts.net:8080",
    ],
)
def test_addresses_an_attacker_cannot_rebind_are_allowed(host):
    assert host_is_allowed(host) is True


@pytest.mark.parametrize("host", ["attacker.example:8080", "rebind.example.com", "evil.ts.net.example.com"])
def test_public_dns_names_are_refused_by_default(host):
    assert host_is_allowed(host) is False


def test_configured_names_are_allowed():
    assert host_is_allowed("scan.example.com:8080", public_host="scan.example.com")
    assert host_is_allowed("ui.example.com", allow_origins=["https://ui.example.com"])
    assert host_is_allowed("tunnel.example.net", extra_hosts=["tunnel.example.net"])
    assert host_is_allowed("a.corp.example.org", extra_hosts=[".corp.example.org"])
    assert host_is_allowed("anything.example", extra_hosts=["*"])
    assert host_is_allowed("x.dyn.example:8080", allow_origin_regex=r"https?://[a-z]+\.dyn\.example(:\d+)?")
    assert not host_is_allowed("corp.example.org.evil.example", extra_hosts=[".corp.example.org"])


def test_middleware_refuses_rebound_read_before_the_endpoint(monkeypatch):
    monkeypatch.delenv(host_guard.ALLOWED_HOSTS_ENV, raising=False)
    monkeypatch.delenv("SHAKERSCAN_PUBLIC_HOST", raising=False)
    guard = TrustedHostGuardMiddleware(_ok_app, allow_origins=["http://localhost:3000"])

    sent = asyncio.run(_drive(guard, _scope("attacker.example:8080")))

    assert sent[0]["status"] == 421
    assert host_guard.ALLOWED_HOSTS_ENV.encode() in sent[1]["body"]
    assert asyncio.run(_drive(guard, _scope("localhost:8080")))[0]["status"] == 200


def test_middleware_honours_environment_and_gateway_secret(monkeypatch):
    guard = TrustedHostGuardMiddleware(_ok_app)
    monkeypatch.setenv(host_guard.ALLOWED_HOSTS_ENV, "scan.example.com, .tunnel.example.net")
    assert asyncio.run(_drive(guard, _scope("scan.example.com")))[0]["status"] == 200
    assert asyncio.run(_drive(guard, _scope("x.tunnel.example.net")))[0]["status"] == 200

    monkeypatch.delenv(host_guard.ALLOWED_HOSTS_ENV)
    monkeypatch.setenv("FLEET_GATEWAY_PROXY_SECRET", "s" * 40)
    forwarded = _scope("fleet.example.com", extra=[(b"x-shakerscan-gateway-secret", b"s" * 40)])
    wrong = _scope("fleet.example.com", extra=[(b"x-shakerscan-gateway-secret", b"t" * 40)])
    assert asyncio.run(_drive(guard, forwarded))[0]["status"] == 200
    assert asyncio.run(_drive(guard, wrong))[0]["status"] == 421


def test_websocket_to_foreign_host_is_closed(monkeypatch):
    monkeypatch.delenv(host_guard.ALLOWED_HOSTS_ENV, raising=False)
    guard = TrustedHostGuardMiddleware(_ok_app)
    sent = asyncio.run(_drive(guard, _scope("attacker.example", kind="websocket")))
    assert sent == [{"type": "websocket.close", "code": 1008}]
