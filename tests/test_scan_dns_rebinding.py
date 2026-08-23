from __future__ import annotations

import asyncio
import socket


def test_canonical_socket_factory_connects_only_to_frozen_target_addresses():
    from runtime.target_bound_socket import FrozenTargetSocketFactory

    factory = FrozenTargetSocketFactory(
        hostname="target.test",
        port=443,
        frozen_addresses=("192.0.2.10", "2001:db8::10"),
    )
    assert factory.resolves_during_connect is False
    assert factory.addresses == ("192.0.2.10", "2001:db8::10")


def test_socket_factory_fails_over_without_dns(monkeypatch):
    from runtime.target_bound_socket import FrozenTargetSocketFactory

    dns_calls = []
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *_args, **_kwargs: dns_calls.append(True),
    )
    attempts = []

    class FakeSocket:
        def __init__(self, family, *_args):
            self.family = family
            self.closed = False

        def settimeout(self, value):
            assert value == 2.0

        def connect(self, sockaddr):
            attempts.append((self.family, sockaddr))
            if len(attempts) == 1:
                raise OSError("first address unavailable")

        def close(self):
            self.closed = True

    factory = FrozenTargetSocketFactory(
        hostname="target.test",
        port=443,
        frozen_addresses=("192.0.2.10", "2001:db8::10"),
    )
    connected = factory.connect(timeout=2.0, socket_factory=FakeSocket)

    assert connected.family == socket.AF_INET6
    assert attempts == [
        (socket.AF_INET, ("192.0.2.10", 443)),
        (socket.AF_INET6, ("2001:db8::10", 443, 0, 0)),
    ]
    assert dns_calls == []


def test_aiohttp_resolver_exposes_all_and_only_frozen_addresses():
    from runtime.pinned_http_replay import _FrozenAddressResolver
    from runtime.target_bound_socket import FrozenTargetSocketFactory

    factory = FrozenTargetSocketFactory(
        hostname="target.test",
        port=443,
        frozen_addresses=("192.0.2.10", "2001:db8::10"),
    )
    resolver = _FrozenAddressResolver(factory=factory)
    records = asyncio.run(resolver.resolve("target.test", 443))

    assert [record["host"] for record in records] == list(factory.addresses)
