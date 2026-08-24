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
    assert factory.policy_receipt == {
        "schema_version": "frozen-target-address-policy/v1",
        "family_preference": "ipv4_first",
        "admitted_address_count": 2,
        "fallback_attempt_limit": 2,
        "no_runtime_resolution": True,
    }


def test_frozen_address_order_is_stable_and_explicitly_family_preferred():
    from target_address_policy import primary_frozen_address
    from runtime.target_bound_socket import FrozenTargetSocketFactory

    first = FrozenTargetSocketFactory(
        hostname="target.test",
        port=443,
        frozen_addresses=("2001:db8::20", "192.0.2.20", "192.0.2.10"),
    )
    repeated = FrozenTargetSocketFactory(
        hostname="target.test",
        port=443,
        frozen_addresses=("192.0.2.10", "192.0.2.20", "2001:db8::20"),
    )
    ipv6 = FrozenTargetSocketFactory(
        hostname="target.test",
        port=443,
        frozen_addresses=("192.0.2.10", "2001:db8::20"),
        family_preference="ipv6_first",
    )

    assert first.addresses == repeated.addresses == (
        "192.0.2.10", "192.0.2.20", "2001:db8::20",
    )
    assert ipv6.addresses == ("2001:db8::20", "192.0.2.10")
    assert first.primary_address == "192.0.2.10"
    assert primary_frozen_address(
        ("2001:db8::20", "192.0.2.20", "192.0.2.10")
    ) == "192.0.2.10"


def test_socket_fallback_is_bounded_without_expanding_the_frozen_set():
    from runtime.target_bound_socket import FrozenTargetSocketFactory

    factory = FrozenTargetSocketFactory(
        hostname="target.test",
        port=443,
        frozen_addresses=tuple(f"192.0.2.{index}" for index in range(1, 12)),
        max_fallback_attempts=3,
    )

    assert len(factory.addresses) == 11
    assert [item.address for item in factory.endpoints()] == [
        "192.0.2.1", "192.0.2.2", "192.0.2.3",
    ]


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
