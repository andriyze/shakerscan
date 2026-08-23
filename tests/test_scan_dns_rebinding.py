from __future__ import annotations

import pytest


@pytest.mark.xfail(
    strict=True,
    reason="V2-P0-03: canonical Python sockets do not yet connect exclusively to frozen addresses",
)
def test_canonical_socket_factory_connects_only_to_frozen_target_addresses():
    from runtime.target_bound_socket import FrozenTargetSocketFactory

    factory = FrozenTargetSocketFactory(
        hostname="target.test",
        port=443,
        frozen_addresses=("192.0.2.10", "2001:db8::10"),
    )
    assert factory.resolves_during_connect is False
    assert factory.addresses == ("192.0.2.10", "2001:db8::10")
