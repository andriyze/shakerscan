"""Suite-wide fixtures."""

from __future__ import annotations

import socket
import sys

import pytest


async def _resolver_unavailable(_hostname):
    raise socket.gaierror(socket.EAI_AGAIN, "name resolution is not available to unit tests")


@pytest.fixture(autouse=True)
def _hermetic_target_resolution(monkeypatch):
    """Keep target-name DNS lookups off the network.

    Scan submission and target creation ask DNS whether the target name has an address record
    (``api/target_resolution.py``), so the www/apex twin can be used when it does not. Unit tests
    must not depend on the machine's resolver, so here the resolver reports a fault -- the
    outcome that, by contract, changes nothing. Tests of that behaviour install their own
    fixture resolver over this one.
    """
    for name, module in list(sys.modules.items()):
        if name.rsplit(".", 1)[-1] == "target_resolution" and hasattr(module, "system_lookup"):
            monkeypatch.setattr(module, "system_lookup", _resolver_unavailable)
