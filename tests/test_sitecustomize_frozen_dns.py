from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys

import pytest


os.environ.pop("SHAKERSCAN_CANONICAL_SCAN_EXECUTION", None)
os.environ.pop("SHAKERSCAN_FROZEN_DNS_ACTIVE", None)
MODULE_PATH = Path(__file__).parents[1] / "scanner" / "sitecustomize.py"
spec = importlib.util.spec_from_file_location(
    "shakerscan_sitecustomize_test", MODULE_PATH,
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def _envelope(*, addresses=None, host="app.example.test"):
    binding = {
        "target_id": "target-1",
        "target_kind": "web",
        "canonical_host": host,
        "allowed_origins": ["https://app.example.test"],
        "allowed_addresses": addresses or ["192.0.2.10", "2001:db8::10"],
        "allowed_root_domains": ["example.test"],
        "environment": "test",
        "scope_receipt_id": "scope-1",
    }
    digest = hashlib.sha256(json.dumps(
        binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode()).hexdigest()
    return json.dumps({
        "schema_version": "native-scan-execution/v3",
        "target_binding": binding,
        "target_binding_digest": digest,
    }, sort_keys=True, separators=(",", ":"))


class FakeSocket:
    AF_UNSPEC = socket.AF_UNSPEC
    AF_INET = socket.AF_INET
    AF_INET6 = socket.AF_INET6
    SOCK_STREAM = socket.SOCK_STREAM
    AI_NUMERICHOST = socket.AI_NUMERICHOST
    EAI_NONAME = socket.EAI_NONAME
    gaierror = socket.gaierror

    def __init__(self):
        self.calls = []
        self.getaddrinfo = self._getaddrinfo
        self.gethostbyname = self._gethostbyname
        self.gethostbyname_ex = self._gethostbyname_ex

    def _getaddrinfo(self, host, port, family=0, type=0, proto=0, flags=0):
        self.calls.append((host, port, family, type, proto, flags))
        if host == "other.example.test":
            return [(self.AF_INET, type, proto, "", ("203.0.113.90", port))]
        parsed = module.ipaddress.ip_address(host)
        sockaddr = (
            (str(parsed), port, 0, 0)
            if parsed.version == 6 else (str(parsed), port)
        )
        return [(
            self.AF_INET6 if parsed.version == 6 else self.AF_INET,
            type,
            proto,
            "",
            sockaddr,
        )]

    @staticmethod
    def _gethostbyname(_host):
        return "203.0.113.91"

    @staticmethod
    def _gethostbyname_ex(host):
        return host, [], ["203.0.113.91"]


def test_no_canonical_envelope_leaves_the_resolver_unchanged():
    fake = FakeSocket()
    assert module.install_frozen_target_resolver(
        environ={}, socket_module=fake,
    ) is None
    assert fake.calls == []


def test_target_resolution_returns_only_frozen_addresses_and_delegates_other_hosts():
    fake = FakeSocket()
    env = {module._ENV_NAME: _envelope()}
    config = module.install_frozen_target_resolver(
        environ=env, socket_module=fake,
    )
    assert config is not None
    assert config.target_host == "app.example.test"
    assert env[module._ACTIVE_ENV_NAME] == config.target_binding_digest

    rows = fake.getaddrinfo(
        "APP.EXAMPLE.TEST.", 443, 0, socket.SOCK_STREAM,
    )
    assert {row[4][0] for row in rows} == {
        "192.0.2.10", "2001:db8::10",
    }
    # The target hostname itself was never passed to the platform resolver.
    assert all(call[0] != "app.example.test" for call in fake.calls)

    delegated = fake.getaddrinfo(
        "other.example.test", 443, socket.AF_INET, socket.SOCK_STREAM,
    )
    assert delegated[0][4][0] == "203.0.113.90"


def test_address_family_filter_and_legacy_lookup_helpers_remain_frozen():
    fake = FakeSocket()
    env = {module._ENV_NAME: _envelope()}
    module.install_frozen_target_resolver(environ=env, socket_module=fake)

    ipv4 = fake.getaddrinfo(
        "app.example.test", 80, socket.AF_INET, socket.SOCK_STREAM,
    )
    assert [row[4][0] for row in ipv4] == ["192.0.2.10"]
    ipv6 = fake.getaddrinfo(
        "app.example.test", 80, socket.AF_INET6, socket.SOCK_STREAM,
    )
    assert [row[4][0] for row in ipv6] == ["2001:db8::10"]
    assert fake.gethostbyname("app.example.test") == "192.0.2.10"
    assert fake.gethostbyname_ex("app.example.test") == (
        "app.example.test", [], ["192.0.2.10"],
    )


def test_compatibility_resolver_uses_the_same_stable_family_policy():
    config = module._configuration_from_environment({
        module._ENV_NAME: _envelope(addresses=[
            "2001:db8::20", "192.0.2.20", "192.0.2.10",
        ]),
    })

    assert config is not None
    assert config.allowed_addresses == (
        "192.0.2.10", "192.0.2.20", "2001:db8::20",
    )


def test_digest_mismatch_and_origin_mismatch_fail_closed():
    payload = json.loads(_envelope())
    payload["target_binding_digest"] = "0" * 64
    with pytest.raises(module.FrozenResolverError, match="digest mismatch"):
        module._configuration_from_environment({
            module._ENV_NAME: json.dumps(payload),
        })

    payload = json.loads(_envelope())
    payload["target_binding"]["allowed_origins"] = [
        "https://other.example.test",
    ]
    payload["target_binding_digest"] = module._canonical_json_digest(
        payload["target_binding"],
    )
    with pytest.raises(module.FrozenResolverError, match="does not match"):
        module._configuration_from_environment({
            module._ENV_NAME: json.dumps(payload),
        })


def test_reinstall_is_idempotent_but_conflicting_authority_is_rejected():
    fake = FakeSocket()
    env = {
        module._ENV_NAME: _envelope(addresses=["192.0.2.10"]),
    }
    first = module.install_frozen_target_resolver(
        environ=env, socket_module=fake,
    )
    second = module.install_frozen_target_resolver(
        environ=env, socket_module=fake,
    )
    assert first == second

    conflicting = {
        module._ENV_NAME: _envelope(addresses=["192.0.2.11"]),
    }
    with pytest.raises(module.FrozenResolverError, match="different frozen"):
        module.install_frozen_target_resolver(
            environ=conflicting,
            socket_module=fake,
        )
