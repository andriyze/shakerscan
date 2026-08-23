from __future__ import annotations

import asyncio

from api.capabilities.tls import inspect_tls_binding, inspect_tls_origin
from api.runtime.models import TargetBinding
from scanner import scanner as scanner_main


def _target(*, origin: str = "https://app.example.test") -> TargetBinding:
    return TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=(origin,),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
    )


class _TlsObject:
    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    def selected_alpn_protocol(self):
        return "h2"

    def getpeercert(self, *, binary_form=False):
        return b"certificate" if binary_form else {}


class _Writer:
    def __init__(self):
        self.closed = False

    def get_extra_info(self, name):
        return _TlsObject() if name == "ssl_object" else None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


def test_shared_tls_capability_runs_typed_protocol_and_trust_handshakes(monkeypatch):
    calls = []
    writer = _Writer()

    async def fake_open_connection(**kwargs):
        calls.append(kwargs)
        return object(), writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    result = asyncio.run(inspect_tls_origin(
        "https://app.example.test",
        target=_target(),
        timeout_seconds=15,
    ))

    assert len(calls) == 3
    assert {call["host"] for call in calls} == {"192.0.2.10"}
    assert {call["server_hostname"] for call in calls} == {"app.example.test"}
    assert result["status"] == "success"
    assert result["observation"]["protocol"] == "TLSv1.3"
    assert result["observation"]["supported_protocols"] == [
        "TLSv1.2", "TLSv1.3",
    ]
    assert result["observation"]["certificate_trust"] == "trusted"
    assert result["observation"]["certificate_sha256"]
    assert result["budget_consumed"] == {
        "tcp_ports_attempted": 3,
        "tool_wall_seconds": 1,
    }
    assert writer.closed is True


def test_tls_binding_inspects_every_frozen_origin_and_address(monkeypatch):
    calls = []

    async def fake_open_connection(**kwargs):
        calls.append(kwargs)
        return object(), _Writer()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    target = TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=(
            "https://app.example.test",
            "https://app.example.test:8443",
        ),
        allowed_addresses=("192.0.2.10", "192.0.2.11"),
        allowed_root_domains=("example.test",),
    )

    result = asyncio.run(inspect_tls_binding(target=target))

    assert result["status"] == "success"
    assert len(result["observations"]) == 4
    assert {
        (item["origin"], item["pinned_address"])
        for item in result["observations"]
    } == {
        (origin, address)
        for origin in target.allowed_origins
        for address in target.allowed_addresses
    }
    assert len(calls) == 12
    assert result["budget_consumed"]["tcp_ports_attempted"] == 12


def test_shared_tls_capability_blocks_origin_outside_binding(monkeypatch):
    async def unexpected_connection(**_kwargs):
        raise AssertionError("TLS traffic started outside its frozen binding")

    monkeypatch.setattr(asyncio, "open_connection", unexpected_connection)
    result = asyncio.run(inspect_tls_origin(
        "https://other.example.test",
        target=_target(),
    ))

    assert result["status"] == "blocked"
    assert result["budget_consumed"] == {
        "tcp_ports_attempted": 0,
        "tool_wall_seconds": 0,
    }


def test_scanner_adapts_placed_tls_without_network_execution(monkeypatch):
    async def unexpected_connection(**_kwargs):
        raise AssertionError("report assembly repeated TLS traffic")

    monkeypatch.setattr(asyncio, "open_connection", unexpected_connection)
    summary = {
        "status": "success",
        "observations": [{
            "kind": "tls_protocol",
            "origin": "https://app.example.test",
            "server_hostname": "app.example.test",
            "pinned_address": "192.0.2.10",
            "port": 443,
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "alpn_protocol": "h2",
            "certificate_sha256": "a" * 64,
            "certificate_bytes": 11,
            "certificate_trust": "not_evaluated",
        }],
        "budget_consumed": {
            "tcp_ports_attempted": 1,
            "tool_wall_seconds": 1,
        },
        "receipt": {"receipt_hash": "b" * 64},
    }
    result = scanner_main._canonical_tls_placement_result(
        summary,
        {"target_binding_digest": "c" * 64},
        host="app.example.test",
        port=443,
        scheme="https",
    )

    assert result["runtime"]["canonical_capability"] == "tls.inspect"
    assert result["runtime"]["tcp_ports_attempted"] == 1
    assert result["tlsx"]["endpoints"][0]["tlsversion"] == "TLSv1.3"
    assert result["nmap"]["skipped"] is True
    assert result["testssl"]["skipped"] is True
    assert result["sslyze"]["skipped"] is True


def test_scanner_never_falls_back_to_in_process_tls():
    result = scanner_main._canonical_tls_placement_result(
        None,
        {"target_binding_digest": "d" * 64},
        host="app.example.test",
        port=443,
        scheme="https",
    )

    assert result["runtime"]["status"] == "blocked"
    assert result["runtime"]["reason"] == "tls_capability_placement_missing"
    assert result["runtime"]["tcp_ports_attempted"] == 0
    assert result["tlsx"] == {"endpoints": [], "certificate": {}}
