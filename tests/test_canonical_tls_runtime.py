from __future__ import annotations

import asyncio

from scanner import scanner as scanner_main


def _execution(tcp_ports: int):
    return {
        "runtime_budget": {
            "http_requests": 10,
            "state_changing_requests": 0,
            "browser_actions": 0,
            "tcp_ports_attempted": tcp_ports,
            "hosts_attempted": 1,
            "tool_wall_seconds": 10,
        },
        "target_binding": {
            "allowed_addresses": ["192.0.2.10"],
        },
        "target_binding_digest": "a" * 64,
    }


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


def test_canonical_tls_uses_one_frozen_address_handshake(monkeypatch):
    calls = []
    writer = _Writer()

    async def fake_open_connection(**kwargs):
        calls.append(kwargs)
        return object(), writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    result = asyncio.run(scanner_main._canonical_tls_runtime_probe(
        _execution(1),
        host="app.example.test",
        port=443,
        scheme="https",
    ))

    assert len(calls) == 1
    assert calls[0]["host"] == "192.0.2.10"
    assert calls[0]["server_hostname"] == "app.example.test"
    assert result["runtime"] == {
        "schema_version": "canonical-tls-runtime/v1",
        "target_binding_digest": "a" * 64,
        "server_hostname": "app.example.test",
        "port": 443,
        "tcp_ports_attempted": 1,
        "tool_wall_seconds": 1,
        "status": "success",
        "pinned_address": "192.0.2.10",
    }
    assert result["tlsx"]["endpoints"][0]["tlsversion"] == "TLSv1.3"
    assert result["nmap"]["skipped"] is True
    assert result["testssl"]["skipped"] is True
    assert result["sslyze"]["skipped"] is True
    assert writer.closed is True


def test_canonical_tls_makes_no_connection_without_tcp_hold(monkeypatch):
    async def unexpected_connection(**_kwargs):
        raise AssertionError("TLS traffic started without a durable TCP hold")

    monkeypatch.setattr(asyncio, "open_connection", unexpected_connection)
    result = asyncio.run(scanner_main._canonical_tls_runtime_probe(
        _execution(0),
        host="app.example.test",
        port=443,
        scheme="https",
    ))

    assert result["runtime"]["status"] == "blocked"
    assert result["runtime"]["tcp_ports_attempted"] == 0
    assert result["tlsx"] == {"endpoints": [], "certificate": {}}
