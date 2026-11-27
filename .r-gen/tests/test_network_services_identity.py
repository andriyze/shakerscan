"""Network services name a listener by its protocol reply, never by its port number."""

from __future__ import annotations

import asyncio

from scanner.scanner_tools import network_services as ns
from scanner.scanner_tools import service_identity as si
from tests.test_service_protocol_adapters import _mongo, _scripted, _serve


def _run(handler, monkeypatch, *, hint: str, category: str):
    async def run():
        async with _serve(handler) as port:
            monkeypatch.setitem(si.CONVENTIONAL_PORT_SERVICES, port, hint)
            monkeypatch.setattr(ns, category, (port,))
            for other in ("VPN_TCP_PORTS", "REMOTE_ACCESS_TCP_PORTS", "IOT_TCP_PORTS",
                          "INDUSTRIAL_TCP_PORTS", "DATABASE_TCP_PORTS"):
                if other != category:
                    monkeypatch.setattr(ns, other, ())
            monkeypatch.setattr(ns, "VPN_UDP_PORTS", ())
            return port, await ns.check_network_services("127.0.0.1", timeout=60, scan_vpn=False)

    return asyncio.run(run())


def test_a_handshake_only_database_is_not_reported_as_unauthenticated(monkeypatch):
    port, result = _run(
        _mongo({"ok": 0.0, "errmsg": "command listDatabases requires authentication", "code": 13}),
        monkeypatch, hint="mongodb", category="DATABASE_TCP_PORTS",
    )
    titles = [finding["title"] for finding in result["findings"]]
    assert titles == ["Exposed MongoDB Service"]
    assert result["database_exposure"]["unauthenticated"] == []
    detected = result["database_exposure"]["detected"][0]
    assert detected["authentication"] == si.AUTH_REQUIRED and detected["port"] == port


def test_a_handshake_without_an_access_decision_says_authentication_not_tested(monkeypatch):
    _port, result = _run(_mongo({"ok": 1.0}), monkeypatch, hint="mongodb", category="DATABASE_TCP_PORTS")
    finding = result["findings"][0]
    assert finding["title"] == "Exposed MongoDB Service" and finding["severity"] == "high"
    assert si.AUTH_NOT_TESTED_LABEL in finding["description"]
    assert finding["evidence"]["authentication"] == si.AUTH_NOT_TESTED


def test_a_fake_service_on_the_redis_port_is_not_redis(monkeypatch):
    """The old check called any open 6379 without "ERR" in its banner unauthenticated Redis."""
    port, result = _run(_scripted(replies=lambda _d: b"hello\r\n"), monkeypatch,
                        hint="redis", category="DATABASE_TCP_PORTS")
    assert result["findings"] == []
    assert result["database_exposure"]["detected"] == []
    row = result["services"][0]
    assert row["port"] == port and row["protocol"] is None
    assert row["port_hint"] == "redis" and row["status"] == si.STATUS_UNIDENTIFIED


def test_a_silent_service_on_the_redis_port_is_not_redis(monkeypatch):
    _port, result = _run(_scripted(), monkeypatch, hint="redis", category="DATABASE_TCP_PORTS")
    assert result["findings"] == []
    assert result["services"][0]["status"] == si.STATUS_SILENT


def test_proven_unauthenticated_redis_is_critical_with_its_proof(monkeypatch):
    info = b"# Server\r\nredis_version:7.2.4\r\n"
    reply = b"$" + str(len(info)).encode() + b"\r\n" + info + b"\r\n"
    _port, result = _run(_scripted(replies=lambda d: reply if b"INFO" in d else None), monkeypatch,
                         hint="redis", category="DATABASE_TCP_PORTS")
    finding = result["findings"][0]
    assert finding["title"] == "Unauthenticated Redis Access" and finding["severity"] == "critical"
    assert finding["evidence"]["authentication_proof"] == "redis_info_without_credentials"


def test_an_unconfirmed_industrial_port_is_a_hint_not_the_protocol(monkeypatch):
    async def run():
        async with _serve(_scripted()) as port:
            monkeypatch.setattr(ns, "INDUSTRIAL_PORT_HINTS", {port: "DNP3"})
            monkeypatch.setattr(ns, "INDUSTRIAL_TCP_PORTS", (port,))
            for other in ("VPN_TCP_PORTS", "REMOTE_ACCESS_TCP_PORTS", "IOT_TCP_PORTS", "DATABASE_TCP_PORTS"):
                monkeypatch.setattr(ns, other, ())
            return await ns.check_network_services(
                "127.0.0.1", timeout=60, scan_vpn=False,
            )

    result = asyncio.run(run())
    assert result["industrial_protocols"]["critical_exposure"] is False
    finding = result["findings"][0]
    assert "protocol not confirmed" in finding["title"] and finding["severity"] == "medium"
    assert finding["evidence"]["identity_basis"] == "port_hint"


def test_wireguard_is_listed_as_not_identifiable_and_never_detected(monkeypatch):
    for name in ("VPN_TCP_PORTS", "REMOTE_ACCESS_TCP_PORTS", "IOT_TCP_PORTS", "INDUSTRIAL_TCP_PORTS",
                 "DATABASE_TCP_PORTS", "VPN_UDP_PORTS"):
        monkeypatch.setattr(ns, name, ())
    monkeypatch.setattr(ns, "VPN_UDP_PORTS", (1,))
    result = asyncio.run(ns.check_network_services("127.0.0.1", timeout=30))
    assert result["vpn_services"]["detected"] == []
    assert result["vpn_services"]["not_identifiable"][0]["port"] == 51820


def test_nmap_unknown_or_table_names_are_port_hints_never_services(monkeypatch):
    """correct_service_name turned Nmap's "unknown" on 5432/3306/27017/6379 into that service."""
    from scanner.scanner_tools import nmap

    assert nmap.nmap_service_identity(5432, {"name": "unknown"}) == {
        "name": "unknown", "method": None, "port_hint": "postgresql",
    }
    assert nmap.nmap_service_identity(6379, {"name": "redis", "method": "table"})["name"] == "unknown"
    assert nmap.nmap_service_identity(6379, {"name": "redis", "method": "table"})["port_hint"] == "redis"
    probed = nmap.nmap_service_identity(6379, {"name": "http", "method": "probed"})
    assert probed == {"name": "http", "method": "probed"}

    xml = (
        "<?xml version='1.0'?><nmaprun><host><ports>"
        "<port protocol='tcp' portid='27017'><state state='open'/><service name='unknown'/></port>"
        "<port protocol='tcp' portid='40000'><state state='open'/>"
        "<service name='redis' product='Redis key-value store' version='7.2.4' method='probed' conf='10'/></port>"
        "</ports></host></nmaprun>"
    )

    async def fake_run(cmd, timeout=None):
        return xml, "", 0

    monkeypatch.setattr(nmap, "run", fake_run)
    result = asyncio.run(nmap.nmap_full_scan("192.0.2.10", quick_mode=True))
    by_port = {row["port"]: row for row in result["services"]}
    assert by_port[27017]["name"] == "unknown" and by_port[27017]["port_hint"] == "mongodb"
    assert "original_detection" not in by_port[27017]
    # A real service on an unusual port keeps the name Nmap's probe matched.
    assert by_port[40000]["name"] == "redis" and "port_hint" not in by_port[40000]


def test_a_cdn_edge_address_is_not_examined_as_the_origin(monkeypatch):
    async def edge_only(_host):
        return ["104.16.132.229"]

    async def never(*_args, **_kwargs):
        raise AssertionError("an edge address must not be port-scanned as the origin")

    monkeypatch.setattr(ns, "_resolve", edge_only)
    monkeypatch.setattr(ns, "_scan_address", never)
    result = asyncio.run(ns.check_network_services("app.example.test", timeout=30))
    assert result["cdn_edges"][0]["provider"] == "Cloudflare"
    assert result["note"] == "application assessed through the CDN; origin network not assessed"
    assert result["findings"] == [] and result["services"] == []
