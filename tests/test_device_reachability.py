import asyncio
import errno
import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import device_reachability  # noqa: E402


def _host_xml(state="up", reason="syn-ack"):
    return (
        "<?xml version='1.0'?><nmaprun><host>"
        f"<status state='{state}' reason='{reason}'/><address addr='192.0.2.10' addrtype='ipv4'/>"
        "</host><runstats><finished exit='success'/><hosts up='1' down='0' total='1'/></runstats></nmaprun>"
    )


def test_host_discovery_requires_a_real_positive_reason():
    assert device_reachability.parse_host_discovery(_host_xml())["positive"] is True
    assumed = device_reachability.parse_host_discovery(_host_xml(reason="user-set"))
    assert assumed["host_state"] == "up"
    assert assumed["positive"] is False
    assert device_reachability.parse_host_discovery(_host_xml(state="down", reason="no-response"))["positive"] is False


def test_common_reachability_tier_includes_connected_device_services():
    ports = set(device_reachability.REACHABILITY_TCP_PORTS)
    assert {
        22, 80, 443, 554, 631, 1883, 3000, 3001, 5555, 6466, 6467,
        7345, 8001, 8002, 8008, 8009, 8060, 8554, 9000, 9100, 36669,
    }.issubset(ports)
    assert len(ports) <= device_reachability.MAX_REACHABILITY_TCP_PORTS


def test_connection_refused_is_positive_online_evidence(monkeypatch):
    async def refused(_host, _port):
        raise OSError(errno.ECONNREFUSED, "refused")

    async def nmap(_locator, **_kwargs):
        return {"complete": True, "positive": False, "host_state": "down", "reason": "no-response"}

    monkeypatch.setattr(asyncio, "open_connection", refused)
    monkeypatch.setattr(device_reachability, "_nmap_host_discovery", nmap)
    verdict = asyncio.run(device_reachability.probe_device_reachability(
        "tv.lan", "192.0.2.10", attempts=1, timeout=0.2,
    ))
    assert verdict["status"] == "online"
    assert verdict["online"] is True
    assert verdict["positive_signals"]["tcp_refused_ports"]
    assert verdict["service_accessible"] is None


def test_silence_is_inconclusive_not_offline_or_online(monkeypatch):
    async def silent(_host, _port):
        raise asyncio.TimeoutError()

    async def nmap(_locator, **_kwargs):
        return {"complete": True, "positive": False, "host_state": "down", "reason": "no-response"}

    monkeypatch.setattr(asyncio, "open_connection", silent)
    monkeypatch.setattr(device_reachability, "_nmap_host_discovery", nmap)
    verdict = asyncio.run(device_reachability.probe_device_reachability(
        "tv.lan", "192.0.2.10", attempts=2, timeout=0.2,
    ))
    assert verdict["status"] == "inconclusive"
    assert verdict["online"] is None
    assert verdict["network_accessible"] is None


def test_nonstandard_port_hint_is_probed_by_tcp_and_host_discovery(monkeypatch):
    observed: dict[str, tuple[int, ...]] = {}

    async def probe_round(_locator, ports, **_kwargs):
        observed["tcp"] = ports
        return [
            {"port": port, "outcome": "open" if port == 7345 else "no_response"}
            for port in ports
        ]

    async def nmap(_locator, *, tcp_ports, **_kwargs):
        observed["nmap"] = tcp_ports
        return {"complete": True, "positive": False, "host_state": "down", "reason": "no-response"}

    monkeypatch.setattr(device_reachability, "_tcp_probe_round", probe_round)
    monkeypatch.setattr(device_reachability, "_nmap_host_discovery", nmap)
    verdict = asyncio.run(device_reachability.probe_device_reachability(
        "tv.lan", "192.0.2.10", attempts=1, timeout=0.2, port_hints=[7345],
    ))
    assert verdict["status"] == "online"
    assert verdict["positive_signals"]["tcp_open_ports"] == [7345]
    assert observed["tcp"][0] == 7345
    assert observed["nmap"][0] == 7345


def test_consistent_network_unreachable_is_distinct_from_silence(monkeypatch):
    async def unreachable(_host, _port):
        raise OSError(errno.EHOSTUNREACH, "host unreachable")

    async def nmap(_locator, **_kwargs):
        return {"complete": True, "positive": False, "host_state": "down", "reason": "no-response"}

    monkeypatch.setattr(asyncio, "open_connection", unreachable)
    monkeypatch.setattr(device_reachability, "_nmap_host_discovery", nmap)
    verdict = asyncio.run(device_reachability.probe_device_reachability(
        "tv.lan", "192.0.2.10", attempts=2, timeout=0.2,
    ))
    assert verdict["status"] == "unreachable"
    assert verdict["network_accessible"] is False
    assert verdict["service_accessible"] is False


def test_cancellation_reaps_concurrent_host_discovery(monkeypatch):
    nmap_cancelled = False

    async def slow_nmap(_locator, **_kwargs):
        nonlocal nmap_cancelled
        try:
            await asyncio.sleep(60)
        finally:
            nmap_cancelled = True

    async def cancelled():
        await asyncio.sleep(0)
        return True

    monkeypatch.setattr(device_reachability, "_nmap_host_discovery", slow_nmap)
    with pytest.raises(ValueError, match="cancelled during reachability"):
        asyncio.run(device_reachability.probe_device_reachability(
            "tv.lan", "192.0.2.10", cancel_check=cancelled,
        ))
    assert nmap_cancelled is True


def test_scan_responses_corroborate_online_and_service_accessibility():
    preflight = {
        "schema_version": "device-reachability/v1", "status": "online", "online": True,
        "network_accessible": True, "service_accessible": None, "confidence": "high",
        "positive_signals": {},
    }
    closed = device_reachability.corroborate_device_reachability(
        preflight,
        services=[],
        tool_receipts=[{"port_state_counts": {"closed": 65535}}],
        protocol_results=[],
        health_checkpoints=[],
        full_tcp_visibility=True,
    )
    assert closed["status"] == "online"
    assert closed["service_accessible"] is False
    opened = device_reachability.corroborate_device_reachability(
        preflight,
        services=[{"state": "open", "transport": "tcp", "port": 443}],
        tool_receipts=[],
        protocol_results=[],
        health_checkpoints=[],
        full_tcp_visibility=False,
    )
    assert opened["service_accessible"] is True
    assert opened["post_scan_corroborated"] is True
