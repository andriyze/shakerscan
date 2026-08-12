import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import device_posture  # noqa: E402


def test_normalize_device_locator_accepts_one_host_and_rejects_scope_expansion():
    assert device_posture.normalize_device_locator("[2001:db8::1]") == "2001:db8::1"
    assert device_posture.normalize_device_locator("TV.LAN.") == "tv.lan"
    for invalid in ("https://tv.lan", "10.0.0.0/24", "host/path", "host?x=1"):
        with pytest.raises(ValueError):
            device_posture.normalize_device_locator(invalid)


def test_parse_nmap_services_preserves_transport_and_tls_identity():
    xml = """<?xml version='1.0'?>
    <nmaprun><host><address addr='10.0.0.4' addrtype='ipv4'/><hostnames><hostname name='tv.lan'/></hostnames>
    <ports><port protocol='tcp' portid='8443'><state state='open'/><service name='http' tunnel='ssl' product='Embedded UI'><cpe>cpe:/a:test</cpe></service></port>
    <port protocol='udp' portid='1900'><state state='open|filtered'/><service name='upnp'/></port></ports></host></nmaprun>"""
    services, identity = device_posture.parse_nmap_services(xml)
    assert services[0]["service_name"] == "https"
    assert services[0]["cpe"] == "cpe:/a:test"
    assert services[1]["transport"] == "udp"
    assert identity["hostnames"] == ["tv.lan"]


def test_policy_defaults_to_review_and_honors_deny():
    services = [
        {"transport": "tcp", "port": 23, "service_name": "telnet"},
        {"transport": "tcp", "port": 45678, "service_name": "unknown"},
    ]
    rules = [{"action": "deny", "transport": "tcp", "ports": [23], "service": "telnet", "severity": "critical"}]
    evaluated, findings = device_posture.evaluate_service_policy(services, rules, policy_name="test")
    assert [row["policy_disposition"] for row in evaluated] == ["deny", "review"]
    assert [row["severity"] for row in findings] == ["critical", "medium"]


def test_web_detection_checks_nonstandard_ports(monkeypatch):
    calls = []

    async def fake_probe(locator, port, *, tls, server_name=None, timeout=3.0):
        calls.append((port, tls))
        if port == 49152 and tls:
            return {"origin": "https://10.0.0.8:49152", "port": port, "scheme": "https", "tls": True}
        return None

    monkeypatch.setattr(device_posture, "_probe_http", fake_probe)
    origins = asyncio.run(device_posture.detect_web_origins(
        "10.0.0.8", [{"transport": "tcp", "port": 49152, "state": "open", "service_name": "unknown"}], cap=5,
    ))
    assert origins[0]["origin"] == "https://10.0.0.8:49152"
    assert calls == [(49152, False), (49152, True)]
