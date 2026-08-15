import asyncio
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import device_posture, device_protocols  # noqa: E402


def test_ssdp_parser_preserves_metadata_without_following_cross_scope_location():
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
        b"USN: uuid:fixture::urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
        b"SERVER: FixtureOS/1.0 UPnP/1.1 FixtureTV/2.0\r\n"
        b"LOCATION: http://192.0.2.99:8008/device.xml\r\n\r\n"
    )
    parsed = device_protocols.parse_ssdp_response(response, locator="192.0.2.40")
    assert parsed["server"] == "FixtureOS/1.0 UPnP/1.1 FixtureTV/2.0"
    assert parsed["location_in_scope"] is False
    assert parsed["search_target"].endswith("MediaRenderer:1")


def test_mdns_parser_extracts_ptr_service_records():
    query = device_protocols.build_mdns_service_query()
    target = device_protocols._encode_dns_name("_googlecast._tcp.local")
    header = struct.pack("!HHHHHH", 0, 0x8400, 1, 1, 0, 0)
    question = query[12:]
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 120, len(target)) + target
    parsed = device_protocols.parse_mdns_response(header + question + answer)
    assert parsed["answers"] == 1
    assert parsed["records"] == [{
        "name": "_services._dns-sd._udp.local",
        "type": "PTR",
        "class": 1,
        "cache_flush": False,
        "ttl": 120,
        "value": "_googlecast._tcp.local",
    }]


def test_protocol_adapters_use_exact_target_unicast_and_bounded_receipts(monkeypatch):
    calls = []

    async def fake_exchange(locator, port, payload, **kwargs):
        calls.append((locator, port, len(payload), kwargs))
        if port == 1900:
            return [{
                "data": b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nSERVER: Fixture\r\n\r\n",
                "address": "192.0.2.40",
                "port": 1900,
            }], {"complete": True, "scope": "exact_target_unicast"}
        return [], {"complete": True, "scope": "exact_target_unicast"}

    monkeypatch.setattr(device_protocols, "_udp_exchange", fake_exchange)
    results = asyncio.run(device_protocols.discover_core_device_protocols(
        "192.0.2.40", udp_ports=(1900, 5353),
    ))
    assert [(call[0], call[1]) for call in calls] == [("192.0.2.40", 1900), ("192.0.2.40", 5353)]
    assert results[0]["confirmed"] is True
    assert results[0]["receipt"]["scope"] == "exact_target_unicast"


def test_protocol_response_promotes_udp_uncertainty_to_validated_service():
    observations = [{
        "transport": "udp", "port": 1900, "state": "open|filtered", "service_name": "upnp",
        "policy_eligible": False,
    }]
    services, remaining = device_posture.merge_protocol_confirmations([], observations, [{
        "protocol": "ssdp", "transport": "udp", "port": 1900, "confirmed": True,
        "responses": [{"server": "Fixture TV"}],
    }])
    assert remaining == []
    assert services[0]["state"] == "open"
    assert services[0]["confidence"] == "validated"
    assert services[0]["policy_eligible"] is True
    assert services[0]["product"] == "Fixture TV"


def test_fast_inventory_includes_core_device_discovery_protocols():
    ports = device_posture.PROFILES["inventory"].udp_ports
    assert 1900 in ports
    assert 5353 in ports
