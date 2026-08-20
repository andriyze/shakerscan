from __future__ import annotations

import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from capabilities.network import (
    CapabilityInputError,
    PortsDiscoverAdapter,
    ServiceFingerprintAdapter,
    SubdomainsDiscoverAdapter,
)
from runtime.models import ScanPolicy, TargetBinding


@pytest.fixture
def target() -> TargetBinding:
    return TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=("192.0.2.10", "2001:db8::10"),
        allowed_root_domains=("example.test",),
        scope_receipt_id="scope-1",
    )


@pytest.fixture
def active_policy() -> ScanPolicy:
    return ScanPolicy(
        active_testing=True,
        network_discovery=True,
        subdomain_discovery=True,
        approval_receipt_id="approval-1",
    )


def test_ports_discover_uses_only_bound_addresses_and_server_owned_flags(target, active_policy):
    prepared = PortsDiscoverAdapter().prepare(
        target=target,
        args={"profile": "device_common", "host": "10.0.0.5", "flags": "-p-"},
        policy=active_policy,
    )

    assert len(prepared.commands) == 2
    assert {command.destination_address for command in prepared.commands} == {
        "192.0.2.10", "2001:db8::10"
    }
    assert all(command.argv[command.argv.index("-host") + 1] == command.destination_address
               for command in prepared.commands)
    assert all("10.0.0.5" not in command.argv and "-p-" not in command.argv
               for command in prepared.commands)
    assert prepared.estimated_budget["tcp_ports_attempted"] == 46
    assert prepared.redacted_execution["approved_addresses"] == ["192.0.2.10", "2001:db8::10"]


def test_ports_discover_profiles_and_custom_ports_are_bounded(target, active_policy):
    top = PortsDiscoverAdapter().prepare(
        target=target, args={"profile": "top_1000"}, policy=active_policy
    )
    assert "1000" in top.commands[0].argv
    assert top.estimated_budget["tcp_ports_attempted"] == 2_000

    custom = PortsDiscoverAdapter().prepare(
        target=target, args={"ports": [443, 22, 443]}, policy=active_policy
    )
    assert custom.redacted_execution["port_count"] == 2
    assert custom.commands[0].argv[custom.commands[0].argv.index("-p") + 1] == "22,443"

    for invalid in ([0], [65536], [True], ["1;touch /tmp/pwn"]):
        with pytest.raises(CapabilityInputError):
            PortsDiscoverAdapter().prepare(
                target=target, args={"ports": invalid}, policy=active_policy
            )
    with pytest.raises(CapabilityInputError):
        PortsDiscoverAdapter().prepare(
            target=target, args={"ports": list(range(1, 1002))}, policy=active_policy
        )


def test_network_capabilities_require_explicit_policy_and_approval(target):
    adapter = PortsDiscoverAdapter()
    with pytest.raises(CapabilityInputError, match="policy"):
        adapter.prepare(target=target, args={}, policy=ScanPolicy())
    with pytest.raises(CapabilityInputError, match="approval"):
        adapter.prepare(
            target=target, args={}, policy=ScanPolicy(active_testing=True, network_discovery=True)
        )


def test_service_fingerprint_uses_bounded_ports_and_safe_nmap_contract(target, active_policy):
    prepared = ServiceFingerprintAdapter().prepare(
        target=target,
        args={"ports": [8443, 22], "profile": "version_light",
              "target": "attacker.test", "nse": "--script=all"},
        policy=active_policy,
    )

    assert prepared.estimated_budget["tcp_ports_attempted"] == 4
    for command in prepared.commands:
        argv = command.argv
        assert argv[-1] == command.destination_address
        assert argv[argv.index("-p") + 1] == "22,8443"
        assert {"-sT", "-Pn", "-n", "-sV", "--version-light", "--reason", "-oX"} <= set(argv)
        assert not any("script" in value or value in {"-O", "-sS", "-f", "-D"} for value in argv)
        assert "attacker.test" not in argv

    with pytest.raises(CapabilityInputError):
        ServiceFingerprintAdapter().prepare(
            target=target, args={"ports": list(range(1, 258))}, policy=active_policy
        )


def test_naabu_timeout_preserves_valid_jsonl_records():
    output = "\n".join((
        '{"ip":"192.0.2.10","port":443}',
        "malformed",
        '{"host":"2001:db8::10","port":8443}',
    ))
    parsed = PortsDiscoverAdapter().parse(output, timed_out=True)

    assert parsed.status == "partial"
    assert parsed.partial is True and parsed.timed_out is True
    assert [row["port"] for row in parsed.observations] == [443, 8443]
    assert parsed.errors


def test_nmap_xml_parser_normalizes_service_observations_and_partial_timeout():
    xml = """<?xml version='1.0'?>
<nmaprun><host><address addr='192.0.2.10' addrtype='ipv4'/><ports>
<port protocol='tcp' portid='8443'><state state='open' reason='syn-ack'/>
<service name='https' product='nginx' version='1.25'><cpe>cpe:/a:nginx:nginx:1.25</cpe></service>
</port></ports></host></nmaprun>"""
    parsed = ServiceFingerprintAdapter().parse(xml)

    assert parsed.status == "succeeded"
    assert parsed.observations == ({
        "kind": "open_port", "address": "192.0.2.10", "port": 8443,
        "transport": "tcp",
    }, {
        "kind": "service", "address": "192.0.2.10", "port": 8443,
        "transport": "tcp", "state": "open", "reason": "syn-ack",
        "service": "https", "product": "nginx", "version": "1.25",
        "cpe": ["cpe:/a:nginx:nginx:1.25"],
    })

    partial = ServiceFingerprintAdapter().parse(xml[:-10], timed_out=True)
    assert partial.partial is True and partial.timed_out is True
    assert partial.errors == ("malformed_nmap_xml:ParseError",)


def test_subdomain_capability_is_root_bound_and_filters_output(target, active_policy):
    adapter = SubdomainsDiscoverAdapter()
    prepared = adapter.prepare(
        target=target, args={"root_domain": "example.test", "domain": "evil.test"},
        policy=active_policy,
    )
    assert prepared.commands[0].argv[prepared.commands[0].argv.index("-d") + 1] == "example.test"
    assert "evil.test" not in prepared.commands[0].argv

    parsed = adapter.parse(
        '{"host":"api.example.test"}\n{"host":"evil.test"}\nwww.example.test',
        root_domain="example.test",
    )
    assert [row["host"] for row in parsed.observations] == [
        "api.example.test", "www.example.test"
    ]
    assert parsed.partial is True

    with pytest.raises(CapabilityInputError):
        adapter.prepare(target=target, args={"root_domain": "evil.test"}, policy=active_policy)
