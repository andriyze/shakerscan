"""NSE is a bounded Hunt action, not a planner-controlled Nmap command line."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from capabilities.network import CapabilityInputError, NetworkExecutionAdapter, network_capability_adapter
from hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
from hunt.contracts import allowed_capability_names
from hunt.start_contract import normalize_hunt_start_payload
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import ScanPolicy, TargetBinding


TARGET = TargetBinding(
    target_id="device-1", target_kind="device", canonical_host="172.31.32.220",
    allowed_origins=("http://172.31.32.220",), allowed_addresses=("172.31.32.220",),
    allowed_root_domains=(), scope_receipt_id="scope-1",
)
POLICY = ScanPolicy(active_testing=True, network_discovery=True, approval_receipt_id="approval-1")
XML = """<?xml version='1.0'?>
<nmaprun><host><address addr='172.31.32.220' addrtype='ipv4'/><ports>
<port protocol='tcp' portid='8443'><state state='open'/><script id='ssl-enum-ciphers'
 output='TLSv1.2: least strength: B'/><script id='http-security-headers'
 output='Content-Security-Policy: private-token-DO-NOT-LEAK'/></port>
</ports></host></nmaprun>"""


def test_nse_is_registered_for_device_hunt_with_explicit_discovery_authority():
    spec = CAPABILITY_REGISTRY.require("service.nse_check")
    assert "device" in spec.target_kinds
    assert spec.required_approval == "network_discovery"
    assert spec.hunt_executor == "worker_network"
    assert spec.output_schema == "nmap-nse-observation/v1"
    for kind in ("device", "web"):
        contract = normalize_hunt_start_payload({
            "target_id": "11111111-1111-1111-1111-111111111111", "target_kind": kind,
            "policy": {"active_testing": True, "network_discovery": True,
                       "authorization_confirmed": True, "approval_receipt_id": "approval-1"},
        })
        assert "service.nse_check" in allowed_capability_names(contract, credentials_available=False)


def test_nse_prepares_only_reviewed_scripts_and_bound_ports():
    adapter = network_capability_adapter("service.nse_check")
    prepared = adapter.prepare(target=TARGET, args={
        "ports": [8443, 8008], "scripts": ["ssl-enum-ciphers", "http-security-headers"],
    }, policy=POLICY)
    argv = prepared.commands[0].argv
    assert argv[-1] == "172.31.32.220"
    assert argv[argv.index("-p") + 1] == "8008,8443"
    assert argv[argv.index("--script") + 1] == "http-security-headers,ssl-enum-ciphers"
    assert "--script-timeout" in argv and "--host-timeout" in argv
    assert prepared.estimated_budget["http_requests"] == 8
    assert prepared.estimated_budget["tcp_ports_attempted"] == 2
    assert prepared.estimated_budget["device_fragility_points"] == 76

    for invalid in (
        {"ports": [8443], "scripts": ["vuln"]},
        {"ports": [8443], "scripts": ["http-vuln-cve2017-5638"]},
        {"ports": [8443], "scripts": ["ssl-enum-ciphers"], "script_args": "unsafe=1"},
        {"ports": [8443], "scripts": ["ssl-enum-ciphers"], "host": "other.test"},
        {"ports": [1, 2, 3, 4, 5], "scripts": ["ssl-enum-ciphers"]},
    ):
        with pytest.raises(CapabilityInputError):
            adapter.prepare(target=TARGET, args=invalid, policy=POLICY)
    with pytest.raises(CapabilityInputError, match="policy"):
        adapter.prepare(target=TARGET, args={"ports": [8443], "scripts": ["ssl-enum-ciphers"]},
                        policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"))


def test_nse_parses_bounded_observations_without_echoing_target_output():
    parser = network_capability_adapter("service.nse_check")
    result = parser.parse(XML)
    assert result.status == "succeeded"
    assert len(result.observations) == 2
    assert result.observations[0]["port"] == 8443
    assert all(item["status"] == "reported" for item in result.observations)
    assert result.observations[0]["signals"] == {"tls_versions": ["TLSv1.2"], "least_strength": "B"}
    assert result.observations[1]["signals"] == {"mentioned_headers": ["content-security-policy"], "missing_headers": []}
    assert "private-token" not in str(result.observations)
    assert all(item["proof_state"] == "observation_only" for item in result.observations)
    partial = parser.parse(XML + "<truncated", timed_out=True)
    assert partial.partial and partial.timed_out
    assert len(partial.observations) == 2


def test_nse_empty_script_output_is_indeterminate():
    parser = network_capability_adapter("service.nse_check")
    xml = XML.replace("Content-Security-Policy: private-token-DO-NOT-LEAK", "")
    result = parser.parse(xml)
    assert result.partial and result.status == "partial"
    assert "nse_script_no_output:http-security-headers:8443" in result.errors
    assert result.observations[1]["status"] == "no_output"
    assert result.observations[1]["signals"] == {"mentioned_headers": [], "missing_headers": []}


def test_nse_normalizes_a_real_hsts_misconfiguration_signal():
    parser = network_capability_adapter("service.nse_check")
    xml = XML.replace("Content-Security-Policy: private-token-DO-NOT-LEAK",
                      "Strict_Transport_Security: HSTS not configured in HTTPS Server")
    observation = parser.parse(xml).observations[1]
    assert observation["signals"]["missing_headers"] == ["strict-transport-security"]


def test_nse_execution_reconciles_conservative_http_and_port_usage():
    parser = network_capability_adapter("service.nse_check")
    prepared = parser.prepare(target=TARGET, args={
        "ports": [8443], "scripts": ["ssl-enum-ciphers", "http-security-headers"],
    }, policy=POLICY)
    called = []

    async def run_command(argv, **_kwargs):
        called.append(argv)
        return SimpleNamespace(stdout=XML, returncode=0, timed_out=False, partial=False,
                               stdout_truncated=False, cancelled=False)

    result = asyncio.run(CapabilityExecutor().execute(
        CapabilityExecutionContext(
            specification=CAPABILITY_REGISTRY.require("service.nse_check"),
            target=TARGET,
            requested_budget={**prepared.estimated_budget, "agent_actions": 1, "active_actions": 1},
        ),
        NetworkExecutionAdapter(prepared=prepared, parser=parser, command_runner=run_command,
                                max_stdout_bytes=10000, max_stderr_bytes=1000),
        heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False,
    ))
    assert result.status == "success"
    assert called and called[0][0] == "nmap"
    assert result.actual_budget["http_requests"] == 4
    assert result.actual_budget["tcp_ports_attempted"] == 1
    assert result.actual_budget["device_fragility_points"] == 38
    assert len(result.observations) == 2


def test_nse_keeps_observations_for_a_lan_host_that_reports_a_mac_address():
    # nmap emits a MAC <address> after the IP for a directly attached host; it
    # must not clear the scanned host and silently drop every observation.
    parser = network_capability_adapter("service.nse_check")
    xml = XML.replace(
        "<address addr='172.31.32.220' addrtype='ipv4'/>",
        "<address addr='172.31.32.220' addrtype='ipv4'/>"
        "<address addr='AA:BB:CC:DD:EE:FF' addrtype='mac' vendor='Example'/>",
    )
    result = parser.parse(xml)
    assert result.status == "succeeded"
    assert [item["address"] for item in result.observations] == ["172.31.32.220"] * 2


def test_nse_requested_script_that_never_ran_is_indeterminate_not_clean():
    parser = network_capability_adapter("service.nse_check")
    closed = """<?xml version='1.0'?>
<nmaprun><host><address addr='172.31.32.220' addrtype='ipv4'/><ports>
<port protocol='tcp' portid='8008'><state state='closed'/></port>
</ports></host></nmaprun>"""
    result = parser.parse(closed, expected_ports=[8008], expected_scripts=["http-methods"])
    assert result.status == "partial" and result.partial
    assert result.errors == ("nse_script_not_run:http-methods:8008",)
    complete = parser.parse(XML, expected_ports=[8443],
                            expected_scripts=["http-security-headers", "ssl-enum-ciphers"])
    assert complete.status == "succeeded" and not complete.errors


def test_nse_execution_marks_a_missing_script_result_partial():
    parser = network_capability_adapter("service.nse_check")
    prepared = parser.prepare(target=TARGET, args={
        "ports": [8443, 8008], "scripts": ["ssl-enum-ciphers", "http-security-headers"],
    }, policy=POLICY)

    async def run_command(argv, **_kwargs):
        return SimpleNamespace(stdout=XML, returncode=0, timed_out=False, partial=False,
                               stdout_truncated=False, cancelled=False)

    result = asyncio.run(CapabilityExecutor().execute(
        CapabilityExecutionContext(
            specification=CAPABILITY_REGISTRY.require("service.nse_check"),
            target=TARGET,
            requested_budget={**prepared.estimated_budget, "agent_actions": 1, "active_actions": 1},
        ),
        NetworkExecutionAdapter(prepared=prepared, parser=parser, command_runner=run_command,
                                max_stdout_bytes=10000, max_stderr_bytes=1000),
        heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False,
    ))
    assert result.status != "success"
    assert len(result.observations) == 2
