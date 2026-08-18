import asyncio
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import device_posture  # noqa: E402


def _nmap_xml(ports: str = "", *, timed_out: bool = False, finished_exit: str = "success") -> str:
    timeout_attr = " timedout='1720000000'" if timed_out else ""
    return (
        "<?xml version='1.0'?><nmaprun scanner='nmap'>"
        f"<host{timeout_attr}><status state='up'/><address addr='10.0.0.4' addrtype='ipv4'/>"
        f"<hostnames><hostname name='device.test'/></hostnames><ports>{ports}</ports></host>"
        f"<runstats><finished elapsed='1.25' exit='{finished_exit}' summary='done'/><hosts up='1' down='0' total='1'/></runstats>"
        "</nmaprun>"
    )


def _tcp_scope_result(ports: list[int], *, complete: bool = True):
    services = [{
        "transport": "tcp", "port": port, "state": "open",
        "state_reason": "tcp-connect", "service_name": "unknown",
        "product": "", "version": "", "extra_info": "", "tunnel": None,
        "cpe": None, "confidence": "confirmed", "policy_eligible": True,
        "discovery_tool": "naabu",
    } for port in ports]
    return services, [], {
        "hostnames": [],
        "addresses": [{"address": "10.0.0.4", "type": "ipv4", "vendor": None}],
        "os_matches": [],
    }, {
        "stage": "tcp_scope_discovery", "tool": "naabu", "transport": "tcp",
        "exit_code": 0 if complete else 124, "complete": complete, "parsed": True,
        "confirmed_open_count": len(services), "inconclusive_count": 0,
        "reachable_open_port_inventory_complete": complete,
        "closed_filtered_classification_complete": False,
        "silent_port_classification": "closed_or_filtered_not_distinguished",
        "scope": "all_tcp", "required_port_count": 65535,
        "completed_required_port_count": 65535 if complete else 57343,
        "incomplete_reasons": [] if complete else ["incomplete_range:fixture"],
        "chunk_receipts": [],
    }


def test_normalize_device_locator_accepts_one_host_and_rejects_scope_expansion():
    assert device_posture.normalize_device_locator("[2001:db8::1]") == "2001:db8::1"
    assert device_posture.normalize_device_locator("TV.LAN.") == "tv.lan"
    for invalid in ("https://tv.lan", "10.0.0.0/24", "host/path", "host?x=1"):
        with pytest.raises(ValueError):
            device_posture.normalize_device_locator(invalid)


def test_parse_nmap_services_preserves_transport_and_tls_identity():
    ports = """<port protocol='tcp' portid='8443'><state state='open' reason='syn-ack'/><service name='http' tunnel='ssl' product='Embedded UI'><cpe>cpe:/a:test</cpe></service></port>
    <port protocol='udp' portid='1900'><state state='open|filtered' reason='no-response'/><service name='upnp'/></port>"""
    xml = _nmap_xml(ports).replace("device.test", "tv.lan")
    services, observations, identity, scan_status = device_posture.parse_nmap_evidence(xml)
    assert services[0]["service_name"] == "https"
    assert services[0]["cpe"] == "cpe:/a:test"
    assert services[0]["confidence"] == "confirmed"
    assert observations[0]["transport"] == "udp"
    assert observations[0]["confidence"] == "inconclusive"
    assert observations[0]["policy_eligible"] is False
    assert identity["hostnames"] == ["tv.lan"]
    assert scan_status["complete"] is True
    compatibility_services, _ = device_posture.parse_nmap_services(xml)
    assert [(item["transport"], item["port"]) for item in compatibility_services] == [("tcp", 8443)]


def test_nmap_host_timeout_is_partial_even_when_nmap_exits_successfully():
    ports = "<port protocol='tcp' portid='80'><state state='open' reason='syn-ack'/><service name='http'/></port>"
    services, observations, _, scan_status = device_posture.parse_nmap_evidence(
        _nmap_xml(ports, timed_out=True),
    )
    assert [item["port"] for item in services] == [80]
    assert observations == []
    assert scan_status["finished_exit"] == "success"
    assert scan_status["complete"] is False
    assert scan_status["incomplete_reasons"] == ["nmap_host_timeout"]


def test_filtered_tcp_ports_are_counted_as_visibility_uncertainty():
    ports = "<port protocol='tcp' portid='443'><state state='filtered' reason='no-response'/><service name='https'/></port>"
    services, observations, _, scan_status = device_posture.parse_nmap_evidence(_nmap_xml(ports))
    assert services == []
    assert observations == []
    assert scan_status["port_state_counts"] == {"filtered": 1}
    assert scan_status["tcp_filtered_count"] == 1


def test_parse_naabu_evidence_accepts_only_valid_confirmed_ports():
    output = "\n".join([
        '{"host":"10.0.0.4","ip":"10.0.0.4","port":7345,"protocol":"tcp"}',
        '{"host":"10.0.0.4","ip":"10.0.0.4","port":443,"protocol":"tcp"}',
        '{"port":0}',
        'not-json',
    ])
    services, receipt = device_posture.parse_naabu_evidence(output, "10.0.0.4")
    assert [service["port"] for service in services] == [443, 7345]
    assert all(service["state"] == "open" for service in services)
    assert all(service["discovery_tool"] == "naabu" for service in services)
    assert receipt["parsed"] is False
    assert receipt["malformed_line_count"] == 2


def test_all_tcp_scope_uses_bounded_naabu_connect_discovery(monkeypatch):
    commands = []

    async def fake_run(cmd, timeout=60, input_text=None, retry=0):
        commands.append(cmd)
        return '{"host":"10.0.0.4","ip":"10.0.0.4","port":7345,"protocol":"tcp"}\n', "", 0

    monkeypatch.setattr(device_posture, "run", fake_run)
    monkeypatch.setattr(device_posture, "_naabu_available", lambda: True)
    services, observations, identity, receipt = asyncio.run(
        device_posture._run_tcp_scope_discovery(
            "10.0.0.4",
            device_posture.PROFILES["posture"],
            max_port_probes_per_second=250,
        ),
    )
    assert [service["port"] for service in services] == [7345]
    assert observations == []
    assert identity["addresses"][0]["address"] == "10.0.0.4"
    assert receipt["tool"] == "naabu"
    assert receipt["complete"] is True
    assert receipt["scope"] == "all_tcp"
    assert receipt["required_port_count"] == 65535
    assert receipt["completed_required_port_count"] == 65535
    assert len(commands) == 9  # priority ports first, then eight bounded ranges
    assert commands[0][commands[0].index("-p") + 1].split(",")[0] == "21"
    assert commands[1][commands[1].index("-p") + 1] == "1-8192"
    assert commands[-1][commands[-1].index("-p") + 1] == "57345-65535"
    assert all(command[command.index("-scan-type") + 1] == "c" for command in commands)
    assert all(command[command.index("-rate") + 1] == "250" for command in commands)
    assert all(command[command.index("-c") + 1] == "313" for command in commands)
    assert all("-verify" in command for command in commands)
    assert all(command[command.index("-timeout") + 1] == "1000ms" for command in commands)
    assert all(command[command.index("-input-read-timeout") + 1] == "1s" for command in commands)


def test_failed_naabu_scope_retries_ranges_without_nmap_and_preserves_partial_results(monkeypatch):
    commands = []
    failed_once = False

    async def fake_run(cmd, timeout=60, input_text=None, retry=0):
        nonlocal failed_once
        commands.append(cmd)
        port_spec = cmd[cmd.index("-p") + 1]
        if port_spec == "1-8192" and not failed_once:
            failed_once = True
            return '{"host":"10.0.0.4","port":7345}\n', "naabu interrupted", 1
        return "", "", 0

    monkeypatch.setattr(device_posture, "run", fake_run)
    monkeypatch.setattr(device_posture, "_naabu_available", lambda: True)
    services, _, _, receipt = asyncio.run(
        device_posture._run_tcp_scope_discovery("10.0.0.4", device_posture.PROFILES["posture"]),
    )
    assert [service["port"] for service in services] == [7345]
    assert all(command[0] == "naabu" for command in commands)
    assert len(commands) == 10
    failed_attempts = [
        item for item in receipt["chunk_receipts"]
        if item["stage"] == "tcp_scope_range_1_of_8"
    ]
    assert [item["attempt"] for item in failed_attempts] == [1, 2]
    assert failed_attempts[0]["complete"] is False
    assert failed_attempts[1]["complete"] is True
    assert receipt["complete"] is True


def test_permanently_failed_naabu_range_is_partial_and_never_falls_back_to_nmap(monkeypatch):
    commands = []

    async def fake_run(cmd, timeout=60, input_text=None, retry=0):
        commands.append(cmd)
        port_spec = cmd[cmd.index("-p") + 1]
        if port_spec == "1-8192":
            Path(cmd[cmd.index("-o") + 1]).write_text(
                '{"host":"10.0.0.4","port":7345}\n', encoding="utf-8",
            )
            return "", "timeout", 124
        return "", "", 0

    monkeypatch.setattr(device_posture, "run", fake_run)
    monkeypatch.setattr(device_posture, "_naabu_available", lambda: True)
    services, _, _, receipt = asyncio.run(
        device_posture._run_tcp_scope_discovery("10.0.0.4", device_posture.PROFILES["posture"]),
    )
    assert [service["port"] for service in services] == [7345]
    assert all(command[0] == "naabu" for command in commands)
    assert receipt["complete"] is False
    assert receipt["failed_required_stages"] == ["tcp_scope_range_1_of_8"]
    assert receipt["completed_required_port_count"] == 65535 - 8192
    failed_attempts = [
        item for item in receipt["chunk_receipts"]
        if item["stage"] == "tcp_scope_range_1_of_8"
    ]
    assert all(item["partial_output_recovered"] is True for item in failed_attempts)


def test_health_callback_halts_later_ranges_without_losing_priority_results(monkeypatch):
    commands = []
    events = []

    async def fake_run(cmd, timeout=60, input_text=None, retry=0):
        commands.append(cmd)
        return '{"host":"10.0.0.4","port":7345}\n', "", 0

    async def stop_after_priority(event):
        events.append(event)
        return False

    monkeypatch.setattr(device_posture, "run", fake_run)
    monkeypatch.setattr(device_posture, "_naabu_available", lambda: True)
    services, _, _, receipt = asyncio.run(device_posture._run_tcp_scope_discovery(
        "10.0.0.4", device_posture.PROFILES["posture"], stage_callback=stop_after_priority,
    ))
    assert [service["port"] for service in services] == [7345]
    assert len(commands) == 1
    assert len(events) == 9
    assert receipt["complete"] is False
    assert receipt["completed_required_port_count"] == 0
    assert receipt["failed_required_stages"] == [
        f"tcp_scope_range_{index}_of_8" for index in range(1, 9)
    ]
    skipped = [
        item for item in receipt["chunk_receipts"]
        if "device_health_degraded" in item.get("incomplete_reasons", [])
    ]
    assert len(skipped) == 8


def test_policy_defaults_to_review_and_honors_deny():
    services = [
        {"transport": "tcp", "port": 23, "service_name": "telnet"},
        {"transport": "tcp", "port": 45678, "service_name": "unknown"},
    ]
    rules = [{"action": "deny", "transport": "tcp", "ports": [23], "service": "telnet", "severity": "critical"}]
    evaluated, findings = device_posture.evaluate_service_policy(services, rules, policy_name="test")
    assert [row["policy_disposition"] for row in evaluated] == ["deny", "review"]
    assert [row["severity"] for row in findings] == ["critical", "medium"]


def test_policy_excludes_open_filtered_observations():
    service = {
        "transport": "udp", "port": 1900, "state": "open|filtered",
        "service_name": "upnp", "confidence": "inconclusive", "policy_eligible": False,
    }
    evaluated, findings = device_posture.evaluate_service_policy(
        [service],
        [{"action": "deny", "transport": "udp", "ports": [1900], "service": "upnp", "severity": "high"}],
        policy_name="media",
    )
    assert evaluated[0]["policy_disposition"] == "not_evaluated"
    assert findings == []


def test_device_decision_distinguishes_review_from_block():
    review = {
        "tool": "device_policy", "severity": "high",
        "evidence": {"disposition": "review"},
    }
    deny = {
        "tool": "device_policy", "severity": "low",
        "evidence": {"disposition": "deny"},
    }
    assert device_posture._device_decision([review], complete=True)[0] == "needs_review"
    assert device_posture._device_decision([deny], complete=True)[0] == "block"
    assert device_posture._device_decision([], complete=False)[0] == "needs_review"
    assert device_posture._device_decision([], complete=True)[0] == "allow"


def test_staged_scan_preserves_priority_ports_and_separates_udp_uncertainty(monkeypatch):
    commands = []

    async def fake_scope(*_args, **_kwargs):
        return _tcp_scope_result([80, 443])

    async def fake_run(cmd, timeout=60, input_text=None, retry=0):
        commands.append(cmd)
        if "-sU" in cmd:
            ports = (
                "<port protocol='udp' portid='53'><state state='open|filtered' reason='no-response'/><service name='domain'/></port>"
                "<port protocol='udp' portid='123'><state state='open' reason='udp-response'/><service name='ntp' product='Fixture NTP'/></port>"
            )
            return _nmap_xml(ports), "", 0
        if "-sV" in cmd:
            ports = (
                "<port protocol='tcp' portid='80'><state state='open' reason='syn-ack'/><service name='http' product='Fixture HTTP'/></port>"
                "<port protocol='tcp' portid='443'><state state='open' reason='syn-ack'/><service name='http' tunnel='ssl' product='Fixture TLS'/></port>"
            )
            return _nmap_xml(ports), "", 0
        raise AssertionError(f"unexpected scanner command: {cmd}")

    monkeypatch.setattr(device_posture, "run", fake_run)
    monkeypatch.setattr(device_posture, "_run_tcp_scope_discovery", fake_scope)
    services, observations, _, receipts, completeness = asyncio.run(
        device_posture._nmap_scan("device.test", device_posture.PROFILES["posture"]),
    )

    assert [(item["transport"], item["port"]) for item in services] == [
        ("tcp", 80), ("tcp", 443), ("udp", 123),
    ]
    assert [(item["transport"], item["port"]) for item in observations] == [("udp", 53)]
    assert completeness["complete"] is False
    assert completeness["execution_complete"] is True
    assert completeness["uncertainty_present"] is True
    assert completeness["tcp_discovery_complete"] is True
    assert completeness["incomplete_stages"] == ["udp_service_uncertainty"]
    assert receipts[0]["stage"] == "tcp_scope_discovery"
    fingerprint_command = next(cmd for cmd in commands if "-sV" in cmd and "-sT" in cmd)
    assert fingerprint_command[fingerprint_command.index("-p") + 1] == "80,443"
    assert all("-p-" not in command for command in commands)


def test_complete_naabu_inventory_does_not_claim_closed_filtered_classification(monkeypatch):
    async def fake_scope(*_args, **_kwargs):
        return _tcp_scope_result([])

    async def fake_run(cmd, timeout=60, input_text=None, retry=0):
        if "-sU" in cmd:
            closed = "<port protocol='udp' portid='53'><state state='closed' reason='port-unreach'/><service name='domain'/></port>"
            return _nmap_xml(closed), "", 0
        raise AssertionError(f"unexpected scanner command: {cmd}")

    monkeypatch.setattr(device_posture, "run", fake_run)
    monkeypatch.setattr(device_posture, "_run_tcp_scope_discovery", fake_scope)
    services, observations, _, _, completeness = asyncio.run(
        device_posture._nmap_scan("device.test", device_posture.PROFILES["posture"]),
    )
    assert services == []
    assert observations == []
    assert completeness["execution_complete"] is True
    assert completeness["tcp_visibility_complete"] is True
    assert completeness["tcp_closed_filtered_classification_complete"] is False
    assert completeness["tcp_silent_port_classification"] == "closed_or_filtered_not_distinguished"
    assert completeness["complete"] is True
    assert "tcp_scope_visibility" not in completeness["incomplete_stages"]


def test_udp_silence_prevents_allow_without_becoming_a_service(monkeypatch):
    async def fake_scope(*_args, **_kwargs):
        return _tcp_scope_result([])

    async def fake_run(cmd, timeout=60, input_text=None, retry=0):
        if "-sU" in cmd:
            uncertain = "<port protocol='udp' portid='1900'><state state='open|filtered' reason='no-response'/><service name='upnp'/></port>"
            return _nmap_xml(uncertain), "", 0
        return _nmap_xml(""), "", 0

    monkeypatch.setattr(device_posture, "run", fake_run)
    monkeypatch.setattr(device_posture, "_run_tcp_scope_discovery", fake_scope)
    services, observations, _, _, completeness = asyncio.run(
        device_posture._nmap_scan("device.test", device_posture.PROFILES["posture"]),
    )
    assert services == []
    assert [(item["transport"], item["port"]) for item in observations] == [("udp", 1900)]
    assert completeness["execution_complete"] is True
    assert completeness["uncertainty_present"] is True
    assert completeness["complete"] is False
    assert "udp_service_uncertainty" in completeness["incomplete_stages"]


def test_udp_extraports_silence_prevents_allow(monkeypatch):
    async def fake_scope(*_args, **_kwargs):
        return _tcp_scope_result([])

    def extraports_xml(protocol: str, state: str, count: int) -> str:
        return (
            "<?xml version='1.0'?><nmaprun scanner='nmap'>"
            f"<scaninfo protocol='{protocol}'/><host><status state='up'/><address addr='10.0.0.4' addrtype='ipv4'/>"
            f"<ports><extraports state='{state}' count='{count}'/></ports></host>"
            "<runstats><finished elapsed='1.0' exit='success' summary='done'/><hosts up='1' down='0' total='1'/></runstats>"
            "</nmaprun>"
        )

    async def fake_run(cmd, timeout=60, input_text=None, retry=0):
        if "-sU" in cmd:
            return extraports_xml("udp", "open|filtered", 15), "", 0
        return extraports_xml("tcp", "closed", 100), "", 0

    monkeypatch.setattr(device_posture, "run", fake_run)
    monkeypatch.setattr(device_posture, "_run_tcp_scope_discovery", fake_scope)
    services, observations, _, receipts, completeness = asyncio.run(
        device_posture._nmap_scan("device.test", device_posture.PROFILES["inventory"]),
    )
    udp_receipt = next(receipt for receipt in receipts if receipt["transport"] == "udp")
    assert services == []
    assert observations == []
    assert udp_receipt["udp_extraports_inconclusive_count"] == 15
    assert completeness["udp_extraports_inconclusive_count"] == 15
    assert completeness["execution_complete"] is True
    assert completeness["uncertainty_present"] is True
    assert completeness["complete"] is False
    assert "udp_service_uncertainty" in completeness["incomplete_stages"]


def test_require_policy_fails_closed_when_ssh_controls_are_unverified_or_weak():
    rule = {
        "action": "require",
        "transport": "tcp",
        "service": "ssh",
        "requirements": {"password_auth": False, "weak_algorithms": False},
        "severity": "high",
    }
    services = [{"transport": "tcp", "port": 2222, "service_name": "ssh", "ssh": {"scan_completed": False}}]
    evaluated, findings = device_posture.evaluate_service_policy(services, [rule], policy_name="ssh-baseline")
    assert evaluated[0]["policy_disposition"] == "require"
    assert findings[0]["severity"] == "high"
    assert "could not be verified" in findings[0]["description"]

    services[0]["ssh"] = {
        "scan_completed": True,
        "auth_methods_complete": True,
        "password_auth_enabled": True,
        "weak_algorithms": ["mac_in:hmac-sha1"],
    }
    _, findings = device_posture.evaluate_service_policy(services, [rule], policy_name="ssh-baseline")
    assert findings[0]["evidence"]["requirement_failures"] == [
        "SSH password authentication is enabled",
        "SSH negotiated a weak cryptographic algorithm",
    ]


def test_require_policy_passes_when_ssh_controls_are_proven():
    service = {
        "transport": "tcp",
        "port": 22,
        "service_name": "ssh",
        "ssh": {
            "scan_completed": True,
            "auth_methods_complete": True,
            "password_auth_enabled": False,
            "weak_algorithms": [],
            "publickey_enabled": True,
        },
    }
    rule = {
        "action": "require",
        "transport": "tcp",
        "service": "ssh",
        "requirements": {"password_auth": False, "weak_algorithms": False, "publickey_auth": True},
    }
    evaluated, findings = device_posture.evaluate_service_policy([service], [rule], policy_name="ssh-baseline")
    assert evaluated[0]["policy_disposition"] == "require"
    assert findings == []


def test_scanner_rejects_resolved_credentials_under_safe_remote_before_network(monkeypatch):
    async def unexpected_resolve(_locator):
        raise AssertionError("resolver must not run before the credential safety boundary")

    monkeypatch.setattr(device_posture, "resolve_device_address", unexpected_resolve)
    with pytest.raises(ValueError, match="credentials are forbidden"):
        asyncio.run(device_posture.run_device_posture_scan("tv.test", {
            "device_profile": "inventory",
            "safety_profile": "safe_remote",
            "confirm_authorized": True,
            "_resolved_device_credentials": [{
                "role": "ssh", "profile_id": "fixture", "auth_kind": "ssh_password",
                "username": "admin", "secret": "not-persisted",
            }],
        }))


def test_web_detection_checks_nonstandard_ports(monkeypatch):
    calls = []

    async def fake_probe(locator, port, *, tls, origin_locator=None, timeout=3.0):
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


def test_device_scan_emits_independent_safety_and_normalized_evidence(monkeypatch):
    services = [{
        "transport": "tcp", "port": 8443, "state": "open", "service_name": "https",
        "policy_eligible": True, "tunnel": "ssl",
    }]

    async def fake_nmap(locator, profile, **kwargs):
        return services, [], {"addresses": [{"address": "192.0.2.40", "type": "ipv4"}], "hostnames": ["tv.test"]}, [], {
            "complete": True,
            "execution_complete": True,
            "tcp_discovery_complete": True,
            "tcp_visibility_complete": True,
            "tcp_filtered_ports_count": 0,
            "tcp_fingerprinting_complete": True,
            "udp_discovery_complete": True,
            "uncertainty_present": False,
            "incomplete_stages": [],
        }

    async def fake_health(locator, *, stage, tcp_ports=(), timeout=1.5):
        return {"stage": stage, "status": "healthy" if tcp_ports else "indeterminate"}

    async def fake_reachability(locator, resolved_address, **kwargs):
        return {
            "schema_version": "device-reachability/v1", "status": "online", "online": True,
            "network_accessible": True, "service_accessible": True, "confidence": "high",
            "reason": "fixture response", "locator": locator, "resolved_address": resolved_address,
            "resolution_succeeded": True, "positive_signals": {"tcp_open_ports": [8443]},
            "attempts": [], "nmap_host_discovery": {},
        }

    async def fake_origins(locator, rows, **kwargs):
        return [{
            "origin": "https://tv.test:8443", "port": 8443, "scheme": "https",
            "tls": True, "status_line": "HTTP/1.1 200 OK",
        }]

    async def fake_protocols(locator, *, udp_ports):
        return []

    monkeypatch.setattr(device_posture, "_nmap_scan", fake_nmap)
    async def fake_resolve(_locator, **_kwargs):
        return "192.0.2.40"
    monkeypatch.setattr(device_posture, "resolve_device_address", fake_resolve)
    monkeypatch.setattr(device_posture, "probe_device_reachability", fake_reachability)
    monkeypatch.setattr(device_posture, "check_device_health", fake_health)
    monkeypatch.setattr(device_posture, "discover_core_device_protocols", fake_protocols)
    monkeypatch.setattr(device_posture, "detect_web_origins", fake_origins)
    result = asyncio.run(device_posture.run_device_posture_scan("tv.test", {
        "device_profile": "inventory",
        "safety_profile": "safe_remote",
        "confirm_authorized": True,
        "include_web_dast": True,
        "device_policy": {"name": "test", "rules": [{"action": "allow", "transport": "tcp", "service": "https", "encrypted": True}]},
    }))
    posture = result["device_posture"]
    assert posture["profile"] == "inventory"
    assert posture["safety"]["profile"]["name"] == "safe_remote"
    assert posture["evidence_graph"]["schema_version"] == "device-evidence/v1"
    assert result["scan_metadata"]["device_coverage_profile"] == "inventory"
    assert result["scan_metadata"]["device_safety_profile"] == "safe_remote"
    assert posture["reachability"]["status"] == "online"


def test_inconclusive_reachability_stops_before_inventory_and_has_no_grade(monkeypatch):
    async def fake_resolve(_locator, **_kwargs):
        return "192.0.2.55"

    async def fake_reachability(locator, resolved_address, **kwargs):
        return {
            "schema_version": "device-reachability/v1", "status": "inconclusive", "online": None,
            "network_accessible": False, "service_accessible": None, "confidence": "none",
            "reason": "No direct response proved that the device is online.",
            "locator": locator, "resolved_address": resolved_address, "resolution_succeeded": True,
            "positive_signals": {"tcp_open_ports": [], "tcp_refused_ports": []},
            "attempts": [], "nmap_host_discovery": {},
        }

    async def forbidden_inventory(*_args, **_kwargs):
        raise AssertionError("inventory must not run without positive reachability")

    monkeypatch.setattr(device_posture, "resolve_device_address", fake_resolve)
    monkeypatch.setattr(device_posture, "probe_device_reachability", fake_reachability)
    monkeypatch.setattr(device_posture, "_nmap_scan", forbidden_inventory)
    result = asyncio.run(device_posture.run_device_posture_scan("tv.test", {
        "device_profile": "inventory",
        "safety_profile": "safe_remote",
        "confirm_authorized": True,
        "include_web_dast": True,
        "device_policy": {"name": "test", "rules": []},
    }))
    assert result["result"] == {"score": None, "grade": None}
    assert result["device_posture"]["reachability"]["status"] == "inconclusive"
    assert result["device_posture"]["completeness"]["reachability_confirmed"] is False
    assert result["device_posture"]["decision"]["decision"] == "needs_review"


def test_posture_reuses_all_tcp_fallback_when_only_nonstandard_port_responds(monkeypatch):
    services = [{
        "transport": "tcp", "port": 7345, "state": "open", "service_name": "unknown",
        "policy_eligible": True,
    }]
    fallback = (
        services,
        [],
        {"addresses": [{"address": "192.0.2.55", "type": "ipv4"}], "hostnames": []},
        {
            "stage": "tcp_scope_discovery", "transport": "tcp", "complete": True,
            "xml_parsed": True, "confirmed_open_count": 1, "tcp_filtered_count": 0,
            "port_state_counts": {"open": 1, "closed": 65534}, "incomplete_reasons": [],
        },
    )
    reused = False

    async def fake_resolve(_locator, **_kwargs):
        return "192.0.2.55"

    async def fake_reachability(locator, resolved_address, **kwargs):
        assert 7345 in kwargs["port_hints"]
        assert 6466 in kwargs["port_hints"]
        return {
            "schema_version": "device-reachability/v1", "status": "inconclusive", "online": None,
            "network_accessible": None, "service_accessible": None, "confidence": "none",
            "reason": "No direct response proved that the device is online.",
            "locator": locator, "resolved_address": resolved_address, "resolution_succeeded": True,
            "positive_signals": {"tcp_open_ports": [], "tcp_refused_ports": []},
            "attempts": [], "nmap_host_discovery": {},
        }

    async def fake_scope(*_args, **_kwargs):
        return fallback

    async def fake_nmap(_locator, _profile, **kwargs):
        nonlocal reused
        reused = kwargs["prefetched_tcp_scope"] is fallback
        return services, [], fallback[2], [fallback[3]], {
            "complete": True, "execution_complete": True, "tcp_discovery_complete": True,
            "tcp_visibility_complete": True, "tcp_filtered_ports_count": 0,
            "tcp_fingerprinting_complete": True, "udp_discovery_complete": True,
            "uncertainty_present": False, "incomplete_stages": [],
        }

    async def fake_health(_locator, *, stage, tcp_ports=(), timeout=1.5):
        return {"stage": stage, "status": "healthy", "attempted_tcp_ports": list(tcp_ports), "responsive_tcp_ports": list(tcp_ports)}

    async def fake_protocols(_locator, *, udp_ports):
        return []

    async def fake_origins(*_args, **_kwargs):
        return []

    monkeypatch.setattr(device_posture, "resolve_device_address", fake_resolve)
    monkeypatch.setattr(device_posture, "probe_device_reachability", fake_reachability)
    monkeypatch.setattr(device_posture, "_run_tcp_scope_discovery", fake_scope)
    monkeypatch.setattr(device_posture, "_nmap_scan", fake_nmap)
    monkeypatch.setattr(device_posture, "check_device_health", fake_health)
    monkeypatch.setattr(device_posture, "discover_core_device_protocols", fake_protocols)
    monkeypatch.setattr(device_posture, "detect_web_origins", fake_origins)
    result = asyncio.run(device_posture.run_device_posture_scan("tv.test", {
        "device_profile": "posture",
        "safety_profile": "safe_remote",
        "confirm_authorized": True,
        "include_web_dast": False,
        "device_class": "media",
        "device_policy": {"name": "test", "rules": []},
    }))
    assert reused is True
    assert result["device_posture"]["reachability"]["status"] == "online"
    assert result["device_posture"]["reachability"]["fallback"]["inventory_reused"] is True


def test_major_tv_manufacturer_port_sets_cover_native_and_multi_os_models():
    ports = device_posture.TV_MANUFACTURER_TCP_PORTS
    assert {7345, 9000}.issubset(ports["vizio"])
    assert {3000, 3001}.issubset(ports["lg"])
    assert {8001, 8002}.issubset(ports["samsung"])
    assert {6466, 6467, 8008, 8009, 8060}.issubset(ports["tcl"])
    assert {6466, 6467, 8008, 8009, 8060, 36669}.issubset(ports["hisense"])


def test_hisense_manufacturer_adds_vidaa_mqtt_to_preflight(monkeypatch):
    captured: list[int] = []

    async def fake_resolve(_locator, **_kwargs):
        return "192.0.2.56"

    async def fake_reachability(locator, resolved_address, **kwargs):
        captured.extend(kwargs["port_hints"])
        return {
            "schema_version": "device-reachability/v1", "status": "inconclusive", "online": None,
            "network_accessible": None, "service_accessible": None, "confidence": "none",
            "reason": "silence", "locator": locator, "resolved_address": resolved_address,
            "resolution_succeeded": True, "positive_signals": {}, "attempts": [], "nmap_host_discovery": {},
        }

    monkeypatch.setattr(device_posture, "resolve_device_address", fake_resolve)
    monkeypatch.setattr(device_posture, "probe_device_reachability", fake_reachability)
    result = asyncio.run(device_posture.run_device_posture_scan("tv.test", {
        "device_class": "media", "device_manufacturer": "Hisense USA",
        "device_profile": "inventory", "safety_profile": "safe_remote",
        "confirm_authorized": True, "include_web_dast": False,
        "device_policy": {"name": "test", "rules": []},
    }))
    assert 36669 in captured
    assert result["device_posture"]["reachability"]["status"] == "inconclusive"


def test_posture_fallback_silence_stays_inconclusive(monkeypatch):
    async def fake_resolve(_locator, **_kwargs):
        return "192.0.2.55"

    async def fake_reachability(locator, resolved_address, **_kwargs):
        return {
            "schema_version": "device-reachability/v1", "status": "inconclusive", "online": None,
            "network_accessible": None, "service_accessible": None, "confidence": "none",
            "reason": "silence", "locator": locator, "resolved_address": resolved_address,
            "resolution_succeeded": True, "positive_signals": {}, "attempts": [], "nmap_host_discovery": {},
        }

    async def fake_scope(*_args, **_kwargs):
        return [], [], {}, {
            "stage": "tcp_scope_discovery", "transport": "tcp", "complete": True,
            "xml_parsed": True, "confirmed_open_count": 0, "tcp_filtered_count": 65535,
            "port_state_counts": {"filtered": 65535}, "incomplete_reasons": [],
        }

    monkeypatch.setattr(device_posture, "resolve_device_address", fake_resolve)
    monkeypatch.setattr(device_posture, "probe_device_reachability", fake_reachability)
    monkeypatch.setattr(device_posture, "_run_tcp_scope_discovery", fake_scope)
    result = asyncio.run(device_posture.run_device_posture_scan("tv.test", {
        "device_profile": "posture", "safety_profile": "safe_remote",
        "confirm_authorized": True, "include_web_dast": False,
        "device_policy": {"name": "test", "rules": []},
    }))
    assert result["result"] == {"score": None, "grade": None}
    assert result["device_posture"]["reachability"]["status"] == "inconclusive"


def test_fingerprinting_is_capped_and_forces_incomplete_coverage(monkeypatch):
    fingerprinted_ports = []

    async def fake_scope(*_args, **_kwargs):
        return _tcp_scope_result(list(range(1, 601)))

    async def fake_run(cmd, timeout=60, input_text=None, retry=0):
        if "-sU" in cmd:
            closed = "<port protocol='udp' portid='53'><state state='closed' reason='port-unreach'/><service name='domain'/></port>"
            return _nmap_xml(closed), "", 0
        if "-sV" in cmd:
            ports_arg = cmd[cmd.index("-p") + 1]
            batch = [int(value) for value in ports_arg.split(",")]
            fingerprinted_ports.extend(batch)
            ports = "".join(
                f"<port protocol='tcp' portid='{port}'><state state='open' reason='syn-ack'/><service name='http'/></port>"
                for port in batch
            )
            return _nmap_xml(ports), "", 0
        raise AssertionError(f"unexpected scanner command: {cmd}")

    monkeypatch.setattr(device_posture, "run", fake_run)
    monkeypatch.setattr(device_posture, "_run_tcp_scope_discovery", fake_scope)
    services, _, _, _, completeness = asyncio.run(
        device_posture._nmap_scan("device.test", device_posture.PROFILES["posture"]),
    )
    assert len(services) == 600
    assert len(set(fingerprinted_ports)) == device_posture.MAX_FINGERPRINT_PORTS
    assert completeness["tcp_fingerprint_truncated_count"] == 88
    assert completeness["tcp_fingerprinting_complete"] is False
    assert completeness["execution_complete"] is False
    assert completeness["complete"] is False
    assert "tcp_fingerprint_truncated" in completeness["incomplete_stages"]


def test_device_destination_denies_metadata_but_allows_authorized_public_hosts(monkeypatch):
    monkeypatch.delenv("SHAKERSCAN_DEVICE_ALLOW_METADATA_TARGETS", raising=False)
    monkeypatch.delenv("SHAKERSCAN_DEVICE_DENY_CIDRS", raising=False)
    with pytest.raises(ValueError, match="metadata"):
        device_posture.validate_device_destination("169.254.169.254")
    assert device_posture.validate_device_destination("8.8.8.8") == "8.8.8.8"


def test_device_destination_supports_operator_deny_cidrs(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_DEVICE_DENY_CIDRS", "203.0.113.0/24")
    with pytest.raises(ValueError, match="configured control-plane"):
        device_posture.validate_device_destination("203.0.113.10")


def test_multi_address_resolution_uses_numeric_ip_order(monkeypatch):
    class FakeLoop:
        async def getaddrinfo(self, *_args, **_kwargs):
            return [
                (2, 1, 6, "", ("10.0.0.10", 0)),
                (2, 1, 6, "", ("10.0.0.9", 0)),
            ]

    monkeypatch.setattr(device_posture.asyncio, "get_running_loop", lambda: FakeLoop())
    assert asyncio.run(device_posture.resolve_device_address("tv.local")) == "10.0.0.9"


def test_vendor_port_hints_require_exact_manufacturer_or_model_tokens():
    assert 8001 not in device_posture.manufacturer_priority_ports("NotSamsung-compatible", "Generic")
    assert 8001 in device_posture.manufacturer_priority_ports("Samsung", "Tizen TV")


def test_device_worker_deployment_is_isolated_from_web_dast():
    root = Path(__file__).resolve().parents[1]
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
    launcher = (root / "scanner.sh").read_text(encoding="utf-8")

    assert "device-worker:" in compose
    assert 'profiles: ["devices"]' in compose
    assert "hostname: shakerscan-device-worker" in compose
    assert "DEVICE_ONLY_WORKER=true" in compose
    assert "compose --profile devices up --no-build -d device-worker" in launcher
    assert "compose --profile devices up -d --build device-worker" not in launcher
    assert "compose --profile devices up --no-build -d --force-recreate device-worker" in launcher
    assert "refresh_device_worker_after_rebuild \"$existing_device_workers\"" in launcher
    assert "Usage: ./scanner.sh devices {start|stop|restart|status|logs}" in launcher


def test_device_inventory_only_retires_services_after_matching_complete_coverage():
    root = Path(__file__).resolve().parents[1]
    worker = (root / "api" / "worker.py").read_text(encoding="utf-8")
    api = (root / "api" / "api.py").read_text(encoding="utf-8")

    assert 'completeness.get("complete") and completeness.get("tcp_scope") == "all_65535"' in worker
    assert 'completeness.get("udp_discovery_complete") and udp_ports_requested' in worker
    assert 'for service in [*services, *observations]:' in worker
    assert "ds.device_target_id=d.id AND ds.state='open'" in api
    assert "device_target_id=$1 AND state='open'" in api
    assert "device_target_id=$1 AND state='open|filtered' AND scan_id=$2" in api
    assert '"inconclusive_observations": [_decode_device_row(item) for item in observations]' in api


def test_upgrade_migration_adds_run_kind_before_device_filtered_views():
    root = Path(__file__).resolve().parents[1]
    migrations = (root / "api" / "retest_contract.py").read_text(encoding="utf-8")

    run_kind_column = migrations.index("ADD COLUMN IF NOT EXISTS run_kind TEXT DEFAULT 'web_dast'")
    latest_scans_view = migrations.index("CREATE OR REPLACE VIEW latest_scans AS")
    assert run_kind_column < latest_scans_view
