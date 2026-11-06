"""Every authorized address is scanned, CDN edges are not origins, and sweeps resume."""

from __future__ import annotations

import asyncio

import pytest

from scanner.scanner_tools import cdn_edges, device_posture, device_service_identity
from api.devices.router import DeviceScanRequest, _incomplete_tcp_ranges, _network_coverage
from tests.test_service_protocol_adapters import _scripted, _serve


def _child(address: str, *, services, findings=(), complete=True, status="online"):
    return {
        "target": "app.example.test",
        "resolved_target": address,
        "result": {"score": 90, "grade": "A"},
        "findings": [dict(item) for item in findings],
        "device_posture": {
            "resolved_target": address,
            "reachability": {"status": status},
            "services": [dict(item) for item in services],
            "web_origins": [],
            "runtime_destinations": [],
            "decision": {"decision": "pass", "rationale": "fixture"},
            "completeness": {"complete": complete, "execution_complete": complete,
                             "incomplete_stages": [] if complete else ["tcp_scope_range_3_of_8"]},
            "address_coverage": [{"address": address, "tcp_ranges": []}],
        },
    }


def test_a_name_with_two_addresses_runs_one_pinned_child_per_address(monkeypatch):
    calls = []

    async def fake_addresses(locator, **kwargs):
        return ["192.0.2.10", "2001:db8::10"], ["10.0.0.5"]

    async def fake_pinned(locator, options):
        calls.append((locator, options["_pinned_address"], options["resolved_budget"]["max_duration_minutes"]))
        port = 22 if options["_pinned_address"] == "192.0.2.10" else 3306
        return _child(options["_pinned_address"], services=[
            {"transport": "tcp", "port": port, "state": "open", "service_name": "x"},
        ])

    monkeypatch.setattr(device_posture, "resolve_device_addresses", fake_addresses)
    monkeypatch.setattr(device_posture, "_run_pinned_device_posture_scan", fake_pinned)
    result = asyncio.run(device_posture.run_device_posture_scan("app.example.test", {
        "device_profile": "posture", "resolved_budget": {"max_duration_minutes": 120},
    }))
    assert [call[1] for call in calls] == ["192.0.2.10", "2001:db8::10"]
    assert all(call[2] == 60 for call in calls)  # the budget is shared, not multiplied
    posture = result["device_posture"]
    assert [row["port"] for row in posture["services"]] == [22, 3306]
    assert posture["services"][1]["observed_addresses"] == ["2001:db8::10"]
    listed = {row["address"]: row for row in posture["addresses"]}
    assert set(listed) == {"192.0.2.10", "2001:db8::10", "10.0.0.5"}
    assert listed["10.0.0.5"]["not_scanned"] == "refused_by_destination_policy"
    # A refused address is named but was never in scope: it does not make the scan partial.
    assert posture["completeness"]["complete"] is True
    assert posture["completeness"]["address_count"] == 3


def test_one_address_keeps_the_single_pinned_scan(monkeypatch):
    seen = []

    async def fake_addresses(locator, **kwargs):
        return ["192.0.2.10"], []

    async def fake_pinned(locator, options):
        seen.append(options.get("_pinned_address"))
        return _child("192.0.2.10", services=[])

    monkeypatch.setattr(device_posture, "resolve_device_addresses", fake_addresses)
    monkeypatch.setattr(device_posture, "_run_pinned_device_posture_scan", fake_pinned)
    asyncio.run(device_posture.run_device_posture_scan("app.example.test", {}))
    assert seen == [None]


def test_merge_keeps_each_finding_with_its_address_and_needs_every_child_complete():
    merged = device_posture.merge_address_children("app.example.test", [
        _child("192.0.2.10", services=[{"transport": "tcp", "port": 22, "state": "open"}],
               findings=[{"title": "Telnet", "severity": "high", "evidence": {}}]),
        _child("192.0.2.11", services=[{"transport": "tcp", "port": 22, "state": "open"}],
               findings=[{"title": "Telnet", "severity": "high"}], complete=False),
    ])
    assert [item["evidence"]["connect_address"] for item in merged["findings"]] == ["192.0.2.10", "192.0.2.11"]
    assert merged["device_posture"]["services"][0]["observed_addresses"] == ["192.0.2.10", "192.0.2.11"]
    completeness = merged["device_posture"]["completeness"]
    assert completeness["complete"] is False
    assert "address:192.0.2.11:tcp_scope_range_3_of_8" in completeness["incomplete_stages"]


def test_resolve_device_addresses_splits_admitted_and_refused(monkeypatch):
    async def fake_getaddrinfo(host, port, type=None):
        return [(None, None, None, None, ("10.0.0.5", 0)), (None, None, None, None, ("192.0.2.10", 0)),
                (None, None, None, None, ("2001:db8::10", 0, 0, 0))]

    async def run():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
        return await device_posture.resolve_device_addresses(
            "app.example.test", admit=lambda address: not address.startswith("10."),
        )

    assert asyncio.run(run()) == (["192.0.2.10", "2001:db8::10"], ["10.0.0.5"])


# --- resumable sweep and declared scopes -----------------------------------------------------

def _chunk_order(monkeypatch, **kwargs):
    order = []

    async def fake_chunk(locator, *, stage, port_args, port_count, **_kwargs):
        order.append(port_args[-1])
        return [], {}, {"stage": stage, "complete": True, "parsed": True, "port_spec": port_args[-1],
                        "port_count": port_count, "attempt": 1}

    monkeypatch.setattr(device_posture, "_run_naabu_chunk", fake_chunk)
    _services, _u, _i, receipt = asyncio.run(device_posture._run_naabu_tcp_scope_discovery(
        "192.0.2.10", priority_ports=(22, 80), **kwargs,
    ))
    return order, receipt


def test_ranges_a_budget_cut_left_incomplete_run_first_and_every_range_still_runs(monkeypatch):
    order, receipt = _chunk_order(monkeypatch, full_tcp=True, resume_first=("40961-49152",))
    assert order[0] == "22,80" and order[1] == "40961-49152"
    assert len(order) == 1 + len(device_posture._full_tcp_ranges())
    assert receipt["scope"] == "all_tcp" and receipt["complete"] is True


def test_a_declared_port_set_is_the_whole_scope(monkeypatch):
    order, receipt = _chunk_order(monkeypatch, full_tcp=False, explicit_ports=(443, 80, 8443))
    assert order == ["80,443,8443"]
    assert receipt["scope"] == "declared_ports"


def test_incomplete_ranges_are_read_from_the_stored_coverage():
    coverage = [{"tcp_ranges": [
        {"stage": "tcp_scope_range_1_of_8", "ports": "1-8192", "complete": True},
        {"stage": "tcp_scope_range_6_of_8", "ports": "40961-49152", "complete": False},
        {"stage": "tcp_scope_range_6_of_8", "ports": "40961-49152", "complete": False},
        {"stage": "x", "ports": "1-2; rm", "complete": False},
    ], "tcp_ranges_incomplete": ["tcp_scope_range_6_of_8", "x"]}]
    assert _incomplete_tcp_ranges(coverage) == ["40961-49152"]
    assert _incomplete_tcp_ranges("not json") == []


def test_coverage_names_ranges_retries_and_the_printer_exclusion():
    receipts = [{"stage": "tcp_scope_discovery", "chunk_receipts": [
        {"stage": "tcp_scope_range_1_of_8", "port_spec": "1-8192", "port_count": 8192, "attempt": 1, "complete": False},
        {"stage": "tcp_scope_range_1_of_8", "port_spec": "1-8192", "port_count": 8192, "attempt": 2, "complete": True},
        {"stage": "tcp_scope_range_2_of_8", "port_spec": "8193-16384", "port_count": 8192, "attempt": 1, "complete": False,
         "incomplete_reasons": ["overall_device_budget_exhausted"]},
    ]}]
    coverage = device_service_identity.address_coverage(
        "192.0.2.10", tool_receipts=receipts, udp_ports=(53, 123), tcp_scope="all_65535",
    )
    assert coverage["retries"] == 1
    assert coverage["tcp_ranges_incomplete"] == ["tcp_scope_range_2_of_8"]
    assert coverage["exclusions"][0]["ports"] == "9100-9107"
    assert coverage["udp_ports_requested"] == [53, 123]


# --- CDN edge versus origin ------------------------------------------------------------------

@pytest.mark.parametrize("address,provider", [
    ("104.16.132.229", "Cloudflare"), ("2606:4700::6810:84e5", "Cloudflare"),
    ("::ffff:104.16.132.229", "Cloudflare"), ("203.0.113.5", None), ("not-an-ip", None),
])
def test_cloudflare_edges_are_recognised_from_published_ranges(address, provider):
    assert cdn_edges.edge_provider(address) == provider


def test_an_edge_is_labelled_as_assessed_through_the_cdn_only():
    role = cdn_edges.network_role("104.16.132.229")
    assert role["note"] == "application assessed through the CDN; origin network not assessed"
    assert role["origin_assessed"] is False and 443 in role["tcp_ports_examined"]
    assert cdn_edges.network_role("203.0.113.5") is None
    assert cdn_edges.edge_from_headers({"Server": "cloudflare", "CF-RAY": "x"}) == "Cloudflare"
    assert cdn_edges.edge_from_headers({"Server": "nginx"}) is None


def test_the_origin_server_name_is_a_dns_name_only():
    assert DeviceScanRequest(server_name="App.Example.TEST.").server_name == "app.example.test"
    for bad in ("https://app.example.test", "app example", "a/b", "-bad.test"):
        with pytest.raises(ValueError):
            DeviceScanRequest(server_name=bad)
    assert device_posture._server_name("203.0.113.5") is None
    assert device_posture._server_name("app.example.test") == "app.example.test"


# --- nmap table guesses and protocol identification ------------------------------------------

def test_an_nmap_table_guess_is_a_port_hint_not_the_service():
    xml = (
        "<?xml version='1.0'?><nmaprun><host><address addr='192.0.2.10' addrtype='ipv4'/><ports>"
        "<port protocol='tcp' portid='6379'><state state='open' reason='syn-ack'/>"
        "<service name='redis' method='table' conf='3'/></port>"
        "<port protocol='tcp' portid='2222'><state state='open' reason='syn-ack'/>"
        "<service name='ssh' product='OpenSSH' version='9.6p1' method='probed' conf='10'/></port>"
        "</ports></host><runstats><finished exit='success'/></runstats></nmaprun>"
    )
    services, *_rest = device_posture.parse_nmap_evidence(xml)
    by_port = {row["port"]: row for row in services}
    assert by_port[6379]["service_name"] == "unknown" and by_port[6379]["port_hint"] == "redis"
    assert by_port[2222]["service_name"] == "ssh" and "port_hint" not in by_port[2222]


def test_an_unnamed_port_takes_the_protocol_its_handshake_confirmed():
    async def run():
        async with _serve(_scripted(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n")) as port:
            services = [{"transport": "tcp", "port": port, "state": "open", "service_name": "unknown",
                         "product": "", "version": ""}]
            receipt = await device_service_identity.identify_device_services("127.0.0.1", services)
            return services[0], receipt

    service, receipt = asyncio.run(run())
    assert service["service_name"] == "ssh" and service["identity_basis"] == "protocol_adapter"
    assert service["product"] == "OpenSSH" and service["version"] == "9.6p1"
    assert service["identity"]["version_reported"] == "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
    assert receipt["identified"] == 1 and receipt["required"] is False


def test_an_edge_scan_examines_only_the_proxied_ports_and_says_the_origin_was_not_assessed(monkeypatch):
    seen = {}

    async def fake_reachability(locator, resolved_address, **kwargs):
        return {"status": "online", "locator": locator, "resolved_address": resolved_address,
                "positive_signals": {"tcp_open_ports": [443]}, "attempts": []}

    async def fake_nmap(address, profile, **kwargs):
        seen["tcp_args"], seen["udp_ports"] = profile.tcp_args, profile.udp_ports
        return ([{"transport": "tcp", "port": 443, "state": "open", "service_name": "https"}], [],
                {"hostnames": [], "addresses": [], "os_matches": []}, [],
                {"complete": True, "execution_complete": True, "incomplete_stages": []})

    async def no_tcp_identification(address, services, **_kwargs):
        return {"stage": "device_protocol_identification", "required": False, "complete": True}

    async def nothing(*_args, **_kwargs):
        return []

    async def healthy(*_args, **_kwargs):
        return {"status": "healthy"}

    monkeypatch.setattr(device_posture, "probe_device_reachability", fake_reachability)
    monkeypatch.setattr(device_posture, "corroborate_device_reachability", lambda reachability, **_k: reachability)
    monkeypatch.setattr(device_posture, "_nmap_scan", fake_nmap)
    monkeypatch.setattr(device_posture, "identify_device_services", no_tcp_identification)
    monkeypatch.setattr(device_posture, "identify_device_udp", nothing)
    monkeypatch.setattr(device_posture, "discover_core_device_protocols", nothing)
    monkeypatch.setattr(device_posture, "detect_web_origins", nothing)
    monkeypatch.setattr(device_posture, "check_device_health", healthy)
    result = asyncio.run(device_posture.run_device_posture_scan("104.16.132.229", {
        "device_profile": "posture", "safety_profile": "observe_only", "confirm_authorized": True,
        "device_policy": {"name": "test", "rules": []},
    }))
    assert seen["tcp_args"][0] == "-p" and "443" in seen["tcp_args"][1].split(",")
    assert seen["udp_ports"] == ()
    posture = result["device_posture"]
    assert posture["network_role"]["note"] == "application assessed through the CDN; origin network not assessed"
    assert posture["completeness"]["tcp_scope"] == "cdn_edge_proxied_ports"
    assert posture["address_coverage"][0]["network_role"]["provider"] == "Cloudflare"


def test_the_device_page_gets_the_edge_note_and_a_per_address_summary():
    role = cdn_edges.network_role("104.16.132.229")
    coverage = _network_coverage(role, [
        {"address": "192.0.2.10", "primary": True, "reachability_status": "online", "complete": True,
         "confirmed_services_count": 2, "services": [{"port": 22}]},
        {"address": "10.0.0.5", "primary": False, "not_scanned": "refused_by_destination_policy"},
    ])
    assert coverage["network_role"]["note"] == cdn_edges.EDGE_NOTE
    assert coverage["addresses"][0]["confirmed_services_count"] == 2
    assert "services" not in coverage["addresses"][0]
    assert coverage["addresses"][1]["not_scanned"] == "refused_by_destination_policy"
    assert _network_coverage(None, None) is None


def test_an_authorized_address_beyond_the_child_limit_makes_the_scan_partial():
    merged = device_posture.merge_address_children("app.example.test", [
        _child("192.0.2.10", services=[]), _child("192.0.2.11", services=[]),
    ], not_scanned=[{"address": "192.0.2.99", "reason": "address_child_limit"}])
    assert merged["device_posture"]["completeness"]["complete"] is False
    assert "address:192.0.2.99:address_child_limit" in merged["device_posture"]["completeness"]["incomplete_stages"]
