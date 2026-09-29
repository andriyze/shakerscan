from __future__ import annotations

import asyncio
import errno
import ipaddress
import socket

from api.capabilities import tls as tls_capability
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


class _ClosedSensitiveTlsObject(_TlsObject):
    def __init__(self):
        self.closed = False

    def version(self):
        return None if self.closed else super().version()

    def cipher(self):
        return None if self.closed else super().cipher()

    def selected_alpn_protocol(self):
        return None if self.closed else super().selected_alpn_protocol()


class _ClosedSensitiveWriter(_Writer):
    def __init__(self):
        super().__init__()
        self.tls_object = _ClosedSensitiveTlsObject()

    def get_extra_info(self, name):
        return self.tls_object if name == "ssl_object" else None

    def close(self):
        self.closed = True
        self.tls_object.closed = True


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
    assert result["observation"]["attempted_addresses"] == ["192.0.2.10"]
    assert result["observation"]["connected_addresses"] == ["192.0.2.10"]
    assert result["observation"]["address_policy"]["no_runtime_resolution"] is True
    assert result["budget_consumed"] == {
        "tcp_ports_attempted": 3,
        "tool_wall_seconds": 1,
    }
    assert writer.closed is True


def test_tls_evidence_is_snapshotted_before_the_connection_closes(monkeypatch):
    writers = []

    async def fake_open_connection(**_kwargs):
        writer = _ClosedSensitiveWriter()
        writers.append(writer)
        return object(), writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    result = asyncio.run(inspect_tls_origin(
        "https://app.example.test",
        target=_target(),
        timeout_seconds=15,
    ))

    observation = result["observation"]
    assert all(writer.closed for writer in writers)
    assert observation["protocol"] == "TLSv1.3"
    assert observation["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert observation["legacy_protocol_negotiated"] is False


def test_tls_default_address_is_stable_not_resolver_order(monkeypatch):
    calls = []

    async def fake_open_connection(**kwargs):
        calls.append(kwargs)
        return object(), _Writer()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    target = TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=("2001:db8::20", "192.0.2.20", "192.0.2.10"),
        allowed_root_domains=("example.test",),
    )

    result = asyncio.run(inspect_tls_origin(
        "https://app.example.test", target=target, timeout_seconds=15,
    ))

    assert result["status"] == "success"
    assert {call["host"] for call in calls} == {"192.0.2.10"}
    assert result["observation"]["pinned_address"] == "192.0.2.10"


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


def _cdn_target() -> TargetBinding:
    # A CDN name: several A records plus AAAA records, all frozen at submission.
    return TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=(
            "192.0.2.10", "192.0.2.11", "2001:db8::10", "2001:db8::11",
        ),
        allowed_root_domains=("example.test",),
    )


def _ipv6_unreachable_connection(calls):
    async def fake_open_connection(**kwargs):
        calls.append(kwargs["host"])
        if ipaddress.ip_address(kwargs["host"]).version == 6:
            raise OSError(errno.ENETUNREACH, "Network is unreachable")
        return object(), _Writer()

    return fake_open_connection


def _worker_without_ipv6_route(address, _port=443):
    if ipaddress.ip_address(address).version == 6:
        return {
            "reason": "worker_route_unavailable",
            "address_family": "ipv6",
            "errno": "ENETUNREACH",
        }
    return None


def test_addresses_the_worker_cannot_route_do_not_make_a_cdn_target_partial(
    monkeypatch,
):
    calls = []
    monkeypatch.setattr(asyncio, "open_connection", _ipv6_unreachable_connection(calls))
    monkeypatch.setattr(
        tls_capability, "worker_route_gap", _worker_without_ipv6_route, raising=False,
    )

    result = asyncio.run(inspect_tls_binding(target=_cdn_target()))

    assert result["status"] == "success"
    assert result["partial"] is False
    assert result["ok"] is True
    assert result["error"] is None
    assert result["errors"] == []
    by_address = {item["pinned_address"]: item for item in result["observations"]}
    # Every frozen address stays in the record; the unroutable ones say why.
    assert set(by_address) == set(_cdn_target().allowed_addresses)
    for address in ("192.0.2.10", "192.0.2.11"):
        assert by_address[address]["status"] == "success"
    for address in ("2001:db8::10", "2001:db8::11"):
        observation = by_address[address]
        assert observation["status"] == "not_examined"
        assert observation["connected_addresses"] == []
        assert observation["examination_gap"] == {
            "reason": "worker_route_unavailable",
            "address_family": "ipv6",
            "errno": "ENETUNREACH",
        }
        assert observation["protocol_attempts"] == [{
            "protocol": "TLSv1.2",
            "supported": False,
            "error_type": "OSError",
            "error_errno": "ENETUNREACH",
        }]
        assert "certificate_sha256" not in observation
    # A locally refused connect is not retried per protocol profile.
    assert calls.count("2001:db8::10") == 1
    assert calls.count("2001:db8::11") == 1
    assert result["budget_consumed"]["tcp_ports_attempted"] == 3 + 3 + 1 + 1


def test_a_remote_unreachable_answer_stays_a_partial_failure(monkeypatch):
    calls = []
    monkeypatch.setattr(asyncio, "open_connection", _ipv6_unreachable_connection(calls))
    # The worker has an IPv6 route, so ENETUNREACH came from the target path.
    monkeypatch.setattr(
        tls_capability, "worker_route_gap", lambda *_args: None, raising=False,
    )

    result = asyncio.run(inspect_tls_binding(target=_cdn_target()))

    assert result["status"] == "partial"
    assert result["partial"] is True
    assert result["errors"] == [
        "tls_handshake:no_supported_protocol",
        "tls_handshake:no_supported_protocol",
    ]
    failed = [
        item for item in result["observations"] if item["status"] == "failed"
    ]
    assert {item["pinned_address"] for item in failed} == {
        "2001:db8::10", "2001:db8::11",
    }
    assert all(
        attempt["error_errno"] == "ENETUNREACH"
        for item in failed for attempt in item["protocol_attempts"]
    )
    assert calls.count("2001:db8::10") == 3


def test_a_binding_with_no_routable_address_fails_rather_than_passing(monkeypatch):
    calls = []
    monkeypatch.setattr(asyncio, "open_connection", _ipv6_unreachable_connection(calls))
    monkeypatch.setattr(
        tls_capability, "worker_route_gap", _worker_without_ipv6_route, raising=False,
    )
    target = TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=("2001:db8::10",),
        allowed_root_domains=("example.test",),
    )

    result = asyncio.run(inspect_tls_binding(target=target))

    assert result["ok"] is False
    assert result["status"] == "failed"
    assert result["error"] == "tls_route_unavailable:worker_route_unavailable"
    assert result["observations"][0]["status"] == "not_examined"


def test_hunt_tls_on_an_unroutable_address_is_an_explicit_failure(monkeypatch):
    calls = []
    monkeypatch.setattr(asyncio, "open_connection", _ipv6_unreachable_connection(calls))
    monkeypatch.setattr(
        tls_capability, "worker_route_gap", _worker_without_ipv6_route, raising=False,
    )

    result = asyncio.run(inspect_tls_origin(
        "https://app.example.test",
        target=_cdn_target(),
        pinned_address="2001:db8::10",
    ))

    assert result["ok"] is False
    assert result["status"] == "not_examined"
    assert result["error"] == "tls_route_unavailable:worker_route_unavailable"
    assert result["budget_consumed"]["tcp_ports_attempted"] == 1


_IF_INET6_LOOPBACK_ONLY = "00000000000000000000000000000001 01 80 10 80       lo\n"
_IF_INET6_GLOBAL = _IF_INET6_LOOPBACK_ONLY + (
    "20010db8000000000000000000000002 02 40 00 00     eth0\n"
    "fe800000000000000000000000000002 02 40 20 80     eth0\n"
)
_ROUTE_WITH_DEFAULT = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
    "eth0\t00000000\t010013AC\t0003\t0\t0\t0\t00000000\n"
)


def _kernel_tables(monkeypatch, tmp_path, *, if_inet6, route=_ROUTE_WITH_DEFAULT):
    inet6 = tmp_path / "if_inet6"
    inet6.write_text(if_inet6)
    routes = tmp_path / "route"
    routes.write_text(route)
    monkeypatch.setattr(tls_capability, "_PROC_IF_INET6", str(inet6))
    monkeypatch.setattr(tls_capability, "_PROC_ROUTE", str(routes))


def test_worker_route_gap_reads_the_kernel_tables_without_opening_a_socket(monkeypatch, tmp_path):
    def no_socket(*_args, **_kwargs):
        raise AssertionError("the route check must not open a socket")

    monkeypatch.setattr(socket, "socket", no_socket)
    _kernel_tables(monkeypatch, tmp_path, if_inet6=_IF_INET6_LOOPBACK_ONLY)
    assert tls_capability.worker_route_gap("2001:db8::10", errno.ENETUNREACH) == {
        "reason": "worker_route_unavailable",
        "address_family": "ipv6",
        "errno": "ENETUNREACH",
    }
    # IPv4 still has its default route, so an unreachable answer is the target path's.
    assert tls_capability.worker_route_gap("192.0.2.10", errno.ENETUNREACH) is None

    # A worker with a global IPv6 address keeps an IPv6 unreachable answer as a failure.
    _kernel_tables(monkeypatch, tmp_path, if_inet6=_IF_INET6_GLOBAL)
    assert tls_capability.worker_route_gap("2001:db8::10", errno.ENETUNREACH) is None

    # Unreadable tables (not Linux) never convert a failure into an examination gap.
    monkeypatch.setattr(tls_capability, "_PROC_IF_INET6", str(tmp_path / "missing"))
    assert tls_capability.worker_route_gap("2001:db8::10", errno.ENETUNREACH) is None
    assert tls_capability.worker_route_gap("2001:db8::10", errno.EAFNOSUPPORT) == {
        "reason": "worker_address_family_unavailable",
        "address_family": "ipv6",
        "errno": "EAFNOSUPPORT",
    }


def test_scanner_tls_projection_ignores_addresses_that_were_never_contacted():
    unexamined = {
        "kind": "tls_protocol",
        "origin": "https://app.example.test",
        "server_hostname": "app.example.test",
        "pinned_address": "2001:db8::10",
        "port": 443,
        "status": "not_examined",
        "examination_gap": {"reason": "worker_route_unavailable"},
    }
    examined = {
        "kind": "tls_protocol",
        "origin": "https://app.example.test",
        "server_hostname": "app.example.test",
        "pinned_address": "192.0.2.10",
        "port": 443,
        "status": "success",
        "protocol": "TLSv1.3",
        "certificate_sha256": "a" * 64,
    }
    result = scanner_main._canonical_tls_placement_result(
        {
            "status": "success",
            "observations": [unexamined, examined],
            "budget_consumed": {"tcp_ports_attempted": 4, "tool_wall_seconds": 2},
            "receipt": {"receipt_hash": "b" * 64},
        },
        {"target_binding_digest": "c" * 64},
        host="app.example.test",
        port=443,
        scheme="https",
    )
    assert [item["ip"] for item in result["tlsx"]["endpoints"]] == ["192.0.2.10"]
    assert result["tlsx"]["certificate"]["fingerprints"] == {"sha256": "a" * 64}

    validation = scanner_main._canonical_pre_scan_validation(
        "https://app.example.test",
        {"target_binding": {"allowed_addresses": ["2001:db8::10"]}},
        {"tls.inspect": {"observations": [unexamined]}},
    )
    assert validation["connectivity"]["reachable"] is False
