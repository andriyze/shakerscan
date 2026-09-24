"""Native NSE analysis -> pinned transport -> actual wire evidence.

The dedicated CI job requires tooling; portable unit runs can skip native tooling.
All targets are ephemeral loopback fixtures, never an external acceptance target.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import socket
from types import SimpleNamespace

import pytest

from capabilities.network import NetworkExecutionAdapter, network_capability_adapter
from hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.budget_reservations import DurableBudgetReservation
from runtime.models import ScanPolicy, TargetBinding
from tests.test_hunt_nse_http import http_fixture, tls_context


def require_native(address="127.0.0.1"):
    reason = None
    if not shutil.which("nmap"):
        reason = "native nmap is not installed"
    elif ":" in address and not socket.has_ipv6:
        reason = "IPv6 loopback is unavailable"
    if reason:
        if os.environ.get("SHAKERSCAN_REQUIRE_NATIVE_NSE") == "1":
            pytest.fail(reason)
        pytest.skip(reason)


async def execute(port, scripts, *, address="127.0.0.1", allow_write=True, scheme="http"):
    target = TargetBinding("native-fixture", "device", "fixture.test", allowed_addresses=(address,),
                           allowed_origins=(f"{scheme}://fixture.test:{port}",))
    parser = network_capability_adapter("service.nse_check")
    prepared = parser.prepare(target=target, args={"ports": [port], "scripts": list(scripts)},
                              policy=ScanPolicy(active_testing=True, network_discovery=True,
                                                allow_state_changing_http=allow_write,
                                                approval_receipt_id="fixture"))
    async def runner(argv, **kwargs):
        proc = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), kwargs["hard_timeout"])
        except BaseException:
            proc.kill()
            await proc.wait()
            raise
        assert proc.returncode == 0, stderr.decode()
        return SimpleNamespace(stdout=stdout.decode(), returncode=proc.returncode, timed_out=False,
                               partial=False, stdout_truncated=False, cancelled=False)
    charges = {**prepared.estimated_budget, "active_actions": 1, "agent_actions": 1}
    reserved = DurableBudgetReservation.request(owner_kind="hunt", owner_id="native-fixture",
        capability_name="service.nse_check", amounts=charges).reserve(lease_seconds=180)
    assert dict(reserved.requested) == charges  # The worker's digest must match admission.
    running = reserved.start(worker_id="native-fixture", lease_seconds=180)
    result = await CapabilityExecutor().execute(
        CapabilityExecutionContext(CAPABILITY_REGISTRY.require("service.nse_check"), target,
                                   running.requested),
        NetworkExecutionAdapter(prepared=prepared, parser=parser, command_runner=runner,
                                max_stdout_bytes=200000, max_stderr_bytes=10000),
        heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False,
    )
    settled = running.commit(actual=result.actual_budget, execution_receipt_hash="a" * 64)
    assert settled.status == "committed" and dict(settled.actual) == dict(result.actual_budget)
    return result, prepared


@pytest.mark.parametrize("address", ["127.0.0.1", "::1"])
def test_native_nse_finds_http_methods_on_nonstandard_ipv4_and_ipv6_ports(address):
    require_native(address)
    async def run():
        def reply(method, path):
            if method not in {"HEAD", "GET", "POST", "OPTIONS"}:
                return 501, {}, b""
            return 200, {"Allow": "GET, HEAD, OPTIONS, POST"}, b""
        async with http_fixture(reply, address=address) as (port, wire):
            result, prepared = await execute(port, ("http-methods",), address=address)
            assert result.status == "success", (result.errors, result.observations)
            assert any("GET" in row["signals"].get("methods", []) for row in result.observations)
            assert result.actual_budget["http_requests"] == len(wire) == 3
            assert result.actual_budget["state_changing_requests"] == 1
            assert prepared.estimated_budget["http_requests"] > result.actual_budget["http_requests"]
            assert all(f"Host: fixture.test:{port}".encode() in data for _,_,data in wire)
    asyncio.run(run())


def test_native_method_fallback_counts_all_six_script_requests_plus_detection():
    require_native()
    async def run():
        def reply(method, path):
            return (200, {}, b"") if method in {"HEAD", "GET", "POST", "OPTIONS"} else (501, {}, b"")
        async with http_fixture(reply) as (port, wire):
            result, _ = await execute(port, ("http-methods",))
            assert result.status == "success", result.errors
            assert len(wire) == result.actual_budget["http_requests"] == 7
            assert result.actual_budget["state_changing_requests"] == 2
            assert result.actual_budget["device_fragility_points"] == 2 + len(wire)
    asyncio.run(run())


def test_native_header_redirect_keeps_other_asset_untouched_and_other_checks_work():
    require_native()
    async def run():
        async with http_fixture() as (foreign_port, foreign_wire):
            def reply(method, path):
                if method == "HEAD":
                    return 302, {"Location": f"http://foreign.test:{foreign_port}/secret"}, b""
                return 200, {"Allow": "GET, HEAD, OPTIONS, POST"}, b""
            async with http_fixture(reply) as (port, wire):
                result, _ = await execute(port, ("http-security-headers", "http-methods"))
                assert result.status == "partial" and "nse_redirect_outside_asset" in result.errors
                assert not foreign_wire
                assert any("GET" in row["signals"].get("methods", []) for row in result.observations)
                assert result.actual_budget["http_requests"] == len(wire)
    asyncio.run(run())


def test_native_header_redirect_reaches_same_asset_self_signed_https_service(tmp_path):
    require_native()
    async def run():
        async with http_fixture(lambda *_: (200, {"X-Frame-Options": "DENY"}, b""),
                                tls=tls_context(tmp_path)) as (tls_port, tls_wire):
            async with http_fixture(lambda *_: (302, {"Location": f"https://fixture.test:{tls_port}/admin"}, b"")) as (port, plain_wire):
                result, _ = await execute(port, ("http-security-headers",))
                assert result.status == "success", (result.errors, result.observations)
                rows = [row for row in result.observations if row["script_id"] == "http-security-headers"]
                assert rows and rows[0]["port"] == tls_port
                assert rows[0]["service_origin"] == f"https://fixture.test:{tls_port}"
                assert "x-frame-options" in rows[0]["signals"]["mentioned_headers"]
                assert result.actual_budget["http_requests"] == len(plain_wire) + len(tls_wire) == 3
    asyncio.run(run())


def test_native_read_only_method_check_preserves_results_instead_of_refusing():
    require_native()
    async def run():
        async with http_fixture(lambda *_: (200, {}, b"")) as (port, wire):
            result, _ = await execute(port, ("http-methods",), allow_write=False)
            assert result.status == "success" and not result.partial
            assert result.errors == ()
            gaps = result.redacted_execution["coverage_gaps"]
            assert gaps and all(gap["status"] == "not_requested" for gap in gaps)
            assert all(gap["reason"] == "nse_optional_method_not_authorized" for gap in gaps)
            assert all(m in {"GET", "HEAD", "OPTIONS"} for m,_,_ in wire)
            assert result.actual_budget["http_requests"] == len(wire) > 0
            assert result.actual_budget.get("state_changing_requests", 0) == 0
            assert any("GET" in row["signals"].get("methods", []) for row in result.observations)
    asyncio.run(run())


def test_native_tls_enumeration_still_runs_on_nonstandard_service_without_version_probes(tmp_path):
    require_native()
    async def run():
        async with http_fixture(tls=tls_context(tmp_path)) as (port, wire):
            result, prepared = await execute(port, ("ssl-enum-ciphers",), scheme="https")
            assert result.status == "success", result.errors
            assert any(row["signals"].get("tls_versions") for row in result.observations)
            assert result.actual_budget.get("http_requests", 0) == 0 and wire == []
            assert "-sV" not in prepared.commands[0].argv
    asyncio.run(run())


def test_native_trace_check_preserves_positive_result_and_request_accounting():
    require_native()
    async def run():
        def reply(method, path):
            return (200, {}, b"TRACE / HTTP/1.1\r\n") if method == "TRACE" else (200, {}, b"")
        async with http_fixture(reply) as (port, wire):
            result, _ = await execute(port, ("http-trace",))
            assert result.status == "success", (result.errors, result.observations)
            assert result.observations[0]["signals"]["trace_enabled_reported"]
            assert [m for m,_,_ in wire] == ["HEAD", "TRACE"]
            assert result.actual_budget["http_requests"] == len(wire) == 2
    asyncio.run(run())


def test_native_https_to_http_redirect_reports_final_service_not_tls_heuristic(tmp_path):
    require_native()
    async def run():
        async with http_fixture(lambda *_: (200, {"X-Frame-Options": "DENY"}, b"")) as (plain_port, plain_wire):
            async with http_fixture(lambda *_: (302, {"Location": f"http://fixture.test:{plain_port}/"}, b""),
                                    tls=tls_context(tmp_path)) as (port, tls_wire):
                result, _ = await execute(port, ("http-security-headers",), scheme="https")
                assert result.status == "success", (result.errors, result.observations)
                row = result.observations[0]
                assert row["port"] == plain_port and row["service_origin"].startswith("http://")
                assert "strict-transport-security" not in row["signals"]["missing_headers"]
                assert result.actual_budget["http_requests"] == len(plain_wire) + len(tls_wire) == 3
    asyncio.run(run())
