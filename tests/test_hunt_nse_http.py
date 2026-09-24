"""Behavioral tests of NSE HTTP's real pinned socket path and pre-write accounting."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
import socket
import ssl
import subprocess

import pytest

from capabilities.nse import NseCheckAdapter
from capabilities.nse_http_runtime import decorate_observations
from capabilities.nse_http_transport import NseHttpTransport
from runtime.models import TargetBinding


@asynccontextmanager
async def http_fixture(reply=None, *, address="127.0.0.1", tls=None):
    wire = []
    async def serve(reader, writer):
        try:
            data = await reader.readuntil(b"\r\n\r\n")
            method, path, _ = data.split(b"\r\n", 1)[0].decode().split(" ", 2)
            wire.append((method, path, data))
            status, headers, body = reply(method, path) if reply else (200, {}, b"ok")
            if status is None:
                return
            headers = {"Content-Length": str(len(body)), "Connection": "close", **headers}
            writer.write(f"HTTP/1.1 {status} Fixture\r\n".encode() +
                         b"".join(f"{k}: {v}\r\n".encode() for k,v in headers.items()) + b"\r\n" +
                         (body if method != "HEAD" else b""))
            await writer.drain()
        except (OSError, asyncio.IncompleteReadError, UnicodeError, ValueError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
    server = await asyncio.start_server(serve, address, 0, ssl=tls)
    async with server:
        yield server.sockets[0].getsockname()[1], wire


def tls_context(directory: Path) -> ssl.SSLContext:
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=wrong-host.invalid", "-keyout", str(key), "-out", str(cert)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    return context


def bridge(port, *, scripts=("http-methods",), allow_write=True, address="127.0.0.1", scheme="http"):
    target = TargetBinding("fixture", "device", "fixture.test", allowed_addresses=(address,),
                           allowed_origins=(f"{scheme}://fixture.test:{port}",))
    return NseHttpTransport(target=target, ports=(port,), scripts=scripts, allow_write=allow_write,
                           cancelled=lambda: False, heartbeat=lambda: asyncio.sleep(0))


def call(port, method="OPTIONS", script="http-methods", path="/", redirects=False):
    return dict(port=port, method=method, script=script, path=path, redirects=redirects)


def test_actual_counts_include_detection_and_optional_method_probes():
    async def run():
        async with http_fixture() as (port, wire):
            client = bridge(port)
            for method in ("OPTIONS", "ZZZZ", "GET", "HEAD", "POST", "OPTIONS"):
                assert (await client.request(call(port, method)))["status"] == 200
            assert [m for m, _, _ in wire] == ["HEAD", "OPTIONS", "ZZZZ", "GET", "HEAD", "POST", "OPTIONS"]
            assert client.actual == {"http_requests": 7, "state_changing_requests": 2}
            assert client.limits["http_requests"] == 8
            assert all(f"Host: fixture.test:{port}".encode() in data for _,_,data in wire)
    asyncio.run(run())


def test_same_asset_redirect_reaches_other_port_and_keeps_real_evidence_origin():
    async def run():
        async with http_fixture(lambda *_: (200, {"X-Frame-Options": "DENY"}, b"")) as (other, second):
            async with http_fixture(lambda *_: (302, {"Location": f"http://fixture.test:{other}/admin?token=secret-token"}, b"")) as (port, first):
                client = bridge(port, scripts=("http-security-headers",))
                response = await client.request(call(port, "HEAD", "http-security-headers", redirects=True))
                assert response["status"] == 200
                assert client.actual["http_requests"] == len(first) + len(second) == 3
                assert client.errors == []
                observation = {"port": port, "script_id": "http-security-headers", "signals": {}}
                row = decorate_observations([observation], client)[0]
                assert row["port"] == other and row["requested_port"] == port
                assert row["service_origin"] == f"http://fixture.test:{other}"
                assert "secret-token" not in str(row)
    asyncio.run(run())


def test_outside_asset_redirect_is_evidence_and_does_not_stop_other_checks():
    async def run():
        async with http_fixture() as (other, foreign):
            def reply(method, path):
                return (302, {"Location": f"http://other.test:{other}/"}, b"") if method == "HEAD" else (200, {"Allow": "GET"}, b"")
            async with http_fixture(reply) as (port, wire):
                client = bridge(port, scripts=("http-security-headers", "http-methods"))
                result = await client.request(call(port, "HEAD", "http-security-headers", redirects=True))
                assert result["status"] == 302
                assert "nse_redirect_outside_asset" in client.errors and foreign == []
                assert (await client.request(call(port)))["status"] == 200
                assert client.actual["http_requests"] == len(wire) == 3
    asyncio.run(run())


def test_read_only_authority_skips_optional_writes_but_keeps_read_checks():
    async def run():
        async with http_fixture() as (port, wire):
            client = bridge(port, allow_write=False)
            assert (await client.request(call(port, "POST")))["error"] == "nse_optional_method_not_authorized"
            assert (await client.request(call(port, "ZZZZ")))["error"] == "nse_optional_method_not_authorized"
            assert (await client.request(call(port, "GET")))["status"] == 200
            assert [m for m,_,_ in wire] == ["HEAD", "GET"]
            assert client.actual["state_changing_requests"] == 0
            assert client.errors == []
            assert {gap["method"] for gap in client.coverage_gaps} == {"POST", "ZZZZ"}
            assert all(gap["status"] == "not_requested" for gap in client.coverage_gaps)
            row = decorate_observations([{"port": port, "script_id": "http-methods"}], client)[0]
            assert row["coverage_gaps"] == client.coverage_gaps
    asyncio.run(run())


def test_budget_is_checked_before_headers_and_does_not_invent_spend():
    async def run():
        async with http_fixture() as (port, wire):
            client = bridge(port)
            client.limits["http_requests"] = 2
            assert (await client.request(call(port)))["status"] == 200
            assert (await client.request(call(port)))["error"] == "nse_http_budget_reached"
            assert len(wire) == client.actual["http_requests"] == 2
    asyncio.run(run())


def test_http_library_retry_attempts_are_all_metered():
    async def run():
        async with http_fixture(lambda m,p: (None,{},b"") if m == "GET" else (200,{},b"")) as (port,wire):
            client = bridge(port)
            result = await client.request(call(port, "GET"))
            assert result["status"] is None
            assert client.actual["http_requests"] == len(wire)
            assert len(wire) >= 2
    asyncio.run(run())


def test_cancelled_request_cannot_send_more_traffic():
    async def run():
        async with http_fixture() as (port,wire):
            client = bridge(port)
            await client.request(call(port))
            before = len(wire)
            client.cancelled = lambda: True
            with pytest.raises(asyncio.CancelledError):
                await client.request(call(port))
            assert len(wire) == before
    asyncio.run(run())


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_selected_service_transport_handles_self_signed_tls_without_prompt(tmp_path, scheme):
    async def run():
        tls = tls_context(tmp_path) if scheme == "https" else None
        async with http_fixture(tls=tls) as (port, wire):
            client = bridge(port, scheme=scheme)
            result = await client.request(call(port))
            assert result["status"] == 200 and client.errors == []
            assert len(wire) == client.actual["http_requests"] == 2
    asyncio.run(run())


def test_bridge_xml_preserves_original_script_ids_and_error_semantics():
    xml = """<nmaprun><host><address addr='127.0.0.1' addrtype='ipv4'/><ports>
    <port portid='8008' protocol='tcp'><state state='open'/><script id='nse_http'>
    <table key='http-methods'><elem key='output'>Supported Methods: GET HEAD POST OPTIONS</elem></table>
    <table key='http-trace'><elem key='output'>ERROR: Script execution failed</elem></table>
    </script></port></ports></host></nmaprun>"""
    parsed = NseCheckAdapter().parse(xml, expected_ports=(8008,), expected_scripts=("http-methods", "http-trace"))
    assert parsed.status == "partial" and len(parsed.observations) == 2
    assert parsed.observations[0]["script_id"] == "http-methods"
    assert "GET" in parsed.observations[0]["signals"]["methods"]
    assert parsed.errors == ("nse_script_failed:http-trace:8008",)


def test_native_structured_tables_keep_all_methods_and_header_signals():
    xml = """<nmaprun><host><address addr='127.0.0.1' addrtype='ipv4'/><ports>
    <port portid='8008' protocol='tcp'><state state='open'/><script id='nse_http'>
    <table key='http-methods'><table key='Supported Methods'><elem>GET</elem><elem>HEAD</elem>
    <elem>OPTIONS</elem><elem>POST</elem></table></table>
    <table key='http-security-headers'><table key='X_Frame_Options'>
    <elem>Header: X-Frame-Options: DENY</elem></table></table>
    </script></port></ports></host></nmaprun>"""
    parsed = NseCheckAdapter().parse(xml, expected_ports=(8008,),
                                     expected_scripts=("http-methods", "http-security-headers"))
    assert parsed.status == "succeeded" and not parsed.errors
    assert parsed.observations[0]["signals"]["methods"] == ["GET", "HEAD", "OPTIONS", "POST"]
    assert parsed.observations[1]["signals"]["mentioned_headers"] == ["x-frame-options"]


def test_skipped_optional_method_does_not_send_detection_traffic_or_consume_budget():
    async def run():
        async with http_fixture() as (port, wire):
            client = bridge(port, allow_write=False)
            for _ in range(2):
                assert (await client.request(call(port, "POST")))["skipped"] is True
            assert wire == [] and client.exchanges == []
            assert client.actual == {"http_requests": 0, "state_changing_requests": 0}
            assert len(client.coverage_gaps) == 1 and client.errors == []
    asyncio.run(run())


def test_anonymous_redirect_exception_does_not_accept_credentials_or_mutate_binding():
    async def run():
        async with http_fixture() as (other, final_wire):
            async with http_fixture(lambda *_: (302, {"Location": f"http://fixture.test:{other}/"}, b"")) as (port, _):
                client = bridge(port, scripts=("http-security-headers",))
                before = client.target
                response = await client.request({**call(port, "HEAD", "http-security-headers", redirects=True),
                                                 "headers": {"Authorization": "Bearer never-send-this"}})
                assert response["status"] == 200 and final_wire
                assert client.target == before
                assert not any(b"Authorization:" in raw or b"never-send-this" in raw for _, _, raw in final_wire)
    asyncio.run(run())
