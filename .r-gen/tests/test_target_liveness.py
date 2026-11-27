"""Target liveness checks against real local sockets, including hostile servers.

Unit fixtures: every server below is a local asyncio server on 127.0.0.1 started by the test.
The destination policy refuses loopback, so the tests that need traffic replace the policy
predicate for 127.0.0.1 only; ``test_loopback_is_never_contacted`` checks the real policy.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
import socket
import tempfile
import ssl
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import pytest

from api.targets import liveness as lv

SECRET = "Set-Cookie: session=hunter2-do-not-store"


def _plan(ports, host="127.0.0.1", environment="production", **kwargs):
    return lv.CheckPlan(target_id=uuid.uuid4(), host=host, environment=environment,
                        ports=[lv.PortPlan(port, mode) for port, mode in ports], **kwargs)


@pytest.fixture
def admit_loopback(monkeypatch):
    real = lv.target_resolution.policy_admits

    def policy(environment):
        admit = real(environment)
        return lambda address: address == "127.0.0.1" or admit(address)
    monkeypatch.setattr(lv.target_resolution, "policy_admits", policy)


class Server:
    """One local TCP server whose behaviour is a coroutine ``handle(reader, writer)``."""

    def __init__(self, handle, ssl_context=None):
        self.handle, self.ssl_context, self.connections = handle, ssl_context, 0
        self.requests: list[bytes] = []

    async def __aenter__(self):
        async def serve(reader, writer):
            self.connections += 1
            try:
                await self.handle(self, reader, writer)
            except (ConnectionError, ssl.SSLError, asyncio.IncompleteReadError):
                pass
            finally:
                writer.close()
        self.server = await asyncio.start_server(serve, "127.0.0.1", 0, ssl=self.ssl_context)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        self.server.close()
        await self.server.wait_closed()


async def _read_request(server, reader):
    data = await reader.readuntil(b"\r\n\r\n")
    server.requests.append(data)
    return data


def _http(status_line: bytes, extra: bytes = b""):
    async def handle(server, reader, writer):
        await _read_request(server, reader)
        writer.write(status_line + b"\r\n" + SECRET.encode() + b"\r\nContent-Length: 4\r\n" + extra + b"\r\nbody")
        await writer.drain()
    return handle


def _tls_context():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "liveness.fixture.invalid")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30)).sign(key, hashes.SHA256()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with tempfile.TemporaryDirectory() as folder:
        cert_path, key_path = os.path.join(folder, "c.pem"), os.path.join(folder, "k.pem")
        with open(cert_path, "wb") as handle:
            handle.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as handle:
            handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        context.load_cert_chain(cert_path, key_path)
    return context


def _closed_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def run(coro):
    return asyncio.run(coro)


def test_http_answer_is_live_and_only_the_status_is_kept(admit_loopback):
    async def go():
        async with Server(_http(b"HTTP/1.1 503 Service Unavailable")) as server:
            result = await lv.run_check(_plan([(server.port, "http")]))
            return result, server
    result, server = run(go())
    assert result["status"] == lv.LIVE and result["dns"] == "resolves"
    assert result["reachable"] is True and result["live"] is True and result["reason"] is None
    assert result["ports"] == [{"port": server.port, "mode": "http", "address": "127.0.0.1", "tcp": "open",
                                "answered": True, "http_status": 503}]
    assert "hunter2" not in json.dumps(result)
    # One GET /, no body, no credentials, the liveness agent named.
    assert len(server.requests) == 1
    request = server.requests[0].decode()
    assert request.startswith("GET / HTTP/1.1\r\n") and "User-Agent: ShakerScan-Liveness/1" in request
    assert "Cookie" not in request and "Authorization" not in request


def test_redirect_is_live_and_not_followed(admit_loopback):
    async def go():
        async with Server(_http(b"HTTP/1.1 302 Found", b"Location: http://169.254.169.254/latest\r\n")) as server:
            return await lv.run_check(_plan([(server.port, "http")])), server
    result, server = run(go())
    assert result["status"] == lv.LIVE and result["ports"][0]["http_status"] == 302
    assert server.connections == 1


def test_tls_service_is_live_without_trusting_its_certificate(admit_loopback):
    async def go():
        async with Server(_http(b"HTTP/1.1 200 OK"), ssl_context=_tls_context()) as server:
            return await lv.run_check(_plan([(server.port, "https")]))
    result = run(go())
    assert result["status"] == lv.LIVE and result["ports"][0]["http_status"] == 200


def test_plain_service_on_a_tls_port_is_reachable_not_live(admit_loopback):
    async def go():
        async with Server(_http(b"HTTP/1.1 200 OK")) as server:
            return await lv.run_check(_plan([(server.port, "https")])), server.port
    result, port = run(go())
    assert result["status"] == lv.REACHABLE and result["live"] is False and result["reachable"] is True
    assert result["ports"][0]["note"] == "tls_failed"
    assert result["reason"] == f"port {port}: connected, TLS handshake failed"


def test_silent_service_is_reachable_within_the_answer_budget(admit_loopback, monkeypatch):
    monkeypatch.setattr(lv, "ANSWER_TIMEOUT_SECONDS", 0.3)

    async def silent(server, reader, writer):
        await asyncio.sleep(5)

    async def go():
        async with Server(silent) as server:
            started = asyncio.get_running_loop().time()
            result = await lv.run_check(_plan([(server.port, "http")]))
            return result, asyncio.get_running_loop().time() - started
    result, elapsed = run(go())
    assert result["status"] == lv.REACHABLE and result["ports"][0]["note"] == "no_answer"
    assert elapsed < 2


def test_endless_garbage_is_read_to_the_limit_only(admit_loopback):
    async def flood(server, reader, writer):
        await _read_request(server, reader)
        for _ in range(200):
            writer.write(b"A" * 65536)
            await writer.drain()

    async def go():
        async with Server(flood) as server:
            return await lv.run_check(_plan([(server.port, "http")]))
    result = run(go())
    assert result["status"] == lv.REACHABLE and result["ports"][0]["note"] == "not_http"
    assert "AAAA" not in json.dumps(result)


def test_status_line_lookalikes_are_not_http(admit_loopback):
    async def go(line):
        async with Server(_http(line)) as server:
            return await lv.run_check(_plan([(server.port, "http")]))
    for line in (b"HTTP/1.1 999 Nope", b"SSH-2.0-OpenSSH_9.6", b"HTTP/1.1 20 Short", b"<html>HTTP/1.1 200 OK"):
        assert run(go(line))["status"] == lv.REACHABLE, line


def test_banner_port_is_live_and_the_banner_is_not_stored(admit_loopback):
    async def banner(server, reader, writer):
        writer.write(b"SSH-2.0-SecretBuild_" + SECRET.encode() + b"\r\n")
        await writer.drain()
        await asyncio.sleep(0.2)

    async def go():
        async with Server(banner) as server:
            return await lv.run_check(_plan([(server.port, "tcp")])), server
    result, server = run(go())
    assert result["status"] == lv.LIVE and result["ports"][0]["answered"] is True
    assert "SecretBuild" not in json.dumps(result) and not server.requests


def test_refused_port_is_unreachable_with_the_reason(admit_loopback):
    port = _closed_port()
    result = run(lv.run_check(_plan([(port, "http")])))
    assert result["status"] == lv.UNREACHABLE and result["reachable"] is False and result["live"] is False
    assert result["reason"] == f"port {port}: connection refused"


def test_loopback_is_never_contacted():
    async def go():
        async with Server(_http(b"HTTP/1.1 200 OK")) as server:
            return await lv.run_check(_plan([(server.port, "http")])), server
    result, server = run(go())
    assert result["status"] == lv.BLOCKED and server.connections == 0
    assert "outside the destination policy" in result["reason"]


@pytest.mark.parametrize("private, expected", [("refuse", ["93.184.216.34"]), ("allow", ["10.0.0.5", "93.184.216.34"])])
def test_mixed_answer_connects_only_to_admitted_addresses(monkeypatch, private, expected):
    """The cloud metadata address is never contacted; private ranges follow the deployment's
    private-network setting, as Scan admission does."""
    monkeypatch.setenv("SHAKERSCAN_PRIVATE_NETWORK_TARGETS", private)

    async def lookup(host):
        return ["10.0.0.5", "169.254.169.254", "93.184.216.34"]
    tried = []

    async def fake_open(address, port, **kwargs):
        tried.append(address)
        raise ConnectionRefusedError()
    monkeypatch.setattr(lv.asyncio, "open_connection", fake_open)
    result = run(lv.run_check(_plan([(443, "https")], host="app.fixture.invalid"), lookup=lookup))
    assert tried == expected
    assert result["status"] == lv.UNREACHABLE
    assert sorted(result["addresses"]) == sorted(["10.0.0.5", "169.254.169.254", "93.184.216.34"])


def test_dns_outcomes(monkeypatch):
    async def no_record(host):
        raise socket.gaierror(socket.EAI_NONAME, "no")

    async def hangs(host):
        await asyncio.sleep(10)

    async def failing(host):
        raise socket.gaierror(socket.EAI_AGAIN, "temporary")
    plan = _plan([(443, "https")], host="gone.fixture.invalid")
    assert run(lv.run_check(plan, lookup=no_record))["status"] == lv.NO_DNS
    assert run(lv.run_check(plan, lookup=no_record))["dns"] == "no_record"
    assert run(lv.run_check(plan, lookup=failing))["status"] == lv.DNS_ERROR
    monkeypatch.setattr(lv, "DNS_TIMEOUT_SECONDS", 0.2)
    result = run(lv.run_check(plan, lookup=hangs))
    assert result["status"] == lv.DNS_ERROR and result["dns"] == "error"
    assert result["reachable"] is None and result["live"] is None


def test_blocked_and_archived_targets_send_nothing(monkeypatch):
    async def lookup(host):
        raise AssertionError("no lookup for a target that may not be checked")
    blocked = _plan([(443, "https")], host="x.fixture.invalid", blocked_reason="the target's scope is blocked")
    assert run(lv.run_check(blocked, lookup=lookup))["status"] == lv.BLOCKED
    archived = _plan([(443, "https")], host="x.fixture.invalid", inactive=True)
    assert run(lv.run_check(archived, lookup=lookup))["reason"] == "the target is archived"


def test_whole_check_has_a_deadline(monkeypatch):
    monkeypatch.setattr(lv, "CHECK_TIMEOUT_SECONDS", 0.2)

    async def slow(plan, lookup=None):
        await asyncio.sleep(5)
    monkeypatch.setattr(lv, "run_check", slow)
    result = run(lv.check_with_deadline(_plan([(80, "http")])))
    assert result["status"] == lv.UNREACHABLE and "did not finish" in result["reason"]


def test_port_choice():
    choose = lv.choose_ports
    assert [(p.port, p.mode) for p in choose(["https://a.example", "http://a.example:8081"], [22], [])] == [
        (443, "https"), (8081, "http"), (22, "tcp")]
    assert [(p.port, p.mode) for p in choose([], [], [])] == [(443, "https"), (80, "http")]
    assert [(p.port, p.mode) for p in choose(["host://a.example"], [8443, "80", 0, 70000], [
        {"port": 5432, "service_name": "postgresql"}, {"port": 9000, "service_name": "http"}])] == [
        (8443, "https"), (5432, "tcp"), (9000, "http")]
    many = choose([f"https://a.example:{port}" for port in range(8000, 8010)], [], [])
    assert len(many) == lv.MAX_PORTS


def test_public_liveness_defaults_to_unchecked():
    assert lv.public_liveness({})["status"] == lv.UNCHECKED
    assert lv.public_liveness({"liveness_status": "bogus"})["status"] == lv.UNCHECKED
    row = {"liveness_status": "live", "liveness_ports": '[{"port": 443}]', "liveness_addresses": None}
    assert lv.public_liveness(row)["ports"] == [{"port": 443}] and lv.public_liveness(row)["addresses"] == []
