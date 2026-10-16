"""Legacy protocol / weak suite support is probed with raw ClientHello messages."""

from __future__ import annotations

import asyncio
import datetime
import ssl
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from api.capabilities import tls_legacy_probe as probe
from api.capabilities.tls import inspect_tls_origin
from api.finding_detail import build_finding_detail
from api.runtime.models import TargetBinding
from api.scan.capability_execution import TLS_CONNECTIONS_PER_PAIR
from api.scan.severity_calibration import calibrate_finding
from api.scan.finding_evidence import tls_finding_evidence

HOST = "legacy.example.test"


def _certificate() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(7).not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=200))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


CERT = _certificate()


def _server_answer(hello: bytes, *, versions: set[int], suites: set[int]) -> bytes:
    """A legacy server: answers a ClientHello with ServerHello+Certificate+Done or an alert."""
    body = hello[9:]
    offered_version = struct.unpack("!H", body[0:2])[0]
    sid = body[34]
    cursor = 35 + sid
    length = struct.unpack("!H", body[cursor:cursor + 2])[0]
    offered = [struct.unpack("!H", body[cursor + 2 + i:cursor + 4 + i])[0] for i in range(0, length, 2)]
    chosen_version = max((v for v in versions if v <= offered_version), default=None)
    chosen_suite = next((code for code in offered if code in suites), None)
    if chosen_version is None:
        return b"\x15\x03\x01\x00\x02\x02\x46"  # protocol_version
    if chosen_suite is None:
        return b"\x15\x03\x01\x00\x02\x02\x28"  # handshake_failure
    hello_body = struct.pack("!H", chosen_version) + b"\x11" * 32 + b"\x00" + struct.pack("!H", chosen_suite) + b"\x00"
    cert_list = len(CERT).to_bytes(3, "big") + CERT
    cert_body = len(cert_list).to_bytes(3, "big") + cert_list
    messages = (
        b"\x02" + len(hello_body).to_bytes(3, "big") + hello_body
        + b"\x0b" + len(cert_body).to_bytes(3, "big") + cert_body
        + b"\x0e\x00\x00\x00"
    )
    return b"\x16" + struct.pack("!HH", chosen_version, len(messages)) + messages


class _Reader:
    def __init__(self, writer):
        self.writer = writer
        self.sent = False

    async def read(self, _limit):
        if self.sent:
            return b""
        self.sent = True
        return self.writer.answer()


class _Writer:
    def __init__(self, versions, suites):
        self.versions, self.suites, self.data = versions, suites, b""

    def write(self, data):
        self.data += data

    async def drain(self):
        return None

    def answer(self):
        return _server_answer(self.data, versions=self.versions, suites=self.suites)

    def close(self):
        return None

    async def wait_closed(self):
        return None


def _legacy_server(monkeypatch, *, versions, suites):
    calls = {"tls": 0, "raw": 0}

    async def fake_open_connection(**kwargs):
        if kwargs.get("ssl") is not None:
            # The worker's TLS library cannot offer what this server requires.
            calls["tls"] += 1
            raise ssl.SSLError(1, "[SSL: UNSUPPORTED_PROTOCOL] unsupported protocol")
        calls["raw"] += 1
        writer = _Writer(versions, suites)
        return _Reader(writer), writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    return calls


def _target() -> TargetBinding:
    return TargetBinding(
        target_id="target-1", target_kind="web", canonical_host=HOST,
        allowed_origins=(f"https://{HOST}",), allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
    )


def test_client_hello_offers_exactly_the_version_and_suites_under_test():
    hello = probe.client_hello(probe.TLS11, (0x000A, 0x0005), HOST, random=b"\x00" * 32)
    assert hello[0] == 0x16 and hello[5] == 1
    assert struct.unpack("!H", hello[9:11])[0] == probe.TLS11
    assert hello[44:50] == b"\x00\x04\x00\x0a\x00\x05"
    assert HOST.encode() in hello
    # A literal address is never sent as SNI.
    assert b"192.0.2.10" not in probe.client_hello(probe.TLS10, (0x000A,), "192.0.2.10")


def test_server_flight_parsing_accepts_only_what_was_offered():
    answer = _server_answer(probe.client_hello(probe.TLS10, (0x000A,), HOST), versions={probe.TLS10}, suites={0x000A})
    flight = probe.parse_server_flight(answer, offered_version=probe.TLS10, offered_suites=(0x000A,))
    assert (flight.outcome, flight.version, flight.suite, flight.complete) == ("accepted", probe.TLS10, 0x000A, True)
    assert flight.certificates == [CERT]
    # A suite that was not offered, an older version than the one under test, and an alert.
    assert probe.parse_server_flight(answer, offered_version=probe.TLS10, offered_suites=(0x0005,)).outcome == "invalid"
    assert probe.parse_server_flight(answer, offered_version=probe.TLS11, offered_suites=(0x000A,)).outcome == "refused"
    alert = probe.parse_server_flight(b"\x15\x03\x01\x00\x02\x02\x28", offered_version=probe.TLS12, offered_suites=(0x000A,))
    assert (alert.outcome, alert.alert) == ("refused", 40)
    assert probe.parse_server_flight(b"HTTP/1.1 400 Bad Request\r\n", offered_version=probe.TLS12, offered_suites=(1,)).outcome == "invalid"
    # Truncated and hostile lengths never raise.
    assert probe.parse_server_flight(answer[:20], offered_version=probe.TLS10, offered_suites=(0x000A,)).outcome in {"invalid", "no_answer"}
    assert probe.parse_server_flight(b"\x16\x03\x01\xff\xff" + b"\x00" * 10, offered_version=probe.TLS10, offered_suites=(1,)).outcome != "accepted"


def test_a_server_that_speaks_only_tls10_with_3des_is_examined_not_failed(monkeypatch):
    calls = _legacy_server(monkeypatch, versions={probe.TLS10}, suites={0x000A})
    result = asyncio.run(inspect_tls_origin(f"https://{HOST}", target=_target(), timeout_seconds=15))

    assert result["ok"] is True and result["status"] == "success"
    observation = result["observation"]
    assert observation["examined_by"] == "raw_client_hello"
    assert observation["protocol"] == "TLSv1"
    assert observation["cipher"] == "DES-CBC3-SHA"
    assert observation["legacy_protocols_supported"] == ["TLSv1"]
    assert observation["weak_ciphers_supported"] == ["DES-CBC3-SHA"]
    assert observation["legacy_protocol_negotiated"] is True and observation["weak_cipher"] is True
    assert observation["certificate_trust"] == "not_evaluated"
    assert observation["certificate_trust_error_type"] == "legacy_handshake_only"
    assert observation["certificate_hostname_matches"] is True
    assert calls["raw"] == probe.PROBE_COUNT
    assert result["budget_consumed"]["tcp_ports_attempted"] == calls["tls"] + calls["raw"] <= TLS_CONNECTIONS_PER_PAIR


def test_a_modern_server_that_still_accepts_tls11_and_rc4_reports_both(monkeypatch):
    _legacy_server(monkeypatch, versions={probe.TLS11, probe.TLS12}, suites={0xC02F, 0x0005, 0x000A})
    result = asyncio.run(inspect_tls_origin(f"https://{HOST}", target=_target(), timeout_seconds=15))
    observation = result["observation"]
    assert observation["legacy_protocols_supported"] == ["TLSv1.1"]
    # Worst first: RC4 before 3DES.
    assert observation["weak_ciphers_supported"] == ["RC4-SHA", "DES-CBC3-SHA"]
    rows = {row["protocol"]: row for row in observation["legacy_protocol_probes"]}
    assert rows["SSLv3"]["supported"] is False and rows["TLSv1"]["result"] == "refused"


def _finding(observation, check):
    evidence = {
        "check": check, "origin": observation["origin"], "protocol": observation["protocol"],
        "cipher": observation["cipher"], "port": observation["port"], "pinned_address": observation["pinned_address"],
        **tls_finding_evidence(observation, [observation], check=check),
    }
    finding = {"tool": "tls.inspect", "severity": "high", "url": observation["origin"], "evidence": evidence,
               "proof_state": "verified", "verified": True,
               "title": "Weak TLS cipher negotiated" if check == "tls_weak_cipher" else "Legacy TLS protocol negotiated"}
    return calibrate_finding(finding)


def test_findings_name_the_accepted_legacy_versions_and_weakest_suite_with_a_reason(monkeypatch):
    _legacy_server(monkeypatch, versions={probe.TLS10, probe.TLS12}, suites={0xC02F, 0x0005})
    observation = asyncio.run(inspect_tls_origin(f"https://{HOST}", target=_target(), timeout_seconds=15))["observation"]
    weak = _finding(observation, "tls_weak_cipher")
    assert weak["evidence"]["cipher"] == "RC4-SHA" and weak["severity"] == "medium"
    assert "weak cipher suite" in weak["evidence"]["severity_basis"]["reason"]
    brief = build_finding_detail(weak)
    assert "RC4-SHA" in brief["summary"]
    assert brief["reproduce"]["command"].startswith("nmap --script ssl-enum-ciphers")
    legacy = _finding(observation, "tls_legacy_protocol")
    assert legacy["severity"] == "medium"
    brief = build_finding_detail(legacy)
    assert "TLSv1" in brief["summary"] and brief["observed"][0]["value"] == "TLSv1"


def test_sslv3_and_export_suites_rate_high():
    _ = probe  # the rule reads only the evidence
    sslv3 = calibrate_finding({"tool": "tls.inspect", "severity": "high", "evidence": {
        "check": "tls_legacy_protocol", "legacy_protocols_supported": ["SSLv3", "TLSv1"]}})
    assert sslv3["severity"] == "high"
    export = calibrate_finding({"tool": "tls.inspect", "severity": "high", "evidence": {
        "check": "tls_weak_cipher", "cipher": "EXP-RC4-MD5"}})
    assert export["severity"] == "high"
