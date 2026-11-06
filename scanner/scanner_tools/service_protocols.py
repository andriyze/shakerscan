"""Bounded native protocol adapters: which protocol answers on a port, never which port it is.

Each adapter sends at most a few fixed, read-only bytes to one already-authorized address and
parses the reply into ``service_identity`` fields: protocol, product, version (with the exact
reported build string) and authentication. The rules every adapter follows:

* The port number only chooses which adapter is tried first. Identity comes from a parsed
  reply; a fake service on a familiar port stays unidentified, and a real service on an unusual
  port is recognised by its handshake.
* A handshake is protocol identity, never access proof. ``authentication`` stays
  ``not_tested`` unless a bounded read-only command the server executed (or refused) decides it,
  and then ``authentication_proof`` names that exchange with a fixed code.
* Silence is inconclusive. A protocol that is silent by design (WireGuard) is reported as not
  identifiable rather than confirmed.
* Every read is bounded in bytes and time, and every value from the target is untrusted: labels
  are bounded and stripped of control characters, and no raw response is kept beyond a short
  printable excerpt of an unidentified banner.
* No credentials are sent and no login is attempted.
* Printer raw ports (TCP 9100-9107) receive no payload: a printer prints whatever arrives, which
  is why Nmap excludes them from version detection too.
"""

from __future__ import annotations

import asyncio
import contextvars
import os
import re
import socket
import ssl
import struct
import time
import warnings
from typing import Any, Awaitable, Callable, Mapping

try:
    from . import service_identity as si
except ImportError:  # flat scanner runtime
    import service_identity as si  # type: ignore[no-redef]

CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 3.0
BANNER_WAIT = 2.5
MAX_READ_BYTES = 16_384
EXCERPT_LIMIT = 120
USER_AGENT = "ShakerScan-Service/1"
# Nmap's own exclusion (nmap-service-probes "Exclude T:9100-9107"): raw printer ports print
# every byte they receive, so they are only connected to, never sent a payload.
PAYLOAD_EXCLUDED_TCP_PORTS = frozenset(range(9100, 9108))
PAYLOAD_EXCLUSION_REASON = "printer_raw_port_payloads_excluded"
# Adapters tried on a listener that says nothing first, after the hinted one. Ordered so the
# cheapest, most common silent protocols come first.
SILENT_TCP_ADAPTERS = (
    "http", "tls", "redis", "memcached", "mongodb", "postgresql", "rdp", "smb",
    "openvpn", "pptp", "mqtt", "amqp",
)
# Industrial protocols are only offered when Nmap or the port names them: an unknown listener
# never receives a fieldbus request.
HINT_ONLY_TCP_ADAPTERS = ("mqtts", "modbus", "enip")
UDP_ADAPTERS = ("dns", "ntp", "ike", "openvpn")
# Service names (Nmap's or the port hint's) mapped to the adapter that can confirm them.
ADAPTER_FOR_SERVICE = {
    "ssh": "banner", "ftp": "banner", "smtp": "banner", "submission": "banner",
    "smtps": "tls", "pop3": "banner", "imap": "banner", "telnet": "banner",
    "mysql": "banner", "vnc": "banner", "http": "http", "http-proxy": "http",
    "https": "tls", "https-alt": "tls", "ssl": "tls", "elasticsearch": "http",
    "redis": "redis", "memcached": "memcached", "memcache": "memcached",
    "mongodb": "mongodb", "mongod": "mongodb", "postgresql": "postgresql", "postgres": "postgresql",
    "rdp": "rdp", "ms-wbt-server": "rdp", "smb": "smb", "microsoft-ds": "smb",
    "netbios-ssn": "smb", "openvpn": "openvpn", "pptp": "pptp",
    "dns": "dns", "domain": "dns", "ntp": "ntp", "ike": "ike", "isakmp": "ike",
    "wireguard": "wireguard", "mqtt": "mqtt", "secure-mqtt": "mqtts", "mqtts": "mqtts",
    "amqp": "amqp", "amqps": "tls", "modbus": "modbus", "mbap": "modbus",
    "ethernetip": "enip", "enip": "enip", "ethernet-ip": "enip",
}

Reader = Callable[..., Awaitable[Any]]
# The first bytes any adapter received while identifying one port: an adapter that did not
# recognise an answer returns None, and this tells "it answered something else" from silence.
_ANSWERS: contextvars.ContextVar[list[bytes] | None] = contextvars.ContextVar("service_answers", default=None)


def _result(
    port: int, transport: str, status: str, *, protocol: str | None = None,
    adapter: str | None = None, **fields: Any,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "schema_version": si.SCHEMA_VERSION,
        "transport": transport,
        "port": int(port),
        "status": status,
        "protocol": protocol,
        "product": None,
        "version": None,
        "version_reported": None,
        "version_basis": None,
        "authentication": si.AUTH_NOT_TESTED,
        "authentication_proof": None,
        "port_hint": si.port_hint(port),
        "adapter": adapter,
        "details": {},
    }
    row.update({key: value for key, value in fields.items() if value is not None})
    if row.get("version") and row.get("version_basis") is None:
        row["version_basis"] = si.VERSION_REPORTED
    return row


def _identified(port: int, transport: str, protocol: str, adapter: str, /, **fields: Any) -> dict[str, Any]:
    fields.pop("protocol", None)
    details = dict(fields.pop("details", None) or {})
    return _result(port, transport, si.STATUS_IDENTIFIED, protocol=protocol, adapter=adapter,
                   details=details, **fields)


def excerpt(data: bytes | None) -> str | None:
    """A short printable excerpt of an unidentified answer (never a whole response)."""
    if not data:
        return None
    text = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in data[:EXCERPT_LIMIT].decode("latin-1"))
    return text.strip(".") or None


# ---------------------------------------------------------------------------
# Transport helpers (one connection each, bounded reads)
# ---------------------------------------------------------------------------

def _tls_context() -> ssl.SSLContext:
    # Identification only: the certificate is not trusted for anything here.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        # Old TLS versions are deprecated for trust, not for recognising an old server.
        warnings.simplefilter("ignore", DeprecationWarning)
        context.minimum_version = ssl.TLSVersion.TLSv1
    try:
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:  # pragma: no cover - OpenSSL builds without SECLEVEL
        pass
    return context


class _Connection:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.received = 0

    async def send(self, payload: bytes) -> bool:
        """Send, or report that the peer has gone: a follow-up exchange on a connection the
        server closed must not discard what its first answer already identified."""
        try:
            self.writer.write(payload)
            await asyncio.wait_for(self.writer.drain(), READ_TIMEOUT)
        except (OSError, ConnectionError, TimeoutError, asyncio.TimeoutError, RuntimeError):
            return False
        return True

    async def read(
        self, *, timeout: float = READ_TIMEOUT, limit: int = MAX_READ_BYTES,
        until: Callable[[bytes], bool] | None = None,
    ) -> bytes:
        """Read until ``until`` holds, the peer closes, ``limit`` bytes or ``timeout``."""
        buffer = b""
        deadline = time.monotonic() + timeout
        while len(buffer) < limit and self.received < MAX_READ_BYTES * 4:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                chunk = await asyncio.wait_for(self.reader.read(limit - len(buffer)), remaining)
            except (TimeoutError, asyncio.TimeoutError):
                break
            except (ConnectionError, OSError, ssl.SSLError):
                break
            if not chunk:
                break
            buffer += chunk
            self.received += len(chunk)
            answers = _ANSWERS.get()
            if answers is not None and not answers:
                answers.append(bytes(chunk[:EXCERPT_LIMIT]))
            if until is not None and until(buffer):
                break
        return buffer

    async def start_tls(self, server_name: str | None) -> dict[str, Any] | None:
        try:
            await asyncio.wait_for(
                self.writer.start_tls(_tls_context(), server_hostname=server_name or None),
                READ_TIMEOUT * 2,
            )
        except (TimeoutError, asyncio.TimeoutError, ssl.SSLError, OSError, ConnectionError, ValueError):
            return None
        return _tls_details(self.writer)

    async def close(self) -> None:
        try:
            self.writer.close()
            await asyncio.wait_for(self.writer.wait_closed(), 1.0)
        except Exception:  # noqa: BLE001 - closing a probe socket never fails the probe
            pass


def _tls_details(writer: asyncio.StreamWriter) -> dict[str, Any]:
    ssl_object = writer.get_extra_info("ssl_object")
    if ssl_object is None:
        return {}
    cipher = ssl_object.cipher() or (None, None, None)
    return {"tls_version": ssl_object.version(), "tls_cipher": cipher[0]}


async def _connect(
    address: str, port: int, *, tls: bool = False, server_name: str | None = None,
    timeout: float = CONNECT_TIMEOUT,
) -> _Connection | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                address, port,
                ssl=_tls_context() if tls else None,
                server_hostname=(server_name or None) if tls else None,
                limit=MAX_READ_BYTES,
            ),
            timeout,
        )
    except (TimeoutError, asyncio.TimeoutError, OSError, ConnectionError, ssl.SSLError, ValueError):
        return None
    return _Connection(reader, writer)


class _Datagram(asyncio.DatagramProtocol):
    def __init__(self, address: str) -> None:
        self.address = address
        self.replies: list[bytes] = []
        self.event = asyncio.Event()

    def datagram_received(self, data: bytes, addr: tuple[Any, ...]) -> None:
        # Only the probed address may answer; anything else is ignored.
        if str(addr[0]).split("%", 1)[0] != self.address or len(self.replies) >= 4:
            return
        self.replies.append(bytes(data[:MAX_READ_BYTES]))
        self.event.set()

    def error_received(self, exc: Exception) -> None:  # ICMP unreachable and similar
        self.event.set()


async def _udp_exchange(address: str, port: int, payload: bytes, *, timeout: float = READ_TIMEOUT) -> bytes | None:
    loop = asyncio.get_running_loop()
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    try:
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _Datagram(address), remote_addr=(address, port), family=family,
        )
    except OSError:
        return None
    try:
        transport.sendto(payload)
        try:
            await asyncio.wait_for(protocol.event.wait(), timeout)
        except (TimeoutError, asyncio.TimeoutError):
            pass
        return protocol.replies[0] if protocol.replies else None
    finally:
        transport.close()


# ---------------------------------------------------------------------------
# Pure parsers (bytes in, identity fields out); tested without a network
# ---------------------------------------------------------------------------

_SSH = re.compile(rb"^SSH-(\d+\.\d+)-([\x21-\x7e]{1,200})(?:[ \t]([\x20-\x7e]{0,200}))?\r?\n")
_SSH_PRODUCTS = (
    (re.compile(r"^OpenSSH_([0-9][0-9A-Za-z.]*)"), "OpenSSH"),
    (re.compile(r"^dropbear_([0-9][0-9.]*)", re.I), "Dropbear SSH"),
    (re.compile(r"^libssh[_-]([0-9][0-9.]*)", re.I), "libssh"),
    (re.compile(r"^Cisco-([0-9][0-9.]*)"), "Cisco SSH"),
    (re.compile(r"^ROSSSH"), "MikroTik RouterOS SSH"),
    (re.compile(r"^AsyncSSH_([0-9][0-9.]*)"), "AsyncSSH"),
    (re.compile(r"^paramiko_([0-9][0-9.]*)"), "Paramiko"),
)


def parse_ssh_banner(data: bytes) -> dict[str, Any] | None:
    """``SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`` -> OpenSSH 8.9p1, reported string kept."""
    match = _SSH.match(data or b"")
    if not match:
        return None
    software = match.group(2).decode("ascii")
    comment = (match.group(3) or b"").decode("ascii").strip()
    reported = f"{software} {comment}".strip()
    product = version = None
    for pattern, name in _SSH_PRODUCTS:
        found = pattern.match(software)
        if found:
            product = name
            version = found.group(1) if found.groups() else None
            break
    return {
        "protocol": "ssh", "product": product, "version": version,
        "version_reported": reported,
        "details": {"protocol_version": match.group(1).decode("ascii")},
    }


def parse_mysql_greeting(data: bytes) -> dict[str, Any] | None:
    """A MySQL/MariaDB initial handshake (protocol 10) or its pre-handshake error packet."""
    if len(data or b"") < 5:
        return None
    length = int.from_bytes(data[0:3], "little")
    if data[3] != 0 or length < 2 or length > 4096 or len(data) < 4 + length:
        return None
    payload = data[4:4 + length]
    if payload[0] == 0xFF and len(payload) >= 3:
        code = int.from_bytes(payload[1:3], "little")
        # 1040 too many connections, 1129 host blocked, 1130 host not allowed.
        if code in {1040, 1129, 1130}:
            return {"protocol": "mysql", "details": {"handshake_error_code": code}}
        return None
    if payload[0] != 0x0A:
        return None
    end = payload.find(b"\x00", 1)
    if end <= 1 or end > 120:
        return None
    reported = payload[1:end]
    if not re.fullmatch(rb"[0-9]+\.[0-9]+\.[0-9]+[\x20-\x7e]*", reported):
        return None
    text = reported.decode("ascii")
    product = "MySQL"
    upstream = text
    maria = re.match(r"^(?:5\.5\.5-)?([0-9]+\.[0-9]+\.[0-9]+)-MariaDB", text)
    if maria:
        product, upstream = "MariaDB", maria.group(1)
    else:
        upstream = re.match(r"^([0-9]+\.[0-9]+\.[0-9]+)", text).group(1)
    return {"protocol": "mysql", "product": product, "version": upstream, "version_reported": text}


def parse_vnc_banner(data: bytes) -> dict[str, Any] | None:
    match = re.match(rb"^RFB (\d{3})\.(\d{3})\n", data or b"")
    if not match:
        return None
    return {"protocol": "vnc", "details": {
        "protocol_version": f"{int(match.group(1))}.{int(match.group(2))}",
    }}


_SMTP_PRODUCTS = (
    (re.compile(r"\bExim ([0-9]+\.[0-9]+(?:\.[0-9]+)?)"), "Exim"),
    (re.compile(r"\bSendmail ([0-9]+\.[0-9]+\.[0-9]+)"), "Sendmail"),
    (re.compile(r"Microsoft ESMTP MAIL Service, Version: ([0-9.]+)"), "Microsoft Exchange SMTP"),
    (re.compile(r"\bPostfix\b"), "Postfix"),
    (re.compile(r"\bOpenSMTPD\b"), "OpenSMTPD"),
    (re.compile(r"\bHaraka/([0-9.]+)"), "Haraka"),
)
_FTP_PRODUCTS = (
    (re.compile(r"\(vsFTPd ([0-9][0-9.]*)\)"), "vsftpd"),
    (re.compile(r"\bProFTPD ([0-9][0-9.]*[a-z]?)"), "ProFTPD"),
    (re.compile(r"\bProFTPD\b"), "ProFTPD"),
    (re.compile(r"\bPure-FTPd\b"), "Pure-FTPd"),
    (re.compile(r"\bFileZilla Server (?:version )?([0-9][0-9.]*)"), "FileZilla Server"),
    (re.compile(r"\bMicrosoft FTP Service\b"), "Microsoft FTP Service"),
)


def _product_from(text: str, table: tuple[tuple[re.Pattern[str], str], ...]) -> tuple[str | None, str | None]:
    found = _product_match(text, table)
    return (found[0], found[1]) if found else (None, None)


def _product_match(text: str, table: tuple[tuple[re.Pattern[str], str], ...]) -> tuple[str, str | None, str] | None:
    """(product, version, the matched text) -- never the rest of a banner, which names hosts."""
    for pattern, name in table:
        found = pattern.search(text)
        if found:
            return name, (found.group(1) if found.groups() else None), found.group(0)
    return None


def smtp_replies_complete(data: bytes) -> bool:
    """A full (possibly multi-line) reply: its last line is ``NNN `` rather than ``NNN-``."""
    lines = [line for line in (data or b"").split(b"\r\n") if line]
    return bool(lines) and bool(re.match(rb"^\d{3}(?: |$)", lines[-1])) and (data or b"").endswith(b"\n")


def reply_code(data: bytes) -> int | None:
    match = re.match(rb"^(\d{3})[ -]", data or b"")
    return int(match.group(1)) if match else None


def parse_ehlo_extensions(data: bytes) -> list[str]:
    extensions = []
    for line in (data or b"").split(b"\r\n")[1:]:
        match = re.match(rb"^250[ -]([A-Za-z0-9][A-Za-z0-9-]{0,40})", line)
        if match:
            extensions.append(match.group(1).decode("ascii").upper())
    return extensions[:32]


def parse_redis_info(data: bytes) -> dict[str, Any] | None:
    """The reply to ``INFO server``: identity plus the access decision it carries."""
    data = data or b""
    if data.startswith(b"-NOAUTH"):
        return {"protocol": "redis", "authentication": si.AUTH_REQUIRED,
                "authentication_proof": "redis_noauth"}
    if data.startswith(b"-DENIED") and b"protected mode" in data[:200]:
        return {"protocol": "redis", "authentication": si.AUTH_REQUIRED,
                "authentication_proof": "redis_protected_mode"}
    if (re.match(rb"^-ERR unknown command [\x20-\x7e]{1,200}\r\n", data)
            or re.match(rb"^-NOPERM [\x20-\x7e]{1,200}\r\n", data)):
        # Redis's own refusal of INFO (a renamed command, an ACL rule): the protocol answered,
        # but nothing decided access.
        return {"protocol": "redis", "authentication": si.AUTH_INCONCLUSIVE}
    bulk = re.match(rb"^\$(\d{1,7})\r\n", data)
    if not bulk:
        return None
    body = data[bulk.end():]
    version = re.search(rb"(?m)^redis_version:([0-9][0-9.]{0,20})\r?$", body)
    if not body.startswith(b"# Server") or not version:
        return None
    product, upstream = "Redis", version.group(1).decode("ascii")
    valkey = re.search(rb"(?m)^valkey_version:([0-9][0-9.]{0,20})\r?$", body)
    if valkey or re.search(rb"(?m)^server_name:valkey\r?$", body):
        product = "Valkey"
        upstream = valkey.group(1).decode("ascii") if valkey else upstream
    mode = re.search(rb"(?m)^redis_mode:([a-z]{1,20})\r?$", body)
    return {
        "protocol": "redis", "product": product, "version": upstream,
        "version_reported": upstream,
        "authentication": si.AUTH_NOT_REQUIRED,
        "authentication_proof": "redis_info_without_credentials",
        "details": {"mode": mode.group(1).decode("ascii")} if mode else {},
    }


def parse_memcached_version(data: bytes) -> dict[str, Any] | None:
    data = data or b""
    if data.startswith(b"CLIENT_ERROR unauthenticated"):
        return {"protocol": "memcached", "product": "Memcached",
                "authentication": si.AUTH_REQUIRED,
                "authentication_proof": "memcached_unauthenticated_refused"}
    match = re.match(rb"^VERSION ([0-9]+\.[0-9]+\.[0-9]+[\x21-\x7e]{0,40})\r\n", data)
    if not match:
        return None
    reported = match.group(1).decode("ascii")
    return {"protocol": "memcached", "product": "Memcached",
            "version": re.match(r"^[0-9]+\.[0-9]+\.[0-9]+", reported).group(0),
            "version_reported": reported}


def memcached_stats_answered(data: bytes) -> bool:
    return bool(re.match(rb"^STAT pid \d+\r\n", data or b"")) and b"\r\nSTAT " in (data or b"")


def postgres_error_fields(data: bytes) -> dict[str, str] | None:
    """An ErrorResponse ('E') message's fields, or None when it is not one."""
    data = data or b""
    if len(data) < 6 or data[0:1] != b"E":
        return None
    length = int.from_bytes(data[1:5], "big")
    if length < 4 or length > 8192:
        return None
    body = data[5:1 + length]
    fields: dict[str, str] = {}
    for part in body.split(b"\x00"):
        if not part:
            continue
        key = chr(part[0])
        if not key.isalpha():
            return None
        fields[key] = part[1:].decode("utf-8", "replace")[:300]
    sqlstate = fields.get("C", "")
    if not re.fullmatch(r"[0-9A-Z]{5}", sqlstate) or "S" not in fields:
        return None
    return fields


def parse_postgres_reply(data: bytes) -> dict[str, Any] | None:
    """PostgreSQL's refusal of an unsupported protocol version: identity, no version.

    The server names the protocol range it supports (``3.0 to 3.2``) before any authentication;
    it reveals no product version, so none is claimed.
    """
    fields = postgres_error_fields(data)
    if fields is None:
        return None
    details: dict[str, Any] = {"sqlstate": fields["C"]}
    supported = re.search(r"(\d+\.\d+) to (\d+\.\d+)", fields.get("M", ""))
    if supported:
        details["protocol_versions"] = f"{supported.group(1)}-{supported.group(2)}"
    return {"protocol": "postgresql", "product": "PostgreSQL", "details": details}


RDP_REQUEST = bytes.fromhex("03000013" + "0ee00000000000" + "01000800" + "01000000")
_RDP_SELECTED = {0: "rdp", 1: "tls", 2: "credssp", 8: "credssp_early_user_auth"}
_RDP_FAILURES = {
    1: "ssl_required_by_server", 2: "ssl_not_allowed_by_server", 3: "ssl_cert_not_on_server",
    4: "inconsistent_flags", 5: "hybrid_required_by_server", 6: "ssl_with_user_auth_required",
}


def parse_rdp_confirm(data: bytes) -> dict[str, Any] | None:
    """An X.224 Connection Confirm to a TLS-only RDP negotiation request."""
    data = data or b""
    if len(data) < 11 or data[0] != 0x03 or data[1] != 0x00:
        return None
    total = int.from_bytes(data[2:4], "big")
    if total < 11 or total > len(data) or (data[5] & 0xF0) != 0xD0:
        return None
    details: dict[str, Any] = {}
    row: dict[str, Any] = {"protocol": "rdp", "details": details}
    if total >= 19:
        kind = data[11]
        code = int.from_bytes(data[15:19], "little")
        if kind == 0x02:
            details["selected_security"] = _RDP_SELECTED.get(code, f"unknown_{code}")
        elif kind == 0x03:
            details["negotiation_failure"] = _RDP_FAILURES.get(code, f"unknown_{code}")
            if code == 5:
                row["authentication"] = si.AUTH_REQUIRED
                row["authentication_proof"] = "rdp_nla_required"
    return row


def smb2_negotiate_request() -> bytes:
    dialects = (0x0202, 0x0210, 0x0300, 0x0302)
    header = (
        b"\xfeSMB" + struct.pack("<H", 64) + b"\x00" * 6 + struct.pack("<HH", 0, 1)
        + b"\x00" * 8 + b"\x00" * 8 + b"\x00" * 8 + b"\x00" * 8 + b"\x00" * 16
    )
    body = struct.pack("<HHHHI", 36, len(dialects), 1, 0, 0) + os.urandom(16) + b"\x00" * 8
    body += b"".join(struct.pack("<H", item) for item in dialects)
    message = header + body
    return b"\x00" + len(message).to_bytes(3, "big") + message


_SMB_DIALECTS = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1", 0x02FF: "2.???"}


def parse_smb2_negotiate(data: bytes) -> dict[str, Any] | None:
    data = data or b""
    if len(data) < 4 + 64 + 8 or data[0] != 0x00:
        return None
    smb = data[4:]
    if smb[0:4] != b"\xfeSMB":
        return None
    status = int.from_bytes(smb[8:12], "little")
    command = int.from_bytes(smb[12:14], "little")
    if command != 0:
        return None
    details: dict[str, Any] = {"status": f"0x{status:08x}"}
    body = smb[64:]
    if status == 0 and len(body) >= 6 and int.from_bytes(body[0:2], "little") == 65:
        security_mode = int.from_bytes(body[2:4], "little")
        dialect = int.from_bytes(body[4:6], "little")
        details["dialect"] = _SMB_DIALECTS.get(dialect, f"0x{dialect:04x}")
        details["signing_required"] = bool(security_mode & 0x02)
    return {"protocol": "smb", "details": details}


def mongodb_op_msg(command: str, request_id: int, extra: bytes = b"") -> bytes:
    """An OP_MSG carrying ``{<command>: 1, <extra>, "$db": "admin"}``."""
    def element_int(name: str, value: int) -> bytes:
        return b"\x10" + name.encode() + b"\x00" + struct.pack("<i", value)

    def element_str(name: str, value: str) -> bytes:
        raw = value.encode() + b"\x00"
        return b"\x02" + name.encode() + b"\x00" + struct.pack("<i", len(raw)) + raw

    elements = element_int(command, 1) + extra + element_str("$db", "admin")
    document = struct.pack("<i", len(elements) + 5) + elements + b"\x00"
    body = struct.pack("<I", 0) + b"\x00" + document
    return struct.pack("<iiii", 16 + len(body), request_id, 0, 2013) + body


def mongodb_op_query_ismaster(request_id: int) -> bytes:
    elements = b"\x10isMaster\x00" + struct.pack("<i", 1)
    document = struct.pack("<i", len(elements) + 5) + elements + b"\x00"
    body = struct.pack("<i", 0) + b"admin.$cmd\x00" + struct.pack("<ii", 0, 1) + document
    return struct.pack("<iiii", 16 + len(body), request_id, 0, 2004) + body


def bson_top_level(document: bytes, *, depth: int = 0) -> dict[str, Any] | None:
    """Top-level scalar fields of one BSON document; arrays and documents as element counts.

    Only one nested level is read (to count an array's elements): a hostile server cannot make
    the parser recurse with deeply nested documents.
    """
    if len(document) < 5:
        return None
    total = int.from_bytes(document[0:4], "little")
    if total < 5 or total > len(document) or document[total - 1] != 0:
        return None
    fields: dict[str, Any] = {}
    offset = 4
    end = total - 1
    while offset < end and len(fields) < 64:
        kind = document[offset]
        name_end = document.find(b"\x00", offset + 1, end)
        if name_end < 0:
            return None
        name = document[offset + 1:name_end].decode("utf-8", "replace")[:64]
        offset = name_end + 1
        try:
            if kind == 0x01:
                fields[name] = struct.unpack_from("<d", document, offset)[0]
                offset += 8
            elif kind == 0x02:
                size = struct.unpack_from("<i", document, offset)[0]
                if size < 1 or offset + 4 + size > end + 1:
                    return None
                fields[name] = document[offset + 4:offset + 4 + size - 1].decode("utf-8", "replace")[:300]
                offset += 4 + size
            elif kind in {0x03, 0x04}:
                size = struct.unpack_from("<i", document, offset)[0]
                if size < 5 or offset + size > end + 1:
                    return None
                nested = bson_top_level(document[offset:offset + size], depth=depth + 1) if depth < 1 else None
                fields[name] = {"elements": len(nested or {})}
                offset += size
            elif kind == 0x05:
                size = struct.unpack_from("<i", document, offset)[0]
                offset += 5 + max(0, size)
            elif kind == 0x07:
                offset += 12
            elif kind == 0x08:
                fields[name] = document[offset] == 1
                offset += 1
            elif kind == 0x0A:
                fields[name] = None
            elif kind == 0x10:
                fields[name] = struct.unpack_from("<i", document, offset)[0]
                offset += 4
            elif kind in {0x09, 0x11, 0x12}:
                fields[name] = struct.unpack_from("<q", document, offset)[0]
                offset += 8
            elif kind == 0x13:
                offset += 16
            else:
                break
        except struct.error:
            return None
    return fields


def mongodb_reply_document(data: bytes, request_id: int) -> dict[str, Any] | None:
    """The first document of an OP_MSG or OP_REPLY answering ``request_id``."""
    data = data or b""
    if len(data) < 21:
        return None
    length, _response_id, response_to, opcode = struct.unpack_from("<iiii", data, 0)
    if response_to != request_id or length < 21 or length > len(data):
        return None
    if opcode == 2013 and data[20] == 0:
        return bson_top_level(data[21:length])
    if opcode == 1 and length >= 36 + 5:
        return bson_top_level(data[36:length])
    return None


def mongodb_reply_complete(data: bytes) -> bool:
    return len(data) >= 4 and len(data) >= int.from_bytes(data[0:4], "little") > 0


def _dechunk(body: bytes) -> bytes:
    """A chunked body's payload (bounded, tolerant of a truncated read)."""
    out = b""
    while body and len(out) < MAX_READ_BYTES:
        size_line, sep, rest = body.partition(b"\r\n")
        try:
            size = int(size_line.split(b";", 1)[0].strip() or b"0", 16)
        except ValueError:
            break
        if not sep or size <= 0:
            break
        out += rest[:size]
        body = rest[size + 2:]
    return out


def _http_split(data: bytes) -> tuple[int, dict[str, str], bytes] | None:
    match = re.match(rb"^HTTP/(?:1\.[01]|2(?:\.0)?) (\d{3})[^\r\n]*\r\n", data or b"")
    if not match:
        return None
    head, _, body = data.partition(b"\r\n\r\n")
    headers: dict[str, str] = {}
    for line in head.split(b"\r\n")[1:64]:
        name, sep, value = line.partition(b":")
        if sep:
            headers[name.decode("latin-1").strip().lower()] = value.decode("latin-1").strip()[:300]
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = _dechunk(body)
    return int(match.group(1)), headers, body


def parse_elasticsearch_root(status: int, headers: Mapping[str, str], body: bytes) -> dict[str, Any] | None:
    """Elasticsearch/OpenSearch from ``GET /``: the JSON banner or the product header."""
    import json

    product_header = (headers.get("x-elastic-product") or "").strip()
    if status in {401, 403}:
        if product_header.lower() == "elasticsearch":
            return {"protocol": "http", "product": "Elasticsearch",
                    "authentication": si.AUTH_REQUIRED,
                    "authentication_proof": "elasticsearch_credentials_required"}
        return None
    if status != 200:
        return None
    try:
        document = json.loads(body[:MAX_READ_BYTES].decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(document, dict) or not isinstance(document.get("version"), dict):
        return None
    version = document["version"]
    number = version.get("number")
    if not isinstance(number, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+-]{0,20}", number):
        return None
    tagline = document.get("tagline")
    if version.get("distribution") == "opensearch":
        product = "OpenSearch"
    elif tagline == "You Know, for Search" or product_header.lower() == "elasticsearch":
        product = "Elasticsearch"
    else:
        return None
    return {"protocol": "http", "product": product,
            "version": re.match(r"^[0-9]+\.[0-9]+\.[0-9]+", number).group(0),
            "version_reported": number,
            "details": {"cluster_metadata_without_credentials": True}}


def _dns_name(name: str) -> bytes:
    return b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\x00"


def dns_version_query(transaction_id: int) -> bytes:
    return struct.pack(">HHHHHH", transaction_id, 0x0000, 1, 0, 0, 0) + _dns_name("version.bind") + struct.pack(">HH", 16, 3)


def _skip_dns_name(data: bytes, offset: int) -> int:
    for _ in range(128):
        if offset >= len(data):
            raise ValueError("truncated name")
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length
    raise ValueError("name too long")


_DNS_PRODUCTS = (
    (re.compile(r"^(9\.[0-9]+\.[0-9]+)"), "ISC BIND"),
    (re.compile(r"^dnsmasq-([0-9][0-9.]*)"), "dnsmasq"),
    (re.compile(r"^unbound ([0-9][0-9.]*)", re.I), "Unbound"),
    (re.compile(r"^PowerDNS (?:Authoritative Server|Recursor) ([0-9][0-9.]*)"), "PowerDNS"),
    (re.compile(r"^Knot DNS ([0-9][0-9.]*)"), "Knot DNS"),
    (re.compile(r"^Microsoft DNS ([0-9][0-9.]*)"), "Microsoft DNS"),
)


def parse_dns_reply(data: bytes, transaction_id: int) -> dict[str, Any] | None:
    """A DNS reply to our ``version.bind`` CHAOS query: protocol always, version if answered.

    The version string is whatever the operator configured; it is reported as such.
    """
    data = data or b""
    if len(data) < 12:
        return None
    ident, flags, qdcount, ancount, _ns, _ar = struct.unpack_from(">HHHHHH", data, 0)
    if ident != transaction_id or not flags & 0x8000 or qdcount > 1:
        return None
    rcode = flags & 0x000F
    row: dict[str, Any] = {"protocol": "dns", "details": {"version_query_rcode": rcode}}
    if rcode != 0 or ancount == 0:
        return row
    try:
        offset = 12
        for _ in range(qdcount):
            offset = _skip_dns_name(data, offset) + 4
        offset = _skip_dns_name(data, offset)
        rtype, _rclass, _ttl, rdlength = struct.unpack_from(">HHIH", data, offset)
        offset += 10
        if rtype != 16 or rdlength < 1:
            return row
        text_length = data[offset]
        reported = data[offset + 1:offset + 1 + min(text_length, rdlength - 1)]
    except (ValueError, struct.error, IndexError):
        return row
    reported_text = si.label(reported, 120)
    if reported_text:
        row["version_reported"] = reported_text
        product, version = _product_from(reported_text, _DNS_PRODUCTS)
        row["product"] = product
        row["version"] = version
    return row


NTP_REQUEST = bytes([0x23]) + b"\x00" * 47


def parse_ntp_reply(data: bytes) -> dict[str, Any] | None:
    data = data or b""
    if len(data) < 48 or data[0] & 0x07 != 4:
        return None
    return {"protocol": "ntp", "details": {"ntp_version": (data[0] >> 3) & 0x07, "stratum": data[1]}}


def ike_main_mode_request(initiator_cookie: bytes) -> bytes:
    attributes = b"".join(struct.pack(">HH", 0x8000 | kind, value) for kind, value in (
        (1, 7), (14, 128), (2, 2), (3, 1), (4, 14), (11, 1), (12, 28800),
    ))
    transform = struct.pack(">BBHBBH", 0, 0, 8 + len(attributes), 1, 1, 0) + attributes
    proposal = struct.pack(">BBHBBBB", 0, 0, 8 + len(transform), 1, 1, 0, 1) + transform
    sa = struct.pack(">BBHII", 0, 0, 12 + len(proposal), 1, 1) + proposal
    header = initiator_cookie + b"\x00" * 8 + struct.pack(">BBBBII", 1, 0x10, 2, 0, 0, 28 + len(sa))
    return header + sa


def parse_ike_reply(data: bytes, initiator_cookie: bytes) -> dict[str, Any] | None:
    data = data or b""
    if data.startswith(b"\x00\x00\x00\x00"):  # NAT-T non-ESP marker
        data = data[4:]
    if len(data) < 28 or data[0:8] != initiator_cookie:
        return None
    next_payload, version, exchange = data[16], data[17], data[18]
    major = version >> 4
    if major not in {1, 2}:
        return None
    response = "proposal_accepted" if next_payload == 1 else "notification" if next_payload in {11, 41} else "other"
    return {"protocol": "ike", "details": {"ike_version": major, "exchange_type": exchange, "response": response}}


def openvpn_reset(session_id: bytes) -> bytes:
    return bytes([0x38]) + session_id + b"\x00" + b"\x00\x00\x00\x00"


def parse_openvpn_reply(data: bytes, session_id: bytes, *, tcp: bool) -> dict[str, Any] | None:
    data = data or b""
    if tcp:
        if len(data) < 2:
            return None
        data = data[2:2 + int.from_bytes(data[0:2], "big")]
    if len(data) < 14 or data[0] >> 3 != 8:  # P_CONTROL_HARD_RESET_SERVER_V2
        return None
    ack_count = data[9]
    if ack_count < 1 or len(data) < 10 + 4 * ack_count + 8:
        return None
    remote = data[10 + 4 * ack_count:10 + 4 * ack_count + 8]
    if remote != session_id:
        return None
    return {"protocol": "openvpn", "product": "OpenVPN", "details": {"control_channel": "hard_reset_answered"}}


def pptp_start_request() -> bytes:
    body = struct.pack(">HHIHHHHIIHH", 156, 1, 0x1A2B3C4D, 1, 0, 0x0100, 0, 1, 1, 0, 0)
    return body + b"\x00" * 64 + b"\x00" * 64


def parse_pptp_reply(data: bytes) -> dict[str, Any] | None:
    data = data or b""
    if len(data) < 156 or struct.unpack_from(">I", data, 4)[0] != 0x1A2B3C4D:
        return None
    if struct.unpack_from(">H", data, 8)[0] != 2:
        return None
    vendor = si.label(data[92:156].split(b"\x00", 1)[0], 64)
    return {"protocol": "pptp", "details": {"vendor": vendor} if vendor else {}}


# ---------------------------------------------------------------------------
# Adapters (each opens its own bounded connection)
# ---------------------------------------------------------------------------

async def _converse_220(connection: _Connection, greeting: bytes, port: int, server_name: str | None) -> dict[str, Any]:
    """A ``220`` greeting is FTP or SMTP; the server's answer to one command decides which."""
    text = si.label(greeting, 300) or ""
    looks_ftp = bool(re.search(r"\bFTP\b|FTPd|FileZilla", text, re.I))
    if not looks_ftp:
        await connection.send(b"EHLO shakerscan.invalid\r\n")
        reply = await connection.read(until=smtp_replies_complete)
        if reply_code(reply) == 250:
            extensions = parse_ehlo_extensions(reply)
            product, version, matched = _product_match(text, _SMTP_PRODUCTS) or (None, None, None)
            details: dict[str, Any] = {"extensions": extensions}
            if "STARTTLS" in extensions:
                await connection.send(b"STARTTLS\r\n")
                ready = await connection.read(until=smtp_replies_complete)
                tls = await connection.start_tls(server_name) if reply_code(ready) == 220 else None
                details["starttls"] = "negotiated" if tls is not None else "offered_failed"
                details.update(tls or {})
            else:
                details["starttls"] = "not_offered"
            try:
                await connection.send(b"QUIT\r\n")
            except Exception:  # noqa: BLE001
                pass
            return _identified(port, "tcp", "smtp", "smtp", product=product, version=version,
                               version_reported=matched if version else None, details=details)
    await connection.send(b"SYST\r\n" if not looks_ftp else b"FEAT\r\n")
    reply = await connection.read(until=smtp_replies_complete)
    code = reply_code(reply)
    if code in {211, 215} or (looks_ftp and code is not None):
        product, version, matched = _product_match(text, _FTP_PRODUCTS) or (None, None, None)
        details = {}
        if code == 211:
            features = {line.strip().upper() for line in reply.decode("latin-1").split("\r\n")[1:]}
            details["auth_tls_offered"] = any(item.startswith("AUTH TLS") for item in features)
        try:
            await connection.send(b"QUIT\r\n")
        except Exception:  # noqa: BLE001
            pass
        return _identified(port, "tcp", "ftp", "ftp", product=product, version=version,
                           version_reported=matched if version else None, details=details)
    return _result(port, "tcp", si.STATUS_UNIDENTIFIED, adapter="banner",
                   details={"banner_excerpt": excerpt(greeting)})


async def _vnc_security(connection: _Connection, banner: bytes, row: dict[str, Any]) -> None:
    """Read the offered security types; select None only when the server offers it."""
    minor = int(banner[8:11]) if banner[8:11].isdigit() else 3
    reply_version = b"RFB 003.008\n" if minor >= 8 else b"RFB 003.007\n" if minor == 7 else b"RFB 003.003\n"
    await connection.send(reply_version)
    if reply_version == b"RFB 003.003\n":
        offered = await connection.read(limit=4, until=lambda data: len(data) >= 4)
        if len(offered) < 4:
            return
        chosen = int.from_bytes(offered, "big")
        types = [chosen] if chosen else []
    else:
        count_raw = await connection.read(limit=1, until=lambda data: len(data) >= 1)
        if not count_raw or count_raw[0] == 0:
            return
        listed = await connection.read(limit=count_raw[0], until=lambda data: len(data) >= count_raw[0])
        types = list(listed)
    row["details"]["security_types"] = types[:16]
    if 1 not in types:
        if types:
            row["authentication"] = si.AUTH_REQUIRED
            row["authentication_proof"] = "vnc_authentication_required"
        return
    if reply_version == b"RFB 003.003\n":
        row["authentication"] = si.AUTH_NOT_REQUIRED
        row["authentication_proof"] = "vnc_security_none_accepted"
        return
    await connection.send(b"\x01")
    if reply_version == b"RFB 003.007\n":
        # 3.7 sends no SecurityResult for None; the offer alone is not proof.
        row["authentication"] = si.AUTH_INCONCLUSIVE
        return
    result = await connection.read(limit=4, until=lambda data: len(data) >= 4)
    if result == b"\x00\x00\x00\x00":
        row["authentication"] = si.AUTH_NOT_REQUIRED
        row["authentication_proof"] = "vnc_security_none_accepted"
    else:
        row["authentication"] = si.AUTH_INCONCLUSIVE


async def adapter_banner(address: str, port: int, *, server_name: str | None = None) -> dict[str, Any] | None:
    """Server-speaks-first protocols. ``None`` when the listener said nothing."""
    connection = await _connect(address, port)
    if connection is None:
        return _result(port, "tcp", si.STATUS_UNREACHABLE, adapter="banner")
    try:
        banner = await connection.read(timeout=BANNER_WAIT, until=lambda data: b"\n" in data or len(data) >= 4 and data[3] == 0)
        if not banner:
            return None
        if banner.startswith(b"SSH-"):
            parsed = parse_ssh_banner(banner)
            if parsed:
                return _identified(port, "tcp", "ssh", "ssh", **parsed)
        mysql = parse_mysql_greeting(banner)
        if mysql is None and len(banner) >= 4 and banner[3] == 0:
            banner += await connection.read(timeout=1.0, until=lambda data: len(data) >= 4 + int.from_bytes(banner[0:3], "little"))
            mysql = parse_mysql_greeting(banner)
        if mysql:
            return _identified(port, "tcp", "mysql", "mysql", **mysql)
        vnc = parse_vnc_banner(banner)
        if vnc:
            row = _identified(port, "tcp", "vnc", "vnc", **vnc)
            if port not in PAYLOAD_EXCLUDED_TCP_PORTS:
                await _vnc_security(connection, banner, row)
            return row
        if port in PAYLOAD_EXCLUDED_TCP_PORTS:
            return _result(port, "tcp", si.STATUS_EXCLUDED, adapter="banner",
                           details={"reason": PAYLOAD_EXCLUSION_REASON, "banner_excerpt": excerpt(banner)})
        if reply_code(banner) == 220:
            if not smtp_replies_complete(banner):
                banner += await connection.read(timeout=1.5, until=smtp_replies_complete)
            return await _converse_220(connection, banner, port, server_name)
        if banner.startswith(b"+OK"):
            product = "Dovecot" if b"Dovecot" in banner[:200] else None
            return _identified(port, "tcp", "pop3", "pop3", product=product)
        if banner.startswith(b"* OK"):
            product = "Dovecot" if b"Dovecot" in banner[:200] else None
            return _identified(port, "tcp", "imap", "imap", product=product)
        if banner[:1] == b"\xff" and len(banner) >= 3 and banner[1] in {251, 252, 253, 254}:
            return _identified(port, "tcp", "telnet", "telnet")
        return _result(port, "tcp", si.STATUS_UNIDENTIFIED, adapter="banner",
                       details={"banner_excerpt": excerpt(banner)})
    finally:
        await connection.close()


async def _http_exchange(
    address: str, port: int, path: str, *, tls: bool, server_name: str | None,
) -> tuple[tuple[int, dict[str, str], bytes] | None, bytes, dict[str, Any]]:
    connection = await _connect(address, port, tls=tls, server_name=server_name)
    if connection is None:
        return None, b"", {}
    try:
        host = server_name or (f"[{address}]" if ":" in address else address)
        default = 443 if tls else 80
        host_header = host if port == default else f"{host}:{port}"
        await connection.send(
            f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {USER_AGENT}\r\n"
            "Accept: application/json\r\nConnection: close\r\n\r\n".encode("ascii")
        )
        raw = await connection.read(limit=MAX_READ_BYTES)
        details = _tls_details(connection.writer) if tls else {}
        return _http_split(raw), raw, details
    finally:
        await connection.close()


async def _http_adapter(address: str, port: int, *, tls: bool, server_name: str | None) -> dict[str, Any] | None:
    parsed, raw, tls_details = await _http_exchange(address, port, "/", tls=tls, server_name=server_name)
    if parsed is None:
        if tls and tls_details:
            return _identified(port, "tcp", "tls", "tls", details=tls_details)
        return None
    status, headers, body = parsed
    if b"trying to access MongoDB over HTTP on the native driver port" in body[:400]:
        # MongoDB answers an HTTP request on its driver port: not an HTTP service.
        return None
    protocol = "https" if tls else "http"
    details: dict[str, Any] = {"status": status, **tls_details}
    server = si.label(headers.get("server"), 200)
    if server:
        details["server_header"] = server
    search = parse_elasticsearch_root(status, headers, body)
    if search is None:
        return _identified(port, "tcp", protocol, "https" if tls else "http", details=details)
    search["details"] = {**details, **search.get("details", {})}
    row = _identified(port, "tcp", protocol, "elasticsearch", **search)
    if row["authentication"] == si.AUTH_NOT_TESTED:
        # The root banner is cluster metadata; the access proof is an index listing.
        listing, _raw, _tls = await _http_exchange(
            address, port, "/_cat/indices?format=json&h=index", tls=tls, server_name=server_name,
        )
        if listing is not None:
            listing_status, _headers, listing_body = listing
            if listing_status == 200 and listing_body.lstrip().startswith(b"["):
                row["authentication"] = si.AUTH_NOT_REQUIRED
                row["authentication_proof"] = "elasticsearch_index_listing_without_credentials"
            elif listing_status in {401, 403}:
                row["authentication"] = si.AUTH_REQUIRED
                row["authentication_proof"] = "elasticsearch_credentials_required"
    return row


async def adapter_http(address: str, port: int, *, server_name: str | None = None) -> dict[str, Any] | None:
    return await _http_adapter(address, port, tls=False, server_name=server_name)


async def adapter_tls(address: str, port: int, *, server_name: str | None = None) -> dict[str, Any] | None:
    return await _http_adapter(address, port, tls=True, server_name=server_name)


async def _one_exchange(address: str, port: int, payload: bytes, *, until: Callable[[bytes], bool] | None = None) -> bytes | None:
    connection = await _connect(address, port)
    if connection is None:
        return None
    try:
        await connection.send(payload)
        return await connection.read(until=until)
    except (TimeoutError, asyncio.TimeoutError, OSError, ConnectionError):
        return b""
    finally:
        await connection.close()


async def adapter_redis(address: str, port: int, *, server_name: str | None = None) -> dict[str, Any] | None:
    reply = await _one_exchange(address, port, b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n",
                                until=lambda data: data.endswith(b"\r\n\r\n") or data.startswith((b"-", b"+")) and data.endswith(b"\r\n"))
    parsed = parse_redis_info(reply or b"")
    return _identified(port, "tcp", "redis", "redis", **parsed) if parsed else None


async def adapter_memcached(address: str, port: int, *, server_name: str | None = None) -> dict[str, Any] | None:
    connection = await _connect(address, port)
    if connection is None:
        return None
    try:
        await connection.send(b"version\r\n")
        parsed = parse_memcached_version(await connection.read(until=lambda data: data.endswith(b"\r\n")))
        if parsed is None:
            return None
        row = _identified(port, "tcp", "memcached", "memcached", **parsed)
        if row["authentication"] == si.AUTH_NOT_TESTED:
            await connection.send(b"stats\r\n")
            stats = await connection.read(until=lambda data: data.endswith(b"END\r\n"))
            if memcached_stats_answered(stats):
                row["authentication"] = si.AUTH_NOT_REQUIRED
                row["authentication_proof"] = "memcached_stats_without_credentials"
        return row
    finally:
        await connection.close()


async def adapter_mongodb(address: str, port: int, *, server_name: str | None = None) -> dict[str, Any] | None:
    connection = await _connect(address, port)
    if connection is None:
        return None
    try:
        base = int.from_bytes(os.urandom(3), "big") + 1
        await connection.send(mongodb_op_msg("hello", base))
        hello = mongodb_reply_document(await connection.read(until=mongodb_reply_complete), base)
        if hello is None:
            await connection.close()
            connection = await _connect(address, port)
            if connection is None:
                return None
            await connection.send(mongodb_op_query_ismaster(base + 3))
            legacy = mongodb_reply_document(await connection.read(until=mongodb_reply_complete), base + 3)
            if legacy is None or "ok" not in legacy:
                return None
            return _identified(port, "tcp", "mongodb", "mongodb", product="MongoDB",
                               details={"wire": "op_query", "max_wire_version": legacy.get("maxWireVersion")})
        if "ok" not in hello:
            return None
        details: dict[str, Any] = {"wire": "op_msg"}
        if isinstance(hello.get("maxWireVersion"), int):
            details["max_wire_version"] = hello["maxWireVersion"]
        if hello.get("msg") == "isdbgrid":
            details["router"] = "mongos"
        row = _identified(port, "tcp", "mongodb", "mongodb", product="MongoDB", details=details)
        # buildInfo is answered before authentication: the reported version.
        await connection.send(mongodb_op_msg("buildInfo", base + 1))
        build = mongodb_reply_document(await connection.read(until=mongodb_reply_complete), base + 1)
        reported = build.get("version") if isinstance(build, dict) else None
        if isinstance(reported, str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+-]{0,20}", reported):
            row["version"] = re.match(r"^[0-9]+\.[0-9]+\.[0-9]+", reported).group(0)
            row["version_reported"] = reported
            row["version_basis"] = si.VERSION_REPORTED
        # The access proof: list database names (read-only; only the count is kept).
        await connection.send(mongodb_op_msg("listDatabases", base + 2, extra=b"\x08nameOnly\x00\x01"))
        listing = mongodb_reply_document(await connection.read(until=mongodb_reply_complete), base + 2)
        if isinstance(listing, dict):
            if listing.get("ok") in {1, 1.0} and isinstance(listing.get("databases"), dict):
                row["authentication"] = si.AUTH_NOT_REQUIRED
                row["authentication_proof"] = "mongodb_list_databases_without_credentials"
                row["details"]["database_count"] = listing["databases"]["elements"]
            elif listing.get("code") in {13, 18} or "auth" in str(listing.get("errmsg") or "").lower():
                row["authentication"] = si.AUTH_REQUIRED
                row["authentication_proof"] = "mongodb_unauthorized"
        return row
    finally:
        await connection.close()


async def adapter_postgresql(address: str, port: int, *, server_name: str | None = None) -> dict[str, Any] | None:
    # An unsupported protocol version (9999.0) is refused before any authentication.
    startup = struct.pack(">ii", 0, 9999 << 16) + b"user\x00shakerscan\x00\x00"
    startup = struct.pack(">i", len(startup)) + startup[4:]
    reply = await _one_exchange(address, port, startup,
                                until=lambda data: len(data) >= 5 and len(data) >= 1 + int.from_bytes(data[1:5], "big"))
    parsed = parse_postgres_reply(reply or b"")
    if parsed is None:
        return None
    row = _identified(port, "tcp", "postgresql", "postgresql", **parsed)
    ssl_reply = await _one_exchange(address, port, struct.pack(">ii", 8, 80877103),
                                    until=lambda data: len(data) >= 1)
    if ssl_reply in {b"S", b"N"}:
        row["details"]["tls_supported"] = ssl_reply == b"S"
    return row


async def adapter_rdp(address: str, port: int, *, server_name: str | None = None) -> dict[str, Any] | None:
    reply = await _one_exchange(address, port, RDP_REQUEST,
                                until=lambda data: len(data) >= 4 and len(data) >= int.from_bytes(data[2:4], "big"))
    parsed = parse_rdp_confirm(reply or b"")
    return _identified(port, "tcp", "rdp", "rdp", **parsed) if parsed else None


async def adapter_smb(address: str, port: int, *, server_name: str | None = None) -> dict[str, Any] | None:
    reply = await _one_exchange(address, port, smb2_negotiate_request(),
                                until=lambda data: len(data) >= 4 and len(data) >= 4 + int.from_bytes(data[1:4], "big"))
    parsed = parse_smb2_negotiate(reply or b"")
    return _identified(port, "tcp", "smb", "smb", **parsed) if parsed else None


async def adapter_openvpn(address: str, port: int, *, server_name: str | None = None) -> dict[str, Any] | None:
    session_id = os.urandom(8)
    packet = openvpn_reset(session_id)
    reply = await _one_exchange(address, port, len(packet).to_bytes(2, "big") + packet,
                                until=lambda data: len(data) >= 2 and len(data) >= 2 + int.from_bytes(data[0:2], "big"))
    parsed = parse_openvpn_reply(reply or b"", session_id, tcp=True)
    return _identified(port, "tcp", "openvpn", "openvpn", **parsed) if parsed else None


async def adapter_pptp(address: str, port: int, *, server_name: str | None = None) -> dict[str, Any] | None:
    reply = await _one_exchange(address, port, pptp_start_request(), until=lambda data: len(data) >= 156)
    parsed = parse_pptp_reply(reply or b"")
    return _identified(port, "tcp", "pptp", "pptp", **parsed) if parsed else None


_MQTT_CLIENT_ID = b"shakerscan-identify"
_MQTT_BODY = (
    b"\x00\x04MQTT\x04\x02\x00\x3c"  # protocol name, level 4, clean session, keep-alive 60
    + len(_MQTT_CLIENT_ID).to_bytes(2, "big") + _MQTT_CLIENT_ID
)
MQTT_CONNECT = b"\x10" + bytes([len(_MQTT_BODY)]) + _MQTT_BODY


def parse_mqtt_connack(data: bytes) -> dict[str, Any] | None:
    """CONNACK to a credential-less CONNECT: return code 0 is anonymous access."""
    data = data or b""
    if len(data) < 4 or data[0] != 0x20 or data[1] != 0x02 or data[2] > 1:
        return None
    code = data[3]
    row: dict[str, Any] = {"protocol": "mqtt", "details": {"connack_code": code}}
    if code == 0:
        row["authentication"] = si.AUTH_NOT_REQUIRED
        row["authentication_proof"] = "mqtt_anonymous_connect_accepted"
    elif code in {4, 5}:
        row["authentication"] = si.AUTH_REQUIRED
        row["authentication_proof"] = "mqtt_connect_not_authorized"
    elif code > 5:
        return None
    return row


AMQP_HEADER = b"AMQP\x00\x00\x09\x01"


def parse_amqp_start(data: bytes) -> dict[str, Any] | None:
    """Connection.Start (server properties name product and version) or a protocol header."""
    data = data or b""
    if data.startswith(b"AMQP") and len(data) >= 8:
        return {"protocol": "amqp", "details": {"offered_version": ".".join(str(b) for b in data[5:8])}}
    if len(data) < 12 or data[0] != 1 or data[1:3] != b"\x00\x00":
        return None
    if data[7:11] != b"\x00\x0a\x00\x0a":  # class 10 (connection), method 10 (start)
        return None
    properties: dict[str, str] = {}
    try:
        offset = 13
        table_end = offset + 4 + struct.unpack_from(">I", data, offset)[0]
        offset += 4
        while offset < min(table_end, len(data)) and len(properties) < 16:
            key_length = data[offset]
            key = data[offset + 1:offset + 1 + key_length].decode("latin-1")
            offset += 1 + key_length
            kind = data[offset:offset + 1]
            offset += 1
            if kind == b"S":
                size = struct.unpack_from(">I", data, offset)[0]
                properties[key] = data[offset + 4:offset + 4 + min(size, 200)].decode("utf-8", "replace")
                offset += 4 + size
            elif kind == b"F":
                offset += 4 + struct.unpack_from(">I", data, offset)[0]
            elif kind == b"t":
                offset += 1
            else:
                break
    except (struct.error, IndexError):
        pass
    product = si.label(properties.get("product"), 80)
    version = si.label(properties.get("version"), 40)
    row: dict[str, Any] = {"protocol": "amqp", "product": product}
    if version and re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}[0-9A-Za-z.+-]{0,20}", version):
        row["version"] = re.match(r"^[0-9]+(?:\.[0-9]+){1,3}", version).group(0)
        row["version_reported"] = version
    return row


def modbus_device_id_request(transaction_id: int) -> bytes:
    # Read Device Identification (function 43 / MEI 14), basic objects: read-only.
    return struct.pack(">HHHB", transaction_id, 0, 5, 0) + b"\x2b\x0e\x01\x00"


def parse_modbus_reply(data: bytes, transaction_id: int) -> dict[str, Any] | None:
    data = data or b""
    if len(data) < 9:
        return None
    ident, protocol_id, length = struct.unpack_from(">HHH", data, 0)
    if ident != transaction_id or protocol_id != 0 or length < 3:
        return None
    function = data[7]
    if function == 0xAB:  # exception to function 43: still Modbus
        return {"protocol": "modbus", "details": {"exception_code": data[8]}}
    if function != 0x2B or len(data) < 14 or data[8] != 0x0E:
        return None
    objects: dict[int, str] = {}
    offset, count = 14, data[13]
    for _ in range(min(count, 8)):
        if offset + 2 > len(data):
            break
        object_id, size = data[offset], data[offset + 1]
        objects[object_id] = si.label(data[offset + 2:offset + 2 + size], 80) or ""
        offset += 2 + size
    vendor, product = objects.get(0), objects.get(1)
    row: dict[str, Any] = {"protocol": "modbus", "product": " ".join(x for x in (vendor, product) if x) or None}
    revision = objects.get(2)
    if revision:
        row["version_reported"] = revision
    return row


def enip_list_identity(context: bytes) -> bytes:
    return struct.pack("<HHII", 0x63, 0, 0, 0) + context + struct.pack("<I", 0)


def parse_enip_identity(data: bytes, context: bytes) -> dict[str, Any] | None:
    data = data or b""
    if len(data) < 24 or struct.unpack_from("<H", data, 0)[0] != 0x63 or data[12:20] != context:
        return None
    row: dict[str, Any] = {"protocol": "ethernet-ip", "details": {}}
    try:
        # item count (2), item type (2), item length (2), version (2), socket address (16)
        offset = 24 + 2 + 2 + 2 + 2 + 16
        vendor_id, device_type, product_code = struct.unpack_from("<HHH", data, offset)
        major, minor = data[offset + 6], data[offset + 7]
        name_length = data[offset + 14]
        name = si.label(data[offset + 15:offset + 15 + name_length], 80)
    except (struct.error, IndexError):
        return row
    row["product"] = name
    row["version_reported"] = f"{major}.{minor:03d}"
    row["details"] = {"vendor_id": vendor_id, "device_type": device_type, "product_code": product_code}
    return row


async def _mqtt_adapter(address: str, port: int, *, tls: bool, server_name: str | None) -> dict[str, Any] | None:
    connection = await _connect(address, port, tls=tls, server_name=server_name)
    if connection is None:
        return None
    try:
        await connection.send(MQTT_CONNECT)
        parsed = parse_mqtt_connack(await connection.read(limit=4, until=lambda data: len(data) >= 4))
        if parsed is None:
            return None
        if parsed.get("authentication") == si.AUTH_NOT_REQUIRED:
            try:
                await connection.send(b"\xe0\x00")  # DISCONNECT: nothing is subscribed or published
            except Exception:  # noqa: BLE001
                pass
        row = _identified(port, "tcp", "mqtt", "mqtts" if tls else "mqtt", **parsed)
        row["details"]["tls"] = tls
        return row
    finally:
        await connection.close()


async def adapter_mqtt(address: str, port: int, *, server_name: str | None = None) -> dict[str, Any] | None:
    return await _mqtt_adapter(address, port, tls=False, server_name=server_name)


async def adapter_mqtts(address: str, port: int, *, server_name: str | None = None) -> dict[str, Any] | None:
    return await _mqtt_adapter(address, port, tls=True, server_name=server_name)


async def adapter_amqp(address: str, port: int, *, server_name: str | None = None) -> dict[str, Any] | None:
    reply = await _one_exchange(address, port, AMQP_HEADER,
                                until=lambda data: data.startswith(b"AMQP") and len(data) >= 8 or data.endswith(b"\xce"))
    parsed = parse_amqp_start(reply or b"")
    return _identified(port, "tcp", "amqp", "amqp", **parsed) if parsed else None


async def adapter_modbus(address: str, port: int, *, server_name: str | None = None) -> dict[str, Any] | None:
    transaction_id = int.from_bytes(os.urandom(2), "big")
    reply = await _one_exchange(address, port, modbus_device_id_request(transaction_id),
                                until=lambda data: len(data) >= 6 and len(data) >= 6 + int.from_bytes(data[4:6], "big"))
    parsed = parse_modbus_reply(reply or b"", transaction_id)
    return _identified(port, "tcp", "modbus", "modbus", **parsed) if parsed else None


async def adapter_enip(address: str, port: int, *, server_name: str | None = None) -> dict[str, Any] | None:
    context = os.urandom(8)
    reply = await _one_exchange(address, port, enip_list_identity(context),
                                until=lambda data: len(data) >= 24 and len(data) >= 24 + int.from_bytes(data[2:4], "little"))
    parsed = parse_enip_identity(reply or b"", context)
    return _identified(port, "tcp", "ethernet-ip", "enip", **parsed) if parsed else None


TCP_ADAPTERS: Mapping[str, Callable[..., Awaitable[dict[str, Any] | None]]] = {
    "banner": adapter_banner, "http": adapter_http, "tls": adapter_tls, "redis": adapter_redis,
    "memcached": adapter_memcached, "mongodb": adapter_mongodb, "postgresql": adapter_postgresql,
    "rdp": adapter_rdp, "smb": adapter_smb, "openvpn": adapter_openvpn, "pptp": adapter_pptp,
    "mqtt": adapter_mqtt, "mqtts": adapter_mqtts, "amqp": adapter_amqp,
    "modbus": adapter_modbus, "enip": adapter_enip,
}


def adapter_order(port: int, hints: tuple[str | None, ...] = ()) -> list[str]:
    """The banner read first, then the hinted adapters, then the rest of the silent set."""
    order = ["banner"]
    for hint in (*hints, si.port_hint(port)):
        adapter = ADAPTER_FOR_SERVICE.get(str(hint or "").strip().lower())
        if adapter and adapter in TCP_ADAPTERS and adapter not in order:
            order.append(adapter)
    order.extend(name for name in SILENT_TCP_ADAPTERS if name not in order)
    return order


async def identify_tcp_service(
    address: str, port: int, *, hints: tuple[str | None, ...] = (), server_name: str | None = None,
    max_adapters: int = len(SILENT_TCP_ADAPTERS) + 1,
) -> dict[str, Any]:
    """Identify the protocol on one open TCP port of one authorized address.

    The banner is read first (and decides when the server speaks first); a silent listener is
    then offered one adapter at a time, the hinted ones first, each on a new connection. A
    listener nothing matched is ``not_identified`` (it answered) or ``inconclusive`` (silence).
    """
    port = int(port)
    answers: list[bytes] = []
    token = _ANSWERS.set(answers)
    try:
        return await _identify_tcp(address, port, hints, server_name, max_adapters, answers)
    finally:
        _ANSWERS.reset(token)


async def _identify_tcp(
    address: str, port: int, hints: tuple[str | None, ...], server_name: str | None,
    max_adapters: int, answers: list[bytes],
) -> dict[str, Any]:
    attempted: list[str] = []
    for name in adapter_order(port, hints)[:max(1, max_adapters)]:
        if name != "banner" and port in PAYLOAD_EXCLUDED_TCP_PORTS:
            row = _result(port, "tcp", si.STATUS_EXCLUDED, adapter=None,
                          details={"reason": PAYLOAD_EXCLUSION_REASON})
            row["adapters_attempted"] = attempted
            return row
        attempted.append(name)
        try:
            row = await TCP_ADAPTERS[name](address, port, server_name=server_name)
        except Exception:  # noqa: BLE001 -- a malformed answer fails one adapter, not the port
            row = None
        if row is None:
            continue
        if row["status"] == si.STATUS_UNREACHABLE:
            row["adapters_attempted"] = attempted
            return row
        row["adapters_attempted"] = attempted
        # Identified, excluded, or a banner nothing recognised: the listener spoke first, so
        # payloads would only be answered by the same unknown service.
        return row
    if answers:
        row = _result(port, "tcp", si.STATUS_UNIDENTIFIED, details={"answer_excerpt": excerpt(answers[0])})
    else:
        row = _result(port, "tcp", si.STATUS_SILENT)
    row["adapters_attempted"] = attempted
    return row


async def identify_udp_service(address: str, port: int, *, hints: tuple[str | None, ...] = ()) -> dict[str, Any]:
    """One bounded datagram per adapter. No reply is inconclusive, never a confirmation."""
    port = int(port)
    names = [ADAPTER_FOR_SERVICE.get(str(item or "").lower()) for item in (*hints, si.port_hint(port))]
    if "wireguard" in names:
        # WireGuard answers nothing to an unauthenticated initiator: it cannot be confirmed.
        return _result(port, "udp", si.STATUS_NOT_IDENTIFIABLE, adapter="wireguard",
                       details={"reason": "silent_by_design"})
    order = [name for name in names if name in UDP_ADAPTERS]
    order = list(dict.fromkeys(order or UDP_ADAPTERS))
    attempted: list[str] = []
    for name in order:
        attempted.append(name)
        try:
            parsed = await _udp_adapter(name, address, port)
        except Exception:  # noqa: BLE001 -- a malformed datagram fails one adapter, not the port
            parsed = None
        if parsed:
            row = _identified(port, "udp", parsed["protocol"], name, **parsed)
            row["adapters_attempted"] = attempted
            return row
    row = _result(port, "udp", si.STATUS_SILENT)
    row["adapters_attempted"] = attempted
    return row


async def _udp_adapter(name: str, address: str, port: int) -> dict[str, Any] | None:
    """One bounded datagram exchange; the reply must echo the identifier the probe carried."""
    if name == "dns":
        transaction_id = int.from_bytes(os.urandom(2), "big")
        reply = await _udp_exchange(address, port, dns_version_query(transaction_id))
        return parse_dns_reply(reply or b"", transaction_id)
    if name == "ntp":
        return parse_ntp_reply(await _udp_exchange(address, port, NTP_REQUEST) or b"")
    if name == "ike":
        cookie = os.urandom(8)
        payload = ike_main_mode_request(cookie)
        if port == 4500:
            payload = b"\x00\x00\x00\x00" + payload  # NAT-T non-ESP marker
        return parse_ike_reply(await _udp_exchange(address, port, payload) or b"", cookie)
    if name == "openvpn":
        session_id = os.urandom(8)
        reply = await _udp_exchange(address, port, openvpn_reset(session_id))
        return parse_openvpn_reply(reply or b"", session_id, tcp=False)
    return None


def public_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """An adapter row reduced to the allowlisted identity fields plus bounded details."""
    details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
    safe_details: dict[str, Any] = {}
    for key, value in list(details.items())[:24]:
        if isinstance(value, bool) or isinstance(value, int) and not isinstance(value, bool):
            safe_details[str(key)[:40]] = value
        elif isinstance(value, str):
            safe_details[str(key)[:40]] = si.label(value, 200)
        elif isinstance(value, list):
            safe_details[str(key)[:40]] = [
                item if isinstance(item, int) else si.label(item, 40) for item in value[:32]
            ]
    return {
        "schema_version": si.SCHEMA_VERSION,
        "transport": row.get("transport"),
        "port": row.get("port"),
        "status": row.get("status") if row.get("status") in si.STATUSES else si.STATUS_UNIDENTIFIED,
        "adapter": si.label(row.get("adapter"), 40),
        "adapters_attempted": [si.label(item, 40) for item in row.get("adapters_attempted") or []][:16],
        **si.identity_fields(row),
        "details": safe_details,
    }


__all__ = [
    "PAYLOAD_EXCLUDED_TCP_PORTS", "PAYLOAD_EXCLUSION_REASON", "adapter_order",
    "identify_tcp_service", "identify_udp_service", "public_row",
]
