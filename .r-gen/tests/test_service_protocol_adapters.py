"""Protocol adapters identify by handshake, never by port, and never call a handshake access.

Every server here is a local fixture speaking hostile or misleading bytes: a fake service on a
familiar port, a real protocol on an unusual one, a database that answers its handshake but
refuses commands.
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from scanner.scanner_tools import service_identity as si
from scanner.scanner_tools import service_protocols as sp


def _serve(handler):
    """Run ``handler(reader, writer)`` on 127.0.0.1 and an ephemeral port; yield the port."""

    class Server:
        async def __aenter__(self):
            self.server = await asyncio.start_server(handler, "127.0.0.1", 0)
            self.port = self.server.sockets[0].getsockname()[1]
            return self.port

        async def __aexit__(self, *exc):
            self.server.close()
            await self.server.wait_closed()

    return Server()


def _scripted(greeting: bytes = b"", replies=None, *, close_after_reply: bool = False):
    """Send ``greeting``, then answer each received chunk by ``replies(data) -> bytes|None``."""

    async def handler(reader, writer):
        try:
            if greeting:
                writer.write(greeting)
                await writer.drain()
            while True:
                data = await asyncio.wait_for(reader.read(4096), 5)
                if not data:
                    break
                answer = replies(data) if replies else None
                if answer is None:
                    continue
                writer.write(answer)
                await writer.drain()
                if close_after_reply:
                    break
        except Exception:
            pass
        finally:
            writer.close()

    return handler


def _identify(handler, **kwargs):
    async def run():
        async with _serve(handler) as port:
            return await sp.identify_tcp_service("127.0.0.1", port, **kwargs)

    return asyncio.run(run())


def _bson(fields: dict) -> bytes:
    body = b""
    for name, value in fields.items():
        key = name.encode() + b"\x00"
        if isinstance(value, bool):
            body += b"\x08" + key + (b"\x01" if value else b"\x00")
        elif isinstance(value, float):
            body += b"\x01" + key + struct.pack("<d", value)
        elif isinstance(value, int):
            body += b"\x10" + key + struct.pack("<i", value)
        elif isinstance(value, str):
            raw = value.encode() + b"\x00"
            body += b"\x02" + key + struct.pack("<i", len(raw)) + raw
        elif isinstance(value, list):
            body += b"\x04" + key + _bson({str(i): item for i, item in enumerate(value)})
        elif isinstance(value, dict):
            body += b"\x03" + key + _bson(value)
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


def _op_msg_reply(request: bytes, document: dict) -> bytes:
    request_id = struct.unpack_from("<i", request, 4)[0]
    body = struct.pack("<I", 0) + b"\x00" + _bson(document)
    return struct.pack("<iiii", 16 + len(body), 99, request_id, 2013) + body


def _mongo(list_databases: dict):
    def replies(data: bytes):
        if b"hello\x00" in data:
            return _op_msg_reply(data, {"isWritablePrimary": True, "maxWireVersion": 21, "ok": 1.0})
        if b"buildInfo\x00" in data:
            return _op_msg_reply(data, {"version": "7.0.5-ent", "ok": 1.0})
        if b"listDatabases\x00" in data:
            return _op_msg_reply(data, list_databases)
        return None

    return _scripted(replies=replies)


# --- a fake service on a familiar port is not mislabeled --------------------------------------

def test_a_silent_listener_is_inconclusive_not_the_port_service():
    row = _identify(_scripted(), hints=("redis",), max_adapters=4)
    assert row["status"] == si.STATUS_SILENT
    assert row["protocol"] is None and row["authentication"] == si.AUTH_NOT_TESTED


def test_a_fake_redis_that_answers_anything_is_not_redis():
    row = _identify(_scripted(replies=lambda _data: b"OK hello there\r\n"), hints=("redis",), max_adapters=3)
    assert row["protocol"] is None
    assert row["status"] == si.STATUS_UNIDENTIFIED
    assert row["authentication"] == si.AUTH_NOT_TESTED


def test_a_fake_banner_on_a_familiar_port_is_kept_as_an_excerpt_only():
    row = _identify(_scripted(b"Welcome to totally-ssh\x1b[2J\r\n"), hints=("ssh",))
    assert row["status"] == si.STATUS_UNIDENTIFIED and row["protocol"] is None
    assert "\x1b" not in row["details"]["banner_excerpt"]


# --- a real service on an unusual port is recognised -----------------------------------------

def test_ssh_on_an_unusual_port_keeps_the_full_build_suffix():
    row = _identify(_scripted(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"))
    assert row["protocol"] == "ssh" and row["product"] == "OpenSSH"
    assert row["version"] == "8.9p1"
    assert row["version_reported"] == "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    assert row["authentication"] == si.AUTH_NOT_TESTED


def test_redis_on_an_unusual_port_is_found_without_a_hint_and_access_is_proven_by_info():
    info = b"# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\nexecutable:/srv/secret\r\n"
    reply = b"$" + str(len(info)).encode() + b"\r\n" + info + b"\r\n"
    row = _identify(_scripted(replies=lambda data: reply if b"INFO" in data else None))
    assert row["protocol"] == "redis" and row["product"] == "Redis" and row["version"] == "7.2.4"
    assert row["authentication"] == si.AUTH_NOT_REQUIRED
    assert row["authentication_proof"] == "redis_info_without_credentials"
    assert "secret" not in repr(sp.public_row(row))


def test_redis_requiring_a_password_is_identified_and_reported_as_required():
    row = _identify(_scripted(replies=lambda _d: b"-NOAUTH Authentication required.\r\n"), hints=("redis",))
    assert row["protocol"] == "redis"
    assert row["authentication"] == si.AUTH_REQUIRED and row["authentication_proof"] == "redis_noauth"


# --- a handshake-only database is not unauthenticated access ---------------------------------

def test_mongodb_answering_hello_but_refusing_list_databases_is_not_open():
    row = _identify(_mongo({"ok": 0.0, "errmsg": "command listDatabases requires authentication", "code": 13}),
                    hints=("mongodb",))
    assert row["protocol"] == "mongodb" and row["version"] == "7.0.5"
    assert row["version_reported"] == "7.0.5-ent"
    assert row["authentication"] == si.AUTH_REQUIRED
    assert row["authentication_proof"] == "mongodb_unauthorized"


def test_mongodb_listing_databases_without_credentials_is_proven_open():
    row = _identify(_mongo({"databases": [{"name": "a"}, {"name": "b"}], "ok": 1.0}), hints=("mongodb",))
    assert row["authentication"] == si.AUTH_NOT_REQUIRED
    assert row["authentication_proof"] == "mongodb_list_databases_without_credentials"
    assert row["details"]["database_count"] == 2


def test_mongodb_with_an_unexpected_list_reply_stays_not_tested():
    row = _identify(_mongo({"ok": 1.0}), hints=("mongodb",))
    assert row["protocol"] == "mongodb" and row["authentication"] == si.AUTH_NOT_TESTED


def test_mysql_greeting_identifies_without_claiming_access():
    version = b"5.5.5-10.11.6-MariaDB-0+deb12u1"
    payload = b"\x0a" + version + b"\x00" + b"\x01\x00\x00\x00" + b"x" * 20
    greeting = len(payload).to_bytes(3, "little") + b"\x00" + payload
    row = _identify(_scripted(greeting))
    assert row["protocol"] == "mysql" and row["product"] == "MariaDB"
    assert row["version"] == "10.11.6" and row["version_reported"] == version.decode()
    assert row["authentication"] == si.AUTH_NOT_TESTED


def test_memcached_stats_is_the_access_proof():
    def replies(data):
        if data.startswith(b"version"):
            return b"VERSION 1.6.21\r\n"
        if data.startswith(b"stats"):
            return b"STAT pid 1\r\nSTAT uptime 5\r\nEND\r\n"
        return None

    row = _identify(_scripted(replies=replies), hints=("memcached",))
    assert row["protocol"] == "memcached" and row["version"] == "1.6.21"
    assert row["authentication_proof"] == "memcached_stats_without_credentials"


def test_elasticsearch_root_banner_alone_is_metadata_not_access():
    root = (b'{"name":"n","cluster_name":"c","version":{"number":"8.12.0"},'
            b'"tagline":"You Know, for Search"}')

    def replies(data):
        if data.startswith(b"GET / "):
            return b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + root
        if data.startswith(b"GET /_cat/indices"):
            return b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
        return None

    row = _identify(_scripted(replies=replies, close_after_reply=True), hints=("elasticsearch",))
    assert row["product"] == "Elasticsearch" and row["version"] == "8.12.0"
    assert row["authentication"] == si.AUTH_REQUIRED
    assert row["details"]["cluster_metadata_without_credentials"] is True


def test_smtp_starttls_offer_is_recorded():
    def replies(data):
        if data.startswith(b"EHLO"):
            return b"250-mail.example.test\r\n250-PIPELINING\r\n250 SIZE 1000\r\n"
        return None

    row = _identify(_scripted(b"220 mail.example.test ESMTP Exim 4.96 #2 Ubuntu\r\n", replies))
    assert row["protocol"] == "smtp" and row["product"] == "Exim" and row["version"] == "4.96"
    assert row["version_reported"] == "Exim 4.96"
    assert row["details"]["starttls"] == "not_offered"


def test_ftp_is_told_from_smtp_by_its_answer():
    def replies(data):
        if data.startswith(b"FEAT"):
            return b"211-Features:\r\n AUTH TLS\r\n211 End\r\n"
        return None

    row = _identify(_scripted(b"220 (vsFTPd 3.0.5)\r\n", replies))
    assert row["protocol"] == "ftp" and row["product"] == "vsftpd" and row["version"] == "3.0.5"
    assert row["details"]["auth_tls_offered"] is True


def test_vnc_none_security_is_proven_by_the_security_result():
    def replies(data):
        if data.startswith(b"RFB "):
            return b"\x01\x01"
        if data == b"\x01":
            return b"\x00\x00\x00\x00"
        return None

    row = _identify(_scripted(b"RFB 003.008\n", replies))
    assert row["protocol"] == "vnc"
    assert row["authentication_proof"] == "vnc_security_none_accepted"


def test_printer_raw_ports_receive_no_payload(monkeypatch):
    received = []

    async def handler(reader, writer):
        try:
            data = await asyncio.wait_for(reader.read(4096), 4)
            received.append(data)
        except Exception:
            pass
        writer.close()

    async def run():
        async with _serve(handler) as port:
            monkeypatch.setattr(sp, "PAYLOAD_EXCLUDED_TCP_PORTS", frozenset({port}))
            return await sp.identify_tcp_service("127.0.0.1", port, hints=("redis",))

    row = asyncio.run(run())
    assert row["status"] == si.STATUS_EXCLUDED
    assert row["details"]["reason"] == sp.PAYLOAD_EXCLUSION_REASON
    assert received in ([], [b""])


def test_wireguard_is_never_confirmed():
    row = asyncio.run(sp.identify_udp_service("127.0.0.1", 51820))
    assert row["status"] == si.STATUS_NOT_IDENTIFIABLE and row["protocol"] is None


# --- pure parsers ----------------------------------------------------------------------------

def test_rdp_nla_required_and_tls_selected():
    nla = bytes.fromhex("030000130ed00000123400" + "03000800" + "05000000")
    assert sp.parse_rdp_confirm(nla)["authentication_proof"] == "rdp_nla_required"
    tls = bytes.fromhex("030000130ed00000123400" + "02000800" + "01000000")
    parsed = sp.parse_rdp_confirm(tls)
    assert parsed["details"]["selected_security"] == "tls" and "authentication" not in parsed
    assert sp.parse_rdp_confirm(b"\x03\x00\x00\x0bHELLO") is None


def test_postgres_refusal_names_the_protocol_range_but_no_version():
    fields = b"SFATAL\x00VFATAL\x00C0A000\x00Munsupported frontend protocol 9999.0: server supports 3.0 to 3.2\x00\x00"
    message = b"E" + struct.pack(">i", len(fields) + 4) + fields
    parsed = sp.parse_postgres_reply(message)
    assert parsed["protocol"] == "postgresql" and "version" not in parsed
    assert parsed["details"]["protocol_versions"] == "3.0-3.2"
    assert sp.parse_postgres_reply(b"Ehello world") is None


def test_smb2_negotiate_reply():
    header = b"\xfeSMB" + struct.pack("<H", 64) + b"\x00" * 6 + struct.pack("<HH", 0, 1) + b"\x00" * 48
    body = struct.pack("<HHH", 65, 0x03, 0x0302) + b"\x00" * 58
    message = header + body
    parsed = sp.parse_smb2_negotiate(b"\x00" + len(message).to_bytes(3, "big") + message)
    assert parsed["details"] == {"status": "0x00000000", "dialect": "3.0.2", "signing_required": True}


def test_dns_version_bind_reply():
    query = sp.dns_version_query(0x1234)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 16, 3, 0, 17) + bytes([16]) + b"9.18.24-1-Debian"
    reply = struct.pack(">HHHHHH", 0x1234, 0x8400, 1, 1, 0, 0) + query[12:] + answer
    parsed = sp.parse_dns_reply(reply, 0x1234)
    assert parsed["product"] == "ISC BIND" and parsed["version"] == "9.18.24"
    assert sp.parse_dns_reply(reply, 0x9999) is None


def test_ike_and_openvpn_replies_must_echo_our_identifiers():
    cookie = b"12345678"
    reply = cookie + b"R" * 8 + bytes([11, 0x10, 2, 0]) + b"\x00" * 8
    assert sp.parse_ike_reply(reply, cookie)["details"]["response"] == "notification"
    assert sp.parse_ike_reply(reply, b"other!!!") is None
    session = b"abcdefgh"
    server = bytes([0x40]) + b"S" * 8 + b"\x01" + b"\x00\x00\x00\x00" + session + b"\x00\x00\x00\x00"
    assert sp.parse_openvpn_reply(server, session, tcp=False)["protocol"] == "openvpn"
    assert sp.parse_openvpn_reply(server, b"zzzzzzzz", tcp=False) is None


def test_ntp_reply_needs_server_mode():
    assert sp.parse_ntp_reply(bytes([0x24, 2]) + b"\x00" * 46)["details"]["stratum"] == 2
    assert sp.parse_ntp_reply(bytes([0x23]) + b"\x00" * 47) is None


@pytest.mark.parametrize("port,hint,first", [(6379, None, "redis"), (8080, "ssh", "banner")])
def test_the_port_only_orders_the_adapters(port, hint, first):
    order = sp.adapter_order(port, (hint,))
    assert order[0] == "banner"
    if first != "banner":
        assert order[1] == first
    assert set(sp.SILENT_TCP_ADAPTERS) <= set(order)


def test_mqtt_anonymous_connect_is_the_access_proof():
    def replies(data):
        if data.startswith(b"\x10"):
            assert data[1] == len(data) - 2  # a well-formed CONNECT
            return b"\x20\x02\x00\x00"
        return None

    row = _identify(_scripted(replies=replies), hints=("mqtt",))
    assert row["protocol"] == "mqtt"
    assert row["authentication_proof"] == "mqtt_anonymous_connect_accepted"
    refused = sp.parse_mqtt_connack(b"\x20\x02\x00\x05")
    assert refused["authentication"] == si.AUTH_REQUIRED


def test_amqp_start_names_product_and_version():
    def table(entries):
        body = b"".join(bytes([len(k)]) + k + b"S" + struct.pack(">I", len(v)) + v for k, v in entries)
        return struct.pack(">I", len(body)) + body

    payload = b"\x00\x0a\x00\x0a\x00\x09" + table([(b"product", b"RabbitMQ"), (b"version", b"3.12.13")])
    frame = b"\x01\x00\x00" + struct.pack(">I", len(payload)) + payload + b"\xce"
    parsed = sp.parse_amqp_start(frame)
    assert parsed["product"] == "RabbitMQ" and parsed["version"] == "3.12.13"


def test_modbus_device_identification_and_exception():
    reply = struct.pack(">HHHB", 7, 0, 20, 0) + b"\x2b\x0e\x01\x01\x00\x00\x02" + b"\x00\x07Siemens" + b"\x01\x03S71"
    parsed = sp.parse_modbus_reply(reply, 7)
    assert parsed["protocol"] == "modbus" and parsed["product"] == "Siemens S71"
    assert sp.parse_modbus_reply(struct.pack(">HHHB", 7, 0, 3, 0) + b"\xab\x01", 7)["protocol"] == "modbus"
    assert sp.parse_modbus_reply(reply, 8) is None


def test_industrial_adapters_are_never_tried_on_an_unknown_port():
    order = sp.adapter_order(40000, ())
    assert "modbus" not in order and "enip" not in order
    assert "modbus" in sp.adapter_order(502, ())


def test_mongodb_answering_http_on_its_driver_port_is_not_an_http_service():
    reply = (b"HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n"
             b"It looks like you are trying to access MongoDB over HTTP on the native driver port.\n")

    def replies(data):
        if data.startswith(b"GET "):
            return reply
        if b"hello\x00" in data:
            return _op_msg_reply(data, {"isWritablePrimary": True, "ok": 1.0})
        return None

    row = _identify(_scripted(replies=replies, close_after_reply=True), max_adapters=8)
    assert row["protocol"] == "mongodb"


def test_a_chunked_index_listing_is_still_the_access_proof():
    root = b'{"version":{"number":"8.15.3"},"tagline":"You Know, for Search"}'

    def replies(data):
        if data.startswith(b"GET / "):
            return b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(root) + root
        if data.startswith(b"GET /_cat/indices"):
            return b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n[]\r\n0\r\n\r\n"
        return None

    row = _identify(_scripted(replies=replies, close_after_reply=True), hints=("elasticsearch",))
    assert row["authentication_proof"] == "elasticsearch_index_listing_without_credentials"


def test_only_redis_own_refusals_count_as_redis():
    assert sp.parse_redis_info(b"-ERR unknown command 'INFO', with args beginning with: 'server' \r\n")["protocol"] == "redis"
    assert sp.parse_redis_info(b"-ERR whatever\r\n") is None


def test_deeply_nested_bson_from_a_hostile_server_is_not_recursed():
    document = b"\x05\x00\x00\x00\x00"
    for _ in range(3000):
        body = b"\x03a\x00" + document
        document = struct.pack("<i", len(body) + 5) + body + b"\x00"
    parsed = sp.bson_top_level(document)
    assert parsed == {"a": {"elements": 1}}
