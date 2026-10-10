"""Withheld values: COPY block positions, archive-format dumps, URL cuts, CDATA, escapes, the
resource head read and the sealed knowledge budget.

Every value below is a synthetic unit fixture, never a real secret.
"""

from __future__ import annotations

import asyncio
import copy
import json
import re
import struct
import time
import uuid

import httpx
import pytest
from runtime.hunt_http_exchange import (
    MAX_PRIVATE_RESULT_BYTES,
    _fit_private_payload,
    _knowledge_entries,
    persist_withheld_values,
    prepare_http_exchange,
    sealed_hunt_knowledge,
    withholding_operation,
)
from runtime.string_escapes import unescape_copy_text, unescape_js, unescape_php, unescape_yaml_double

from api.capabilities import artifact as artifact_capability
from api.capabilities.http import WorkerPrivateHTTPResponse
from tests.test_hunt_withheld_values_review import (
    ACTION,
    HUNT,
    RUN,
    TARGET,
    _ActionRows,
    _collect,
    _hunt_inspect_path,
    _KnowledgeRows,
    _range_server,
    masking,
)


@pytest.fixture
def encryption_key(monkeypatch, tmp_path):
    import secret_store
    from cryptography.fernet import Fernet

    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(secret_store, "_loaded", False)
    monkeypatch.setattr(secret_store, "_fernet", None)


class _RecentFirstRows(_KnowledgeRows):
    """The sealed rows as the worker's query returns them: the most recently completed first."""

    async def fetch(self, sql, *args):
        return [row for row in reversed(list(self.rows.values())) if row["private_http_result"]]


# --- A COPY block seen open earlier never lends its columns to a later block -------------------

def _two_table_dump(audit_rows: int = 30_000, user_rows: int = 60_000) -> bytes:
    parts = ["--\n-- PostgreSQL database dump\n--\n",
             "COPY public.audit (id, email, name, created_at) FROM stdin;\n"]
    parts += [f"{i}\ta{i}@fixture.test\tAlice {i}\t2024-02-19 14:07:31\n" for i in range(audit_rows)]
    parts.append("\\.\n\n")
    parts.append("COPY public.users (id, email, password, created_at) FROM stdin;\n")
    parts += [f"{i}\tu{i}@fixture.test\tFx{i}TwoPass!q\t2024-02-19 14:07:31\n" for i in range(user_rows)]
    parts.append("\\.\n")
    return "".join(parts).encode()


@pytest.mark.parametrize("path", ["/download?id=7", "/backup.sql"])
@pytest.mark.parametrize("head_first", [False, True])
def test_windows_in_a_later_same_width_block_never_take_the_earlier_blocks_columns(
    monkeypatch, encryption_key, path, head_first,
):
    document = _two_table_dump()
    conn = _RecentFirstRows()
    if head_first:
        _hunt_inspect_path(monkeypatch, document, path, 0, conn)
    for offset in (len(document) - 900_000, len(document) - 300_000):
        result, _seen = _hunt_inspect_path(monkeypatch, document, path, offset, conn)
        text = json.dumps(result)
        assert not re.search(r"Fx\d+TwoPass!q", text), (path, head_first, offset)
        sample = result["observation"]["text_sample"]
        assert "@fixture.test" in sample and "2024-02-19 14:07:31" in sample


def test_copy_block_positions_follow_what_was_read():
    document = _two_table_dump(audit_rows=2_000, user_rows=2_000)
    users_header = document.index(b"COPY public.users")
    users_rows = document.index(b"\n", users_header) + 1
    audit_end = document.index(b"\\.\n")
    tables: dict[str, list[str]] = {}
    masking.track_copy_blocks(tables, 0, document[:4_096])  # a head read: audit is open
    assert masking.copy_block_at(tables, 2_000) == "audit"
    assert masking.copy_block_at(tables, 50_000) is None  # past what was read: not known
    masking.track_copy_blocks(tables, 4_096, document[4_096:8_192])  # a contiguous read
    assert masking.copy_block_at(tables, 8_000) == "audit"
    # A read that shows audit's end and the users header: users is open from its first row.
    masking.track_copy_blocks(tables, audit_end - 100, document[audit_end - 100:users_rows + 500])
    assert masking.copy_block_at(tables, users_rows + 100) == "users"
    assert masking.copy_block_at(tables, audit_end + 2) is None  # between the blocks


def test_rows_known_inside_their_block_keep_exact_columns_and_others_fail_closed():
    header = "COPY public.audit (id, email, name, note) FROM stdin;\n"
    rows = "".join(f"{i}\ta{i}@fixture.test\tAlice Smith {i}\tFx{i}Note!q\n" for i in range(50))
    tables: dict[str, list[str]] = {"copy:audit": ["id", "email", "name", "note"]}
    masking.track_copy_blocks(tables, 0, (header + rows).encode())
    window = rows[len(rows) // 2:]
    position = len(header) + len(rows) // 2

    def masked(block_position):
        collector = masking.WithheldValues(ACTION)
        collector.sql_path, collector.sql_tables, collector.sql_dump_like = "/x", {"/x": tables}, True
        collector.copy_block = masking.copy_block_at(tables, block_position)
        with masking.collecting_withheld_values(collector):
            return mask_body_text(window)

    inside = masked(position)
    assert "Alice Smith 40" in inside and "Fx40Note!q" in inside  # the note column is not secret
    unknown = masked(position + 1_000_000)  # not known to be inside audit: by shape
    assert "Alice Smith 40" not in unknown and "Fx40Note!q" not in unknown
    assert "a40@fixture.test" in unknown


mask_body_text = masking.mask_body_text


# --- Archive-format dumps (pg_dump -Fc / -Ft) --------------------------------------------------

def _pg_string(text: str) -> bytes:
    raw = text.encode()
    return b"\x00" + struct.pack("<i", len(raw)) + raw


def _tar_header(name: str, size: int) -> bytes:
    header = (name.encode().ljust(100, b"\0") + b"0000600\0" + b"0000000\0" * 2
              + f"{size:011o}\0".encode() + b"0" * 12)
    return header.ljust(512, b"\0")


_TOC_STATEMENTS = (
    "SET client_encoding = 'UTF8';\n",
    "CREATE TABLE public.users (\n    id integer,\n    email text,\n    password text\n);\n",
    "COPY public.users (id, email, password) FROM stdin;\n",
)


def _toc() -> bytes:
    toc = b"PGDMP\x01\x10\x00\x04\x08\x01\x03" + b"\0" * 40
    for statement in _TOC_STATEMENTS:
        toc += b"\x00\x00\x00\x00\x00" + _pg_string("TABLE") + _pg_string(statement) + b"\x00" * 20
    return toc


def _pg_tar(rows: int = 60_000) -> bytes:
    toc = _toc()
    data = "".join(f"{i}\tu{i}@fixture.test\tFx{i}TarPass!q\n" for i in range(rows)).encode() + b"\\.\n"
    return (_tar_header("toc.dat", len(toc)) + toc.ljust(-(-len(toc) // 512) * 512, b"\0")
            + _tar_header("3001.dat", len(data)) + data)


def _pg_custom_uncompressed(rows: int = 60_000) -> bytes:
    data = "".join(f"{i}\tu{i}@fixture.test\tFx{i}CustomPass!q\n" for i in range(rows)).encode()
    return _toc() + b"\x01\x02\x00\x00\x00" + data + b"\\.\n"


@pytest.mark.parametrize("build", [_pg_tar, _pg_custom_uncompressed])
def test_archive_format_dump_heads_read_as_dumps(build):
    head = build(200)[:65_536].decode("utf-8", errors="replace")
    assert masking.looks_like_dump_head(head)
    assert masking.looks_like_dump_head("\x00\x07TABLE\x00" + _TOC_STATEMENTS[2])  # unanchored
    assert not masking.looks_like_dump_head("id\tname\n1\tAlice\n2\tBob\n")


@pytest.mark.parametrize(("build", "pattern"), [
    (_pg_tar, r"Fx\d+TarPass!q"), (_pg_custom_uncompressed, r"Fx\d+CustomPass!q"),
])
def test_archive_format_dump_rows_never_leak(monkeypatch, encryption_key, build, pattern):
    document = build()
    conn = _RecentFirstRows()
    for offset in (200_000, 900_000, 1_500_000):
        result, _seen = _hunt_inspect_path(
            monkeypatch, document, "/files/7", offset, conn, {"content-type": "application/octet-stream"})
        assert not re.search(pattern, json.dumps(result)), offset
        assert "@fixture.test" in result["observation"]["text_sample"]


# --- Found values are searched for with and without surrounding whitespace ----------------------

def test_a_found_value_with_whitespace_is_withheld_where_it_is_echoed_trimmed():
    collector = masking.WithheldValues(ACTION)
    collector.bind_known([" Fake9Pass77x ", "Other8Pass66y\t"], found=True)
    with masking.collecting_withheld_values(collector):
        masked = mask_body_text("Welcome back, Fake9Pass77x! and Other8Pass66y.")
    assert "Fake9Pass77x" not in masked and "Other8Pass66y" not in masked
    assert collector.found[:4] == [" Fake9Pass77x ", "Fake9Pass77x", "Other8Pass66y\t", "Other8Pass66y"]
    collector = masking.WithheldValues(ACTION)
    collector.bind_known(["  abcde  "], found=True)  # the trimmed form is too short to search for
    assert collector.found == ["  abcde  "]


# --- URL fields: masked whole before they are cut, and every marker has its entry ---------------

TOKEN = "FxTok" + "Z9" * 300  # longer than any URL field's cut


def _http(monkeypatch, handler, args):
    from api.capabilities.http import execute_bound_http_request
    from runtime.models import TargetBinding

    class _MockClient(httpx.AsyncClient):
        def __init__(self, *items, **kwargs):
            kwargs.pop("transport", None)
            super().__init__(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _MockClient)
    target = TargetBinding(
        target_id="t", target_kind="web", canonical_host="shop.test",
        allowed_origins=("https://shop.test",), allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("shop.test",))

    async def operation():
        return await execute_bound_http_request(
            "https://shop.test", args, target=target, allow_bound_origin_redirects=True)

    wrapped, collector = withholding_operation("http.request", ACTION, operation)
    return asyncio.run(wrapped()), collector


def _redirect_to(location):
    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": location})
        return httpx.Response(200, content=b"ok")
    return handler


def test_a_long_location_token_is_sealed_whole_with_one_reference(monkeypatch):
    location = "/cb?pad=" + "p" * 300 + f"&code={TOKEN}"
    result, collector = _http(monkeypatch, _redirect_to(location), {
        "method": "GET", "path": "/start", "follow_redirects": True})
    assert collector.values == [TOKEN]
    assert result["redirect_chain"][0]["location"].endswith("&code=[withheld:1]")
    assert result["response"]["final_url"].endswith("&code=[withheld:1]")
    entries = result["response"]["withheld_values"]
    assert [entry["marker"] for entry in entries] == ["[withheld:1]"] and entries[0]["length"] == len(TOKEN)


def test_a_cut_through_a_reference_shows_no_reference(monkeypatch):
    # The masked location puts the marker across the 500-character cut.
    location = "/cb?pad=" + "p" * 481 + f"&code={TOKEN}"
    result, _collector = _http(monkeypatch, _redirect_to(location), {
        "method": "GET", "path": "/start", "follow_redirects": False})
    shown = result["response"]["location"]
    assert len(shown) <= 500 and shown.endswith("&code=***") and "[with" not in shown
    assert TOKEN[:20] not in json.dumps(result)


def test_markers_in_url_fields_have_entries(monkeypatch):
    result, _collector = _http(monkeypatch, _redirect_to(f"/cb?code={TOKEN[:40]}"), {
        "method": "GET", "path": "/start", "follow_redirects": False})
    assert result["response"]["location"] == "/cb?code=[withheld:1]"
    assert [entry["marker"] for entry in result["response"]["withheld_values"]] == ["[withheld:1]"]


def test_csp_report_uri_tokens_are_withheld(monkeypatch):
    secret = "FxCspSecret0123456789"

    def handler(request):
        return httpx.Response(200, content=b"ok", headers={
            "content-security-policy": f"default-src 'self'; report-uri https://r.example/csp?token={secret}",
            "content-security-policy-report-only": f"default-src 'none'; report-uri /csp?token={secret}"})

    result, collector = _http(monkeypatch, handler, {"method": "GET", "path": "/"})
    headers = result["response"]["security_headers"]
    assert secret not in json.dumps(result) and collector.values == [secret]
    assert headers["content-security-policy"].endswith("csp?token=[withheld:1]")
    assert headers["content-security-policy-report-only"].endswith("csp?token=[withheld:1]")
    assert result["response"]["withheld_values"][0]["marker"] == "[withheld:1]"


def test_without_a_collector_url_fields_are_only_cut():
    assert masking.bounded_public_url("/cb?code=" + TOKEN, 50) == ("/cb?code=" + TOKEN)[:50]


# --- CDATA-wrapped values ---------------------------------------------------------------------

@pytest.mark.parametrize(("body", "secret"), [
    ("<password><![CDATA[Cd9Pass77x]]></password>", "Cd9Pass77x"),
    ("<config>\n  <password>\n    <![CDATA[Cd<9]Pass77x]]>\n  </password>\n</config>", "Cd<9]Pass77x"),
    ('<property name="hibernate.connection.password"><![CDATA[Hb9&Pass77x]]></property>', "Hb9&Pass77x"),
    ("<table><tr><td>DB_PASSWORD</td><td><![CDATA[Td9<Pass77x]]></td></tr></table>", "Td9<Pass77x"),
])
def test_cdata_wrapped_values_are_withheld_exactly(body, secret):
    masked, collector = _collect(body)
    assert secret not in masked and collector.values == [secret]
    assert "[withheld:1]" in masked


# --- Escapes decoded by each format's grammar --------------------------------------------------

@pytest.mark.parametrize(("body", "secret"), [
    ('db:\n  password: "Ye\\t9Pass77x\\u00e9"\n', "Ye\t9Pass77xé"),
    ('db:\n  password: "Yx\\x419Pass\\$77"\n', "YxA9Pass\\$77"),  # an undefined escape keeps its backslash
    ('var cfg = {password: "Jd\\u00419Pass\\x4177"};', "JdA9PassA77"),
    ("var cfg = {password: 'Js\\q9Pass\\u{1F600}x'};", "Jsq9Pass\U0001F600x"),
    ('var c = {"api_key": ["Ja\\ud83d\\ude009Pass77"]};', "Ja\U0001F6009Pass77"),
    ("$cfg = ['password' => 'Ph\\n9Pass\\'77'];", "Ph\\n9Pass'77"),  # PHP single quotes
    ('$cfg = ["password" => "Pd\\x419Pass\\q77"];', "PdA9Pass\\q77"),
    ("define('DB_PASSWORD', 'Df\\t9Pass\\\\77');", "Df\\t9Pass\\77"),
    ("COPY public.users (id, password) FROM stdin;\n1\tFa\\x41ke9Pass\\101\\q\n\\.\n", "FaAke9PassAq"),
    ("COPY public.users (id, password) FROM stdin;\n1\tCp\\303\\2519Pass77\n\\.\n", "Cpé9Pass77"),
])
def test_escaped_values_are_sealed_as_the_server_holds_them(body, secret):
    _masked, collector = _collect(body)
    assert collector.values == [secret]


def test_escape_grammars_round_trip_into_the_request(encryption_key):
    body = 'db:\n  password: "Rt\\u00e9\\x419Pass77"\n'
    masked, collector = _collect(body)
    conn = _ActionRows()
    asyncio.run(persist_withheld_values(conn, run=RUN, action_id=ACTION, target=TARGET,
                                        values=collector, status="success", observations=[masked]))
    inputs, _headers, _exchange = asyncio.run(prepare_http_exchange(
        conn, run=RUN, action_id=uuid.uuid4(), target=TARGET, context={},
        policy={"active_testing": True, "allow_state_changing_http": True},
        values={"method": "POST", "path": "/login", "json_body": {"password": None},
                "request_bindings": [{"withheld_ref": f"withheld://hunt/{ACTION}/1", "body_pointer": "/password"}]},
        trusted_headers={}))
    assert inputs["json_body"]["password"] == "RtéA9Pass77"


def test_escape_decoders_are_exact():
    assert unescape_js("a\\0b\\tc\\'\\\"\\\\\\/") == "a\0b\tc'\"\\/"
    assert unescape_js("\\101\\x41\\u0041\\u{41}") == "AAAA"
    assert unescape_yaml_double("\\N\\_\\L\\P\\e\\ \\/") == "\x85\xa0\u2028\u2029\x1b /"
    assert unescape_yaml_double("\\U0001F600\\q") == "\U0001F600\\q"
    assert unescape_php("a\\nb\\'c\\\\", "'") == "a\\nb'c\\"
    assert unescape_php("\\101\\x41\\u{41}\\$\\q", '"') == "AAA$\\q"
    assert unescape_copy_text("\\b\\f\\n\\r\\t\\v\\\\\\.\\q\\7\\x7") == "\b\f\n\r\t\v\\.q\x07\x07"


# --- The resource head read -------------------------------------------------------------------

def _copy_dump(rows: int = 60_000) -> bytes:
    parts = ["COPY public.users (id, email, password, created_at) FROM stdin;\n"]
    parts += [f"{i}\tu{i}@fixture.test\tFx{i}HeadPass!q\t2024-02-19 14:07:31\n" for i in range(rows)]
    parts.append("\\.\n")
    return "".join(parts).encode()


def _failing_head_server(monkeypatch, document: bytes, seen: list, recorded: list | None = None):
    async def fake_execute(_target_url, args, **kwargs):
        start, end = (int(part) for part in args["headers"]["Range"].split("=")[1].split("-"))
        seen.append((start, end, kwargs.get("timeout_seconds")))
        if start == 0 and end == artifact_capability.HEAD_PROBE_BYTES - 1:
            kwargs["private_response_sink"](WorkerPrivateHTTPResponse(
                status_code=500, final_url="https://honey.fixture.test/x", _body=b"", _headers={}, _cookies={}))
            return {"ok": True}
        chunk = document[start:end + 1]
        kwargs["private_response_sink"](WorkerPrivateHTTPResponse(
            status_code=206, final_url="https://honey.fixture.test/x", _body=chunk,
            _headers={"content-type": "text/plain",
                      "content-range": f"bytes {start}-{start + len(chunk) - 1}/{len(document)}"},
            _cookies={}))
        return {"ok": True}

    monkeypatch.setattr(artifact_capability, "execute_bound_http_request", fake_execute)


def _inspect_action(conn, path, offset, recorder=None):
    action = str(uuid.uuid4())

    async def operation():
        return await artifact_capability.inspect_target_artifact(
            "https://honey.fixture.test", {"path": path, "offset": offset, "max_bytes": 16_384},
            target=TARGET, transaction_recorder=recorder)

    async def seed():
        return await sealed_hunt_knowledge(conn, run_id=HUNT, target=TARGET)

    wrapped, collector = withholding_operation("artifact.inspect", action, operation, seed)
    result = asyncio.run(wrapped())
    conn.rows[action] = {"status": "completed", "private_http_result": None}
    asyncio.run(persist_withheld_values(conn, run=RUN, action_id=action, target=TARGET, values=collector,
                                        status="success", observations=[result]))
    return result


def test_an_unreadable_head_is_asked_for_a_bounded_number_of_times(monkeypatch, encryption_key):
    document = _copy_dump()
    conn = _RecentFirstRows()
    seen: list = []
    _failing_head_server(monkeypatch, document, seen)
    charges = []
    for offset in (200_000, 300_000, 400_000, 500_000):
        result = _inspect_action(conn, "/download?id=7", offset)
        assert "HeadPass!q" not in json.dumps(result)  # fails closed every time
        charges.append(result["budget_consumed"]["http_requests"])
    heads = [item for item in seen if item[0] == 0]
    assert len(heads) == artifact_capability.MAX_HEAD_ATTEMPTS == 2
    assert charges == [2, 2, 1, 1]


def test_a_head_already_in_hand_is_not_read_again(monkeypatch, encryption_key):
    document = ("id\tname\tcreated\tstatus\n" + "".join(
        f"{i}\tAlice Smith {i}\t2024-01-0{1 + i % 9}\tactive\n" for i in range(20_000))).encode()
    seen: list = []
    _range_server(monkeypatch, document, seen)
    conn = _RecentFirstRows()
    result = _inspect_action(conn, "/export.tsv", 1_000)
    assert seen == [(0, 1_000 + 16_384 - 1)]  # the window's own read starts at byte 0
    assert result["budget_consumed"]["http_requests"] == 1
    assert "[withheld:" not in result["observation"]["text_sample"]
    _inspect_action(conn, "/export.tsv", 300_000)  # the verdict is remembered
    assert all(start != 0 for start, _end in seen[1:])


def test_the_head_read_is_archived_without_its_body(monkeypatch, encryption_key):
    document = _copy_dump()
    recorded: list = []

    async def fake_execute(_target_url, args, **kwargs):
        start, end = (int(part) for part in args["headers"]["Range"].split("=")[1].split("-"))
        chunk = document[start:end + 1]
        kwargs["transaction_recorder"]({
            "status_code": 206, "response_body": chunk, "response_body_bytes": len(chunk),
            "response_body_sha256": "x" * 64, "fidelity": "wire_request"})
        kwargs["private_response_sink"](WorkerPrivateHTTPResponse(
            status_code=206, final_url="https://honey.fixture.test/x", _body=chunk,
            _headers={"content-type": "text/plain",
                      "content-range": f"bytes {start}-{start + len(chunk) - 1}/{len(document)}"},
            _cookies={}))
        return {"ok": True}

    monkeypatch.setattr(artifact_capability, "execute_bound_http_request", fake_execute)
    result = _inspect_action(_RecentFirstRows(), "/download?id=7", 2_000_000, recorded.append)
    assert result["observation"]["resource_head_checked"]
    window, head = recorded
    assert window["fidelity"] == "wire_request_window" and len(window["response_body"]) == 16_384
    assert head["fidelity"] == "wire_request_metadata" and head["status_code"] == 206
    assert head["response_body"] is None and head["response_body_sha256"] is None


def test_both_requests_share_the_reserved_wall_time(monkeypatch, encryption_key):
    from runtime.capability_registry import CAPABILITY_REGISTRY

    reserved = CAPABILITY_REGISTRY.require("artifact.inspect").budget_cost["tool_wall_seconds"]
    assert reserved == artifact_capability.INSPECT_WALL_SECONDS
    document = _copy_dump()
    seen: list = []
    _range_server(monkeypatch, document, seen)
    collector = masking.WithheldValues(ACTION)
    collector.sql_path = "/download?id=7"
    span = document[200_000:216_384]

    async def check(deadline):
        with masking.collecting_withheld_values(collector):
            return await artifact_capability._check_resource_head(
                "https://honey.fixture.test", "/download?id=7", TARGET, 200_000, span, None,
                span_start=200_000, deadline=deadline)

    # Too little of the reservation left: no head read, the rows fail closed.
    assert asyncio.run(check(time.monotonic() + 1)) == 0 and seen == [] and collector.sql_dump_like
    collector.sql_dump_like = False
    calls: list = []
    real = artifact_capability._fetch_artifact

    async def spy(*args, **kwargs):
        calls.append(kwargs["timeout_seconds"])
        return await real(*args, **kwargs)

    monkeypatch.setattr(artifact_capability, "_fetch_artifact", spy)
    assert asyncio.run(check(time.monotonic() + 12.5)) == 1
    assert calls and calls[0] <= 12


# --- Sealed knowledge: verdicts first, this action's columns before older ones ------------------

def test_verdicts_and_new_columns_outlive_older_knowledge(encryption_key):
    collector = masking.WithheldValues(ACTION)
    collector.sql_tables = {"/old.sql": {
        f"table_{index}": [f"column_{index}_{column}" for column in range(60)] for index in range(200)}}
    collector.sql_seeded = copy.deepcopy(collector.sql_tables)
    collector.sql_tables["/new.sql"] = {
        "\0head": ["dump"], "\0copy_open": ["users", "120", "65536"],
        "users": ["id", "email", "password"]}
    collector.sql_tables["/old.sql"]["table_0"] = ["id", "password"]  # relearned this action
    conn = _ActionRows()
    sealing = asyncio.run(persist_withheld_values(
        conn, run=RUN, action_id=ACTION, target=TARGET, values=collector, status="success"))
    from secret_store import decrypt_secret
    payload = json.loads(decrypt_secret(conn.rows[ACTION]["private_http_result"]))
    assert sealing["not_retained"]["sql_tables"] > 0
    assert payload["sql_tables"]["/new.sql"] == collector.sql_tables["/new.sql"]
    assert payload["sql_tables"]["/old.sql"]["table_0"] == ["id", "password"]


def test_fit_evicts_the_last_entries_first():
    entries = _knowledge_entries(
        {"/a": {"\0head": ["dump"], "new": ["c"] * 10}}, {}, {"/a": {"older": ["d"] * 10}})
    assert [table for _path, table, _columns in entries] == ["\0head", "new", "older"]
    big = [("/a", f"t{index}", ["x" * 100] * 50) for index in range(40)]
    payload, _values, kept = _fit_private_payload({}, [], entries[:2] + big)
    assert kept < 42 and len(json.dumps(payload).encode()) <= MAX_PRIVATE_RESULT_BYTES
    assert list(payload["sql_tables"]["/a"])[:2] == ["\0head", "new"]
