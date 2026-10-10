"""Withheld values: schema-qualified tables, quoted identifiers, COPY block extents across reads
and resource versions, JSON-led bodies, unsendable values, dotenv escapes and URL userinfo.

Every value below is a synthetic unit fixture, never a real secret.
"""

from __future__ import annotations

import json
import re

import pytest

from tests.test_hunt_withheld_values_positions import _RecentFirstRows
from tests.test_hunt_withheld_values_review import (
    ACTION,
    _collect,
    _hunt_inspect_path,
    _inspect_at,
    masking,
)

SECRET = re.compile(r"Fx\d+BlockPass!q")


@pytest.fixture
def encryption_key(monkeypatch, tmp_path):
    import secret_store
    from cryptography.fernet import Fernet

    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(secret_store, "_loaded", False)
    monkeypatch.setattr(secret_store, "_fernet", None)


def _leaks(result) -> int:
    return len(SECRET.findall(json.dumps(result)))


def _rows(prefix: str, count: int, secret: bool) -> list[str]:
    return [f"{i}\t{prefix}{i}@fixture.test\t{f'Fx{i}BlockPass!q' if secret else f'Label {i}'}"
            f"\t2024-02-19 14:07:31\n" for i in range(count)]


_HEAD = "--\n-- PostgreSQL database dump\n--\n"


# --- The same table name in two schemas ---------------------------------------------------------

def test_same_table_name_in_two_schemas_keeps_its_own_columns(monkeypatch):
    parts = [_HEAD, "COPY auth.users (id, email, password, created_at) FROM stdin;\n"]
    parts += _rows("u", 5_000, True) + ["\\.\n\n"]
    public_header = len("".join(parts).encode())
    parts += ["COPY public.users (id, email, label, created_at) FROM stdin;\n"]
    parts += _rows("p", 100, False) + ["\\.\n"]
    document = "".join(parts).encode()
    collector = masking.WithheldValues(ACTION)
    first, _ = _inspect_at(monkeypatch, document, 0, 16_384, collector)  # auth.users opens
    second, _ = _inspect_at(monkeypatch, document, public_header + 1_000, 4_096, collector)
    third, _ = _inspect_at(monkeypatch, document, 16_384 + 65_536, 8_192, collector)  # inside auth
    tables = collector.sql_tables["/backup.sql"]
    assert tables["copy:auth.users"] != tables["copy:public.users"]
    assert _leaks(first) == _leaks(second) == _leaks(third) == 0
    assert "Label 5" in second["observation"]["text_sample"]  # public.users keeps its columns


def test_inserts_into_same_named_tables_use_their_schema():
    body = ("CREATE TABLE auth.users (id integer, email text, password text);\n"
            "CREATE TABLE public.users (id integer, email text, label text);\n"
            "INSERT INTO auth.users VALUES (1, 'a@fixture.test', 'Fx1BlockPass!q');\n"
            "INSERT INTO public.users VALUES (2, 'b@fixture.test', 'Visible Label');\n")
    masked, collector = _collect(body)
    assert collector.values == ["Fx1BlockPass!q"] and "Visible Label" in masked


def test_unqualified_block_positions_from_before_are_not_used():
    tables = {"\0copy_open": ["users", "0", "999999"], "copy:users": ["id", "email", "label", "x"]}
    assert masking.copy_block_at(tables, 500) is None


# --- Quoted identifiers ------------------------------------------------------------------------

@pytest.mark.parametrize("header", [
    'COPY public."api-keys" (id, email, token, created_at) FROM stdin;\n',
    'COPY public."My Keys" (id, email, "api-token", created_at) FROM stdin;\n',
    'COPY "My ""Quoted"" Keys" (id, email, token, created_at) FROM stdin;\n',
    'COPY public."User" (id, email, "passwordHash", created_at) FROM stdin;\n',
])
@pytest.mark.parametrize("hunt", [False, True])
def test_copy_headers_with_quoted_identifiers_are_read(header, hunt):
    body = _HEAD + header + "".join(_rows("k", 5, True)) + "\\.\n"
    if hunt:
        masked, _collector = _collect(body)
    else:
        masked = masking.withhold_body_secrets(body)
    assert not SECRET.search(masked) and "k3@fixture.test" in masked


def test_quoted_identifiers_name_blocks_exactly():
    assert masking._sql_table_name('public."My ""Quoted"" Keys"') == 'public.my "quoted" keys'
    assert masking._sql_table_name("`db`.`Users`") == "db.users"
    document = (_HEAD + 'COPY public."api-keys" (id, token) FROM stdin;\n1\tx\n').encode()
    tables: dict[str, list[str]] = {}
    masking.track_copy_blocks(tables, 0, document)
    assert masking.copy_block_at(tables, len(document) - 2) == "public.api-keys"


# --- Block extents ----------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["users", '"api-keys"'])
def test_a_read_ending_inside_a_block_end_does_not_extend_the_block(monkeypatch, name):
    parts = [_HEAD, "COPY public.audit (id, email, label, created_at) FROM stdin;\n"]
    parts += _rows("a", 300, False) + ["\\.\n\n"]
    parts += [f"COPY public.{name} (id, email, password, created_at) FROM stdin;\n"]
    parts += _rows("k", 3_000, True) + ["\\.\n"]
    document = "".join(parts).encode()
    cut = document.index(b"\\.\n\nCOPY") + 1  # just after the backslash of audit's end
    collector = masking.WithheldValues(ACTION)
    first, _ = _inspect_at(monkeypatch, document, 0, cut, collector)
    second, _ = _inspect_at(monkeypatch, document, cut + 65_536, 8_192, collector)
    assert _leaks(first) == _leaks(second) == 0
    tables: dict[str, list[str]] = {}
    masking.track_copy_blocks(tables, 0, document[:cut])
    assert masking.copy_block_at(tables, cut - 1) == "public.audit"
    assert masking.copy_block_at(tables, cut) is None


def test_a_shorter_read_of_the_head_keeps_the_larger_known_extent():
    document = (_HEAD + "COPY public.audit (id, email, label, created_at) FROM stdin;\n"
                + "".join(_rows("a", 6_000, False))).encode()
    tables: dict[str, list[str]] = {}
    masking.track_copy_blocks(tables, 0, document[:200_000])
    masking.track_copy_blocks(tables, 0, document[:65_536])  # the head, read again
    assert masking.copy_block_at(tables, 150_000) == "public.audit"


def test_positions_from_another_version_of_the_resource_are_dropped(monkeypatch, encryption_key):
    def dump(table, label):
        return (_HEAD + f"COPY public.{table} (id, email, {label}, created_at) FROM stdin;\n"
                + "".join(_rows("k", 60_000, label == "password"))).encode()

    conn = _RecentFirstRows()
    _hunt_inspect_path(monkeypatch, dump("audit", "label"), "/backup.sql", 1_048_576, conn)
    result, _ = _hunt_inspect_path(monkeypatch, dump("users", "password"), "/backup.sql", 1_100_000, conn)
    assert _leaks(result) == 0
    tables: dict[str, list[str]] = {}
    masking.track_copy_blocks(tables, 0, dump("audit", "label")[:4_096], resource="100/")
    assert masking.copy_block_at(tables, 2_000, resource="100/") == "public.audit"
    assert masking.copy_block_at(tables, 2_000, resource="200/") is None
    masking.track_copy_blocks(tables, 8_192, b"1\tx\n", resource="200/")
    assert masking.copy_block_at(tables, 2_000) is None


def test_rows_after_a_block_end_with_no_header_in_view_fail_closed():
    body = ("4\tpartial@fixture.test\tLabel\t2024-02-19 14:07:31\n" + "".join(_rows("a", 5, False))
            + "\\.\n\n" + "".join(_rows("k", 5, True)) + "\\.\n")
    collector = masking.WithheldValues(ACTION)
    collector.sql_path, collector.sql_dump_like = "/backup.sql", True
    collector.sql_tables = {"/backup.sql": {"copy:public.audit": ["id", "email", "label", "created_at"]}}
    collector.copy_block = "public.audit"
    with masking.collecting_withheld_values(collector):
        masked = masking.mask_body_text(body)
    assert not SECRET.search(masked) and "Label 3" in masked and "k3@fixture.test" in masked


# --- Bodies that open with JSON ----------------------------------------------------------------

PLAIN = "Fxhunter2Secret9"
JSON_LED = {
    "td": "[]\n<tr><td>Password</td><td>" + PLAIN + "</td></tr>\n",
    "phpdef": "{}\ndefine('DB_PASSWORD', '" + PLAIN + "');\n",
    "insert": "{}\nCREATE TABLE users (id int, pw_hash text);\nINSERT INTO users VALUES (1,'" + PLAIN + "');\n",
    "html_input": '{}\n<input type="password" name="pass" value="' + PLAIN + '">\n',
    "json_then_env": "{}\nDB_PASSWORD=" + PLAIN + "\n",
    "log": "[2024-02-19 14:07:31] production.INFO: env\nDB_PASSWORD=" + PLAIN + "\n",
    "ndjson": '{"event": "boot"}\n{"password": "' + PLAIN + '"}\n',
}


@pytest.mark.parametrize("name", sorted(JSON_LED))
@pytest.mark.parametrize("hunt", [False, True])
def test_text_after_a_leading_json_value_is_masked(name, hunt):
    body = JSON_LED[name]
    masked = _collect(body)[0] if hunt else masking.withhold_body_secrets(body)
    assert PLAIN not in masked


@pytest.mark.parametrize("body", [
    '{"user": "bob", "note": "hello world", "items": [1, 2, 3]}',
    '[{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]\n',
    '{"event": "boot"}\n{"event": "ready", "detail": "listening on 8080"}\n',
])
def test_json_only_bodies_are_unchanged(body):
    assert masking.withhold_body_secrets(body) == body
    assert _collect(body)[0] == body


def test_a_window_starting_at_a_brace_is_masked_as_text_too(monkeypatch, encryption_key):
    line = "p {color:#222}\n"
    line += " " * (16 - len(line))
    document = ("<html><style>\n  " + line * 6_000 + '</style><table><tr><td class="e">MYSQL_PASSWORD</td>'
                '<td class="v">' + PLAIN + "</td></tr></table></html>\n").encode()
    brace = document.rindex(b"{color")
    for offset in (brace, brace + 3):
        result, _ = _hunt_inspect_path(monkeypatch, document, "/info.php", offset, _RecentFirstRows())
        assert PLAIN not in json.dumps(result)
    unclosed = ("{\n  init();\n  var password = '" + PLAIN + "';\n").encode()
    result, _ = _hunt_inspect_path(monkeypatch, b"x" * 70_000 + unclosed, "/app.js", 70_000, _RecentFirstRows())
    assert PLAIN not in json.dumps(result)


# --- Values no request can carry ---------------------------------------------------------------

@pytest.mark.parametrize("body", [
    "<script>var cfg = {password: '\\ud800FxSurr0gate9q'};</script>\n",
    '<script>const API_SECRET = "\\ud83dFxSurr0gate9q";</script>\n',
    'db:\n  password: "\\ud800FxSurr0gate9q"\n',
    'let DB_PASSWORD = "\\ud800FxSurr0gate9q";\n',
    'define("DB_PASSWORD", "\\u{D800}FxSurr0gate9q");\n',
])
def test_a_lone_surrogate_value_is_withheld_without_a_reference(body):
    masked, collector = _collect(body)
    assert "FxSurr0gate9q" not in masked and "***" in masked and collector.values == []
    assert "FxSurr0gate9q" not in masking.withhold_body_secrets(body)


def test_a_lone_surrogate_value_never_fails_an_inspect(monkeypatch, encryption_key):
    body = b"<script>var cfg = {password: '\\ud800FxSurr0gate9q'};</script>\n"
    result, _ = _hunt_inspect_path(monkeypatch, body, "/app.js", 0, _RecentFirstRows())
    assert result["ok"] and "FxSurr0gate9q" not in json.dumps(result)


# --- dotenv escapes and URL userinfo ----------------------------------------------------------

@pytest.mark.parametrize(("body", "secret"), [
    ('DB_PASSWORD="Dv\\x41\\q\\t9"\n', "Dv\\x41\\q\t9"),  # dotenv keeps escapes it does not define
    ("export DB_PASSWORD='Dv\\n9\\'x'\n", "Dv\\n9'x"),
    ('const API_SECRET = "Js\\x419Pass";\n', "JsA9Pass"),  # not a dotenv line: JavaScript rules
])
def test_dotenv_values_are_decoded_by_dotenv_rules(body, secret):
    assert _collect(body)[1].values == [secret]


def test_url_userinfo_passwords_are_withheld_as_references():
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        shown = masking.bounded_public_url("https://user:Fx%40Userinfo9@x.test/cb?a=1", 500)
    assert shown == "https://user:[withheld:1]@x.test/cb?a=1" and collector.values == ["Fx@Userinfo9"]
