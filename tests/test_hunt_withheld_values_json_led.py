"""Withheld values: bodies and windows that open with JSON, ranged HTTP responses, JSON literals
under secret-like keys, delimiter-doubled SQL names, resource versions, dotenv spacing and URL
userinfo.

Every value below is a synthetic unit fixture, never a real secret.
"""

from __future__ import annotations

import json
import re

import httpx
import pytest

from api.http_experiment import response_summary
from tests.test_hunt_withheld_values_positions import _RecentFirstRows
from tests.test_hunt_withheld_values_review import (
    ACTION,
    _collect,
    _hunt_inspect_path,
    _inspect_at,
    masking,
)

S = "Fxhunter2Secret9"


@pytest.fixture
def encryption_key(monkeypatch, tmp_path):
    import secret_store
    from cryptography.fernet import Fernet

    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(secret_store, "_loaded", False)
    monkeypatch.setattr(secret_store, "_fernet", None)


# --- JSON-led text is never masked less than JSON masking alone masks it ------------------------

def _env_document(separators) -> bytes:
    items = [{"name": f"VAR_{i}", "value": f"plain-{i}"} if i % 2 else
             {"name": f"SECRET_KEY_{i}", "value": f"Fx{i}EnvPass!q"} for i in range(3_000)]
    return json.dumps({"kind": "Pod", "spec": {"containers": [{"env": items}]}},
                      separators=separators).encode()


@pytest.mark.parametrize("separators", [(",", ":"), (", ", ": ")])
@pytest.mark.parametrize("hunt", [False, True])
def test_windows_starting_at_an_array_item_withhold_every_descriptor_value(monkeypatch, separators, hunt):
    document = _env_document(separators)
    offsets = [match.start() for match in re.finditer(rb'\{"name', document)][1::400]
    for offset in offsets:
        result, _ = _inspect_at(monkeypatch, document, offset, 4_096,
                                masking.WithheldValues(ACTION) if hunt else None)
        assert not re.search(r"Fx\d+EnvPass!q", json.dumps(result)), offset


JSON_FORMS = [
    '{"name": "db_password", "value": "%s"}', '{"key": "API_KEY", "value": "%s"}',
    '{"Name":"password","Value":"%s"}', '{"field": "password", "val": "%s"}',
    '{"env": [{"name": "SECRET_KEY", "value": "%s"}]}', '{"password":\n"%s"}', '{"password":"%s"}',
    '{"pass\\u0077ord": "%s"}', '{"client_secret": ["%s"]}', '{"db": {"password": {"value": "%s"}}}',
    '{"credentials": "%s"}', '{"private_key": "%s"}',
]
LEADS = ["[2024-01-01 00:00:00] INFO request\n", "{}\n", "[]\n", '{"event": "boot"}\n', "[1, 2]\n  ",
         '[{"a": 1}], ']


@pytest.mark.parametrize("form", JSON_FORMS)
@pytest.mark.parametrize("lead", LEADS)
def test_json_after_a_leading_value_is_masked_as_json(form, lead):
    body = lead + form % S
    assert S not in masking.withhold_body_secrets(body)
    assert S not in _collect(body)[0]


def _hidden(text: str, secrets: list[str]) -> set[str]:
    return {secret for secret in secrets if secret not in text}


def test_json_led_masking_is_never_weaker_than_json_masking_alone():
    """Differential: on every JSON-led input, every secret the JSON pass alone hides stays hidden."""
    corpus = []
    for index, form in enumerate(JSON_FORMS):
        for lead in LEADS:
            secret = f"Fx{index}Diff{len(corpus)}Secret"
            corpus.append((lead + form % secret + "\nDB_PASSWORD=" + secret + "x\n", [secret, secret + "x"]))
    compact = _env_document((",", ":")).decode()
    for cut in range(1, 40):
        window = compact[compact.index('{"name', cut * 997):][:4_096]
        corpus.append((window, re.findall(r"Fx\d+EnvPass!q", window)))
    for text, secrets in corpus:
        reference = _hidden(masking.mask_json_text(text), secrets)
        for window in (False, True):
            assert reference <= _hidden(masking.mask_body_text(text, window=window), secrets), text[:120]
            collector = masking.WithheldValues(ACTION)
            with masking.collecting_withheld_values(collector):
                assert reference <= _hidden(masking.mask_body_text(text, window=window), secrets)


# --- A ranged HTTP response is a window ---------------------------------------------------------

@pytest.mark.parametrize(("status", "headers"), [
    (206, {"content-range": "bytes 1000-1999/50000"}),
    (200, {}),  # opens like JSON, does not parse
])
def test_a_ranged_or_unparsable_json_led_response_gets_the_text_passes(status, headers):
    body = ("{\n  init();\n}\ndefine('DB_PASSWORD', '" + S + "');\n$cfg = ['password' => '" + S + "x'];\n").encode()
    response = httpx.Response(status, headers={"content-type": "text/plain", **headers}, content=body)
    for collector in (None, masking.WithheldValues(ACTION)):
        if collector is None:
            summary = response_summary(response, body)
        else:
            with masking.collecting_withheld_values(collector):
                summary = response_summary(response, body)
        assert S not in summary["body_sample"]


def test_a_complete_json_response_is_not_a_window():
    body = json.dumps({"token_expired": False, "has_password": True, "user": "bob"}).encode()
    summary = response_summary(httpx.Response(200, content=body), body)
    assert summary["body_sample"] == body.decode()


# --- JSON literals and numbers under secret-like keys in window mode ----------------------------

KEYS = ["session_id_present", "password_reset_enabled", "token_expired", "auth_required", "has_password",
        "api_key_set", "credentials_valid", "private", "key_id", "token_url", "authorization_endpoint",
        "client_secret_expires_at"]


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("value", [True, False, None])
@pytest.mark.parametrize("indent", [None, 2])
def test_window_mode_keeps_json_literals_and_valid_json(key, value, indent):
    text = json.dumps({"x": 1, key: value, "y": "z"}, indent=indent)
    for window in (False, True):
        masked = masking.mask_body_text(text, window=window)
        assert json.loads(masked)[key] is value


@pytest.mark.parametrize("indent", [None, 2])
def test_a_number_under_a_secret_key_is_withheld_as_a_json_string(indent):
    text = json.dumps({"x": 1, "pin_password": 4821, "y": "z"}, indent=indent)
    masked = masking.mask_body_text(text, window=True)
    assert "4821" not in masked and isinstance(json.loads(masked)["pin_password"], str)


# --- SQL names with doubled delimiters keep their case when quoted ------------------------------

@pytest.mark.parametrize("name", ["`we``ird`", "[we]]ird]", "[dbo].[Users]", '"Users"', "`my table`"])
def test_doubled_delimiter_names_are_read(name):
    body = (f"CREATE TABLE {name} (id int, email text, password text, note text);\n"
            f"INSERT INTO {name} VALUES (1,'a@b.test','{S}','hello');\n")
    masked, _collector = _collect(body)
    assert S not in masked and "hello" in masked
    assert S not in masking.withhold_body_secrets(body)


def test_quoted_names_keep_their_case():
    assert masking._sql_table_name('public."Users"') == "public.Users"
    assert masking._sql_table_name("PUBLIC.USERS") == "public.users"


# --- Resource versions --------------------------------------------------------------------------

_HEAD = "--\n-- PostgreSQL database dump\n--\n"


def _same_size_dump(table: str, column: str, secret: bool) -> bytes:
    rows = "".join(
        f"{i}\tu{i}@fixture.test\t{f'Fx{i:06d}VerPass!q' if secret else f'Lb{i:06d}VerLabl!q'}"
        f"\t2024-02-19 14:07:31\n" for i in range(60_000))
    return (_HEAD + f"COPY public.{table} (id, email, {column}, created_at) FROM stdin;\n" + rows).encode()


def test_a_same_size_rewrite_without_a_validator_keeps_no_positions(monkeypatch, encryption_key):
    first, second = _same_size_dump("audit", "labelxxx", False), _same_size_dump("users", "password", True)
    assert len(first) == len(second)
    conn = _RecentFirstRows()
    _hunt_inspect_path(monkeypatch, first, "/backup.sql", 1_048_576, conn)
    result, _ = _hunt_inspect_path(monkeypatch, second, "/backup.sql", 1_100_000, conn)
    assert not re.search(r"Fx\d+VerPass!q", json.dumps(result))


def test_positions_carry_between_reads_of_a_validated_version(monkeypatch, encryption_key):
    document = _same_size_dump("audit", "label", False)
    conn = _RecentFirstRows()
    etag = {"etag": '"v1"'}
    _hunt_inspect_path(monkeypatch, document, "/backup.sql", 1_048_576, conn, etag)
    result, _ = _hunt_inspect_path(monkeypatch, document, "/backup.sql", 1_100_000, conn, etag)
    sample = result["observation"]["text_sample"]
    assert "VerLabl!q" in sample  # the label column, known inside its block, stays readable
    tables: dict[str, list[str]] = {}
    masking.track_copy_blocks(tables, 0, document[:4_096], resource="v1")
    masking.track_copy_blocks(tables, 4_096, document[4_096:8_192])  # no version: dropped
    assert masking.copy_block_at(tables, 2_000) is None


def test_a_text_verdict_holds_only_for_its_version(monkeypatch, encryption_key):
    tsv = ("id\tname\tcreated\tstatus\n" + "".join(
        f"{i}\tAlice Smith {i}\t2024-01-0{1 + i % 9}\tactive\n" for i in range(20_000))).encode()
    conn = _RecentFirstRows()
    _result, seen = _hunt_inspect_path(monkeypatch, tsv, "/export.tsv", 300_000, conn)
    assert any(start == 0 for start, _end in seen)  # the head was read: plain text
    _result, seen = _hunt_inspect_path(monkeypatch, tsv, "/export.tsv", 400_000, conn)
    assert all(start != 0 for start, _end in seen)  # same version: the verdict holds
    changed = tsv + b"9\tBob\t2024-01-02\tactive\n"
    _result, seen = _hunt_inspect_path(monkeypatch, changed, "/export.tsv", 400_000, conn)
    assert any(start == 0 for start, _end in seen)  # another version: read again


# --- dotenv spacing ----------------------------------------------------------------------------

@pytest.mark.parametrize(("body", "secret"), [
    ("SECRET_KEY = 'Ab\\x41cd9Secret77'\n", "AbAcd9Secret77"),  # Python settings
    ('DB_PASSWORD = "Ab\\u0041cd9Secret77"\n', "AbAcd9Secret77"),
    ('password = "Ab\\x41cd9Secret77";\n', "AbAcd9Secret77"),
    ('DB_PASSWORD="Ab\\x41cd9Secret77"\n', "Ab\\x41cd9Secret77"),  # .env: no blanks around =
    ('export DB_PASSWORD="Ab\\ncd9Secret77"\n', "Ab\ncd9Secret77"),
    ("<?php\nreturn [\n  'password' =>\n      'Ab\\cd9Secret77',\n];\n", "Ab\\cd9Secret77"),
])
def test_assignments_are_decoded_by_their_format(body, secret):
    assert _collect(body)[1].values == [secret]


# --- URL userinfo --------------------------------------------------------------------------------

@pytest.mark.parametrize(("url", "secret"), [
    (" https://app:Fx1Userinfo9@h/", "Fx1Userinfo9"),
    ("//app:Fx2Userinfo9@h/", "Fx2Userinfo9"),
    ("https://ap@p:Fx3Userinfo9@h/x@y", "Fx3Userinfo9"),
    ("https://app:p%40Fx4Userinfo9@h/", "p@Fx4Userinfo9"),
    ("https://app:Fx5%FFUserinfo9@h/", "Fx5%FFUserinfo9"),  # not UTF-8: kept as written
])
def test_userinfo_passwords_are_withheld_exactly(url, secret):
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        shown = masking.mask_url_secrets(url)
    assert collector.values == [secret] and "[withheld:1]@" in shown


@pytest.mark.parametrize("body", [
    "{\n    $db_password = '%s';\n    define('DB_PASSWORD', '%s');\n}\n" % (S, S),
    "[\nDB_PASSWORD=%s\n" % S,
    "{\nDB_PASSWORD=%s\n}" % S,
    "[\nINSERT INTO users (id, email, password) VALUES (1,'a@b','%s');\n]" % S,
    '{<input type="password" name="pw" value="%s">}' % S,
])
def test_a_leading_brace_that_is_not_json_gets_the_text_passes(body):
    assert S not in masking.withhold_body_secrets(body)
    assert S not in _collect(body)[0]
