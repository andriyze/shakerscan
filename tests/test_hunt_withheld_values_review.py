"""Review fixes for N56 (PR #371): leak blockers, oracles, formats, fidelity and Hunt freedoms.

Every value below is a synthetic unit fixture, never a real secret. The principle: keep found
secrets from the model by default, without taking a capability away from the Hunt.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import json
import sys
import urllib.parse
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import secret_store
from capabilities.http_workflow import _scrub_bound_values
from runtime.hunt_http_exchange import (
    WITHHELD_EXPIRES_KEY,
    persist_withheld_values,
    prepare_http_exchange,
)
from runtime.models import TargetBinding

from api.capabilities import artifact as artifact_capability
from api.capabilities.http import WorkerPrivateHTTPResponse
from api.http_experiment import MAX_RESPONSE_SAMPLE, response_summary

masking = sys.modules[artifact_capability.mask_body_text.__module__]
mask_body_text = masking.mask_body_text

HUNT = str(uuid.UUID(int=601))
ACTION = str(uuid.UUID(int=602))
TARGET = TargetBinding(
    target_id=str(uuid.UUID(int=603)), target_kind="web", canonical_host="honey.fixture.test",
    allowed_origins=("https://honey.fixture.test",), allowed_addresses=("192.0.2.10",),
    allowed_root_domains=("fixture.test",), environment="lab", scope_receipt_id=str(uuid.UUID(int=604)),
)
RUN = {"id": HUNT, "status": "active", "completed_at": None}
POLICY = {"active_testing": True}
# A bound value with every character class an encoder changes: case, '/', '+', '&', '"', ' '.
BOUND = 'Adm1n/T0k+en&"x y-9Q'


@pytest.fixture
def encryption_key(monkeypatch, tmp_path):
    from cryptography.fernet import Fernet
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(secret_store, "_loaded", False)
    monkeypatch.setattr(secret_store, "_fernet", None)


def _collect(text: str, *, known=()):
    collector = masking.WithheldValues(ACTION)
    collector.bind_known(known)
    with masking.collecting_withheld_values(collector):
        masked = mask_body_text(text)
    return masked, collector


def _sealed(text: str) -> list[str]:
    """The exact values a planner-facing pass withheld (what a reference would send)."""
    return _collect(text)[1].values


def _summary(body: str, *, known=(), headers=None):
    collector = masking.WithheldValues(ACTION)
    collector.bind_known(known)
    response = httpx.Response(200, headers=headers or {"content-type": "text/plain"}, content=body.encode())
    with masking.collecting_withheld_values(collector):
        return response_summary(response, body.encode()), collector


def _forms(value: str) -> list[str]:
    raw = value.encode()
    return [
        value, value.upper(), value.lower(), html.escape(value), json.dumps(value)[1:-1].replace("/", "\\/"),
        urllib.parse.quote(value, safe=""), urllib.parse.quote_plus(value),
        base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode().rstrip("="),
    ]


# --- Blocker 1: every echo of a bound value is withheld -------------------------------------

@pytest.mark.parametrize("form", [
    "verbatim", "upper", "lower", "html", "json_slash", "json_unicode", "url_quote", "url_quote_plus",
    "base64", "base64url", "basic_auth_embedded", "jwt_embedded",
])
def test_withheld_only_response_withholds_every_echo_form(form):
    raw = BOUND.encode()
    echoes = {
        "verbatim": BOUND, "upper": BOUND.upper(), "lower": BOUND.lower(),
        "html": html.escape(BOUND), "json_slash": json.dumps(BOUND)[1:-1].replace("/", "\\/"),
        "json_unicode": json.dumps(BOUND + "é")[1:-1],
        "url_quote": urllib.parse.quote(BOUND, safe=""), "url_quote_plus": urllib.parse.quote_plus(BOUND),
        "base64": base64.b64encode(raw).decode(), "base64url": base64.urlsafe_b64encode(raw).decode().rstrip("="),
        "basic_auth_embedded": base64.b64encode(b"admin:" + raw).decode(),
        "jwt_embedded": "eyJhbGciOiJub25lIn0." + base64.urlsafe_b64encode(
            json.dumps({"sub": "x", "token": BOUND}).encode()).decode().rstrip("=") + ".sig",
    }
    value = BOUND + "é" if form == "json_unicode" else BOUND
    body = f"<p>welcome back, your key is {echoes[form]} and more text</p>"
    summary, _collector = _summary(body, known=[value])
    scrubbed = _scrub_bound_values({"response": summary}, [value])
    text = json.dumps(scrubbed)
    assert echoes[form] not in summary["body_sample"] and echoes[form] not in text
    assert BOUND.lower() not in text.lower()
    assert "welcome back" in summary["body_sample"]


def test_a_value_straddling_the_sample_edge_is_withheld_before_the_cut():
    body = "x" * (MAX_RESPONSE_SAMPLE - 8) + " " + BOUND + " tail"
    summary, _collector = _summary(body, known=[BOUND])
    sample = summary["body_sample"]
    assert len(sample) <= MAX_RESPONSE_SAMPLE
    for size in range(4, len(BOUND)):
        assert BOUND[:size] not in sample[-len(BOUND):]


@pytest.mark.parametrize("edge", ["head", "tail"])
def test_a_fragment_cut_by_the_text_edge_is_withheld(edge):
    text = ("prefix " + BOUND[:9]) if edge == "head" else (BOUND[-9:] + " suffix")
    masked, _collector = _collect(text, known=[BOUND])
    assert BOUND[:9] not in masked and BOUND[-9:] not in masked


def test_location_final_url_and_redirect_chain_are_scrubbed():
    encoded = urllib.parse.quote(BOUND, safe="")
    response = {
        "response": {"location": f"/cb?u={encoded}", "status": 302},
        "final_url": f"https://honey.fixture.test/next?token={encoded}",
        "redirect_chain": [{"location": f"/a?k={urllib.parse.quote_plus(BOUND)}"}, {"location": f"/b/{BOUND}"}],
    }
    text = json.dumps(_scrub_bound_values(response, [BOUND]))
    for form in _forms(BOUND):
        assert form not in text
    assert "[withheld:bound]" in text


# --- Blocker 2: no raw-body oracles -----------------------------------------------------------

def _inspect(monkeypatch, body: str, *, collector=None, search_terms=()):
    async def fake_execute(_target_url, _args, **kwargs):
        kwargs["private_response_sink"](WorkerPrivateHTTPResponse(
            status_code=200, final_url="https://honey.fixture.test/x", _body=body.encode(),
            _headers={"content-type": "text/plain"}, _cookies={},
        ))
        return {"ok": True, "response": {"status": 200}}

    monkeypatch.setattr(artifact_capability, "execute_bound_http_request", fake_execute)
    args = {"path": "/x", "max_bytes": 16_384, "search_terms": list(search_terms)}

    async def run():
        if collector is None:
            return await artifact_capability.inspect_target_artifact("https://honey.fixture.test", args, target=TARGET)
        with masking.collecting_withheld_values(collector):
            return await artifact_capability.inspect_target_artifact("https://honey.fixture.test", args, target=TARGET)

    return asyncio.run(run())["observation"]


def test_window_digest_is_keyed_when_anything_was_withheld(monkeypatch):
    secret_body = "DB_PASSWORD=Fx_Window_Pw_77\n"
    observation = _inspect(monkeypatch, secret_body, collector=masking.WithheldValues(ACTION))
    assert observation["window_sha256"].startswith("hmac-sha256-")
    assert observation["window_sha256"] != hashlib.sha256(secret_body.encode()).hexdigest()
    plain = _inspect(monkeypatch, "hello world\n")
    assert plain["window_sha256"] == hashlib.sha256(b"hello world\n").hexdigest()


def test_response_body_digest_is_keyed_when_anything_was_withheld():
    summary, _collector = _summary('{"api_key": "Fx_Api_Key_0123456789"}', headers={"content-type": "application/json"})
    assert summary["body_sha256"].startswith("hmac-sha256-")
    plain, _collector = _summary("hello world")
    assert plain["body_sha256"] == hashlib.sha256(b"hello world").hexdigest()


def test_search_counts_never_see_a_withheld_value(monkeypatch):
    body = "DB_PASSWORD=Fx_Search_Pw_42\npassword reset page\n"
    terms = ["Fx_Search_Pw_42", "Fx_S", "password"]
    observation = _inspect(monkeypatch, body, collector=masking.WithheldValues(ACTION), search_terms=terms)
    counts = {item["term"]: item["count"] for item in observation["search_matches"]}
    assert counts["Fx_Search_Pw_42"] == 0 and counts["Fx_S"] == 0
    assert counts["password"] == 2  # labels and prose stay searchable


# --- Blocker 3: the formats that still leaked ------------------------------------------------

FORMATS = {
    "mycnf": ("[client]\nuser=root\npassword=Fx Cnf;Pw 1\n", "Fx Cnf;Pw 1"),
    "php_ini": ("[database]\nhost = db\npassword = FxIniPw2 ; comment\n", "FxIniPw2"),
    "json_wrapped_add": (json.dumps({"content": '<add key="ApiKey" value="FxJsonAddKey3"/>'}), "FxJsonAddKey3"),
    "json_wrapped_insert": (json.dumps({"c": "INSERT INTO users (u,password) VALUES ('a','FxJsonIns4');"}), "FxJsonIns4"),
    "json_wrapped_phpinfo": (json.dumps({"h": "<tr><td>DB_PASSWORD</td><td>FxJsonPhp5</td></tr>"}), "FxJsonPhp5"),
    "php_define": ("define('DB_PASSWORD', 'Fx\\'Def; 6');", "Fx'Def; 6"),
    "php_array": ("return ['mysql' => ['password' => \"FxArr 7\\\"q\", 'username' => 'root']];", 'FxArr 7"q'),
    "xml_property": ('<property name="hibernate.connection.password">FxProp&amp;8</property>', "FxProp&8"),
    "xml_element": ("<server><username>deploy</username><password>FxMvn9</password></server>", "FxMvn9"),
    "sql_name_value_row": ("INSERT INTO `wp_options` VALUES (1,'mailserver_pass','FxMail''10','yes');", "FxMail'10"),
    "json_settings_rows": (json.dumps({"rows": [["smtp_password", "FxRows11"], ["site", "x"]]}), "FxRows11"),
}


@pytest.mark.parametrize("name", sorted(FORMATS))
def test_format_is_withheld_and_sealed_exactly(name):
    body, secret = FORMATS[name]
    masked, collector = _collect(body)
    leaked_fragment = secret.split(" ")[0].split(";")[0][:5]
    assert secret not in masked and leaked_fragment not in masked.replace("[withheld:", ""), masked
    assert secret in collector.values, (name, collector.values)


@pytest.mark.parametrize("body", ["[client]\npassword=FxCnf\n", "[database]\npassword = FxIni\n"])
def test_ini_sections_are_not_mistaken_for_json(body):
    assert "FxCnf" not in mask_body_text(body) and "FxIni" not in mask_body_text(body)


# --- Value fidelity: the sealed value is the exact secret ------------------------------------

@pytest.mark.parametrize(("body", "secret"), [
    ('db:\n  password: "Hunt3r#pass" # prod\n', "Hunt3r#pass"),
    ("password: 'it''s-a-secret'\n", "it's-a-secret"),
    ("INSERT INTO users (u, password) VALUES ('a','o''brien''s pw');", "o'brien's pw"),
    ('<input type="hidden" name="api_token" value="a&amp;b&quot;c1234567">', 'a&b"c1234567'),
    ("Password=P@ss;w0rd;\n", "P@ss;w0rd"),
    ("DB_PASSWORD=Hunter 2 pass\n", "Hunter 2 pass"),
    ('var cfg = {apiKey: "ab\\"cd12345678"};', 'ab"cd12345678'),
    ("<tr><td>DB_PASSWORD</td><td>Hunter&amp;2pass</td></tr>", "Hunter&2pass"),
    ("export API_KEY='abc DEF;123456'\n", "abc DEF;123456"),
    ("Set-Cookie: session=FxSess123; Path=/; HttpOnly\n", "session=FxSess123"),
])
def test_sealed_value_equals_the_real_secret(body, secret):
    masked, collector = _collect(body)
    assert secret in collector.values, collector.values
    assert secret not in masked


def test_redactor_marker_exemption_is_anchored():
    from redaction import redact_text
    assert redact_text("password=[withheld:1]Hunter2pass") == "password=***"
    assert redact_text("password=[withheld:1]&x=1") == "password=[withheld:1]&x=1"
    assert redact_text('{"password": "[withheld:1] Hunter2pass"}') == '{"password": "***"}'
    assert redact_text('{"password": "[withheld:1]"}') == '{"password": "[withheld:1]"}'
    assert redact_text("<password>[withheld:2]</password> https://u:[withheld:3]@h") == (
        "<password>[withheld:2]</password> https://u:[withheld:3]@h")


# --- Should-fix: short values carry no fingerprint ------------------------------------------

def test_short_values_have_no_fingerprint():
    masked, collector = _collect("password=short1\napi_key=LongEnoughValue0123\n")
    entries = {entry["length"]: entry for entry in collector.entries(masked)}
    assert entries[6]["fingerprint"] is None
    assert entries[19]["fingerprint"]


# --- Freedom: the JSON case binds and is usable --------------------------------------------

class _ActionRows:
    def __init__(self, prior=None):
        self.rows = {ACTION: {"status": "completed", "private_http_result": prior}}

    async def fetchrow(self, sql, *args):
        row = self.rows.get(str(args[0]))
        if row is None or ("status='completed'" in sql and row["status"] != "completed"):
            return None
        return row

    async def execute(self, sql, *args):
        self.rows[str(args[0])]["private_http_result"] = args[2]
        return "UPDATE 1"


def _bind(reference):
    return {"method": "GET", "path": "/hub/admin",
            "request_bindings": [{"withheld_ref": reference, "header": "X-Api-Key"}]}


@pytest.mark.parametrize("key", ["api_key", "access_token", "client_secret"])
def test_a_json_key_value_is_withheld_bound_and_sent(encryption_key, key):
    secret = f"Fx{key.title().replace('_', '')}0123456789"
    summary, collector = _summary(json.dumps({key: secret, "user": "bob"}),
                                  headers={"content-type": "application/json"})
    assert secret not in json.dumps(summary)
    entry = summary["withheld_values"][0]
    conn = _ActionRows()
    sealing = asyncio.run(persist_withheld_values(
        conn, run=RUN, action_id=ACTION, target=TARGET, values=collector, status="success",
        observations=[{"response": summary}],
    ))
    assert sealing == {"sealed": 1, "status": "sealed"}
    _inputs, headers, _exchange = asyncio.run(prepare_http_exchange(
        conn, run=RUN, action_id=uuid.uuid4(), target=TARGET, context={}, policy=POLICY,
        values=_bind(entry["ref"]), trusted_headers={},
    ))
    assert headers == {"X-Api-Key": secret}


# --- Freedom: handle lifetime -----------------------------------------------------------------

def test_references_live_for_the_hunt_up_to_a_day(encryption_key):
    conn = _ActionRows()
    asyncio.run(persist_withheld_values(
        conn, run=RUN, action_id=ACTION, target=TARGET, values={1: "FxLongLived0123"}, status="success",
    ))
    private = json.loads(secret_store.decrypt_secret(conn.rows[ACTION]["private_http_result"]))
    expires = datetime.fromisoformat(private[WITHHELD_EXPIRES_KEY]) - datetime.now(timezone.utc)
    assert timedelta(hours=23) < expires <= timedelta(hours=24)
    # Two hours later (past the one-hour capture TTL) the reference still resolves.
    private["expires_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    conn.rows[ACTION]["private_http_result"] = secret_store.encrypt_secret(json.dumps(private))
    _inputs, headers, _exchange = asyncio.run(prepare_http_exchange(
        conn, run=RUN, action_id=uuid.uuid4(), target=TARGET, context={}, policy=POLICY,
        values=_bind(f"withheld://hunt/{ACTION}/1"), trusted_headers={},
    ))
    assert headers == {"X-Api-Key": "FxLongLived0123"}


@pytest.mark.parametrize("status", ["failed", "completed", "cancelled"])
def test_a_hunt_that_is_no_longer_live_refuses_its_references(encryption_key, status):
    conn = _ActionRows()
    asyncio.run(persist_withheld_values(
        conn, run=RUN, action_id=ACTION, target=TARGET, values={1: "FxEnded0123456"}, status="success",
    ))
    with pytest.raises(ValueError, match="no longer live"):
        asyncio.run(prepare_http_exchange(
            conn, run={**RUN, "status": status}, action_id=uuid.uuid4(), target=TARGET, context={},
            policy=POLICY, values=_bind(f"withheld://hunt/{ACTION}/1"), trusted_headers={},
        ))


# --- Freedom: no over-masking of CSRF tokens and identifiers --------------------------------

@pytest.mark.parametrize("body", [
    '<meta name="csrf-token" content="FxCsrfMeta0123456789">',
    '<input type="hidden" name="_token" value="FxCsrfLaravel0123456">',
    '<input type="hidden" name="authenticity_token" value="FxCsrfRails0123456">',
    '<input type="hidden" name="csrfmiddlewaretoken" value="FxCsrfDjango0123456">',
    '<input type="hidden" name="__RequestVerificationToken" value="FxCsrfAspNet0123456">',
    '<input type="hidden" name="xsrf_token" value="FxXsrf0123456789">',
])
def test_csrf_tokens_stay_visible_to_the_planner_but_not_in_archives(body):
    value = body.split('="')[-1].split('"')[0]
    masked, _collector = _collect(body)
    assert value in masked
    assert value not in mask_body_text(body)  # the shared archive view still withholds it


@pytest.mark.parametrize("body", [
    "INSERT INTO payments (id, customer_id, intent, charge) VALUES "
    "('Ab12Cd34Ef56Gh78Ij90','cus_9fKx2LmQpRsTuVwXyZ01','pi_3Nq8Lm2Kx9Vb4Rt7Yu1Io','ch_3Nq8Lm2Kx9Vb4Rt7Yu1Io');",
    "INSERT INTO sessions (user_ref, uuid) VALUES ('u_9fKx2LmQpRsTuVwX','9b2b7c1e-1111-4222-8333-444455556666');",
    "INSERT INTO orders (id, ref) VALUES (1,'ORD2024AbCdEf99887766');",
])
def test_identifiers_in_sql_rows_stay_visible(body):
    assert mask_body_text(body) == body


def test_sql_rows_without_columns_withhold_issued_key_prefixes():
    # Without column names a row withholds what its own shape proves; the column context of a
    # window read at an offset is restored by artifact.inspect (see the pagination tests).
    body = "INSERT INTO t VALUES (1,'ak_9f3c9e1a7b2d84c60e5a9f1b3d7c2e8a4','SKU-2024-0042');"
    masked = mask_body_text(body)
    assert "ak_9f3c" not in masked and "SKU-2024-0042" in masked


# --- Freedom: JWTs are usable references -----------------------------------------------------

JWT = "eyJhbGciOiJIUzI1NiJ9." + base64.urlsafe_b64encode(b'{"role":"service_role"}').decode().rstrip("=") + ".c2lnbmF0dXJlYnl0ZXM"


def test_artifact_jwt_becomes_a_reference(monkeypatch):
    collector = masking.WithheldValues(ACTION)
    observation = _inspect(monkeypatch, f'const anon = "{JWT}";', collector=collector)
    assert JWT not in json.dumps(observation)
    assert JWT in collector.values
    assert any(entry["marker"] in observation["text_sample"] for entry in observation["withheld_values"])


def test_javascript_jwt_observation_carries_a_reference():
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        analysis = artifact_capability.analyze_javascript_bytes(f'const k = "{JWT}";'.encode())
    jwt = analysis["jwt_observations"][0]
    assert jwt["withheld_ref"] == f"withheld://hunt/{ACTION}/1" and jwt["marker"] == "[withheld:1]"
    assert collector.shown_values(json.dumps(analysis)) == {1: JWT}
    assert analysis["content_sha256"].startswith("hmac-sha256-")


# --- Robustness: an unreadable prior private result is kept, visibly ------------------------

def test_unreadable_prior_private_result_is_kept_and_reported(encryption_key):
    conn = _ActionRows(prior="enc:fernet:not-decryptable")
    sealing = asyncio.run(persist_withheld_values(
        conn, run=RUN, action_id=ACTION, target=TARGET, values={1: "FxPrior0123456"}, status="success",
    ))
    assert sealing == {"sealed": 0, "status": "prior_private_result_unreadable"}
    assert conn.rows[ACTION]["private_http_result"] == "enc:fernet:not-decryptable"


def test_skill_documents_the_reference_workflow():
    from pathlib import Path
    skill = (Path(__file__).resolve().parents[1] / "skills" / "hunt" / "SKILL.md").read_text()
    assert "withheld_values" in skill and "withheld_ref" in skill and "withheld://hunt/" in skill


# --- Round 2 blocker: a window read at an offset keeps its masking context ------------------

def _range_server(monkeypatch, document: bytes, seen: list):
    async def fake_execute(_target_url, args, **kwargs):
        start, end = (int(part) for part in args["headers"]["Range"].split("=")[1].split("-"))
        seen.append((start, end))
        chunk = document[start:end + 1]
        kwargs["private_response_sink"](WorkerPrivateHTTPResponse(
            status_code=206, final_url="https://honey.fixture.test/backup.sql", _body=chunk,
            _headers={"content-type": "text/plain",
                      "content-range": f"bytes {start}-{start + len(chunk) - 1}/{len(document)}"},
            _cookies={},
        ))
        return {"ok": True, "response": {"status": 206}}

    monkeypatch.setattr(artifact_capability, "execute_bound_http_request", fake_execute)


def _inspect_at(monkeypatch, document: bytes, offset: int, length: int, collector=None):
    seen: list = []
    _range_server(monkeypatch, document, seen)
    args = {"path": "/backup.sql", "offset": offset, "max_bytes": length}

    async def run():
        if collector is None:
            return await artifact_capability.inspect_target_artifact("https://honey.fixture.test", args, target=TARGET)
        with masking.collecting_withheld_values(collector):
            return await artifact_capability.inspect_target_artifact("https://honey.fixture.test", args, target=TARGET)

    return asyncio.run(run()), seen


_DUMP_HEAD = "CREATE TABLE `users` (\n `id` int,\n `email` varchar(100),\n `password` varchar(255)\n);\n"
PAGINATED_DUMPS = {
    "per_row_inserts": _DUMP_HEAD + "".join(
        f"INSERT INTO `users` VALUES ({i},'u{i}@fixture.test','Fx{i}Pass!q');\n" for i in range(800)),
    "extended_insert": _DUMP_HEAD + "INSERT INTO `users` VALUES " + ",".join(
        f"({i},'u{i}@fixture.test','Fx{i}Pass!q')" for i in range(800)) + ";\n",
}


@pytest.mark.parametrize("style", sorted(PAGINATED_DUMPS))
@pytest.mark.parametrize("hunt", [True, False])
def test_paginated_dump_windows_withhold_every_password(monkeypatch, style, hunt):
    document = PAGINATED_DUMPS[style].encode()
    leaked = 0
    for offset in range(0, len(document), 16_384):
        collector = masking.WithheldValues(ACTION) if hunt else None
        result, seen = _inspect_at(monkeypatch, document, offset, 16_384, collector)
        text = json.dumps(result)
        leaked += text.count("Pass!q")
        if offset:
            assert seen[-1][0] == max(0, offset - artifact_capability.CONTEXT_BYTES)
        assert "@fixture.test" in result["observation"]["text_sample"]
    assert leaked == 0


@pytest.mark.parametrize(("document", "cut_before", "secret"), [
    ("APP_ENV=prod\nDB_PASSWORD=Hunter2passFx\nAPP_KEY=x\n", "Hunter2passFx", "Hunter2passFx"),
    ('<appSettings>\n<add key="ApiKey" value="abc123xyzSECRETFx"/>\n<add key="X" value="y"/>',
     "abc123xyzSECRETFx", "abc123xyzSECRETFx"),
    ("APP_ENV=prod\nDB_PASSWORD=Hunter2passFx\nAPP_KEY=x\n", "2passFx", "Hunter2passFx"),
])
def test_a_deliberate_offset_cut_does_not_reveal_the_value(monkeypatch, document, cut_before, secret):
    data = document.encode()
    offset = data.index(cut_before.encode())
    collector = masking.WithheldValues(ACTION)
    result, _seen = _inspect_at(monkeypatch, data, offset, 64, collector)
    sample = result["observation"]["text_sample"]
    assert cut_before not in sample and secret not in json.dumps(result)
    assert "[withheld:" in sample


def test_sealed_values_seed_every_later_output(encryption_key):
    """A value sealed earlier in the Hunt is withheld from any later output, whatever surrounds it."""
    from runtime.hunt_http_exchange import sealed_hunt_values, withholding_operation

    class Rows(_ActionRows):
        async def fetch(self, sql, *args):
            return [row for row in self.rows.values() if row["private_http_result"]]

    conn = Rows()
    asyncio.run(persist_withheld_values(
        conn, run=RUN, action_id=ACTION, target=TARGET, values={1: "FxSeededSecret01"}, status="success",
    ))
    assert asyncio.run(sealed_hunt_values(conn, run_id=HUNT, target=TARGET)) == ["FxSeededSecret01"]

    async def seed():
        return await sealed_hunt_values(conn, run_id=HUNT, target=TARGET)

    async def later_output():
        return mask_body_text("plain text mentions FxSeededSecret01 and fxseededsecret01 again")

    operation, collector = withholding_operation("http.request", str(uuid.UUID(int=699)), later_output, seed)
    masked = asyncio.run(operation())
    assert "seededsecret01" not in masked.lower() and "[withheld:1]" in masked
    other_target = TargetBinding(**{**TARGET.__dict__, "canonical_host": "other.fixture.test"})
    assert asyncio.run(sealed_hunt_values(conn, run_id=HUNT, target=other_target)) == []


# --- Round 2 should-fix: encoders that escape only the specials ------------------------------

@pytest.mark.parametrize(("value", "echo"), [
    ("aB3dE5fG7hJ9kL1m==", "aB3dE5fG7hJ9kL1m\\u003d\\u003d"),
    ("Win<ter>&Fx=2024", "Win\\u003cter\\u003e\\u0026Fx\\u003d2024"),
    ("Winter2024!x/Q", "Winter2024&#33;x&#47;Q"),
    ("Winter2024!x/Q", "Winter2024&#x21;x&#x2f;Q"),
    ("it's-Secret99", "it&#039;s-Secret99"),
    ("it's-Secret99", "it\\u0027s-Secret99"),
])
def test_specials_only_encoder_echoes_are_withheld(value, echo):
    out = masking.scrub_known_values(f"pre {echo} post", [value], "[B]")
    assert out == "pre [B] post", out


# --- Round 2 should-fix: the CSRF exemption is HTML-form only -------------------------------

@pytest.mark.parametrize("body", [
    '{"csrf_token": "FxCsrfJson0123456"}',
    '{"_token": "FxCsrfJson0123456"}',
    "csrf_token=FxCsrfConfig0123456",
    "csrf_secret=FxCsrfSecret0123456",
    '<input type="hidden" name="csrf_secret" value="FxCsrfSecret0123456">',
])
def test_csrf_named_secrets_outside_html_forms_stay_withheld(body):
    masked, _collector = _collect(body)
    assert "FxCsrf" not in masked


def test_session_name_value_rows_are_withheld():
    masked, collector = _collect(json.dumps({"rows": [["session_id", "FxSessionRow0123"], ["token_count", "5"]]}))
    assert "FxSessionRow0123" not in masked and '"5"' in masked
    sql, _collector = _collect("INSERT INTO kv VALUES ('PHPSESSID','FxPhpSess0123456');")
    assert "FxPhpSess0123456" not in sql


# --- Round 2 should-fix: secret URL parameters become references -----------------------------

def test_redirect_urls_withhold_secret_parameters_as_references():
    from capabilities.http_workflow import _withhold_url_secrets

    response = {
        "response": {"location": "/cb?code=FxAuthCode998877&state=xyz", "selected_headers": {
            "location": "/cb?code=FxAuthCode998877&state=xyz"}},
        "final_url": "https://honey.fixture.test/reset?reset_token=FxReset0123&lang=en",
        "redirect_chain": [{"location": "/s3?X-Amz-Signature=FxSig0123abcd&x=1"},
                           {"location": "/app#access_token=FxImplicit0123&token_type=bearer"}],
    }
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        _withhold_url_secrets(response)
    text = json.dumps(response)
    for secret in ("FxAuthCode998877", "FxReset0123", "FxSig0123abcd", "FxImplicit0123"):
        assert secret not in text and secret in collector.values
    assert "state=xyz" in text and "lang=en" in text and "token_type=bearer" in text
    assert "code=[withheld:1]" in response["response"]["location"]


# --- Round 2 should-fix: experiment extract digests ------------------------------------------

def test_experiment_extract_digest_is_keyed_when_the_response_held_a_secret(monkeypatch):
    import api.http_experiment as experiment

    keyed = experiment._body_digest(b"FxExtractedToken0123", withheld=True)
    assert keyed.startswith("hmac-sha256-")
    assert keyed != hashlib.sha256(b"FxExtractedToken0123").hexdigest()
    source = (Path(experiment.__file__)).read_text()
    assert '"sha256": hashlib.sha256(value.encode("utf-8")).hexdigest()' not in source


# --- Round 2 should-fix: the SKILL example is a valid http.request ---------------------------

def test_skill_withheld_ref_example_validates_against_the_registry():
    import re as _re

    from runtime.capability_registry import CAPABILITY_REGISTRY
    from runtime.hunt_http_contract import require_http_request_authority

    skill = (Path(__file__).resolve().parents[1] / "skills" / "hunt" / "SKILL.md").read_text()
    block = next(item for item in _re.findall(r"```\n(\{.*?\})\n```", skill, _re.DOTALL) if "withheld_ref" in item)
    example = json.loads(block.replace("<action id>", ACTION))
    CAPABILITY_REGISTRY.validate_hunt_input("http.request", example)
    assert require_http_request_authority(example, {"active_testing": True}) is False
