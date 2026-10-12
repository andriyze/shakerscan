"""A secret holding ``&``, ``=``, ``;``, ``#``, quotes or blanks is withheld whole (2.8.2 acceptance).

A Django-style ``SECRET_KEY`` in honey's ``/.env`` (66 characters, ``&`` at position 50) was shown
to the Hunt planner as ``[withheld:1]&z+...`` and in the masked JSON/HAR exports as ``***&z+...``:
an assignment at the start of a line ended at ``&`` as if it were a query-string separator. A
``web.config`` connection string cut its password at the ``&`` of ``&amp;`` the same way.

Every value below is a synthetic unit fixture, never a real secret. Each is built from distinctive
segments joined by the characters under test, so a leaked tail is detected by any segment.
"""

from __future__ import annotations

import asyncio
import html
import json
import re
import sys
import urllib.parse
import uuid

import pytest
from runtime.models import TargetBinding

from api.capabilities import artifact as artifact_capability
from api.capabilities.http import WorkerPrivateHTTPResponse
from api.runtime.http_archive_reader import export_document

masking = sys.modules[artifact_capability.mask_body_text.__module__]
mask_body_text = masking.mask_body_text

SEPARATORS = "&=;#'\" "
SEGMENTS = ("Qx7vKp", "Wz9kLm", "Ty3mNb", "Pb8nVc", "Rc2hXz", "Ld5jAs", "Fs6gDf", "Hn4tGh")
# Every separator under test inside one value: & = ; # ' " and a blank.
VALUE = "".join(segment + separator for segment, separator in zip(SEGMENTS, SEPARATORS)) + SEGMENTS[-1]
# The same without quotes, for the forms whose syntax cannot carry one unescaped.
UNQUOTED = VALUE.replace("'", "").replace('"', "")
# Honey's shape: 66 characters, Django's alphabet, ``&`` at position 50.
DJANGO_KEY = "django-insecure-" + "k3x9qv7m2pw8zr4t6yn1bc5df0gh2js8la" + "&" + "z+%u95)e2fhb2vu"
assert len(DJANGO_KEY) == 66 and DJANGO_KEY.index("&") == 50


def _leaked(text: str, segments=SEGMENTS) -> list[str]:
    return [segment for segment in segments if segment in text]


def _sql_doubled(value: str) -> str:
    return value.replace("'", "''")


def _sql_backslashed(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')


TABLE = "CREATE TABLE `users` (`id` int, `username` varchar(20), `password` varchar(255));\n"

# (name, body, the value the body holds, segments that must not survive)
BODIES = [
    (".env unquoted", f"DEBUG=False\nSECRET_KEY={VALUE}\nALLOWED_HOSTS=*\n", VALUE),
    (".env export", f"export DB_PASSWORD={VALUE}\n", VALUE),
    (".env double-quoted", 'SECRET_KEY="' + VALUE.replace('"', '\\"') + '"\n', VALUE),
    (".env single-quoted", "SECRET_KEY='" + VALUE.replace("'", "\\'") + "'\n", VALUE),
    (".env leading ampersand", f"API_TOKEN=&{UNQUOTED}\n", "&" + UNQUOTED),
    (".ini", f"[database]\npassword = {VALUE}\nhost = db.fixture.test\n", VALUE),
    ("web.config appSettings",
     f'<appSettings>\n  <add key="ApiKey" value="{html.escape(VALUE)}" />\n</appSettings>\n', VALUE),
    ("web.config connection string",
     '<connectionStrings>\n  <add name="Default" connectionString="Server=sql.fixture.test;'
     f'Database=App;User Id=app;Password={html.escape(UNQUOTED.replace(";", ""))};" />\n'
     "</connectionStrings>\n", UNQUOTED.replace(";", "")),
    ("web.config quoted connection string",
     '<add name="Default" connectionString="Server=s;Password=\''
     + html.escape(VALUE.replace("'", "''")) + '\';Database=App" />\n', VALUE),
    ("appsettings.json connection string",
     json.dumps({"ConnectionStrings": {
         "Default": f"Server=s;Password={UNQUOTED.replace(';', '')};Database=App"}}),
     UNQUOTED.replace(";", "")),
    ("plain connection string", f"Server=s;Password={UNQUOTED.replace(';', '')};Database=App\n",
     UNQUOTED.replace(";", "")),
    ("phpinfo table",
     '<table>\n<tr><td class="e">DB_PASSWORD </td><td class="v">' + html.escape(VALUE)
     + ' </td></tr>\n<tr><td class="e">DB_HOST </td><td class="v">db.fixture.test </td></tr>\n</table>',
     VALUE),
    ("phpinfo text", f"DB_PASSWORD => {VALUE}\nDB_HOST => db.fixture.test\n", VALUE),
    ("SQL INSERT doubled quotes", TABLE + f"INSERT INTO `users` VALUES (1,'bob','{_sql_doubled(VALUE)}');\n",
     VALUE),
    ("SQL INSERT backslash escapes",
     TABLE + f"INSERT INTO `users` VALUES (1,'bob','{_sql_backslashed(VALUE)}');\n", VALUE),
    ("SQL COPY", f"COPY public.users (id, username, password) FROM stdin;\n1\tbob\t{VALUE}\n\\.\n", VALUE),
    ("YAML", f"secret_key: {VALUE}\n", VALUE),
    ("redirect link in a body",
     '<a href="/login?next=%2Fcb%3Faccess_token%3D'
     + urllib.parse.quote(urllib.parse.quote(VALUE, safe=""), safe="") + '">continue</a>',
     # Nested once: the inner URL carries the value percent-encoded, as it is sent there.
     urllib.parse.quote(VALUE, safe="")),
]


@pytest.mark.parametrize(("name", "body", "value"), BODIES, ids=[item[0] for item in BODIES])
def test_masked_view_withholds_the_whole_value(name, body, value):
    masked = mask_body_text(body)
    assert _leaked(masked) == [], f"{name}: tail left in {masked!r}"


@pytest.mark.parametrize(("name", "body", "value"), BODIES, ids=[item[0] for item in BODIES])
def test_planner_view_binds_the_whole_value_behind_one_reference(name, body, value):
    collector = masking.WithheldValues(str(uuid.UUID(int=601)))
    with masking.collecting_withheld_values(collector):
        masked = mask_body_text(body)
    assert _leaked(masked) == [], f"{name}: tail left in {masked!r}"
    # The reference stands for the complete value, so a Hunt that binds it sends the real one.
    assert value in collector.values, name


def test_honey_shaped_django_key_is_one_reference_and_nothing_after_it():
    body = f"DEBUG=False\nSECRET_KEY={DJANGO_KEY}\nDATABASE_URL=postgres://app@db.fixture.test/app\n"
    collector = masking.WithheldValues(str(uuid.UUID(int=602)))
    with masking.collecting_withheld_values(collector):
        masked = mask_body_text(body)
    assert "SECRET_KEY=[withheld:1]\n" in masked
    assert DJANGO_KEY[51:] not in masked and "z+%u95" not in masked
    assert collector.values[0] == DJANGO_KEY
    assert "SECRET_KEY=***\n" in mask_body_text(body)


@pytest.mark.parametrize("encode", [
    lambda value: urllib.parse.quote(value, safe=""), urllib.parse.quote_plus,
])
def test_redirect_url_parameter_is_withheld_whole(encode):
    for url, kept in (
        (f"https://honey.fixture.test/cb?code={encode(VALUE)}&state=fixture-state", "state=fixture-state"),
        (f"https://honey.fixture.test/cb#access_token={encode(VALUE)}&token_type=bearer", "token_type=bearer"),
    ):
        masked = masking.mask_url_secrets(url)
        assert _leaked(masked) == [], masked
        assert kept in masked


@pytest.mark.parametrize("text", [
    "GET /search?token=abc123def&next=%2Fhome HTTP/1.1",
    '<a href="/x?password=abc123def&amp;next=1">next</a>',
])
def test_inline_query_parameters_after_a_secret_stay_visible(text):
    """Mid-line, ``&`` still separates query parameters: only the secret's own value goes."""
    masked = mask_body_text(text)
    assert "abc123def" not in masked
    assert "next=" in masked


# --- The masked archive exports and the model-facing artifact output ----------------------------

HUNT = str(uuid.UUID(int=611))
ACTION = str(uuid.UUID(int=612))
TARGET = TargetBinding(
    target_id=str(uuid.UUID(int=613)), target_kind="web", canonical_host="honey.fixture.test",
    allowed_origins=("https://honey.fixture.test",), allowed_addresses=("192.0.2.10",),
    allowed_root_domains=("fixture.test",), environment="lab", scope_receipt_id=str(uuid.UUID(int=614)),
)
ARCHIVED = [body for _name, body, _value in BODIES]


def _hunt_rows():
    rows = [{
        "id": str(uuid.UUID(int=700 + index)), "plane": "hunt", "sequence": index,
        "hunt_run_id": HUNT, "hunt_action_id": ACTION, "capability_name": "artifact.inspect",
        "method": "GET", "url": f"https://honey.fixture.test/f{index}", "status_code": 200,
        "request_headers": {}, "request_body": None,
        "response_headers": {"content-type": "text/plain"}, "response_body": body,
        "metadata_json": {},
    } for index, body in enumerate(ARCHIVED)]
    rows.append({
        "id": str(uuid.UUID(int=799)), "plane": "hunt", "sequence": len(rows),
        "hunt_run_id": HUNT, "hunt_action_id": ACTION, "capability_name": "http.request",
        "method": "GET", "url": "https://honey.fixture.test/login", "status_code": 302,
        "request_headers": {}, "request_body": None,
        "response_headers": {"location": "https://honey.fixture.test/cb?code="
                             + urllib.parse.quote(VALUE, safe="") + "&state=fixture-state"},
        "response_body": "", "metadata_json": {},
    })
    return rows


@pytest.mark.parametrize("export_format", ["transactions", "har"])
def test_hunt_masked_archive_export_holds_no_tail(export_format):
    rows = _hunt_rows()
    document = export_document(
        rows, export_format=export_format, redaction="redacted", owner={"hunt_id": HUNT}, total=len(rows),
    )
    text = json.dumps(document)
    assert _leaked(text) == []
    assert DJANGO_KEY[51:] not in text
    assert "db.fixture.test" in text  # the bodies are present; only the secrets are withheld


def _inspect(monkeypatch, body: str, collector):
    async def fake_execute(_target_url, _args, **kwargs):
        kwargs["private_response_sink"](WorkerPrivateHTTPResponse(
            status_code=200, final_url="https://honey.fixture.test/.env", _body=body.encode(),
            _headers={"content-type": "text/plain"}, _cookies={},
        ))
        return {"ok": True, "response": {"status": 200}}

    monkeypatch.setattr(artifact_capability, "execute_bound_http_request", fake_execute)

    async def run():
        with masking.collecting_withheld_values(collector):
            return await artifact_capability.inspect_target_artifact(
                "https://honey.fixture.test", {"path": "/.env", "max_bytes": 16_384}, target=TARGET)

    return asyncio.run(run())


@pytest.mark.parametrize(("name", "body", "value"), BODIES, ids=[item[0] for item in BODIES])
def test_artifact_output_shows_the_planner_no_tail(monkeypatch, name, body, value):
    collector = masking.WithheldValues(ACTION)
    result = _inspect(monkeypatch, body, collector)
    text = json.dumps(result)
    assert _leaked(text) == [], name
    assert value in collector.values, name


def test_fixture_value_holds_every_separator_under_test():
    assert all(separator in VALUE for separator in SEPARATORS)
    assert re.split(r"[&=;#'\" ]", VALUE) == list(SEGMENTS)


# --- Every other path a body reaches the planner by -----------------------------------------------

def test_http_request_observation_withholds_the_whole_value(monkeypatch):
    """``http.request`` run as the worker runs it (executor -> adapter -> observation): a .env body
    and a redirect whose code holds every separator."""
    import httpx
    from api.capabilities.http import execute_bound_http_request
    from capabilities.inline import HttpRequestExecutionAdapter
    from runtime.capability_registry import CAPABILITY_REGISTRY
    from runtime.hunt_http_exchange import withholding_operation

    env = BODIES[0][1]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={
                "location": "/.env?code=" + urllib.parse.quote(VALUE, safe="") + "&state=fixture-state"})
        return httpx.Response(200, headers={"content-type": "text/plain"}, content=env.encode())

    class _MockClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs.pop("transport", None)
            super().__init__(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _MockClient)

    async def operation():
        return await execute_bound_http_request(
            "https://honey.fixture.test",
            {"method": "GET", "path": "/start", "follow_redirects": True, "selected_headers": ["location"]},
            target=TARGET, allow_bound_origin_redirects=True)

    wrapped, collector = withholding_operation("http.request", ACTION, operation)
    adapter = HttpRequestExecutionAdapter(
        specification=CAPABILITY_REGISTRY.require("http.request"), operation=wrapped,
        requested_budget={"http_requests": 5, "tool_wall_seconds": 30}, redacted_execution={})
    outcome = asyncio.run(adapter.execute(heartbeat=lambda: None, cancelled=lambda: False))
    observation = json.dumps(outcome.observations)
    assert outcome.status == "success"
    assert _leaked(observation) == []
    assert VALUE in collector.values and "state=fixture-state" in observation


@pytest.mark.parametrize(("name", "body", "value"), BODIES, ids=[item[0] for item in BODIES])
def test_http_experiment_summary_withholds_the_whole_value(name, body, value):
    """``http.experiment`` (and the research agent's experiments) summarize a response body."""
    import httpx
    from api.http_experiment import response_summary

    collector = masking.WithheldValues(ACTION)
    response = httpx.Response(200, headers={"content-type": "text/plain"}, content=body.encode())
    with masking.collecting_withheld_values(collector):
        summary = response_summary(response, body.encode())
    assert _leaked(json.dumps(summary)) == [], name
    assert value in collector.values, name


def test_mcp_tool_result_relays_no_tail(monkeypatch):
    """The client's ``shakerscan_hunt_capability`` MCP tool relays the planner view unchanged."""
    from tests.test_hunt_withheld_values import _load_mcp
    from tests.test_mcp_refusal_reasons import ScriptedOpener

    mcp = _load_mcp()
    collector = masking.WithheldValues(ACTION)
    observation = _inspect(monkeypatch, BODIES[0][1], collector)["observation"]
    hunt_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab"
    client = mcp.ArsenalClient("http://127.0.0.1:8080", poll_seconds=0.01, action_wait_seconds=0.5)
    client.opener = ScriptedOpener({
        ("GET", f"/hunts/{hunt_id}"): {
            "hunt_id": hunt_id, "status": "active",
            "capabilities": [{"name": "artifact.inspect", "input_schema": {"type": "object"}}],
        },
        ("POST", f"/hunts/{hunt_id}/capabilities/artifact.inspect"): {
            "hunt_id": hunt_id, "capability": "artifact.inspect", "action_id": ACTION,
            "action_result": {"status": "success", "observations": [observation]},
        },
    })
    result = client.call_tool("shakerscan_hunt_capability", {
        "hunt_id": hunt_id, "capability_name": "artifact.inspect",
        "input": {"path": "/.env"}, "idempotency_key": "separators-key-1",
    })
    text = json.dumps(result)
    assert _leaked(text) == []
    assert f"withheld://hunt/{ACTION}/1" in text


# --- Hostile values: generated, seeded ------------------------------------------------------------
#
# Each generated secret mixes the separators and encodings that cut values before (& = ; # % +,
# quotes, blanks, newlines where the format can carry one, non-ASCII, very long values) and is
# placed in every format in the form that format writes it. No substring of 4 or more characters
# of the secret (or of its encoded form in a URL) may reach the planner view or the masked
# JSON/HAR exports, except one the same body without the secret already shows.

import random  # noqa: E402

_HOSTILE_SPECIALS = "&=;#%+'\" "
_HOSTILE_UNICODE = "éжб密碼ß€🔑"
_ALNUM = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"


def _hostile_values(count: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    values = []
    for index in range(count):
        length = rng.choice((8, 16, 33, 66, 140, 700, 2000)) if index % 5 else rng.randint(6, 24)
        pool = _ALNUM * 3 + _HOSTILE_SPECIALS * 2 + _HOSTILE_UNICODE
        middle = "".join(rng.choice(pool) for _ in range(length))
        # An unquoted value's own syntax: no blank before a comment character, not starting with a
        # bracket, starting and ending with a plain character (a trailing ``;`` is a separator).
        middle = re.sub(r" +([#;])", r"\1", middle)
        values.append(rng.choice(_ALNUM) + middle + rng.choice(_ALNUM))
    return values


HOSTILE = _hostile_values(36, seed=283)
assert any("&" in value and "%" in value and "+" in value for value in HOSTILE)
assert any(len(value) > 1000 for value in HOSTILE)


def _dq_env(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _copy_field(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n")


_HOSTILE_FORMS = {
    ".env unquoted": lambda v: f"DEBUG=0\nSECRET_KEY={v}\nALLOWED_HOSTS=*\n",
    ".env double-quoted multi-line": lambda v: 'DB_PASSWORD="' + _dq_env(v[: len(v) // 2] + "\n" + v[len(v) // 2:]) + '"\n',
    "json": lambda v: json.dumps({"debug": False, "api_key": v}),
    "yaml double-quoted": lambda v: "secret_key: " + json.dumps(v, ensure_ascii=False) + "\nhost: db.fixture.test\n",
    "web.config value": lambda v: f'<appSettings>\n  <add key="ApiKey" value="{html.escape(v)}" />\n</appSettings>\n',
    "web.config connection string": lambda v: (
        '<add name="Default" connectionString="Server=s;Password=\''
        + html.escape(v.replace("'", "''")) + '\';Database=App" />\n'),
    "phpinfo": lambda v: ('<table><tr><td class="e">DB_PASSWORD </td><td class="v">' + html.escape(v)
                          + ' </td></tr></table>'),
    "sql insert": lambda v: TABLE + "INSERT INTO `users` VALUES (1,'bob','" + v.replace("'", "''") + "');\n",
    "sql copy": lambda v: ("COPY public.users (id, username, password) FROM stdin;\n1\tbob\t"
                           + _copy_field(v) + "\n\\.\n"),
    # Backslash-escaped quotes, the way minified JavaScript and PHP write them, after a ``;``.
    "js minified": lambda v: "!function(){};var apiKey=" + json.dumps(v, ensure_ascii=False) + ";var b=2;",
    "php single-quoted": lambda v: ("<?php $a=1;$password='" + v.replace("\\", "\\\\").replace("'", "\\'")
                                    + "';\n"),
    "connection string with blanks": lambda v: (
        "Server=s; Database=App; Password='" + v.replace("\n", " ").replace("'", "''") + "'; Encrypt=True\n"),
    # A password input with no secret-like name (2.9.0): its type makes it a password.
    "password input": lambda v: '<form><input name="f7" value="' + html.escape(v) + '" type="password"></form>',
    "redirect link": lambda v: ('<a href="/cb?access_token=' + urllib.parse.quote(v, safe="")
                                + '&amp;state=fixture-state">continue</a>'),
}


def _hostile_forms(value: str) -> list[str]:
    """The secret as it may appear: itself and URL-encoded."""
    return [value, urllib.parse.quote(value, safe=""), urllib.parse.quote_plus(value)]


def _hostile_leaks(output: str, value: str, template_output: str) -> list[str]:
    leaks = []
    for form in _hostile_forms(value):
        for start in range(0, max(1, len(form) - 3)):
            piece = form[start:start + 4]
            if len(piece) == 4 and piece in output and piece not in template_output:
                leaks.append(piece)
                break
    return leaks


def _template(form: str) -> str:
    return mask_body_text(_HOSTILE_FORMS[form]("Zz"))


@pytest.mark.parametrize("form", sorted(_HOSTILE_FORMS))
def test_hostile_values_never_reach_the_planner_view(form):
    template = _template(form)
    for value in HOSTILE:
        collector = masking.WithheldValues(ACTION)
        with masking.collecting_withheld_values(collector):
            masked = mask_body_text(_HOSTILE_FORMS[form](value))
        assert _hostile_leaks(masked, value, template) == [], (form, len(value))


@pytest.mark.parametrize("export_format", ["transactions", "har"])
def test_hostile_values_never_reach_the_masked_exports(export_format):
    rows, expected = [], []
    for form in sorted(_HOSTILE_FORMS):
        for value in HOSTILE[:12]:
            index = len(rows)
            rows.append({
                "id": str(uuid.UUID(int=900 + index)), "plane": "hunt", "sequence": index,
                "hunt_run_id": HUNT, "hunt_action_id": ACTION, "capability_name": "artifact.inspect",
                "method": "GET", "url": f"https://honey.fixture.test/h{index}", "status_code": 302,
                "request_headers": {},
                "request_body": None,
                "response_headers": {"content-type": "text/plain", "location": (
                    "https://honey.fixture.test/cb?code=" + urllib.parse.quote(value, safe="") + "&state=s")},
                "response_body": _HOSTILE_FORMS[form](value), "metadata_json": {},
            })
            expected.append((form, value))
    document = export_document(rows, export_format=export_format, redaction="redacted",
                               owner={"hunt_id": HUNT}, total=len(rows))
    text = json.dumps(document, ensure_ascii=False)
    template = "".join(_template(form) for form in _HOSTILE_FORMS) + json.dumps(
        export_document(rows[:1], export_format=export_format, redaction="redacted",
                        owner={"hunt_id": HUNT}, total=1), ensure_ascii=False)
    for form, value in expected:
        # JSON text escapes a quote, a backslash, a newline; compare the decoded and the escaped forms.
        escaped = json.dumps(value, ensure_ascii=False)[1:-1]
        assert _hostile_leaks(text, value, template) == [], (export_format, form, len(value))
        assert _hostile_leaks(text, escaped, template) == [], (export_format, form, len(value))


# --- Review of the fix: code is not a secret, and no tail at any length --------------------------

@pytest.mark.parametrize("code", [
    "tokens.map(token => token.trim())",
    "  password => validatePassword(password),",
    "const apiKey => fetch('/k')",
    "$a = ['password' => $_ENV['DB_PASS'], 'token' => getToken()];",
    "match ($x) { 'secret' => handleSecret() }",
])
def test_arrow_code_is_not_read_as_a_php_info_value(code):
    """``=>`` is a separator only as ``php -i`` writes it, not in JS or PHP code."""
    assert mask_body_text(code) == code


@pytest.mark.parametrize(("body", "value"), [
    ("Server=s;Password='Ab1;Cd2''Ef3Gh4TailQq';Database=App", "Ab1;Cd2'Ef3Gh4TailQq"),
    ('Server=s;Password=Ab1"Ef3Gh4TailQq;Database=App', 'Ab1"Ef3Gh4TailQq'),
    (json.dumps({"conn": 'Server=s;Password=Ab1&Ef3"Gh4TailQq;'}), 'Ab1&Ef3"Gh4TailQq'),
])
def test_plain_connection_string_values_with_quotes_are_withheld_whole(body, value):
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        masked = mask_body_text(body)
    assert "TailQq" not in masked and "Gh4" not in masked
    assert collector.values == [value]


def test_a_line_value_longer_than_any_bound_is_withheld_whole():
    value = "A" * 9000 + "&TailSecretQq"
    masked = mask_body_text(f"SECRET_KEY={value}\nDEBUG=0\n")
    assert masked == "SECRET_KEY=***\nDEBUG=0\n"
    inline = mask_body_text("note: api_key=" + "B" * 9000 + "TailSecretQq here")
    assert "TailSecretQq" not in inline and inline.endswith(" here")


def test_a_line_value_ending_in_a_bracket_keeps_it():
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        masked = mask_body_text("SECRET_KEY=k3x9qv7m2p+bqeo=)\n")
    assert masked == "SECRET_KEY=[withheld:1]\n" and collector.values == ["k3x9qv7m2p+bqeo=)"]


def test_an_unclosed_quote_does_not_swallow_the_markup_after_it():
    body = 'PASSWORD="abc123def\n<input name="token" value="zz">\n<p>after</p>\n'
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        masked = mask_body_text(body)
    assert "abc123def" not in masked and "<p>after</p>" in masked
    assert "abc123def" in collector.values


@pytest.mark.parametrize("body", [
    '!function(){};var apiKey="Qx7vKp\\"Wz9kLmTy3mNb";',
    '(0);const client_secret="Qx7vKp\\"Wz9kLm&Ty3mNb";',
    "var a=1;password='Qx7vKp\\'Wz9kLmTy3mNb';var b=2;",
    'n.x=1;apiKey:"Qx7vKp\\"Wz9kLmTy3mNb",y:2',
    '<?php $a=1;$password="Qx7vKp\\"Wz9kLmTy3mNb";',
    'Server=s;Password="Qx7vKp"Wz9kLmTy3mNb;Database=App',
])
def test_escaped_quotes_after_a_semicolon_are_withheld_whole(body):
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        masked = mask_body_text(body)
    assert _leaked(masked, ("Qx7v", "Wz9k", "Ty3m", "3mNb")) == [], masked
    assert any("Wz9kLm" in value and "Qx7vKp" in value for value in collector.values)


@pytest.mark.parametrize("body", [
    "Server=s; Database=App; Password=Ab1&Cd2Tail; Encrypt=True",
    json.dumps({"ConnectionStrings": {"Default": "Server=s; Database=App; Password=Ab1&Cd2Tail; Encrypt=True"}}),
])
def test_connection_strings_with_blanks_after_the_separator_are_withheld_whole(body):
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        masked = mask_body_text(body)
    assert "Cd2Tail" not in masked and "Encrypt=True" in masked
    assert collector.values == ["Ab1&Cd2Tail"]


@pytest.mark.parametrize(("body", "kept"), [
    ("$_SERVER['DB_PASSWORD'] => Ab1&Cd2Tail\n$_ENV['DB_PASSWORD'] => Ab1&Cd2Tail\n$_SERVER['HOME'] => /root\n",
     "/root"),
    ("services:\n  app:\n    environment:\n      - DB_PASSWORD=Ab1&Cd2Tail\n      - DEBUG=0\n", "DEBUG=0"),
    ("class JConfig {\n\tpublic $password = 'Ab1&Cd2Tail';\n\tpublic $user = 'joomla';\n}", "joomla"),
    (" " * 40 + "SECRET_KEY=Ab1&Cd2Tail\n", "SECRET_KEY="),
])
def test_php_info_superglobals_compose_lists_php_properties_and_deep_indents(body, kept):
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        masked = mask_body_text(body)
    assert "Cd2Tail" not in masked and kept in masked
    assert collector.values == ["Ab1&Cd2Tail"]


# --- URL userinfo (N1): a password behind an empty user name, and every other userinfo shape -------
#
# 2.8.2 and 2.8.3 acceptance: ``REDIS_URL=redis://:<password>@redis.internal:6379/0`` in honey's
# ``/.env`` reached the planner whole in ``http.request``'s ``response.body_sample``, while
# ``DATABASE_URL=postgres://user:<password>@...`` was withheld: the body passes knew a userinfo
# password only by the provider pattern, which needs a user name. The exports and
# ``artifact.inspect`` also ran the scanner's free-text redaction, which hid the gap there. The
# passwords below are generated (seeded) synthetic fixtures, never real secrets.

_URL_SCHEMES = ("redis", "rediss", "amqp", "mongodb+srv", "postgres", "mysql", "http", "https", "ftp", "smtp")
_URL_HOSTS = ("redis.internal:6379", "[::1]:6379", "[2001:db8::7]", "10.0.0.5:5672", "db.fixture.test")
# What a userinfo password may hold as written (RFC 3986 unreserved, sub-delimiters and ``:``), and
# ``@``: the userinfo ends at the authority's last one.
_USERINFO_WRITTEN = "-._~!$&'()*+,;=:@"
# What it may hold only percent-encoded.
_USERINFO_ENCODED_ONLY = " /?#%\"<>[]\\^`{|}" + _HOSTILE_UNICODE


def _url_cases(count: int, seed: int) -> list[tuple[str, str, str, str, str]]:
    """(scheme, user name, decoded password, password as written, host)."""
    rng = random.Random(seed)
    cases = []
    for index in range(count):
        length = rng.choice((4, 6, 9, 16, 24, 40, 120))
        encoded = index % 3 == 0
        pool = _ALNUM * 3 + _USERINFO_WRITTEN * 2 + (_USERINFO_ENCODED_ONLY if encoded else "")
        password = rng.choice(_ALNUM) + "".join(rng.choice(pool) for _ in range(length)) + rng.choice(_ALNUM)
        written = urllib.parse.quote(password, safe=rng.choice(("", "!$&'()*+,;=:"))) if encoded else password
        user = "" if index % 2 == 0 else rng.choice(("app", "halvern_app", "u%40corp", "default"))
        cases.append((_URL_SCHEMES[index % len(_URL_SCHEMES)], user, password, written,
                      _URL_HOSTS[index % len(_URL_HOSTS)]))
    return cases


URL_CASES = _url_cases(60, seed=2831)
assert sum(1 for case in URL_CASES if case[1] == "") >= 25  # the N1 shape: no user name
assert any("@" in case[3] for case in URL_CASES) and any("%" in case[3] for case in URL_CASES)
assert {case[0] for case in URL_CASES} == set(_URL_SCHEMES)


def _url(scheme: str, user: str, written: str, host: str) -> str:
    return f"{scheme}://{user}:{written}@{host}/0"


# Where a URL is written. The second item says whether the reference must bind the decoded password
# exactly (markup character references read as their characters, percent-escapes decoded).
_URL_CONTEXTS = {
    ".env": (lambda url: f"DEBUG=0\nREDIS_URL={url}\nALLOWED_HOSTS=*\n", True),
    ".env double-quoted": (lambda url: f'CACHE_URL="{url}"\nDEBUG=0\n', True),
    ".env single-quoted": (lambda url: "BROKER_URL='" + url.replace("'", "%27") + "'\nDEBUG=0\n", True),
    "json string": (lambda url: json.dumps({"debug": False, "cache": {"backends": [url]}}), True),
    "json escaped in a string": (lambda url: json.dumps({"settings": json.dumps({"cache": url})}), True),
    "yaml": (lambda url: f"cache:\n  url: {url}\n  timeout: 5\n", True),
    "query string": (lambda url: f"GET /connect?next={url}&x=1 HTTP/1.1\n", True),
    "query string percent-encoded": (
        lambda url: "<a href=\"/connect?next=" + urllib.parse.quote(url, safe="") + "&amp;x=1\">go</a>", True),
    "html attribute": (lambda url: f'<a href="{html.escape(url)}">cache</a>', True),
    "html text": (lambda url: f"<pre>connecting to {html.escape(url)} failed</pre>", True),
    "js string": (lambda url: f"var cache = '{url.replace(chr(39), '%27')}'; var n = 2;", True),
    "log line": (lambda url: f"[error] connecting to {url} failed: timeout\n", True),
}


def _url_leaks(output: str, password: str, written: str, template: str) -> list[str]:
    leaks = []
    for form in dict.fromkeys((password, written, urllib.parse.quote(password, safe=""))):
        for start in range(0, max(1, len(form) - 3)):
            piece = form[start:start + 4]
            if len(piece) == 4 and piece in output and piece not in template:
                leaks.append(piece)
                break
    return leaks


def _url_template(context: str, scheme: str, user: str, host: str) -> str:
    return mask_body_text(_URL_CONTEXTS[context][0](_url(scheme, user, "Zz", host)))


@pytest.mark.parametrize("context", sorted(_URL_CONTEXTS))
def test_url_userinfo_passwords_never_reach_the_planner_view(context):
    build, exact = _URL_CONTEXTS[context]
    for scheme, user, password, written, host in URL_CASES:
        body = build(_url(scheme, user, written, host))
        collector = masking.WithheldValues(ACTION)
        with masking.collecting_withheld_values(collector):
            masked = mask_body_text(body)
        template = _url_template(context, scheme, user, host)
        case = (context, scheme, user, len(password))
        assert _url_leaks(masked, password, written, template) == [], case
        assert _url_leaks(mask_body_text(body), password, written, template) == [], case
        if exact:
            # The reference stands for the password a client sends: decoded, whole.
            assert password in collector.values, case
        if "percent-encoded" not in context:
            assert f"@{host}" in html.unescape(masked).replace("\\/", "/"), case  # the host stays readable
            assert f"://{user}:" in html.unescape(masked), case  # so does the user name


@pytest.mark.parametrize("scheme", _URL_SCHEMES)
@pytest.mark.parametrize("userinfo", ["user:@", ":@", "user@", "@"])
def test_url_userinfo_without_a_password_is_kept(scheme, userinfo):
    body = f"CACHE_URL={scheme}://{userinfo}cache.fixture.test:6379/0\nDEBUG=0\n"
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        assert mask_body_text(body) == body
    assert collector.values == []


# --- Every entry point, with the N1 shape and the generated userinfo passwords --------------------

# The empty user name cases (the N1 shape), raw and percent-encoded, with ``@`` and ``:`` inside.
N1_CASES = [case for case in URL_CASES if case[1] == ""][:12]
N1_PASSWORD = "Rd5:p@ss!w$rd&x'Kq9Zt"


def _n1_env(written: str, scheme: str = "redis", host: str = "redis.internal:6379") -> str:
    return (f"DEBUG=0\nDATABASE_URL=postgres://halvern_app:Pg7Hx2Vw9Kq@db.fixture.test/app\n"
            f"REDIS_URL={scheme}://:{written}@{host}/0\nALLOWED_HOSTS=*\n")


def _assert_withheld(text: str, password: str, written: str, collector=None, template: str = "") -> None:
    assert _url_leaks(text, password, written, template) == [], text[:400]
    if collector is not None:
        assert password in collector.values


def test_honey_n1_redis_url_is_one_reference_beside_the_database_url():
    body = _n1_env("S3cr3tPassw0rd123Zq")
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        masked = mask_body_text(body)
    assert "REDIS_URL=redis://:[withheld:2]@redis.internal:6379/0\n" in masked
    assert "DATABASE_URL=postgres://halvern_app:[withheld:1]@db.fixture.test/app\n" in masked
    assert collector.values == ["Pg7Hx2Vw9Kq", "S3cr3tPassw0rd123Zq"]
    assert "REDIS_URL=redis://:***@redis.internal:6379/0\n" in mask_body_text(body)


@pytest.mark.parametrize("case", N1_CASES + [("redis", "", N1_PASSWORD, N1_PASSWORD, "redis.internal")],
                         ids=lambda case: f"{case[0]}-{len(case[2])}")
def test_http_request_observation_withholds_an_empty_user_password(monkeypatch, case):
    """``http.request`` as the worker runs it: the body sample, a followed redirect whose location
    nests the URL, and a selected header that carries one."""
    import httpx
    from api.capabilities.http import execute_bound_http_request
    from capabilities.inline import HttpRequestExecutionAdapter
    from runtime.capability_registry import CAPABILITY_REGISTRY
    from runtime.hunt_http_exchange import withholding_operation

    scheme, _user, password, written, host = case

    def observe(written: str):
        url = _url(scheme, "", written, host)

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/start":
                return httpx.Response(302, headers={"location": "/.env?next=" + urllib.parse.quote(url, safe="")})
            return httpx.Response(200, headers={"content-type": "text/plain", "x-cache-backend": url},
                                  content=_n1_env(written, scheme, host).encode())

        class _MockClient(httpx.AsyncClient):
            def __init__(self, *args, **kwargs):
                kwargs.pop("transport", None)
                super().__init__(transport=httpx.MockTransport(handler), **kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", _MockClient)

        async def operation():
            return await execute_bound_http_request(
                "https://honey.fixture.test",
                {"method": "GET", "path": "/start", "follow_redirects": True,
                 "selected_headers": ["location", "x-cache-backend"]},
                target=TARGET, allow_bound_origin_redirects=True)

        wrapped, collector = withholding_operation("http.request", ACTION, operation)
        adapter = HttpRequestExecutionAdapter(
            specification=CAPABILITY_REGISTRY.require("http.request"), operation=wrapped,
            requested_budget={"http_requests": 5, "tool_wall_seconds": 30}, redacted_execution={})
        outcome = asyncio.run(adapter.execute(heartbeat=lambda: None, cancelled=lambda: False))
        assert outcome.status == "success"
        return json.dumps(outcome.observations, ensure_ascii=False), collector

    observation, collector = observe(written)
    template, _ = observe("Zz")
    _assert_withheld(observation, password, written, collector, template)
    assert "REDIS_URL=" in observation and "ALLOWED_HOSTS" in observation


@pytest.mark.parametrize("case", N1_CASES, ids=lambda case: f"{case[0]}-{len(case[2])}")
def test_http_experiment_summary_withholds_an_empty_user_password(case):
    import httpx
    from api.http_experiment import response_summary

    scheme, _user, password, written, host = case
    url = _url(scheme, "", written, host)
    body = json.dumps({"cache": url, "env": _n1_env(written, scheme, host)})
    collector = masking.WithheldValues(ACTION)
    response = httpx.Response(200, headers={"content-type": "application/json", "x-cache-backend": url,
                                            "link": f"<{url}>; rel=cache"}, content=body.encode())
    with masking.collecting_withheld_values(collector):
        summary = response_summary(response, body.encode(), selected_json_paths=["$.cache"],
                                   selected_headers=["x-cache-backend", "link"])
    text = json.dumps(summary, ensure_ascii=False)
    _assert_withheld(text, password, written, collector)
    shown = {entry["marker"] for entry in summary["withheld_values"]}
    assert set(re.findall(r"\[withheld:\d+\]", text)) <= shown  # every marker shown has its entry


@pytest.mark.parametrize("case", N1_CASES, ids=lambda case: f"{case[0]}-{len(case[2])}")
def test_artifact_inspect_withholds_an_empty_user_password(monkeypatch, case):
    scheme, _user, password, written, host = case
    collector = masking.WithheldValues(ACTION)
    result = _inspect(monkeypatch, _n1_env(written, scheme, host), collector)
    _assert_withheld(json.dumps(result, ensure_ascii=False), password, written, collector)


@pytest.mark.parametrize("export_format", ["transactions", "har"])
def test_masked_exports_withhold_userinfo_passwords_in_every_field(export_format):
    rows = []
    for index, (scheme, user, password, written, host) in enumerate(URL_CASES):
        url = _url(scheme, user, written, host)
        rows.append({
            "id": str(uuid.UUID(int=1200 + index)), "plane": "hunt", "sequence": index,
            "hunt_run_id": HUNT, "hunt_action_id": ACTION, "capability_name": "http.request",
            "method": "GET", "url": "https://honey.fixture.test/go?next=" + url, "status_code": 302,
            "request_headers": {"referer": url}, "request_body": None,
            "response_headers": {"content-type": "text/plain", "location": url,
                                 "link": f"<{url}>; rel=next", "refresh": f"0; url={url}"},
            "response_body": _URL_CONTEXTS[".env"][0](url), "metadata_json": {"hops": [url]},
        })
    def export(rows):
        return json.dumps(export_document(rows, export_format=export_format, redaction="redacted",
                                          owner={"hunt_id": HUNT}, total=len(rows)), ensure_ascii=False)

    text = export(rows)
    # The same rows with a two-character password: what the export shows without the secret.
    template_rows = [json.loads(json.dumps(row).replace(json.dumps(_url(*case[:2], case[3], case[4]))[1:-1],
                                                        json.dumps(_url(*case[:2], "Zz", case[4]))[1:-1]))
                     for row, case in zip(rows, URL_CASES)]
    assert all(json.dumps(row).count("Zz") >= 6 for row in template_rows)
    template = export(template_rows)
    for scheme, user, password, written, host in URL_CASES:
        encoded = urllib.parse.quote(written, safe="")
        assert _url_leaks(text, password, written, template) == [], (export_format, scheme, len(password))
        assert _url_leaks(text, encoded, encoded, template) == [], (export_format, scheme, len(password))


def test_mcp_tool_result_relays_no_empty_user_password(monkeypatch):
    from tests.test_hunt_withheld_values import _load_mcp
    from tests.test_mcp_refusal_reasons import ScriptedOpener

    mcp = _load_mcp()
    collector = masking.WithheldValues(ACTION)
    observation = _inspect(monkeypatch, _n1_env(N1_PASSWORD), collector)["observation"]
    hunt_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaac"
    client = mcp.ArsenalClient("http://127.0.0.1:8080", poll_seconds=0.01, action_wait_seconds=0.5)
    client.opener = ScriptedOpener({
        ("GET", f"/hunts/{hunt_id}"): {
            "hunt_id": hunt_id, "status": "active",
            "capabilities": [{"name": "artifact.inspect", "input_schema": {"type": "object"}}],
        },
        ("POST", f"/hunts/{hunt_id}/capabilities/artifact.inspect"): {
            "hunt_id": hunt_id, "capability": "artifact.inspect", "action_id": ACTION,
            "action_result": {"status": "success", "observations": [observation]},
        },
    })
    result = client.call_tool("shakerscan_hunt_capability", {
        "hunt_id": hunt_id, "capability_name": "artifact.inspect",
        "input": {"path": "/.env"}, "idempotency_key": "n1-key-1",
    })
    _assert_withheld(json.dumps(result, ensure_ascii=False), N1_PASSWORD, N1_PASSWORD)
    assert N1_PASSWORD in collector.values


@pytest.mark.parametrize("field", [
    "redis://:{pw}@cache.internal:6379/0", "//:{pw}@cache.internal/x", " https://:{pw}@h.fixture.test/",
    "<https://:{pw}@h.fixture.test/a>; rel=next", "0; url=https://:{pw}@h.fixture.test/",
    "default-src 'self'; report-uri https://:{pw}@r.fixture.test/csp",
    "https://h.fixture.test/cb?next=redis://:{pw}@cache/0&state=s",
    "https://h.fixture.test/cb?next=redis%3A%2F%2F%3A{encoded}%40cache%2F0&state=s",
])
def test_url_fields_withhold_an_empty_user_password(field):
    """``Location``, ``Link``, ``Refresh``, a CSP ``report-uri``, a redirect hop: one URL field,
    where the password may also sit in a URL nested (or percent-encoded) in the query."""
    value = field.format(pw=N1_PASSWORD, encoded=urllib.parse.quote(N1_PASSWORD, safe=""))
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        masked = masking.mask_url_secrets(value)
        bounded = masking.bounded_public_url(value, 500)
    for text in (masked, bounded, masking.mask_url_secrets(value)):
        _assert_withheld(text, N1_PASSWORD, N1_PASSWORD)
    assert collector.values == [N1_PASSWORD]


@pytest.mark.parametrize("text", ["a://" * 50_000 + "@", "a://:" * 50_000 + "@", "a://:b@" * 30_000,
                                  "a%3A%2F%2F%3Ab%40" * 20_000, "x://" + "@" * 200_000])
def test_url_userinfo_pass_is_linear(text):
    import time

    started = time.perf_counter()
    masking.mask_url_userinfo(text)
    masking.mask_url_userinfo(text, form="url")
    assert time.perf_counter() - started < 2.0


# --- Review of the fix: no userinfo across strings, references kept, escapes read ----------------

@pytest.mark.parametrize("body", [
    '<script id="__NEXT_DATA__" type="application/json">{"props":{"site":"https://example.com",'
    '"apiBase":"https://api.example.com","contact":"support@example.com"}}</script>',
    '!function(e){var t={api:"https://api.example.com",ver:"1.2"};e.exports=t}(this);require("@babel/runtime")',
    'callback({"home":"https://example.com","mail":"x@y.com"})',
    "var a={u:'https://api.example.com',m:'x@y.com'}",
])
def test_a_bare_host_never_starts_a_userinfo_in_a_later_string(body):
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        assert mask_body_text(body) == body
    assert collector.values == []


def test_a_quoted_url_ends_at_its_quote_and_keeps_the_references_after_it():
    key = "sk_live_" + "51HabcDEFghiJKLmnoPQRstu"
    body = f'<script>window.cfg={{"api":"http://api:8080","stripeKey":"{key}","owner":"ops@corp.com"}}</script>'
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        masked = mask_body_text(body)
    assert '"api":"http://api:8080"' in masked and '"owner":"ops@corp.com"' in masked
    assert key not in masked and key in collector.values


def test_a_reference_inside_a_userinfo_is_kept_and_the_password_bound_alone():
    collector = masking.WithheldValues(ACTION)
    collector.bind_known(["svc"])
    with masking.collecting_withheld_values(collector):
        masked = mask_body_text("REDIS_URL=redis://ro_svc:S3cr3tPassQ@h.fixture.test/0\n")
    assert "S3cr3t" not in masked and "[withheld:[" not in masked and "***" not in masked
    assert re.fullmatch(r"REDIS_URL=redis://ro_\[withheld:\d\]:\[withheld:\d\]@h\.fixture\.test/0\n", masked), masked
    assert "S3cr3tPassQ" in collector.values


@pytest.mark.parametrize(("body", "password"), [
    ('<script>var cfg={"redis":"redis:\\/\\/:S3cr3tPassQ@h"}</script>', "S3cr3tPassQ"),
    ("<td>redis://:S3cr3t&amp;PassQ@h</td>", "S3cr3t&PassQ"),
    ("<td>redis://:S3cr3t&#39;PassQ@h</td>", "S3cr3t'PassQ"),
])
def test_escaped_slashes_and_markup_references_are_read(body, password):
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        masked = mask_body_text(body)
    assert "S3cr3t" not in masked and "PassQ" not in masked
    assert collector.values == [password]


def test_selected_values_outside_a_hunt_stay_comparable():
    import httpx
    from api.http_experiment import response_summary

    def summary(password: str):
        body = json.dumps({"cache": f"redis://:{password}@cache.fixture.test/0"}).encode()
        response = httpx.Response(200, headers={"content-type": "application/json"}, content=body)
        return response_summary(response, body, selected_json_paths=["$.cache"])

    assert summary("FirstPassQ1")["selected_json"] != summary("OtherPassQ2")["selected_json"]


def test_json_text_is_read_as_written_never_across_its_strings():
    """Stored metadata can be JSON text: a bare host in one string never opens a userinfo that
    ends at an address in a later one, and a password inside one string is still withheld."""
    text = json.dumps({"hop": "https://h.fixture.test", "workflow_values_private": True,
                       "contact": "ops@corp.com", "cache": "redis://:S3cr3tPassQ@c"}, separators=(",", ":"))
    masked = masking.withhold_url_userinfo({"metadata_json": text})["metadata_json"]
    assert json.loads(masked)["contact"] == "ops@corp.com"
    assert json.loads(masked)["cache"] == "redis://:***@c"


def test_an_address_as_the_user_name_keeps_the_user_name_and_withholds_the_password():
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        masked = mask_body_text("MAIL_URL=smtp://ops@corp.example:Ml7PassQx@mail.fixture.test:587\n")
    assert masked == "MAIL_URL=smtp://ops@corp.example:[withheld:1]@mail.fixture.test:587\n"
    assert collector.values == ["Ml7PassQx"]


@pytest.mark.parametrize(("body", "password"), [
    ('REDIS_URL="redis://:pa\\"ssW0rd99@redis:6379"\n', 'pa"ssW0rd99'),
    ('const u = "redis://:pa\\"ssW0rd99@redis";', 'pa"ssW0rd99'),
    ("const u = 'redis://:pa\\'ssW0rd99@redis';", "pa'ssW0rd99"),
    ('<script>var c="redis:\\/\\/user:pa\\"ssW0rd99@h"</script>', 'pa"ssW0rd99'),
])
def test_an_escaped_quote_does_not_close_a_quoted_url(body, password):
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        masked = mask_body_text(body)
    assert "ssW0rd99" not in masked
    assert collector.values == [password]


@pytest.mark.parametrize(("body", "password"), [
    ("REDIS_URL=redis://:S3cr3t&amp;Pass@h\n", "S3cr3t&amp;Pass"),  # a .env: written as is
    ("REDIS_URL=redis://:S3&copyright9;Pass@h\n", "S3&copyright9;Pass"),
    ("<td>redis://:Pw&lt;x&ampy9@h</td>", "Pw<x&ampy9"),  # only complete references are read
])
def test_character_references_are_read_only_in_markup_and_only_whole(body, password):
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        mask_body_text(body)
    assert collector.values == [password]
