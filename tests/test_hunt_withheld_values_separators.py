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
