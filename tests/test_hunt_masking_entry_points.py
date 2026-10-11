"""Every output that carries target response text to a model is masked whole before it is cut.

2.9.0 masking review (after #395): five older gaps were reported, each reproduced here first.

1. ``authz.replay_plan`` returned (and stored) replayed response headers and bodies unmasked; the
   interactive session's endpoint test, which it calls, returned them unmasked too.
2. Cut before mask: a planner-chosen ``Range`` header, the ``artifact.inspect`` window end and the
   32 KB body ceiling cut text before it was masked, so a value split there showed (the whole value
   when a ranged window started just after its label).
3. ``javascript.analyze`` returned routes, JWT claims and source map references unmasked.
4. The device HTTP result showed a CSP header (``report-uri`` token) and body unmasked by the body
   masking, and a plain SHA-256 of the body.
5. The scanner redactor's URL userinfo rule matched across compact JSON strings.

Every value below is a synthetic unit fixture, never a real secret.
"""

from __future__ import annotations

import asyncio
import base64
import html
import json
import sys

import httpx
import pytest
from runtime.models import TargetBinding

import tests.test_hunt_withheld_values_separators as hostile
from api.capabilities import artifact as artifact_capability
from api.capabilities.http import WorkerPrivateHTTPResponse
from api.http_experiment import MAX_BODY_BYTES, response_summary

masking = sys.modules[artifact_capability.mask_body_text.__module__]
ACTION = "00000000-0000-4000-8000-0000000009a1"
TARGET = TargetBinding(
    target_id="00000000-0000-4000-8000-0000000009a2", target_kind="web",
    canonical_host="honey.fixture.test", allowed_origins=("https://honey.fixture.test",),
    allowed_addresses=("192.0.2.10",), allowed_root_domains=("fixture.test",), environment="lab",
    scope_receipt_id="00000000-0000-4000-8000-0000000009a3",
)
# Synthetic provider-format and markup secrets: recognised only whole.
AWS_KEY = "AKIA" + "QX7VKPWZ9KLMTY3M"
WEB_VALUE = "Qx7vKpWz9kLmTy3mNbPb8nVc"
WEB_CONFIG = f'<appSettings>\n  <add key="ApiKey" value="{WEB_VALUE}" />\n</appSettings>\n'


def _hunt(callable_, *args, **kwargs):
    collector = masking.WithheldValues(ACTION)
    with masking.collecting_withheld_values(collector):
        return callable_(*args, **kwargs), collector


# --- The shared cut: mask the whole text, then cut --------------------------------------------

def test_a_value_the_cut_splits_is_withheld_whole_and_its_reference_binds_it_exactly():
    cut = WEB_CONFIG.index(WEB_VALUE) + 9
    # Masked alone, the text before the cut shows the value's first nine characters (the
    # attribute's closing quote is past the cut).
    assert WEB_VALUE[:9] in masking.mask_body_text(WEB_CONFIG[:cut])
    shown, collector = _hunt(
        masking.mask_before_cut, WEB_CONFIG[:cut], WEB_CONFIG[cut:], masking.mask_body_text)
    assert WEB_VALUE[:4] not in shown and shown.endswith("value=\"***")
    # Withheld whole with no reference: no piece is referenced, and nothing past the cut is.
    assert collector.values == []
    assert masking.mask_before_cut(WEB_CONFIG[:cut], WEB_CONFIG[cut:], masking.mask_body_text) \
        == shown


def test_a_cut_that_splits_nothing_shows_exactly_the_cut_text_masked():
    body = "".join(f"<p>item {i}</p>\n" for i in range(400)) + WEB_CONFIG
    for cut in (17, 999, 4_000):
        assert masking.mask_before_cut(body[:cut], body[cut:], masking.mask_body_text) == \
            masking.mask_body_text(body[:cut])


def test_a_character_the_cut_splits_begins_what_follows():
    text, after = masking.decode_cut("aé".encode()[:2], "aé".encode()[2:] + b"z")
    assert (text, after) == ("a", "éz")


# --- Claim 2: http.request / experiments --------------------------------------------------------

def test_a_ranged_window_past_a_label_was_shown_whole_and_is_now_withheld():
    body = f"DEBUG=0\nSECRET_KEY={WEB_VALUE}\nHOST=x\n".encode()
    start = body.index(WEB_VALUE.encode())
    window = body[start:start + 30]
    response = httpx.Response(
        206, headers={"content-range": f"bytes {start}-{start + 29}/{len(body)}"}, content=window)
    summary, _collector = _hunt(response_summary, response, window)
    assert WEB_VALUE[:4] not in json.dumps(summary)
    assert summary["body_sample"].startswith("[ranged body withheld: bytes ")
    assert "artifact.inspect" in summary["body_sample"]


@pytest.mark.parametrize("content_range, shown", [
    ("bytes 0-49/50", False),         # a 206 is always an answer to a Range
    ("bytes 0-19/50", False),         # a prefix: the server cut its end
    ("bytes 20-49/50", False),        # a window past byte 0
    ("bytes 0-19/*", False),          # length unknown
    (None, False),                    # a 206 that says nothing
])
def test_only_a_range_that_is_the_whole_resource_is_shown(content_range, shown):
    body = b"x" * 50 if content_range == "bytes 0-49/50" else b"x" * 20
    headers = {"content-range": content_range} if content_range else {}
    summary = response_summary(httpx.Response(206, headers=headers, content=body), body)
    assert summary["body_sample"].startswith("[ranged body withheld") is not shown


def _past_the_ceiling(text: str, value: str, offset: int = 9) -> bytes:
    """``text`` (which holds ``value``) after one long masked secret, so that the 32 KB ceiling
    falls ``offset`` characters into ``value`` and inside the 2 000-character sample."""
    position = len(text.split(value[:4])[0].encode())
    lead = "SECRET_KEY=" + "A" * (MAX_BODY_BYTES - position - offset - 12) + "\n"
    return (lead + text).encode()


def test_the_body_ceiling_cuts_after_masking():
    body = _past_the_ceiling(WEB_CONFIG, WEB_VALUE)
    assert body.index(WEB_VALUE.encode()) < MAX_BODY_BYTES < body.index(WEB_VALUE.encode()) + 24
    response = httpx.Response(200, content=body)
    # Before: only the 32 KB prefix was masked, and it ends inside the value.
    assert WEB_VALUE[:6] in masking.mask_body_text(body[:MAX_BODY_BYTES].decode())
    summary, collector = _hunt(response_summary, response, body)
    assert WEB_VALUE[:4] not in summary["body_sample"]
    assert all(value == WEB_VALUE for value in collector.values)  # no piece is referenced
    assert summary["truncated"] is True and summary["bytes_observed"] == len(body)


def test_http_request_reads_what_follows_the_ceiling_to_mask_it(monkeypatch):
    """The executor (``http.request``) reads past its body ceiling for the masking only: the
    archive keeps the 32 KB prefix and its digest."""
    from api.capabilities.http import execute_bound_http_request

    body = _past_the_ceiling(WEB_CONFIG, WEB_VALUE)
    recorded: list[dict] = []

    class _MockClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs.pop("transport", None)
            super().__init__(transport=httpx.MockTransport(
                lambda request: httpx.Response(200, content=body)), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _MockClient)

    async def run():
        return await execute_bound_http_request(
            "https://honey.fixture.test", {"method": "GET", "path": "/web.config"}, target=TARGET,
            transaction_recorder=recorded.append)

    result, _collector = _hunt(asyncio.run, run())
    assert WEB_VALUE[:4] not in json.dumps(result)
    assert len(recorded) == 1 and len(recorded[0]["response_body"]) == MAX_BODY_BYTES
    # What the archive is told it observed: the ceiling and one byte past it, as before.
    assert recorded[0]["response_body_bytes"] == MAX_BODY_BYTES + 1
    assert recorded[0]["response_digest_scope"] == "prefix"


# --- Claim 2: artifact.inspect window end --------------------------------------------------------

def _range_inspect(monkeypatch, document: bytes, args: dict, *, hunt: bool = True):
    recorded: list[dict] = []

    async def fake_execute(_target_url, call_args, **kwargs):
        start, end = (int(part) for part in call_args["headers"]["Range"].split("=")[1].split("-"))
        chunk = document[start:end + 1]
        kwargs["transaction_recorder"]({
            "status_code": 206, "response_body": chunk, "response_body_bytes": len(chunk),
            "response_body_sha256": "x" * 64, "fidelity": "wire_request"})
        kwargs["private_response_sink"](WorkerPrivateHTTPResponse(
            status_code=206, final_url="https://honey.fixture.test/web.config", _body=chunk,
            _headers={"content-type": "text/xml",
                      "content-range": f"bytes {start}-{start + len(chunk) - 1}/{len(document)}"},
            _cookies={}))
        return {"ok": True}

    monkeypatch.setattr(artifact_capability, "execute_bound_http_request", fake_execute)

    async def run():
        return await artifact_capability.inspect_target_artifact(
            "https://honey.fixture.test", args, target=TARGET,
            transaction_recorder=recorded.append)

    if not hunt:
        return asyncio.run(run()), None, recorded
    result, collector = _hunt(asyncio.run, run())
    return result, collector, recorded


def test_artifact_window_ending_inside_a_value_withholds_it_whole(monkeypatch):
    document = WEB_CONFIG.encode()
    end = document.index(WEB_VALUE.encode()) + 9
    for hunt in (True, False):
        result, collector, recorded = _range_inspect(
            monkeypatch, document, {"path": "/web.config", "max_bytes": end}, hunt=hunt)
        sample = result["observation"]["text_sample"]
        assert WEB_VALUE[:4] not in sample, sample
        assert sample.startswith("<appSettings>")
        if collector is not None:
            assert all(value == WEB_VALUE for value in collector.values)
        # The archive keeps the window the planner asked for, not the lookahead.
        assert recorded[0]["response_body"] == document[:end]
        assert not result["observation"]["window_sha256"].isalnum()  # keyed, not a plain digest


# --- Claim 2: hostile generator, secrets across every cut ----------------------------------------

_CUT_OFFSETS = (1, 2, 4, 5, 9, 17, 40, -3, -1)


def _cuts(body: str, value: str):
    position = body.find(value[:4])
    for offset in _CUT_OFFSETS:
        cut = position + offset if offset > 0 else position + len(value) + offset
        if position < cut < len(body):
            yield cut


@pytest.mark.parametrize("form", sorted(hostile._HOSTILE_FORMS))
def test_hostile_values_cut_anywhere_never_reach_the_planner(form):
    template = hostile._template(form)
    for value in hostile.HOSTILE[:14]:
        body = hostile._HOSTILE_FORMS[form](value)
        for cut in _cuts(body, value):
            shown, collector = _hunt(
                masking.mask_before_cut, body[:cut], body[cut:], masking.mask_body_text)
            assert hostile._hostile_leaks(shown, value, template) == [], (form, cut - body.find(value[:4]))
            plain = masking.mask_before_cut(body[:cut], body[cut:], masking.mask_body_text)
            assert hostile._hostile_leaks(plain, value, template) == [], (form, cut)


@pytest.mark.parametrize("form", ["web.config value", "js minified", "php single-quoted",
                                  "connection string with blanks", ".env double-quoted multi-line"])
def test_hostile_values_cut_by_an_artifact_window_end(monkeypatch, form):
    template = hostile._template(form)
    for value in hostile.HOSTILE[:6]:
        document = hostile._HOSTILE_FORMS[form](value).encode()
        start = document.find(value[:4].encode())
        for offset in (2, 5, 9):
            result, _collector, _recorded = _range_inspect(
                monkeypatch, document, {"path": "/x", "max_bytes": start + offset})
            sample = result["observation"]["text_sample"]
            assert hostile._hostile_leaks(sample, value, template) == [], (form, offset)


@pytest.mark.parametrize("form", ["web.config value", "js minified", "json", "sql insert"])
def test_hostile_values_across_the_body_ceiling(form):
    template = hostile._template(form)
    for value in hostile.HOSTILE[:6]:
        text = hostile._HOSTILE_FORMS[form](value)
        for offset in (2, 9):
            body = _past_the_ceiling(text, value, offset)
            summary, _collector = _hunt(response_summary, httpx.Response(200, content=body), body)
            assert hostile._hostile_leaks(summary["body_sample"], value, template) == [], (form, offset)


# --- Claim 1: authz.replay_plan and the interactive endpoint test ----------------------------------

def test_a_tested_endpoint_response_is_masked_whole_before_it_is_cut():
    from api.session_manager import TEST_ENDPOINT_BODY_CHARS, masked_endpoint_response

    body = "x" * (TEST_ENDPOINT_BODY_CHARS - 30) + WEB_CONFIG + json.dumps({"key": AWS_KEY})
    raw = {
        "status": 200, "body": body, "json": {"user": "bob", "api_key": "Zq9vXk2pLm4nRt7s", "aws": AWS_KEY},
        "headers": {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; report-uri "
                                       "https://csp.fixture.test/r?sentry_key=Rp4kLm9vXq2nTt7s",
            "x-cache-backend": "redis://:Hn4tGhPb8nVc@cache.fixture.test:6379/0",
            "www-authenticate": 'Bearer realm="x", error="invalid_token"',
        },
    }
    shown = masked_endpoint_response(raw)
    text = json.dumps(shown)
    for secret in (WEB_VALUE[:6], AWS_KEY, "Zq9vXk2pLm4nRt7s", "Rp4kLm9vXq2nTt7s", "Hn4tGhPb8nVc"):
        assert secret not in text, secret
    assert shown["headers"]["www-authenticate"] == "<redacted>"
    assert shown["json"]["user"] == "bob"
    assert len(shown["body"]) <= TEST_ENDPOINT_BODY_CHARS


def test_authz_replay_observations_go_through_the_masked_view():
    """The replay builds each observation's response from ``masked_endpoint_response`` (the
    executor itself is exercised in test_api_helpers)."""
    from tests.api_sources import definition_source

    source = definition_source("_execute_authz_replay_plan")
    assert "shown = masked_endpoint_response(replay)" in source
    assert '"headers": shown.get("headers") or {}' in source
    assert '"body_sample": shown.get("body")' in source
    assert 'replay.get("body")' not in source and 'replay.get("headers")' not in source


# --- Claim 3: javascript.analyze ------------------------------------------------------------------

def _segment(value):
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")


def test_javascript_routes_claims_and_source_maps_are_masked():
    token = ".".join((_segment({"alg": "HS256"}), _segment({
        "iss": "https://svc:Lm9vXq2nTt7sRp4k@issuer.fixture.test/auth", "aud": AWS_KEY, "role": "anon"}),
        "signaturebytes"))
    inline_map = "data:application/json;base64," + base64.b64encode(
        json.dumps({"sourcesContent": [f"const k='{AWS_KEY}'"]}).encode()).decode()
    body = (
        f'fetch("/api/hooks/{AWS_KEY}/run");fetch("/api/reset;token=Wz9kLmTy3mNbPb8n");'
        f'const t="{token}";\n//# sourceMappingURL={inline_map}\n'
        '//# sourceMappingURL=https://u:Fs6gDfHn4tGhQq@cdn.fixture.test/app.js.map\n'
    ).encode()
    for hunt in (False, True):
        result = _hunt(artifact_capability.analyze_javascript_bytes, body)[0] if hunt else \
            artifact_capability.analyze_javascript_bytes(body)
        text = json.dumps(result)
        for secret in (AWS_KEY, "Wz9kLmTy3mNbPb8n", "Lm9vXq2nTt7sRp4k", "Fs6gDfHn4tGhQq", "sourcesContent"):
            assert secret not in text, (hunt, secret)
        assert "/api/hooks/" in text and "/api/reset;token=" in text
        assert result["jwt_observations"][0]["claims"]["role"] == "anon"
        assert result["content_sha256"].startswith("hmac-sha256-")  # keyed, never a plain digest


def test_a_token_the_bundle_end_cuts_is_not_referenced():
    token = ".".join((_segment({"alg": "HS256"}), _segment({"role": "anon"}), "signaturebytes"))
    body = f'const t="{token}"'.encode()[:-1 - 4]
    result, collector = _hunt(artifact_capability.analyze_javascript_bytes, body, truncated=True)
    assert result["jwt_observations"] == [] and collector.values == []
    whole, collector = _hunt(artifact_capability.analyze_javascript_bytes, f'const t="{token}"'.encode())
    assert collector.values == [token]


# --- Claim 4: device HTTP ------------------------------------------------------------------------

def test_device_csp_and_body_preview_are_masked_and_the_digest_is_keyed():
    from api.devices import router as device_router

    headers = device_router._device_planner_response_headers({
        "Content-Security-Policy": "default-src 'self'; report-uri "
                                   "https://u:Pb8nVcRc2hXz@csp.fixture.test/r?sentry_key=Rp4kLm9vXq2nTt7s",
        "Server": "lighttpd", "Set-Cookie": "sid=Ty3mNbPb8nVcRc2h",
    })
    text = json.dumps(headers)
    assert "Rp4kLm9vXq2nTt7s" not in text and "Pb8nVcRc2hXz" not in text and "Ty3mNbPb8nVcRc2h" not in text
    assert headers["Server"] == "lighttpd" and "report-uri https://u:***@csp.fixture.test" in text

    body = ("<html>" + "x" * 300 + f"<pre>aws={AWS_KEY}</pre>" + WEB_CONFIG).encode()
    preview = device_router._redact_device_http_body_preview("/status?mode=full", body)
    assert AWS_KEY not in preview and WEB_VALUE not in preview
    # Cut by the 16 KB read inside a value: withheld whole.
    cut = body.index(WEB_VALUE.encode()) + 9
    preview = device_router._redact_device_http_body_preview("/s", body[:cut], body[cut:])
    assert WEB_VALUE[:4] not in preview
    router_source = open(device_router.__file__, encoding="utf-8").read()
    assert '"body_sha256": keyed_response_digest(body)' in router_source
    assert '"body_sha256": hashlib.sha256(body)' not in router_source
    assert '"headers": _device_planner_response_headers(' in router_source


# --- Claim 5: the scanner redactor's userinfo rule --------------------------------------------

@pytest.mark.parametrize("text, expected", [
    ('{"u":"http://a","p":"x:y@z"}', '{"u":"http://a","p":"x:y@z"}'),
    ('{"a":"https://h","b":"note:hi@there"}', '{"a":"https://h","b":"note:hi@there"}'),
    ('{"a":"redis://:pa@ss@host"}', '{"a":"redis://:***@host"}'),
    ('{"a":"https://user:p%2Fw@host"}', '{"a":"https://user:***@host"}'),
])
def test_scanner_userinfo_rule_stays_inside_one_json_string(text, expected):
    from scanner.redaction import redact_text

    assert redact_text(text) == expected
    assert json.loads(redact_text(text))  # still JSON


def test_scanner_userinfo_rule_never_shows_a_reference_from_a_hunt():
    from scanner.redaction import redact_text

    with masking.collecting_withheld_values(masking.WithheldValues(ACTION)):
        assert redact_text("redis://:Hn4tGhPb8nVc@cache") == "redis://:***@cache"


def test_hostile_url_passwords_through_the_scanner_redactor():
    from scanner.redaction import redact_text

    for scheme, user, password, written, host in hostile.URL_CASES:
        url = hostile._url(scheme, user, written, host)
        for text in (json.dumps({"a": "https://x", "cache": url, "e": "me@ex.com"}), f"see {url} now",
                     html.escape(f'<a href="{url}">')):
            shown = redact_text(text)
            template = redact_text(text.replace(written, "Zz"))
            assert hostile._url_leaks(shown, password, written, template) == [], (text, shown)
            if text.startswith("{"):
                assert json.loads(shown)["e"] == "me@ex.com"


# --- Review of the fix ------------------------------------------------------------------------

def test_the_cut_text_alone_never_replaces_what_the_whole_text_taught():
    """A window ending inside a CREATE TABLE column list: the columns the whole text names are
    kept for the next window of the dump, not the cut list (``password`` read as ``p``)."""
    import copy

    dump = "-- dump\nCREATE TABLE users (id int, name text, password text);\n"
    full = dump + "INSERT INTO users VALUES (1,'bob','Zq9vLmT4pRw2');\n"
    cut = dump.index("password") + 1
    first = masking.WithheldValues(ACTION)
    first.sql_path, first.sql_dump_like = "/backup.sql", True
    with masking.collecting_withheld_values(first):
        masking.mask_before_cut(full[:cut], full[cut:], masking.mask_body_text)
    later = masking.WithheldValues(ACTION)
    later.sql_path, later.sql_dump_like = "/backup.sql", True
    later.sql_tables = copy.deepcopy(first.sql_tables)
    with masking.collecting_withheld_values(later):
        shown = masking.mask_body_text(full[full.index("INSERT"):], window=True)
    assert "Zq9vLmT4pRw2" not in shown


def test_values_only_past_the_cut_are_not_numbered():
    body = "A_TOKEN=Qx7vKpWz9kLmTy3m\n" + "x" * 50 + "\nB_TOKEN=Wz9kLmTy3mNbPb8n\nC_SECRET=Ty3mNbPb8nVcRc2h\n"
    cut = body.index("xxx") + 10
    shown, collector = _hunt(masking.mask_before_cut, body[:cut], body[cut:], masking.mask_body_text)
    assert shown.startswith("A_TOKEN=[withheld:1]") and collector.values == ["Qx7vKpWz9kLmTy3m"]


@pytest.mark.parametrize("charset", ["utf-16", "utf-32", "base64", "no-such-codec"])
def test_a_charset_the_target_names_never_breaks_the_summary(charset):
    body = "DB_PASSWORD=Qx7vKpWz9kLmTy3m\n".encode("utf-16-le") if charset.startswith("utf") else b"x=1"
    response = httpx.Response(200, headers={"content-type": f"text/plain; charset={charset}"}, content=body)
    summary = response_summary(response, body)
    assert "Qx7vKpWz9kLmTy3m" not in json.dumps(summary)


def test_a_stream_that_pauses_after_the_ceiling_costs_only_the_lookahead_wait():
    import time

    from api.http_experiment import LOOKAHEAD_WAIT_SECONDS, read_capped_body

    class Paused(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"x" * (MAX_BODY_BYTES + 100)
            await asyncio.sleep(30)
            yield b"never"

    async def run():
        response = httpx.Response(200, stream=Paused())
        started = time.perf_counter()
        body, lookahead, ended = await read_capped_body(response)
        return body, lookahead, ended, time.perf_counter() - started

    body, lookahead, ended, elapsed = asyncio.run(run())
    assert len(body) == MAX_BODY_BYTES + 1 and len(lookahead) == 99 and ended is False
    assert elapsed < LOOKAHEAD_WAIT_SECONDS + 1


def test_the_executor_lookahead_never_spends_the_request_deadline(monkeypatch):
    import time

    from api.capabilities.http import _read_bounded_response

    class Paused:
        async def aiter_bytes(self):
            yield b"x" * (MAX_BODY_BYTES + 100)
            await asyncio.sleep(30)
            yield b"never"

    async def run():
        lookahead = bytearray()
        started = time.perf_counter()
        result = await _read_bounded_response(
            Paused(), deadline=time.perf_counter() + 10, lookahead=lookahead, lookahead_limit=16_384)
        return result, lookahead, time.perf_counter() - started

    (body, _digest, observed, truncated, exceeded), lookahead, elapsed = asyncio.run(run())
    assert truncated and not exceeded and observed == MAX_BODY_BYTES + 1
    assert len(body) == MAX_BODY_BYTES and len(lookahead) == 100 and elapsed < 2


def test_device_location_keeps_its_public_url_redaction():
    from api.devices import router as device_router

    headers = device_router._device_planner_response_headers(
        {"Location": "http://admin:pw@10.0.0.1/login.htm?sid=AbCdEf123456Gh&x=1"})
    assert "AbCdEf123456Gh" not in headers["Location"] and "pw@" not in headers["Location"]


def test_interactive_extract_masks_values_and_page_content():
    """The interactive session's extract action (its page needs a browser): read as source."""
    from api import session_manager

    source = open(session_manager.__file__, encoding="utf-8").read()
    assert 'values.append(_masked_endpoint_text(val) if isinstance(val, str) else val)' in source
    assert 'result["html"] = _masked_endpoint_text(await page.content())' in source
    assert '== "password"' in source


# --- Second review (PR #398) ------------------------------------------------------------------

@pytest.mark.parametrize("text, secret", [
    ("upstream connect failed: postgres://app:Pa#ss?w0rd@db.internal:5432/app", "Pa#ss?w0rd"),
    ("MongoServerSelectionError mongodb://root:Hunt3r#2024@mongo:27017", "Hunt3r#2024"),
    ("redis://:S3cr?tV4lue@cache:6379/0 refused", "S3cr?tV4lue"),
    ("<a href='ftp://u:o'neil99@h/'>", "o'neil99"),
])
def test_a_password_with_unencoded_delimiters_is_withheld_on_every_path(text, secret):
    from scanner.redaction import redact_text

    assert secret[:4] not in redact_text(text)
    assert secret[:4] not in masking.mask_body_text(text)
    shown, collector = _hunt(masking.mask_body_text, text)
    assert secret[:4] not in shown and collector.values == [secret]


def _paused_executor(monkeypatch, body: bytes, split: int, pause: float, timeout: int = 15):
    from api.capabilities.http import execute_bound_http_request

    class Paused(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield body[:split]
            await asyncio.sleep(pause)
            yield body[split:]

    class _MockClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs.pop("transport", None)
            super().__init__(transport=httpx.MockTransport(
                lambda request: httpx.Response(200, stream=Paused())), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _MockClient)

    async def run():
        return await execute_bound_http_request(
            "https://honey.fixture.test", {"method": "GET", "path": "/web.config"}, target=TARGET,
            timeout_seconds=timeout)

    return _hunt(asyncio.run, run())[0]


@pytest.mark.parametrize("split, pause, timeout", [
    (MAX_BODY_BYTES + 1, 1.0, 15),   # a pause just past the ceiling: the lookahead reads nothing
    (MAX_BODY_BYTES - 3, 3.0, 1),    # a deadline cuts the body inside the value
])
def test_a_cut_the_lookahead_could_not_read_past_withholds_the_last_line(monkeypatch, split, pause, timeout):
    body = _past_the_ceiling(WEB_CONFIG, WEB_VALUE)
    result = _paused_executor(monkeypatch, body, split, pause, timeout)
    assert WEB_VALUE[:4] not in json.dumps(result)


LONG_VALUE = "".join("Qx7vKpWz9kLmTy3mNbPb8nVcRc2hXz"[i % 30] + str(i % 7) for i in range(20_000))


@pytest.mark.parametrize("form", [
    '<add key="ApiKey" value="%s" />', '<input type="hidden" name="csrf_token" value="%s">',
    "$config['db_password'] = '%s';", 'SECRET_KEY="%s"\n', '{"private_key": "%s"}',
])
def test_a_value_longer_than_the_lookahead_is_withheld_from_its_opening_quote(form):
    body = form % LONG_VALUE
    start = body.index(LONG_VALUE)
    for cut in (start + 5, start + 100):
        after = body[cut:cut + masking.CUT_LOOKAHEAD_CHARS]
        for hunt in (False, True):
            call = (lambda: _hunt(masking.mask_before_cut, body[:cut], after, masking.mask_body_text,
                                  after_complete=False)[0]) if hunt else (
                lambda: masking.mask_before_cut(body[:cut], after, masking.mask_body_text, after_complete=False))
            shown = call()
            assert not any(LONG_VALUE[k:k + 4] in shown for k in range(0, 120)), (form, cut, shown[-40:])


def test_a_closed_value_past_the_cut_keeps_the_window_visible():
    body = 'var a="x";' * 4_000 + 'var b="' + "y" * 50 + '";'
    cut = 19_000
    shown = masking.mask_before_cut(body[:cut], body[cut:cut + masking.CUT_LOOKAHEAD_CHARS],
                                    masking.mask_body_text, after_complete=False)
    assert shown == masking.mask_body_text(body[:cut])


@pytest.mark.parametrize("status, content_range", [
    (200, "bytes 19-48/51"),    # a Range answered with 200
    (206, "bytes 0-29/30"),     # a 206 that claims the whole resource
    (416, "bytes */51"),
])
def test_any_ranged_answer_withholds_its_body(status, content_range):
    """A 200 whose Content-Range is the whole resource and whose body is that long is shown."""
    whole = b"x" * 30
    assert response_summary(httpx.Response(200, headers={"content-range": "bytes 0-29/30"}, content=whole),
                            whole)["body_sample"] == "x" * 30
    body = f"SECRET_KEY={WEB_VALUE}\nHOST=x\n".encode()[11:41]
    summary = response_summary(httpx.Response(status, headers={"content-range": content_range}, content=body), body)
    assert summary["body_sample"].startswith("[ranged body withheld") and WEB_VALUE[:4] not in summary["body_sample"]


def test_the_sample_cut_never_splits_a_reference():
    text = "x" * 1_995 + "[withheld:12] tail"
    assert masking.bounded_masked_text(text, 2_000) == "x" * 1_995 + "***"
    body = ("A_TOKEN=Qx7vKpWz9kLmTy3m\n" * 13 + "x" * (2_000 - 13 * 21 - 3) + "\nZ_TOKEN=Wz9kLmTy3mNbPb8n\n").encode()
    summary, _collector = _hunt(response_summary, httpx.Response(200, content=body), body)
    assert not summary["body_sample"].rstrip("*").endswith("[withheld")
    assert "[withheld:" not in summary["body_sample"][-12:] or summary["body_sample"].endswith("]")


def test_a_source_map_reference_the_bundle_end_cuts_is_skipped():
    password = "Hn4tGhPb8nVcQ"
    source = ("var a=1;\n" * 50 + f"//# sourceMappingURL=https://deploy:{password}@maps.fixture.test/a.map\n").encode()
    start = source.index(password.encode())
    for offset in (6, 10):
        result, _collector = _hunt(artifact_capability.analyze_javascript_bytes, source[:start + offset],
                                   truncated=True)
        assert password[:4] not in json.dumps(result) and result["source_maps"] == []


def test_secret_named_headers_and_bare_tokens_in_a_tested_endpoint_are_withheld():
    from api.session_manager import masked_endpoint_response

    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijkLMNOP"
    shown = masked_endpoint_response({
        "body": f'[{{"id":1}}, "{jwt}", "Authorization header: Bearer zz0123456789abcdefQ"]',
        "headers": {"X-Subject-Token": "gAAAAABmZ2tW8kQx9fake_fernet_token_value_1234567890",
                    "X-Auth-Token": jwt, "X-Upstream-Auth": "Bearer zz0123456789abcdefQ",
                    "Content-Type": "application/json"},
        "json": None})
    text = json.dumps(shown)
    for secret in (jwt, "gAAAAABmZ2tW8kQx9", "zz0123456789abcdefQ"):
        assert secret not in text, secret
    assert shown["headers"]["Content-Type"] == "application/json"


def test_replay_rows_stored_before_the_fix_are_masked_when_read():
    import api.api as api_module

    row = {"id": "a", "finding_ids": "[]", "hypothesis_ids": "[]", "evidence_object_ids": "[]",
           "tool_receipt_ids": "[]", "blocked_by": "[]", "result_json": json.dumps({"authz_replay": {
               "observations": [{"observed_status": 200, "response": {
                   "status": 200, "headers": {"x-cache-backend": "redis://:Hn4tGhPb8nVc@c:6379"},
                   "body_sample": '{"aws": "' + AWS_KEY + '"}'}}]}})}
    public = api_module._public_campaign_action_row(row)
    text = json.dumps(public)
    assert AWS_KEY not in text and "Hn4tGhPb8nVc" not in text
    assert public["result_json"]["authz_replay"]["observations"][0]["observed_status"] == 200
