"""A Hunt action's one secrecy boundary and one execution contract, against hostile targets.

Every page and answer here is shaped by a target that wants something: a session echoed back in
an error page, a password hidden where tag stripping loses its context, a duplicated attribute,
a cookie value chosen to blind the planner or to carry a scanner's injection marker, a proof
that would outlive its action. Values are synthetic; the transports are labelled doubles and no
traffic leaves the test.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import re
import sys
import time
from types import SimpleNamespace
import uuid

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
for _path in (ROOT / "api", ROOT / "scanner"):
    if str(_path) not in sys.path:
        sys.path.append(str(_path))

import agent_tools  # noqa: E402
from capabilities.http import WorkerPrivateHTTPResponse  # noqa: E402
from capabilities.sqli_proof import _excerpt  # noqa: E402
from http_experiment import response_summary  # noqa: E402
from hunt import scanner_sqli_proof  # noqa: E402
from runtime.archive_body_masking import WithheldValues, collecting_withheld_values  # noqa: E402
from runtime.hunt_http_exchange import (  # noqa: E402
    HttpWorkflowExchange, captured_binding, origin_key, sealed_hunt_knowledge,
)
from runtime.hunt_http_exchange_contract import public_capture_references  # noqa: E402
from runtime.html_outline import SIGN_IN_HINT  # noqa: E402
from runtime.models import TargetBinding  # noqa: E402
from runtime.public_secrecy import PublicSecrecy, identity_values  # noqa: E402
from runtime.request_replay_executor import ReplayTransportResult  # noqa: E402

HUNT, ACTION = str(uuid.UUID(int=901)), str(uuid.UUID(int=902))
ORIGIN = "https://app.test"
TARGET = TargetBinding(target_id=str(uuid.UUID(int=903)), target_kind="web",
    canonical_host="app.test", allowed_origins=(ORIGIN, "http://app.test"),
    allowed_addresses=("192.0.2.30",), allowed_root_domains=("app.test",),
    environment="lab", scope_receipt_id=str(uuid.UUID(int=904)))
SESSION = "sess-Q7mZ2pK9vX4bN8cR1tY6wL3j"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZGEiLCJyb2xlIjoic3RhZmYifQ.c2lnbmF0dXJlLXZhbHVlLWhlcmU"


# --- the page outline never shows what the body sample withholds (review item 1, 12, 13) ----------

def _summary(html: str, *, known=(), url: str = f"{ORIGIN}/account"):
    response = httpx.Response(200, headers={"content-type": "text/html; charset=utf-8"},
                              content=html.encode(), request=httpx.Request("GET", url))
    collector = WithheldValues(ACTION)
    collector.bind_known(list(known))
    with collecting_withheld_values(collector):
        return response_summary(response, html.encode())


HOSTILE_PAGES = {
    # context the tag stripping loses: an element named like a key, a textarea, a table column
    "element_id": ('<div id="api_key">ApiKeyValue-7Hq2Lw9Zx4Pn</div><a href="/next">next</a>',
                   "ApiKeyValue-7Hq2Lw9Zx4Pn"),
    "textarea": ('<form method="post" action="/save"><textarea name="password">TextareaPass-55Kd</textarea>'
                 '</form>', "TextareaPass-55Kd"),
    "table_column": ("<table><tr><th>user</th><th>password</th></tr>"
                     "<tr><td>ada</td><td>ColumnPass-93Fz</td></tr></table>", "ColumnPass-93Fz"),
    # an entity-encoded hidden secret
    "entity": ('<form><input type="hidden" name="api_key" value="&#115;k_live_9fQ2xB7mL4zP1vC8dR3t">'
               "</form>", "sk_live_9fQ2xB7mL4zP1vC8dR3t"),
    # browsers read the first of a repeated attribute: this is a password field
    "duplicate_type": ('<form><input type=password type=hidden name=pin value="DupTypeSecret-31Q"></form>',
                       "DupTypeSecret-31Q"),
}


@pytest.mark.parametrize("name", sorted(HOSTILE_PAGES))
def test_no_outline_view_shows_a_value_the_body_sample_withholds(name):
    body, secret = HOSTILE_PAGES[name]
    summary = _summary(f"<!DOCTYPE html><html><head><title>Account</title></head><body>{body}</body></html>")
    assert "html" in summary
    outline = json.dumps(summary["html"])
    if secret not in summary["body_sample"]:
        assert secret not in outline, name
    # whatever the body sample shows, the derived view never shows more of it
    for size in (6, 10):
        assert secret[:size] not in outline or secret[:size] in summary["body_sample"], name


def test_a_duplicated_type_reads_the_first_one_and_never_shows_the_value():
    summary = _summary('<html><body><form><input type=password type=hidden name=pin value="DupTypeSecret-31Q">'
                       "</form></body></html>")
    (form,) = summary["html"]["forms"]
    assert form["fields"] == [{"name": "pin", "type": "password"}]
    assert form["sign_in"] is True and summary["html"]["sign_in_hint"] == SIGN_IN_HINT


def test_known_values_in_attributes_and_links_are_withheld_before_any_cut_or_case_change():
    # The target echoes the Hunt's session into a form's method, a field's name and type, and an
    # entity-encoded link: nothing of it shows, neither cut to a prefix nor upper-cased.
    encoded = "".join(f"&#{ord(char)};" for char in SESSION)
    page = (f'<html><body><form method="{SESSION}" action="/p?s={encoded}">'
            f'<input name="{SESSION}x" type="{SESSION}"></form>'
            f'<a href="/hub/orders?ref={encoded}">orders</a></body></html>')
    summary = _summary(page, known=[SESSION])
    rendered = json.dumps(summary["html"])
    for piece in (SESSION, SESSION[:10], SESSION.upper()[:10], SESSION[-10:]):
        assert piece not in rendered
    (form,) = summary["html"]["forms"]
    assert re.fullmatch(r"\[withheld:\d+\]|\*\*\*", form["method"])
    assert not form["fields"][0]["type"].isupper()
    assert any(link.startswith("/hub/orders?ref=") for link in summary["html"]["links"])


def test_ordinary_attributes_keep_their_usual_case():
    summary = _summary('<html><body><form method=post action=/login><input name=user TYPE=TEXT>'
                       "<input name=pw type=Password></form></body></html>")
    (form,) = summary["html"]["forms"]
    assert form["method"] == "POST"
    assert form["fields"] == [{"name": "user", "type": "text"}, {"name": "pw", "type": "password"}]


def test_a_value_cut_by_the_body_limit_is_withheld_in_the_outline_too():
    filler = "<p>" + "lorem ipsum " * 2_800 + "</p>"
    page = (f"<html><body>{filler}<form><input type=hidden name=api_key "
            'value="CutSecret-4Rt8Yu2Iop9Asd3F"></form></body></html>')
    summary = _summary(page)
    assert "CutSecret" not in json.dumps(summary)


# --- the secrecy boundary (review items 2 and 11) -------------------------------------------------

ECHOING_ERROR_PAGE = (
    "<h1>Database error</h1>\n"
    "<p>SQLITE_ERROR: unrecognized token near \"'\"</p>\n"
    f"<pre>Cookie: lang=en; sid={SESSION}\n"
    f"Authorization: Bearer {JWT}</pre>\n"
    f"<table><tr><td>HTTP_COOKIE</td><td>lang=en; sid={SESSION}</td></tr>\n"
    f"<tr><td>HTTP_AUTHORIZATION</td><td>Bearer {JWT}</td></tr></table>\n"
)
HEADERS = {"Cookie": f"lang=en; sid={SESSION}", "Authorization": f"Bearer {JWT}"}


def _no_identity(text: str) -> None:
    for value in (SESSION, JWT, *JWT.split(".")):
        assert value not in text


def test_identity_values_cover_every_cookie_and_every_part_of_a_bearer_jwt():
    values = set(identity_values(HEADERS))
    assert {SESSION, JWT, *JWT.split(".")} <= values
    assert "en" not in values  # shorter than anything worth searching for


def test_the_proof_excerpt_of_an_error_page_echoing_the_request_shows_no_identity():
    result = ReplayTransportResult(status_code=500, connected_address="192.0.2.30", final_url=f"{ORIGIN}/i",
                                   response_headers={}, response_body=ECHOING_ERROR_PAGE.encode(), elapsed_ms=4)
    excerpt = _excerpt(result, PublicSecrecy.for_headers(HEADERS))
    _no_identity(excerpt)
    assert "SQLITE_ERROR" in excerpt
    # Even with no known values, the labelled lines are withheld.
    _no_identity(_excerpt(result) or "")


def test_the_boundary_withholds_identities_in_every_observation_field():
    observations = [
        {"kind": "sqli_proof", "redacted_excerpt": ECHOING_ERROR_PAGE, "secret_values_visible": False,
         "response_pairs": [{"control_status": 200}], "payload_sha256": "ab" * 32},
        {"kind": "sqli_finding", "message": f"sid={SESSION} reflected", "url": f"{ORIGIN}/i?sid={SESSION}"},
        {"kind": "note", "nested": [{"deep": SESSION.upper()}], "cookie": "anything"},
    ]
    sanitized = PublicSecrecy.for_headers(HEADERS).observations(observations)
    _no_identity(json.dumps(sanitized))
    assert SESSION.upper() not in json.dumps(sanitized)
    assert sanitized[0]["secret_values_visible"] is False and sanitized[0]["payload_sha256"] == "ab" * 32
    assert sanitized[2]["cookie"] == "***"
    assert "SQLITE_ERROR" in sanitized[0]["redacted_excerpt"]


# --- the proof runs under the action's contract (review item 3) ----------------------------------

class _Echoing:
    """Labelled double: the proof's pinned transport. Answers like ECHOING_ERROR_PAGE on a quote,
    after ``delay`` seconds whatever the timeout (a slow connection set-up the request timeout does
    not cover); records when each request started and the time it was given."""

    sent: list = []
    delay = 0.0

    async def send(self, request, *, target, timeout_seconds, follow_redirects):
        type(self).sent.append((time.monotonic(), timeout_seconds))
        await asyncio.sleep(self.delay)
        quoted = "%27" in request.url
        return ReplayTransportResult(
            status_code=500 if quoted else 200, connected_address="192.0.2.30", final_url=request.url,
            response_headers={}, elapsed_ms=4,
            response_body=ECHOING_ERROR_PAGE.encode() if quoted else b"<p>item</p>")


def _phase(monkeypatch, *, deadline, delay=0.0, cancelled=lambda: False, actual=None):
    class Pool:
        def acquire(self):
            class Conn:
                async def __aenter__(self): return object()
                async def __aexit__(self, *_): return False
            return Conn()

    async def archive(*_args):
        return None

    async def beat():
        return None

    _Echoing.sent, _Echoing.delay = [], delay
    monkeypatch.setattr(scanner_sqli_proof, "PinnedAiohttpReplayTransport", _Echoing)
    monkeypatch.setattr(scanner_sqli_proof.http_archive, "archive_hunt_capture", archive)
    return asyncio.run(scanner_sqli_proof.prove_hunt_sqli_signal(
        pool=Pool(), results_dir="/tmp", run={"id": HUNT, "target_id": TARGET.target_id},
        action_id=uuid.UUID(ACTION), target=TARGET, execution_target=f"{ORIGIN}/item?id=1",
        values={"path": "/item?id=1"}, observations=[{"kind": "sqli_finding", "param": "id"}],
        reserved={"http_requests": 1_800, "tool_wall_seconds": 1_200},
        actual=actual or {"http_requests": 100, "tool_wall_seconds": 100},
        headers=HEADERS, principal_slot="captured_session", heartbeat=beat, cancelled=cancelled,
        deadline=deadline,
    ))


def test_no_proof_request_starts_after_the_actions_deadline(monkeypatch):
    start = time.monotonic()
    phase = _phase(monkeypatch, deadline=start + 4.5, delay=1.5)
    assert phase.ran and phase.timed_out and phase.status == "partial"
    assert phase.observations[0]["proof_state"] == "not_proven"
    # every request started before the deadline and was given no more time than was left
    assert all(sent_at < start + 4.5 and sent_at + timeout <= start + 4.6 for sent_at, timeout in _Echoing.sent)
    assert time.monotonic() - start < 4.5 + scanner_sqli_proof.PROOF_DEADLINE_GRACE_SECONDS
    assert phase.used["tool_wall_seconds"] <= 4 and phase.used["http_requests"] == len(_Echoing.sent)


def test_an_unfunded_deadline_sends_nothing(monkeypatch):
    phase = _phase(monkeypatch, deadline=time.monotonic() + 2)
    assert not phase.ran and phase.observations[0]["not_proven_reason"] == "proof_unfunded"
    assert _Echoing.sent == []


def test_a_cancellation_during_the_proof_is_the_actions_outcome(monkeypatch):
    calls = {"n": 0}

    def cancelled():
        calls["n"] += 1
        return calls["n"] > 2

    phase = _phase(monkeypatch, deadline=time.monotonic() + 600, cancelled=cancelled)
    assert phase.status == "cancelled" and phase.ran
    assert phase.observations[0]["proof_state"] == "not_proven"


def test_a_proof_that_finishes_settles_inside_its_grant_and_shows_no_identity(monkeypatch):
    phase = _phase(monkeypatch, deadline=time.monotonic() + 600)
    (proof,) = phase.observations
    assert proof["proof_state"] == "verified" and phase.status == "success"
    _no_identity(json.dumps(proof))
    assert phase.used["http_requests"] == len(_Echoing.sent) == 4


# --- captured cookies: origin binding, Hunt-wide masking, scanner markers (items 14-16) ----------

def _captured(cookies, final_url=f"{ORIGIN}/login"):
    state = HttpWorkflowExchange(HUNT, ACTION, TARGET, ({"name": "session", "header": "Set-Cookie"},))
    state.capture_response(WorkerPrivateHTTPResponse(
        status_code=303, final_url=final_url, _body=b"", _headers={}, _cookies=dict(cookies)))
    return state


def _bind(state, destination):
    async def row(*_):
        return {"private_http_result": state.encrypted_result}

    return asyncio.run(captured_binding(
        SimpleNamespace(fetchrow=row), run_id=HUNT, target=TARGET,
        binding={"source_action_id": ACTION, "capture_name": "session"}, destination=destination))


@pytest.fixture
def vault(monkeypatch):
    from cryptography.fernet import Fernet
    import secret_store

    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(secret_store, "_fernet", None)
    monkeypatch.setattr(secret_store, "_loaded", False)


def test_a_captured_cookie_goes_back_only_to_the_origin_that_set_it(vault):
    state = _captured({"sid": SESSION})
    assert _bind(state, f"{ORIGIN}/orders") == (f"sid={SESSION}", True)
    assert _bind(state, "https://APP.test:443/x")[1]
    for elsewhere in ("http://app.test/orders", "https://app.test:8443/", "http://app.test:443/"):
        with pytest.raises(ValueError, match="origin that set it"):
            _bind(state, elsewhere)
    assert origin_key("http://[2001:db8::1]/x") == "http://[2001:db8::1]:80"


def test_a_cookie_capture_is_shown_as_the_binding_that_sends_it(vault):
    state = _captured({"sid": SESSION})
    (reference,) = state.public_result()
    assert reference == {"source_action_id": ACTION, "capture_name": "session", "header": "Cookie"}
    assert public_capture_references([reference], source_action_id=ACTION) == [reference]
    forged = {**reference, "header": "Authorization"}
    assert public_capture_references([forged], source_action_id=ACTION) == [
        {"source_action_id": ACTION, "capture_name": "session"}]


def test_a_target_cannot_blind_the_hunt_with_ordinary_cookie_values(vault):
    state = _captured({"sid": SESSION, "banner": "Orders and tickets", "path": "/hub/orders/list"})

    class Conn:
        async def fetch(self, *_):
            return [{"private_http_result": state.encrypted_result}]

    values = asyncio.run(sealed_hunt_knowledge(Conn(), run_id=HUNT, target=TARGET))["values"]
    assert SESSION in values
    assert not any(value in values for value in ("Orders and tickets", "/hub/orders/list"))
    assert not any("banner=" in value for value in values)


@pytest.mark.parametrize(("tool", "value"), [
    ("ffuf", "sid=abcFUZZdef01"), ("sqlmap", "sid=abc*def0123"), ("nuclei", "sid={{BaseURL}}0123"),
])
def test_a_session_value_carrying_the_tools_marker_is_refused(tool, value):
    with pytest.raises(agent_tools.AgentToolError, match="injection marker"):
        agent_tools._trusted_scanner_header_args(tool, {"Cookie": value})
    from runtime.hunt_scanner_contract import header_marker_refusal
    assert header_marker_refusal(tool, value)
    assert header_marker_refusal("dalfox", value) is None


def test_signed_in_sqlmap_never_tests_the_session_cookies():
    args = agent_tools._trusted_scanner_header_args("sqlmap", {"Cookie": f"lang=en; sid={SESSION}"})
    assert args[:1] == ["--headers"] and args[args.index("--skip") + 1] == "lang,sid"
    assert "--skip" not in agent_tools._trusted_scanner_header_args("sqlmap", {"Authorization": f"Bearer {JWT}"})


def test_the_scanner_dispatch_refuses_a_captured_cookie_with_the_tools_marker(monkeypatch):
    from hunt import scanner_identity
    from hunt.dispatch_authority import HuntDispatchRejected
    import runtime.hunt_http_exchange as exchange

    async def bound(*_args, **_kwargs):
        return "sid=abc*def0123", True

    monkeypatch.setattr(exchange, "captured_binding", bound)
    with pytest.raises(HuntDispatchRejected, match="injection marker"):
        asyncio.run(scanner_identity._captured_login_identity(
            object(), run_id=HUNT, target=TARGET, policy={"active_testing": True},
            capability_name="sqli.verify", destination=f"{ORIGIN}/item?id=1",
            binding={"source_action_id": ACTION, "capture_name": "session", "header": "Cookie"}))
    # Dalfox reads no such marker: the same cookie is sent.
    identity = asyncio.run(scanner_identity._captured_login_identity(
        object(), run_id=HUNT, target=TARGET, policy={"active_testing": True},
        capability_name="xss.verify", destination=f"{ORIGIN}/s?q=1",
        binding={"source_action_id": ACTION, "capture_name": "session", "header": "Cookie"}))
    assert identity.principal_slot == "captured_session"
