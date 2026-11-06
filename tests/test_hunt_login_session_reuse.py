"""A Hunt's own login is reusable, and the planner sees the page (links, forms, visible text).

Real admission, the unchanged production worker function, encryption and pinned loopback
traffic (the harness of test_hunt_http_pairing_workflow). The target is a local fixture shaped
like a form-login web application: a login answering 303 with its session cookie, pages that
open with about 1.9 KB of CSS before any link. Values are synthetic.
"""
from __future__ import annotations

import asyncio
from dataclasses import replace
import json
import re
from types import SimpleNamespace
from urllib.parse import parse_qs
import uuid

import httpx
import pytest

from capabilities import artifact as artifact_capability
from http_experiment import response_summary
from runtime.archive_body_masking import WithheldValues, collecting_withheld_values
from runtime.capability_registry import CAPABILITY_REGISTRY, CapabilityInputContractError
from runtime.hunt_http_exchange import HttpWorkflowExchange, captured_binding
from runtime.html_outline import MAX_LINKS, MAX_TEXT_CHARS
from runtime.models import TargetBinding
from tests.test_hunt_http_pairing_workflow import Connection, encrypted_vault, execute  # noqa: F401

SESSION = "hs-7f3a9c2e41d84b0f9e1a6c5d3b2f8e70"
FLASH = "welcome-banner-41"
PASSWORD = "fixture-password-correct"
HUNT, ACTION = str(uuid.UUID(int=301)), str(uuid.UUID(int=302))
TARGET = TargetBinding(target_id=str(uuid.UUID(int=303)), target_kind="web",
    canonical_host="app.test", allowed_origins=("http://app.test:8000",),
    allowed_addresses=("192.0.2.20",), allowed_root_domains=("app.test",),
    environment="lab", scope_receipt_id=str(uuid.UUID(int=304)))

# The application's stylesheet, inline in every page's head: about 1.9 KB before the body.
CSS = "\n".join((
    ":root{--bg:#f4f6f9;--panel:#fff;--ink:#1f2a37;--muted:#64748b;--line:#e2e8f0;--brand:#1e4e8c}",
    "*{box-sizing:border-box}body{margin:0;font:14px/1.5 -apple-system,Segoe UI,Roboto,Arial,sans-serif}",
    "a{color:var(--brand);text-decoration:none}a:hover{text-decoration:underline}",
    ".top{background:var(--brand);display:flex;align-items:center;gap:24px;padding:0 24px;height:56px}",
    ".top b{font-size:16px;letter-spacing:.02em}.top nav{display:flex;gap:18px;flex-wrap:wrap}",
    "main{max-width:1080px;margin:0 auto;padding:24px;display:grid;gap:20px}",
    ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px}",
    ".card{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:16px}",
    ".card h3{margin:0 0 8px;font-size:13px;text-transform:uppercase;letter-spacing:.06em}",
    ".big{font-size:26px;font-weight:600}table{width:100%;border-collapse:collapse}",
    "th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line)}",
    ".login{max-width:360px;margin:12vh auto;background:var(--panel);border:1px solid var(--line)}",
    ".login input{width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:4px}",
    ".login button{padding:10px;border:0;border-radius:4px;background:var(--brand);font-weight:600}",
    ".err{color:#b91c1c;font-size:13px}.muted{color:var(--muted)}",
) * 2)


def page(title: str, body: str) -> str:
    return ('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            f"<title>{title} · Example Hub</title><style>{CSS}</style></head><body>{body}</body></html>")


LOGIN_PAGE = page("Sign in", '<form class="login" method="post" action="/hub/login">'
    '<b>Example Hub</b><span class="muted">Sign in with your employee account</span>'
    '<label>Username<input name="username" autocomplete="username"></label>'
    '<label>Password<input name="password" type="password" value="prefilled-not-shown"></label>'
    '<input type="hidden" name="csrf_token" value="c5f1e9a7b3d24f6e8a0c2b4d6f8e1a3c">'
    '<input type="hidden" name="next" value="/hub/">'
    '<button type="submit">Sign in</button></form>')


def orders_page(echo: str = "") -> str:
    rows = "".join(f'<tr><td><a href="/hub/api/orders/{n}">#{n}</a></td><td>open</td></tr>' for n in (1001, 1002))
    return page("Orders", '<header class="top"><b>Example Hub</b><nav><a href="/hub/">Dashboard</a>'
        '<a href="/hub/orders">Orders</a><a href="/hub/tickets">Tickets</a>'
        '<a href="https://status.example.net/hub">Status</a><a href="javascript:void(0)">Menu</a>'
        '<a href="/hub/directory">Directory</a></nav><span class="who">Ada Lovelace · staff · '
        '<a href="/hub/logout">Sign out</a></span></header>'
        f'<main><h2>Good morning, Ada</h2><p data-session="{echo}">Session {echo}</p>'
        f'<div class="card"><h3>Orders</h3><table>{rows}</table></div>'
        '<script>window.hubConfig={"api":"/hub/api/"}</script></main>')


def test_the_pages_open_with_css_past_the_old_sample():
    # The fixture is what the planner faced: no link inside the first 1.9 KB.
    first_link = orders_page().index("/hub/")
    assert first_link > 1_900 and LOGIN_PAGE.index("<form") > 1_900


# --- capture -------------------------------------------------------------------------------------

def _private(response_cookies, status=303, headers=None, final_url="http://app.test:8000/hub/login"):
    return SimpleNamespace(status_code=status, headers=lambda: dict(headers or {}), body=lambda: b"",
                           cookies=lambda: dict(response_cookies), final_url=final_url)


def test_a_redirect_login_cookie_is_captured_as_name_value_pairs():
    state = HttpWorkflowExchange(HUNT, ACTION, TARGET, ({"name": "session", "header": "Set-Cookie"},))
    state.capture_response(_private({"hub_session": SESSION, "hub_flash": FLASH}))
    assert state.captured_names == ("session",) and not state.missing_names and state.capture_error is None
    assert state.encrypted_result.startswith("enc:fernet:")
    assert SESSION not in repr(state) + json.dumps(state.public_result()) + state.encrypted_result

    async def scenario():
        async def row(*_):
            return {"private_http_result": state.encrypted_result}
        return await captured_binding(SimpleNamespace(fetchrow=row), run_id=HUNT, target=TARGET,
                                      binding={"source_action_id": ACTION, "capture_name": "session"})
    value, is_cookie = asyncio.run(scenario())
    assert is_cookie and value == f"hub_session={SESSION}; hub_flash={FLASH}"


def test_any_header_is_captured_on_a_redirect_and_a_missing_one_is_reported_not_fatal():
    state = HttpWorkflowExchange(HUNT, ACTION, TARGET, (
        {"name": "next", "header": "Location"}, {"name": "token", "header": "X-Token"},
        {"name": "body", "json_pointer": "/token"}))
    state.capture_response(_private({}, status=302, headers={"location": "/hub/"}))
    assert state.captured_names == ("next",)
    assert state.missing_names == ("token", "body")
    assert state.encrypted_result.startswith("enc:fernet:")


def test_a_response_that_sets_no_cookie_records_the_capture_missing():
    state = HttpWorkflowExchange(HUNT, ACTION, TARGET, ({"name": "session", "header": "Set-Cookie"},))
    state.capture_response(_private({}, status=401))
    assert state.captured_names == () and state.missing_names == ("session",)
    assert state.public_result() == [] and state.encrypted_result is None


# --- the planner's view of a page ---------------------------------------------------------------

def _summary(html: str, url: str = "http://app.test:8000/hub/orders"):
    response = httpx.Response(200, headers={"content-type": "text/html; charset=utf-8"},
                              content=html.encode(), request=httpx.Request("GET", url))
    collector = WithheldValues(ACTION)
    with collecting_withheld_values(collector):
        return response_summary(response, html.encode()), collector


def test_an_html_answer_carries_its_links_forms_and_visible_text():
    summary, _ = _summary(orders_page())
    outline = summary["html"]
    assert outline["title"] == "Orders · Example Hub"
    # Same-origin first, as paths, in document order; then other origins; never javascript:.
    assert outline["links"][:4] == ["/hub/", "/hub/orders", "/hub/tickets", "/hub/directory"]
    assert "/hub/api/orders/1001" in outline["links"] and "/hub/logout" in outline["links"]
    assert outline["links"][-1] == "https://status.example.net/hub"
    assert not any("javascript" in link for link in outline["links"])
    text = outline["text_sample"]
    assert "Good morning, Ada" in text and "#1001" in text
    assert "box-sizing" not in text and "hubConfig" not in text  # no style, no script
    # The body sample is unchanged: still the page's first bytes.
    assert summary["body_sample"].startswith("<!DOCTYPE html>")


def test_a_login_form_shows_field_names_never_a_password_value():
    summary, collector = _summary(LOGIN_PAGE, "http://app.test:8000/hub/login")
    (form,) = summary["html"]["forms"]
    assert form["method"] == "POST" and form["action"] == "/hub/login"
    fields = {field["name"]: field for field in form["fields"]}
    assert fields["username"] == {"name": "username", "type": "text"}
    assert fields["password"] == {"name": "password", "type": "password"}
    assert fields["next"]["value"] == "/hub/"
    # A secret-named hidden value is withheld behind a reference the planner can bind.
    assert re.fullmatch(r"\[withheld:\d+\]", fields["csrf_token"]["value"])
    rendered = json.dumps(summary)
    assert "prefilled-not-shown" not in json.dumps(summary["html"])
    assert "c5f1e9a7b3d24f6e8a0c2b4d6f8e1a3c" not in rendered
    assert any(entry["marker"] == fields["csrf_token"]["value"] for entry in summary["withheld_values"])
    assert collector.values  # sealed with the action like any other withheld value


def test_the_outline_is_bounded():
    many = page("Many", "".join(f'<a href="/p/{n}">{"word " * 12}</a>' for n in range(200)))
    summary, _ = _summary(many)
    outline = summary["html"]
    assert len(outline["links"]) == MAX_LINKS and outline["links_total"] == 200
    assert len(outline["text_sample"]) <= MAX_TEXT_CHARS and outline["text_truncated"] is True
    assert len(json.dumps(outline)) < 4_000


def test_outside_a_hunt_and_for_other_content_there_is_no_outline():
    response = httpx.Response(200, headers={"content-type": "text/html"}, content=LOGIN_PAGE.encode(),
                              request=httpx.Request("GET", "http://app.test:8000/hub/login"))
    assert "html" not in response_summary(response, LOGIN_PAGE.encode())
    response = httpx.Response(200, headers={"content-type": "application/json"}, content=b'{"a":"<a href=/x>"}',
                              request=httpx.Request("GET", "http://app.test:8000/api"))
    with collecting_withheld_values(WithheldValues(ACTION)):
        assert "html" not in response_summary(response, b'{"a":"<a href=/x>"}')


# --- log in, then reuse the session: the worker end to end --------------------------------------

async def hub_server(wire, *, session=SESSION):
    async def serve(reader, writer):
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            length = re.search(rb"(?im)^content-length: (\d+)", head)
            body = await reader.readexactly(int(length[1])) if length else b""
            wire.append((head, body))
            cookie = re.search(rb"(?im)^cookie: ([^\r\n]*)", head)
            if head.startswith(b"POST /hub/login "):
                form = parse_qs(body.decode())
                if form.get("password") == [PASSWORD]:
                    response = ("HTTP/1.1 303 See Other\r\nLocation: /hub/\r\n"
                                f"Set-Cookie: hub_session={session}; HttpOnly; SameSite=Lax; Path=/hub\r\n"
                                f"Set-Cookie: hub_flash={FLASH}; Path=/hub\r\n"
                                "Set-Cookie: hub_old=; Max-Age=0; Path=/hub\r\n"
                                "Content-Length: 0\r\nConnection: close\r\n\r\n").encode()
                else:
                    content = page("Sign in", '<div class="err">Invalid credentials</div>').encode()
                    response = (b"HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\nConnection: close\r\n"
                                b"Content-Length: " + str(len(content)).encode() + b"\r\n\r\n" + content)
            elif cookie and f"hub_session={session}".encode() in cookie[1]:
                content = orders_page(echo=session).encode()
                response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n"
                            b"Content-Length: " + str(len(content)).encode() + b"\r\n\r\n" + content)
            else:
                response = b"HTTP/1.1 303 See Other\r\nLocation: /hub/login\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            writer.write(response)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
    return await asyncio.start_server(serve, "127.0.0.1", 0)


LOGIN = {"method": "POST", "path": "/hub/login", "form_body": {"username": "ada", "password": PASSWORD},
         "capture": [{"name": "session", "header": "Set-Cookie"}]}


def _bound(login_result, header="Cookie"):
    return [{**login_result["captures"][0], "header": header}]


def test_a_hunt_logs_in_and_reads_signed_in_pages_without_seeing_the_cookie():
    async def scenario():
        wire = []
        server = await hub_server(wire)
        async with server:
            conn = Connection(f"http://fixture.test:{server.sockets[0].getsockname()[1]}")
            login, _ = await execute(conn, LOGIN, "hub-login")
            assert login["status"] == "success", login
            # The capture is shown as the binding that sends the session back.
            assert login["captures"] == [{"source_action_id": login["captures"][0]["source_action_id"],
                                          "capture_name": "session", "header": "Cookie"}]
            answer = login["typed_output"]["records"][0]["response"]
            assert answer["status"] == 303 and "captures_missing" not in answer
            # The login's answer: its status and the cookies' names and attributes, never values.
            assert {cookie["name"] for cookie in answer["set_cookie_metadata"]} >= {"hub_session", "hub_flash"}
            assert next(c for c in answer["set_cookie_metadata"] if c["name"] == "hub_session")["httponly"]

            orders, _ = await execute(conn, {"method": "GET", "path": "/hub/orders",
                                             "request_bindings": _bound(login)}, "hub-orders")
            assert orders["status"] == "success", orders
            sent = wire[-1][0]
            # Every cookie the login set, as name=value pairs, no attributes, the deleted one gone.
            sent_cookie = re.search(rb"(?im)^cookie: ([^\r\n]*)", sent)[1].decode()
            assert sorted(sent_cookie.split("; ")) == sorted([f"hub_session={SESSION}", f"hub_flash={FLASH}"])
            response = orders["typed_output"]["records"][0]["response"]
            assert response["status"] == 200
            # The planner keeps the signed-in page: its links, forms and text.
            assert "/hub/api/orders/1001" in response["html"]["links"]
            assert "Good morning, Ada" in response["html"]["text_sample"]
            assert "withheld" in response["html"]["text_sample"]  # the echoed session
            assert conn.raw_archive[-1]["principal_slot"] == "workflow_binding"

            # The cookie value never reaches the planner, the stored action results or the inputs.
            public = json.dumps([login, orders, LOGIN])
            stored = json.dumps([row.get("result_summary") for row in conn.actions.values()], default=str)
            for secret in (SESSION, FLASH):
                assert secret not in public and secret not in stored
            sealed = [row["private_http_result"] for row in conn.actions.values() if row.get("private_http_result")]
            assert sealed and all(item.startswith("enc:fernet:") and SESSION not in item for item in sealed)
    asyncio.run(scenario())


def test_a_failed_login_is_a_result_not_a_failed_action():
    async def scenario():
        wire = []
        server = await hub_server(wire)
        async with server:
            conn = Connection(f"http://fixture.test:{server.sockets[0].getsockname()[1]}")
            wrong = {**LOGIN, "form_body": {"username": "ada", "password": "wrong-password"}}
            result, _ = await execute(conn, wrong, "hub-login-wrong")
            assert result["status"] == "success" and result["ok"] is True, result
            response = result["typed_output"]["records"][0]["response"]
            assert response["status"] == 401 and response["captures_missing"] == ["session"]
            assert result["captures"] == []
            assert not any(row.get("private_http_result") for row in conn.actions.values())
    asyncio.run(scenario())


def test_a_short_session_cookie_is_sent_but_its_answer_is_reduced_to_the_status():
    short = "s1x"

    async def scenario():
        wire = []
        server = await hub_server(wire, session=short)
        async with server:
            conn = Connection(f"http://fixture.test:{server.sockets[0].getsockname()[1]}")
            login, _ = await execute(conn, LOGIN, "hub-login-short")
            orders, _ = await execute(conn, {"method": "GET", "path": "/hub/orders",
                                             "request_bindings": _bound(login)}, "hub-orders-short")
            assert orders["status"] == "success", orders
            response = orders["typed_output"]["records"][0]["response"]
            # A three-character value would match ordinary text: nothing but the status is shown.
            assert response["status"] == 200 and response["workflow_values_visible"] is False
            assert "html" not in response and "body_sample" not in response
    asyncio.run(scenario())


# --- artifact.inspect reads a longer signed-in page as the same session -------------------------

def test_artifact_inspect_takes_a_session_and_capture_bindings_in_its_schema():
    binding = {"source_action_id": ACTION, "capture_name": "session", "header": "Cookie"}
    CAPABILITY_REGISTRY.validate_hunt_input("artifact.inspect", {"path": "/hub/admin", "request_bindings": [binding]})
    CAPABILITY_REGISTRY.validate_hunt_input("artifact.inspect", {"path": "/hub/admin", "as_principal": "primary"})
    CAPABILITY_REGISTRY.validate_hunt_input("artifact.inspect", {
        "path": "/hub/admin", "session_ref": "11111111-2222-4333-8444-555555555555"})
    for bad in ({**binding, "withheld_ref": "withheld://hunt/x/1"}, {"capture_name": "session", "header": "Cookie"},
                {**binding, "body_pointer": "/x"}):
        with pytest.raises(CapabilityInputContractError):
            CAPABILITY_REGISTRY.validate_hunt_input("artifact.inspect", {"path": "/", "request_bindings": [bad]})


def test_artifact_read_admission_meters_an_identity_like_http_request():
    from fastapi import HTTPException
    from hunt.artifact_identity import artifact_read_identity
    binding = [{"source_action_id": ACTION, "capture_name": "session", "header": "Cookie"}]
    assert artifact_read_identity({"path": "/"}, {}) == ("anonymous", False, False)
    assert artifact_read_identity({"path": "/", "as_principal": "primary"}, {}) == ("primary", False, False)
    assert artifact_read_identity({"path": "/", "session_ref": "x"}, {}) == ("anonymous", True, False)
    assert artifact_read_identity({"path": "/", "request_bindings": binding}, {"active_testing": True}) == (
        "anonymous", False, True)
    with pytest.raises(HTTPException) as refused:
        artifact_read_identity({"path": "/", "request_bindings": binding}, {"active_testing": False})
    assert refused.value.status_code == 403


def test_artifact_inspect_reads_a_signed_in_page_with_a_captured_cookie(monkeypatch, tmp_path):
    from aiohttp import web
    from cryptography.fernet import Fernet
    import secret_store
    from hunt.artifact_identity import resolve_artifact_identity
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(secret_store, "_loaded", False)
    monkeypatch.setattr(secret_store, "_fernet", None)
    long_page = orders_page(echo=SESSION).replace("</main>", "<p>" + "Quarterly payroll line. " * 300 + "</p></main>")
    seen = []

    async def scenario():
        async def admin(request):
            seen.append(request.headers.get("Cookie"))
            if request.headers.get("Cookie") != f"hub_session={SESSION}":
                raise web.HTTPSeeOther("/hub/login")
            return web.Response(text=long_page, content_type="text/html")

        app = web.Application()
        app.router.add_get("/hub/admin", admin)
        runner = web.AppRunner(app, shutdown_timeout=1)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        base = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
        target = replace(TARGET, canonical_host="127.0.0.1", allowed_origins=(base,),
                         allowed_addresses=("127.0.0.1",), allowed_root_domains=("127.0.0.1",))
        state = HttpWorkflowExchange(HUNT, ACTION, target, ({"name": "session", "header": "Set-Cookie"},))
        state.capture_response(_private({"hub_session": SESSION}, final_url=f"{base}/hub/login"))

        class Pool:
            def acquire(self):
                pool = self

                class Acquired:
                    async def __aenter__(self):
                        async def fetchrow(*_):
                            return {"private_http_result": state.encrypted_result}
                        return SimpleNamespace(fetchrow=fetchrow)

                    async def __aexit__(self, *_):
                        return None
                del pool
                return Acquired()

        values = {"path": "/hub/admin", "max_bytes": 16_384,
                  "request_bindings": [{"source_action_id": ACTION, "capture_name": "session", "header": "Cookie"}]}
        try:
            headers, bound, slot = await resolve_artifact_identity(
                pool=Pool(), run={"id": HUNT}, hunt_id=HUNT, context={}, target=target, policy=None,
                hunt_policy={"active_testing": True}, target_url=base, values=values, stack=None,
                session_store=None)
            assert slot == "workflow_binding" and headers == {"Cookie": f"hub_session={SESSION}"}
            with pytest.raises(Exception):
                await resolve_artifact_identity(
                    pool=Pool(), run={"id": HUNT}, hunt_id=HUNT, context={}, target=target, policy=None,
                    hunt_policy={"active_testing": False}, target_url=base, values=values, stack=None,
                    session_store=None)
            recorded = []
            collector = WithheldValues(ACTION)
            with collecting_withheld_values(collector):
                collector.bind_known(bound)
                result = await artifact_capability.inspect_target_artifact(
                    base, values, target=target, transaction_recorder=recorded.append,
                    trusted_headers=headers, principal_slot=slot)
            anonymous = await artifact_capability.inspect_target_artifact(base, {"path": "/hub/admin"}, target=target)
            return result, recorded, anonymous
        finally:
            await runner.cleanup()

    result, recorded, anonymous = asyncio.run(scenario())
    assert result["ok"] is True, result
    observation = result["observation"]
    assert observation["returned_bytes"] > 2_000 and "Quarterly payroll line." in observation["text_sample"]
    assert SESSION not in json.dumps(result)
    assert recorded and recorded[0]["principal_slot"] == "workflow_binding"
    assert seen[0] == f"hub_session={SESSION}"
    # Without the session the page is not reached: the read follows the redirect to the login.
    assert seen[-1] is None and SESSION not in json.dumps(anonymous)


async def _admit_and_run(conn, name, inputs, key):
    """The harness's admission and worker, for a capability other than http.request."""
    from hunt.capability_reservations import hunt_capability_action_digest, hunt_capability_lease_seconds
    from hunt.target_binding import web_hunt_target
    from runtime.budget_reservations import DurableBudgetReservation
    from tests.test_hunt_authz_verification_limit import admission, Lifecycle
    from tests.test_hunt_http_pairing_workflow import worker
    from tests.test_hunt_replay_worker_lifecycle import noop
    CAPABILITY_REGISTRY.validate_hunt_input(name, inputs)
    fn = admission(conn)

    async def approval(*_, **kwargs):
        conn.approvals.append(kwargs["risk_tier"])
        return {"scope_receipt_id": "scope"}
    fn.__globals__.update(PostgresBudgetReservationStore=lambda: conn.store,
        DurableBudgetReservation=DurableBudgetReservation,
        hunt_capability_action_digest=hunt_capability_action_digest,
        hunt_capability_lease_seconds=hunt_capability_lease_seconds,
        _validate_approval_receipt_for_action=approval, require_device_admission=noop,
        web_hunt_target=web_hunt_target, _hunt_managed_principal_reference=lambda *_, **__: None,
        _hunt_public=lambda *_, **__: {"capabilities": [{"name": "http.request"}, {"name": name}]})
    life = Lifecycle(name)
    life.specification = CAPABILITY_REGISTRY.require(name)
    life.placement = life.specification.hunt_executor
    admitted = await fn(str(conn.run["id"]), name, SimpleNamespace(input=inputs, idempotency_key=key), life)
    stored = next(row for row in conn.store.rows.values() if row.action_id == admitted["action_id"])
    job = {"job_id": str(uuid.uuid4()), "hunt_id": str(conn.run["id"]), "action_id": admitted["action_id"],
           "budget_reservation_id": stored.record.reservation_id, "action_digest": stored.action_digest,
           "capability_name": name, "capability_input": inputs, "expected_budget": dict(stored.record.requested)}
    run_job = worker(conn)
    from capabilities.artifact import analyze_target_javascript, inspect_target_artifact
    from capabilities.inline import ArtifactInspectionExecutionAdapter
    from scanner_tools.url_redaction import redact_url
    run_job.__globals__.update(inspect_target_artifact=inspect_target_artifact, redact_url=redact_url,
                               analyze_target_javascript=analyze_target_javascript,
                               ArtifactInspectionExecutionAdapter=ArtifactInspectionExecutionAdapter)
    await run_job(job)
    return json.loads(json.dumps(conn.result, default=str)), dict(stored.record.requested)


def test_the_worker_reads_a_long_signed_in_page_with_the_hunts_login_cookie():
    async def scenario():
        wire = []
        server = await hub_server(wire)
        async with server:
            conn = Connection(f"http://fixture.test:{server.sockets[0].getsockname()[1]}")
            conn.run["policy_json"]["allowed_capabilities"] = ["http.request", "artifact.inspect"]
            login, _ = await execute(conn, LOGIN, "hub-login-inspect")
            approvals = len(conn.approvals)
            read, requested = await _admit_and_run(conn, "artifact.inspect", {
                "path": "/hub/orders", "max_bytes": 16_384, "request_bindings": _bound(login)}, "hub-inspect")
            assert read["status"] == "success", read
            # Metered and approved as an active read, like the http.request it could have been.
            assert requested.get("active_actions") == 1 and conn.approvals[approvals] == "active"
            assert f"hub_session={SESSION}".encode() in wire[-1][0]
            observation = read["typed_output"]["records"][0]
            assert observation["returned_bytes"] > 2_000 and "Good morning, Ada" in observation["text_sample"]
            assert read["execution"]["as_principal"] == "workflow_binding"
            assert read["execution"]["credential_headers_injected"] is True
            assert SESSION not in json.dumps(read) and FLASH not in json.dumps(read)
            assert conn.raw_archive[-1]["principal_slot"] == "workflow_binding"
    asyncio.run(scenario())


def test_an_unknown_capture_reference_sends_no_read_and_settles_the_hold():
    async def scenario():
        wire = []
        server = await hub_server(wire)
        async with server:
            conn = Connection(f"http://fixture.test:{server.sockets[0].getsockname()[1]}")
            conn.run["policy_json"]["allowed_capabilities"] = ["http.request", "artifact.inspect"]
            stale = [{"source_action_id": str(uuid.uuid4()), "capture_name": "session", "header": "Cookie"}]
            read, _ = await _admit_and_run(conn, "artifact.inspect",
                                           {"path": "/hub/orders", "request_bindings": stale}, "hub-inspect-stale")
            assert read["status"] in {"failed", "blocked"}, read
            assert read["durable_budget_settled"] and not read["error"].startswith("worker_fault"), read
            assert wire == []
    asyncio.run(scenario())


def test_a_malformed_link_is_left_out_and_never_fails_the_answer():
    summary, _ = _summary(page("Broken", '<a href="http://[x/">bad</a><a href="/hub/ok">ok</a>'))
    assert summary["html"]["links"] == ["/hub/ok"]


@pytest.mark.parametrize("capture,cookies,headers", [
    ({"name": "session", "json_pointer": "/token"}, {}, {}),       # a PIN or token: http.request's
    ({"name": "session", "header": "X-Pin"}, {}, {"x-pin": "4821"}),
    ({"name": "session", "header": "Set-Cookie"}, {"sid": "abc"}, {}),  # too short to withhold
])
def test_artifact_inspect_sends_only_a_long_session_cookie(capture, cookies, headers):
    from runtime.credential_refs import CredentialReferenceError
    from hunt.artifact_identity import resolve_artifact_identity
    state = HttpWorkflowExchange(HUNT, ACTION, TARGET, (capture,))
    response = SimpleNamespace(status_code=200, headers=lambda: dict(headers),
                               body=lambda: b'{"token":"4821"}', cookies=lambda: dict(cookies),
                               final_url="http://app.test:8000/hub/login")
    state.capture_response(response)
    assert state.encrypted_result

    class Pool:
        def acquire(self):
            class Acquired:
                async def __aenter__(self):
                    async def fetchrow(*_):
                        return {"private_http_result": state.encrypted_result}
                    return SimpleNamespace(fetchrow=fetchrow)

                async def __aexit__(self, *_):
                    return None
            return Acquired()

    values = {"path": "/hub/admin",
              "request_bindings": [{"source_action_id": ACTION, "capture_name": "session", "header": "Cookie"}]}
    with pytest.raises(CredentialReferenceError, match="only a captured session cookie"):
        asyncio.run(resolve_artifact_identity(
            pool=Pool(), run={"id": HUNT}, hunt_id=HUNT, context={}, target=TARGET, policy=None,
            hunt_policy={"active_testing": True}, target_url="http://app.test:8000", values=values,
            stack=None, session_store=None))
