"""Real Chromium plus real pinned HTTP, against an isolated synthetic loopback app.

The two dispatchers and worker-authority reloads have separate integration suites.
This opt-in test exercises the registered adapter through the actual browser and
wire transport. A browser administrative denial is a failure, never a skip/pass.
"""
import asyncio
from contextlib import asynccontextmanager
from dataclasses import asdict
import json
import os

import pytest

from capabilities.browser_login import BrowserLoginValues, BrowserLoginWorkflow
from capabilities.browser_login_action import BrowserLoginAdapter, BrowserLoginMaterial
from runtime.browser_login_contract import BROWSER_LOGIN_CAPABILITY
from runtime.models import TargetBinding, ScanPolicy

CHROMIUM = os.environ.get("SHAKERSCAN_BROWSER_TEST_EXECUTABLE")
pytestmark = pytest.mark.skipif(not CHROMIUM, reason="explicit installed Chromium path required")


@pytest.mark.parametrize("storage", ["cookie", "local_storage"])
@pytest.mark.parametrize("valid_password", [True, False])
def test_registered_action_real_browser_and_pinned_transport(storage, valid_password):
    async def scenario():
        posts = []
        paths = []
        pending = set()
        login = b'''<!doctype html><input id="username"><input id="password" type="password">
<button id="sign-in" type="button">Sign in</button><div id="login-error" hidden>Rejected</div>
<script>document.querySelector('#sign-in').onclick=async()=>{
 const r=await fetch('/session',{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({username:document.querySelector('#username').value,
 password:document.querySelector('#password').value})});
 if(r.ok){localStorage.setItem('synthetic-session','active');location.href='/account';}
 else document.querySelector('#login-error').hidden=false;};</script>'''
        async def serve(reader, writer):
            task = asyncio.current_task()
            pending.add(task)
            try:
                raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
                lines = raw.decode("latin-1").split("\r\n")
                method, path, _ = lines[0].split(" ")
                headers = {k.lower(): v.strip() for line in lines[1:] if ":" in line for k,v in [line.split(":",1)]}
                body = await reader.readexactly(int(headers.get("content-length", "0")))
                paths.append((method, path))
                status, extra = 200, b""
                if path == "/login":
                    data = login
                elif path == "/session" and method == "POST":
                    payload = json.loads(body)
                    posts.append(payload)
                    assert payload["username"] == "synthetic-user"
                    if payload["password"] == "synthetic-password":
                        data = b"ok"
                        extra = b"Set-Cookie: synthetic-session=active; HttpOnly; Path=/; SameSite=Lax\r\n"
                    else:
                        status, data = 401, b"rejected"
                elif path == "/account":
                    if storage == "cookie":
                        data = (b'<div id="private-account">Account</div>'
                                if "synthetic-session=active" in headers.get("cookie", "")
                                else b'<div id="login-error">Expired</div>')
                    else:
                        data = b'''<div id="private-account" hidden>Account</div><div id="login-error" hidden>Expired</div>
<script>document.querySelector(localStorage.getItem('synthetic-session')==='active'?'#private-account':'#login-error').hidden=false;</script>'''
                else:
                    status, data = 404, b"not found"
                writer.write(f"HTTP/1.1 {status} Response\r\nContent-Type: text/html\r\nContent-Length: {len(data)}\r\nConnection: close\r\n".encode() + extra + b"\r\n" + data)
                await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError):
                # Chromium can open speculative sockets without sending HTTP.
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except ConnectionError:
                    pass
                pending.discard(task)
        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        origin = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        workflow = BrowserLoginWorkflow(
            origin=origin, login_url=origin + "/login", submit_url=origin + "/session",
            check_url=origin + "/account", username_selector="#username", password_selector="#password",
            submit_selector="#sign-in", authenticated_selector="#private-account", rejected_selector="#login-error",
            timeout_ms=10000, qa_timeout_ms=10000,
        )
        target = TargetBinding(target_id="22222222-2222-4222-8222-222222222222", target_kind="web",
                               canonical_host="127.0.0.1", allowed_origins=(origin,),
                               allowed_addresses=("127.0.0.1",), scope_receipt_id="synthetic-scope")
        prepared = BrowserLoginAdapter.prepare(target=target, base_url=origin, args={"as_principal": "primary"},
            profile_ref={"profile_id": "11111111-1111-4111-8111-111111111111", "profile_version": 1, "principal_slot": "primary"})
        async def revalidate():
            pass
        @asynccontextmanager
        async def material():
            yield BrowserLoginMaterial(
                {"schema_version": "browser-login-profile/v1", "workflow": asdict(workflow),
                 "checks": [{"url": origin + "/account", "visible_selector": "#private-account"}]},
                BrowserLoginValues("synthetic-user", "synthetic-password" if valid_password else "synthetic-wrong-password"),
                revalidate,
            )
        @asynccontextmanager
        async def browser_factory():
            from playwright.async_api import async_playwright
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(executable_path=CHROMIUM, headless=True,
                    args=["--no-sandbox", "--disable-background-networking", "--disable-component-update"])
                try:
                    yield browser
                finally:
                    await browser.close()
        try:
            adapter = BrowserLoginAdapter(prepared, credential_loader=material, browser_factory=browser_factory,
                policy=ScanPolicy(active_testing=True, allow_state_changing_http=True,
                                  approval_receipt_id="synthetic-approval", scope_receipt_id="synthetic-scope"))
            result = await adapter.execute(heartbeat=revalidate, cancelled=lambda: False)
            assert len(posts) == 1, "The test must reach the login; pre-login denial is not acceptance."
            assert result.status == ("success" if valid_password else "failed")
            assert result.actual_budget["state_changing_requests"] == 1
            assert result.observations[0]["authentication_verified"] is valid_password
            if valid_password:
                assert result.observations[0]["checks_completed"] == 1
                assert paths[0] == ("GET", "/account")
            assert "synthetic-password" not in repr(result)
        finally:
            server.close()
            await server.wait_closed()
            if pending:
                await asyncio.gather(*tuple(pending), return_exceptions=True)
    asyncio.run(scenario())
