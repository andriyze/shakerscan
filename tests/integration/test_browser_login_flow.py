"""Opt-in real Chromium login QA; every response is a synthetic local fixture.

No external application, credentials, scanner, or exploitation is involved. An
administrative browser policy blocking the loopback origin is a test blocker,
not a reason to change that policy or to turn the failing test into a pass.
"""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest

_SOURCE = Path(__file__).resolve().parents[2] / "api/capabilities/browser_login.py"
_SPEC = importlib.util.spec_from_file_location("browser_login_flow", _SOURCE)
assert _SPEC is not None and _SPEC.loader is not None
bl = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = bl
_SPEC.loader.exec_module(bl)
CHROMIUM = os.environ.get("SHAKERSCAN_BROWSER_TEST_EXECUTABLE")
pytestmark = pytest.mark.skipif(not CHROMIUM, reason="explicit installed Chromium path required")
ORIGIN = "http://127.0.0.1:8765"


def test_real_login_follows_only_saved_redirect_destinations():
    """Fulfilled redirects must re-enter the pinned browser route before login."""
    async def scenario():
        from playwright.async_api import async_playwright

        login = b'''<div id="root"></div><script>
document.getElementById('root').innerHTML='<form action="/login" method="post"><input id="username" name="username"><input id="password" name="password" type="password"><button id="submit" type="submit">Sign in</button></form>';
</script>'''
        calls = []

        async def transport(request, phase):
            path = request.url.removeprefix(ORIGIN)
            calls.append((phase, request.method, path))
            if path == "/dashboard" and phase == "anonymous":
                return bl.BrowserLoginResponse(303, {"Location": "/login"}, b"")
            if path == "/login" and request.method == "GET":
                return bl.BrowserLoginResponse(200, {"Content-Type": "text/html"}, login)
            if path == "/login" and request.method == "POST":
                return bl.BrowserLoginResponse(303, {
                    "Location": "/dashboard", "Set-Cookie": "session=synthetic; Path=/",
                }, b"")
            if path == "/dashboard":
                return bl.BrowserLoginResponse(200, {"Content-Type": "text/html"},
                                               b'<div id="authenticated">okay</div>')
            return bl.BrowserLoginResponse(404, {}, b"")

        workflow = bl.BrowserLoginWorkflow(
            origin=ORIGIN, login_url=ORIGIN + "/login", submit_url=ORIGIN + "/login",
            check_url=ORIGIN + "/dashboard", username_selector="#username",
            password_selector="#password", submit_selector="#submit",
            authenticated_selector="#authenticated", rejected_selector="#rejected",
            timeout_ms=5_000,
        )
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(executable_path=CHROMIUM, headless=True,
                args=["--no-sandbox", "--disable-background-networking"])
            try:
                receipt = await bl.run_browser_login_checks(
                    browser, workflow=workflow,
                    values=bl.BrowserLoginValues("synthetic-user", "synthetic-password"),
                    transport=transport,
                    checks=(bl.BrowserReadOnlyCheck(workflow.check_url, "#authenticated"),),
                )
            finally:
                await browser.close()
        assert receipt["status"] == "completed"
        assert receipt["anonymous_check_verified"] is True
        assert receipt["login_response_status"] == 303
        assert receipt["checks_completed"] == 1
        assert ("anonymous", "GET", "/login") in calls
        assert ("login", "POST", "/login") in calls
        assert all(path in {"/login", "/dashboard"} for _, _, path in calls)

    asyncio.run(scenario())


@pytest.mark.parametrize("storage", ["cookie", "local_storage"])
@pytest.mark.parametrize("mode", ["fixed_qa", "expiry"])
@pytest.mark.parametrize("decoded_gzip_response", [False, True])
def test_real_login_protected_navigation_and_expiry(storage, mode, decoded_gzip_response):
    async def scenario():
        from playwright.async_api import async_playwright

        polling = storage == "cookie" and mode == "fixed_qa" and decoded_gzip_response
        poll_script = b"<script>setInterval(() => fetch('/poll'), 20); fetch('/poll');</script>" if polling else b""
        login = b'''<!doctype html><input id="username"><input id="password" type="password">
<button id="sign-in" type="button">Sign in</button><div id="login-error" hidden>Rejected</div>
<script>
document.querySelector('#sign-in').onclick=async()=>{
 const r=await fetch('/session',{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({username:document.querySelector('#username').value,
 password:document.querySelector('#password').value})});
 if(r.ok){localStorage.setItem('synthetic-session','active');location.href='/account';}
 else document.querySelector('#login-error').hidden=false;
};
</script>''' + poll_script
        async def transport(request, phase):
            path = request.url.removeprefix(ORIGIN)
            headers = {"Content-Type": "text/html"}
            if decoded_gzip_response:
                # The pinned HTTP sender has already decoded the gzip body,
                # while its response headers still describe the wire encoding.
                headers["Content-Encoding"] = "gzip"
            if path == "/login":
                return bl.BrowserLoginResponse(200, headers, login)
            if path == "/poll":
                await asyncio.sleep(0.15)
                return bl.BrowserLoginResponse(200, {"Content-Type": "text/plain"}, b"ok")
            if path == "/session" and request.method == "POST":
                assert json.loads(request.post_data) == {"username": "synthetic-user", "password": "synthetic-password"}
                headers["Set-Cookie"] = "synthetic-session=active; Path=/; HttpOnly; SameSite=Lax"
                return bl.BrowserLoginResponse(200, headers, b"ok")
            if path == "/account":
                if storage == "cookie":
                    authenticated = "synthetic-session=active" in (await request.all_headers()).get("cookie", "")
                    body = (b'<div id="private-account">Account</div>' if authenticated else
                            b'<div id="login-error">Expired</div>') + poll_script
                else:
                    body = b'''<div id="private-account" hidden>Account</div><div id="login-error" hidden>Expired</div>
<script>document.querySelector(localStorage.getItem('synthetic-session')==='active'?'#private-account':'#login-error').hidden=false;</script>'''
                return bl.BrowserLoginResponse(200, headers, body)
            return bl.BrowserLoginResponse(404, headers, b"not found")

        workflow = bl.BrowserLoginWorkflow(
            origin=ORIGIN, login_url=ORIGIN + "/login", submit_url=ORIGIN + "/session",
            check_url=ORIGIN + "/account", username_selector="#username",
            password_selector="#password", submit_selector="#sign-in",
            authenticated_selector="#private-account", rejected_selector="#login-error",
            timeout_ms=10_000 if polling else 5_000,
        )
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(executable_path=CHROMIUM, headless=True,
                args=["--no-sandbox", "--disable-background-networking", "--disable-component-update"])
            try:
                values = bl.BrowserLoginValues("synthetic-user", "synthetic-password")
                if mode == "fixed_qa":
                    result = await bl.run_browser_login_checks(
                        browser, workflow=workflow, values=values, transport=transport,
                        checks=(bl.BrowserReadOnlyCheck(workflow.check_url, "#private-account"),),
                    )
                    assert result["status"] == "completed"
                    assert result["anonymous_check_verified"] is True
                    assert result["qa_completed"] is True
                    assert result["context_closed"] is True
                    assert result["login_submissions"] == 1
                    assert result["checks_completed"] == 1
                    assert "synthetic-password" not in repr(result)
                else:
                    entered = False
                    with pytest.raises(bl.BrowserLoginError, match="authentication_rejected") as caught:
                        async with bl.authenticated_browser_page(
                            browser, workflow=workflow, values=values, transport=transport,
                        ) as (page, receipt):
                            entered = True
                            assert receipt["authentication_verified"] is True
                            assert receipt["login_submissions"] == 1
                            if storage == "cookie":
                                await page.context.clear_cookies()
                            else:
                                await page.evaluate("localStorage.clear()")
                            await page.goto(workflow.check_url, wait_until="domcontentloaded")
                            assert await bl.browser_authentication_state(page, workflow) == "authentication_rejected"
                    # A login failure must not accidentally satisfy this expiry test.
                    assert entered
                    assert caught.value.receipt["context_closed"] is True
                    assert not caught.value.receipt["authentication_verified"]
                    assert not caught.value.receipt["qa_completed"]
            finally:
                await browser.close()
    asyncio.run(scenario())
