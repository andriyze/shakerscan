"""A form sign-in is posted from its own page, with its hidden anti-CSRF field and cookies.

A driven DVWA Hunt sent the right default pair (admin/password) and got the sign-in page back:
DVWA refuses a POST without the page's user_token and the session that issued it.
"""
from __future__ import annotations

import asyncio
import re
import sys
import urllib.parse
from pathlib import Path
from uuid import UUID

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runtime.form_prefetch import hidden_fields  # noqa: E402

PAGE = """<html><form action="search.php" method="get"><input type="hidden" name="q" value="x"></form>
<form action="login.php" method="post"><input type="text" name="username"><input type="password" name="password">
<input type="submit" name="Login" value="Login"><input type="hidden" name="user_token" value="tok-123"></form></html>"""


def test_the_hidden_fields_of_the_form_that_posts_to_the_request_are_taken():
    assert hidden_fields(PAGE, page_url="http://a.test/login.php", post_url="http://a.test/login.php") == {
        "user_token": "tok-123", "Login": "Login"}
    # The request's own field is never replaced (hidden_fields only reports; the client merges).
    assert hidden_fields(PAGE.replace('name="Login"', 'name="go"'), page_url="http://a.test/login.php",
                         post_url="http://a.test/login.php")["go"] == "Login"
    # No form names the action: the page's one password form.
    assert hidden_fields(PAGE.replace('action="login.php"', 'action=""'),
                         page_url="http://a.test/login.php", post_url="http://a.test/session") == {
        "user_token": "tok-123", "Login": "Login"}
    assert hidden_fields("<p>no form</p>", page_url="http://a.test/", post_url="http://a.test/login") == {}


def test_the_engines_client_posts_the_form_with_its_pages_token_and_session():
    from capabilities.http import execute_bound_http_request
    from runtime.models import TargetBinding

    async def scenario():
        seen = []

        async def app(reader, writer):
            head = b""
            while not head.endswith(b"\r\n\r\n"):
                chunk = await reader.read(1)
                if not chunk:
                    break
                head += chunk
            text = head.decode()
            length = int((re.search(r"(?i)content-length: (\d+)", text) or [0, 0])[1])
            body = (await reader.readexactly(length)).decode() if length else ""
            cookie = (re.search(r"(?i)cookie: ([^\r\n]+)", text) or [None, ""])[1]
            seen.append((text.split(" ", 2)[:2], cookie, body))
            if text.startswith("GET"):
                page = PAGE.encode()
                writer.write(b"HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=s3ss10nabcdef; path=/\r\n"
                             b"Content-Type: text/html\r\nContent-Length: %d\r\n\r\n" % len(page) + page)
            else:
                fields = dict(urllib.parse.parse_qsl(body))
                # DVWA acts only when the submit button's field arrives.
                ok = (fields.get("user_token") == "tok-123" and "PHPSESSID=s3ss10nabcdef" in cookie
                      and "Login" in fields)
                writer.write(b"HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\n\r\n"
                             % (b"index.php" if ok else b"login.php"))
            await writer.drain()
            writer.close()

        try:
            server = await asyncio.start_server(app, "127.0.0.1", 0)
        except PermissionError:
            pytest.skip("the unit-test sandbox forbids loopback listeners")
        base = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        target = TargetBinding(target_id=str(UUID(int=2)), target_kind="web", canonical_host="127.0.0.1",
                               allowed_origins=(base,), allowed_addresses=("127.0.0.1",),
                               allowed_root_domains=("127.0.0.1",), environment="lab", scope_receipt_id=str(UUID(int=3)))
        plain = await execute_bound_http_request(
            base, {"method": "POST", "path": "/login.php", "form_body": {"username": "admin", "password": "password"}},
            target=target, allow_write=True)
        prefetched = await execute_bound_http_request(
            base, {"method": "POST", "path": "/login.php", "form_prefetch": True,
                   "form_body": {"username": "admin", "password": "password"}},
            target=target, allow_write=True)
        server.close()
        await server.wait_closed()
        return plain, prefetched, seen

    plain, prefetched, seen = asyncio.run(scenario())
    assert plain["response"]["location"] == "login.php"
    assert prefetched["response"]["location"] == "index.php"
    assert prefetched["form_prefetch"]["hidden_fields"] == ["Login", "user_token"]
    assert prefetched["prefetch_requests"] == 1
    posted = dict(urllib.parse.parse_qsl(seen[-1][2]))
    assert posted["Login"] == "Login" and posted["user_token"] == "tok-123"
    assert "tok-123" not in repr(prefetched)  # the token travels only in the POST


def test_the_recorded_shape_and_the_proofs_replay_keep_the_prefetch():
    from hunt import default_credentials as dc
    from hunt.default_credential_proof import build_request
    from hunt.server_sweep import _default_credential_request

    values = _default_credential_request("/login.php", "username", "password", "dc-01", json_body=False,
                                         form_page="/login.php")
    assert values["form_prefetch"] is True and values["form_page"] == "/login.php"
    assert values["capture"] == [{"name": "session", "header": "Set-Cookie"}]
    assert dc.validate_request_shape(values) == "dc-01"
    shape = dc.request_shape(values, "http://a.test/login.php")
    assert shape["replayable"] and shape["form_prefetch"] is True
    request = build_request(shape, username="admin", secret="password")
    assert request["form_prefetch"] is True and request["form_page"] == "/login.php"
    json_values = _default_credential_request("/api/login", "email", "password", "dc-01", json_body=True)
    assert "form_prefetch" not in json_values and "capture" not in json_values
