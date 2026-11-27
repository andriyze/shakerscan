"""Real loopback requests proving credentials cannot follow a broader host scope."""

import asyncio

import pytest

from capabilities.http import execute_bound_http_request
from runtime.models import TargetBinding


@pytest.mark.parametrize("identity,scheme", [(value, "http") for value in
    ("bearer", "custom_header", "cookie", "response_cookie", "anonymous")] + [("bearer", "https")])
def test_bound_cross_origin_redirect_does_not_disclose_identity(identity, scheme):
    async def exercise():
        calls = [0, 0]
        identity_received = []
        destinations = []

        async def destination(reader, writer):
            calls[1] += 1
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        async with await asyncio.start_server(destination, "127.0.0.1", 0) as second:
            destinations.append(f"{scheme}://127.0.0.1:{second.sockets[0].getsockname()[1]}")

            async def origin(reader, writer):
                request = await reader.readuntil(b"\r\n\r\n")
                identity_received.append(b"synthetic-secret" in request)
                calls[0] += 1
                cookie = "Set-Cookie: session=synthetic-response-secret; Path=/\r\n" if identity == "response_cookie" else ""
                writer.write((f"HTTP/1.1 302 Found\r\nLocation: {destinations[0]}/finish\r\n"
                              f"{cookie}Content-Length: 0\r\nConnection: close\r\n\r\n").encode())
                await writer.drain()
                writer.close()
                await writer.wait_closed()

            async with await asyncio.start_server(origin, "127.0.0.1", 0) as first:
                origin_url = f"http://127.0.0.1:{first.sockets[0].getsockname()[1]}"
                target = TargetBinding(target_id="fixture", target_kind="web", canonical_host="127.0.0.1",
                    allowed_origins=(origin_url, destinations[0]), allowed_addresses=("127.0.0.1",), environment="lab")
                headers = {"Authorization": "Bearer synthetic-secret"} if identity == "bearer" else (
                    {"X-Application-Key": "synthetic-secret"} if identity == "custom_header" else {})
                result = await execute_bound_http_request(origin_url, {"method": "GET", "path": "/start", "follow_redirects": True},
                    target=target, trusted_headers=headers, allow_identity_headers=True,
                    cookies={"session": "synthetic-secret"} if identity == "cookie" else None,
                    allow_bound_origin_redirects=True)
                assert calls[0] == 1
                assert identity_received == [identity in {"bearer", "custom_header", "cookie"}]
                assert calls[1] == (1 if identity == "anonymous" else 0)
                if identity != "anonymous":
                    assert result["redirect_chain"][-1]["stopped"] == "credential_destination"
    asyncio.run(exercise())


@pytest.mark.parametrize("field", ["path", "form_page"])
@pytest.mark.parametrize("escape", ["/http://127.0.0.1:{port}/admin", "/https://127.0.0.1:{port}/admin",
                                    "/HTTP://127.0.0.1:{port}/admin"])
def test_a_path_naming_an_absolute_url_never_leaves_the_bound_origin(field, escape):
    """A path whose first segment names a scheme is refused; nothing is sent elsewhere."""
    async def exercise():
        reached = []

        async def answer(tag):
            async def serve(reader, writer):
                await reader.readuntil(b"\r\n\r\n")
                reached.append(tag)
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            return serve

        async with await asyncio.start_server(await answer("bound"), "127.0.0.1", 0) as bound, \
                await asyncio.start_server(await answer("other"), "127.0.0.1", 0) as other:
            origin_url = f"http://127.0.0.1:{bound.sockets[0].getsockname()[1]}"
            hostile = escape.format(port=other.sockets[0].getsockname()[1])
            target = TargetBinding(target_id="fixture", target_kind="web", canonical_host="127.0.0.1",
                allowed_origins=(origin_url,), allowed_addresses=("127.0.0.1",), environment="lab")
            args = {"method": "GET", "path": hostile}
            if field == "form_page":
                args = {"method": "POST", "path": "/login", "form_body": {"user": "a"},
                        "form_prefetch": True, "form_page": hostile}
            result = await execute_bound_http_request(origin_url, args, target=target,
                trusted_headers={"Authorization": "Bearer synthetic-secret"},
                cookies={"session": "synthetic-secret"}, principal_slot="primary", allow_write=True)
            assert "other" not in reached
            assert result["ok"] is False and str(result["error"]).startswith("scope:")
    asyncio.run(exercise())
