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
