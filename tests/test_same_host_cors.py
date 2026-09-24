"""The UI works at every address that reaches the same engine, not only the configured one.

The allowlist names one address. A LAN install answered on the private IP the launcher picked,
and the same engine opened by public IP or through a tunnel lost its CORS headers on reads and
answered 403 to every write, so the Request Collections upload failed with "Cross-origin browser
mutation is not allowed" while reads silently returned nothing usable. Only address literals are
admitted, so a rebound DNS name gains nothing; names stay with the operator's configuration.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from public_api_contract import (  # noqa: E402
    SameHostCorsMiddleware,
    UnsafeOriginGuardMiddleware,
    origin_is_same_deployment,
)

CONFIGURED = ("http://localhost:3000", "http://172.31.33.227:3000")


def scope(method="POST", *, origin=None, host=None, extra=None):
    headers = []
    if origin:
        headers.append((b"origin", origin.encode()))
    if host:
        headers.append((b"host", host.encode()))
    for key, value in (extra or {}).items():
        headers.append((key.encode(), value.encode()))
    return {"type": "http", "method": method, "headers": headers}


async def ok_app(_scope, _receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": b"{}"})


async def drive(app, call_scope):
    sent: list[dict] = []

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    await app(call_scope, receive, send)
    return sent


def headers_of(sent):
    start = next(item for item in sent if item["type"] == "http.response.start")
    return {key.decode().lower(): value.decode() for key, value in start["headers"]}


class TestTheSameDeploymentPredicate:
    @pytest.mark.parametrize(("origin", "host"), [
        ("http://172.31.33.227:3000", "172.31.33.227:8080"),
        ("http://18.215.239.210:3000", "18.215.239.210:8080"),
        ("http://127.0.0.1:3000", "127.0.0.1:8080"),
        ("https://192.168.1.165:3000", "192.168.1.165"),
        ("http://[2001:db8::1]:3000", "[2001:db8::1]:8080"),
    ])
    def test_the_ui_on_the_address_this_request_reached(self, origin, host):
        assert origin_is_same_deployment(origin, host) is True

    @pytest.mark.parametrize(("origin", "host"), [
        ("http://evil.test", "172.31.33.227:8080"),
        ("http://172.31.33.227.evil.test:3000", "172.31.33.227:8080"),
        ("http://evil.test", "evil.test.internal:8080"),
        ("null", "172.31.33.227:8080"),
        ("http://172.31.33.227:3000", ""),
        ("http://172.31.33.227:3000", "18.215.239.210:8080"),
    ])
    def test_a_different_site_never_matches(self, origin, host):
        assert origin_is_same_deployment(origin, host) is False

    @pytest.mark.parametrize("name", [
        "evil.test", "shakerscan.local", "box.example.test", "localhost",
    ])
    def test_a_name_never_matches_itself_so_dns_rebinding_gains_nothing(self, name):
        """A page on a name whose DNS is flipped to an internal address would present that
        name as both Origin and Host and match on name equality alone. Only address literals
        are admitted here; names stay with the operator via SHAKERSCAN_CORS_ALLOW_ORIGINS."""
        assert origin_is_same_deployment(f"http://{name}:3000", f"{name}:8080") is False


class TestMutationsFromEveryRouteToTheSameEngine:
    def guard(self):
        return UnsafeOriginGuardMiddleware(
            ok_app, allow_origins=CONFIGURED, allow_origin_regex="",
        )

    def test_the_upload_that_failed_now_reaches_the_endpoint(self):
        sent = asyncio.run(drive(self.guard(), scope(
            origin="http://18.215.239.210:3000", host="18.215.239.210:8080",
        )))
        assert headers_of(sent)["content-type"] == "application/json"
        assert sent[0]["status"] == 200

    def test_a_configured_origin_still_works(self):
        sent = asyncio.run(drive(self.guard(), scope(
            origin="http://172.31.33.227:3000", host="172.31.33.227:8080",
        )))
        assert sent[0]["status"] == 200

    def test_a_cross_site_mutation_is_still_refused(self):
        """A browser sets Host to the address it connected to and cannot forge it, so an
        attacker's page still carries its own Origin against our Host."""
        sent = asyncio.run(drive(self.guard(), scope(
            origin="http://evil.test", host="172.31.33.227:8080",
        )))
        assert sent[0]["status"] == 403
        assert json.loads(sent[1]["body"])["detail"] == (
            "Cross-origin browser mutation is not allowed"
        )

    def test_a_request_without_an_origin_is_untouched(self):
        sent = asyncio.run(drive(self.guard(), scope(host="172.31.33.227:8080")))
        assert sent[0]["status"] == 200


class TestReadsAndPreflightsCarryTheirHeaders:
    def app(self):
        return SameHostCorsMiddleware(ok_app, expose_headers=("x-shakerscan-hunt-contract",))

    def test_a_read_from_the_same_address_is_readable_by_the_browser(self):
        sent = asyncio.run(drive(self.app(), scope(
            "GET", origin="http://18.215.239.210:3000", host="18.215.239.210:8080",
        )))
        headers = headers_of(sent)
        assert headers["access-control-allow-origin"] == "http://18.215.239.210:3000"
        assert headers["vary"] == "Origin"
        assert headers["access-control-expose-headers"] == "x-shakerscan-hunt-contract"

    def test_a_preflight_from_the_same_host_is_answered(self):
        sent = asyncio.run(drive(self.app(), scope(
            "OPTIONS", origin="http://18.215.239.210:3000", host="18.215.239.210:8080",
            extra={
                "access-control-request-method": "POST",
                "access-control-request-headers": "content-type,idempotency-key",
            },
        )))
        headers = headers_of(sent)
        assert sent[0]["status"] == 200
        assert headers["access-control-allow-origin"] == "http://18.215.239.210:3000"
        assert "POST" in headers["access-control-allow-methods"]
        assert headers["access-control-allow-headers"] == "content-type,idempotency-key"

    def test_a_foreign_origin_gets_no_header_from_this_layer(self):
        sent = asyncio.run(drive(self.app(), scope(
            "GET", origin="http://evil.test", host="18.215.239.210:8080",
        )))
        assert "access-control-allow-origin" not in headers_of(sent)

    def test_the_configured_policy_answer_is_never_duplicated(self):
        """Registered outside the configured CORS layer, so whatever it recognised wins."""
        async def already_answered(_scope, _receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": [
                (b"access-control-allow-origin", b"http://18.215.239.210:3000"),
            ]})
            await send({"type": "http.response.body", "body": b""})

        app = SameHostCorsMiddleware(already_answered, expose_headers=("x-a",))
        sent = asyncio.run(drive(app, scope(
            "GET", origin="http://18.215.239.210:3000", host="18.215.239.210:8080",
        )))
        start = next(item for item in sent if item["type"] == "http.response.start")
        allow = [key for key, _v in start["headers"] if key.lower() == b"access-control-allow-origin"]
        assert len(allow) == 1

    def test_a_request_without_an_origin_passes_straight_through(self):
        sent = asyncio.run(drive(self.app(), scope("GET", host="18.215.239.210:8080")))
        assert "access-control-allow-origin" not in headers_of(sent)
