"""Behavioural regressions from the 2026-11 Hunt/runtime audit.

Each case failed before its fix: a deadline stop settled as an over-reservation, one hostile
document or value crashed a whole action, or a best-effort side effect replaced a real result.
"""
from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from types import SimpleNamespace

from api.capabilities import auth, recon_active, spec_ingest
from api.capabilities.replay import RecordedReplayTransport
from api.runtime import http_archive, v2_runtime_hardening


def test_recon_wall_time_never_exceeds_the_reserved_deadline():
    # A loop that stops at its 5 s deadline has spent 5 s, not 5 s plus a rounding second.
    started = time.monotonic() - 5.2
    assert recon_active._elapsed(started, 5) == 5
    assert recon_active._elapsed(time.monotonic(), 30) == 1
    assert recon_active._elapsed(time.monotonic() - 2.5, 30) == 3


def test_one_unreadable_spec_document_keeps_the_routes_of_the_others():
    good = json.dumps({"openapi": "3.0.0", "paths": {"/kept": {"get": {}}}}).encode()
    bad_server = json.dumps({
        "openapi": "3.0.0", "servers": [{"url": "http://[x"}], "paths": {"/lost": {"get": {}}},
    }).encode()
    nested = ("[" * 100_000 + "]" * 100_000).encode()
    issues: list[str] = []
    routes = spec_ingest.ingest_spec_bodies(
        [
            ("https://target.example/a.json", bad_server, "application/json"),
            ("https://target.example/b.json", nested, "application/json"),
            ("https://target.example/c.json", good, "application/json"),
        ],
        origin="https://target.example", issues=issues,
    )
    assert [route["url"] for route in routes] == ["https://target.example/kept"]
    assert "spec_invalid_server" in issues


def test_session_timing_survives_a_non_finite_or_deeply_nested_login_answer():
    now = datetime(2026, 11, 9, tzinfo=timezone.utc)
    for body in (b'{"expires_in": 1e999}', b'{"expires_in": NaN}', b"[" * 100_000):
        response = SimpleNamespace(body=lambda body=body: body)
        expires_at, refresh_at = auth._session_timing(response, now=now)
        assert now < refresh_at <= expires_at


def test_a_nameless_header_does_not_drop_the_headers_after_it():
    assert http_archive.normalized_headers({"A": "1", " ": "x", "B": "2"}) == {"a": "1", "b": "2"}


def test_receipt_redaction_survives_a_string_that_is_not_a_parsable_url():
    # urlsplit raises on an unbalanced IPv6 bracket; the inline patterns must still apply.
    assert v2_runtime_hardening._redact_string("http://[oops/path") == "http://[oops/path"


def test_a_failing_archive_recorder_does_not_replace_the_replay_result():
    class Transport:
        async def send(self, request, **kwargs):
            return SimpleNamespace(
                response_headers={}, response_body=b"ok", status_code=200,
                connected_address="192.0.2.1", elapsed_ms=1, error_code=None,
            )

    def recorder(_row):
        raise RuntimeError("archive unavailable")

    transport = RecordedReplayTransport(Transport(), recorder, principal_slot=None)
    request = SimpleNamespace(method="GET", url="https://target.example/", headers={}, body=None)
    assert asyncio.run(transport.send(request)).status_code == 200
