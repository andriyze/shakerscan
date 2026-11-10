"""Behavioural regressions from the 2026-11 Hunt/runtime audit.

Each case failed before its fix: a deadline stop settled as an over-reservation, one hostile
document or value crashed a whole action, or a best-effort side effect replaced a real result.
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

from api.capabilities import auth, recon_active, spec_ingest
from api.capabilities.browser import BrowserInteractAdapter, _browser_result
from api.capabilities.network import PortsDiscoverAdapter
from api.capabilities.replay import RecordedReplayTransport
from api.finding_routes import router as finding_router
from api.runtime import http_archive, v2_runtime_hardening
from api.runtime.models import TargetBinding


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


def test_a_navigation_that_used_its_whole_timeout_settles_as_the_reservation():
    # The clock starts before proxy and browser launch, which the reservation does not cover.
    target = TargetBinding(
        target_id="target-1", target_kind="web", canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",), allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",), scope_receipt_id="scope-1",
    )
    prepared = BrowserInteractAdapter.prepare(
        target=target, base_url="https://app.example.test",
        args={"steps": [{"action": "click", "selector": "#tab"}], "timeout_ms": 1_000, "max_requests": 5},
    )
    reserved = prepared.estimated_budget["tool_wall_seconds"]
    settled = _browser_result(
        prepared, status="partial", request_count=1, browser_actions=1,
        started=time.monotonic() - (reserved + 0.4), observations=[], blocked=[],
        errors=("navigation_timeout",), timed_out=True,
    )
    assert settled.actual_budget["tool_wall_seconds"] == reserved


def test_a_port_scan_line_that_is_not_an_object_is_one_malformed_record():
    parsed = PortsDiscoverAdapter().parse('[1, 2]\n"text"\n{"ip": "192.0.2.7", "port": 443}\n')
    assert [(row["address"], row["port"]) for row in parsed.observations] == [("192.0.2.7", 443)]
    assert parsed.partial and len(parsed.errors) == 2


def test_deleting_an_approved_finding_reaches_the_deletion(monkeypatch):
    # The route used a helper it never imported, so every approved delete raised NameError.
    import importlib

    finding, preview, receipt = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    seen: dict[str, object] = {}

    async def execute(pool, preview_id, approval_receipt_id, **kwargs):
        seen.update(pool=pool, preview_id=preview_id, approval_receipt_id=approval_receipt_id, **kwargs)
        return {"deleted": 1}

    # The route imports the service under whichever API import layout the process uses.
    for name in ("data_lifecycle.service", "api.data_lifecycle.service"):
        try:
            monkeypatch.setattr(importlib.import_module(name), "execute", execute)
        except ModuleNotFoundError:
            pass
    monkeypatch.setattr(finding_router, "_pool", lambda: "pool")
    answer = asyncio.run(finding_router.delete_finding(
        str(finding), scan_id=None, preview_id=preview, approval_receipt_id=receipt,
    ))
    assert answer == {"deleted": 1, "id": str(finding)}
    assert seen == {
        "pool": "pool", "preview_id": preview, "approval_receipt_id": receipt,
        "kind": "findings", "entity_id": finding, "selection": None,
    }
