"""Regression tests for smart BOLA/IDOR heuristics."""

import asyncio
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from scanner.scanner_tools.access_control_checks import smart_bola_test


def _fake_http_response(url: str, status_code: int, body: str) -> dict:
    return {
        "status_code": status_code,
        "headers": {"content-type": "application/json"},
        "body": body,
        "final_url": url,
        "elapsed_ms": 1.0,
        "error": None,
    }


def _fake_session(token: str) -> SimpleNamespace:
    """Minimal stand-in for AuthSession exposing config/state for build_headers."""
    return SimpleNamespace(
        config=SimpleNamespace(headers={"Authorization": f"Bearer {token}"}, cookies={}),
        state=SimpleNamespace(cookies_received={}),
    )


def test_smart_bola_skips_operational_rate_limit_endpoint(monkeypatch):
    async def should_not_fetch(*args, **kwargs):
        raise AssertionError("Operational endpoint should be skipped before fetch")

    monkeypatch.setattr(
        "scanner.scanner_tools.proof_of_exploit.fetch_with_capture",
        should_not_fetch,
    )

    results = asyncio.run(
        smart_bola_test(
            base_url="https://example.com",
            discovered_urls=["https://example.com/api/rate-limit/?id=2"],
            max_endpoints=10,
            timeout=1,
        )
    )

    assert not results["vulnerable"]
    assert results["findings"] == []
    assert results["endpoints_analyzed"] == 0


def test_smart_bola_flags_unauthenticated_resource_access_once(monkeypatch):
    async def fake_fetch(url, **kwargs):
        path_parts = [part for part in urlsplit(url).path.split("/") if part]
        resource_id = path_parts[-1] if path_parts else "1"
        body = json.dumps(
            {
                "user_id": int(resource_id),
                "email": f"user{resource_id}@example.com",
                "role": "user",
            }
        )
        return _fake_http_response(url, 200, body)

    monkeypatch.setattr(
        "scanner.scanner_tools.proof_of_exploit.fetch_with_capture",
        fake_fetch,
    )

    results = asyncio.run(
        smart_bola_test(
            base_url="https://example.com",
            discovered_urls=["https://example.com/api/users/2"],
            max_endpoints=10,
            timeout=1,
        )
    )

    unauth_findings = [f for f in results["findings"] if "Unauthenticated access" in f.get("title", "")]
    assert results["vulnerable"]
    assert len(unauth_findings) == 1
    assert unauth_findings[0]["evidence"]["successful_count"] >= 2


def test_smart_bola_skips_when_id_parameter_is_ignored(monkeypatch):
    async def fake_fetch(url, **kwargs):
        _ = parse_qs(urlsplit(url).query).get("id", ["1"])[0]
        # Constant payload regardless requested ID.
        body = json.dumps(
            {
                "user_id": 1,
                "email": "current-user@example.com",
            }
        )
        return _fake_http_response(url, 200, body)

    monkeypatch.setattr(
        "scanner.scanner_tools.proof_of_exploit.fetch_with_capture",
        fake_fetch,
    )

    results = asyncio.run(
        smart_bola_test(
            base_url="https://example.com",
            discovered_urls=["https://example.com/api/users?id=7"],
            max_endpoints=10,
            timeout=1,
        )
    )

    assert not results["vulnerable"]
    assert results["findings"] == []


def test_smart_bola_skips_ignored_id_with_volatile_response_fields(monkeypatch):
    call_state = {"n": 0}

    async def fake_fetch(url, **kwargs):
        call_state["n"] += 1
        _ = parse_qs(urlsplit(url).query).get("id", ["1"])[0]
        # Same resource regardless of requested ID, but with per-request
        # values that should not make the ID look response-sensitive.
        body = json.dumps(
            {
                "user_id": 1,
                "email": "current-user@example.com",
                "request_id": f"11111111-1111-4111-8111-{call_state['n']:012d}",
                "generated_at": f"2026-06-03T12:00:{call_state['n']:02d}Z",
            }
        )
        return _fake_http_response(url, 200, body)

    monkeypatch.setattr(
        "scanner.scanner_tools.proof_of_exploit.fetch_with_capture",
        fake_fetch,
    )

    results = asyncio.run(
        smart_bola_test(
            base_url="https://example.com",
            discovered_urls=["https://example.com/api/users?id=7"],
            max_endpoints=10,
            timeout=1,
        )
    )

    assert not results["vulnerable"]
    assert results["findings"] == []


def test_smart_bola_cross_user_equivalent_emits_suspected_lead(monkeypatch):
    # Both users get the SAME user-specific data for a fixed resource, with
    # only a per-request CSRF token differing. Exact equality would miss this;
    # the normalized comparison must flag it as a suspected (not confirmed) BOLA.
    call_state = {"n": 0}

    async def fake_fetch(url, **kwargs):
        call_state["n"] += 1
        body = json.dumps(
            {
                "user_id": 1,
                "email": "alice@acme.io",
                "full_name": "Alice Anderson",
                "csrf_token": f"tok{call_state['n']:024d}",  # volatile, differs per request
            }
        )
        return _fake_http_response(url, 200, body)

    monkeypatch.setattr(
        "scanner.scanner_tools.proof_of_exploit.fetch_with_capture",
        fake_fetch,
    )

    results = asyncio.run(
        smart_bola_test(
            base_url="https://example.com",
            discovered_urls=["https://example.com/api/users/1"],
            user1_session=_fake_session("user1"),
            user2_session=_fake_session("user2"),
            max_endpoints=10,
            timeout=1,
        )
    )

    cross = [f for f in results["findings"] if "Cross-user data access" in f.get("title", "")]
    assert cross, "expected a cross-user BOLA lead"
    finding = cross[0]
    # Emitted as a suspected lead requiring verification, not auto-confirmed.
    assert finding["suspected"] is True
    assert finding["needs_verification"] is True
    assert finding["evidence"]["responses_equivalent"] is True
    assert finding["evidence"]["user_specific_signals"]


def test_smart_bola_cross_user_chrome_only_is_not_flagged(monkeypatch):
    # Both users get an identical generic dashboard page with no user-specific
    # data values — only chrome words. Must NOT flag.
    async def fake_fetch(url, **kwargs):
        body = (
            "<html><nav><a href='/profile'>Profile</a>"
            "<a href='/account'>Account</a></nav>"
            "<main>Welcome to the dashboard</main></html>"
        )
        return _fake_http_response(url, 200, body)

    monkeypatch.setattr(
        "scanner.scanner_tools.proof_of_exploit.fetch_with_capture",
        fake_fetch,
    )

    results = asyncio.run(
        smart_bola_test(
            base_url="https://example.com",
            discovered_urls=["https://example.com/api/users/1"],
            user1_session=_fake_session("user1"),
            user2_session=_fake_session("user2"),
            max_endpoints=10,
            timeout=1,
        )
    )

    cross = [f for f in results["findings"] if "Cross-user data access" in f.get("title", "")]
    assert cross == []


def test_smart_bola_respects_max_seconds_budget(monkeypatch):
    # Regression for the internal graceful-deadline fix: with a tiny overall
    # budget and multiple ID-pattern templates, smart_bola_test must stop the
    # endpoint loop and flag budget_exceeded rather than running unbounded
    # (and without being hard-cancelled, which would discard partial results).
    async def fake_fetch(url, **kwargs):
        body = json.dumps({"user_id": 1, "email": "alice@acme.io"})
        return _fake_http_response(url, 200, body)

    monkeypatch.setattr(
        "scanner.scanner_tools.proof_of_exploit.fetch_with_capture",
        fake_fetch,
    )

    results = asyncio.run(
        smart_bola_test(
            base_url="https://example.com",
            discovered_urls=[
                "https://example.com/api/users/1",
                "https://example.com/api/orders/2",
                "https://example.com/api/items/3",
            ],
            max_endpoints=50,
            timeout=1,
            max_seconds=0.0001,  # effectively already expired
        )
    )

    assert results.get("budget_exceeded") is True


def test_smart_bola_no_budget_runs_to_completion(monkeypatch):
    # Without max_seconds the deadline machinery is inert (no early stop).
    async def fake_fetch(url, **kwargs):
        body = json.dumps({"user_id": 1, "email": "alice@acme.io"})
        return _fake_http_response(url, 200, body)

    monkeypatch.setattr(
        "scanner.scanner_tools.proof_of_exploit.fetch_with_capture",
        fake_fetch,
    )

    results = asyncio.run(
        smart_bola_test(
            base_url="https://example.com",
            discovered_urls=["https://example.com/api/users/1"],
            max_endpoints=5,
            timeout=1,
        )
    )

    assert results.get("budget_exceeded") is False
