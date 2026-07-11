"""Regression tests for smart BOLA/IDOR heuristics."""

import asyncio
import json
import sys
from types import SimpleNamespace
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

_SCANNER_DIR = Path(__file__).resolve().parents[1] / "scanner"
if str(_SCANNER_DIR) not in sys.path:
    sys.path.insert(0, str(_SCANNER_DIR))

from scanner_tools.access_control_checks import (
    _looks_like_bola_resource_response,
    authz_resource_replay_test,
    smart_bola_test,
)


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


def _auth_token(headers: dict | None) -> str:
    auth = (headers or {}).get("Authorization") or ""
    return auth.replace("Bearer ", "")


def test_bola_resource_heuristic_recognizes_juice_shop_address_resource():
    body = json.dumps({"id": 7, "fullName": "Alice", "mobileNum": "1234567890"})

    assert _looks_like_bola_resource_response("https://shop.test/api/Addresss/7", body) is True


def test_bola_resource_heuristic_recognizes_crapi_vehicle_resource():
    body = json.dumps({"id": 2, "vin": "VIN123", "model": "Corsa", "year": 2020})

    assert _looks_like_bola_resource_response("https://crapi.test/identity/api/v2/vehicle/2", body) is True


def test_smart_bola_skips_operational_rate_limit_endpoint(monkeypatch):
    async def should_not_fetch(*args, **kwargs):
        raise AssertionError("Operational endpoint should be skipped before fetch")

    monkeypatch.setattr(
        "scanner_tools.proof_of_exploit.fetch_with_capture",
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
        "scanner_tools.proof_of_exploit.fetch_with_capture",
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
    assert results["endpoint_attempts"]
    attempt = results["endpoint_attempts"][0]
    assert attempt["family"] == "bola"
    assert attempt["custom_endpoint"] == "GET /api/users/2"
    assert attempt["status"] == "completed"
    assert attempt["attempted_params_count"] == attempt["completed_params_count"]


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
        "scanner_tools.proof_of_exploit.fetch_with_capture",
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
        "scanner_tools.proof_of_exploit.fetch_with_capture",
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
        "scanner_tools.proof_of_exploit.fetch_with_capture",
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
    assert any(a.get("family") == "bola" for a in results["endpoint_attempts"])


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
        "scanner_tools.proof_of_exploit.fetch_with_capture",
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


def test_smart_bola_authz_replay_confirms_user1_object_access_by_user2(monkeypatch):
    async def fake_fetch(url, **kwargs):
        token = _auth_token(kwargs.get("headers"))
        path = urlsplit(url).path
        if path == "/api/orders":
            if token == "user1":
                return _fake_http_response(
                    url,
                    200,
                    json.dumps([{"id": 101, "email": "alice@example.com", "amount": 42}]),
                )
            if token == "user2":
                return _fake_http_response(
                    url,
                    200,
                    json.dumps([{"id": 202, "email": "bob@example.com", "amount": 7}]),
                )
            return _fake_http_response(url, 401, json.dumps({"error": "unauthorized"}))
        if path == "/api/orders/101":
            return _fake_http_response(
                url,
                200,
                json.dumps({"id": 101, "email": "alice@example.com", "amount": 42}),
            )
        if path == "/api/orders/202":
            return _fake_http_response(
                url,
                200,
                json.dumps({"id": 202, "email": "bob@example.com", "amount": 7}),
            )
        return _fake_http_response(url, 404, json.dumps({"error": "not found"}))

    monkeypatch.setattr(
        "scanner_tools.proof_of_exploit.fetch_with_capture",
        fake_fetch,
    )

    results = asyncio.run(
        smart_bola_test(
            base_url="https://example.com",
            discovered_urls=["https://example.com/api/orders"],
            user1_session=_fake_session("user1"),
            user2_session=_fake_session("user2"),
            max_endpoints=10,
            timeout=1,
        )
    )

    authz = [f for f in results["findings"] if f.get("tool") == "smart_authz"]
    assert authz, "expected confirmed authz replay finding"
    finding = authz[0]
    assert finding["severity"] == "high"
    assert finding["evidence"]["producer_endpoint"] == "GET /api/orders"
    assert finding["evidence"]["consumer_endpoint"] == "GET /api/orders/101"
    assert finding["evidence"]["source_principal"] == "user1"
    assert finding["evidence"]["attacker_principal"] == "user2"
    assert finding["evidence"]["object_id_absent_from_attacker_listing"] is True
    assert finding["evidence"]["authz_diff"]["replayed_owner_object_missing_from_attacker_listing"] is True
    attempts = [
        a for a in results["endpoint_attempts"]
        if a.get("family") == "authz" and a.get("proof_type") == "cross_principal_replay"
    ]
    assert attempts
    assert attempts[0]["producer_endpoint"] == "GET /api/orders"
    assert attempts[0]["consumer_endpoint"] == "GET /api/orders/101"
    assert attempts[0]["auth_state"] == "user2"
    assert attempts[0]["proof_type"] == "cross_principal_replay"
    assert attempts[0]["status"] == "completed"


def test_authz_replay_maps_listing_suffix_to_item_endpoint(monkeypatch):
    async def fake_fetch(url, **kwargs):
        token = _auth_token(kwargs.get("headers"))
        path = urlsplit(url).path
        if path == "/workshop/api/shop/orders/all":
            if token == "user1":
                return _fake_http_response(
                    url,
                    200,
                    json.dumps({
                        "orders": [
                            {
                                "id": 15,
                                "user": {"email": "alice@example.com"},
                                "transaction_id": "txn-owner",
                            }
                        ]
                    }),
                )
            if token == "user2":
                return _fake_http_response(url, 200, json.dumps({"orders": []}))
            return _fake_http_response(url, 401, json.dumps({"error": "unauthorized"}))
        if path == "/workshop/api/shop/orders/all/15":
            return _fake_http_response(url, 404, json.dumps({"error": "not found"}))
        if path == "/workshop/api/shop/orders/15":
            return _fake_http_response(
                url,
                200,
                json.dumps({
                    "order": {
                        "id": 15,
                        "user": {"email": "alice@example.com"},
                        "transaction_id": "txn-owner",
                    },
                    "payment": {
                        "order_id": 15,
                        "card_owner_name": "Alice",
                        "card_number": "XXXXXXXXXXXX5159",
                    },
                }),
            )
        return _fake_http_response(url, 404, json.dumps({"error": "not found"}))

    monkeypatch.setattr(
        "scanner_tools.proof_of_exploit.fetch_with_capture",
        fake_fetch,
    )

    results = asyncio.run(
        smart_bola_test(
            base_url="https://example.com",
            discovered_urls=["https://example.com/workshop/api/shop/orders/all"],
            user1_session=_fake_session("user1"),
            user2_session=_fake_session("user2"),
            max_endpoints=10,
            timeout=1,
        )
    )

    authz = [f for f in results["findings"] if f.get("tool") == "smart_authz"]
    assert authz, "expected listing producer to replay against item endpoint"
    assert authz[0]["evidence"]["producer_endpoint"] == "GET /workshop/api/shop/orders/all"
    assert authz[0]["evidence"]["consumer_endpoint"] == "GET /workshop/api/shop/orders/15"
    assert authz[0]["severity"] == "high"


def test_authz_replay_uses_vin_identifiers_and_vehicle_placeholders(monkeypatch):
    async def fake_fetch(url, **kwargs):
        token = _auth_token(kwargs.get("headers"))
        path = urlsplit(url).path
        if path == "/identity/api/v2/vehicle/vehicles":
            if token == "user1":
                return _fake_http_response(
                    url,
                    200,
                    json.dumps([{"vin": "VINOWNER001", "model": "Corsa", "year": 2020}]),
                )
            if token == "user2":
                return _fake_http_response(
                    url,
                    200,
                    json.dumps([{"vin": "VINATTACK002", "model": "Focus", "year": 2021}]),
                )
            return _fake_http_response(url, 401, json.dumps({"error": "unauthorized"}))
        if path == "/workshop/api/merchant/service_requests/VINOWNER001":
            return _fake_http_response(
                url,
                200,
                json.dumps({
                    "vin": "VINOWNER001",
                    "email": "alice@example.com",
                    "service_status": "ready",
                }),
            )
        return _fake_http_response(url, 404, json.dumps({"error": "not found"}))

    monkeypatch.setattr(
        "scanner_tools.proof_of_exploit.fetch_with_capture",
        fake_fetch,
    )

    results = asyncio.run(
        smart_bola_test(
            base_url="https://example.com",
            discovered_urls=[
                "https://example.com/identity/api/v2/vehicle/vehicles",
                "https://example.com/workshop/api/merchant/service_requests/<vehicleVIN>",
            ],
            user1_session=_fake_session("user1"),
            user2_session=_fake_session("user2"),
            max_endpoints=10,
            timeout=1,
        )
    )

    authz = [f for f in results["findings"] if f.get("tool") == "smart_authz"]
    assert authz, "expected VIN object replay to prove BOLA"
    assert authz[0]["evidence"]["object_id_key"] == "vin"
    assert authz[0]["evidence"]["requested_object_id"] == "VINOWNER001"
    assert authz[0]["evidence"]["consumer_endpoint"] == "GET /workshop/api/merchant/service_requests/VINOWNER001"


def test_authz_replay_prioritizes_owned_resource_producers_over_noise(monkeypatch):
    fetched_paths = []

    async def fake_fetch(url, **kwargs):
        token = _auth_token(kwargs.get("headers"))
        path = urlsplit(url).path
        fetched_paths.append(path)
        if path == "/api/orders":
            if token == "user1":
                return _fake_http_response(
                    url,
                    200,
                    json.dumps([{"id": 101, "email": "alice@example.com", "amount": 42}]),
                )
            return _fake_http_response(
                url,
                200,
                json.dumps([{"id": 202, "email": "bob@example.com", "amount": 7}]),
            )
        if path == "/api/orders/101":
            return _fake_http_response(
                url,
                200,
                json.dumps({"id": 101, "email": "alice@example.com", "amount": 42}),
            )
        if path == "/api/products":
            return _fake_http_response(url, 200, json.dumps([{"id": 1, "name": "public"}]))
        return _fake_http_response(url, 404, json.dumps({"error": "not found"}))

    monkeypatch.setattr(
        "scanner_tools.proof_of_exploit.fetch_with_capture",
        fake_fetch,
    )

    results = asyncio.run(
        authz_resource_replay_test(
            base_url="https://example.com",
            discovered_urls=[
                "https://example.com/api/products",
                "https://example.com/api/health",
                "https://example.com/api/docs",
                "https://example.com/api/orders",
            ],
            user1_session=_fake_session("user1"),
            user2_session=_fake_session("user2"),
            max_producers=1,
            timeout=1,
        )
    )

    assert results["producer_selection_strategy"] == "owned_resource_path_rank_diverse_v2"
    assert results["producer_candidate_count"] == 1
    assert fetched_paths[:2] == ["/api/orders", "/api/orders"]
    assert [f for f in results["findings"] if f.get("tool") == "smart_authz"]


def test_authz_replay_skips_auth_flow_producers(monkeypatch):
    async def should_not_fetch(*args, **kwargs):
        raise AssertionError("auth/reset producers should be filtered before fetch")

    monkeypatch.setattr(
        "scanner_tools.proof_of_exploit.fetch_with_capture",
        should_not_fetch,
    )

    results = asyncio.run(
        authz_resource_replay_test(
            base_url="https://example.com",
            discovered_urls=[
                "https://example.com/api/v2/user/reset-password",
                "https://example.com/api/auth/login",
                "https://example.com/api/products",
            ],
            user1_session=_fake_session("user1"),
            user2_session=_fake_session("user2"),
            max_producers=10,
            timeout=1,
        )
    )

    assert results["producer_candidate_count"] == 0
    assert results["endpoint_attempts"] == []


def test_smart_bola_authz_replay_skips_object_visible_in_both_listings(monkeypatch):
    async def fake_fetch(url, **kwargs):
        token = _auth_token(kwargs.get("headers"))
        path = urlsplit(url).path
        if path == "/api/projects":
            body = json.dumps([{"id": 101, "name": f"shared-for-{token}"}])
            return _fake_http_response(url, 200, body)
        if path == "/api/projects/101":
            return _fake_http_response(url, 200, json.dumps({"id": 101, "name": "shared"}))
        return _fake_http_response(url, 404, "{}")

    monkeypatch.setattr(
        "scanner_tools.proof_of_exploit.fetch_with_capture",
        fake_fetch,
    )

    results = asyncio.run(
        smart_bola_test(
            base_url="https://example.com",
            discovered_urls=["https://example.com/api/projects"],
            user1_session=_fake_session("user1"),
            user2_session=_fake_session("user2"),
            max_endpoints=10,
            timeout=1,
        )
    )

    assert [f for f in results["findings"] if f.get("tool") == "smart_authz"] == []
    producer_attempts = [
        a for a in results["endpoint_attempts"]
        if a.get("family") == "authz" and a.get("proof_type") == "resource_producer_discovery"
    ]
    replay_attempts = [
        a for a in results["endpoint_attempts"]
        if a.get("family") == "authz" and a.get("proof_type") == "cross_principal_replay"
    ]
    assert producer_attempts
    assert producer_attempts[0]["resource_ids_found"] == 1
    assert replay_attempts == []


def test_smart_bola_authz_records_no_resource_id_producer_telemetry(monkeypatch):
    async def fake_fetch(url, **kwargs):
        return _fake_http_response(url, 200, json.dumps({"message": "ok", "status": "ready"}))

    monkeypatch.setattr(
        "scanner_tools.proof_of_exploit.fetch_with_capture",
        fake_fetch,
    )

    results = asyncio.run(
        smart_bola_test(
            base_url="https://example.com",
            discovered_urls=["https://example.com/api/things"],
            user1_session=_fake_session("user1"),
            user2_session=_fake_session("user2"),
            max_endpoints=10,
            timeout=1,
        )
    )

    attempts = [
        a for a in results["endpoint_attempts"]
        if a.get("family") == "authz" and a.get("proof_type") == "resource_producer_discovery"
    ]
    assert attempts
    assert attempts[0]["status"] == "completed"
    assert attempts[0]["resource_ids_found"] == 0
    assert attempts[0]["skip_reason"] == "no_resource_ids_found"


def test_smart_bola_respects_max_seconds_budget(monkeypatch):
    # Regression for the internal graceful-deadline fix: with a tiny overall
    # budget and multiple ID-pattern templates, smart_bola_test must stop the
    # endpoint loop and flag budget_exceeded rather than running unbounded
    # (and without being hard-cancelled, which would discard partial results).
    async def fake_fetch(url, **kwargs):
        body = json.dumps({"user_id": 1, "email": "alice@acme.io"})
        return _fake_http_response(url, 200, body)

    monkeypatch.setattr(
        "scanner_tools.proof_of_exploit.fetch_with_capture",
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


def test_smart_bola_stops_before_request_when_cancelled(monkeypatch):
    import scanner_tools.access_control_checks as access_control_checks

    monkeypatch.setattr(access_control_checks, "scanner_cancel_requested", lambda: True)

    async def fail_fetch(*args, **kwargs):
        raise AssertionError("BOLA must not issue a request after cancellation")

    monkeypatch.setattr("scanner_tools.proof_of_exploit.fetch_with_capture", fail_fetch)
    results = asyncio.run(
        smart_bola_test(
            base_url="https://example.com",
            discovered_urls=["https://example.com/api/users/1"],
            max_endpoints=5,
            timeout=1,
        )
    )

    assert results["cancelled"] is True
    assert results["budget_exhausted_reason"] == "cancelled"
    assert results["endpoints_analyzed"] == 0


def test_smart_bola_no_budget_runs_to_completion(monkeypatch):
    # Without max_seconds the deadline machinery is inert (no early stop).
    async def fake_fetch(url, **kwargs):
        body = json.dumps({"user_id": 1, "email": "alice@acme.io"})
        return _fake_http_response(url, 200, body)

    monkeypatch.setattr(
        "scanner_tools.proof_of_exploit.fetch_with_capture",
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
