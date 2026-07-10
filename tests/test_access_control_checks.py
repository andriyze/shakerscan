import asyncio
import json
import os
import sys
from types import SimpleNamespace


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

import scanner_tools.access_control_checks as access_control_checks  # noqa: E402
from scanner_tools.access_control_checks import determine_severity  # noqa: E402


def _session(token: str) -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(headers={"Authorization": f"Bearer {token}"}, cookies={}),
        state=SimpleNamespace(cookies_received={}),
    )


def test_forced_browsing_debug_dev_metrics_is_high_not_critical():
    assert determine_severity(200, "debug_dev", "/metrics") == "high"


def test_forced_browsing_sensitive_files_and_admin_stay_critical():
    assert determine_severity(200, "sensitive_files", "/.env") == "critical"
    assert determine_severity(200, "admin_panels", "/admin") == "critical"


def test_forced_browsing_accepts_prometheus_metrics_body(monkeypatch):
    async def fake_spa(*args, **kwargs):
        return {"is_spa_catch_all": False}

    async def fake_homepage_hash(*args, **kwargs):
        return None

    async def fake_run(cmd, **kwargs):
        url = cmd[-1]
        if "-I" in cmd:
            return ("200" if url.endswith("/metrics") else "404", "", 0)
        if url.endswith("/metrics"):
            body = "# HELP process_cpu_seconds_total Total user and system CPU time\n# TYPE process_cpu_seconds_total counter\nprocess_cpu_seconds_total 1\n"
            return (body + "\n---CURL_METADATA---\n200|text/plain|120", "", 0)
        return ("\n---CURL_METADATA---\n404|text/plain|0", "", 0)

    monkeypatch.setattr(access_control_checks, "detect_spa_catch_all", fake_spa)
    monkeypatch.setattr(access_control_checks, "fetch_homepage_hash", fake_homepage_hash)
    monkeypatch.setattr(access_control_checks, "run", fake_run)

    result = asyncio.run(access_control_checks.check_forced_browsing(
        "https://app.test",
        categories=["debug_dev"],
        timeout_per_request=1,
    ))

    assert result["vulnerable"] is True
    metrics = next(item for item in result["findings"] if item["path"] == "/metrics")
    assert metrics["severity"] == "high"
    assert metrics["accessible"] is True
    assert metrics["content_type"] == "text/plain"
    assert not metrics.get("content_validation_failed")
    assert metrics.get("proof_type") is None


def test_prometheus_sensitive_exposure_requires_multiple_metric_classes():
    generic = """# HELP process_cpu_seconds_total CPU time
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 1
http_requests_total{status=\"200\"} 10
"""
    assert access_control_checks._prometheus_sensitive_metric_proof(generic, "text/plain") is None

    sensitive = """# HELP service_users_registered Registered users
# TYPE service_users_registered gauge
service_users_registered 12
service_orders_placed_total 8
service_wallet_balance_total 500
service_auth_challenges_total 3
"""
    proof = access_control_checks._prometheus_sensitive_metric_proof(sensitive, "text/plain; version=0.0.4")

    assert proof is not None
    assert proof["proof_type"] == "sensitive_content_exposure"
    assert proof["proof_state"] == "verified"
    assert proof["sensitive_metric_categories"] == ["commerce", "identity", "security"]
    assert "service_wallet_balance_total" in proof["sensitive_metric_names"]

    formatted = access_control_checks.format_findings_for_scanner({
        "findings": [{
            "path": "/observability",
            "url": "https://app.test/observability",
            "status_code": 200,
            "category": "debug_dev",
            "severity": "high",
            "accessible": True,
            **proof,
        }],
    }, "https://app.test")
    assert formatted[0]["evidence"]["proof_type"] == "sensitive_content_exposure"
    assert formatted[0]["evidence"]["sensitive_metric_count"] == proof["sensitive_metric_count"]



def test_authz_guard_rejects_id_ignored_endpoint_returning_own_object():
    """Regression: /rest/saveLoginIp-style endpoints ignore the requested id and
    echo the caller's OWN object. The attacker requested owner id=685 but received
    their own object id=686 -> NOT cross-principal access, must not be confirmed BOLA."""
    from scanner_tools.access_control_checks import _resource_ids_from_response
    attacker_body = '{"id":686,"username":"","email":"shaker.fin2@example.com","role":"customer"}'
    returned = _resource_ids_from_response(attacker_body)
    assert "686" in returned
    # The owner object (685) was NOT received -> guard rejects the BOLA claim.
    assert "685" not in returned

    # Positive control: a genuine cross-principal hit returns the owner's object id.
    owner_body = '{"id":685,"email":"shaker.fin1@example.com","role":"customer"}'
    assert "685" in _resource_ids_from_response(owner_body)


def test_authz_producer_rank_prefers_service_collection_over_query_variants():
    rank = access_control_checks._rank_authz_producer_url

    collection = "https://app.test/workshop/api/shop/orders/all"
    query_variant = "https://app.test/api/v2/user/pictures?id=1"
    compound_resource = "https://app.test/workshop/api/mechanic/mechanic_report"

    assert rank(collection) > rank(query_variant)
    assert rank(compound_resource) >= 60


def test_authz_producer_selection_diversifies_repeated_query_paths():
    urls = [
        "https://app.test/api/v2/user/pictures?id=1",
        "https://app.test/api/v2/user/pictures?username=test",
        "https://app.test/api/v2/user/pictures?email=test@test.com",
        "https://app.test/workshop/api/shop/orders/all",
        "https://app.test/workshop/api/mechanic/mechanic_report",
    ]
    ranked = sorted(urls, key=access_control_checks._rank_authz_producer_url, reverse=True)

    selected = access_control_checks._select_authz_producers(ranked, 3)

    assert "https://app.test/workshop/api/shop/orders/all" in selected
    assert sum("/api/v2/user/pictures" in url for url in selected) == 1
    assert len({access_control_checks._authz_producer_path_key(url) for url in selected}) == 3


def test_authz_resource_refs_extract_vin_identifiers():
    body = json.dumps({"vin": "VINOWNER001", "model": "Corsa", "year": 2020})

    assert "VINOWNER001" in access_control_checks._resource_ids_from_response(body)


def test_authz_consumer_template_replaces_vehicle_vin_placeholder_and_query():
    path_candidate = access_control_checks._replace_discovered_consumer_id(
        "https://app.test/workshop/api/merchant/service_requests/<vehicleVIN>",
        "VINOWNER001",
    )
    query_candidate = access_control_checks._replace_discovered_consumer_id(
        "https://app.test/workshop/api/mechanic/service_report?VIN=",
        "VINOWNER001",
    )

    assert path_candidate["custom_endpoint"] == "GET /workshop/api/merchant/service_requests/VINOWNER001"
    assert query_candidate["custom_endpoint"] == "GET /workshop/api/mechanic/service_report?VIN=VINOWNER001"


def test_authz_resource_replay_detects_write_side_bola(monkeypatch):
    from scanner_tools.access_control_checks import authz_resource_replay_test
    import scanner_tools.proof_of_exploit as poe

    async def fake_fetch(url, method="GET", data=None, headers=None, **kwargs):
        principal = "user2" if headers and headers.get("Authorization") == "Bearer user2" else "user1"
        if url.endswith("/api/orders") and method == "GET":
            if principal == "user1":
                body = [{"id": 101, "email": "owner@example.test", "amount": 25}]
            else:
                body = [{"id": 202, "email": "attacker@example.test", "amount": 10}]
            return {"status_code": 200, "headers": {"content-type": "application/json"}, "body": json.dumps(body)}
        if url.endswith("/api/orders/101") and method == "GET":
            if principal == "user1":
                return {
                    "status_code": 200,
                    "headers": {"content-type": "application/json"},
                    "body": json.dumps({"id": 101, "email": "owner@example.test", "amount": 25}),
                }
            return {"status_code": 403, "headers": {"content-type": "application/json"}, "body": '{"error":"forbidden"}'}
        if url.endswith("/api/orders/101") and method == "PATCH":
            assert data == "{}"
            assert headers["Content-Type"] == "application/json"
            return {
                "status_code": 200,
                "headers": {"content-type": "application/json"},
                "body": json.dumps({"id": 101, "email": "owner@example.test", "amount": 25, "status": "unchanged"}),
            }
        return {"status_code": 404, "headers": {"content-type": "application/json"}, "body": "{}"}

    monkeypatch.setattr(poe, "fetch_with_capture", fake_fetch)

    result = asyncio.run(authz_resource_replay_test(
        "https://app.test",
        ["/api/orders"],
        _session("user1"),
        _session("user2"),
        max_producers=1,
        max_replays=4,
    ))

    assert result["vulnerable"] is True
    assert result["write_replays_attempted"] == 1
    assert result["write_replays_completed"] == 1
    assert result["write_cross_principal_violations"] == 1
    finding = next(f for f in result["findings"] if f["id"].startswith("smart_authz_write:"))
    assert finding["severity"] == "critical"
    assert finding["evidence"]["proof_type"] == "write_cross_principal_replay"
    assert finding["evidence"]["requested_object_id"] == "101"
    assert finding["evidence"]["attacker_returned_object_ids"] == ["101"]
    assert any(
        attempt["proof_type"] == "write_cross_principal_replay"
        and attempt["method"] == "PATCH"
        and attempt["status"] == "completed"
        for attempt in result["endpoint_attempts"]
    )


def test_authz_resource_replay_uses_discovered_consumer_templates(monkeypatch):
    from scanner_tools.access_control_checks import authz_resource_replay_test
    import scanner_tools.proof_of_exploit as poe

    owner_vehicle_id = "vehOWNER101"
    attacker_vehicle_id = "vehATTACK202"

    async def fake_fetch(url, method="GET", data=None, headers=None, **kwargs):
        principal = "user2" if headers and headers.get("Authorization") == "Bearer user2" else "user1"
        if url.endswith("/identity/api/v2/vehicle/vehicles?vehicle_id=1"):
            if principal == "user1":
                body = [{"vehicle_id": owner_vehicle_id, "vin": "VIN-OWNER-1"}]
            else:
                body = [{"vehicle_id": attacker_vehicle_id, "vin": "VIN-ATTACKER-2"}]
            return {"status_code": 200, "headers": {"content-type": "application/json"}, "body": json.dumps(body)}
        if url.endswith(f"/identity/api/v2/vehicle/{owner_vehicle_id}/location"):
            body = {"vehicle_id": owner_vehicle_id, "vin": "VIN-OWNER-1", "latitude": 51.5, "longitude": -0.1}
            return {"status_code": 200, "headers": {"content-type": "application/json"}, "body": json.dumps(body)}
        return {"status_code": 404, "headers": {"content-type": "application/json"}, "body": "{}"}

    monkeypatch.setattr(poe, "fetch_with_capture", fake_fetch)

    result = asyncio.run(authz_resource_replay_test(
        "https://crapi.test",
        [
            "/identity/api/v2/vehicle/vehicles?vehicle_id=1",
            "/identity/api/v2/vehicle/<vehicleId>/location",
        ],
        _session("user1"),
        _session("user2"),
        max_producers=2,
        max_replays=8,
    ))

    assert result["vulnerable"] is True
    assert result["consumer_template_count"] == 2
    assert result["cross_principal_violations"] == 1
    finding = next(f for f in result["findings"] if f["id"].startswith("smart_authz:"))
    assert finding["evidence"]["consumer_endpoint"] == f"GET /identity/api/v2/vehicle/{owner_vehicle_id}/location"
    assert finding["evidence"]["requested_object_id"] == owner_vehicle_id
    assert owner_vehicle_id in finding["evidence"]["attacker_returned_object_ids"]
    assert any(
        attempt["consumer_endpoint"] == f"GET /identity/api/v2/vehicle/{owner_vehicle_id}/location"
        and attempt["status"] == "completed"
        for attempt in result["endpoint_attempts"]
    )


def test_authz_write_replay_rejects_id_ignored_own_object(monkeypatch):
    from scanner_tools.access_control_checks import authz_resource_replay_test
    import scanner_tools.proof_of_exploit as poe

    async def fake_fetch(url, method="GET", data=None, headers=None, **kwargs):
        principal = "user2" if headers and headers.get("Authorization") == "Bearer user2" else "user1"
        if url.endswith("/api/orders") and method == "GET":
            body = [{"id": 101, "email": "owner@example.test"}] if principal == "user1" else [{"id": 202, "email": "attacker@example.test"}]
            return {"status_code": 200, "headers": {"content-type": "application/json"}, "body": json.dumps(body)}
        if url.endswith("/api/orders/101") and method == "GET":
            if principal == "user1":
                return {"status_code": 200, "headers": {"content-type": "application/json"}, "body": '{"id":101,"email":"owner@example.test"}'}
            return {"status_code": 403, "headers": {"content-type": "application/json"}, "body": '{"error":"forbidden"}'}
        if url.endswith("/api/orders/101") and method == "PATCH":
            return {
                "status_code": 200,
                "headers": {"content-type": "application/json"},
                "body": json.dumps({"id": 202, "email": "attacker@example.test"}),
            }
        return {"status_code": 404, "headers": {"content-type": "application/json"}, "body": "{}"}

    monkeypatch.setattr(poe, "fetch_with_capture", fake_fetch)

    result = asyncio.run(authz_resource_replay_test(
        "https://app.test",
        ["/api/orders"],
        _session("user1"),
        _session("user2"),
        max_producers=1,
        max_replays=4,
    ))

    assert result["write_replays_attempted"] == 1
    assert result["write_cross_principal_violations"] == 0
    assert not any(f["id"].startswith("smart_authz_write:") for f in result["findings"])
    assert any(
        attempt.get("proof_type") == "write_cross_principal_replay"
        and attempt.get("last_verdict") == "owner_object_not_confirmed_in_write_response"
        for attempt in result["endpoint_attempts"]
    )


def test_debug_dev_json_catch_all_is_not_flagged_but_real_signatures_are():
    """A JSON catch-all body with one loose token must not validate as a debug endpoint,
    while a real actuator/prometheus signature still does."""
    hcc = access_control_checks._has_category_content
    # Single generic token in a plain JSON body -> not a debug endpoint (was a false HIGH).
    ok, _ = hcc('{"status":"ok"}', "application/json", "debug_dev")
    assert ok is False
    ok, _ = hcc('{"total_count":0}', "application/json", "debug_dev")
    assert ok is False
    # Real Spring actuator health (strong "components":) -> valid.
    ok, reason = hcc('{"status":"UP","components":{"db":{"status":"UP"}}}', "application/json", "debug_dev")
    assert ok is True
    # Prometheus metrics (strong "# HELP"/"# TYPE") -> valid.
    ok, _ = hcc("# HELP x total\n# TYPE x counter\nx 1\n", "text/plain", "debug_dev")
    assert ok is True
    # Two generic tokens together still validate (genuine actuator-ish body).
    ok, _ = hcc('{"status":"UP","health":"OK"}', "application/json", "debug_dev")
    assert ok is True
