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
    assert finding["evidence"]["attacker_returned_object_ids"] == [owner_vehicle_id]
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
