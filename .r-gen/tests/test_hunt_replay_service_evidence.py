"""Real replay observation -> canonical settlement -> shared service projection."""
import json

import pytest

from api.exposure.hunt_service_sources import validated_hunt_source
from api.exposure.service_inventory import build_inventory
from api.runtime.request_replay_executor import ReplayTransportResult, _observation
from scanner_tools.request_replay import ReplayRequest
from tests.test_hunt_service_sources import NOW, TARGET, fixture


def replay_observation(**overrides):
    request = ReplayRequest(
        request_id="captured-request", ordinal=0, name="fixture", folder="",
        method="GET", url=TARGET["locator"] + "/start?token=PRIVATE",
        headers=(("Authorization", "PRIVATE"),), body=b"", body_mode="none",
        auth_type="bearer", has_sensitive_material=True,
    )
    return _observation(request, ReplayTransportResult(**{
        "status_code": 200, "connected_address": "192.0.2.1",
        "final_url": "http://app.example.test:8081/result?token=PRIVATE",
        "response_headers": {"Set-Cookie": "PRIVATE"}, "response_body": b"PRIVATE",
        **overrides,
    }))


def inventory(observation, *, status="completed"):
    row, *_ = fixture(observations=[observation], capability="collections.replay_safe", status=status)
    return build_inventory(TARGET, [validated_hunt_source(row, TARGET)], now=NOW)[0]


def test_real_replay_receipt_enriches_reached_service_not_requested_origin():
    item, = inventory(replay_observation())
    assert item["application_origin"] == "http://app.example.test:8081"
    assert item["address"] == "192.0.2.1" and item["port"] == 8081
    assert item["identity_basis"] == "http_response"
    assert item["presence"] == "observed_open"
    assert item["findings"] == item["cve_candidates"] == []
    assert item["evidence"][0]["hunt_id"]
    assert "PRIVATE" not in json.dumps(item)


@pytest.mark.parametrize("overrides", [
    {"status_code": None, "connected_address": None, "error_code": "timeout", "timed_out": True},
    {"final_url": "https://foreign.example.test"},
    {"connected_address": "192.0.2.9"},
])
def test_no_response_or_unbound_destination_never_invents_a_reached_service(overrides):
    assert inventory(replay_observation(**overrides)) == []


def test_partial_positive_http_response_is_presence_not_complete_coverage():
    item, = inventory(replay_observation(status_code=403), status="partial")
    assert item["presence"] == "observed_open" and item["observation_status"] == "partial"
    assert item["findings"] == []


def test_missing_actual_final_url_does_not_fall_back_to_requested_url():
    item = replay_observation()
    item.pop("final_url")
    assert inventory(item) == []
