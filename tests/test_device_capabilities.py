import os
import sys

import pytest


ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "api"))

import device_capabilities  # noqa: E402


def test_smart_tv_catalog_resolves_evidence_and_platform_without_making_planned_tools_executable():
    result = device_capabilities.capability_catalog_for_device(
        {"id": "device-1", "device_class": "media", "manufacturer": "Example", "model": "Android TV"},
        services=[
            {"transport": "tcp", "port": 22, "state": "open", "service_name": "ssh"},
            {"transport": "tcp", "port": 8443, "state": "open", "service_name": "https", "web_origin": "https://tv:8443"},
        ],
        credential_kinds={"ssh_private_key"},
        completed_capabilities={"tcp-udp-network-discovery"},
    )
    by_id = {item["id"]: item for item in result["items"]}
    assert result["detected_platform"] == "android"
    assert by_id["tcp-udp-network-discovery"]["state"] == "completed"
    assert by_id["ssh-authenticated-host-review"]["state"] == "ready"
    assert by_id["agent-confirmed-ssh-shell"]["state"] == "approval_required"
    assert by_id["android-tv-platform-review"]["state"] == "planned"
    assert by_id["tizen-tv-platform-review"]["state"] == "not_applicable"
    assert by_id["wireless-bluetooth-wifi-direct"]["state"] == "sensor_required"


def test_host_review_capability_fails_closed_without_service_or_credential():
    result = device_capabilities.capability_catalog_for_device(
        {"id": "device-1", "device_class": "media"}, services=[], credential_kinds=set(),
    )
    item = next(item for item in result["items"] if item["id"] == "ssh-authenticated-host-review")
    assert item["state"] == "blocked"
    assert item["blockers"] == ["active_ssh_credential_required", "confirmed_ssh_required"]


def test_only_server_implemented_capabilities_can_be_requested_for_execution():
    assert device_capabilities.validate_executable_capabilities(["ssh-authenticated-host-review", "ssh-authenticated-host-review"]) == ["ssh-authenticated-host-review"]
    assert device_capabilities.validate_executable_capabilities(["agent-confirmed-ssh-shell"]) == ["agent-confirmed-ssh-shell"]
    with pytest.raises(ValueError, match="unsupported executable"):
        device_capabilities.validate_executable_capabilities(["hardware-debug-lab-review"])


def test_vendor_name_alone_does_not_overstate_platform_detection():
    result = device_capabilities.capability_catalog_for_device(
        {"id": "device-1", "device_class": "media", "manufacturer": "Samsung", "model": "Unknown TV"},
        services=[],
    )
    assert result["detected_platform"] is None
    tizen = next(item for item in result["items"] if item["id"] == "tizen-tv-platform-review")
    assert tizen["state"] == "ready"
    assert tizen["implementation"] == "partial"
    assert "platform_not_confirmed" not in tizen["blockers"]
