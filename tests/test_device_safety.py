import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import device_safety  # noqa: E402


def test_safety_profiles_keep_coverage_independent_and_fail_closed():
    catalog = {item["name"]: item for item in device_safety.safety_profile_catalog()}
    assert catalog["observe_only"]["available"] is True
    assert catalog["safe_remote"]["available"] is True
    assert catalog["authenticated_active"]["available"] is False
    assert catalog["lab_invasive"]["available"] is False
    assert catalog["observe_only"]["allowed_action_classes"] == ("readonly",)

    observe = device_safety.DeviceSafetyGovernor(device_safety.SAFETY_PROFILES["observe_only"])
    assert observe.authorize("inventory", "readonly")["allowed"] is True
    with pytest.raises(PermissionError, match="ephemeral_state is forbidden"):
        observe.authorize("control_probe", "ephemeral_state")

    safe = device_safety.DeviceSafetyGovernor(device_safety.SAFETY_PROFILES["safe_remote"])
    assert safe.authorize("bounded_pairing_probe", "ephemeral_state")["allowed"] is True


def test_safety_request_rejects_misleading_or_unavailable_modes():
    with pytest.raises(ValueError, match="not Web DAST children"):
        device_safety.validate_safety_request({
            "safety_profile": "observe_only",
            "include_web_dast": True,
        })
    with pytest.raises(ValueError, match="authenticated_device_collector_not_ready"):
        device_safety.validate_safety_request({"safety_profile": "authenticated_active"})
    assert device_safety.validate_safety_request({
        "safety_profile": "safe-remote",
        "include_web_dast": True,
    }).name == "safe_remote"


def test_health_degradation_halts_future_actions_after_a_healthy_checkpoint():
    governor = device_safety.DeviceSafetyGovernor(device_safety.SAFETY_PROFILES["safe_remote"])
    governor.record_health({"stage": "post_inventory", "status": "healthy"})
    governor.record_health({"stage": "final", "status": "degraded"})
    assert governor.halted is True
    assert governor.receipt()["halt_reason"] == "device health degraded at final"
    with pytest.raises(PermissionError, match="device health degraded"):
        governor.authorize("another_probe", "readonly")
