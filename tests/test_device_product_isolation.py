"""Compatibility contracts for the connected-device product boundary."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import api as api_module  # noqa: E402


def test_device_children_are_hidden_from_the_default_scan_list():
    hidden = api_module._hidden_scan_roles_for_list()
    assert api_module.DEVICE_WEB_ORIGIN_ROLE in hidden
    assert api_module.DEVICE_WEB_ORIGIN_ROLE not in api_module._hidden_scan_roles_for_list(include_internal=True)


def test_device_run_kind_is_not_a_web_dast_scan_type():
    assert "device_posture" not in api_module.VALID_DAST_SCAN_TYPES
    assert api_module.VALID_DAST_SCAN_TYPES == {
        "quick", "standard", "deep", "full", "aggressive", "smart",
    }


def test_device_deployment_decision_does_not_fall_through_to_dast():
    decision = api_module.build_deployment_decision({
        "id": "device-scan",
        "status": "completed",
        "run_kind": "device_posture",
        "scan_type": "device_posture",
        "result": {
            "result": {"score": 80, "grade": "B"},
            "findings": [],
            "device_posture": {
                "decision": {
                    "decision": "needs_review",
                    "rationale": "An unexpected service was observed.",
                    "policy_name": "device-default-v1",
                }
            },
        },
    })

    assert decision["product"] == "device_posture"
    assert decision["decision"] == "needs_review"
    assert decision["policy_name"] == "device-default-v1"


def test_device_taxonomy_is_excluded_without_reclassifying_existing_products():
    dast = api_module._source_type_filter_sql("dast")
    assert "device" in dast
    assert api_module._source_type_filter_sql("device") == " AND f.source = 'device'"
