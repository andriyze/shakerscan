"""Compatibility contracts for the connected-device product boundary."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import api as api_module  # noqa: E402
import worker  # noqa: E402


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


def test_device_postprocessing_keeps_review_findings_out_of_allow_and_block():
    result = {
        "result": {},
        "findings": [{
            "tool": "device_policy",
            "severity": "high",
            "evidence": {"disposition": "review"},
        }],
        "device_posture": {
            "completeness": {"complete": True, "web_probe_truncated": False},
            "web_dast_children": {"failed": 0, "truncated": 0},
            "decision": {},
        },
    }
    worker._device_score_with_web_findings(result)
    assert result["device_posture"]["decision"]["decision"] == "needs_review"

    result["findings"][0]["evidence"]["disposition"] = "deny"
    result["findings"][0]["severity"] = "low"
    worker._device_score_with_web_findings(result)
    assert result["device_posture"]["decision"]["decision"] == "block"


def test_device_uncertainty_requires_review_without_score_penalty():
    result = {
        "result": {},
        "findings": [],
        "device_posture": {
            "completeness": {
                "complete": False,
                "execution_complete": True,
                "uncertainty_present": True,
                "web_probe_truncated": False,
            },
            "web_dast_children": {"failed": 0, "truncated": 0},
            "decision": {},
        },
    }
    worker._device_score_with_web_findings(result)
    assert result["result"] == {"score": 100, "grade": "A"}
    assert result["device_posture"]["decision"]["decision"] == "needs_review"


def test_device_unconfirmed_reachability_never_gets_a_score():
    result = {
        "result": {"score": 100, "grade": "A"},
        "findings": [],
        "device_posture": {
            "reachability": {
                "status": "inconclusive",
                "reason": "No direct device response was received.",
            },
            "completeness": {"complete": False, "execution_complete": False},
            "decision": {},
        },
    }

    worker._device_score_with_web_findings(result)

    assert result["result"] == {"score": None, "grade": None}
    assert result["device_posture"]["decision"] == {
        "decision": "needs_review",
        "rationale": "No direct device response was received.",
    }
