"""Regression coverage for the public authenticated-assurance read projection."""

from uuid import uuid4

from authenticated_assurance.evaluation import scan_authentication_summary
from authenticated_assurance.router import _health_observations


class Row(dict):
    pass


def _receipt(state="valid", reason="identity_confirmed"):
    return {
        "observations": [{
            "kind": "authentication_health",
            "record": {
                "profile_id": str(uuid4()),
                "state": state,
                "reason_code": reason,
                "checked_at": "2026-09-16T18:00:00+00:00",
                "valid_until": "2026-09-16T18:05:00+00:00" if state == "valid" else None,
                "identity_matched": state == "valid",
                "role_matched": None,
            },
        }],
    }


def test_durable_health_receipt_projects_sampled_coverage_without_response_material():
    receipt = _receipt()
    receipt["observations"].append({"kind": "http_response", "body": "must-not-project"})
    receipt["private"] = "must-not-project"
    observations = _health_observations([Row(receipt_json=receipt)])
    summary = scan_authentication_summary({}, health_observations=observations)
    assert summary["coverage"] == "sampled"
    assert summary["reason_code"] == "sampled_identity_confirmed"
    assert summary["health_sample_count"] == 1
    assert summary["continuous_authentication_proven"] is False
    assert "must-not-project" not in str(summary)


def test_durable_uncertain_health_receipt_projects_partial_gap():
    observations = _health_observations([
        Row(receipt_json=_receipt("unknown", "access_denied")),
    ])
    summary = scan_authentication_summary({}, health_observations=observations)
    assert summary["coverage"] == "partial"
    assert summary["reason_code"] == "authentication_gap"
    assert summary["uncertain_health_sample_count"] == 1


def test_malformed_and_non_health_receipts_are_ignored():
    observations = _health_observations([
        Row(receipt_json={"observations": [{"kind": "http_response", "status": 200}]}),
        Row(receipt_json={"observations": [{"kind": "authentication_health", "record": "bad"}]}),
        Row(receipt_json={}),
    ])
    assert observations == ()
