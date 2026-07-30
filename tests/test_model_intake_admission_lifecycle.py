from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
from model_intake_admissions import record_from_result, triggered_status


def _result(outcome="allow"):
    issued = datetime.now(timezone.utc)
    return {
        "model_intake": {
            "admission": {
                "status": "SIGNED",
                "statement_sha256": "b" * 64,
                "signature": "signature",
                "statement": {
                    "_type": "model-intake-admission/v1",
                    "subject": {"artifact_sha256": "a" * 64, "repository_snapshot_sha256": "c" * 64},
                    "decision": {"outcome": outcome},
                    "policy": {"profile": "production", "version": "v1"},
                    "issued_at": issued.isoformat(),
                    "expires_at": (issued + timedelta(days=90)).isoformat(),
                },
            }
        }
    }


def test_signed_legacy_allow_result_requires_reassessment():
    record = record_from_result(
        scan_id="00000000-0000-4000-8000-000000000001",
        target_id="00000000-0000-4000-8000-000000000002",
        result=_result(),
        reassessment_days=30,
    )

    assert record["status"] == "reassessment_required"
    assert record["schema_version"] == "model-intake-admission/v1"
    assert record["artifact_sha256"] == "a" * 64
    assert record["reassessment_due_at"] < record["expires_at"]


def test_unsigned_or_malformed_package_is_not_registered():
    result = _result()
    result["model_intake"]["admission"]["status"] = "UNSUPPORTED"
    assert record_from_result(scan_id="00000000-0000-4000-8000-000000000001", target_id=None, result=result) is None


def test_unreleased_schema_cannot_become_active_by_label_alone():
    result = _result()
    result["model_intake"]["admission"]["statement"]["_type"] = "model-intake-admission/v2"

    record = record_from_result(
        scan_id="00000000-0000-4000-8000-000000000001",
        target_id=None,
        result=result,
    )

    assert record is None


def test_high_consequence_triggers_revoke_while_normal_changes_require_reassessment():
    assert triggered_status("cve_update") == "reassessment_required"
    assert triggered_status("authorization_incident") == "revoked"
    assert triggered_status("scheduled_review", "revoke") == "revoked"
    with pytest.raises(ValueError):
        triggered_status("made_up")
