import os
import sys

import pytest
from fastapi import HTTPException


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from finding_exceptions.router import (  # noqa: E402
    FindingExceptionRequest,
    _validate_finding_exception_accountability,
)


POLICY_ID = "11111111-1111-4111-8111-111111111111"
TARGET_ID = "22222222-2222-4222-8222-222222222222"


def _effective_request(**overrides):
    payload = {
        "policy_id": POLICY_ID,
        "target_id": TARGET_ID,
        "owner": "service owner",
        "approver": "security approver",
        "reason": "Temporary acceptance during a bounded rollout",
        "compensating_controls": "Alerting and route-level deny rule",
        "status": "active",
        "expires_at": "2099-01-01T00:00:00Z",
    }
    payload.update(overrides)
    return FindingExceptionRequest(**payload)


@pytest.mark.parametrize(
    "field",
    ["policy_id", "target_id", "owner", "approver", "reason", "compensating_controls", "expires_at"],
)
def test_effective_exception_requires_every_accountability_field(field):
    request = _effective_request(**{field: None})

    with pytest.raises(HTTPException) as exc:
        _validate_finding_exception_accountability(request)

    assert exc.value.status_code == 422
    assert field in exc.value.detail


def test_effective_exception_requires_future_expiry():
    request = _effective_request(expires_at="2020-01-01T00:00:00Z")

    with pytest.raises(HTTPException) as exc:
        _validate_finding_exception_accountability(request)

    assert "future" in exc.value.detail


def test_effective_exception_accepts_exact_scoped_complete_record():
    expires_at = _validate_finding_exception_accountability(_effective_request())

    assert expires_at is not None
    assert expires_at.year == 2099


def test_revoked_exception_does_not_require_active_waiver_fields():
    assert _validate_finding_exception_accountability(
        FindingExceptionRequest(status="revoked")
    ) is None
