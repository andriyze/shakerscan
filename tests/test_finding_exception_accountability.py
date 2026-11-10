import asyncio
import os
import sys

import pytest
from fastapi import HTTPException


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from finding_exceptions.router import (  # noqa: E402
    FindingExceptionRequest,
    _require_active_policy_profile,
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
    ["target_id", "owner", "approver", "reason", "compensating_controls", "expires_at"],
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


@pytest.mark.parametrize("value", ["next tuesday", "2099-13-45", "never"])
def test_effective_exception_with_an_unparsable_expiry_is_a_422_not_a_500(value):
    # The parser answers None for text it cannot read; comparing None to now() raised TypeError.
    with pytest.raises(HTTPException) as refused:
        _validate_finding_exception_accountability(_effective_request(expires_at=value))
    assert refused.value.status_code == 422
    assert "ISO 8601" in refused.value.detail


class _ProfilesConn:
    """Answers the policy-profile lookups the exception routes make."""

    def __init__(self, active_ids):
        self.active_ids = set(active_ids)

    async def fetchval(self, query, *args):
        assert "FROM policy_profiles" in query and "is_active=true" in query
        return bool(self.active_ids)

    async def fetchrow(self, query, *args):
        assert "FROM policy_profiles" in query
        return {"id": args[0]} if str(args[0]) in self.active_ids else None


def test_accepting_a_risk_needs_no_policy_when_none_is_configured():
    # A fresh install has no policy profile and nobody can create one without the Model
    # Intake operator credential: the exception applies under the built-in release policy.
    request = _effective_request(policy_id=None)
    assert _validate_finding_exception_accountability(request) is not None
    asyncio.run(_require_active_policy_profile(_ProfilesConn([]), request.policy_id))


def test_a_configured_policy_profile_must_be_named_by_the_exception():
    request = _effective_request(policy_id=None)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(_require_active_policy_profile(_ProfilesConn([POLICY_ID]), request.policy_id))
    assert exc.value.status_code == 422
    assert "policy_id" in exc.value.detail
    asyncio.run(_require_active_policy_profile(_ProfilesConn([POLICY_ID]), POLICY_ID))


def test_an_unknown_policy_is_refused_even_without_configured_profiles():
    with pytest.raises(HTTPException) as exc:
        asyncio.run(_require_active_policy_profile(_ProfilesConn([]), POLICY_ID))
    assert "active policy profile" in exc.value.detail


def test_a_revoked_exception_without_policy_needs_no_profile_lookup():
    asyncio.run(_require_active_policy_profile(_ProfilesConn([POLICY_ID]), None, effective=False))


def test_an_unknown_status_is_refused_before_it_reaches_the_check_constraint():
    # The table accepts five statuses; any other used to reach the INSERT and answer 500.
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        FindingExceptionRequest(status="waived")
    for known in ("active", "approved", "accepted_risk", "revoked", "expired"):
        assert FindingExceptionRequest(status=known).status == known
