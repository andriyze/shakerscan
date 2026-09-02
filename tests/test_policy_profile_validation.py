import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from policy_profiles.router import (  # noqa: E402
    PolicyProfileRequest,
    _validate_policy_profile_request,
)
from fastapi import HTTPException  # noqa: E402


def test_dast_profile_rejects_model_intake_only_controls():
    request = PolicyProfileRequest(
        name="DAST production",
        product_area="dast",
        strict_model_intake=True,
    )

    with pytest.raises(HTTPException) as exc:
        _validate_policy_profile_request(request)

    assert exc.value.status_code == 422
    assert "only valid for model_intake" in exc.value.detail


def test_non_strict_profile_rejects_model_intake_trust_anchors():
    request = PolicyProfileRequest(
        name="Advisory intake",
        product_area="model_intake",
        strict_model_intake=False,
        required_trust_anchor_ids=["11111111-1111-4111-8111-111111111111"],
    )

    with pytest.raises(HTTPException) as exc:
        _validate_policy_profile_request(request)

    assert "require a strict model_intake" in exc.value.detail


def test_product_applicable_policy_profile_is_accepted():
    request = PolicyProfileRequest(
        name="DAST production",
        product_area="dast",
        minimum_block_severity="high",
        strict_model_intake=False,
    )

    _validate_policy_profile_request(request)
