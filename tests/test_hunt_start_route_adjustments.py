"""The request boundary and the projection, not just the contract in the middle.

Testing `normalize_hunt_start_payload` alone proved nothing a caller can observe: the typed
request model rejected a fifth skill before the contract saw it, and the adjustments the
contract produced sat three levels inside the context pack where no client read them.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from api.hunt import run_router
from api.hunt.run_router import HuntStartV2Request, apply_standing_authorization
from api.hunt.run_service import public_hunt_run
from api.hunt.start_contract import (
    MAX_DIRECT_ORIGIN_ADDRESSES,
    MAX_SKILLS,
    normalize_hunt_start_payload,
)

TARGET = str(uuid.uuid4())


def request_body(**overrides):
    body = {
        "target_id": TARGET, "target_kind": "web", "goal": "find bugs",
        "policy": {"authorization_confirmed": True, "approval_receipt_id": "receipt-1"},
    }
    body.update(overrides)
    return body


class TestTheTypedRequestModelMatchesTheAuthorityContract:
    """A literal bound here silently became the real limit, so raising the contract's own
    limit changed nothing a caller could observe."""

    def test_the_skill_cap_is_reachable_through_the_request_model(self):
        skills = [f"skill.web-{index:02d}" for index in range(MAX_SKILLS)]
        parsed = HuntStartV2Request.model_validate(request_body(skill_ids=skills))
        assert len(parsed.skill_ids) == MAX_SKILLS
        contract = normalize_hunt_start_payload(
            parsed.model_dump(mode="python", exclude_none=True),
        )
        assert len(contract.skill_ids) == MAX_SKILLS

    def test_one_skill_past_the_cap_is_still_refused(self):
        with pytest.raises(ValidationError):
            HuntStartV2Request.model_validate(request_body(
                skill_ids=[f"skill.web-{index:02d}" for index in range(MAX_SKILLS + 1)],
            ))

    def test_the_direct_origin_cap_is_reachable_through_the_request_model(self):
        addresses = [f"203.0.113.{index + 1}" for index in range(MAX_DIRECT_ORIGIN_ADDRESSES)]
        parsed = HuntStartV2Request.model_validate(request_body(
            direct_origin_addresses=addresses,
            policy={
                "allow_direct_origin": True, "authorization_confirmed": True,
                "approval_receipt_id": "receipt-1",
            },
        ))
        contract = normalize_hunt_start_payload(
            parsed.model_dump(mode="python", exclude_none=True),
        )
        assert len(contract.direct_origin_addresses) == MAX_DIRECT_ORIGIN_ADDRESSES
        assert contract.policy.active_testing is True

    def test_one_address_past_the_cap_is_still_refused(self):
        with pytest.raises(ValidationError):
            HuntStartV2Request.model_validate(request_body(
                direct_origin_addresses=[
                    f"203.0.113.{index + 1}"
                    for index in range(MAX_DIRECT_ORIGIN_ADDRESSES + 1)
                ],
            ))

    @pytest.mark.parametrize("authority", [
        "allow_state_changing_http", "network_discovery", "allow_oob_interactions",
        "allow_identity_headers",
    ])
    def test_a_sub_authority_survives_the_request_model_and_implies_active_testing(
        self, authority,
    ):
        parsed = HuntStartV2Request.model_validate(request_body(policy={
            authority: True, "authorization_confirmed": True,
            "approval_receipt_id": "receipt-1",
        }))
        contract = normalize_hunt_start_payload(
            parsed.model_dump(mode="python", exclude_none=True),
        )
        assert contract.policy.active_testing is True
        assert getattr(contract.policy, authority) is True
        assert any("active_testing was enabled" in line for line in contract.adjustments)


def hunt_row(context_pack):
    return {
        "id": uuid.uuid4(),
        "target_kind": "web",
        "target_id": uuid.uuid4(),
        "device_target_id": None,
        "objective": "find bugs",
        "status": "active",
        "budget_profile": "balanced",
        "policy_json": json.dumps({"allowed_capabilities": []}),
        "budget_json": {},
        "budget_used_json": "{}",
        "context_pack": context_pack,
        "stop_reason": None,
        "final_debrief": None,
        "created_at": datetime(2026, 9, 21, tzinfo=timezone.utc),
        "updated_at": datetime(2026, 9, 21, tzinfo=timezone.utc),
    }


class TestTheProjectionSurfacesWhatTheServerResolved:
    """Buried in the context pack these were reachable but unread, so a Hunt that did no
    active work still looked like a Hunt that found nothing."""

    def test_adjustments_appear_beside_the_policy_not_only_inside_the_pack(self):
        contract = normalize_hunt_start_payload(request_body(policy={
            "network_discovery": True, "authorization_confirmed": True,
            "approval_receipt_id": "receipt-1",
        }))
        stored = contract.public_dict()
        stored["policy_adjustments"] = contract.resolution_adjustments(
            approval_validated=True,
        )
        projected = public_hunt_run(hunt_row({"hunt_start_contract": stored}))
        assert projected["policy_adjustments"], projected["policy_adjustments"]
        assert any(
            "active_testing was enabled" in line for line in projected["policy_adjustments"]
        )
        assert any(
            "active_testing was enabled" in line
            for line in projected["policy_adjustments"]
        )

    def test_a_validated_privileged_run_reports_no_downgrade(self):
        contract = normalize_hunt_start_payload(request_body(policy={
            "active_testing": True, "authorization_confirmed": True,
            "approval_receipt_id": "receipt-1",
        }))
        stored = contract.public_dict()
        stored["policy_adjustments"] = contract.resolution_adjustments(
            approval_validated=True,
        )
        projected = public_hunt_run(hunt_row({"hunt_start_contract": stored}))
        assert projected["policy_adjustments"] == []

    @pytest.mark.parametrize("pack", [
        {}, {"hunt_start_contract": {}},
        {"hunt_start_contract": {"policy_adjustments": "not-a-list"}},
        {"hunt_start_contract": "not-a-mapping"},
    ])
    def test_a_run_started_before_this_field_existed_projects_an_empty_list(self, pack):
        assert public_hunt_run(hunt_row(pack))["policy_adjustments"] == []

    def test_the_field_is_present_on_a_listing_that_omits_the_context_pack(self):
        contract = normalize_hunt_start_payload(request_body(policy={
            "allow_state_changing_http": True, "authorization_confirmed": True,
            "approval_receipt_id": "receipt-1",
        }))
        stored = contract.public_dict()
        stored["policy_adjustments"] = contract.resolution_adjustments(
            approval_validated=True,
        )
        projected = public_hunt_run(
            hunt_row({"hunt_start_contract": stored}), include_context=False,
        )
        assert "context_pack" not in projected
        assert projected["policy_adjustments"]


def test_standing_authorization_covers_selected_target_credentials():
    """Credential selection reuses the target authorization instead of bypassing lookup."""
    async def resolver(_target_id):
        return {"approval_receipt_id": "standing-1", "scope_receipt_id": "scope-1"}

    payload = request_body(
        policy={"active_testing": True},
        credential_refs={"web_credential_profile_id": "profile-1"},
    )
    result = asyncio.run(apply_standing_authorization(payload, resolver))
    assert result["policy"]["approval_receipt_id"] == "standing-1"


def test_standing_authorization_fills_a_sub_authority_request():
    async def resolver(_target_id):
        return {"approval_receipt_id": "standing-1", "scope_receipt_id": "scope-1"}

    payload = request_body(policy={"network_discovery": True})
    result = asyncio.run(apply_standing_authorization(payload, resolver))
    assert result["policy"]["approval_receipt_id"] == "standing-1"
    assert result["policy"]["authorization_confirmed"] is True
    contract = normalize_hunt_start_payload(result)
    assert contract.policy.active_testing is True


def test_the_public_contract_reports_the_limits_the_request_model_enforces():
    contract = run_router.hunt_start_public_contract()
    assert contract["limits"]["skill_ids"] == MAX_SKILLS
    assert contract["limits"]["direct_origin_addresses"] == MAX_DIRECT_ORIGIN_ADDRESSES
