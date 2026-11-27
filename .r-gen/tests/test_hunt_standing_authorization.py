"""A privileged Hunt reuses the target's standing authorization instead of asking again."""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "api"))

from hunt.run_router import apply_standing_authorization  # noqa: E402

STANDING = {"approval_receipt_id": "aaaaaaaa-0000-0000-0000-000000000001", "scope_receipt_id": "scope-1"}


async def _resolver(target_id):
    return STANDING if target_id == "target-1" else None


def _payload(**policy):
    return {"target_id": "target-1", "target_kind": "web", "policy": {"active_testing": False, **policy}}


def test_active_policy_without_receipt_is_filled_from_the_standing_authorization():
    payload = asyncio.run(apply_standing_authorization(_payload(active_testing=True), _resolver))
    assert payload["policy"]["approval_receipt_id"] == STANDING["approval_receipt_id"]
    assert payload["policy"]["scope_receipt_id"] == "scope-1"
    assert payload["policy"]["authorization_confirmed"] is True


def test_every_privileged_flag_triggers_resolution():
    for flag in ("allow_state_changing_http", "network_discovery", "allow_oob_interactions",
                 "allow_identity_headers", "allow_direct_origin"):
        payload = asyncio.run(apply_standing_authorization(_payload(**{flag: True}), _resolver))
        assert payload["policy"]["approval_receipt_id"], flag


def test_passive_explicit_and_unknown_targets_stay_unchanged_but_credentials_reuse_authority():
    passive = asyncio.run(apply_standing_authorization(_payload(), _resolver))
    assert "approval_receipt_id" not in passive["policy"]
    explicit = asyncio.run(apply_standing_authorization(
        _payload(active_testing=True, approval_receipt_id="explicit"), _resolver,
    ))
    assert explicit["policy"]["approval_receipt_id"] == "explicit"
    assert "authorization_confirmed" not in explicit["policy"]
    credentialed = asyncio.run(apply_standing_authorization(
        {**_payload(active_testing=True), "credential_refs": {"primary": "cred-1"}}, _resolver,
    ))
    assert credentialed["policy"]["approval_receipt_id"] == STANDING["approval_receipt_id"]
    assert credentialed["policy"]["authorization_confirmed"] is True
    unknown = asyncio.run(apply_standing_authorization(
        {**_payload(active_testing=True), "target_id": "target-9"}, _resolver,
    ))
    assert "approval_receipt_id" not in unknown["policy"]
    without_resolver = asyncio.run(apply_standing_authorization(_payload(active_testing=True), None))
    assert "approval_receipt_id" not in without_resolver["policy"]
