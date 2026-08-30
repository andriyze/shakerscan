"""Operator-confirmed direct-origin requests.

Demonstrating that an origin is reachable without the CDN or WAF in front of it requires
connecting to a specific address while still presenting the target's hostname. That is
useful and dangerous for the same reason, so the address comes from the operator and the
planner may only choose among the ones already confirmed.
"""

import asyncio

import pytest

from api.capabilities.http import execute_bound_http_request
from api.hunt.start_contract import (
    MAX_DIRECT_ORIGIN_ADDRESSES,
    HuntStartContractError,
    normalize_hunt_start_payload,
)
from api.runtime.models import TargetBinding


APPROVAL = "11111111-1111-4111-8111-111111111111"
AUTHORIZED = {
    "allow_direct_origin": True,
    "active_testing": True,
    "authorization_confirmed": True,
    "approval_receipt_id": APPROVAL,
}


def _start(**overrides):
    payload = {"target_id": "t1", "target_kind": "web", "goal": "g", "policy": {}}
    payload.update(overrides)
    return normalize_hunt_start_payload(payload)


def _binding():
    return TargetBinding(
        target_id="t1",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=("198.51.100.5",),
    )


def _run(**kwargs):
    return asyncio.run(execute_bound_http_request(
        "https://app.example.test",
        {"method": "GET", "path": "/", **kwargs.pop("args", {})},
        target=_binding(),
        timeout_seconds=kwargs.pop("timeout_seconds", 1),
        **kwargs,
    ))


# --- contract ----------------------------------------------------------------------------

def test_addresses_without_the_authority_are_refused():
    with pytest.raises(HuntStartContractError, match="requires policy.allow_direct_origin"):
        _start(direct_origin_addresses=["203.0.113.10"])


def test_the_authority_without_addresses_is_refused():
    """Granting it with nothing to use it on reads as configured while doing nothing."""
    with pytest.raises(HuntStartContractError, match="at least one direct origin address"):
        _start(policy=AUTHORIZED)


def test_direct_origin_requires_active_testing_and_an_approval_receipt():
    with pytest.raises(HuntStartContractError, match="require active_testing"):
        _start(
            direct_origin_addresses=["203.0.113.10"],
            policy={"allow_direct_origin": True},
        )
    with pytest.raises(HuntStartContractError, match="approval receipt"):
        _start(
            direct_origin_addresses=["203.0.113.10"],
            policy={
                "allow_direct_origin": True, "active_testing": True,
                "authorization_confirmed": True,
            },
        )


def test_only_literal_addresses_are_accepted():
    """A hostname would be resolved at connect time, which is the indirection this field
    exists to remove: the operator is naming the machine, not another name for it."""
    with pytest.raises(HuntStartContractError, match="literal IP addresses"):
        _start(
            direct_origin_addresses=["origin.example.com"], policy=AUTHORIZED,
        )


@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.0.0.8", "169.254.169.254", "::1", "fc00::8", "fe80::1",
    "::ffff:10.0.0.8",
])
def test_private_and_local_direct_origins_are_refused(address):
    with pytest.raises(HuntStartContractError, match="private, local, or non-routable"):
        _start(direct_origin_addresses=[address], policy=AUTHORIZED)


def test_both_address_families_are_accepted_and_deduplicated():
    contract = _start(
        direct_origin_addresses=["203.0.113.10", "2001:db8::10", "203.0.113.10"],
        policy=AUTHORIZED,
    )
    assert list(contract.direct_origin_addresses) == ["203.0.113.10", "2001:db8::10"]


def test_approval_address_binding_is_order_independent_but_exact():
    from api.api import _approval_context_value_matches

    assert _approval_context_value_matches(
        "direct_origin_addresses",
        ["2001:db8::10", "203.0.113.10"],
        ["203.0.113.10", "2001:db8::10"],
    )
    assert not _approval_context_value_matches(
        "direct_origin_addresses", ["203.0.113.11"], ["203.0.113.10"],
    )


def test_the_confirmed_list_is_bounded():
    """A long list stops being an operator naming hosts and becomes a scan range."""
    with pytest.raises(HuntStartContractError, match="at most"):
        _start(
            direct_origin_addresses=[
                f"203.0.113.{index}"
                for index in range(MAX_DIRECT_ORIGIN_ADDRESSES + 1)
            ],
            policy=AUTHORIZED,
        )


# --- persisted policy --------------------------------------------------------------------

def test_unearned_authority_is_stored_as_absent():
    """Workers read the row, not the request. Authority that was asked for but not approved
    must not survive into the row, or every reader has to re-check the receipt."""
    contract = _start(
        direct_origin_addresses=["203.0.113.10"], policy=AUTHORIZED,
    )
    row = contract.persisted_policy(
        approval_validated=False, credential_access=False,
        approval_receipt_id=None, scope_receipt_id=None,
        budget=contract.resolved_budget_object, allowed_capabilities=(),
    )
    assert row["allow_direct_origin"] is False
    assert row["direct_origin_addresses"] == []
    assert row["active_testing"] is False


def test_approved_authority_reaches_the_row():
    contract = _start(
        direct_origin_addresses=["203.0.113.10"], policy=AUTHORIZED,
    )
    row = contract.persisted_policy(
        approval_validated=True, credential_access=False,
        approval_receipt_id=APPROVAL, scope_receipt_id=None,
        budget=contract.resolved_budget_object, allowed_capabilities=("http.request",),
    )
    assert row["allow_direct_origin"] is True
    assert row["direct_origin_addresses"] == ["203.0.113.10"]


# --- executor ----------------------------------------------------------------------------

def test_an_unconfirmed_address_is_refused_before_any_connection():
    result = _run(
        args={"via_address": "203.0.113.99"},
        direct_origin_addresses=("203.0.113.10",),
    )
    assert result["ok"] is False
    assert "not an operator-confirmed direct origin" in result["error"]


def test_a_planner_cannot_reach_an_address_when_none_were_confirmed():
    result = _run(args={"via_address": "203.0.113.10"})
    assert result["ok"] is False
    assert "not an operator-confirmed direct origin" in result["error"]


def test_a_confirmed_address_passes_the_scope_check():
    """It fails at connect, not at scope: the address is admitted and the attempt is real."""
    result = _run(
        args={"via_address": "203.0.113.10"},
        direct_origin_addresses=("203.0.113.10",),
    )
    assert not str(result.get("error", "")).startswith("scope:")


def test_the_target_address_is_still_used_when_no_address_is_named():
    result = _run(direct_origin_addresses=("203.0.113.10",))
    assert not str(result.get("error", "")).startswith("scope:")
    assert result.get("request", {}).get("direct_origin") is not True


def test_http_result_reports_header_filtering_without_values():
    result = _run(args={"headers": {
        "Authorization": "Bearer hidden-token",
        "Origin": "https://comparison.example",
    }})
    request = result["request"]
    assert request["accepted_header_names"] == ["origin"]
    assert request["rejected_headers"] == {
        "authorization": "managed_principal_required",
    }
    assert "hidden-token" not in repr(request)


# --- forged identity headers are metered like the active action they are ------------------

def test_forging_identity_is_classified_as_an_active_call():
    """It was classified by the capability's static risk tier, so anonymous forged-header
    requests never consumed active_actions and ran to the HTTP ceiling instead."""
    from tests.api_sources import api_tree_source

    source = api_tree_source()
    assert "forges_identity" in source
    assert "or forges_identity" in source, "it must widen requires_call_approval"
    assert 'else "active" if forges_identity' in source, "and elevate the approved risk tier"


def test_the_identity_header_vocabulary_has_one_owner():
    """The router classifies calls from the same set the request filter enforces, so a
    header cannot be strippable but unmetered, or metered but never stripped."""
    import api.agent_tools as agent_tools

    assert "cf-connecting-ip" in agent_tools.IDENTITY_HEADERS
    assert "true-client-ip" in agent_tools.IDENTITY_HEADERS
    assert "x-forwarded-for" in agent_tools.IDENTITY_HEADERS
    assert "client-ip" in agent_tools.IDENTITY_HEADERS
    assert "fastly-client-ip" in agent_tools.IDENTITY_HEADERS
    assert "x-azure-clientip" in agent_tools.IDENTITY_HEADERS
    # Credential and transport headers are refused for reasons the operator cannot waive,
    # so they are deliberately not part of this set.
    assert "authorization" not in agent_tools.IDENTITY_HEADERS
    assert "transfer-encoding" not in agent_tools.IDENTITY_HEADERS


def test_a_direct_origin_request_is_metered_as_an_active_action():
    """Reaching an address outside the target's resolved one is the act that demonstrates
    a bypass. On the capability's passive tier it consumed no active action and was never
    re-approved per call, so it ran to the HTTP ceiling instead."""
    from tests.api_sources import api_tree_source

    source = api_tree_source()
    assert "uses_direct_origin" in source
    assert "or uses_direct_origin" in source, "it must widen requires_call_approval"
    assert 'else "active" if forges_identity or uses_direct_origin' in source


def test_the_approval_receipt_binds_the_confirmed_addresses():
    """Otherwise a receipt granted for a target also covers whatever addresses the request
    body happens to name, and the operator's confirmation is not what authorised them."""
    from tests.api_sources import api_tree_source

    source = api_tree_source()
    assert '"direct_origin_addresses": sorted(contract.direct_origin_addresses)' in source
    assert "required_action_context=(" in source
