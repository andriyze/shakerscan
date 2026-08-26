from __future__ import annotations

from pathlib import Path
from tests.api_sources import (
    api_tree_source, definition_source, route_is_declared, route_source,
)


ROOT = Path(__file__).resolve().parents[1]


def _handler_source() -> str:
    return (
        definition_source("execute_hunt_capability")
        + definition_source("_execute_hunt_capability_lifecycle")
    )


def test_ssh_proposal_reserves_and_starts_before_plan_construction():
    handler = _handler_source()

    assert 'is_device_ssh_proposal = placement == "device_ssh_proposal"' in handler
    assert "DeviceExecutionAdapter(" in handler
    assert "dispatch_registered_adapter(" in handler
    assert handler.index("create_requested(") < handler.index(
        "_execute_device_capability_operation("
    )
    assert "An SSH proposal is already in flight for this Hunt" in handler
    assert "_merge_hunt_device_ssh_proposal_context" in handler


def test_blocked_ssh_proposal_refunds_privileged_execution_dimensions():
    handler = _handler_source()

    refund = handler[handler.index("and not device_ssh_plan_proposed"):]
    refund = refund[:refund.index("elif is_device_http")]
    assert "actual_charges = _hunt_nonexecuting_actual(charges)" in refund


def test_ssh_proposal_receipt_is_confirmation_gated_and_plan_bound():
    handler = _handler_source()

    assert '"kind": "immutable_shell_plan"' in handler
    assert '"plan_id": str(proposed_ssh_plan["plan_id"])' in handler
    assert '"plan_digest": str(proposed_ssh_plan["plan_digest"])' in handler
    assert '"requires_user_confirmation": True' in handler
    assert '"ssh_plan": ssh_plan_receipt or None' in handler


def test_ssh_proposal_does_not_reserve_device_fragility():
    handler = _handler_source()

    assert "An SSH proposal is control-plane-only" in handler
    assert "if is_device_ssh_proposal" in handler
    success_settlement = handler[handler.index(
        "elif is_device_ssh_proposal:"
    ):]
    success_settlement = success_settlement[:success_settlement.index(
        "elif is_device_http:"
    )]
    assert 'actual_charges["tool_wall_seconds"]' in success_settlement
    assert "device_fragility_points" not in success_settlement


def test_ssh_proposal_does_not_enter_confirmation_executor():
    handler = _handler_source()

    assert "device.ssh.execute_confirmed" not in handler
    assert "agent-confirmed-ssh-shell" not in handler


def test_ssh_proposal_and_confirmation_accept_canonical_credential_refs():
    operation = definition_source("_execute_device_capability_operation")
    proposal = operation[operation.index('if name == "propose_ssh_shell":'):]
    proposal = proposal[:proposal.index('if name == "inspect_capabilities":')]
    confirmation = definition_source("confirm_hunt_shell_plan")

    assert '_device_agent_credential_reference(state, "ssh")' in proposal
    assert '_device_agent_credential_reference(state, "ssh")' in confirmation
