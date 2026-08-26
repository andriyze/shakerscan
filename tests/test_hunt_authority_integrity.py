from pathlib import Path

from tests.api_sources import (
    api_tree_source, definition_source, route_is_declared, route_source,
)

import pytest

from api.hunt.start_contract import (
    HuntStartContractError,
    HuntStartPolicy,
    bind_validated_receipts,
    normalize_hunt_start_payload,
)


def _passive_payload():
    return {
        "schema_version": "hunt-start/v2",
        "target_id": "target-1",
        "target_kind": "web",
        "goal": "Inspect the target",
        "policy": {
            "active_testing": False,
            "network_discovery": False,
            "allow_state_changing_http": False,
            "authorization_confirmed": False,
        },
    }


def test_unvalidated_scope_reference_is_rejected_at_contract_boundary():
    payload = _passive_payload()
    payload["policy"]["scope_receipt_id"] = "scope-attacker"
    with pytest.raises(HuntStartContractError, match="validated approval"):
        normalize_hunt_start_payload(payload)


def test_server_validated_scope_replaces_an_omitted_client_scope():
    policy = HuntStartPolicy(approval_receipt_id="approval-1")
    assert bind_validated_receipts(policy, {
        "approval_receipt_id": "approval-1",
        "scope_receipt_id": "scope-validated",
    }) == ("approval-1", "scope-validated")


def test_client_scope_must_match_the_scope_linked_to_the_approval():
    policy = HuntStartPolicy(
        approval_receipt_id="approval-1",
        scope_receipt_id="scope-submitted",
    )
    with pytest.raises(HuntStartContractError, match="does not match"):
        bind_validated_receipts(policy, {
            "approval_receipt_id": "approval-1",
            "scope_receipt_id": "scope-validated",
        })


def test_runtime_uses_validated_scope_and_independent_network_permission():
    root = Path(__file__).resolve().parents[1]
    native_api = api_tree_source()
    worker = (root / "api" / "worker.py").read_text()

    assert "approval_context = await _validate_approval_receipt_for_action" in native_api
    assert "validated_approval_id, validated_scope_id = bind_validated_receipts" in native_api
    assert '"scope_receipt_id": validated_scope_id' in native_api
    assert 'normalized_contract["policy"]["scope_receipt_id"] = validated_scope_id' in native_api
    assert 'network_discovery=bool(policy.get("network_discovery"))' in native_api
    assert 'network_discovery=bool(policy.get("active_testing"))' not in native_api
    assert "scope_receipt_id=validated_scope_receipt_id" in native_api
    assert 'scope_receipt_id=str(hunt_policy.get("scope_receipt_id") or "") or None' in worker


def test_hunt_router_owns_the_only_hunt_start_route():
    root = Path(__file__).resolve().parents[1]
    primary_api = (root / "api" / "api.py").read_text()
    hunt_router = (root / "api" / "hunt" / "run_router.py").read_text()
    entrypoint = (root / "scanner" / "entrypoint.sh").read_text()

    assert not (root / "api" / "api_v2.py").exists()
    assert hunt_router.count('    "/hunts",\n    response_model=HuntStartV2Response') == 1
    assert "async def start_hunt(request: Request, response: Response):" in hunt_router
    assert '    "/hunts",\n    response_model=HuntStartV2Response' not in primary_api
    assert "app.include_router(hunt_run_router)" in primary_api
    assert "SHAKERSCAN_ALLOW_LEGACY_HUNT_STARTS" not in primary_api
    assert "LegacyHuntStartRequest" not in primary_api
    assert "LegacyHuntStartRequest" not in hunt_router
    assert "api_v2.py" not in entrypoint
