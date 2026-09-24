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
    # The persisted policy row is projected by HuntStartContract.persisted_policy, so the
    # start handler proves it uses the validated scope by what it passes in. The property
    # is unchanged: the client-submitted scope id never reaches the row.
    assert "scope_receipt_id=validated_scope_id" in native_api
    assert '"scope_receipt_id": scope_receipt_id' in native_api
    assert 'normalized_contract["policy"]["scope_receipt_id"] = validated_scope_id' in native_api
    assert 'network_discovery=bool(policy.get("network_discovery"))' in native_api
    assert 'network_discovery=bool(policy.get("active_testing"))' not in native_api
    assert "scope_receipt_id=validated_scope_receipt_id" in native_api
    # Scope construction moved into the shared asset-binding function. Require
    # workers to use that binding, not duplicate the old inline expression.
    assert "from hunt.target_binding import web_hunt_target as _worker_hunt_web_target" in worker
    assert "scope_receipt_id=target.scope_receipt_id" in worker


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


def test_a_privileged_hunt_without_authorization_is_told_how_to_get_it():
    """The refusal names the standing-authorization route; "approval receipt" alone left an
    agent with no way to find it and reading the refusal as a silent downgrade."""
    payload = _passive_payload()
    payload["policy"].update({"active_testing": True, "allow_state_changing_http": True, "network_discovery": True})
    with pytest.raises(HuntStartContractError, match="authorization_confirmed=true"):
        normalize_hunt_start_payload(payload)
    payload["policy"]["authorization_confirmed"] = True
    with pytest.raises(HuntStartContractError, match=r"POST /targets/\{target_id\}/authorization") as excinfo:
        normalize_hunt_start_payload(payload)
    assert "this target has none" in str(excinfo.value)
    assert "approval_receipt_id" in str(excinfo.value)


@pytest.mark.parametrize("kind", ["web", "api", "network", "device"])
@pytest.mark.parametrize("network_discovery", [False, True])
def test_worker_binding_preserves_validated_scope_and_independent_network_permission(kind, network_discovery):
    from api.hunt.target_binding import web_hunt_target
    from api.capabilities.http import resolve_hunt_http_origin
    from api.capabilities.browser_login_worker import browser_worker_policy
    from api.capabilities.network import CapabilityInputError, PortsDiscoverAdapter

    run = {"target_kind": kind, "target_id": None if kind == "device" else "asset-1",
           "device_target_id": "asset-1" if kind == "device" else None,
           "scope_receipt_id": "untrusted-run-field"}
    context = {"target": {"url": "https://fixture.test", "scope_receipt_id": "untrusted-context-field"},
               "authorized_target_addresses": ["192.0.2.10"]}
    persisted_policy = {"active_testing": True, "network_discovery": network_discovery,
                        "scope_receipt_id": "validated-scope", "approval_receipt_id": "validated-approval"}
    target, _ = web_hunt_target(run, context, persisted_policy)
    service = resolve_hunt_http_origin(target, "https://fixture.test:9443", persisted_policy)
    policy = browser_worker_policy("browser.navigate", policy=persisted_policy, target=service)
    assert service.scope_receipt_id == policy.scope_receipt_id == "validated-scope"
    assert service.target_id == "asset-1" and service.target_kind == kind
    assert service.allowed_addresses == target.allowed_addresses == ("192.0.2.10",)
    assert policy.approval_receipt_id == "validated-approval"
    assert policy.active_testing is True and policy.network_discovery is network_discovery
    # Choosing a known service does not grant permission to discover ports.
    if network_discovery:
        prepared = PortsDiscoverAdapter().prepare(target=service, args={"ports": [9443]}, policy=policy)
        assert prepared.estimated_budget["tcp_ports_attempted"] == 1
    else:
        with pytest.raises(CapabilityInputError, match="network discovery policy is not enabled"):
            PortsDiscoverAdapter().prepare(target=service, args={"ports": [9443]}, policy=policy)
    no_scope, _ = web_hunt_target(run, context, {**persisted_policy, "scope_receipt_id": None})
    assert no_scope.scope_receipt_id is None  # Never infer scope from context or run extras.
