from __future__ import annotations

from pathlib import Path

from tests.api_sources import definition_source
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

import agent_tools
from hunt.action_dispatcher import HUNT_ACTION_DISPATCHER
from hunt.contracts import capability_manifest
from hunt.start_contract import normalize_hunt_start_payload
from runtime.capability_registry import (
    CAPABILITY_REGISTRY,
    CapabilityInputContractError,
)


def test_every_planner_capability_has_one_registry_owned_executor():
    planner_specs = [spec for spec in CAPABILITY_REGISTRY.list() if spec.planner_visible]
    assert planner_specs
    assert all(spec.hunt_executor for spec in planner_specs)
    assert len({spec.name for spec in planner_specs}) == len(planner_specs)

    routed = {
        HUNT_ACTION_DISPATCHER.require(spec.name).name for spec in planner_specs
    }
    assert routed == {spec.name for spec in planner_specs}


@pytest.mark.parametrize("target_kind", ["web", "api", "network", "device"])
def test_manifest_is_semantic_and_keeps_adapter_choice_private(target_kind):
    contract = normalize_hunt_start_payload({
        "schema_version": "hunt-start/v2",
        "target_id": "target-1",
        "target_kind": target_kind,
        "goal": "Inspect the target",
        "budget_profile": "balanced",
        "budgets": {},
        "policy": {
            "active_testing": True,
            "allow_state_changing_http": False,
            "network_discovery": True,
            "authorization_confirmed": True,
            "approval_receipt_id": "approval-1",
        },
        "credential_refs": {"primary_credential_profile_id": "credential-1"},
        "capabilities": [],
        "request_collection_ids": [],
    })
    manifest = capability_manifest(contract, credentials_available=True)
    assert manifest
    assert all(target_kind in item["target_kinds"] for item in manifest)
    assert all("placement" in item for item in manifest)
    serialized = repr(manifest).lower()
    for forbidden in ("adapter_name", "process_tool_name", "run_tool", "raw_argv"):
        assert forbidden not in serialized


def test_registry_input_schema_rejects_hallucinated_flags_and_wrong_shapes():
    assert CAPABILITY_REGISTRY.validate_input(
        "http.request", {"method": "GET", "path": "/health"},
    ) == {"method": "GET", "path": "/health"}

    with pytest.raises(CapabilityInputContractError, match="unsupported fields"):
        CAPABILITY_REGISTRY.validate_input(
            "web.probe", {"argv": ["--target", "https://elsewhere.invalid"]},
        )
    with pytest.raises(CapabilityInputContractError, match="missing required"):
        CAPABILITY_REGISTRY.validate_input("http.request", {"method": "GET"})
    with pytest.raises(CapabilityInputContractError, match="must be an integer"):
        CAPABILITY_REGISTRY.validate_input(
            "browser.navigate", {"timeout_ms": "30000"},
        )
    with pytest.raises(CapabilityInputContractError, match="allowed value"):
        CAPABILITY_REGISTRY.validate_input(
            "device.scan", {
                "coverage_profile": "inventory",
                "reason": "bounded posture check",
                "web_budget_profile": "smart",
            },
        )


def test_hunt_handler_validates_registry_input_before_reservation_or_action_write():
    service_source = (ROOT / "api" / "hunt" / "action_service.py").read_text(
        encoding="utf-8"
    )
    prepare_start = service_source.index("    def prepare(")
    prepare_end = service_source.index("\n    async def execute(", prepare_start)
    prepare = service_source[prepare_start:prepare_end]
    route = definition_source("execute_hunt_capability")

    assert prepare.index("registry.validate_hunt_input") < prepare.index(
        "HuntActionLifecycle("
    )
    assert "HUNT_ACTION_SERVICE.execute(" in route
    assert "_execute_hunt_capability_lifecycle(" in route
    assert "INSERT INTO hunt_actions" not in route


def test_hunt_capability_actions_require_retry_safe_idempotency_keys():
    request_model = definition_source("HuntCapabilityRequest")
    handler = (
        definition_source("execute_hunt_capability")
        + definition_source("_execute_hunt_capability_lifecycle")
    )

    assert "idempotency_key: str" in request_model
    assert "uuid.uuid5" in handler
    assert "idempotency_key_sha256" in handler
    assert "input_digest" in handler
    assert handler.index("existing_action = await conn.fetchrow") < handler.index(
        "INSERT INTO hunt_actions"
    )
    assert '"idempotent_replay": True' in handler
    assert '"idempotent_replay": False' in handler


def test_legacy_loop_never_advertises_or_dispatches_run_tool():
    assert "run_tool" not in agent_tools.CALLABLE_TOOL_NAMES
    assert "run_tool" not in {item["name"] for item in agent_tools.tool_schemas()}
    legacy = (ROOT / "api" / "hunt" / "legacy.py").read_text(encoding="utf-8")
    assert "LegacyHuntIsolationMiddleware" in legacy
    assert '"status": 410' in legacy
