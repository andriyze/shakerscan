from __future__ import annotations

import asyncio
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from hunt.action_dispatcher import (
    HUNT_ACTION_DISPATCHER,
    HuntActionRequest,
    HuntDispatchError,
    RegisteredHuntAdapterFactory,
)
from hunt.capability_executor import CapabilityAdapterResult
from hunt.device_policy import DeviceHuntPolicyError, DeviceHuntPolicyState
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import TargetBinding


class _Adapter:
    def __init__(self, specification):
        self.capability_name = specification.name
        self.adapter_name = specification.adapter
        self.adapter_version = specification.adapter_version

    async def execute(self, *, heartbeat, cancelled):
        await heartbeat()
        return CapabilityAdapterResult(
            status="success",
            observations=({"kind": "test_observation"},),
            actual_budget={"agent_actions": 1},
            execution_started=True,
            parser_version="test/v1",
        )


def _target(kind: str) -> TargetBinding:
    return TargetBinding(
        target_id=f"{kind}-1",
        target_kind=kind,
        canonical_host="example.test" if kind != "device" else "192.0.2.10",
        allowed_origins=("https://example.test",) if kind in {"web", "api"} else (),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",) if kind != "device" else (),
    )


def test_every_planner_capability_is_resolved_without_a_parallel_route_catalog():
    planner = [spec for spec in CAPABILITY_REGISTRY.list() if spec.planner_visible]
    assert planner
    assert {
        HUNT_ACTION_DISPATCHER.require(spec.name).name for spec in planner
    } == {spec.name for spec in planner}
    assert all(HUNT_ACTION_DISPATCHER.placement(spec.name) for spec in planner)


@pytest.mark.parametrize(
    ("capability", "target_kind"),
    [
        ("http.request", "web"),
        ("http.request", "api"),
        ("ports.discover", "network"),
        ("device.inspect", "device"),
        ("collections.inspect", "web"),
        ("collections.inspect", "api"),
        ("collections.inspect", "device"),
        ("collections.replay_safe", "device"),
    ],
)
def test_one_action_and_result_schema_covers_all_target_kinds(
    capability: str, target_kind: str,
):
    spec = CAPABILITY_REGISTRY.require(capability)
    capability_input = (
        {"method": "GET", "path": "/health"}
        if capability == "http.request"
        else {"collection_id": "collection-1"}
        if capability == "collections.replay_safe"
        else {}
    )
    request = HuntActionRequest(
        hunt_id="hunt-1",
        action_id="action-1",
        capability_name=capability,
        target=_target(target_kind),
        capability_input=capability_input,
        requested_budget={"agent_actions": 1},
    )
    factory = RegisteredHuntAdapterFactory({
        spec.adapter: lambda specification, _request: _Adapter(specification),
    })
    result = asyncio.run(HUNT_ACTION_DISPATCHER.execute(
        request,
        factory,
        heartbeat=lambda: asyncio.sleep(0),
        cancelled=lambda: False,
    ))
    public = result.public_dict()
    assert public["schema_version"] == "hunt-action-result/v2"
    assert public["target_kind"] == target_kind
    assert public["capability"] == capability
    assert public["placement"] == spec.hunt_executor
    assert public["status"] == "success"


def test_registry_exposes_the_supported_cross_target_acceptance_matrix():
    expected = {
        "http.request": {"web", "api"},
        "browser.navigate": {"web", "api"},
        "ports.discover": {"web", "api", "network"},
        "collections.replay_safe": {"web", "api", "device"},
        "auth.session.establish": {"web", "api"},
        "device.http.probe": {"device"},
        "device.service.verify": {"device"},
        "device.ssh.propose": {"device"},
    }
    for capability, target_kinds in expected.items():
        assert CAPABILITY_REGISTRY.require(capability).target_kinds == target_kinds


def test_dispatcher_rejects_target_and_adapter_identity_drift():
    request = HuntActionRequest(
        hunt_id="hunt-1",
        action_id="action-1",
        capability_name="device.inspect",
        target=_target("web"),
        capability_input={},
        requested_budget={"agent_actions": 1},
    )
    spec = CAPABILITY_REGISTRY.require("device.inspect")
    factory = RegisteredHuntAdapterFactory({
        spec.adapter: lambda specification, _request: _Adapter(specification),
    })
    with pytest.raises(HuntDispatchError, match="does not support"):
        asyncio.run(HUNT_ACTION_DISPATCHER.execute(
            request,
            factory,
            heartbeat=lambda: asyncio.sleep(0),
            cancelled=lambda: False,
        ))

    wrong = _Adapter(spec)
    wrong.adapter_name = "unregistered.adapter"
    good_request = HuntActionRequest(
        hunt_id="hunt-1",
        action_id="action-1",
        capability_name="device.inspect",
        target=_target("device"),
        capability_input={},
        requested_budget={"agent_actions": 1},
    )
    bad_factory = RegisteredHuntAdapterFactory({
        spec.adapter: lambda _spec, _request: wrong,
    })
    with pytest.raises(HuntDispatchError, match="outside registry authority"):
        asyncio.run(HUNT_ACTION_DISPATCHER.execute(
            good_request,
            bad_factory,
            heartbeat=lambda: asyncio.sleep(0),
            cancelled=lambda: False,
        ))


def test_native_device_policy_is_typed_paced_and_fail_closed():
    state = DeviceHuntPolicyState.initial(
        safety_profile="safe_remote",
        fragility_limit=4,
        request_limit=2,
        scan_limit=1,
    )
    adapter = state.adapter_state(credential_refs=[], collection_refs=[])
    after = {**adapter, "device_http_requests_used": 1, "fragility_used": 1,
             "health_observed": True, "health_failed": True}
    first = state.reconcile_adapter_state(
        adapter, after, actual_fragility=1, health_failed=True,
    )
    assert first.requests_used == 1
    assert first.fragility_used == 1
    assert first.consecutive_health_failures == 1
    assert first.traffic_frozen is False

    before_second = first.adapter_state(credential_refs=[], collection_refs=[])
    after_second = {**before_second, "device_http_requests_used": 2,
                    "health_observed": True, "health_failed": True}
    second = first.reconcile_adapter_state(
        before_second, after_second, health_failed=True,
    )
    assert second.traffic_frozen is True
    with pytest.raises(DeviceHuntPolicyError, match="circuit breaker"):
        second.require_admission(request_attempts=1)


def test_native_device_hunts_never_seed_legacy_agent_state():
    source = (ROOT / "api" / "api.py").read_text(encoding="utf-8")
    start = source.index("async def _start_hunt_v2(")
    end = source.index("\n\nasync def _parse_hunt_start_body", start)
    native_start = source[start:end]
    assert "device_agent.seed_state" not in native_start
    assert '"device_state"' not in native_start
    assert '"device_policy_state"' in native_start
    assert '"device_runtime"' in native_start


def test_replay_uses_the_same_dispatcher_and_exact_replay_engine():
    api_source = (ROOT / "api" / "api.py").read_text(encoding="utf-8")
    worker_source = (ROOT / "api" / "worker.py").read_text(encoding="utf-8")
    api_start = api_source.index("async def _enqueue_hunt_replay_capability(")
    api_end = api_source.index(
        "\n\nasync def _validate_hunt_credential_references", api_start
    )
    submission = api_source[api_start:api_end]
    worker_start = worker_source.index(
        "async def process_request_collection_replay_job("
    )
    worker_end = worker_source.index(
        "\n\ndef _worker_terminal_network_result", worker_start
    )
    execution = worker_source[worker_start:worker_end]
    assert "decrypt_secret" not in submission
    assert '"action_digest": action_digest' in submission
    assert "ReplayExecutionAdapter(" in execution
    assert "_dispatch_registered_hunt_adapter(" in execution
    assert '"receipt_capability_name": replay_spec.name' in execution
    assert '"idempotent_redelivery_in_flight"' in execution


def test_public_hunt_route_returns_the_canonical_action_result_on_first_and_retry():
    source = (ROOT / "api" / "api.py").read_text(encoding="utf-8")
    start = source.index("async def execute_hunt_capability(")
    end = source.index('\n\n@app.post("/hunts/{hunt_id}/shell-plans', start)
    handler = source[start:end]
    assert handler.count('"action_result":') == 2
    assert '"schema_version": "hunt-action-result/v2"' in (
        ROOT / "api" / "hunt" / "action_dispatcher.py"
    ).read_text(encoding="utf-8")
