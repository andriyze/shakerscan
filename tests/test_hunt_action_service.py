import asyncio
from pathlib import Path

from tests.api_sources import (
    api_tree_source, definition_source, route_is_declared, route_source,
)

import pytest

from api.hunt.action_service import (
    HUNT_ACTION_SERVICE,
    HuntActionInputError,
    HuntActionLifecycleError,
    HuntActionService,
    LIFECYCLE_PHASES,
)


def test_one_service_owns_the_fixed_lifecycle_for_every_placement():
    service = HuntActionService()

    async def operation(lifecycle):
        for phase in LIFECYCLE_PHASES[1:-1]:
            lifecycle.advance(phase)
        return {"status": "completed"}

    result = asyncio.run(service.execute("collections.inspect", {}, operation))

    assert result["lifecycle"]["outcome"] == "completed"
    assert [item["phase"] for item in result["lifecycle"]["phases"]] == list(
        LIFECYCLE_PHASES
    )
    placement = result["lifecycle"]["placement"]
    metrics = service.metrics.snapshot()["placements"][placement]
    assert metrics["outcomes"] == {"completed": 1}
    assert all(metrics["phases"][phase] == 1 for phase in LIFECYCLE_PHASES)


def test_service_rejects_phase_reordering_and_unknown_input():
    service = HuntActionService()
    lifecycle = service.prepare("collections.inspect", {})

    with pytest.raises(HuntActionLifecycleError, match="revalidated"):
        lifecycle.advance("dispatching")
    with pytest.raises(HuntActionInputError):
        service.prepare("collections.inspect", {"target": "https://smuggle.test"})


def test_idempotent_replay_never_reenters_admission_or_dispatch():
    service = HuntActionService()

    async def operation(lifecycle):
        lifecycle.mark_replayed()
        return {"status": "completed", "idempotent_replay": True}

    result = asyncio.run(service.execute("collections.inspect", {}, operation))

    assert result["lifecycle"]["outcome"] == "replayed"
    assert [item["phase"] for item in result["lifecycle"]["phases"]] == [
        "validated"
    ]


def test_process_global_service_has_content_free_metrics():
    snapshot = HUNT_ACTION_SERVICE.metrics.snapshot()

    assert snapshot["schema_version"] == "hunt-action-lifecycle-metrics/v1"
    assert "target" not in snapshot
    assert "input" not in snapshot


def test_public_route_delegates_to_service_and_never_persists_device_state():
    route = definition_source("execute_hunt_capability")
    implementation = definition_source("_execute_hunt_capability_lifecycle")

    assert "HUNT_ACTION_SERVICE.execute(" in route
    assert "lifecycle.advance(\"revalidated\")" in implementation
    assert "lifecycle.advance(\"admitted\")" in implementation
    assert "lifecycle.advance(\"dispatching\")" in implementation
    assert "lifecycle.advance(\"persisting\")" in implementation
    assert "lifecycle.advance(\"settled\")" in implementation
    assert 'context["device_state"]' not in implementation
    assert 'context.get("device_state")' not in implementation
    assert "device_adapter_state" in implementation
