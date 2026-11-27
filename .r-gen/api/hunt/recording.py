"""Finish evidence recording without resuming an exhausted Hunt's target traffic."""
from collections.abc import Mapping


def evidence_recording(name: str) -> bool:
    from runtime.capability_registry import CAPABILITY_REGISTRY
    try:
        spec = CAPABILITY_REGISTRY.require(name)
    except KeyError:
        return False
    return (spec.hunt_executor == "inline"
            and spec.placement_requirements.get("control_plane") is True
            and spec.placement_requirements.get("evidence_recording") is True)


def recording_run_allowed(run: Mapping, name: str) -> bool:
    return (run.get("status") == "budget_exhausted"
            and run.get("completed_at") is None and evidence_recording(name))


def recorded_charge(result: Mapping) -> dict[str, int] | None:
    """A finding write that returned an existing record unchanged wrote nothing: release its unit."""
    return {"candidates": 0} if result.get("created") is False else None
