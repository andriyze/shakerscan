"""Retain reusable settled Hunt steps through the existing target recipe/proposal path.

No step runs here. Current target delegation decides whether the recipe is saved or
filed for review; reusing it still invokes the canonical runtime and all its checks.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from fastapi import HTTPException


def _object(value: Any) -> dict:
    try:
        decoded = json.loads(value) if isinstance(value, str) else value
    except (TypeError, ValueError):
        return {}
    return dict(decoded) if isinstance(decoded, Mapping) else {}


def _masked(value: Any) -> bool:
    if isinstance(value, str):
        return any(marker in value for marker in ("***", "[REDACTED]", "<redacted>"))
    if isinstance(value, Mapping):
        return any(_masked(child) for child in value.values())
    return isinstance(value, (list, tuple)) and any(_masked(child) for child in value)


def recipe_steps(actions: list[Mapping]) -> tuple[list[dict], dict, list[str]]:
    from runtime.capability_registry import CAPABILITY_REGISTRY
    from targets.actions import MAX_STEPS

    steps, parameters, evidence, seen = [], {}, [], set()
    for action in actions:
        if action.get("status") != "completed":
            continue
        name = str(action.get("capability_name") or "")
        try:
            spec = CAPABILITY_REGISTRY.require(name)
        except KeyError:
            continue
        if (not spec.planner_visible or not spec.hunt_executor
                or spec.placement_requirements.get("control_plane")
                or not spec.placement_requirements.get("network_reachability")
                or name.startswith("ssh.")):
            continue
        values = _object(action.get("input_summary")).get("input")
        if not isinstance(values, Mapping) or _masked(values):
            continue
        # These inputs hold transient workflow state or free-form request material. Never
        # turn a redacted capture, arbitrary body or internal manifest into a replay recipe.
        if any(values.get(key) for key in (
            "body", "capture", "request_bindings", "request_candidate_manifest_ref",
            "candidate_id", "secret_ref", "session_id",
        )):
            continue
        try:
            values = CAPABILITY_REGISTRY.validate_hunt_input(name, dict(values))
        except ValueError:
            continue
        identity = json.dumps([name, values], sort_keys=True)
        if identity in seen:
            continue
        if len(steps) >= MAX_STEPS:
            break
        seen.add(identity)
        # Sessions belong to a run. A future run supplies its own session instead of
        # replaying an expired reference or silently changing an authenticated step.
        selected_parameters = dict(parameters)
        for key in ("session_ref", "primary_session_ref", "secondary_session_ref"):
            if values.get(key):
                parameter = f"session_{len(selected_parameters) + 1}"
                selected_parameters[parameter] = {"type": "string", "description": f"Current Hunt {key}"}
                values[key] = {"$parameter": parameter}
        if len(selected_parameters) > 16:
            break
        parameters = selected_parameters
        steps.append({"capability": name, "input": values})
        evidence.append(str(action["id"]))
    return steps, parameters, evidence


async def retain_hunt_action(conn: Any, run: Mapping) -> dict | None:
    """One recipe per finished Hunt, committed with its debrief; no planner memory needed."""
    from targets.actions import TargetActionWrite, read_target_actions, validated_recipe, write_target_action
    from targets.hunt_authority import authority_from_row, authority_row
    from targets.instruction_proposals import ActionProposalNote, create_action_proposal
    from .interpretations import notes_quarantined

    if notes_quarantined(run.get("notes")):
        return {"status": "skipped", "reason": "hunt_entries_retracted"}
    target = run.get("device_target_id") or run.get("target_id")
    if not target:
        return None
    # Serialize with permission edits before choosing a direct write or a proposal.
    authority = authority_from_row(await authority_row(conn, target, lock=True))
    if not authority["metadata_changes"]:
        return {"status": "skipped", "reason": "target_metadata_changes_disabled"}
    actions = await conn.fetch(
        """SELECT id, capability_name, status, input_summary FROM hunt_actions
           WHERE hunt_run_id=$1 AND status='completed'
           ORDER BY completed_at, id LIMIT 2000""", run["id"],
    )
    steps, parameters, evidence = recipe_steps([dict(action) for action in actions])
    if not steps:
        return {"status": "skipped", "reason": "no_reusable_steps"}
    saved = await read_target_actions(conn, target)
    request = TargetActionWrite(
        name=f"Hunt {str(run['id'])[:8]} checks",
        instructions=("Checks retained from completed Hunt actions. Supply current session parameters "
                      "where requested. Each step requires the new Hunt's scope, policy, credentials "
                      "and budget; these saved steps grant no authority."),
        steps=steps, parameters=parameters, expected_revision=saved["revision"],
    )
    validated_recipe(request)
    writer = f"hunt:{run['id']}"
    if authority["instruction_changes"]:
        written = await write_target_action(conn, target, "create", expected_revision=saved["revision"],
                                            request=request, source=writer, delegation=authority)
        action = written["actions"][-1]
        return {"status": "saved", "action_id": action["id"], "step_count": len(steps)}
    proposal = await create_action_proposal(conn, target, "create", expected_revision=saved["revision"],
        request=request, note=ActionProposalNote(reason="Retain completed checks for a later Hunt.",
                                                evidence_refs=evidence),
        proposed_by=writer, hunt_run_id=UUID(str(run["id"])))
    return {"status": "proposed", "proposal_id": str(proposal["id"]), "step_count": len(steps),
            "review": "shakerscan knowledge review"}


async def retain_hunt_action_safely(conn: Any, run: Mapping) -> dict:
    # A full target recipe list or an unavailable metadata store must not lose the Hunt's
    # debrief. The savepoint rolls back only this optional write and exposes the failure.
    try:
        async with conn.transaction():
            return await retain_hunt_action(conn, run) or {"status": "skipped", "reason": "no_target"}
    except HTTPException as exc:
        return {"status": "not_saved", "reason": "target_action_refused", "status_code": exc.status_code}
    except Exception as exc:
        return {"status": "not_saved", "reason": f"target_action_error:{type(exc).__name__}"}
