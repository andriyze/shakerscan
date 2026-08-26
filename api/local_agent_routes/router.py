"""Local agent routes.

Extracted verbatim from the api.py monolith. Covers the local agent catalog,
the bounded connectivity/capability test, and candidate plan dry-run parsing.

These routes never execute a planner-supplied argv: a parsed plan stays inert
until an operator confirms the exact immutable commands elsewhere.
"""

from __future__ import annotations

import copy
import json
import re
import uuid
from typing import Any, Callable, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, ValidationError

try:
    from arsenal_routes.router import (
        OperationPlanRequest,
        _contains_forbidden_context_key,
        _operation_plan_allowed_commands,
        _persist_operation_plan,
        _validate_operation_plan,
    )
    from command_arsenal import describe_local_agents, test_local_agent_capability
except ModuleNotFoundError:  # package import in host-side tests
    from ..arsenal_routes.router import (
        OperationPlanRequest,
        _contains_forbidden_context_key,
        _operation_plan_allowed_commands,
        _persist_operation_plan,
        _validate_operation_plan,
    )
    from ..command_arsenal import describe_local_agents, test_local_agent_capability


router = APIRouter()

_pool_provider: Callable[[], Any] | None = None
_deps: dict[str, Callable[..., Any]] = {}


def configure_local_agent_router(
    pool_provider: Callable[[], Any], **collaborators: Callable[..., Any]
) -> None:
    """Bind the pool and the collaborators this domain needs."""
    global _pool_provider
    _pool_provider = pool_provider
    _deps.update(collaborators)


def _pool():
    pool = _pool_provider() if _pool_provider is not None else None
    if pool is None:
        raise HTTPException(status_code=503, detail="database pool is not ready")
    return pool


def _dep(name: str) -> Callable[..., Any]:
    call = _deps.get(name)
    if call is None:
        raise HTTPException(status_code=503, detail=f"{name} is not ready")
    return call


def _get(name: str) -> Any:
    """Resolve an injected collaborator that still lives in the composition root."""
    return _dep(name)()



def _context_pack_payload_from_row(*a: Any, **k: Any) -> Any:
    return _get("_context_pack_payload_from_row")(*a, **k)


def _context_pack_target_scope(*a: Any, **k: Any) -> Any:
    return _get("_context_pack_target_scope")(*a, **k)


def _disallowed_commands_from_context(*a: Any, **k: Any) -> Any:
    return _get("_disallowed_commands_from_context")(*a, **k)


def _json_size_bytes(*a: Any, **k: Any) -> Any:
    return _get("_json_size_bytes")(*a, **k)


def _validate_bounded_agent_parameters(*a: Any, **k: Any) -> Any:
    return _get("_validate_bounded_agent_parameters")(*a, **k)


def _validate_candidate_target_scope(*a: Any, **k: Any) -> Any:
    return _get("_validate_candidate_target_scope")(*a, **k)


__all__ = ["configure_local_agent_router", "router"]
class LocalAgentPlanRequest(BaseModel):
    agent: str = Field(default="codex")
    context_pack_id: str
    objective: str
    created_by: Optional[str] = None


class LocalAgentPlanParseRequest(BaseModel):
    agent: str = Field(default="codex", min_length=1, max_length=64)
    context_pack_id: str
    raw_output: str = Field(min_length=1)
    max_output_bytes: int = Field(default=32768, ge=128, le=262144)
    created_by: Optional[str] = None


class LocalAgentTestRequest(BaseModel):
    agent: str = Field(default="codex", min_length=1, max_length=64)
    timeout_seconds: int = Field(default=5, ge=1, le=10)
    max_output_bytes: int = Field(default=2000, ge=128, le=8000)


@router.get("/agents/local")
async def local_agents(
    probe_versions: bool = Query(False, description="Run short read-only version probes for detected local agent CLIs."),
):
    """Read-only local-agent capability matrix. Does not read auth artifacts or execute prompts."""
    return describe_local_agents(probe_versions=bool(probe_versions))


@router.post("/agents/local/test")
async def local_agent_test(req: LocalAgentTestRequest):
    """Run a harmless local-agent capability ping with no prompt or planner execution."""
    try:
        return test_local_agent_capability(
            req.agent,
            timeout_seconds=req.timeout_seconds,
            max_output_bytes=req.max_output_bytes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/agents/local/plan")
async def local_agent_dry_run_plan(req: LocalAgentPlanRequest):
    """Persist a local-agent-labeled dry-run OperationPlan from a bounded context pack.

    This endpoint intentionally does not spawn Codex, Claude Code, OpenCode, Hermes, shell
    commands, or scanners. It gives operators a validated planning artifact while the
    local-agent execution boundary remains disabled.
    """
    async with _pool().acquire() as conn:
        plan_req, metadata = await _build_local_agent_dry_run_plan(conn, req)
        response = await _persist_operation_plan(conn, plan_req)
    return {
        **response,
        "local_agent_spawned": False,
        "planner_execution_enabled": False,
        "agent": {
            "agent": metadata["agent"].get("agent"),
            "status": metadata["agent"].get("status"),
            "auth_detected": metadata["agent"].get("auth_detected"),
            "binary_path": metadata["agent"].get("binary_path"),
        },
        "context_pack_id": metadata["context_pack"].get("id"),
        "planner_notes": metadata.get("planner_notes") or [],
    }


@router.post("/agents/local/plan/parse")
async def local_agent_parse_candidate_plan(req: LocalAgentPlanParseRequest):
    """Validate raw local-agent planner output without persisting or executing it.

    This endpoint is intentionally fail-closed: accepted output must be a single
    exact JSON OperationPlan object bound to the supplied AgentContextPack.
    """
    async with _pool().acquire() as conn:
        return await _parse_local_agent_candidate_plan(conn, req)
async def _parse_local_agent_candidate_plan(
    conn,
    req: LocalAgentPlanParseRequest,
) -> dict[str, Any]:
    agent_name = str(req.agent or "").strip()
    local_agents = describe_local_agents(probe_versions=False)
    known_agents = {
        str(agent.get("agent")): agent
        for agent in local_agents.get("agents", [])
        if isinstance(agent, dict) and agent.get("agent")
    }
    if agent_name not in known_agents:
        raise HTTPException(status_code=400, detail="Unknown local agent")

    try:
        context_uuid = uuid.UUID(str(req.context_pack_id))
    except ValueError:
        raise HTTPException(status_code=400, detail="context_pack_id must be a UUID")
    row = await conn.fetchrow("SELECT * FROM agent_context_packs WHERE id=$1", context_uuid)
    if not row:
        raise HTTPException(status_code=404, detail="Agent context pack not found")

    context_row, context_pack = _context_pack_payload_from_row(row)
    context_scope = _context_pack_target_scope(context_pack)
    candidate, errors = _strict_local_agent_json_object(req.raw_output, max_output_bytes=req.max_output_bytes)
    warnings: list[str] = []
    operation_plan: dict[str, Any] | None = None
    if candidate is not None:
        original_candidate = copy.deepcopy(candidate)
        for field in sorted(set(candidate.keys()) - LOCAL_AGENT_PLAN_FIELDS):
            errors.append(f"unknown_top_level_field:{field}")
        if _contains_forbidden_context_key(original_candidate):
            errors.append("planner_output_contains_forbidden_raw_or_secret_field")
        hidden_paths = sorted(set(_find_hidden_local_agent_execution_requests(original_candidate)))
        for path in hidden_paths[:20]:
            errors.append(f"hidden_state_changing_request:{path}")
        if len(hidden_paths) > 20:
            errors.append("hidden_state_changing_request:truncated")
        if _json_size_bytes(original_candidate) > 32768:
            errors.append("operation_plan_candidate_too_large")

        context_hash = str(context_row.get("context_hash") or "").lower()
        if str(candidate.get("context_hash") or "").strip().lower() != context_hash:
            errors.append("context_pack_hash_mismatch")
        _validate_candidate_target_scope(candidate.get("target_scope"), context_scope, errors)

        planner = candidate.get("planner") if isinstance(candidate.get("planner"), dict) else {}
        planner_kind = str(planner.get("kind") or "local_agent").strip()
        if planner_kind != "local_agent":
            errors.append("planner_kind_must_be_local_agent")
        if planner.get("local_agent_spawned") is True or planner.get("planner_execution_enabled") is True:
            errors.append("planner_output_claims_execution_enabled")

        commands = _operation_plan_allowed_commands()
        allowed = {
            str(item).strip()
            for item in context_pack.get("allowed_commands", [])
            if str(item).strip()
        }
        disallowed = _disallowed_commands_from_context(context_pack)
        actions = candidate.get("actions")
        if not isinstance(actions, list):
            errors.append("actions_required")
            actions = []
        for index, action in enumerate(actions):
            if not isinstance(action, dict):
                errors.append(f"action_{index}_must_be_object")
                continue
            command_name = str(action.get("command") or "").strip()
            command = commands.get(command_name)
            if not command:
                errors.append(f"action_{index}_unknown_command:{command_name}")
                continue
            if allowed:
                if command_name not in allowed:
                    errors.append(f"action_{index}_command_not_allowed_by_context:{command_name}")
            elif str(command.get("status") or "") not in {"read_only", "dry_run"}:
                # Empty context allow-list: admit only read-only/dry-run inspection.
                # A state-changing command must be explicitly allowed by the pack
                # (and remains independently approval-gated).
                errors.append(f"action_{index}_command_not_allowed_by_empty_context:{command_name}")
            if command_name in disallowed:
                errors.append(f"action_{index}_command_disallowed_by_context:{command_name}")
            if not action.get("risk_tier"):
                errors.append(f"action_{index}_risk_tier_required:{command_name}")
            elif str(action.get("risk_tier")) != str(command.get("risk_tier") or "read_only"):
                errors.append(f"action_{index}_risk_tier_mismatch:{command_name}")
            params = action.get("parameters") if isinstance(action.get("parameters"), dict) else {}
            if _json_size_bytes(params) > 4096:
                errors.append(f"action_{index}_parameters_too_large:{command_name}")
            _validate_bounded_agent_parameters(params, path=f"action_{index}.parameters", errors=errors)
            schema = command.get("parameters_schema") if isinstance(command.get("parameters_schema"), dict) else {}
            for param_name, spec in schema.items():
                if not isinstance(spec, dict) or param_name not in params:
                    continue
                value = params.get(param_name)
                if isinstance(value, (int, float)):
                    if "minimum" in spec and value < spec["minimum"]:
                        errors.append(f"action_{index}_parameter_below_minimum:{param_name}")
                    if "maximum" in spec and value > spec["maximum"]:
                        errors.append(f"action_{index}_parameter_above_maximum:{param_name}")

        candidate["planner"] = {
            **planner,
            "kind": "local_agent",
            "agent": agent_name,
            "mode": "parsed_candidate_validation",
            "local_agent_spawned": False,
            "planner_execution_enabled": False,
            "schema_version": local_agents.get("schema_version"),
        }
        candidate["created_by"] = candidate.get("created_by") or req.created_by
        try:
            plan_req = OperationPlanRequest(**candidate)
        except ValidationError as exc:
            errors.append("operation_plan_schema_validation_failed")
            for item in exc.errors():
                loc = ".".join(str(part) for part in item.get("loc", []))
                errors.append(f"schema:{loc}:{item.get('type')}")
        else:
            payload, validation_errors, validation_warnings, _status = await _validate_operation_plan(conn, plan_req)
            errors.extend(validation_errors)
            warnings.extend(validation_warnings)
            operation_plan = payload

    accepted = bool(operation_plan is not None and not errors)
    return {
        "accepted": accepted,
        "validated": accepted,
        "status": "planned" if accepted else "blocked",
        "validation_errors": errors,
        "validation_warnings": warnings,
        "operation_plan": operation_plan,
        "candidate_persisted": False,
        "execution_enabled": False,
        "local_agent_spawned": False,
        "planner_execution_enabled": False,
        "context_pack_id": str(context_uuid),
        "context_hash": str(context_row.get("context_hash") or "").lower(),
        "agent": {
            "agent": known_agents[agent_name].get("agent"),
            "status": known_agents[agent_name].get("status"),
            "auth_detected": known_agents[agent_name].get("auth_detected"),
            "binary_path": known_agents[agent_name].get("binary_path"),
        },
    }


async def _build_local_agent_dry_run_plan(conn, req: LocalAgentPlanRequest) -> tuple[OperationPlanRequest, dict[str, Any]]:
    agent_name = str(req.agent or "").strip()
    local_agents = describe_local_agents(probe_versions=False)
    known_agents = {
        str(agent.get("agent")): agent
        for agent in local_agents.get("agents", [])
        if isinstance(agent, dict) and agent.get("agent")
    }
    if agent_name not in known_agents:
        raise HTTPException(status_code=400, detail="Unknown local agent")

    try:
        context_uuid = uuid.UUID(str(req.context_pack_id))
    except ValueError:
        raise HTTPException(status_code=400, detail="context_pack_id must be a UUID")
    row = await conn.fetchrow("SELECT * FROM agent_context_packs WHERE id=$1", context_uuid)
    if not row:
        raise HTTPException(status_code=404, detail="Agent context pack not found")

    context_row, context_pack = _context_pack_payload_from_row(row)
    actions, missing_inputs, notes = _choose_local_agent_plan_action(context_pack, req.objective)
    if not actions:
        actions = [{"command": "agent_context_pack.list", "risk_tier": "read_only", "parameters": {}, "reason": "fallback read-only context inspection"}]

    plan = OperationPlanRequest(
        objective=str(req.objective or "").strip(),
        planner={
            "kind": "local_agent",
            "agent": agent_name,
            "mode": "deterministic_dry_run",
            "local_agent_spawned": False,
            "planner_execution_enabled": False,
            "schema_version": local_agents.get("schema_version"),
        },
        context_hash=str(context_row.get("context_hash") or "").lower(),
        target_scope=_context_pack_target_scope(context_pack),
        risk_tier="read_only",
        missing_inputs=missing_inputs,
        confirmations=[],
        actions=actions,
        stop_conditions=["scope_blocked", "missing_required_input", "operator_cancelled"],
        success_criteria=["operation_plan_validated", "no_execution_performed"],
        created_by=req.created_by,
    )
    metadata = {
        "agent": known_agents[agent_name],
        "context_pack": context_row,
        "planner_notes": notes,
    }
    return plan, metadata
def _strict_local_agent_json_object(raw_output: str, *, max_output_bytes: int) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    raw = raw_output or ""
    if len(raw.encode("utf-8")) > max_output_bytes:
        return None, ["planner_output_exceeds_max_output_bytes"]
    text = raw.strip()
    if not text:
        return None, ["planner_output_empty"]
    if text.startswith("```") or text.endswith("```"):
        errors.append("planner_output_must_be_exact_json_not_markdown")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        errors.append(f"planner_output_not_single_json_object:{exc.msg}")
        return None, errors
    if not isinstance(parsed, dict):
        errors.append("planner_output_top_level_must_be_object")
        return None, errors
    return parsed, errors


LOCAL_AGENT_PLAN_FIELDS = {
    "objective",
    "planner",
    "context_hash",
    "target_scope",
    "risk_tier",
    "allowed_families",
    "disallowed_families",
    "budget",
    "constraints",
    "missing_inputs",
    "confirmations",
    "actions",
    "stop_conditions",
    "success_criteria",
    "scope_receipt_id",
    "approval_receipt_id",
    "created_by",
}


def _find_hidden_local_agent_execution_requests(value: Any, path: str = "$") -> list[str]:
    hits: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).strip().lower()
            child_path = f"{path}.{normalized or '<empty>'}"
            if normalized in LOCAL_AGENT_HIDDEN_EXECUTION_KEY_FIELDS and nested not in (None, "", [], {}):
                hits.append(child_path)
            hits.extend(_find_hidden_local_agent_execution_requests(nested, child_path))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            hits.extend(_find_hidden_local_agent_execution_requests(nested, f"{path}[{index}]"))
    elif isinstance(value, str) and LOCAL_AGENT_HIDDEN_EXECUTION_PATTERN.search(value):
        hits.append(path)
    return hits


def _choose_local_agent_plan_action(context_pack: dict[str, Any], objective: str) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    allowed = {
        str(item).strip()
        for item in context_pack.get("allowed_commands", [])
        if str(item).strip()
    }
    preconditions = context_pack.get("known_preconditions") if isinstance(context_pack.get("known_preconditions"), dict) else {}
    lowered = objective.lower()
    missing_inputs: list[str] = []
    notes: list[str] = []

    if any(term in lowered for term in ("bola", "idor", "authz", "authorization", "tenant")):
        if str(preconditions.get("second_user_credentials") or "").lower() != "configured":
            missing_inputs.append("second_user_credentials")
            notes.append("missing_second_user_auth")
        if "asm.gaps" in allowed:
            return ([{"command": "asm.gaps", "risk_tier": "read_only", "parameters": {}, "reason": "inspect authz prerequisites before any gated BOLA work"}], missing_inputs, notes)

    if any(term in lowered for term in ("sqli", "sql injection", "xss", "coverage", "covered", "asm")) and "asm.gaps" in allowed:
        return ([{"command": "asm.gaps", "risk_tier": "read_only", "parameters": {}, "reason": "review coverage gaps before queueing any gated work"}], missing_inputs, notes)

    if "target.get" in allowed:
        return ([{"command": "target.get", "risk_tier": "read_only", "parameters": {}, "reason": "inspect target facts before planning"}], missing_inputs, notes)
    if "operation_plan.preview" in allowed:
        return ([{"command": "operation_plan.preview", "risk_tier": "read_only", "parameters": {}, "reason": "preview operation plan without execution"}], missing_inputs, notes)
    if "agent_context_pack.list" in allowed:
        return ([{"command": "agent_context_pack.list", "risk_tier": "read_only", "parameters": {}, "reason": "inspect available context packs"}], missing_inputs, notes)
    return ([], ["allowed_read_only_command"], ["no_allowed_read_only_command"])
LOCAL_AGENT_HIDDEN_EXECUTION_KEY_FIELDS = {
    "argv",
    "cmd",
    "command_line",
    "executable",
    "raw_command",
    "shell",
}


LOCAL_AGENT_HIDDEN_EXECUTION_PATTERN = re.compile(
    r"(?i)\b("
    r"run_shell|execute_shell|curl_this_url|execute_python|run_sqlmap|"
    r"subprocess|os\.system|bash\s+-c|sh\s+-c|python3?\s+-c|"
    r"sqlmap|ffuf|dalfox"
    r")\b"
)




