"""Deterministic contracts for bounded adaptive research episodes.

The planner may select one catalog action or stop. This module never performs
I/O and never grants execution authority; API orchestration applies these
contracts before delegating an accepted action to the Command Arsenal gateway.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


RESEARCH_EPISODE_VERSION = "research-episode-2026-07-11.v1"
RESEARCH_OBSERVATION_VERSION = "observation-pack-2026-07-11.v1"
RESEARCH_DECISION_VERSION = "decision-episode-2026-07-11.v1"

RISK_TIER_ORDER = {
    "read_only": 0,
    "passive": 1,
    "active": 2,
    "intrusive": 3,
    "credential": 4,
    "dangerous": 5,
}

TERMINAL_EPISODE_STATUSES = {
    "completed",
    "cancelled",
    "failed",
    "budget_exhausted",
    "blocked",
}

# Keep the initial actuator narrow. Commands outside these sets remain visible
# to operators through the Arsenal catalog but cannot be selected by a research
# planner.
READ_ONLY_RESEARCH_COMMANDS = {
    "asm.activity",
    "asm.gaps",
    "deployment.decision",
    "finding.get",
    "finding.list",
    "hypothesis.generate_from_graph",
    "hypothesis.list",
    "hypothesis.situation_report",
    "scan.result",
    "target.get",
    "target.principal_matrix",
    "target.principals",
}

GATED_RESEARCH_COMMANDS = {
    "asm.improve",
    "asm.recon",
    "asm.test",
    "finding.retest",
    "experiment.http_diff",
    "experiment.workflow",
    "scan.focused_family",
}

TARGET_BOUND_COMMANDS = {
    "asm.activity",
    "asm.gaps",
    "asm.improve",
    "asm.recon",
    "asm.test",
    "deployment.decision",
    "experiment.http_diff",
    "experiment.workflow",
    "finding.list",
    "hypothesis.generate_from_graph",
    "hypothesis.list",
    "hypothesis.situation_report",
    "scan.focused_family",
    "target.get",
    "target.principal_matrix",
    "target.principals",
}

DEFAULT_BUDGET_LIMITS = {
    "steps": 5,
    "actions": 5,
    "active_actions": 0,
    "requests": 0,
    "wire_requests": 0,
    "seconds": 300,
    "model_tokens": 30000,
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def normalize_budget_limits(value: Any, *, max_steps: int) -> dict[str, int]:
    raw = value if isinstance(value, dict) else {}
    bounded_steps = max(1, min(int(max_steps or DEFAULT_BUDGET_LIMITS["steps"]), 25))
    limits = dict(DEFAULT_BUDGET_LIMITS)
    limits["steps"] = bounded_steps
    limits["actions"] = bounded_steps
    ceilings = {
        "steps": 25,
        "actions": 25,
        "active_actions": 10,
        "requests": 500,
        "wire_requests": 3600,
        "seconds": 3600,
        "model_tokens": 500000,
    }
    for key, ceiling in ceilings.items():
        if key not in raw:
            continue
        try:
            parsed = int(raw[key])
        except (TypeError, ValueError):
            continue
        limits[key] = max(0, min(parsed, ceiling))
    limits["steps"] = min(limits["steps"], bounded_steps)
    limits["actions"] = min(limits["actions"], limits["steps"])
    return limits


def normalize_budget_used(value: Any) -> dict[str, int]:
    raw = value if isinstance(value, dict) else {}
    return {
        key: max(0, int(raw.get(key) or 0))
        for key in ("steps", "actions", "active_actions", "requests", "wire_requests", "seconds", "model_tokens")
    }


def remaining_budget(limits: Any, used: Any) -> dict[str, int]:
    normalized_limits = normalize_budget_limits(limits, max_steps=int((limits or {}).get("steps") or 5))
    normalized_used = normalize_budget_used(used)
    return {
        key: max(0, int(normalized_limits.get(key) or 0) - int(normalized_used.get(key) or 0))
        for key in normalized_limits
    }


def action_cost(command: dict[str, Any]) -> dict[str, int]:
    risk = str(command.get("risk_tier") or "read_only")
    timeout = max(1, min(int(command.get("timeout_seconds") or 30), 600))
    active = 1 if RISK_TIER_ORDER.get(risk, 99) >= RISK_TIER_ORDER["active"] else 0
    requests = max(1, int(command.get("request_cost") or 1)) if active else 0
    # experiment.workflow is always executed twice -- the initial run plus an independent trusted
    # replay at promotion -- so reserve the worst-case two-run request/time budget up front instead
    # of under-reserving by half and letting a hunt overrun its request/time cap.
    runs = 2 if str(command.get("name") or "") == "experiment.workflow" else 1
    return {
        "steps": 1,
        "actions": 1,
        "active_actions": active,
        "requests": requests * runs,
        "seconds": timeout * runs,
        "model_tokens": 0,
    }


def budget_violations(limits: Any, used: Any, cost: Any) -> list[str]:
    remaining = remaining_budget(limits, used)
    return [
        f"budget_exhausted:{key}"
        for key, amount in (cost or {}).items()
        if int(amount or 0) > int(remaining.get(key) or 0)
    ]


def apply_cost(used: Any, cost: Any) -> dict[str, int]:
    result = normalize_budget_used(used)
    for key in result:
        result[key] += max(0, int((cost or {}).get(key) or 0))
    return result


def command_projection(
    command: dict[str, Any],
    *,
    max_risk_tier: str,
    has_approval: bool,
    execution_feature_enabled: bool,
) -> dict[str, Any]:
    name = str(command.get("name") or "")
    status = str(command.get("status") or "")
    risk = str(command.get("risk_tier") or "read_only")
    reasons: list[str] = []
    supported = name in READ_ONLY_RESEARCH_COMMANDS or name in GATED_RESEARCH_COMMANDS
    if not supported:
        reasons.append("not_research_agent_supported")
    if status not in {"read_only", "dry_run", "gated"}:
        reasons.append(f"catalog_status:{status or 'unknown'}")
    if RISK_TIER_ORDER.get(risk, 99) > RISK_TIER_ORDER.get(max_risk_tier, -1):
        reasons.append("risk_exceeds_episode")
    if name in GATED_RESEARCH_COMMANDS:
        if not has_approval:
            reasons.append("approval_receipt_missing")
        if not execution_feature_enabled:
            reasons.append("execution_feature_disabled")
    return {
        "name": name,
        "status": status,
        "risk_tier": risk,
        "description": command.get("description"),
        "parameters_schema": command.get("parameters_schema") or {},
        "required_confirmations": list(command.get("required_confirmations") or []),
        "proposable": supported and not any(
            reason.startswith("catalog_status:") or reason == "risk_exceeds_episode"
            for reason in reasons
        ),
        "currently_executable": not reasons,
        "blocked_by": reasons,
    }


def normalize_decision(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    action = raw.get("action") if isinstance(raw.get("action"), dict) else {}
    return {
        "decision_version": str(raw.get("decision_version") or RESEARCH_DECISION_VERSION),
        "decision": str(raw.get("decision") or "").strip(),
        "observation_id": str(raw.get("observation_id") or "").strip(),
        "context_hash": str(raw.get("context_hash") or "").strip().lower(),
        "hypothesis_id": str(raw.get("hypothesis_id") or "").strip() or None,
        "action": {
            "command": str(action.get("command") or "").strip(),
            "parameters": action.get("parameters") if isinstance(action.get("parameters"), dict) else {},
        },
        "expected_signal": str(raw.get("expected_signal") or "").strip()[:2000],
        "falsifier": str(raw.get("falsifier") or "").strip()[:2000],
        "reason": str(raw.get("reason") or "").strip()[:2000],
        "confidence": max(0.0, min(float(raw.get("confidence") or 0.0), 1.0)),
        "requested_input": str(raw.get("requested_input") or "").strip()[:2000] or None,
        "stop_reason": str(raw.get("stop_reason") or "").strip()[:500] or None,
    }


def validate_decision(
    value: Any,
    *,
    episode: dict[str, Any],
    observation: dict[str, Any],
    command_catalog: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[str], list[str], dict[str, Any] | None]:
    decision = normalize_decision(value)
    errors: list[str] = []
    warnings: list[str] = []
    cost: dict[str, Any] | None = None

    if decision["decision_version"] != RESEARCH_DECISION_VERSION:
        errors.append("decision_version_unsupported")
    if decision["observation_id"] != str(observation.get("id") or ""):
        errors.append("observation_id_mismatch")
    if decision["context_hash"] != str(observation.get("context_hash") or "").lower():
        errors.append("context_hash_mismatch")
    if decision["decision"] not in {"execute_action", "request_input", "stop"}:
        errors.append("decision_type_invalid")

    if decision["decision"] == "execute_action":
        command_name = decision["action"]["command"]
        command = command_catalog.get(command_name)
        if not command:
            errors.append(f"unknown_command:{command_name}")
        allowed = {
            str(item.get("name"))
            for item in observation.get("proposable_commands", [])
            if isinstance(item, dict) and item.get("proposable")
        }
        if command_name not in allowed:
            errors.append(f"command_not_proposable:{command_name}")
        if command:
            risk = str(command.get("risk_tier") or "read_only")
            if RISK_TIER_ORDER.get(risk, 99) > RISK_TIER_ORDER.get(str(episode.get("max_risk_tier") or "read_only"), -1):
                errors.append("risk_exceeds_episode")
            cost = action_cost(command)
            errors.extend(budget_violations(episode.get("budget_limits"), episode.get("budget_used"), cost))
        if not decision["expected_signal"]:
            errors.append("expected_signal_required")
        if not decision["falsifier"]:
            errors.append("falsifier_required")
        if command_name in {"experiment.http_diff", "experiment.workflow"} and not decision.get("hypothesis_id"):
            errors.append("hypothesis_id_required_for_experiment")
    elif decision["decision"] == "request_input" and not decision["requested_input"]:
        errors.append("requested_input_required")
    elif decision["decision"] == "stop" and not decision["stop_reason"]:
        errors.append("stop_reason_required")

    if not decision["reason"]:
        warnings.append("reason_empty")
    return decision, errors, warnings, cost
