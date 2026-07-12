import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

import research_agent as agent  # noqa: E402


def _command(name="asm.gaps", risk="read_only", status="read_only"):
    return {
        "name": name,
        "status": status,
        "risk_tier": risk,
        "description": "test",
        "parameters_schema": {"target_id": {"type": "string"}},
        "required_confirmations": [],
        "timeout_seconds": 20,
    }


def _episode(**overrides):
    payload = {
        "max_risk_tier": "read_only",
        "budget_limits": agent.normalize_budget_limits({}, max_steps=5),
        "budget_used": agent.normalize_budget_used({}),
    }
    payload.update(overrides)
    return payload


def _observation(command_name="asm.gaps"):
    return {
        "id": "11111111-1111-4111-8111-111111111111",
        "context_hash": "a" * 64,
        "proposable_commands": [{"name": command_name, "proposable": True}],
    }


def _decision(command_name="asm.gaps"):
    return {
        "decision_version": agent.RESEARCH_DECISION_VERSION,
        "decision": "execute_action",
        "observation_id": "11111111-1111-4111-8111-111111111111",
        "context_hash": "a" * 64,
        "action": {"command": command_name, "parameters": {}},
        "expected_signal": "coverage gaps are present",
        "falsifier": "all obligations are already closed",
        "reason": "inspect coverage first",
        "confidence": 0.8,
    }


def test_read_only_decision_is_accepted_with_bounded_cost():
    command = _command()
    decision, errors, warnings, cost = agent.validate_decision(
        _decision(),
        episode=_episode(),
        observation=_observation(),
        command_catalog={"asm.gaps": command},
    )

    assert errors == []
    assert decision["action"]["command"] == "asm.gaps"
    assert cost == {
        "steps": 1,
        "actions": 1,
        "active_actions": 0,
        "requests": 0,
        "seconds": 20,
        "model_tokens": 0,
    }
    assert warnings == []


def test_stale_observation_and_missing_falsifier_fail_closed():
    candidate = _decision()
    candidate["context_hash"] = "b" * 64
    candidate["falsifier"] = ""

    _, errors, _, _ = agent.validate_decision(
        candidate,
        episode=_episode(),
        observation=_observation(),
        command_catalog={"asm.gaps": _command()},
    )

    assert "context_hash_mismatch" in errors
    assert "falsifier_required" in errors


def test_risk_escalation_and_active_budget_exhaustion_fail_closed():
    command = _command("asm.test", risk="active", status="gated")
    _, errors, _, _ = agent.validate_decision(
        _decision("asm.test"),
        episode=_episode(max_risk_tier="read_only"),
        observation=_observation("asm.test"),
        command_catalog={"asm.test": command},
    )

    assert "risk_exceeds_episode" in errors
    assert "budget_exhausted:active_actions" in errors


def test_gated_command_projection_explains_missing_authority():
    projected = agent.command_projection(
        _command("asm.test", risk="active", status="gated"),
        max_risk_tier="active",
        has_approval=False,
        execution_feature_enabled=False,
    )

    assert projected["proposable"] is True
    assert projected["currently_executable"] is False
    assert projected["blocked_by"] == ["approval_receipt_missing", "execution_feature_disabled"]


def test_budget_application_is_monotonic_and_bounded():
    limits = agent.normalize_budget_limits({"actions": 2, "seconds": 30}, max_steps=2)
    used = agent.apply_cost({}, {"steps": 1, "actions": 1, "seconds": 20})

    assert agent.remaining_budget(limits, used)["actions"] == 1
    assert agent.budget_violations(limits, used, {"actions": 1, "seconds": 11}) == ["budget_exhausted:seconds"]


def test_only_explicit_command_sets_can_be_research_actuators():
    assert "asm.gaps" in agent.READ_ONLY_RESEARCH_COMMANDS
    assert "asm.test" in agent.GATED_RESEARCH_COMMANDS
    assert "authz.promote_replay_finding" not in agent.GATED_RESEARCH_COMMANDS
    assert "target.principal_matrix.record" not in agent.GATED_RESEARCH_COMMANDS


def test_http_experiment_reserves_worst_case_request_budget():
    command = _command("experiment.http_diff", risk="active", status="gated")
    command["request_cost"] = 4

    assert agent.action_cost(command)["requests"] == 4
    assert "experiment.http_diff" in agent.GATED_RESEARCH_COMMANDS
    assert "experiment.http_diff" in agent.TARGET_BOUND_COMMANDS
