from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from model_intake_agent import embedding_test_plan, parse_planner_reply, planner_prompt  # noqa: E402


def test_prompt_makes_planner_non_authoritative_and_lists_fixed_actions():
    prompt = planner_prompt("550e8400-e29b-41d4-a716-446655440000", "review model", 12)
    assert "never an admission authority" in prompt
    assert "execute commands" in prompt
    assert "validate_runner_plan" in prompt
    assert "promote a submission" in prompt


def test_parser_accepts_only_fixed_bounded_actions():
    parsed = parse_planner_reply(
        '```json\n{"tool_calls":[{"name":"inspect_submission","arguments":{}}]}\n```'
    )
    assert parsed == {
        "done": False,
        "tool_calls": [{"name": "inspect_submission", "arguments": {}}],
    }
    with pytest.raises(ValueError, match="fixed catalog"):
        parse_planner_reply(
            '```json\n{"tool_calls":[{"name":"run_command","arguments":{"command":"id"}}]}\n```'
        )


def test_parser_rejects_authority_claim_and_multiple_payloads():
    with pytest.raises(ValueError, match="forbidden authority"):
        parse_planner_reply('```json\n{"done":true,"approved":true}\n```')
    with pytest.raises(ValueError, match="exactly one"):
        parse_planner_reply('```json\n{"done":true}\n```\n```json\n{"done":true}\n```')


def test_debrief_is_advisory_and_bounded():
    parsed = parse_planner_reply(
        '```json\n{"done":true,"assessment":"Evidence is incomplete.",'
        '"recommendations":["Run the fixed runtime profile."],"abstained":true}\n```'
    )
    assert parsed["done"] is True
    assert parsed["abstained"] is True


def test_embedding_plan_has_security_quality_and_no_admission_effect():
    plan = embedding_test_plan({"use_case": "code knowledge graph", "languages": ["Python", "Go"]})
    assert "retrieval relevance on an owner-approved representative corpus" in plan["required_suites"]
    assert "cross-tenant data isolation in the deployed vector store" in plan["required_suites"]
    assert plan["admission_effect"].startswith("none_until")
