"""Keyless, non-authoritative planner contract for Model Intake."""

from __future__ import annotations

import json
import re
from typing import Any


ACTION_CATALOG = {
    "inspect_submission": "Read server-owned subjects, evidence states, and runner jobs.",
    "inspect_readiness": "Read scanner, provider, and physical runner readiness.",
    "validate_runner_plan": "Validate an exact proposed deployment bundle and fixed runner operation without queueing it.",
    "draft_embedding_test_plan": "Generate a deterministic security and quality test-plan skeleton for the stated use case.",
    "recommend_follow_up": "Record one bounded recommendation for operator review; it does not execute.",
}

FORBIDDEN_AUTHORITY_KEYS = {
    "approved", "approval", "approve", "admitted", "admission", "allow",
    "exception", "override", "promote", "promotion", "policy_override",
    "trusted_key", "trust_anchor", "disable_scanner", "command", "argv",
}


def planner_prompt(submission_id: str, objective: str, action_budget: int) -> str:
    actions = "\n".join(f"- {name}: {description}" for name, description in ACTION_CATALOG.items())
    return f"""You are the optional keyless Model Intake investigation planner for submission {submission_id}.

Objective: {objective}
Remaining bounded actions: {action_budget}

You improve investigation and explanation. You are never an admission authority. You cannot approve a
model, modify authoritative manifests/evidence, trust keys, disable required checks, grant exceptions,
promote a submission, turn INCOMPLETE into PASS, or execute commands. Deterministic policy remains final.

Available actions:
{actions}

Reply with exactly one fenced JSON object. To inspect or plan:
```json
{{"tool_calls":[{{"name":"inspect_submission","arguments":{{}}}}]}}
```
To finish:
```json
{{"done":true,"assessment":"...","recommendations":["..."],"abstained":false}}
```
Use evidence returned by tools, identify uncertainty, and abstain when evidence is insufficient.
"""


def parse_planner_reply(reply: str, *, max_calls: int = 5) -> dict[str, Any]:
    if not isinstance(reply, str) or not reply.strip() or len(reply.encode()) > 64_000:
        raise ValueError("planner reply is empty or oversized")
    matches = re.findall(r"```json\s*(\{.*?\})\s*```", reply, flags=re.DOTALL | re.IGNORECASE)
    if len(matches) != 1:
        raise ValueError("planner reply must contain exactly one fenced JSON object")
    try:
        value = json.loads(matches[0])
    except json.JSONDecodeError as exc:
        raise ValueError("planner reply JSON is invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("planner reply must be an object")
    forbidden = FORBIDDEN_AUTHORITY_KEYS.intersection(value)
    if forbidden:
        raise ValueError(f"planner reply attempts forbidden authority: {','.join(sorted(forbidden))}")
    if value.get("done") is True:
        if set(value) - {"done", "assessment", "recommendations", "abstained"}:
            raise ValueError("planner debrief contains unsupported fields")
        assessment = str(value.get("assessment") or "").strip()
        recommendations = value.get("recommendations")
        if len(assessment) > 20_000 or not isinstance(recommendations, list) or len(recommendations) > 50:
            raise ValueError("planner debrief exceeds its bounds")
        if any(not isinstance(item, str) or len(item) > 2_000 for item in recommendations):
            raise ValueError("planner recommendation is invalid")
        return {
            "done": True,
            "assessment": assessment,
            "recommendations": recommendations,
            "abstained": value.get("abstained") is True,
        }
    calls = value.get("tool_calls")
    if set(value) != {"tool_calls"} or not isinstance(calls, list) or not 1 <= len(calls) <= max_calls:
        raise ValueError("planner reply must contain one bounded tool_calls list")
    normalized = []
    for call in calls:
        if not isinstance(call, dict) or set(call) != {"name", "arguments"}:
            raise ValueError("planner action shape is invalid")
        name = str(call.get("name") or "")
        arguments = call.get("arguments")
        if name not in ACTION_CATALOG or not isinstance(arguments, dict):
            raise ValueError("planner action is not in the fixed catalog")
        if any(key in FORBIDDEN_AUTHORITY_KEYS for key in arguments):
            raise ValueError("planner action arguments attempt forbidden authority")
        normalized.append({"name": name, "arguments": arguments})
    return {"done": False, "tool_calls": normalized}


def embedding_test_plan(arguments: dict[str, Any]) -> dict[str, Any]:
    use_case = str(arguments.get("use_case") or "corporate vector embeddings")[:500]
    languages = [str(item)[:80] for item in arguments.get("languages", [])[:20]] if isinstance(arguments.get("languages"), list) else []
    return {
        "schema_version": "model-intake-embedding-test-plan/v1",
        "use_case": use_case,
        "languages": languages,
        "required_suites": [
            "fixed known-answer vectors bound by SHA-256",
            "repeatability across cold starts",
            "shape, dtype, finite-value, and normalization invariants",
            "retrieval relevance on an owner-approved representative corpus",
            "code-language and long-input coverage",
            "resource ceilings and timeout behavior",
            "cross-tenant data isolation in the deployed vector store",
            "deletion, retention, cache authorization, and logging controls",
        ],
        "admission_effect": "none_until_generated_evidence_and_deterministic_policy_accept_it",
    }


__all__ = ["ACTION_CATALOG", "embedding_test_plan", "parse_planner_reply", "planner_prompt"]
