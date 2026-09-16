"""AI Gate boundary entrypoint. All credentials arrive through worker hydration."""

from __future__ import annotations

import asyncio
import copy
import json
import re
from typing import Any, Callable
from urllib.parse import urlsplit

from ..budget import RequestBudget, TokenBudget
from . import PACK
from .contract import BoundaryContract, ContractError, relative_path
from .execution import BoundaryScenario
from .report import result_for
from .transport import BoundaryTransport, BoundaryTransportError, budget_limit, origin_of


def prepare(target_url: str, options: dict[str, Any], header_builder: Callable) -> tuple:
    target = copy.deepcopy(options.get("ai_target"))
    if not isinstance(target, dict):
        raise ContractError("hydrated_ai_target_required")
    if options.get("ai_probe_pack") != PACK:
        raise ContractError("explicit_boundary_probe_pack_required")
    environment = str(options.get("ai_environment") or "preview").strip().lower()
    if target.get("production_mode") is True or environment not in {"preview", "staging", "lab", "test"}:
        raise ContractError("boundary_alpha_does_not_support_production")
    if target.get("target_type", "api_chat") not in {"api_chat", "rag", "ai_rag", "agent_trace"}:
        raise ContractError("boundary_alpha_requires_a_json_chat_api")
    if target.get("streaming_mode") not in {None, "", "json"} or target.get("method", "POST") != "POST":
        raise ContractError("boundary_alpha_requires_nonstreaming_post_chat")
    metadata = target.get("metadata_json") or {}
    contract = BoundaryContract.parse(metadata.get("boundary_contract"))
    endpoint = target.get("endpoint_url") or target_url
    origin = origin_of(endpoint)
    if origin_of(target_url) != origin:
        raise ContractError("chat_origin_differs_from_authorized_target")
    chat_path = relative_path(urlsplit(endpoint).path or "/")
    template = target.get("request_template")
    if not isinstance(template, dict):
        raise ContractError("json_chat_request_template_required")
    serialized = json.dumps(template)
    if len(serialized) > 16000 or "{{prompt}}" not in serialized or "{{session_id}}" not in serialized:
        raise ContractError("bounded_template_requires_prompt_and_fresh_session_id")
    headers: dict[str, dict[str, str]] = {}
    principals = target.get("principals")
    if not isinstance(principals, list):
        raise ContractError("two_hydrated_principals_required")
    for identity in (contract.owner, contract.attacker):
        matching = [p for p in principals if isinstance(p, dict) and p.get("role") == identity.role]
        if len(matching) != 1:
            raise ContractError("principal_role_missing_or_ambiguous")
        credential = matching[0].get("credential")
        if not isinstance(credential, dict) or credential.get("auth_kind") not in {
            "bearer", "basic_auth", "api_key_header", "custom_header", "cookie", "multi_header",
        }:
            raise ContractError("supported_hydrated_principal_credential_required")
        # No shared target auth/header template can shadow a selected principal.
        selected = header_builder({"credential": credential})
        if not selected or any(not isinstance(k, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", k)
                               or k.lower() in {"host", "content-length", "transfer-encoding", "connection", "proxy-authorization"}
                               for k in selected):
            raise ContractError("unsafe_or_empty_principal_headers")
        if any(not isinstance(v, str) or not v or "\r" in v or "\n" in v for v in selected.values()):
            raise ContractError("invalid_principal_header_value")
        headers[identity.role] = selected
    normalized = [{k.lower(): v for k, v in value.items()} for value in headers.values()]
    if normalized[0] == normalized[1]:
        raise ContractError("identical_principal_credentials")
    return target, contract, origin, chat_path, template, headers


def redact_fixture_markers(value: Any) -> Any:
    if isinstance(value, str):
        return re.sub(r"ssb_[0-9a-f]{48}", "[REDACTED_SYNTHETIC_MARKER]", value)
    if isinstance(value, dict):
        return {key: redact_fixture_markers(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_fixture_markers(item) for item in value]
    return value


async def execute_boundary(target_url: str, options: dict[str, Any], *, header_builder: Callable,
                           aiohttp_module: Any = None) -> dict[str, Any]:
    """Execute the scenario; the caller attaches the shared AI Gate manifest."""
    if aiohttp_module is None:
        import aiohttp as aiohttp_module
    target, contract, origin, chat_path, template, headers = prepare(target_url, options, header_builder)
    requests = RequestBudget(budget_limit(target.get("request_budget"), 64, 1000))
    tokens = TokenBudget(budget_limit(target.get("token_budget"), 32000, 1000000))
    rate = target.get("rate_limit_rps", 2)
    if type(rate) not in {int, float}:
        raise ContractError("invalid_rate_limit")
    timeout = aiohttp_module.ClientTimeout(total=15, connect=5)
    async with aiohttp_module.ClientSession(timeout=timeout, cookie_jar=aiohttp_module.DummyCookieJar(),
                                           trust_env=False) as session:
        transport = BoundaryTransport(session, origin=origin, headers=headers, requests=requests,
                                      tokens=tokens, rate_limit_rps=float(rate))
        scenario = BoundaryScenario(contract, transport, chat_path=chat_path, request_template=template)
        try:
            async with asyncio.timeout(180):
                await scenario.execute()
        except asyncio.CancelledError:
            raise  # Cancellation never becomes a completed/clean assessment.
        except (ContractError, BoundaryTransportError) as exc:
            scenario.errors.append(str(exc))
        except TimeoutError:
            scenario.errors.append("boundary_wall_clock_limit")
        except RuntimeError:
            scenario.errors.append("boundary_request_budget_or_runtime_failure")
        except Exception as exc:
            scenario.errors.append(type(exc).__name__)
        return result_for(scenario.summary(), target=target,
            environment=str(options.get("ai_environment") or "preview").strip().lower(),
            request_usage=requests.to_dict(), token_usage=tokens.to_dict(), records=transport.records)


async def run_boundary_scan(target_url: str, options: dict[str, Any]) -> dict[str, Any]:
    """AI Gate worker integration, reusing the existing scoring and manifest."""
    try:
        from ai_gate.targets.rest_json import build_headers
        import ai_gate_scan as shared
    except ModuleNotFoundError:
        from ..targets.rest_json import build_headers
        from ... import ai_gate_scan as shared
    from .catalog import boundary_probe

    result = await execute_boundary(target_url, options, header_builder=build_headers)
    gate = result["ai_gate"]
    gate["scan_profile"] = str(options.get("ai_scan_profile") or "standard")
    probe = boundary_probe()
    summary = gate["boundary"]
    if summary["coverage_complete"] or result["findings"]:
        score, grade = shared._score_result(result["findings"])
        result["result"].update(score=score, grade=grade)
    decision, rationale = shared._compute_decision(result["findings"], gate["decision"]["environment"])
    if decision == "allow" and summary["state"] != "passed":
        decision, rationale = "needs_approval", "Boundary verification is incomplete; no security pass was established."
    gate["decision"].update(decision=decision, rationale=rationale)
    # Existing manifest/attestation pipeline owns signing and release enforcement.
    budget = TokenBudget(gate["usage"]["token_budget"])
    budget.input_tokens = gate["usage"]["input_tokens_estimated"]
    budget.output_tokens = gate["usage"]["output_tokens_estimated"]
    gate["evidence_manifest"] = shared._build_evidence_manifest(
        target=redact_fixture_markers(options["ai_target"]), options=options, planned_probes=(probe,),
        executed_probes=[probe], transcripts=gate["transcripts"], findings=result["findings"],
        control_evidence={}, execution_plan=gate["execution_plan"], coverage_matrix=gate["coverage_matrix"],
        token_budget=budget, judge_config=None, semantic_judge_config=None,
    )
    return result
