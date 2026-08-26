"""Agent routes.

Extracted verbatim from the api.py monolith. Covers the keyless agent-driven
surface: tool readiness, per-target context packs, bounded tool execution, the
durable hunt-session handshake the external coding agent drives, the two-tier
suspected/verified finding read, and the bridge that hands a suspected finding
to the deterministic verifier.

Two-tier is the whole point of this module: agent output may create notes,
observations, and evidence-backed candidates, but only a deterministic proof
contract promotes a finding to verified. The promotion path is injected, not
reimplemented here.
"""

from __future__ import annotations

import asyncio
import math
import urllib.parse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import time
from typing import Any, Callable, Mapping, Optional, Sequence
import uuid

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

try:
    from action_scope import _decode_json_value
    from ai_gate.targets.widget_playwright import logger
    from api_utils import _json_safe_row, _optional_uuid, _uuid_or_400, utc_now_iso
    from capabilities.http import execute_bound_http_request
    from http_experiment import MAX_REDIRECT_HOPS, compare_summaries
    from hunt.run_service import agent_tools
    from retest_contract import build_retest_job_payload, normalize_retest_type, validate_retest_job_payload
    from runtime.models import TargetBinding
    from serialization import row_to_dict
    from workflow_experiment import WorkflowContractError
    from arsenal_routes import router as _arsenal_routes
    from devices import router as _devices
    from finding_routes import router as _finding_routes
    from fleet_routes import router as _fleet_routes
    from settings_routes import router as _settings_routes
    from targets import router as _targets
except ModuleNotFoundError:  # package import in host-side tests
    from ..action_scope import _decode_json_value
    from ..ai_gate.targets.widget_playwright import logger
    from ..api_utils import _json_safe_row, _optional_uuid, _uuid_or_400, utc_now_iso
    from ..capabilities.http import execute_bound_http_request
    from ..http_experiment import MAX_REDIRECT_HOPS, compare_summaries
    from ..hunt.run_service import agent_tools
    from ..retest_contract import build_retest_job_payload, normalize_retest_type, validate_retest_job_payload
    from ..runtime.models import TargetBinding
    from ..serialization import row_to_dict
    from ..workflow_experiment import WorkflowContractError
    from ..arsenal_routes import router as _arsenal_routes
    from ..devices import router as _devices
    from ..finding_routes import router as _finding_routes
    from ..fleet_routes import router as _fleet_routes
    from ..settings_routes import router as _settings_routes
    from ..targets import router as _targets

try:
    import agent_budget
    import agent_context_pack
    import agent_loop
    import agent_provenance
    import agent_text_toolcalls
    import family_proof
    import investigation_candidates
    import source_ingest
    from evidence_triage import redact_finding_evidence as _redact_finding_evidence
    from hunt.interaction_router import _AGENT_MUTATING_VERIFY_FAMILIES, _agent_tool_query_kb
    from target_dedupe import canonical_web_host as _canonical_web_host
except ModuleNotFoundError:  # package import in host-side tests
    from .. import (
        agent_budget,
        agent_context_pack,
        agent_loop,
        agent_provenance,
        agent_text_toolcalls,
        family_proof,
        investigation_candidates,
        source_ingest,
    )
    from ..evidence_triage import redact_finding_evidence as _redact_finding_evidence
    from ..hunt.interaction_router import _AGENT_MUTATING_VERIFY_FAMILIES, _agent_tool_query_kb
    from ..target_dedupe import canonical_web_host as _canonical_web_host


router = APIRouter()

_pool_provider: Callable[[], Any] | None = None
_deps: dict[str, Callable[..., Any]] = {}


_AGENT_HUNT_DEFAULT_ITERATIONS = 20
AGENT_TOOL_WORKER_BUILD_REGISTRY_KEY = "shakerscan:agent_tool_worker_build"
_AGENT_MAX_TOOLS_PER_TURN = 12
_AGENT_TOOL_HTTP_TIMEOUT_SECONDS = 15
_AGENT_HUNT_TRANSCRIPT_SOFT_CAP = 120
_AGENT_AUTO_VERIFY_LIMIT = 8
_AGENT_UNVERIFIABLE_FAMILY_REPORT_LIMIT = 10
_AGENT_AUTO_VERIFY_SKIP_REPORT_LIMIT = 10
_AGENT_HUNT_MAX_ITERATIONS = 40


def configure_agent_router(
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



def _ai_ops_execute_enabled(*a: Any, **k: Any) -> Any:
    return _get("_ai_ops_execute_enabled")(*a, **k)


def _load_effective_ai_settings(*a: Any, **k: Any) -> Any:
    return _get("_load_effective_ai_settings")(*a, **k)


def _provision_same_origin_url(*a: Any, **k: Any) -> Any:
    return _get("_provision_same_origin_url")(*a, **k)


async def _require_approval_receipt_if_policy_enabled(*a: Any, **k: Any) -> Any:
    return await _get("_require_approval_receipt_if_policy_enabled")(*a, **k)


async def _validate_approval_receipt_for_action(*a: Any, **k: Any) -> Any:
    return await _get("_validate_approval_receipt_for_action")(*a, **k)


async def _verify_suspected_finding_workflow(*a: Any, **k: Any) -> Any:
    return await _get("_verify_suspected_finding_workflow")(*a, **k)


def current_scanner_version(*a: Any, **k: Any) -> Any:
    return _get("current_scanner_version")(*a, **k)


def enqueue_job(*a: Any, **k: Any) -> Any:
    return _get("enqueue_job")(*a, **k)


def expected_build_fingerprint(*a: Any, **k: Any) -> Any:
    return _get("expected_build_fingerprint")(*a, **k)


def get_redis(*a: Any, **k: Any) -> Any:
    return _get("get_redis")(*a, **k)


def worker_build_current(*a: Any, **k: Any) -> Any:
    return _get("worker_build_current")(*a, **k)


__all__ = ["configure_agent_router", "router"]
class AgentToolExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: str = Field(min_length=1, max_length=64)
    arguments: dict[str, Any] = Field(default_factory=dict)
    approval_receipt_id: Optional[str] = None


class AgentHuntRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    objective: str = Field(default="", max_length=2000)
    max_iterations: int = Field(default=_AGENT_HUNT_DEFAULT_ITERATIONS, ge=1, le=_AGENT_HUNT_MAX_ITERATIONS)
    token_budget: int = Field(default=9000, ge=1000, le=24000)
    persist: bool = True
    # Persisting a SUSPECTED finding is a state change; when the operator has enabled the
    # approval-receipt policy, a hunt must carry a receipt (the app's authorization mechanism).
    approval_receipt_id: Optional[str] = None
    origin_url: Optional[str] = Field(default=None, max_length=2048)


class AgentHuntSessionStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    objective: str = Field(default="", max_length=2000)
    max_iterations: int = Field(default=_AGENT_HUNT_DEFAULT_ITERATIONS, ge=1, le=_AGENT_HUNT_MAX_ITERATIONS)
    token_budget: int = Field(default=9000, ge=1000, le=24000)
    mode: str = Field(
        default="read_only",
        pattern="^(read_only|deep_hunt)$",
        description=(
            "read_only keeps the free-form investigator passive. deep_hunt requires a "
            "target-bound credential approval and enables bounded active tools plus proof promotion."
        ),
    )
    # Optional: satisfies the approval-receipt policy when the operator has enabled it (persisting
    # SUSPECTED findings is a state change). Required for deep_hunt.
    approval_receipt_id: Optional[str] = None
    # B2 opt-in grey-box grounding: a LOCAL source directory (contained in SHAKERSCAN_SOURCE_ROOT)
    # to ingest into a security-ranked source_excerpt pack section + source-derived leads. Absent
    # -> the hunt runs black-box only (the default).
    source_dir: Optional[str] = Field(default=None, max_length=500)
    origin_url: Optional[str] = Field(
        default=None,
        max_length=2048,
        description="Concrete HTTP(S) origin on the selected target host. Defaults to the most recently scanned origin.",
    )


class AgentHuntReplyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # The session's raw planner reply: a ```json {"tool_calls":[...]} ``` block to keep hunting,
    # or a {"done":true,"findings":[...],"abstained":bool} debrief to finish. Parsed by the same
    # text-contract shim the configured_ai path uses, so there is one tool-calling contract.
    reply: str = Field(min_length=1, max_length=200_000)


class AgentVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Verification runs a gated credential-tier workflow, so a valid target-bound approval receipt
    # is required (the same authorization the menu experiment.workflow path uses).
    approval_receipt_id: str = Field(min_length=1)


@router.get("/agent/tools/readiness")
async def get_agent_tool_readiness():
    return _agent_tool_worker_readiness()


@router.get("/agent/context/{target_id}")
async def get_agent_context_pack(
    target_id: str,
    objective: str = Query(default=""),
    token_budget: int = Query(default=6000, ge=500, le=24000),
    endpoint_limit: int = Query(default=25, ge=0, le=50),
    finding_limit: int = Query(default=15, ge=0, le=25),
):
    """Reasoning-grade, token-bounded context pack for the autonomous agent.

    Assembled from Layer-1 tables (endpoint inventory, application graph, findings,
    principals, hypotheses, recent scan tech/WAF/verification rollups) through the same
    redaction path as research observations, then packed with **honest drop telemetry**
    (borrows T3MP3ST ``packContext``: always-present map, relevance ranking by objective,
    head/tail elision, explicit included/dropped lists — no silent loss). Read-only.
    """
    async with _pool().acquire() as conn:
        context_req = await _arsenal_routes._build_agent_context_pack_from_target(
            conn,
            _arsenal_routes.AgentContextPackFromTargetRequest(
                target_id=target_id,
                include_findings=True,
                include_endpoints=True,
                include_gaps=True,
                finding_limit=finding_limit,
                endpoint_limit=endpoint_limit,
                created_by="agent_context_endpoint",
            ),
        )
    context = _arsenal_routes._canonical_agent_context_pack(context_req)
    sections = _agent_context_pack_sections(context)
    pack = agent_context_pack.pack_context(
        sections,
        token_budget=token_budget,
        objective=objective,
        prior_intel=_agent_pack_compact(context.get("known_preconditions"), 400),
    )
    return {
        "target_id": context.get("target_id"),
        "objective": objective,
        "context_hash": context.get("context_hash"),
        "token_budget": token_budget,
        "sections_available": [section["key"] for section in sections],
        "pack": pack,
    }


@router.post("/agent/tools/{target_id}/execute")
async def execute_agent_tool_endpoint(target_id: str, req: AgentToolExecuteRequest):
    """Execute ONE autonomous-agent tool against a target (read-only surface: http_request
    is limited to safe methods here; state-changing writes flow through a gated research
    episode with a validated approval receipt). Same building block the ReAct loop uses."""
    target_uuid = _uuid_or_400(target_id, "target id")
    async with _pool().acquire() as conn:
        target = await conn.fetchrow("SELECT id, url, is_active FROM targets WHERE id=$1", target_uuid)
        if not target or not target["is_active"]:
            raise HTTPException(status_code=404, detail="Active target not found")
        await _require_approval_receipt_if_policy_enabled(
            conn, req.approval_receipt_id, action_name="agent.tool", risk_tier="active",
            created_by="agent_tool_endpoint",
        )
    name = str(req.tool or "").strip()
    if name not in agent_tools.CALLABLE_TOOL_NAMES:
        raise HTTPException(status_code=400, detail=f"unknown tool; allowed {sorted(agent_tools.CALLABLE_TOOL_NAMES)}")
    result = await _execute_agent_tool(
        target_uuid, str(target["url"]), name, req.arguments,
        created_by="agent_tool_endpoint", allow_write=False, allow_active=False,
        authorized_addresses=await _resolve_agent_target_addresses(str(target["url"])),
    )
    return {"target_id": str(target_uuid), "tool": name, "result": result}


@router.post("/agent/hunt/{target_id}")
async def run_agent_hunt_endpoint(target_id: str, req: AgentHuntRequest):
    """Run the autonomous LLM-driven ReAct hunt against a target (read-only tool surface:
    writes require a gated episode with an approval receipt). Synchronous, bounded. Returns
    the SUSPECTED-tier findings (provenance-gated), which of them are net-new vs the DAST
    baseline, the tool-call transcript events, and the durable run receipt id."""
    target_uuid = _uuid_or_400(target_id, "target id")
    async with _pool().acquire() as conn:
        target = await conn.fetchrow("SELECT id, url, is_active FROM targets WHERE id=$1", target_uuid)
        if not target or not target["is_active"]:
            raise HTTPException(status_code=404, detail="Active target not found")
        target_origins = await _arsenal_routes._target_web_origins(conn, target_uuid, target["url"])
        target_url = _resolve_hunt_origin(target["url"], target_origins, req.origin_url)
        await _require_approval_receipt_if_policy_enabled(
            conn, req.approval_receipt_id, action_name="agent.hunt", risk_tier="active",
            created_by="agent_hunt_endpoint",
        )
    return await _run_agent_hunt(
        target_uuid, target_url, req.objective,
        max_iterations=req.max_iterations, created_by="agent_hunt_endpoint",
        allow_write=False, allow_active=False, token_budget=req.token_budget,
        approval_receipt_id=req.approval_receipt_id, persist=req.persist,
        target_origins=target_origins,
    )


@router.post("/agent/hunt/{target_id}/session")
async def start_agent_hunt_session(target_id: str, req: AgentHuntSessionStartRequest):
    """Start a keyless, turn-based AI investigation.

    ``read_only`` preserves the passive Explorer contract. ``deep_hunt`` is the product's
    autonomous exploration + bounded-exploitation mode: it requires a live target-bound,
    credential-tier approval, enables active scanner templates, and may promote supported
    evidence through the deterministic proof moat. Raw state-changing HTTP stays disabled;
    mutations remain inside typed workflows with restoration/proof contracts.
    """
    target_uuid = _uuid_or_400(target_id, "target id")
    allow_active = req.mode == "deep_hunt"
    allow_write = False
    async with _pool().acquire() as conn:
        target = await conn.fetchrow("SELECT id, url, is_active FROM targets WHERE id=$1", target_uuid)
        if not target or not target["is_active"]:
            raise HTTPException(status_code=404, detail="Active target not found")
        target_origins = await _arsenal_routes._target_web_origins(conn, target_uuid, target["url"])
        target_url = _resolve_hunt_origin(target["url"], target_origins, req.origin_url)
        if allow_active:
            if not _ai_ops_execute_enabled():
                raise HTTPException(
                    status_code=409,
                    detail="Deep Hunt active execution is disabled by server policy",
                )
            await _validate_approval_receipt_for_action(
                conn,
                req.approval_receipt_id,
                target_url=target_url,
                target_id=target_uuid,
                action_name="agent.hunt",
                command="agent.hunt",
                risk_tier="credential",
                always_require_receipt=True,
                require_target_binding=True,
                require_expiry=True,
                created_by="deep_hunt_session",
            )
        else:
            await _require_approval_receipt_if_policy_enabled(
                conn, req.approval_receipt_id, action_name="agent.hunt", risk_tier="active",
                created_by="agent_hunt_session",
            )
    # B2: opt-in grey-box source grounding. Containment-checked local ingest (400 on any
    # boundary failure); absent -> black-box-only hunt (the default).
    source_excerpt: Optional[dict[str, Any]] = None
    if req.source_dir:
        try:
            source_excerpt = source_ingest.ingest_source(
                req.source_dir, token_budget=min(6000, req.token_budget // 2 or 1000))
        except source_ingest.SourceIngestError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    state = await _agent_seed_state(
        target_uuid, target_url, req.objective,
        created_by="deep_hunt_session" if allow_active else "agent_hunt_session",
        token_budget=req.token_budget,
        max_iterations=req.max_iterations,
        source_excerpt=source_excerpt,
        target_origins=target_origins,
    )
    # Source-derived route hints become residue-backed LEADS on the board (never findings);
    # best-effort, bounded — a hint ingest failure must never block a hunt.
    if source_excerpt and source_excerpt.get("hints"):
        try:
            async with _pool().acquire() as conn:
                for hint in list(source_excerpt["hints"])[:25]:
                    hint_req, _skip = _arsenal_routes._source_hint_to_hypothesis_request(
                        hint,
                        target_id=str(target_uuid),
                        source_label="source_ingest",
                        created_by="source_ingest",
                    )
                    if hint_req is not None:
                        await _arsenal_routes._upsert_hypothesis(conn, hint_req)
        except Exception:
            logger.exception("source-ingest lead seeding failed for target %s (best-effort)", target_uuid)
    # Keyless sessions are turn-bounded already; Deep Hunt additionally receives hard
    # request/action ceilings so a single planner reply cannot turn authorization into
    # unbounded traffic. Ceilings are set for exploration room (bucket-2 breadth) — they bound
    # only how much the discovery tier may probe, never what it may trust; the provenance gate
    # and family_proof moat are the trust boundary and are untouched. The model sees the granted
    # capability and its boundary.
    state["action_budget_limit"] = req.max_iterations * _AGENT_MAX_TOOLS_PER_TURN
    state["request_budget_limit"] = min(400, req.max_iterations * 12)
    state["wire_request_budget_limit"] = agent_budget.keyless_hunt_wire_budget(req.max_iterations)
    state["active_action_budget_limit"] = min(24, req.max_iterations)
    capability_message = (
        "Deep Hunt authorization is active for this target. You may use bounded active run_tool "
        "templates and authenticated read probes when useful. Raw POST/PUT/PATCH/DELETE requests "
        "remain blocked; use evidence-backed leads and the server's deterministic proof workflows "
        "for verification. Stay on the selected target host, name the concrete origin when switching "
        "scheme or port, and stop when the objective is answered."
        if allow_active else
        "This is a read-only discovery run. Active scanner templates and state-changing HTTP are blocked."
    )
    state["messages"].insert(1, {"role": "system", "content": capability_message})
    async with _pool().acquire() as conn:
        row = await conn.fetchrow(
            """INSERT INTO agent_hunt_runs
                   (target_id, objective, status, planner_mode, max_iterations,
                    allow_write, allow_active, approval_receipt_id, token_budget, state, created_by)
               VALUES ($1,$2,'awaiting_planner','agent',$3,$4,$5,$6,$7,$8,$9)
               RETURNING *""",
            target_uuid,
            req.objective,
            req.max_iterations,
            allow_write,
            allow_active,
            _optional_uuid(req.approval_receipt_id) if req.approval_receipt_id else None,
            req.token_budget,
            json.dumps(state, default=str),
            "deep_hunt_session" if allow_active else "agent_hunt_session",
        )
    return _agent_hunt_run_public(row)


@router.get("/agent/hunt/session/{run_id}")
async def get_agent_hunt_session(run_id: str):
    """Return the current observation (transcript + status) for a keyless hunt run."""
    async with _pool().acquire() as conn:
        row = await _agent_hunt_run_or_404(conn, run_id)
    return _agent_hunt_run_public(row)


@router.post("/agent/hunt/session/{run_id}/reply")
async def submit_agent_hunt_reply(run_id: str, req: AgentHuntReplyRequest):
    """Submit one planner reply to a keyless hunt run and get the next observation. The server
    executes any requested tools (scope-/approval-gated), advances the loop with the same
    anti-stall steering as the in-process driver, and — on a debrief or the iteration cap —
    provenance-gates and persists SUSPECTED findings (the family_proof VERIFIED moat is untouched).
    Returns the next transcript to reason over, or the finalized result when the hunt ends.

    Turn execution is split lock / execute / write so target HTTP and subprocesses never run inside
    a row-locked transaction (audit N3): a SHORT locked phase claims the turn (awaiting_planner ->
    planning), tools run UNLOCKED, then a SHORT locked phase writes the result back."""
    run_uuid = _uuid_or_400(run_id, "run id")
    planning_token = uuid.uuid4()

    # --- Phase 1: claim the turn under a short lock (no tool work here) ---
    async with _pool().acquire() as conn:
        async with conn.transaction():
            row = await _agent_hunt_run_or_404(conn, run_id, for_update=True)
            status = str(row["status"])
            # Never auto-reclaim an apparently stale in-flight turn. A slow scanner/provider can
            # legitimately exceed the stale threshold; replaying the reply would duplicate target
            # traffic. Operators can cancel the run (which clears its fencing token) and start a new
            # session. The old worker may finish locally but cannot write over cancellation.
            if status != "awaiting_planner":
                if status in ("completed", "cancelled", "failed"):
                    raise HTTPException(status_code=409, detail=f"Hunt run is {status}, not awaiting a planner reply")
                raise HTTPException(status_code=409, detail="Another reply for this run is already in flight")
            target_uuid = row["target_id"]
            target = await conn.fetchrow("SELECT url, is_active FROM targets WHERE id=$1", target_uuid)
            primary_target_url = str((target or {}).get("url") or "")
            # Stop hunting a target the operator has deactivated (soft-deleted) mid-run. (Audit P1.)
            if not primary_target_url or not (target or {}).get("is_active"):
                cancelled = await conn.fetchrow(
                    "UPDATE agent_hunt_runs SET status='cancelled', stop_reason='target_deactivated', "
                    "updated_at=NOW() WHERE id=$1 RETURNING *", run_uuid)
                return _agent_hunt_run_public(cancelled)
            approval_receipt_id = str(row["approval_receipt_id"]) if row["approval_receipt_id"] else None
            state = _decode_json_value(row["state"]) or {}
            target_url = _resolve_hunt_origin(
                primary_target_url,
                _arsenal_routes._normalized_web_origins(primary_target_url, state.get("target_origins") or []),
                state.get("target_url"),
            )
            max_iterations = int(row["max_iterations"] or _AGENT_HUNT_DEFAULT_ITERATIONS)
            if state.get("wire_request_budget_limit") is None:
                state["wire_request_budget_limit"] = agent_budget.keyless_hunt_wire_budget(max_iterations)
            allow_write = bool(row["allow_write"])
            allow_active = bool(row["allow_active"])
            # Revalidate Deep Hunt authority on every turn. An expired, revoked, wrong-target,
            # or downgraded receipt must stop active execution even when the run was valid at
            # creation time. Passive sessions retain the configurable receipt-policy behavior.
            if allow_active or allow_write:
                await _validate_approval_receipt_for_action(
                    conn,
                    approval_receipt_id,
                    target_url=target_url,
                    target_id=target_uuid,
                    action_name="agent.hunt",
                    command="agent.hunt",
                    risk_tier="credential" if allow_write or allow_active else "active",
                    always_require_receipt=True,
                    require_target_binding=True,
                    require_expiry=True,
                    created_by=f"deep_hunt_session:{run_id}",
                )
            else:
                await _require_approval_receipt_if_policy_enabled(
                    conn, approval_receipt_id, action_name="agent.hunt", risk_tier="active",
                    created_by=f"agent_hunt_session:{run_id}")
            await conn.execute(
                "UPDATE agent_hunt_runs SET status='planning', planning_token=$2, updated_at=NOW() WHERE id=$1",
                run_uuid,
                planning_token,
            )

    iteration = int(state.get("iterations") or 0)
    was_forced = bool(state.get("forced_debrief"))

    # --- Phase 2: run the turn UNLOCKED (target HTTP / subprocesses live here) ---
    try:
        # One-time compatibility migration for sessions created before DNS pinning shipped.
        # Resolution happens after the row lock is released and is then persisted with the
        # updated state; it is never refreshed for subsequent tool calls.
        if not state.get("authorized_target_addresses"):
            state["authorized_target_addresses"] = await _resolve_agent_target_addresses(target_url)

        async def _turn_cancelled() -> bool:
            async with _pool().acquire() as conn:
                return not bool(await conn.fetchval(
                    "SELECT status='planning' AND planning_token=$2 "
                    "FROM agent_hunt_runs WHERE id=$1",
                    run_uuid,
                    planning_token,
                ))

        if was_forced:
            # Forced-debrief turn: extract findings ONLY — do NOT execute any tool_calls in it. This
            # mirrors the in-process driver's forced debrief so the keyless path cannot grant an extra
            # round of tool execution beyond the declared iteration cap. (Audit N2.)
            if len(state["debug_replies"]) < 3:
                state["debug_replies"].append(req.reply[:700])
            state["messages"].append({"role": "assistant", "content": req.reply[:6000]})
            final = agent_text_toolcalls.interpret_assistant(req.reply)
            state["findings"] = final.get("findings") or []
            state["abstained"] = bool(final.get("abstained"))
            state["stop_reason"] = "forced_debrief"
            state["iterations"] = iteration + 1
            state["events"].append({"iteration": iteration, "forced_debrief": True, "findings": len(state["findings"])})
            finalize = True
        else:
            outcome = await _agent_apply_reply(
                state, req.reply, target_uuid=target_uuid, target_url=target_url,
                created_by=f"agent_hunt_session:{run_id}", allow_write=allow_write,
                allow_active=allow_active, approval_receipt_id=approval_receipt_id,
                hypothesis_id=None, iteration=iteration, max_iterations=max_iterations,
                should_stop=_turn_cancelled)
            state["iterations"] = iteration + 1
            finalize = bool(outcome["stop"])
            if outcome["stop"]:
                state["stop_reason"] = outcome["stop_reason"]
            elif state["iterations"] >= max_iterations:
                # Cap reached without a debrief: request a final-summary turn (its reply is terminal,
                # findings only), mirroring the in-process forced debrief.
                state["forced_debrief"] = True
                state["messages"].append({"role": "user", "content": agent_loop.forced_debrief_message()})
        result = None
        if finalize and state.get("stop_reason") != "cancelled":
            result = await _agent_finalize_and_persist(
                state, target_uuid=target_uuid, target_url=target_url,
                created_by=f"agent_hunt_session:{run_id}", approval_receipt_id=approval_receipt_id,
                hypothesis_id=None, persist=True, allow_write=allow_write,
                cancelled_check=_turn_cancelled,
                agent_hunt_run_id=str(run_uuid))
    except Exception:
        # Release the claim so the session can retry this turn, then surface the error.
        async with _pool().acquire() as conn:
            await conn.execute(
                "UPDATE agent_hunt_runs SET status='awaiting_planner', planning_token=NULL, updated_at=NOW() "
                "WHERE id=$1 AND status='planning' AND planning_token=$2",
                run_uuid,
                planning_token,
            )
        raise

    # --- Phase 3: write the result back under a short lock ---
    async with _pool().acquire() as conn:
        async with conn.transaction():
            if finalize:
                updated = await conn.fetchrow(
                    "UPDATE agent_hunt_runs SET status=$2, stop_reason=$3, state=$4, result=$5, "
                    "planning_token=NULL, updated_at=NOW() "
                    "WHERE id=$1 AND status='planning' AND planning_token=$6 RETURNING *",
                    run_uuid, _agent_run_final_status(state["stop_reason"]), state["stop_reason"],
                    json.dumps(state, default=str), json.dumps(result, default=str), planning_token)
            else:
                updated = await conn.fetchrow(
                    "UPDATE agent_hunt_runs SET status='awaiting_planner', state=$2, "
                    "planning_token=NULL, updated_at=NOW() "
                    "WHERE id=$1 AND status='planning' AND planning_token=$3 RETURNING *",
                    run_uuid, json.dumps(state, default=str), planning_token)
            if not updated:
                updated = await _agent_hunt_run_or_404(conn, run_id)
    return _agent_hunt_run_public(updated)


@router.post("/agent/hunt/session/{run_id}/cancel")
async def cancel_agent_hunt_session(run_id: str):
    """Cancel a keyless hunt run. No debrief findings exist until the session finishes, so this
    just marks the run cancelled; anything already probed remains in the audit trail (receipts)."""
    async with _pool().acquire() as conn:
        async with conn.transaction():
            row = await _agent_hunt_run_or_404(conn, run_id, for_update=True)
            if str(row["status"]) not in {"awaiting_planner", "planning"}:
                return _agent_hunt_run_public(row)
            updated = await conn.fetchrow(
                "UPDATE agent_hunt_runs SET status='cancelled', stop_reason='cancelled', "
                "planning_token=NULL, updated_at=NOW() "
                "WHERE id=$1 RETURNING *",
                row["id"],
            )
    return _agent_hunt_run_public(updated)


@router.get("/agent/hunt/runs")
async def list_agent_hunt_runs(
    target_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
):
    """List keyless hunt runs (newest first, summary only — no transcript) so abandoned
    awaiting_planner/planning runs are visible rather than accumulating invisibly (audit N5b).
    Filter by target_id and/or status."""
    clauses: list[str] = []
    params: list[Any] = []
    if target_id:
        params.append(_uuid_or_400(target_id, "target id"))
        clauses.append(f"target_id=${len(params)}")
    if status:
        s = str(status).strip().lower()
        if s not in ("awaiting_planner", "planning", "completed", "cancelled", "failed"):
            raise HTTPException(status_code=400, detail="invalid status filter")
        params.append(s)
        clauses.append(f"status=${len(params)}")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, target_id, objective, status, stop_reason, max_iterations, "
            "(state->>'iterations') AS iterations, created_by, created_at, updated_at "
            f"FROM agent_hunt_runs{where} ORDER BY created_at DESC LIMIT ${len(params)}",
            *params,
        )
    return {"runs": [_json_safe_row(r) for r in rows], "count": len(rows)}


@router.get("/agent/findings/{target_id}")
async def get_agent_two_tier_findings(target_id: str):
    """Verified findings plus non-authoritative Deep Hunt candidates for one target."""
    target_uuid = _uuid_or_400(target_id, "target id")
    async with _pool().acquire() as conn:
        verified = await conn.fetch(
            """SELECT id, title, severity, tool, url, last_verification_verdict, first_seen_at
               FROM findings WHERE target_id=$1 AND status='active'
                 AND last_verification_verdict='exploited'
                 AND tool IN ('autonomous_workflow','bola')
               ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                        WHEN 'low' THEN 3 ELSE 4 END, first_seen_at DESC LIMIT 200""",
            target_uuid,
        )
        suspected = await conn.fetch(
            """SELECT id, title, claimed_severity AS severity, family,
                      canonical_locus, verification_context, status,
                      created_at AS first_seen_at, last_seen_at
               FROM investigation_candidates
               WHERE target_id=$1 AND plane='web'
                 AND status IN ('new','verification_queued','verifying','inconclusive','blocked')
               ORDER BY last_seen_at DESC LIMIT 200""",
            target_uuid,
        )
    def _suspected_row(row: Any) -> dict[str, Any]:
        item = _json_safe_row(row)
        locus = _decode_json_value(item.pop("canonical_locus", None)) or {}
        context = _decode_json_value(item.pop("verification_context", None)) or {}
        item["tool"] = "investigation_candidate"
        item["url"] = locus.get("route") or locus.get("url") or context.get("target_url")
        item["predicate"] = context.get("predicate")
        item["net_new_vs_known"] = context.get("net_new_vs_known")
        item["trust_tier"] = "candidate"
        item["candidate_status"] = item.pop("status", "new")
        return item
    return {
        "target_id": str(target_uuid),
        "verified": [_json_safe_row(row) for row in verified],
        "suspected": [_suspected_row(row) for row in suspected],
    }


@router.post("/agent/findings/{finding_id}/verify")
async def verify_suspected_agent_finding(finding_id: str, req: AgentVerifyRequest):
    """Attempt to UPGRADE one SUSPECTED autonomous-agent finding to VERIFIED via the existing
    family_proof two-run verification (Gap B). On success the SUSPECTED row becomes the VERIFIED one
    (in place); otherwise it stays SUSPECTED. Requires gated execution (enabled by default) plus a
    valid target-bound approval receipt. Supports the bola / auth_bypass / data_exposure families."""
    finding_uuid = _uuid_or_400(finding_id, "finding id")
    return await _verify_suspected_finding_workflow(
        finding_uuid, req.approval_receipt_id, created_by="agent_verify_bridge")
def _resolve_hunt_origin(primary_url: Any, origins: list[str], requested_origin: Any = None) -> str:
    """Choose a concrete Hunt origin inside the target's host boundary.

    A requested scheme/port may be new, but it must resolve to the same host asset.
    Without an explicit choice, the most recently scanned origin wins.
    """
    primary_host = _canonical_web_host(primary_url)
    if not primary_host:
        raise HTTPException(status_code=400, detail="Hunt requires a valid web target host")
    if requested_origin:
        try:
            chosen, _note = _targets.normalize_target_url(str(requested_origin))
        except _targets.TargetNormalizationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not chosen or _canonical_web_host(chosen) != primary_host:
            raise HTTPException(
                status_code=400,
                detail="Hunt origin must use the same host as the selected target",
            )
        return chosen
    for origin in origins:
        if _canonical_web_host(origin) == primary_host:
            return origin
    normalized, _note = _targets.normalize_target_url(str(primary_url or ""))
    if not normalized:
        raise HTTPException(status_code=400, detail="Hunt target origin is invalid")
    return normalized


def _agent_tool_worker_readiness() -> dict[str, Any]:
    """Return fresh, build-current isolated Hunt scanner capacity."""
    expected_fingerprint = expected_build_fingerprint()
    expected_version = current_scanner_version()
    now = datetime.now(timezone.utc)
    # The isolated worker must serve every registered external process adapter. V2-only
    # capabilities expose their own placement/readiness.
    required_tools = {
        str(spec.binary) for spec in agent_tools.CAPABILITY_REGISTRY.process_tools() if spec.binary
    }
    reports: list[dict[str, Any]] = []
    try:
        raw_reports = get_redis().hgetall(AGENT_TOOL_WORKER_BUILD_REGISTRY_KEY) or {}
    except Exception:
        raw_reports = {}
    for raw_host, raw_payload in raw_reports.items():
        host = raw_host.decode("utf-8", "replace") if isinstance(raw_host, bytes) else str(raw_host)
        payload = raw_payload.decode("utf-8", "replace") if isinstance(raw_payload, bytes) else raw_payload
        try:
            report = json.loads(payload) if isinstance(payload, str) else dict(payload)
            reported_at = datetime.fromisoformat(str(report.get("reported_at") or "").replace("Z", "+00:00"))
            if reported_at.tzinfo is None:
                reported_at = reported_at.replace(tzinfo=timezone.utc)
            age_seconds = (now - reported_at.astimezone(timezone.utc)).total_seconds()
            if not (-_devices._WORKER_BUILD_REPORT_CLOCK_SKEW_SECONDS <= age_seconds <= _devices._WORKER_BUILD_REPORT_MAX_AGE_SECONDS):
                continue
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        tools = sorted({str(item).strip().lower() for item in report.get("tools", []) if str(item).strip()})
        build_current = worker_build_current(
            reported_fingerprint=report.get("build_fingerprint"),
            reported_version=report.get("scanner_version"),
            expected_fingerprint=expected_fingerprint,
            expected_version=expected_version,
        )
        reports.append({
            "worker_id": host,
            "build_current": build_current,
            "tools": tools,
            "reported_at": report.get("reported_at"),
            "capable": build_current is True and required_tools.issubset(tools),
        })
    capable_count = sum(1 for report in reports if report["capable"])
    if capable_count:
        status, reason = "ready", None
    elif reports and any(report["build_current"] is False for report in reports):
        status, reason = "not_ready", "agent_tool_worker_build_stale"
    elif reports:
        status, reason = "not_ready", "agent_tool_worker_missing_tools_or_build_identity"
    else:
        status, reason = "not_ready", "no_fresh_agent_tool_worker"
    return {
        "status": status,
        "reason": reason,
        "queue_name": _get("AGENT_TOOL_QUEUE_NAME"),
        "worker_count": len(reports),
        "capable_worker_count": capable_count,
        "required_tools": sorted(required_tools),
        "workers": reports,
        "expected_build_fingerprint": expected_fingerprint,
    }


def _agent_context_pack_sections(context: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a canonical (already-redacted) agent context pack into rankable pack
    sections for :func:`agent_context_pack.pack_context`. Each section is
    ``{key, body, loc, bytes}``; bodies are compact human-readable text so the honest
    packer can relevance-rank, elide, and drop with visible telemetry."""
    surface = context.get("current_surface") if isinstance(context.get("current_surface"), dict) else {}
    principals = surface.get("principal_matrix") if isinstance(surface.get("principal_matrix"), dict) else {}
    graph = surface.get("attack_graph") if isinstance(surface.get("attack_graph"), dict) else {}

    def _rows(value: Any) -> list[dict[str, Any]]:
        return [item for item in (value or []) if isinstance(item, dict)]

    sections: list[dict[str, Any]] = []

    def _add(key: str, lines: Any, loc: int) -> None:
        body = ("\n".join(lines) if isinstance(lines, list) else str(lines)).strip()
        if body:
            sections.append({"key": key, "body": body, "loc": loc, "bytes": len(body)})

    target_summary = context.get("target_summary") if isinstance(context.get("target_summary"), dict) else {}
    if target_summary:
        _add("target", [f"{k}: {v}" for k, v in target_summary.items()], 1)

    endpoint_lines: list[str] = []
    for endpoint in _rows(surface.get("sample_endpoints")):
        method = str(endpoint.get("method") or "GET").upper()
        path = endpoint.get("path") or ""
        bits = [f"[{endpoint.get('auth_state') or 'anonymous'}]"]
        if endpoint.get("test_status"):
            bits.append(str(endpoint["test_status"]))
        if endpoint.get("last_verdict"):
            bits.append(f"verdict={endpoint['last_verdict']}")
        if endpoint.get("content_type"):
            bits.append(str(endpoint["content_type"]))
        line = f"{method} {path}  {' '.join(bits)}".rstrip()
        if endpoint.get("param_shape"):
            line += f"\n    params: {_agent_pack_compact(endpoint['param_shape'], 200)}"
        if endpoint.get("replay_spec"):
            line += f"\n    replay: {str(endpoint['replay_spec'])[:200]}"
        endpoint_lines.append(line)
    _add("endpoints", endpoint_lines, len(endpoint_lines))

    coverage_lines = [f"coverage: {_agent_pack_compact(surface.get('coverage'), 400)}"]
    for count in _rows(surface.get("endpoint_counts")):
        coverage_lines.append(f"  {count.get('auth_state')}/{count.get('test_status')}: {count.get('count')}")
    if surface.get("exhausted_families"):
        coverage_lines.append(f"exhausted_families: {_agent_pack_compact(surface.get('exhausted_families'), 200)}")
    _add("coverage", coverage_lines, len(coverage_lines))

    # B1: observed-artifact provenance — which collected artifacts (crawl / har / js bundle analysis /
    # ffuf / openapi / manual) the surface was mined from. Leads and drafts are derived from these
    # artifacts; this section is the planner's observability-coverage signal (missing js -> client
    # routes unexplored; missing har -> authenticated traffic never captured).
    source_rows = _rows(surface.get("endpoint_source_counts"))
    if source_rows:
        artifact_lines = [
            "endpoint discovery sources (what has been OBSERVED so far):",
            *[f"  {row.get('source')}: {row.get('count')} endpoints" for row in source_rows],
        ]
        if surface.get("asm_last_recon_at"):
            artifact_lines.append(f"last recon: {surface.get('asm_last_recon_at')}")
        if surface.get("asm_last_test_at"):
            artifact_lines.append(f"last endpoint test: {surface.get('asm_last_test_at')}")
        _add("observed_artifacts", artifact_lines, len(artifact_lines))

    principal_lines: list[str] = []
    for principal in _rows(principals.get("principals")):
        principal_lines.append(
            f"{principal.get('label')}  role={principal.get('role')} "
            f"tenant={principal.get('tenant_id') or '-'} auth={principal.get('auth_state')} "
            f"credential={'yes' if principal.get('credential_configured') else 'no'}"
        )
    for expectation in _rows(principals.get("expectations")):
        principal_lines.append(
            f"expect {expectation.get('method')} {expectation.get('path')} "
            f"role={expectation.get('principal_role')} access={expectation.get('expected_access')} "
            f"status={expectation.get('expected_http_status')}"
        )
    _add("principals", principal_lines, len(principal_lines))

    graph_lines = [
        f"nodes={len(_rows(graph.get('nodes')))} edges={len(_rows(graph.get('edges')))} "
        f"truncated={graph.get('truncated')}"
    ]
    for node in _rows(graph.get("nodes")):
        graph_lines.append(f"node {node.get('node_type')}:{node.get('node_key')} {node.get('label') or ''}".rstrip())
    for edge in _rows(graph.get("edges")):
        graph_lines.append(f"edge {edge.get('src_key')} -[{edge.get('edge_type')}]-> {edge.get('dst_key')}")
    _add("application_graph", graph_lines, len(graph_lines))

    hypothesis_lines: list[str] = []
    for hypothesis in _rows(context.get("hypotheses_summary")):
        hypothesis_lines.append(
            f"[{hypothesis.get('family')}] {hypothesis.get('title') or hypothesis.get('dedupe_key') or ''} "
            f"status={hypothesis.get('status')} conf={hypothesis.get('confidence')} src={hypothesis.get('source')}"
        )
    _add("hypotheses", hypothesis_lines, len(hypothesis_lines))

    finding_lines: list[str] = []
    for finding in _rows(context.get("findings_summary")):
        verdict = finding.get("last_verification_verdict") or "unverified"
        finding_lines.append(
            f"{str(finding.get('severity', '')).upper()} [{verdict}] {finding.get('title')} "
            f"@ {finding.get('url') or ''}  ({finding.get('tool')}/{finding.get('status')})"
        )
    _add("known_findings", finding_lines, len(finding_lines))

    gap_rows = _rows(context.get("current_gaps"))
    _add("gaps", [_agent_pack_compact(gap, 300) for gap in gap_rows], len(gap_rows))

    invariant_rows = _rows(surface.get("approved_invariant_contracts"))
    if invariant_rows:
        _add("invariant_contracts", [_agent_pack_compact(item, 400) for item in invariant_rows], len(invariant_rows))

    # A3: UNAPPROVED invariant candidates (auto-drafted from black-box facts + operator drafts).
    # Explicitly labeled non-authoritative: they are review hints for the planner, never rules;
    # a SUSPECTED observation matching one is the signal to ask the operator for approval.
    candidate_rows = _rows(surface.get("invariant_candidate_contracts"))
    if candidate_rows:
        candidate_lines = [
            f"UNAPPROVED CANDIDATE (no authority): {_agent_pack_compact(item, 300)}"
            for item in candidate_rows
        ]
        _add("invariant_candidates", candidate_lines, len(candidate_lines))

    scan_rows = _rows(surface.get("recent_scans"))
    if scan_rows:
        _add("recent_scans", [_agent_pack_compact(scan, 400) for scan in scan_rows], len(scan_rows))

    preconditions = context.get("known_preconditions") if isinstance(context.get("known_preconditions"), dict) else {}
    if preconditions:
        _add("preconditions", [f"{k}: {v}" for k, v in preconditions.items()], 1)

    return sections


async def _resolve_agent_target_addresses(url: str) -> list[str]:
    """Compatibility name for Hunt's frozen runtime target binding."""
    return await _fleet_routes._resolve_runtime_target_addresses(url, subject="Hunt target")


async def _execute_agent_tool(
    target_uuid: uuid.UUID,
    target_url: str,
    name: str,
    args: dict[str, Any],
    *,
    created_by: str,
    allow_write: bool = False,
    allow_active: bool = False,
    approval_receipt_id: Optional[str] = None,
    results: Optional[dict[str, Any]] = None,
    hypothesis_id: Optional[str] = None,
    authorized_addresses: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Dispatch one agent tool call. Guard errors are returned (not raised) so the ReAct
    loop can feed them back to the model as an error-recovery message."""
    results = results or {}
    args = args if isinstance(args, dict) else {}
    try:
        if name == "http_request":
            return await _agent_tool_http_request(
                target_uuid, target_url, args, created_by=created_by,
                allow_write=allow_write, approval_receipt_id=approval_receipt_id,
                hypothesis_id=hypothesis_id,
                authorized_addresses=authorized_addresses,
            )
        if name == "query_kb":
            kind, flt = agent_tools.coerce_query_kb(args)
            return await _agent_tool_query_kb(target_uuid, kind, flt)
        if name == "note":
            return await _agent_tool_note(target_uuid, agent_tools.coerce_note(args), created_by=created_by)
        if name == "diff":
            return _agent_tool_diff(args.get("left"), args.get("right"), results)
        if name == "run_tool":
            return await _agent_tool_run_tool(
                target_uuid, target_url, args, created_by=created_by,
                allow_active=allow_active, approval_receipt_id=approval_receipt_id,
                hypothesis_id=hypothesis_id,
                authorized_addresses=authorized_addresses,
            )
    except agent_tools.AgentToolError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 — a tool fault must not crash the loop
        return {"ok": False, "error": f"tool_fault:{type(exc).__name__}"}
    return {"ok": False, "error": f"unknown tool '{name}'. Callable: {sorted(agent_tools.CALLABLE_TOOL_NAMES)}"}




async def _agent_seed_state(
    target_uuid: uuid.UUID,
    target_url: str,
    objective: str,
    *,
    created_by: str,
    token_budget: int,
    max_iterations: int,
    target_origins: Optional[list[str]] = None,
    source_excerpt: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build the context pack (slice 1) + system/user seed and return a fresh loop state."""
    async with _pool().acquire() as conn:
        context_req = await _arsenal_routes._build_agent_context_pack_from_target(
            conn,
            _arsenal_routes.AgentContextPackFromTargetRequest(
                target_id=str(target_uuid), finding_limit=20, endpoint_limit=40,
                created_by=created_by,
            ),
        )
    context = _arsenal_routes._canonical_agent_context_pack(context_req)
    sections = _agent_context_pack_sections(context)
    # B2: operator-supplied source excerpt (grey-box opt-in). One ranked section; pack_context
    # ranking/elision applies unchanged. Absent -> black-box-only pack (the default).
    if source_excerpt and str(source_excerpt.get("text") or "").strip():
        body = str(source_excerpt["text"])
        sections.append({"key": "source_excerpt", "body": body, "loc": len(body), "bytes": len(body.encode())})
    pack = agent_context_pack.pack_context(sections, token_budget=token_budget, objective=objective)
    tools = agent_tools.tool_schemas()
    contract = agent_text_toolcalls.render_tool_contract(tools)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": agent_loop.build_system_prompt(contract, max_iterations=max_iterations)},
        {"role": "user", "content": agent_loop.build_user_message(objective, pack["text"])},
    ]
    state = _agent_new_state(objective, messages, pack["included"])
    state["target_url"] = target_url
    state["target_origins"] = _arsenal_routes._normalized_web_origins(target_url, target_origins or [])
    # Freeze the DNS authorization set once, at hunt creation. Every direct request and
    # external scanner invocation connects to one of these exact addresses, so DNS changes
    # during a session cannot redirect an authorized public target into a private service.
    state["authorized_target_addresses"] = await _resolve_agent_target_addresses(target_url)
    if source_excerpt and isinstance(source_excerpt.get("stats"), dict):
        state["source_ingest"] = source_excerpt["stats"]
    return state


async def _agent_apply_reply(
    state: dict[str, Any],
    reply: Any,
    *,
    target_uuid: uuid.UUID,
    target_url: str,
    created_by: str,
    allow_write: bool,
    allow_active: bool,
    approval_receipt_id: Optional[str],
    hypothesis_id: Optional[str],
    iteration: int,
    max_iterations: int,
    deadline_monotonic: Optional[float] = None,
    should_stop: Optional[Any] = None,
) -> dict[str, Any]:
    """Apply ONE planner reply to the loop state: interpret it, execute any requested tools
    (gated), record evidence, and run the anti-stall steering. Mutates ``state`` and returns
    ``{"stop": bool, "stop_reason": str|None}``. This is the shared heart of both drivers; the
    provider-error / cancellation handling that is specific to the in-process loop stays in
    :func:`_run_agent_hunt`. A keyless turn just calls this once per submitted reply."""
    if isinstance(reply, dict):
        reply.pop("_provider_meta", None)  # provider telemetry must not pollute the transcript
    decision = agent_text_toolcalls.interpret_assistant(reply)
    assistant_content = reply if isinstance(reply, str) else json.dumps(reply, default=str)[:6000]
    if len(state["debug_replies"]) < 3:
        state["debug_replies"].append((reply if isinstance(reply, str) else json.dumps(reply, default=str))[:700])
    state["messages"].append({"role": "assistant", "content": assistant_content})

    if not decision["tool_calls"]:
        # A refusal returned as a *successful* reply is HONORED (recorded + stop), never
        # auto-overridden — we respect the model's safety signal rather than route around it.
        reply_text = reply if isinstance(reply, str) else json.dumps(reply, default=str)
        if not decision["findings"] and agent_text_toolcalls.is_likely_refusal(reply_text):
            state["events"].append({"iteration": iteration, "model_declined": True})
            state["abstained"] = True
            return {"stop": True, "stop_reason": "model_declined"}
        # Genuine finish: a TERMINAL turn — findings reported, or a structural done/abstain block
        # (interpret_assistant sets done only for a parsed debrief structure, never for prose). A
        # bad/prose reply is done=False and falls through to the malformed-reply retry, so one bad
        # reply cannot silently finalize the hunt with zero findings. (External-audit N1.)
        if decision.get("done"):
            state["findings"] = decision.get("findings") or []
            state["abstained"] = bool(decision.get("abstained"))
            state["events"].append({"iteration": iteration, "final": True, "findings": len(state["findings"]), "abstained": state["abstained"]})
            return {"stop": True, "stop_reason": "natural_stop"}
        # Otherwise a malformed/empty reply (JSON-mode hiccup or unparseable prose) — re-prompt.
        state["empty_replies"] += 1
        if state["empty_replies"] > 2:
            state["events"].append({"iteration": iteration, "empty_reply_giveup": True})
            return {"stop": True, "stop_reason": "empty_replies"}
        state["events"].append({"iteration": iteration, "empty_reply_reprompt": state["empty_replies"]})
        state["messages"].append({"role": "user", "content": (
            "[System: your last reply had no tool_calls and no findings. If you are still "
            'hunting, reply with a ```json {"tool_calls":[...]} ``` block. If you are truly '
            'done, reply with {"done":true,"findings":[...],"abstained":bool}.]'
        )})
        return {"stop": False, "stop_reason": None}
    state["empty_replies"] = 0

    made_progress = False
    turn_calls = decision["tool_calls"][:_AGENT_MAX_TOOLS_PER_TURN]
    if len(decision["tool_calls"]) > _AGENT_MAX_TOOLS_PER_TURN:
        dropped = len(decision["tool_calls"]) - _AGENT_MAX_TOOLS_PER_TURN
        state["events"].append({"iteration": iteration, "tool_calls_capped": dropped})
        state["messages"].append({"role": "user", "content": (
            f"[System: you requested {len(decision['tool_calls'])} tools in one turn; only the first "
            f"{_AGENT_MAX_TOOLS_PER_TURN} were run. Request the remaining {dropped} next turn.]"
        )})
    for call in turn_calls:
        if should_stop is not None:
            try:
                if await should_stop():
                    state["events"].append({"iteration": iteration, "cancelled": True})
                    return {"stop": True, "stop_reason": "cancelled"}
            except Exception:
                pass
        name = str(call.get("name") or "")
        args = call.get("arguments") if isinstance(call.get("arguments"), dict) else {}
        kind, signature = agent_loop.classify_tool_call(
            name, args, state["seen_calls"], agent_tools.CALLABLE_TOOL_NAMES
        )
        if kind == "hallucinated":
            state["messages"].append({"role": "user", "content": f"[tool {name}] " + agent_loop.hallucinated_tool_message(name, sorted(agent_tools.CALLABLE_TOOL_NAMES))})
            state["events"].append({"iteration": iteration, "tool": name, "hallucinated": True})
            continue
        if kind == "duplicate":
            state["messages"].append({"role": "user", "content": f"[tool {name}] " + agent_loop.dup_steer_message(name, state["seen_calls"][signature])})
            state["events"].append({"iteration": iteration, "tool": name, "duplicate": True})
            continue

        # The episode request budget counts traffic-producing TOOL INVOCATIONS, not the
        # scanner's internal wire traffic.  External scanners have their own fixed per-tool
        # wire ceilings and are reported separately below.  Charging the conservative wire
        # reservation here made Nuclei (450 max wire requests) impossible to invoke because a
        # Deep Hunt session is capped at 400 request units.
        request_units = agent_tools.request_budget_units(name)
        wire_request_reservation = 1 if name == "http_request" else 0
        if name == "run_tool":
            try:
                scanner_name, _, scanner_options = agent_tools.coerce_run_tool(args)
                wire_request_reservation = agent_tools.scanner_request_reservation(
                    scanner_name, scanner_options
                )
            except (agent_tools.AgentToolError, KeyError, TypeError, ValueError):
                # Unknown scanner work will fail validation before execution. Keep a bounded
                # invocation charge, but reserve no fictitious wire traffic.
                wire_request_reservation = 0
        active_units = 0
        if name == "http_request":
            try:
                active_units = 1 if agent_tools.is_write_method(
                    agent_tools.coerce_method(args.get("method"))
                ) else 0
            except agent_tools.AgentToolError:
                active_units = 0
        elif name == "run_tool":
            try:
                tool_name, _, _ = agent_tools.coerce_run_tool(args)
                active_units = 1 if agent_tools.SCANNER_ARG_TEMPLATES[tool_name]["risk"] != "read_only" else 0
            except (agent_tools.AgentToolError, KeyError):
                active_units = 0

        action_limit = state.get("action_budget_limit")
        request_limit = state.get("request_budget_limit")
        wire_request_limit = state.get("wire_request_budget_limit")
        active_limit = state.get("active_action_budget_limit")
        if action_limit is not None and int(state["tool_calls_made"]) >= int(action_limit):
            state["events"].append({"iteration": iteration, "budget_exhausted": "actions"})
            return {"stop": True, "stop_reason": "budget_exhausted:actions"}
        if request_limit is not None and int(state["request_units_used"]) + request_units > int(request_limit):
            state["events"].append({"iteration": iteration, "budget_exhausted": "requests"})
            return {"stop": True, "stop_reason": "budget_exhausted:requests"}
        if (
            wire_request_limit is not None
            and int(state.get("wire_requests_reserved") or 0) + wire_request_reservation
            > int(wire_request_limit)
        ):
            remaining_wire_requests = max(
                0,
                int(wire_request_limit) - int(state.get("wire_requests_reserved") or 0),
            )
            state["events"].append({
                "iteration": iteration,
                "budget_exhausted": "wire_requests",
                "reservation_rejected": wire_request_reservation,
                "remaining_wire_requests": remaining_wire_requests,
            })
            denial = {
                "ok": False,
                "error": "wire_request_budget_insufficient",
                "tool": name,
                "required_reservation": wire_request_reservation,
                "remaining": remaining_wire_requests,
            }
            state["messages"].append({
                "role": "user",
                "content": f"[tool {name} -> denied] " + json.dumps(denial, sort_keys=True),
            })
            state["seen_calls"][signature] = agent_loop.format_tool_result(denial, max_chars=160)
            continue
        if active_limit is not None and int(state["active_actions_used"]) + active_units > int(active_limit):
            state["events"].append({"iteration": iteration, "budget_exhausted": "active_actions"})
            return {"stop": True, "stop_reason": "budget_exhausted:active_actions"}

        state["tool_calls_made"] += 1
        state["request_units_used"] += request_units
        state["wire_requests_reserved"] = (
            int(state.get("wire_requests_reserved") or 0) + wire_request_reservation
        )
        state["active_actions_used"] += active_units
        remaining_seconds = (
            None if deadline_monotonic is None
            else deadline_monotonic - time.monotonic()
        )
        if remaining_seconds is not None and remaining_seconds <= 0:
            state["events"].append({"iteration": iteration, "budget_exhausted": "seconds"})
            return {"stop": True, "stop_reason": "budget_exhausted:seconds"}
        try:
            tool_call = _execute_agent_tool(
                target_uuid, target_url, name, args, created_by=created_by,
                allow_write=allow_write, allow_active=allow_active,
                approval_receipt_id=approval_receipt_id,
                results=state["results_store"], hypothesis_id=hypothesis_id,
                authorized_addresses=state.get("authorized_target_addresses") or [],
            )
            if should_stop is None:
                result = (
                    await tool_call
                    if remaining_seconds is None
                    else await asyncio.wait_for(tool_call, timeout=max(0.1, remaining_seconds))
                )
            else:
                tool_task = asyncio.create_task(tool_call)
                while not tool_task.done():
                    poll_timeout = 1.0
                    if deadline_monotonic is not None:
                        poll_timeout = min(
                            poll_timeout,
                            max(0.1, deadline_monotonic - time.monotonic()),
                        )
                    done, _pending = await asyncio.wait({tool_task}, timeout=poll_timeout)
                    if done:
                        break
                    if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                        tool_task.cancel()
                        try:
                            await tool_task
                        except asyncio.CancelledError:
                            pass
                        state["events"].append({"iteration": iteration, "budget_exhausted": "seconds"})
                        return {"stop": True, "stop_reason": "budget_exhausted:seconds"}
                    try:
                        cancelled = bool(await should_stop())
                    except Exception:
                        cancelled = False
                    if cancelled:
                        tool_task.cancel()
                        try:
                            await tool_task
                        except asyncio.CancelledError:
                            pass
                        state["events"].append({"iteration": iteration, "cancelled": True})
                        return {"stop": True, "stop_reason": "cancelled"}
                result = await tool_task
        except asyncio.TimeoutError:
            state["events"].append({"iteration": iteration, "budget_exhausted": "seconds"})
            return {"stop": True, "stop_reason": "budget_exhausted:seconds"}

        if name == "http_request":
            # A shaped request means the HTTP executor reached its single wire attempt; contract or
            # approval failures occur before a request is shaped and safely settle at zero.
            # Each followed redirect hop is charged as an extra request unit + wire request at
            # execution time (bounded by MAX_REDIRECT_HOPS, so the budget can only be overshot
            # by that fixed cap even when every hop of every call redirects).
            hops_followed = 0
            if isinstance(result, dict):
                try:
                    hops_followed = max(0, min(MAX_REDIRECT_HOPS, int(result.get("hops_followed") or 0)))
                except (TypeError, ValueError):
                    hops_followed = 0
            actual = (1 if isinstance(result.get("request"), dict) else 0) + hops_followed
            state["wire_requests_actual_confirmed"] = int(
                state.get("wire_requests_actual_confirmed") or 0
            ) + actual
            state["wire_requests_observed_minimum"] = int(
                state.get("wire_requests_observed_minimum") or 0
            ) + actual
            if hops_followed:
                state["request_units_used"] = int(state["request_units_used"] or 0) + hops_followed
                state["wire_requests_reserved"] = int(
                    state.get("wire_requests_reserved") or 0
                ) + hops_followed
                state["events"].append({
                    "iteration": iteration,
                    "tool": name,
                    "redirect_hops_charged": hops_followed,
                })
        elif name == "run_tool":
            accounting = str(result.get("wire_request_accounting") or "unavailable")
            observed = max(0, int(result.get("wire_requests_observed_minimum") or 0))
            state["wire_requests_observed_minimum"] = int(
                state.get("wire_requests_observed_minimum") or 0
            ) + observed
            if accounting == "exact" and result.get("wire_requests_actual") is not None:
                wire_settlement = agent_tools.settle_scanner_wire_reservation(
                    charged_total=int(state.get("wire_requests_reserved") or 0),
                    reservation=wire_request_reservation,
                    accounting=accounting,
                    actual=result.get("wire_requests_actual"),
                    budget_limit=wire_request_limit,
                )
                actual = int(wire_settlement["actual"] or 0)
                state["wire_requests_reserved"] = int(wire_settlement["charged_total"])
                state["wire_requests_actual_confirmed"] = int(
                    state.get("wire_requests_actual_confirmed") or 0
                ) + actual
                if wire_settlement["reservation_overrun"]:
                    state["events"].append({
                        "iteration": iteration,
                        "wire_request_reservation_overrun": wire_settlement["reservation_overrun"],
                        "wire_request_budget_overrun": wire_settlement["budget_overrun"],
                        "scanner": scanner_name,
                    })
            else:
                state["wire_request_unsettled_tools"] = int(
                    state.get("wire_request_unsettled_tools") or 0
                ) + 1
        state["seen_calls"][signature] = agent_loop.format_tool_result(result, max_chars=160)

        if result.get("ok") and result.get("provenance") == "tool":
            made_progress = True
            state["resp_counter"] += 1
            if name == "run_tool":
                ref = f"scan_{state['resp_counter']}"
                state["evidence_by_ref"][ref] = {"type": "output", "content": json.dumps(
                    {"tool": result.get("tool"), "url": result.get("url"), "lines": result.get("output_lines")},
                    default=str)[:6000]}
            else:  # http_request
                ref = f"resp_{state['resp_counter']}"
                state["results_store"][ref] = result
                state["evidence_by_ref"][ref] = agent_tools.http_evidence_item(result.get("request") or {}, result.get("response") or {})
            result = {**result, "ref": ref}
        elif name == "diff" and result.get("ok"):
            made_progress = True

        state["messages"].append({"role": "user", "content": f"[tool {name} -> {'ok' if result.get('ok') else 'error'}] " + agent_loop.format_tool_result(result)})
        state["events"].append({
            "iteration": iteration,
            "tool": name,
            "ok": bool(result.get("ok")),
            "ref": result.get("ref"),
            "wire_requests_reserved": wire_request_reservation,
            "wire_request_accounting": result.get("wire_request_accounting") if name == "run_tool" else "exact",
            "wire_requests_actual": (
                result.get("wire_requests_actual") if name == "run_tool"
                else (1 if isinstance(result.get("request"), dict) else 0)
            ),
            "wire_requests_observed_minimum": result.get("wire_requests_observed_minimum") if name == "run_tool" else None,
        })

    state["messages"] = _agent_trim_transcript(state["messages"])
    state["no_progress"] = 0 if made_progress else state["no_progress"] + 1
    if state["no_progress"] >= 4 and iteration < max_iterations - 2:
        state["messages"].append({"role": "user", "content": agent_loop.no_progress_message(state["no_progress"])})
        state["no_progress"] = 0
    return {"stop": False, "stop_reason": None, "made_progress": made_progress}


async def _agent_finalize_and_persist(
    state: dict[str, Any],
    *,
    target_uuid: uuid.UUID,
    target_url: str,
    created_by: str,
    approval_receipt_id: Optional[str],
    hypothesis_id: Optional[str],
    persist: bool,
    allow_write: bool = False,
    cancelled_check: Optional[Any] = None,
    request_budget_limit: Optional[int] = None,
    wire_request_budget_limit: Optional[int] = None,
    action_budget_limit: Optional[int] = None,
    active_action_budget_limit: Optional[int] = None,
    seconds_budget_limit: Optional[int] = None,
    research_episode_id: Optional[str] = None,
    agent_hunt_run_id: Optional[str] = None,
) -> dict[str, Any]:
    """Gate -> receipt -> persist -> (auto-verify) -> assemble the run result. Shared final stage of
    both drivers, so a keyless hunt produces the identical result shape as configured_ai."""
    objective = str(state.get("objective") or "")
    gated_findings = _agent_finalize_gate(state)
    receipt_id = await _agent_run_summary_receipt(
        state, target_uuid=target_uuid, target_url=target_url, objective=objective,
        approval_receipt_id=approval_receipt_id, hypothesis_id=hypothesis_id,
        gated_findings=gated_findings, created_by=created_by,
    )
    persisted: list[dict[str, Any]] = []
    auto_verified: list[dict[str, Any]] = []
    dast_retests: list[dict[str, Any]] = []
    if persist and gated_findings:
        persisted = await _agent_persist_suspected_findings(
            gated_findings, target_uuid=target_uuid, target_url=target_url, receipt_id=receipt_id,
            research_episode_id=research_episode_id,
            agent_hunt_run_id=agent_hunt_run_id,
        )
        remaining_requests = (
            None if request_budget_limit is None
            else max(0, int(request_budget_limit) - int(state.get("request_units_used") or 0))
        )
        remaining_actions = (
            None if action_budget_limit is None
            else max(0, int(action_budget_limit) - int(state.get("tool_calls_made") or 0))
        )
        remaining_active_actions = (
            None if active_action_budget_limit is None
            else max(0, int(active_action_budget_limit) - int(state.get("active_actions_used") or 0))
        )
        remaining_seconds = (
            None if seconds_budget_limit is None
            else max(0, int(seconds_budget_limit) - int(state.get("elapsed_seconds") or 0))
        )
        # Do not spend active verification traffic after a cancel — mirror the keyless driver's guard
        # so both drivers behave the same on cancellation. (External-audit BUG 4.)
        auto_verified = [] if state.get("stop_reason") == "cancelled" else await _agent_auto_verify(
            gated_findings,
            approval_receipt_id=approval_receipt_id,
            created_by=f"{created_by}:auto_verify",
            allow_write=allow_write,
            cancelled_check=cancelled_check,
            request_budget=remaining_requests,
            action_budget=remaining_actions,
            active_action_budget=remaining_active_actions,
            seconds_budget=remaining_seconds,
        )
        # Route SUSPECTED DAST-retestable leads (injection + traversal/redirect/ssti/cmdi/cors) into
        # the deterministic retest pipeline. The worker's prover is the arbiter; the finding stays
        # SUSPECTED until it confirms.
        dast_retests = [] if state.get("stop_reason") == "cancelled" else (
            await _agent_auto_queue_dast_retests(
                persisted, target_uuid=target_uuid,
                approval_receipt_id=approval_receipt_id,
                created_by=f"{created_by}:dast_verify",
            )
        )
    auto_verify_requests = sum(int(item.get("request_units_reserved") or 0) for item in auto_verified)
    auto_verify_actions = sum(int(item.get("action_units_reserved") or 0) for item in auto_verified)
    auto_verify_active_actions = sum(
        int(item.get("active_action_units_reserved") or 0) for item in auto_verified
    )
    auto_verify_seconds = sum(int(item.get("seconds_reserved") or 0) for item in auto_verified)
    unsettled_tool_count = int(state.get("wire_request_unsettled_tools") or 0)
    actual_confirmed = int(state.get("wire_requests_actual_confirmed") or 0)
    return {
        "target_id": str(target_uuid),
        "objective": objective,
        "iterations": state["iterations"],
        "stop_reason": state["stop_reason"],
        "tool_calls_made": state["tool_calls_made"],
        "request_units_used": int(state.get("request_units_used") or 0),
        "wire_requests_reserved": int(state.get("wire_requests_reserved") or 0),
        "wire_request_budget_limit": (
            wire_request_budget_limit
            if wire_request_budget_limit is not None
            else state.get("wire_request_budget_limit")
        ),
        "wire_requests_actual": None if unsettled_tool_count else actual_confirmed,
        "wire_requests_actual_confirmed": actual_confirmed,
        "wire_requests_observed_minimum": int(state.get("wire_requests_observed_minimum") or 0),
        "wire_request_unsettled_tools": unsettled_tool_count,
        "request_accounting": "exact" if not unsettled_tool_count else "mixed_conservative",
        "active_actions_used": int(state.get("active_actions_used") or 0),
        "model_tokens_used": int(state.get("model_tokens_used") or 0),
        "elapsed_seconds": int(state.get("elapsed_seconds") or 0),
        "http_evidence_count": len(state["evidence_by_ref"]),
        "abstained": state["abstained"],
        "findings": gated_findings,
        "persisted": persisted,
        "net_new_count": sum(1 for record in persisted if record.get("net_new")),
        "auto_verified": auto_verified,
        "verified_count": sum(1 for a in auto_verified if a.get("verified")),
        "dast_retests_queued": dast_retests,
        "dast_retests_count": len(dast_retests),
        "auto_verify_requests_reserved": auto_verify_requests,
        "auto_verify_actions_reserved": auto_verify_actions,
        "auto_verify_active_actions_reserved": auto_verify_active_actions,
        "auto_verify_seconds_reserved": auto_verify_seconds,
        "run_receipt_id": receipt_id,
        "events": state["events"][-50:],
        "context_included": state["context_included"],
        # Raw model output can echo values it observed in tool results; redact before surfacing.
        "debug_replies": [_arsenal_routes._redact_agent_text(r) for r in state["debug_replies"]],
    }


def _agent_hunt_run_public(row: Any) -> dict[str, Any]:
    """Serialize an agent_hunt_runs row into the session-facing observation: the transcript to
    reason over, the loop status, and (on completion) the finalized SUSPECTED result."""
    item = row_to_dict(row) if row is not None and not isinstance(row, dict) else dict(row or {})
    state = _decode_json_value(item.get("state")) or {}
    result = _decode_json_value(item.get("result")) or {}
    status = str(item.get("status") or "")
    awaiting = status == "awaiting_planner"
    allow_write = bool(item.get("allow_write"))
    allow_active = bool(item.get("allow_active"))
    execution_mode = "deep_hunt" if allow_active else "read_only"
    return {
        "run_id": str(item.get("id")) if item.get("id") else None,
        "target_id": str(item.get("target_id")) if item.get("target_id") else None,
        "target_url": state.get("target_url"),
        "target_origins": state.get("target_origins") or [],
        "objective": item.get("objective"),
        "status": status,
        "awaiting_planner": awaiting,
        "iterations": int(state.get("iterations") or 0),
        "max_iterations": item.get("max_iterations"),
        "stop_reason": item.get("stop_reason"),
        "mode": execution_mode,
        "tool_surface": {
            "allow_write": allow_write,
            "allow_active": allow_active,
            "note": (
                "Deep Hunt: bounded active scanners and approved proof promotion are enabled; "
                "arbitrary state-changing HTTP remains blocked."
                if allow_active else
                "Read-only discovery: active scanners and state-changing HTTP are blocked."
            ),
        },
        # The full (trimmed) transcript the session must reason over to produce its next reply.
        "transcript": state.get("messages") or [],
        "next_action": (
            f"POST /agent/hunt/session/{item.get('id')}/reply with your next tool_calls block or final debrief"
            if awaiting else status
        ),
        "result": result or None,
    }


async def _agent_hunt_run_or_404(conn, run_id: str, *, for_update: bool = False) -> Any:
    query = "SELECT * FROM agent_hunt_runs WHERE id=$1"
    if for_update:
        query += " FOR UPDATE"
    row = await conn.fetchrow(query, _uuid_or_400(run_id, "run id"))
    if not row:
        raise HTTPException(status_code=404, detail="Agent hunt run not found")
    return row


def _agent_run_final_status(stop_reason: str) -> str:
    """Map a loop stop reason to a terminal agent_hunt_runs status (audit N5a). The runs table has
    no 'blocked'; a refusal or repeated malformed replies are 'failed', not a clean 'completed'."""
    reason = str(stop_reason or "")
    if reason in ("model_declined", "empty_replies") or reason.startswith("planner_error"):
        return "failed"
    if reason == "cancelled":
        return "cancelled"
    return "completed"


def _agent_pack_compact(value: Any, limit: int = 1500) -> str:
    try:
        text = json.dumps(value, default=str, ensure_ascii=False, sort_keys=True)
    except Exception:
        text = str(value)
    return text[:limit]


async def _agent_tool_http_request(
    target_uuid: uuid.UUID,
    target_url: str,
    args: dict[str, Any],
    *,
    created_by: str,
    allow_write: bool,
    approval_receipt_id: Optional[str] = None,
    hypothesis_id: Optional[str] = None,
    authorized_addresses: Optional[list[str]] = None,
    trusted_collection_headers: Optional[Mapping[str, Any]] = None,
    record_receipt: bool = True,
) -> dict[str, Any]:
    method = agent_tools.coerce_method(args.get("method"))
    path = agent_tools.validate_same_origin_path(args.get("path"))
    if agent_tools.is_write_method(method) and not allow_write:
        return {
            "ok": False,
            "needs_approval": True,
            "error": f"{method} is a state-changing request; it requires a credential-tier "
            "approval receipt on the episode (gated). Use a read method to probe first.",
        }
    # Redirect following is read-only: it must never replay a write onto a redirect hop.
    follow_redirects = args.get("follow_redirects") is True
    if follow_redirects and method not in {"GET", "HEAD", "OPTIONS"}:
        return {
            "ok": False,
            "error": "follow_redirects is only permitted for read methods (GET/HEAD/OPTIONS); "
            "a redirect chain must not replay a state-changing request.",
        }
    slot = agent_tools.normalize_principal_slot(args.get("as_principal"))
    try:
        request_origin = _resolve_hunt_origin(
            target_url,
            [target_url],
            args.get("origin"),
        )
        frozen_addresses = list(authorized_addresses or [])[:16]
        if not frozen_addresses:
            raise agent_tools.AgentToolError("hunt has no frozen target resolution set")
        parsed_origin = urllib.parse.urlsplit(request_origin)
        bound_target = TargetBinding(
            target_id=str(target_uuid),
            target_kind="web",
            canonical_host=parsed_origin.hostname,
            allowed_origins=(request_origin,),
            allowed_addresses=tuple(frozen_addresses),
        )
    except HTTPException as exc:
        return {"ok": False, "error": f"scope: {exc.detail}"}
    except (agent_tools.AgentToolError, ValueError) as exc:
        return {"ok": False, "error": f"scope: {exc}"}

    auth_headers: dict[str, Any] = {}
    cookies: dict[str, Any] = {}
    principal_identity = None
    if slot != "anonymous":
        try:
            async with _pool().acquire() as conn:
                contexts = await _arsenal_routes._resolve_workflow_principal_contexts(conn, target_uuid, {slot})
            ctx = contexts.get(slot) or {}
            auth_headers = ctx.get("headers") or {}
            cookies = ctx.get("cookies") or {}
            principal_identity = ctx.get("identity_fingerprint")
        except WorkflowContractError as exc:
            return {"ok": False, "error": f"principal '{slot}' unavailable: {exc}"}
    started_at = datetime.now(timezone.utc)
    operation_args = dict(args)
    operation_args.update({
        "method": method,
        "path": path,
        "follow_redirects": follow_redirects,
        "origin": request_origin,
    })
    raw_result = await execute_bound_http_request(
        request_origin,
        operation_args,
        target=bound_target,
        allow_write=allow_write,
        trusted_headers={
            **dict(trusted_collection_headers or {}),
            **dict(auth_headers),
        },
        cookies=cookies,
        principal_slot=slot,
        timeout_seconds=_AGENT_TOOL_HTTP_TIMEOUT_SECONDS,
    )
    request_view = dict(raw_result.get("request") or {
        "method": method,
        "origin": request_origin,
        "path": path,
        "as_principal": slot,
        "follow_redirects": follow_redirects,
    })
    summary = (
        dict(raw_result.get("response") or {})
        if isinstance(raw_result.get("response"), Mapping) else None
    )
    error = str(raw_result.get("error") or "").strip() or None
    status_label = "failed" if error else "success"
    safe_summary = _arsenal_routes._redact_agent_payload(summary) if summary else None
    redirect_chain = (
        list(raw_result.get("redirect_chain") or [])
        if isinstance(raw_result.get("redirect_chain"), list) else []
    )
    hops_followed = max(0, int(raw_result.get("hops_followed") or 0))
    finished_at = datetime.now(timezone.utc)
    receipt_id = None
    if record_receipt:
        try:
            async with _pool().acquire() as conn:
                async with conn.transaction():
                    receipt_result = await _arsenal_routes._record_tool_receipt(conn, _arsenal_routes.ToolReceiptRequest(
                        tool_name="agent.http_request",
                        adapter_version="2026-07-18.v1",
                        redacted_argv=["agent.http_request", method, path, f"as:{slot}"],
                        target_scope={
                            "target_id": str(target_uuid),
                            "target_url": request_origin,
                            "same_target_host_only": True,
                        },
                        approval_receipt_id=approval_receipt_id,
                        status=status_label,
                        parser_status="parsed" if safe_summary else "not_applicable",
                        started_at=started_at.isoformat(),
                        finished_at=finished_at.isoformat(),
                        redaction_summary="Credential headers server-injected from principal; response bounded + redacted.",
                        metadata_json={
                            "request": request_view,
                            "status": (safe_summary or {}).get("status"),
                            "principal_identity": principal_identity,
                            "hypothesis_id": hypothesis_id,
                            "error": error,
                            "redirect_chain": _arsenal_routes._redact_agent_payload(redirect_chain) if redirect_chain else [],
                            "hops_followed": hops_followed,
                        },
                        created_by=created_by,
                    ))
                    receipt_id = (receipt_result.get("tool_receipt") or {}).get("id")
        except Exception:
            receipt_id = None

    if error:
        return {
            "ok": False,
            "error": error,
            "request": request_view,
            "receipt_id": receipt_id,
        }
    result_payload: dict[str, Any] = {
        "ok": True, "request": request_view, "response": safe_summary,
        "receipt_id": receipt_id, "provenance": "tool",
    }
    if follow_redirects:
        result_payload["redirect_chain"] = _arsenal_routes._redact_agent_payload(redirect_chain) if redirect_chain else []
        result_payload["hops_followed"] = hops_followed
    return result_payload


async def _agent_tool_note(target_uuid: uuid.UUID, note: dict[str, Any], *, created_by: str) -> dict[str, Any]:
    receipt_id = None
    async with _pool().acquire() as conn:
        async with conn.transaction():
            receipt_result = await _arsenal_routes._record_tool_receipt(conn, _arsenal_routes.ToolReceiptRequest(
                tool_name="agent.note",
                adapter_version="2026-07-18.v1",
                redacted_argv=["agent.note", note["kind"], note["title"][:60]],
                target_scope={"target_id": str(target_uuid)},
                status="success",
                parser_status="not_applicable",
                redaction_summary="Agent scratchpad note.",
                metadata_json={
                    "kind": note["kind"], "title": note["title"], "detail": note["detail"],
                    "family": note.get("family"), "severity": note.get("severity"),
                },
                created_by=created_by,
            ))
            receipt_id = (receipt_result.get("tool_receipt") or {}).get("id")
    return {"ok": True, "note": note, "receipt_id": receipt_id}


async def _agent_tool_run_tool(
    target_uuid: uuid.UUID,
    target_url: str,
    args: dict[str, Any],
    *,
    created_by: str,
    allow_active: bool,
    approval_receipt_id: Optional[str] = None,
    hypothesis_id: Optional[str] = None,
    authorized_addresses: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Run a bounded external scanner via a hardcoded argv template (port of T3MP3ST
    adapterToCustomTool): the model picks tool + target only; every flag is fixed; the
    target is forced onto the selected target host; active scanners require the gated tier."""
    name, raw_target, options = agent_tools.coerce_run_tool(args)
    template = agent_tools.SCANNER_ARG_TEMPLATES[name]
    wire_request_reservation = agent_tools.scanner_request_reservation(name, options)
    if template["risk"] != "read_only" and not allow_active:
        return {"ok": False, "needs_approval": True,
                "error": f"run_tool '{name}' is active; it requires a gated episode with an approval receipt."}

    try:
        url = _resolve_hunt_tool_url(target_url, raw_target)
    except HTTPException as exc:
        return {"ok": False, "error": f"scope: {exc.detail}"}

    try:
        frozen_addresses = list(authorized_addresses or [])[:16]
        if not frozen_addresses:
            raise agent_tools.AgentToolError("hunt has no frozen target resolution set")
        pinned_address = agent_tools.validate_pinned_scanner_address(
            None, frozen_addresses,
        )
    except agent_tools.AgentToolError as exc:
        return {"ok": False, "error": f"scope: {exc}"}
    # Blind OOB (interactsh) is off unless a gated hunt AND an operator-configured PRIVATE
    # server are both present; the public ProjectDiscovery servers are never used.
    oob_interactsh_server, oob_interactsh_token = agent_tools.resolve_hunt_interactsh_config(
        allow_active=allow_active,
    )
    binary, argv, timeout_ms = agent_tools.build_scanner_argv(
        name, url, options, pinned_address=pinned_address,
        oob_interactsh_server=oob_interactsh_server,
        oob_interactsh_token=oob_interactsh_token,
    )
    started_at = datetime.now(timezone.utc)
    try:
        worker_result = await _enqueue_agent_scanner_tool(
            name=name,
            execution_target=url,
            registered_target=target_url,
            options=options,
            timeout_ms=timeout_ms,
            pinned_address=pinned_address,
            authorized_addresses=frozen_addresses,
            reserved_budget=dict(
                agent_tools.CAPABILITY_REGISTRY.for_process_tool(name).budget_cost
            ),
            oob_interactsh_server=oob_interactsh_server,
            oob_interactsh_token=oob_interactsh_token,
        )
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"run_tool_fault:{type(exc).__name__}"}
    finished_at = datetime.now(timezone.utc)

    status_label = str(worker_result.get("status") or "failed")
    error = str(worker_result.get("error") or "").strip() or None
    lines = [str(line) for line in list(worker_result.get("output_lines") or [])[:60]]
    typed_output = worker_result.get("typed_output") if isinstance(worker_result.get("typed_output"), dict) else {}
    settlement = worker_result.get("settlement") if isinstance(worker_result.get("settlement"), dict) else {}
    settlement_mode = str(settlement.get("mode") or "unavailable")
    wire_requests_actual = settlement.get("actual") if settlement_mode == "exact" else None
    wire_requests_observed = max(0, int(settlement.get("observed_minimum") or 0))
    # The scanned URL can carry query values the model chose; keep only the path in the durable
    # receipt so a receipt never persists a query-string secret. (External-audit P2.)
    safe_url = url.split("?", 1)[0][:200]
    receipt_id = None
    try:
        async with _pool().acquire() as conn:
            async with conn.transaction():
                receipt_result = await _arsenal_routes._record_tool_receipt(conn, _arsenal_routes.ToolReceiptRequest(
                    tool_name=f"agent.run_tool.{name}",
                    adapter_version="2026-07-18.v1",
                    redacted_argv=[binary, name, safe_url],
                    target_scope={
                        "target_id": str(target_uuid),
                        "target_url": safe_url,
                        "same_target_host_only": True,
                    },
                    approval_receipt_id=approval_receipt_id,
                    status=status_label,
                    parser_status=str(typed_output.get("parser_status") or "not_applicable"),
                    started_at=started_at.isoformat(),
                    finished_at=finished_at.isoformat(),
                    redaction_summary="Hardcoded-argv scanner; output bounded + redacted; receipt URL query-stripped.",
                    metadata_json={
                        "tool": name,
                        "url_scanned": safe_url,
                        "lines": len(lines),
                        "error": error,
                        "hypothesis_id": hypothesis_id,
                        "wire_request_accounting": settlement_mode,
                        "wire_requests_reserved": wire_request_reservation,
                        "wire_requests_actual": wire_requests_actual,
                        "wire_requests_observed_minimum": wire_requests_observed,
                        "wire_request_counter_source": settlement.get("source"),
                        "execution_plane": "worker_queue",
                        "pinned_address": pinned_address,
                        "network_binding": worker_result.get("network_binding"),
                        "typed_parser": typed_output.get("parser"),
                        "typed_record_count": typed_output.get("record_count"),
                    },
                    created_by=created_by,
                ))
                receipt_id = (receipt_result.get("tool_receipt") or {}).get("id")
    except Exception:
        receipt_id = None

    if error and not lines:
        return {
            "ok": False,
            "error": f"{name}:{error}",
            "receipt_id": receipt_id,
            "wire_request_accounting": settlement_mode,
            "wire_requests_reserved": wire_request_reservation,
            "wire_requests_actual": wire_requests_actual,
            "wire_requests_observed_minimum": wire_requests_observed,
            "execution_plane": "worker_queue",
            "network_binding": worker_result.get("network_binding"),
        }
    safe_lines = [_arsenal_routes._redact_agent_text(ln)[:1200] for ln in lines[:60]]
    return {
        "ok": True,
        "tool": name,
        "url": url,
        "execution_status": status_label,
        "complete": status_label == "success",
        "partial_reason": error if status_label != "success" else None,
        "line_count": int(worker_result.get("line_count") or len(lines)),
        "output_lines": safe_lines,
        "receipt_id": receipt_id,
        "provenance": "tool",
        "wire_request_accounting": settlement_mode,
        "wire_requests_reserved": wire_request_reservation,
        "wire_requests_actual": wire_requests_actual,
        "wire_requests_observed_minimum": wire_requests_observed,
        "wire_request_counter_source": settlement.get("source"),
        "execution_plane": "worker_queue",
        "network_binding": worker_result.get("network_binding"),
        "typed_observations": typed_output.get("records") or [],
        "typed_parser_status": typed_output.get("parser_status"),
    }


def _agent_tool_diff(left: Any, right: Any, results: dict[str, Any]) -> dict[str, Any]:
    return {"ok": True, "diff": compare_summaries(_agent_resolve_ref(left, results), _agent_resolve_ref(right, results))}




def _agent_trim_transcript(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep system + first user + the most recent turns; drop the oldest middle messages
    so a long run stays inside the window (T3MP3ST caps per-result; we also cap count)."""
    if len(messages) <= _AGENT_HUNT_TRANSCRIPT_SOFT_CAP:
        return messages
    head = messages[:2]
    tail = messages[-(_AGENT_HUNT_TRANSCRIPT_SOFT_CAP - 3):]
    note = {"role": "user", "content": "[System: older transcript elided to fit the context window.]"}
    return [*head, note, *tail]


def _agent_new_state(objective: str, messages: list[dict[str, Any]], included: list[str]) -> dict[str, Any]:
    """A fresh, JSONB-serializable ReAct loop state. Shared by the in-process (configured_ai)
    loop and the durable turn-based keyless driver so the two can never diverge."""
    return {
        "objective": objective,
        "messages": messages,
        "seen_calls": {},          # dup_signature -> short prior-result preview
        "results_store": {},       # ref -> full tool result (for diff resolution)
        "evidence_by_ref": {},     # ref -> {type, content} tool-provenance evidence item
        "resp_counter": 0,
        "no_progress": 0,
        "empty_replies": 0,
        "tool_calls_made": 0,
        "request_units_used": 0,
        "wire_requests_reserved": 0,
        "wire_request_budget_limit": None,
        "wire_requests_actual_confirmed": 0,
        "wire_requests_observed_minimum": 0,
        "wire_request_unsettled_tools": 0,
        "active_actions_used": 0,
        "model_tokens_used": 0,
        "action_budget_limit": None,
        "request_budget_limit": None,
        "active_action_budget_limit": None,
        "iterations": 0,
        "findings": [],            # model debrief findings (set on finalize)
        "abstained": False,
        "stop_reason": "max_iterations",
        "events": [],
        "debug_replies": [],
        "context_included": included,
        "forced_debrief": False,   # keyless: cap reached, the NEXT reply is the forced debrief
    }


def _agent_finalize_gate(state: dict[str, Any]) -> list[dict[str, Any]]:
    """Provenance-gate the model's debrief findings (SUSPECTED tier). ONLY a finding's OWN
    cited evidence refs count — never borrow another finding's (or the run's) tool output. A
    finding whose refs do not resolve to real tool evidence fails the gate and is surfaced
    (tier 'blocked') but NOT persisted: fail-closed against false-positive persistence."""
    gated_findings: list[dict[str, Any]] = []
    for raw in state["findings"]:
        finding = agent_provenance.strip_self_verification(dict(raw))
        refs = raw.get("evidence_refs") or []
        finding["evidence"] = [state["evidence_by_ref"][r] for r in refs if r in state["evidence_by_ref"]]
        gate = agent_provenance.gate_live_finding(finding)
        gated_findings.append({"finding": finding, "gate": gate, "tier": "suspected" if gate["passed"] else "blocked"})
    return gated_findings


async def _agent_run_summary_receipt(
    state: dict[str, Any],
    *,
    target_uuid: uuid.UUID,
    target_url: str,
    objective: str,
    approval_receipt_id: Optional[str],
    hypothesis_id: Optional[str],
    gated_findings: list[dict[str, Any]],
    created_by: str,
) -> Optional[str]:
    """Durable run-summary tool receipt (audit trail). Best-effort: a receipt failure must not
    lose the findings."""
    try:
        async with _pool().acquire() as conn:
            async with conn.transaction():
                receipt_result = await _arsenal_routes._record_tool_receipt(conn, _arsenal_routes.ToolReceiptRequest(
                    tool_name="agent.hunt",
                    adapter_version="2026-07-18.v1",
                    redacted_argv=["agent.hunt", str(target_uuid), f"iters:{state['iterations']}"],
                    target_scope={"target_id": str(target_uuid), "target_url": target_url, "same_origin_only": True},
                    approval_receipt_id=approval_receipt_id,
                    status="success",
                    parser_status="parsed",
                    redaction_summary="Autonomous ReAct hunt; tool outputs bounded + redacted.",
                    metadata_json={
                        "objective": objective[:500],
                        "iterations": state["iterations"],
                        "tool_calls_made": state["tool_calls_made"],
                        "wire_requests_reserved": int(state.get("wire_requests_reserved") or 0),
                        "wire_request_budget_limit": state.get("wire_request_budget_limit"),
                        "wire_requests_actual_confirmed": int(state.get("wire_requests_actual_confirmed") or 0),
                        "wire_requests_observed_minimum": int(state.get("wire_requests_observed_minimum") or 0),
                        "wire_request_unsettled_tools": int(state.get("wire_request_unsettled_tools") or 0),
                        "http_evidence": len(state["evidence_by_ref"]),
                        "stop_reason": state["stop_reason"],
                        "findings_suspected": sum(1 for g in gated_findings if g["tier"] == "suspected"),
                        "findings_blocked": sum(1 for g in gated_findings if g["tier"] == "blocked"),
                        "hypothesis_id": hypothesis_id,
                    },
                    created_by=created_by,
                ))
                return (receipt_result.get("tool_receipt") or {}).get("id")
    except Exception:
        return None


async def _agent_persist_suspected_findings(
    gated_findings: list[dict[str, Any]],
    *,
    target_uuid: uuid.UUID,
    target_url: str,
    receipt_id: Optional[str],
    research_episode_id: Optional[str] = None,
    agent_hunt_run_id: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Persist gate-passing claims as candidates; blocked overclaims are never persisted."""
    persisted: list[dict[str, Any]] = []
    try:
        async with _pool().acquire() as conn:
            known_keys = await _arsenal_routes._research_known_vulnerability_keys(conn, target_uuid)
            for entry in gated_findings:
                if not entry["gate"]["passed"]:
                    continue  # blocked overclaim — never persisted
                async with conn.transaction():
                    record = await _persist_agent_suspected_finding(
                        conn, target_uuid, target_url, entry["finding"], entry["gate"],
                        run_receipt_id=receipt_id,
                        research_episode_id=research_episode_id,
                        agent_hunt_run_id=agent_hunt_run_id,
                        known_keys=known_keys,
                    )
                entry["persisted"] = record
                persisted.append(record)
    except Exception as exc:  # noqa: BLE001
        persisted.append({"error": f"persist_failed:{type(exc).__name__}"})
    return persisted


async def _agent_auto_verify(
    gated_findings: list[dict[str, Any]],
    *,
    approval_receipt_id: Optional[str],
    created_by: str,
    allow_write: bool = False,
    cancelled_check: Optional[Any] = None,
    request_budget: Optional[int] = None,
    action_budget: Optional[int] = None,
    active_action_budget: Optional[int] = None,
    seconds_budget: Optional[int] = None,
) -> list[dict[str, Any]]:
    """Close the loop unattended (Gap B auto-wiring): when the hunt carries an approval receipt AND
    execution is enabled, auto-attempt VERIFIED promotion for the gate-passing SUSPECTED findings the
    bridge can verify. The family_proof moat decides — a non-provable finding stays SUSPECTED. This is
    best-effort: a verify failure is recorded, never allowed to break the hunt. Bounded per run."""
    execution_enabled = _ai_ops_execute_enabled()
    attempts: list[dict[str, Any]] = []
    # Taxonomy signals and operational skips have separate report budgets. A long run full of
    # approval/budget skips must not hide a later family-name drift signal.
    taxonomy_telemetry: list[dict[str, Any]] = []
    skip_telemetry: list[dict[str, Any]] = []

    def record_taxonomy(item: dict[str, Any]) -> None:
        if len(taxonomy_telemetry) < _AGENT_UNVERIFIABLE_FAMILY_REPORT_LIMIT:
            taxonomy_telemetry.append(item)

    def record_skip(item: dict[str, Any]) -> None:
        if len(skip_telemetry) < _AGENT_AUTO_VERIFY_SKIP_REPORT_LIMIT:
            skip_telemetry.append(item)

    cancelled = False
    execution_stop_reason: str | None = None
    for entry in gated_findings:
        record = entry.get("persisted")
        if not isinstance(record, dict) or not record.get("id"):
            continue
        persistence_state = str(record.get("persisted") or "")
        if persistence_state not in {"created", "existing"}:
            continue
        if persistence_state == "existing" and str(record.get("existing_status") or "") not in {
            "new", "inconclusive", "blocked",
        }:
            continue
        claimed_family = str((entry.get("finding") or {}).get("family") or "")
        family = family_proof.canonical_family(claimed_family)
        if family not in _get("_AGENT_VERIFIABLE_FAMILIES"):
            # NOT silent: a family the moat cannot verify is either a DAST-retest lead (promoted by
            # _agent_auto_queue_dast_retests instead) or a taxonomy mismatch that leaves the finding
            # permanently SUSPECTED. Both were previously indistinguishable from "nothing to verify",
            # which is how a doc/contract family-name drift could go unnoticed in every run summary.
            record_taxonomy({
                "finding_id": str(record["id"]),
                "verified": False,
                "skipped": (
                    "family_eligible_for_dast_retest"
                    if normalize_retest_type(claimed_family) in _AGENT_DAST_RETEST_FAMILIES
                    else "family_not_verifiable"
                ),
                "claimed_family": claimed_family[:80],
                "canonical_family": family[:80],
            })
            continue
        if not approval_receipt_id or not execution_enabled:
            record_skip({
                "finding_id": str(record["id"]),
                "verified": False,
                "skipped": (
                    "auto_verify_requires_approval"
                    if not approval_receipt_id
                    else "auto_verify_execution_disabled"
                ),
                "claimed_family": claimed_family[:80],
                "canonical_family": family[:80],
            })
            continue
        # BOLA is NOT auto-promoted. Its family_proof establishes a managed, distinct reference — not
        # OWNERSHIP — so an authenticated shared-behind-login collection (everyone may read any object)
        # passes every predicate and would false-VERIFY. Distinguishing "private, broken" from
        # "intentionally shared" is fundamentally a policy question no autonomous run can settle, so a
        # suspected BOLA stays SUSPECTED for a human to promote. The manual /agent/findings/{id}/verify
        # endpoint remains for an accountable human decision. (Zero-FP: unattended never promotes BOLA.)
        if family in _AGENT_AUTO_VERIFY_EXCLUDED_FAMILIES:
            record_skip({"finding_id": str(record["id"]), "verified": False,
                         "skipped": "auto_verify_disabled_ownership_unprovable"})
            continue
        # A mutating verification (create-MA does live create POSTs) must not run from a read-only
        # hunt, even with a receipt — that would violate the hunt's no-writes invariant. The
        # GET-only families (auth_bypass/data_exposure) stay allowed. (External-audit BUG 3.)
        if family in _AGENT_MUTATING_VERIFY_FAMILIES and not allow_write:
            record_skip({"finding_id": str(record["id"]), "verified": False,
                         "skipped": "mutating_verification_requires_gated_hunt"})
            continue
        if len(attempts) >= _AGENT_AUTO_VERIFY_LIMIT:
            record_skip({"finding_id": str(record["id"]), "verified": False,
                         "skipped": "auto_verify_attempt_limit_reached"})
            continue
        if execution_stop_reason:
            record_skip({"finding_id": str(record["id"]), "verified": False,
                         "skipped": execution_stop_reason})
            continue
        # Re-check cancellation before EACH credential-tier verification. Continue classifying later
        # findings after cancellation so taxonomy/route telemetry is never silently dropped.
        if not cancelled and cancelled_check is not None:
            try:
                cancelled = bool(await cancelled_check())
            except Exception:
                cancelled = False
        if cancelled:
            record_skip({"finding_id": str(record["id"]), "verified": False,
                         "skipped": "cancelled_during_auto_verify"})
            continue
        request_reservation = int(_AGENT_VERIFY_REQUEST_RESERVATIONS.get(family) or 0)
        seconds_reservation = int(_AGENT_VERIFY_SECONDS_RESERVATIONS.get(family) or 0)
        reserved_requests = sum(int(item.get("request_units_reserved") or 0) for item in attempts)
        reserved_actions = sum(int(item.get("action_units_reserved") or 0) for item in attempts)
        reserved_active = sum(int(item.get("active_action_units_reserved") or 0) for item in attempts)
        reserved_seconds = sum(int(item.get("seconds_reserved") or 0) for item in attempts)
        if request_budget is not None and reserved_requests + request_reservation > request_budget:
            execution_stop_reason = "budget_exhausted:requests"
            record_skip({"finding_id": str(record["id"]), "verified": False,
                         "skipped": execution_stop_reason})
            continue
        if action_budget is not None and reserved_actions + 1 > action_budget:
            execution_stop_reason = "budget_exhausted:actions"
            record_skip({"finding_id": str(record["id"]), "verified": False,
                         "skipped": execution_stop_reason})
            continue
        if active_action_budget is not None and reserved_active + 1 > active_action_budget:
            execution_stop_reason = "budget_exhausted:active_actions"
            record_skip({"finding_id": str(record["id"]), "verified": False,
                         "skipped": execution_stop_reason})
            continue
        if seconds_budget is not None and reserved_seconds + seconds_reservation > seconds_budget:
            execution_stop_reason = "budget_exhausted:seconds"
            record_skip({"finding_id": str(record["id"]), "verified": False,
                         "skipped": execution_stop_reason})
            continue
        try:
            result = await _verify_suspected_finding_workflow(
                _uuid_or_400(str(record["id"]), "finding id"), approval_receipt_id, created_by=created_by)
            attempt = {
                "finding_id": str(record["id"]),
                "verified": bool(result.get("verified")),
                "verified_finding_id": result.get("verified_finding_id"),
                "verdict": (result.get("family_proof") or {}).get("verdict"),
                "request_units_reserved": request_reservation,
                "action_units_reserved": 1,
                "active_action_units_reserved": 1,
                "seconds_reserved": seconds_reservation,
            }
            attempts.append(attempt)
            if attempt["verified"]:
                entry["tier"] = "verified"
                entry["verified_finding_id"] = attempt["verified_finding_id"]
                record["persisted"] = "verified"
                record["verified_finding_id"] = attempt["verified_finding_id"]
        except HTTPException as exc:
            attempts.append({
                "finding_id": str(record["id"]),
                "verified": False,
                "skipped": str(exc.detail)[:160],
                "request_units_reserved": request_reservation,
                "action_units_reserved": 1,
                "active_action_units_reserved": 1,
                "seconds_reserved": seconds_reservation,
            })
        except Exception as exc:  # noqa: BLE001 — a verify failure must never break the hunt
            attempts.append({
                "finding_id": str(record["id"]),
                "verified": False,
                "error": type(exc).__name__,
                "request_units_reserved": request_reservation,
                "action_units_reserved": 1,
                "active_action_units_reserved": 1,
                "seconds_reserved": seconds_reservation,
            })
    return attempts + taxonomy_telemetry + skip_telemetry


async def _agent_auto_queue_dast_retests(
    persisted: list[dict[str, Any]],
    *,
    target_uuid: uuid.UUID,
    approval_receipt_id: Optional[str],
    created_by: str,
) -> list[dict[str, Any]]:
    """Route DAST-retestable candidates into the deterministic retest pipeline.

    The prover is the sole arbiter and a finding is created only after an exploited verdict. Gated on the hunt's
    approval receipt; param-bearing families need a concrete injection point, route-only families
    (cors) do not. Best-effort: a queue failure must never lose findings or fail the hunt."""
    queued: list[dict[str, Any]] = []
    if not approval_receipt_id:
        return queued
    try:
        r = get_redis()
        r.ping()
    except Exception:
        return queued
    for rec in persisted:
        if (
            not isinstance(rec, dict)
            or rec.get("persisted") not in {"created", "existing"}
            or rec.get("existing_status") not in {None, "new", "inconclusive", "blocked"}
            or not rec.get("id")
        ):
            continue
        try:
            async with _pool().acquire() as conn:
                candidate = await conn.fetchrow(
                    """SELECT * FROM investigation_candidates
                       WHERE id=$1 AND plane='web' AND target_id=$2""",
                    uuid.UUID(str(rec["id"])), target_uuid,
                )
                if not candidate:
                    continue
                context = _decode_json_value(candidate["verification_context"]) or {}
                rtype = normalize_retest_type(
                    context.get("retest_type") or candidate["family"]
                )
                # Only deterministic DAST provers. Param-bearing families need a concrete injection
                # point; route-only families (cors) prove from the route alone.
                if rtype not in _AGENT_DAST_RETEST_FAMILIES:
                    continue
                if rtype not in _AGENT_ROUTE_ONLY_RETEST_FAMILIES and not context.get("parameter"):
                    continue
                target_for_retest = str(context.get("target_url") or "")
                approval_context = await _validate_approval_receipt_for_action(
                    conn, approval_receipt_id, target_url=target_for_retest,
                    target_id=str(target_uuid), action_name="finding.retest")
                retest_id, job_id = uuid.uuid4(), str(uuid.uuid4())
                await conn.execute(
                    """INSERT INTO finding_verifications (
                           id, finding_id, candidate_id, target_id, job_id, requested_by,
                           status, finding_type, target_url, original_url, param, payload,
                           method, verification_mode, contract_id, contract_version, proof_basis
                       ) VALUES ($1,NULL,$2,$3,$4,$5,'queued',$6,$7,$7,$8,$9,$10,
                                 'deterministic',$11,'deterministic-retest/v1',
                                 'candidate_native_deterministic_retest')""",
                    retest_id, candidate["id"], target_uuid, job_id, created_by[:120],
                    rtype, target_for_retest, context.get("parameter"), context.get("payload"),
                    str(context.get("method") or "GET").upper(),
                    str(candidate["verifier_contract_id"] or f"web.{rtype}"),
                )
                await conn.execute(
                    """UPDATE investigation_candidates
                       SET status='verification_queued', latest_verification_id=$2,
                           verification_context=verification_context || jsonb_build_object(
                               'verification_id',$2::text,'job_id',$3::text
                           ), updated_at=NOW()
                       WHERE id=$1""",
                    candidate["id"], retest_id, job_id,
                )
            job_data = build_retest_job_payload(
                job_id=job_id, verification_id=str(retest_id), candidate_id=str(candidate["id"]),
                submitted_at=utc_now_iso(), trigger=created_by)
            job_data["mode"] = "deterministic"  # force the real prover, never the AI tier
            if approval_context:
                job_data.update(approval_context)
            valid, _reason = validate_retest_job_payload(job_data)
            if not valid:
                continue
            try:
                enqueue_job(r, _finding_routes.RETEST_QUEUE_NAME, job_data)
            except Exception as enqueue_error:
                async with _pool().acquire() as conn:
                    async with conn.transaction():
                        await conn.execute(
                            """UPDATE finding_verifications
                               SET status='failed', result_status='error', verdict='error',
                                   verdict_reason='Queue handoff failed', retry_class='transient',
                                   retryable=TRUE, error_message=$2, completed_at=NOW(), updated_at=NOW()
                               WHERE id=$1 AND status='queued'""",
                            retest_id, f"queue_handoff_failed:{type(enqueue_error).__name__}",
                        )
                        await conn.execute(
                            """UPDATE investigation_candidates
                               SET status='inconclusive',
                                   verification_context=verification_context || jsonb_build_object(
                                       'queue_error',$2::text
                                   ), updated_at=NOW()
                               WHERE id=$1""",
                            candidate["id"], f"queue_handoff_failed:{type(enqueue_error).__name__}",
                        )
                continue
            queued.append({"candidate_id": str(candidate["id"]), "retest_type": rtype,
                           "retest_id": str(retest_id), "queued_deterministic": True})
        except HTTPException:
            continue  # approval/contract guard failed for this finding — leave it SUSPECTED
        except Exception:
            continue  # best-effort: never fail the hunt on a queue error
    return queued


async def _run_agent_hunt(
    target_uuid: uuid.UUID,
    target_url: str,
    objective: str,
    *,
    max_iterations: int,
    created_by: str,
    allow_write: bool = False,
    approval_receipt_id: Optional[str] = None,
    token_budget: int = 6000,
    hypothesis_id: Optional[str] = None,
    persist: bool = True,
    allow_active: bool = False,
    should_stop: Optional[Any] = None,
    request_budget_limit: Optional[int] = None,
    wire_request_budget_limit: Optional[int] = None,
    action_budget_limit: Optional[int] = None,
    active_action_budget_limit: Optional[int] = None,
    wall_time_budget_seconds: Optional[int] = None,
    model_token_budget_limit: Optional[int] = None,
    target_origins: Optional[list[str]] = None,
    research_episode_id: Optional[str] = None,
    agent_hunt_run_id: Optional[str] = None,
) -> dict[str, Any]:
    run_started = time.monotonic()
    state = await _agent_seed_state(
        target_uuid, target_url, objective,
        created_by=created_by, token_budget=token_budget, max_iterations=max_iterations,
        target_origins=target_origins,
    )
    state["request_budget_limit"] = request_budget_limit
    state["wire_request_budget_limit"] = wire_request_budget_limit
    state["action_budget_limit"] = action_budget_limit
    state["active_action_budget_limit"] = active_action_budget_limit
    deadline_monotonic = (
        None if wall_time_budget_seconds is None
        else run_started + max(0, int(wall_time_budget_seconds))
    )
    if max_iterations <= 0:
        state["stop_reason"] = "budget_exhausted:steps"
        state["events"].append({"iteration": 0, "budget_exhausted": "steps"})
        state["elapsed_seconds"] = max(0, math.ceil(time.monotonic() - run_started))
        return await _agent_finalize_and_persist(
            state,
            target_uuid=target_uuid,
            target_url=target_url,
            created_by=created_by,
            approval_receipt_id=approval_receipt_id,
            hypothesis_id=hypothesis_id,
            persist=persist,
            allow_write=allow_write,
            cancelled_check=should_stop,
            request_budget_limit=request_budget_limit,
            wire_request_budget_limit=wire_request_budget_limit,
            action_budget_limit=action_budget_limit,
            active_action_budget_limit=active_action_budget_limit,
            seconds_budget_limit=wall_time_budget_seconds,
            research_episode_id=research_episode_id,
            agent_hunt_run_id=agent_hunt_run_id,
        )
    planner_errors = 0
    for i in range(max_iterations):
        state["iterations"] = i + 1
        remaining_seconds = (
            None if deadline_monotonic is None
            else deadline_monotonic - time.monotonic()
        )
        if remaining_seconds is not None and remaining_seconds <= 0:
            state["stop_reason"] = "budget_exhausted:seconds"
            state["events"].append({"iteration": i, "budget_exhausted": "seconds"})
            break
        if should_stop is not None:
            try:
                if await should_stop():
                    state["stop_reason"] = "cancelled"
                    state["events"].append({"iteration": i, "cancelled": True})
                    break
            except Exception:
                pass
        planner_timeout = 120 if remaining_seconds is None else max(1, min(120, math.ceil(remaining_seconds)))
        token_reservation = _agent_planner_turn_token_reservation(
            state["messages"],
            max_output_tokens=1400,
        )
        if (
            model_token_budget_limit is not None
            and int(state.get("model_tokens_used") or 0) + token_reservation
            > int(model_token_budget_limit)
        ):
            state["stop_reason"] = "budget_exhausted:model_tokens"
            state["events"].append({"iteration": i, "budget_exhausted": "model_tokens"})
            break
        reply, error, model_tokens_used = await _agent_planner_reply(
            state["messages"],
            max_tokens=1400,
            timeout=planner_timeout,
        )
        state["model_tokens_used"] += int(model_tokens_used or 0)
        if error or reply is None:
            err_str = str(error or "no_reply")
            # HONOR a model safety refusal — record it and stop. We deliberately do NOT
            # auto-"reframe"/override a refusal: routing around the model's own safety signal
            # is a bypass we will not ship. Upstream's reframe helper was NOT ported — there is
            # no such function in this tree, only detection (is_likely_refusal).
            if agent_text_toolcalls.is_likely_refusal(err_str):
                state["events"].append({"iteration": i, "planner_refusal": err_str[:160]})
                state["stop_reason"] = "model_declined"
                break
            # Transient provider error (timeout / rate-limit): retry a bounded number of times so
            # a durable unattended hunt survives a hiccup instead of dying on the first timeout.
            planner_errors += 1
            state["events"].append({"iteration": i, "planner_error": err_str[:160], "retry": planner_errors})
            if planner_errors > 2:
                state["stop_reason"] = f"planner_error:{err_str[:60]}"
                break
            continue
        planner_errors = 0

        outcome = await _agent_apply_reply(
            state, reply, target_uuid=target_uuid, target_url=target_url, created_by=created_by,
            allow_write=allow_write, allow_active=allow_active, approval_receipt_id=approval_receipt_id,
            hypothesis_id=hypothesis_id, iteration=i, max_iterations=max_iterations,
            deadline_monotonic=deadline_monotonic,
            should_stop=should_stop,
        )
        if outcome["stop"]:
            state["stop_reason"] = outcome["stop_reason"]
            break

    # Hit the iteration cap without a debrief — force a final-summary turn so the model's
    # analysis is captured, not lost (T3MP3ST src/agent/index.ts:264-283).
    remaining_seconds = (
        None if deadline_monotonic is None
        else deadline_monotonic - time.monotonic()
    )
    if (
        state["stop_reason"] == "max_iterations"
        and not state["findings"]
        and not state["abstained"]
        and (remaining_seconds is None or remaining_seconds > 0)
    ):
        state["messages"].append({"role": "user", "content": agent_loop.forced_debrief_message()})
        debrief_timeout = 120 if remaining_seconds is None else max(1, min(120, math.ceil(remaining_seconds)))
        token_reservation = _agent_planner_turn_token_reservation(
            state["messages"],
            max_output_tokens=1600,
        )
        if (
            model_token_budget_limit is not None
            and int(state.get("model_tokens_used") or 0) + token_reservation
            > int(model_token_budget_limit)
        ):
            state["stop_reason"] = "budget_exhausted:model_tokens"
            state["events"].append({
                "iteration": state["iterations"],
                "budget_exhausted": "model_tokens",
            })
            reply, error, model_tokens_used = None, "model_token_budget_exhausted", 0
        else:
            reply, error, model_tokens_used = await _agent_planner_reply(
                state["messages"],
                max_tokens=1600,
                timeout=debrief_timeout,
            )
            state["model_tokens_used"] += int(model_tokens_used or 0)
        if not error and reply is not None:
            if isinstance(reply, dict):
                reply.pop("_provider_meta", None)
            if len(state["debug_replies"]) < 3:
                state["debug_replies"].append((reply if isinstance(reply, str) else json.dumps(reply, default=str))[:700])
            final = agent_text_toolcalls.interpret_assistant(reply)
            state["findings"] = final.get("findings") or []
            state["abstained"] = bool(final.get("abstained"))
            state["stop_reason"] = "forced_debrief"
            state["events"].append({"iteration": state["iterations"], "forced_debrief": True, "findings": len(state["findings"])})
    elif state["stop_reason"] == "max_iterations" and remaining_seconds is not None and remaining_seconds <= 0:
        state["stop_reason"] = "budget_exhausted:seconds"
        state["events"].append({"iteration": state["iterations"], "budget_exhausted": "seconds"})

    state["elapsed_seconds"] = max(0, math.ceil(time.monotonic() - run_started))
    return await _agent_finalize_and_persist(
        state, target_uuid=target_uuid, target_url=target_url, created_by=created_by,
        approval_receipt_id=approval_receipt_id, hypothesis_id=hypothesis_id, persist=persist,
        allow_write=allow_write, cancelled_check=should_stop,
        request_budget_limit=request_budget_limit,
        wire_request_budget_limit=wire_request_budget_limit,
        action_budget_limit=action_budget_limit,
        active_action_budget_limit=active_action_budget_limit,
        seconds_budget_limit=wall_time_budget_seconds,
        research_episode_id=research_episode_id,
        agent_hunt_run_id=agent_hunt_run_id,
    )
def _resolve_hunt_tool_url(target_url: str, requested_target: Any) -> str:
    """Resolve a scanner target inside the selected web-host boundary."""
    raw = str(requested_target or "")
    if raw.startswith("http://") or raw.startswith("https://"):
        try:
            concrete_origin, _note = _targets.normalize_target_url(raw)
        except _targets.TargetNormalizationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if _canonical_web_host(concrete_origin) != _canonical_web_host(target_url):
            raise HTTPException(
                status_code=400,
                detail="run_tool target must use the selected target host",
            )
        parsed_raw = urllib.parse.urlsplit(raw)
        path = parsed_raw.path or "/"
        if parsed_raw.query:
            path += f"?{parsed_raw.query}"
        return urllib.parse.urljoin(concrete_origin.rstrip("/") + "/", path.lstrip("/"))
    path = raw if raw.startswith("/") else "/" + raw
    return _provision_same_origin_url(target_url, path)




async def _enqueue_agent_scanner_tool(
    *,
    name: str,
    execution_target: str,
    registered_target: str,
    options: dict[str, Any],
    timeout_ms: int,
    pinned_address: str,
    authorized_addresses: list[str],
    reserved_budget: Mapping[str, int],
    oob_interactsh_server: str | None = None,
    oob_interactsh_token: str | None = None,
) -> dict[str, Any]:
    """Queue fixed-template scanner work and await its bounded worker result.

    Cancellation publishes a short-lived kill marker that the worker polls while the child process
    runs.  A worker also has its own hard timeout, so an API restart cannot orphan the scanner.
    """
    redis_client = get_redis()
    job_id = str(uuid.uuid4())
    result_key = f"agent_tool_result:{job_id}"
    cancel_key = f"agent_tool_cancel:{job_id}"
    payload = {
        "job_id": job_id,
        "type": "agent_scanner_tool",
        "tool_name": name,
        "execution_target": execution_target,
        "registered_target": registered_target,
        "scanner_options": options,
        "timeout_ms": timeout_ms,
        "pinned_address": pinned_address,
        "authorized_addresses": authorized_addresses[:16],
        "_reserved_budget": {
            str(key): int(value) for key, value in reserved_budget.items()
        },
        "oob_interactsh_server": oob_interactsh_server,
        "oob_interactsh_token": oob_interactsh_token,
        "submitted_at": utc_now_iso(),
        "_base_queue_name": _get("AGENT_TOOL_QUEUE_NAME"),
    }
    redis_client.hset(
        f"job:{job_id}",
        mapping={"status": "queued", "current_phase": "agent_tool_queued", "tool": name},
    )
    redis_client.expire(f"job:{job_id}", max(3600, math.ceil(timeout_ms / 1000) + 300))
    enqueue_job(redis_client, _get("AGENT_TOOL_QUEUE_NAME"), payload)
    deadline = asyncio.get_running_loop().time() + timeout_ms / 1000.0 + 30.0
    try:
        while asyncio.get_running_loop().time() < deadline:
            raw = redis_client.get(result_key)
            if raw is not None:
                redis_client.delete(result_key)
                text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
                parsed = json.loads(text)
                if not isinstance(parsed, dict):
                    raise RuntimeError("agent scanner worker returned a malformed result")
                return parsed
            await asyncio.sleep(0.2)
    except asyncio.CancelledError:
        redis_client.set(cancel_key, "1", ex=max(60, math.ceil(timeout_ms / 1000) + 30))
        raise
    redis_client.set(cancel_key, "1", ex=max(60, math.ceil(timeout_ms / 1000) + 30))
    return {
        "status": "timeout",
        "error": "worker_result_timeout",
        "output_lines": [],
        "line_count": 0,
        "typed_output": {"parser_status": "not_applicable", "records": [], "record_count": 0},
        "settlement": {"mode": "unavailable", "actual": None, "observed_minimum": 0,
                       "source": None},
    }


def _agent_resolve_ref(value: Any, results: dict[str, Any]) -> dict[str, Any]:
    """Resolve a diff argument to a response summary: an inline summary dict, a ref like
    'resp_1' into the loop's result store, or a stored {response: summary} wrapper."""
    if isinstance(value, dict):
        return value.get("response") if isinstance(value.get("response"), dict) else value
    if isinstance(value, str):
        entry = results.get(value)
        if isinstance(entry, dict):
            return entry.get("response") if isinstance(entry.get("response"), dict) else entry
    return {}




async def _agent_planner_reply(
    messages: list[dict[str, Any]], *, max_tokens: int = 1400, timeout: int = 90
) -> tuple[Any, Optional[str], int]:
    """One planner turn via the configured AI provider in json_object mode (no schema —
    the model returns {"tool_calls":[...]} or {"done":true,"findings":[...]})."""
    settings = _load_effective_ai_settings()
    ai_url = str(settings.get("ai_url") or "").strip()
    ai_key = str(settings.get("ai_api_key") or "").strip()
    ai_model = str(settings.get("ai_model") or "").strip()
    if not (ai_url and ai_key and ai_model):
        return None, "configured_ai_not_ready", 0
    call_provider = _settings_routes._load_research_ai_provider()
    if not call_provider:
        return None, "provider_unavailable", 0
    failure_meta: dict[str, Any] = {}
    response, error, _latency = await call_provider(
        ai_url=ai_url,
        ai_api_key=ai_key,
        model=ai_model,
        messages=messages,
        timeout_seconds=timeout,
        max_tokens=max_tokens,
        temperature=0.3,
        fallback_models=settings.get("ai_model_fallback"),
        overall_budget_seconds=timeout,
        failure_meta_sink=failure_meta,
        use_circuit_breaker=False,
    )
    provider_meta = (
        response.get("_provider_meta")
        if isinstance(response, dict) and isinstance(response.get("_provider_meta"), dict)
        else failure_meta
    ) or {}
    usage = (
        provider_meta.get("usage_units")
        if isinstance(provider_meta.get("usage_units"), dict)
        else provider_meta.get("usage") if isinstance(provider_meta.get("usage"), dict) else {}
    )
    try:
        provider_tokens = max(
            0,
            int(
                provider_meta.get("planning_units_spent")
                or provider_meta.get("token_units_spent")
                or usage.get("total_units")
                or usage.get("total_tokens")
                or 0
            ),
        )
    except (TypeError, ValueError):
        provider_tokens = 0
    estimated_tokens = max(
        1,
        (
            len(json.dumps(messages, default=str).encode("utf-8"))
            + len(json.dumps(response, default=str).encode("utf-8"))
            + 3
        ) // 4,
    ) if response is not None else 0
    return response, error, provider_tokens or estimated_tokens


def _agent_planner_turn_token_reservation(
    messages: list[dict[str, Any]],
    *,
    max_output_tokens: int,
) -> int:
    """Conservative pre-call reservation used to fail closed before exceeding episode tokens."""
    prompt_tokens = max(
        1,
        (len(json.dumps(messages, default=str).encode("utf-8")) + 3) // 4,
    )
    return prompt_tokens + max(0, int(max_output_tokens))


_AGENT_DAST_RETEST_FAMILIES: frozenset[str] = frozenset({
    "xss", "sqli", "nosqli", "ssrf",
    "path_traversal", "open_redirect", "ssti", "command_injection", "cors",
})


_AGENT_ROUTE_ONLY_RETEST_FAMILIES: frozenset[str] = frozenset({"cors"})


async def _persist_agent_suspected_finding(
    conn,
    target_uuid: uuid.UUID,
    target_url: str,
    finding: dict[str, Any],
    gate: dict[str, Any],
    *,
    run_receipt_id: Optional[str],
    research_episode_id: Optional[str],
    agent_hunt_run_id: Optional[str],
    known_keys: set[str],
) -> dict[str, Any]:
    """Persist a provenance-gated model claim as a non-authoritative investigation candidate.

    The candidate is kept outside ``findings`` until a registered deterministic verifier crosses
    the proof gate. It is deduplicated by family and canonical locus and retains enough bounded,
    redacted context for that verifier to replay the exact claim.
    """
    severity = str(finding.get("severity") or "info").lower()
    if severity not in ("critical", "high", "medium", "low", "info"):
        severity = "info"
    title = (str(finding.get("title") or "Autonomous agent finding")).strip()[:300]
    url_path, method = _agent_finding_locus(finding)
    try:
        concrete_url = _provision_same_origin_url(target_url, url_path) if url_path else target_url
    except HTTPException:
        concrete_url = target_url
    family = finding.get("family")
    vuln_key = (
        _arsenal_routes._canonical_vulnerability_key(family=family, route=(url_path or concrete_url), method=method)
        if family else None
    )
    # "Net new vs DAST" is meaningful only for a recognized family + exact operation.
    # Novel/unknown taxonomy still remains visible as SUSPECTED, but must not inflate this metric.
    net_new = bool(vuln_key) and vuln_key not in known_keys
    fingerprint_identity = vuln_key or (
        f"unclassified:{title}:{severity}:{method or ''}:{url_path or ''}"
    )
    fingerprint = hashlib.sha256(
        f"{target_uuid}:{fingerprint_identity}:autonomous_agent".encode()
    ).hexdigest()[:32]
    # DAST-retestable leads (injection + path_traversal/open_redirect/ssti/command_injection/cors)
    # carry their injection point (param + payload; route-only families like cors need neither) so the
    # deterministic prover can later promote them. `retest_type` makes infer_retest_type resolve the
    # right prover deterministically; the values themselves never self-verify — the worker's prover
    # (DOM-exec / DBMS / timing / file-content / Location-header / template-eval / Origin) is the arbiter.
    retest_family = normalize_retest_type(str(family)) if family else None
    if retest_family not in _AGENT_DAST_RETEST_FAMILIES:
        retest_family = None
    finding_param = str(finding.get("param")).strip()[:500] if (retest_family and finding.get("param")) else None
    finding_payload = str(finding.get("payload"))[:4000] if (retest_family and finding.get("payload")) else None
    evidence_json = _redact_finding_evidence({
        "trust_tier": "suspected",
        "provenance": gate.get("provenance"),
        "predicate": finding.get("predicate"),
        "family": family,
        "route": url_path,
        "method": method,
        "dedupe_dimensions": {
            "route": url_path,
            "method": method,
        } if url_path and method else {},
        "proof": finding.get("details"),
        "remediation": finding.get("remediation"),
        "evidence_refs": finding.get("evidence_refs"),
        "tool_evidence": finding.get("evidence"),
        "agent_run_receipt_id": run_receipt_id,
        "net_new_vs_known": net_new,
    })
    # The deterministic retest reads these from evidence (findings has no param/payload column).
    # Set them AFTER redaction: the payload is an attack string the prover must replay VERBATIM, and
    # a vulnerable param can be named like a secret ("token") — redaction would corrupt both.
    if retest_family:
        evidence_json["retest_type"] = retest_family
        if finding_param:
            evidence_json["param"] = finding_param
        if finding_payload:
            evidence_json["payload"] = finding_payload
    candidate = investigation_candidates.normalize_candidate(
        plane="web",
        target_id=str(target_uuid),
        research_episode_id=research_episode_id,
        agent_hunt_run_id=agent_hunt_run_id,
        family=family or retest_family or "unknown",
        locus={
            "method": method,
            "route": url_path or concrete_url,
            "parameter": finding_param,
        },
        title=title,
        claim=finding.get("details") or title,
        severity=severity,
        evidence_refs=finding.get("evidence_refs") or [],
        verifier_contract_id=(f"web.{retest_family}" if retest_family else None),
        source_kind="deep_hunt",
    )
    candidate_context = {
        "target_url": concrete_url,
        "method": method,
        "route": url_path,
        "parameter": finding_param,
        "payload": finding_payload,
        "retest_type": retest_family,
        "predicate": finding.get("predicate"),
        "proof": finding.get("details"),
        "remediation": finding.get("remediation"),
        "agent_run_receipt_id": run_receipt_id,
        "net_new_vs_known": net_new,
        "cvss": finding.get("cvss"),
        "cwe": finding.get("cwe"),
        "legacy_fingerprint": fingerprint,
        "evidence": evidence_json,
    }
    candidate_record = await investigation_candidates.upsert_candidate(
        conn, candidate, created_by="autonomous_agent",
        observation_context=candidate_context,
    )
    await conn.execute(
        """UPDATE investigation_candidates
           SET verification_context=verification_context || $2::jsonb, updated_at=NOW()
           WHERE id=$1 AND status NOT IN ('verified','refuted','expired')""",
        uuid.UUID(candidate_record["id"]), json.dumps(candidate_context, default=str),
    )
    return {
        "id": candidate_record["id"],
        "candidate_id": candidate_record["id"],
        "subject_type": "candidate",
        "persisted": "created" if candidate_record.get("inserted") else "existing",
        "existing_status": candidate_record.get("status"),
        "net_new": net_new,
        "title": title,
        "url": url_path,
    }








_AGENT_VERIFY_REQUEST_RESERVATIONS: dict[str, int] = {
    "bola": 8,             # four requests, independently replayed
    "auth_bypass": 4,      # two requests, independently replayed
    "data_exposure": 4,    # two requests, independently replayed
    "access_control": 4,   # same read as two role principals, independently replayed
    "field_constraint": 12, # before/mutate/violation/rollback/after, independently replayed
    "workflow": 12,        # forbidden-transition attempt + restore, independently replayed
    "mass_assignment": 20, # up to three shape probes + cleanup + eight-step two-run workflow
}


_AGENT_VERIFY_SECONDS_RESERVATIONS: dict[str, int] = {
    "bola": 180,
    "auth_bypass": 180,
    "data_exposure": 180,
    "access_control": 180,
    "field_constraint": 300,
    "workflow": 300,
    "mass_assignment": 400,
}


_AGENT_AUTO_VERIFY_EXCLUDED_FAMILIES: frozenset[str] = frozenset({"bola"})
def _agent_finding_locus(finding: dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """Resolve the exact vulnerable operation from this finding's cited tool evidence.

    A control/test finding often cites multiple requests. Never choose the first request
    arbitrarily: honor an explicit model-selected route/method only when that exact operation is
    among the cited evidence, or infer it only when all cited requests identify one operation.
    Ambiguity stays SUSPECTED and cannot be auto-verified against the wrong endpoint.
    """
    operations: list[tuple[str, str]] = []
    for ev in finding.get("evidence") or []:
        if not isinstance(ev, dict):
            continue
        try:
            payload = json.loads(ev.get("content") or "{}")
        except Exception:
            continue
        request_view = payload.get("request") if isinstance(payload, dict) else None
        if isinstance(request_view, dict) and request_view.get("path"):
            operation = (
                str(request_view.get("path"))[:500],
                str(request_view.get("method") or "GET").upper(),
            )
            if operation not in operations:
                operations.append(operation)
    requested_route = str(finding.get("route") or "").strip()[:500]
    requested_method = str(finding.get("method") or "").strip().upper()[:12]
    if requested_route and requested_method:
        for path, method in operations:
            if path == requested_route and method == requested_method:
                return path, method
        return None, None
    if len(operations) == 1:
        return operations[0]
    return None, None








