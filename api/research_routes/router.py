"""Research routes.

Extracted verbatim from the api.py monolith. This is the durable compatibility
controller behind the Leads and Test Builder pages: bounded experiment episodes,
their observations, decisions, plan steps, autopilot, settlement and
cancellation, plus campaign launch/control and readiness.

It supports Hunt; it is not a separate engine. New investigation work creates a
Hunt run, and these routes are retained for specialized guided verification and
for reading historical episodes.
"""

from __future__ import annotations

import asyncio
import asyncpg
import copy
import os
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import time
from typing import Any, Callable, Literal, Optional, Sequence
import urllib.parse
import uuid

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, ValidationError

try:
    from action_scope import _decode_json_value
    from ai_gate.targets.widget_playwright import logger
    from api_utils import _int_or_none, _optional_uuid, _uuid_or_400
    from request_models import ScanAdvancedLimits, ScanOptions
    from research_agent import GATED_RESEARCH_COMMANDS, READ_ONLY_RESEARCH_COMMANDS, RESEARCH_DECISION_VERSION, RESEARCH_EPISODE_VERSION, RESEARCH_OBSERVATION_VERSION, TARGET_BOUND_COMMANDS, TERMINAL_EPISODE_STATUSES
    from retest_contract import backfill_campaign_scan_finding_links
    from serialization import row_to_dict
    from ai_targets import router as _ai_targets
    from arsenal_routes import router as _arsenal_routes
    from settings_routes import router as _settings_routes
    from targets import router as _targets
except ModuleNotFoundError:  # package import in host-side tests
    from ..action_scope import _decode_json_value
    from ..ai_gate.targets.widget_playwright import logger
    from ..api_utils import _int_or_none, _optional_uuid, _uuid_or_400
    from ..request_models import ScanAdvancedLimits, ScanOptions
    from ..research_agent import GATED_RESEARCH_COMMANDS, READ_ONLY_RESEARCH_COMMANDS, RESEARCH_DECISION_VERSION, RESEARCH_EPISODE_VERSION, RESEARCH_OBSERVATION_VERSION, TARGET_BOUND_COMMANDS, TERMINAL_EPISODE_STATUSES
    from ..retest_contract import backfill_campaign_scan_finding_links
    from ..serialization import row_to_dict
    from ..ai_targets import router as _ai_targets
    from ..arsenal_routes import router as _arsenal_routes
    from ..settings_routes import router as _settings_routes
    from ..targets import router as _targets

try:
    import family_proof
    import parallel_scan
    from command_arsenal import validate_command_parameters as _validate_command_parameters
    from local_agent_routes.router import _find_hidden_local_agent_execution_requests
    from research_agent import (
        RISK_TIER_ORDER as RESEARCH_RISK_TIER_ORDER,
        action_cost as _research_action_cost,
        apply_cost as _research_apply_cost,
        budget_violations as _research_budget_violations,
        canonical_hash as _research_canonical_hash,
        command_projection as _research_command_projection,
        normalize_budget_limits as _research_normalize_budget_limits,
        normalize_budget_used as _research_normalize_budget_used,
        remaining_budget as _research_remaining_budget,
        validate_decision as _research_validate_decision,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from .. import family_proof, parallel_scan
    from ..command_arsenal import validate_command_parameters as _validate_command_parameters
    from ..local_agent_routes.router import _find_hidden_local_agent_execution_requests
    from ..research_agent import (
        RISK_TIER_ORDER as RESEARCH_RISK_TIER_ORDER,
        action_cost as _research_action_cost,
        apply_cost as _research_apply_cost,
        budget_violations as _research_budget_violations,
        canonical_hash as _research_canonical_hash,
        command_projection as _research_command_projection,
        normalize_budget_limits as _research_normalize_budget_limits,
        normalize_budget_used as _research_normalize_budget_used,
        remaining_budget as _research_remaining_budget,
        validate_decision as _research_validate_decision,
    )


router = APIRouter()

_pool_provider: Callable[[], Any] | None = None
_deps: dict[str, Callable[..., Any]] = {}


RESEARCH_PREFLIGHT_MAX_ATTEMPTS = 2
RESEARCH_RECON_ACTION_CAP = 6
RESEARCH_AUTOPILOT_LEASE_SECONDS = 30
RESEARCH_MAX_OBSERVATIONS_PER_EPISODE = 500
RESEARCH_PLANNER_MODES = {"configured_ai", "agent", "local_codex"}
RESEARCH_BUDGET_KEYS = ("steps", "actions", "active_actions", "requests", "wire_requests", "seconds", "model_tokens")
RESEARCH_PREFLIGHT_RESERVED_COST = {
    "steps": 0,
    "actions": 1,
    "active_actions": 1,
    "requests": 500,
    "wire_requests": 0,
    "seconds": 3600,
    "model_tokens": 0,
}
RESEARCH_PREFLIGHT_TRANSIENT_RETRY_SECONDS = 30
RESEARCH_AUTOPILOT_HEARTBEAT_SECONDS = 10
RESEARCH_DEFAULT_CAMPAIGN_FAMILIES = (
    "sqli", "xss", "auth", "bola", "mass_assignment", "workflow",
    "data_exposure", "access_control", "field_constraint",
)
RESEARCH_INCONCLUSIVE_ACTUATOR_LIMIT = 3
RESEARCH_PREFLIGHT_CLAIM_TTL_SECONDS = 120
RESEARCH_SEMANTIC_FALSIFICATION_LIMIT = 3
RESEARCH_OBSERVATION_MAX_BYTES = 32 * 1024


def configure_research_router(
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


def _json_size_bytes(*a: Any, **k: Any) -> Any:
    return _get("_json_size_bytes")(*a, **k)


def _load_effective_ai_settings(*a: Any, **k: Any) -> Any:
    return _get("_load_effective_ai_settings")(*a, **k)


def _load_effective_automation_settings(*a: Any, **k: Any) -> Any:
    return _get("_load_effective_automation_settings")(*a, **k)


def _normalize_research_planner_mode(*a: Any, **k: Any) -> Any:
    return _get("_normalize_research_planner_mode")(*a, **k)


async def _record_command_result(*a: Any, **k: Any) -> Any:
    return await _get("_record_command_result")(*a, **k)


async def _record_research_event(*a: Any, **k: Any) -> Any:
    return await _get("_record_research_event")(*a, **k)


async def _validate_approval_receipt_for_action(*a: Any, **k: Any) -> Any:
    return await _get("_validate_approval_receipt_for_action")(*a, **k)


def _validate_bounded_agent_parameters(*a: Any, **k: Any) -> Any:
    return _get("_validate_bounded_agent_parameters")(*a, **k)


def get_redis(*a: Any, **k: Any) -> Any:
    return _get("get_redis")(*a, **k)



async def cancel_scan(*a: Any, **k: Any) -> Any:
    return await _get("cancel_scan")(*a, **k)


__all__ = ["configure_research_router", "router"]
class ResearchObservationRequest(BaseModel):
    previous_command_result_id: Optional[str] = None
    created_by: Optional[str] = Field(default="research_agent_controller", max_length=120)


class ResearchPlannerStepRequest(BaseModel):
    execute: bool = True
    # Large reasoning planners (grok-4.5) need >120s on the first, largest observation pack; the old
    # 180s ceiling left no room for a retry after a provider ClientConnectionError. Allow up to 300s.
    timeout_seconds: int = Field(default=60, ge=10, le=300)
    max_tokens: int = Field(default=2500, ge=500, le=8000)
    created_by: Optional[str] = Field(default="configured_ai_research_planner", max_length=120)


class ResearchAutopilotRequest(BaseModel):
    enabled: bool
    planner_mode: Optional[str] = Field(
        default=None,
        pattern="^(configured_ai|agent|local_codex)$",
    )
    created_by: Optional[str] = Field(default="research_agent_operator", max_length=120)


class ResearchCampaignLaunchRequest(BaseModel):
    """Minimal-input durable campaign: target + standing approval + time/episode ceilings."""

    model_config = ConfigDict(extra="forbid")
    target_id: str
    intensity: str = Field(default="deep_hunt", pattern="^(analyze|hunt|relentless|deep_hunt)$")
    approval_receipt_id: Optional[str] = None
    planner_mode: Optional[str] = Field(
        default=None,
        pattern="^(configured_ai|agent|local_codex)$",
        description=(
            "Who chooses each bounded action. Agent mode is the clean-install default and uses "
            "the current Codex/Claude/OpenCode session; configured_ai uses the provider in AI settings."
        ),
    )
    duration_hours: int = Field(default=24, ge=1, le=168)
    max_episodes: int = Field(default=12, ge=1, le=100)
    budget_limits: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional aggregate ceilings; values may only reduce the derived campaign cap.",
    )
    objective: Optional[str] = Field(default=None, min_length=1, max_length=2000)
    allowed_families: list[str] = Field(default_factory=list, max_length=25)
    created_by: Optional[str] = Field(default="research_campaign_api", max_length=120)
    # Opt-in: every episode this campaign spawns runs the LLM-driven ReAct hunt loop
    # (configured_ai only). Leaves the menu/create-MA path untouched for non-agent_loop runs.
    agent_loop: bool = False


class ResearchCampaignControlRequest(BaseModel):
    action: str = Field(pattern="^(pause|resume|cancel)$")
    created_by: Optional[str] = Field(default="research_campaign_operator", max_length=120)


RESEARCH_ASM_FAMILIES = frozenset({"sqli", "xss", "auth", "bola"})


@router.post("/research/episodes")
async def create_research_episode(req: ResearchEpisodeRequest):
    target_uuid = _uuid_or_400(req.target_id, "target id")
    if req.execution_mode == "read_only" and RESEARCH_RISK_TIER_ORDER.get(req.max_risk_tier, 99) > 0:
        raise HTTPException(status_code=400, detail="read_only episodes must use max_risk_tier=read_only")
    if req.execution_mode == "gated" and RESEARCH_RISK_TIER_ORDER.get(req.max_risk_tier, -1) < 2:
        raise HTTPException(status_code=400, detail="gated episodes require max_risk_tier=active or higher")
    budget_limits = _research_normalize_budget_limits(req.budget_limits, max_steps=req.max_steps)
    planner = _arsenal_routes._bounded_research_payload(req.planner or {})
    if not isinstance(planner, dict):
        planner = {}
    if _arsenal_routes._contains_forbidden_context_key(req.planner):
        raise HTTPException(status_code=400, detail="planner metadata contains a forbidden secret field")

    profile_commands = RESEARCH_MISSION_COMMANDS.get(req.mission_profile)
    expected_subject_types = {
        "target_hunt": {"target"},
        "verify_finding": {"finding"},
        "close_asm_gaps": {"target", "asm"},
    }
    if req.subject_type not in expected_subject_types[req.mission_profile]:
        raise HTTPException(status_code=400, detail="Mission profile does not support this subject type")
    subject_id = str(req.subject_id or req.target_id).strip()
    subject_uuid = _uuid_or_400(subject_id, "research subject id")
    allowed_families = [str(item).strip() for item in req.allowed_families if str(item).strip()]

    async with _pool().acquire() as conn:
        # Validations (incl. the gated approval check, which persists a durable "blocked"
        # audit row via _deny on denial) run OUTSIDE an explicit transaction, so a denied
        # creation's audit trail is not rolled back. Only the episode INSERT + first
        # observation are wrapped in a transaction so they stay atomic.
        target = await conn.fetchrow(
            "SELECT id, url, discovery_source FROM targets WHERE id=$1 AND is_active=true",
            target_uuid,
        )
        if not target:
            raise HTTPException(status_code=404, detail="Active target not found")
        parsed_target = urllib.parse.urlparse(str(target["url"] or ""))
        if parsed_target.scheme not in {"http", "https"} or not parsed_target.hostname:
            raise HTTPException(status_code=400, detail="Research episodes require an absolute HTTP(S) web/API target")
        if str(target["discovery_source"] or "") == "model-intake":
            raise HTTPException(status_code=400, detail="Model Intake artifacts are not web/API research targets")
        subject_summary: dict[str, Any] = {"type": req.subject_type, "id": str(subject_uuid)}
        if req.subject_type in {"target", "asm"}:
            if subject_uuid != target_uuid:
                raise HTTPException(status_code=400, detail="Research subject does not match target")
        elif req.subject_type == "finding":
            finding = await conn.fetchrow(
                "SELECT id, target_id, title, tool AS category, tool, cwe, source, ai_target_id FROM findings WHERE id=$1",
                subject_uuid,
            )
            if not finding:
                raise HTTPException(status_code=404, detail="Finding subject not found")
            if finding["target_id"] != target_uuid:
                raise HTTPException(status_code=400, detail="Finding subject is outside the episode target")
            if not _research_finding_is_web(finding):
                raise HTTPException(status_code=400, detail="Finding subject is not a DAST/ASM/manual web finding")
            subject_summary["title"] = str(finding["title"] or "")[:300]
            family = _arsenal_routes._research_finding_family(finding)
            if family:
                subject_summary["family"] = family
                if not allowed_families:
                    allowed_families = [family]
        planner["mission"] = {
            "profile": req.mission_profile,
            "subject": subject_summary,
            "allowed_commands": sorted(profile_commands) if profile_commands is not None else None,
        }
        scope_receipt_id = req.scope_receipt_id
        approval_receipt_id = req.approval_receipt_id
        if req.execution_mode == "gated":
            approval = await _validate_approval_receipt_for_action(
                conn,
                approval_receipt_id,
                target_url=str(target["url"]),
                target_id=target_uuid,
                action_name="research_episode.create",
                command="research.episode",
                risk_tier=req.max_risk_tier,
                created_by=req.created_by,
                always_require_receipt=True,
            )
            if scope_receipt_id and str(approval.get("scope_receipt_id")) != str(scope_receipt_id):
                raise HTTPException(status_code=400, detail="Episode scope receipt does not match approval receipt")
            scope_receipt_id = str(approval.get("scope_receipt_id"))
        operation_plan_id = _optional_uuid(req.operation_plan_id)
        campaign_id = _optional_uuid(req.campaign_id)
        if operation_plan_id and not await conn.fetchval("SELECT 1 FROM operation_plans WHERE id=$1", operation_plan_id):
            raise HTTPException(status_code=404, detail="Operation plan not found")
        if campaign_id:
            campaign_target = await conn.fetchval("SELECT target_id FROM campaigns WHERE id=$1", campaign_id)
            if campaign_target is None:
                raise HTTPException(status_code=404, detail="Campaign not found")
            if campaign_target != target_uuid:
                raise HTTPException(status_code=400, detail="Campaign target does not match research target")
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                INSERT INTO research_episodes (
                    target_id, operation_plan_id, campaign_id, objective, episode_version,
                    planner, execution_mode, status, max_risk_tier, allowed_families,
                    budget_limits, budget_used, scope_receipt_id, approval_receipt_id, created_by,
                    autopilot_enabled
                ) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,'created',$8,$9::jsonb,$10::jsonb,$11::jsonb,$12,$13,$14,$15)
                RETURNING *
                """,
                target_uuid,
                operation_plan_id,
                campaign_id,
                req.objective.strip(),
                RESEARCH_EPISODE_VERSION,
                json.dumps(planner),
                req.execution_mode,
                req.max_risk_tier,
                json.dumps(allowed_families),
                json.dumps(budget_limits),
                json.dumps(_research_normalize_budget_used({})),
                scope_receipt_id,
                _optional_uuid(approval_receipt_id),
                req.created_by,
                req.autopilot,
            )
            await _record_research_event(
                conn,
                row["id"],
                event_type="episode_created",
                status="created",
                summary="Created bounded research episode",
                details={"execution_mode": req.execution_mode, "max_risk_tier": req.max_risk_tier, "budget_limits": budget_limits, "autopilot": req.autopilot},
            )
            await _build_research_observation(conn, row)
        return await _research_episode_detail(conn, str(row["id"]))


@router.get("/research/readiness")
async def research_readiness():
    settings = _load_effective_ai_settings()
    configured_planner_ready = _research_configured_planner_ready()
    default_planner_mode = _normalize_research_planner_mode(
        _load_effective_automation_settings().get("default_research_planner_mode"),
    )
    return {
        # Backward-compatible alias for UI surfaces that still launch configured-provider autopilot.
        "planner_ready": configured_planner_ready,
        "default_planner_mode": default_planner_mode,
        "planner_modes": {
            "agent": {
                "ready": True,
                "durable": False,
                "label": "Current coding agent",
            },
            "local_codex": {
                "ready": True,
                "durable": False,
                "label": "Isolated local Codex",
            },
            "configured_ai": {
                "ready": configured_planner_ready,
                "durable": True,
                "label": "Stored AI provider",
            },
        },
        "configured_planner_ready": configured_planner_ready,
        "execution_enabled": _ai_ops_execute_enabled(),
        "campaign_readiness_policy": {
            "focused_preflight_required_for_gated_campaigns": True,
            "authenticated_preflight_families": sorted(_arsenal_routes.RESEARCH_PRIMARY_CREDENTIAL_FAMILIES),
            "minimum_unique_routes": _arsenal_routes.RESEARCH_SURFACE_MIN_UNIQUE_ROUTES,
            "minimum_narrow_public_routes": _arsenal_routes.RESEARCH_SURFACE_MIN_EXECUTABLE_ROUTES,
            "minimum_authenticated_routes": _arsenal_routes.RESEARCH_SURFACE_MIN_AUTHENTICATED_ROUTES,
            "distinct_second_user_required_for_bola": True,
            "preflight_max_attempts": RESEARCH_PREFLIGHT_MAX_ATTEMPTS,
            "semantic_falsification_limit": RESEARCH_SEMANTIC_FALSIFICATION_LIMIT,
            "recon_action_cap": RESEARCH_RECON_ACTION_CAP,
        },
        "model": str(settings.get("ai_model") or "")[:200] or None,
        "fallback_models": [
            item.strip()
            for item in str(settings.get("ai_model_fallback") or "").split(",")
            if item.strip()
        ],
    }


@router.get("/research/episodes/{episode_id}/benchmark")
async def research_episode_benchmark(
    episode_id: str,
    baseline_scan_id: str = Query(
        ...,
        description=(
            "Completed deterministic Scan baseline with "
            "options.benchmark_request_budget."
        ),
    ),
):
    """Score autonomous net-new verified findings against an explicitly equal-budget DAST baseline."""
    async with _pool().acquire() as conn:
        episode_row = await _research_episode_or_404(conn, episode_id)
        episode = _public_research_episode_row(episode_row)
        baseline_uuid = _uuid_or_400(baseline_scan_id, "baseline scan id")
        baseline = await conn.fetchrow(
            "SELECT id, target_id, scan_type, status, options FROM scans WHERE id=$1",
            baseline_uuid,
        )
        if not baseline or baseline["target_id"] != episode_row["target_id"]:
            raise HTTPException(status_code=400, detail="Baseline scan must belong to the episode target")
        if str(baseline["status"] or "") != "completed" or str(baseline["scan_type"] or "") != "smart":
            raise HTTPException(
                status_code=400,
                detail="Baseline must be a completed deterministic Scan benchmark",
            )
        options = _decode_json_value(baseline["options"]) or {}
        baseline_budget = _int_or_none(options.get("benchmark_request_budget"))
        episode_budget = int((episode.get("budget_limits") or {}).get("requests") or 0)
        if baseline_budget is None:
            raise HTTPException(status_code=400, detail="Baseline lacks options.benchmark_request_budget")
        equal_budget = baseline_budget == episode_budget
        baseline_rows = await conn.fetch(
            "SELECT id, fingerprint, title, tool, cwe, url, evidence, request FROM findings WHERE scan_id=$1",
            baseline_uuid,
        )
        autonomous_rows = await conn.fetch(
            """
            SELECT id, fingerprint, title, severity, tool, cwe, url, evidence, request,
                   last_verification_verdict
            FROM findings
            WHERE target_id=$1 AND tool='autonomous_workflow'
              AND EXISTS (
                  SELECT 1
                  FROM jsonb_array_elements(
                      COALESCE(evidence->'research_provenance_history', '[]'::jsonb)
                  ) AS provenance
                  WHERE provenance->>'episode_id'=$2::text
              )
              AND last_verification_verdict='exploited'
            ORDER BY created_at
            """,
            episode_row["target_id"],
            episode_row["id"],
        )
        # Any fingerprint produced by a NON-autonomous source on this target (the baseline scan,
        # any other DAST/scanner/manual finding, or a scan that ran during the episode window) is
        # not autonomy's to claim as net-new. Exclude all of them, not just the baseline scan.
        prior_source_rows = await conn.fetch(
            "SELECT id, fingerprint, title, tool, cwe, url, evidence, request FROM findings "
            "WHERE target_id=$1 AND COALESCE(tool,'') <> 'autonomous_workflow'",
            episode_row["target_id"],
        )
    prior_keys = {
        key for key in (_arsenal_routes._finding_vulnerability_key(row) for row in [*baseline_rows, *prior_source_rows])
        if key
    }
    autonomous_with_keys = [(row, _arsenal_routes._finding_vulnerability_key(row)) for row in autonomous_rows]
    net_new = [
        {
            field: row.get(field)
            for field in ("id", "fingerprint", "title", "severity", "last_verification_verdict")
        }
        for row, key in autonomous_with_keys if key and key not in prior_keys
    ]
    unattributable = [str(row["id"]) for row, key in autonomous_with_keys if not key]
    episode_actual_requests = int((episode.get("budget_used") or {}).get("requests") or 0)
    return {
        "episode_id": str(episode_row["id"]),
        "baseline_scan_id": str(baseline_uuid),
        "baseline_request_budget_configured": baseline_budget,
        "autonomous_request_budget_configured": episode_budget,
        "autonomous_requests_actual": episode_actual_requests,
        "equal_configured_budget": equal_budget,
        "gate_passed": bool(equal_budget and net_new),
        "net_new_verified_findings": net_new,
        "net_new_verified_count": len(net_new),
        "unattributable_autonomous_finding_ids": unattributable,
        "autonomous_verified_count": len(autonomous_rows),
        "baseline_finding_count": len(baseline_rows),
        "caveats": [
            "Budgets compared are CONFIGURED caps; the baseline's actual HTTP request count is not instrumented here.",
            "No application state snapshot/reset between runs; results can depend on shared mutable state.",
            "Worker build-fingerprint uniformity across the baseline and episode is not enforced here.",
            "gate_passed means: at least one VERIFIED autonomous finding whose canonical family+route identity "
            "no non-autonomous source on this target produced, at equal configured budget -- not a fully controlled superiority proof.",
        ],
        "metric": "net_new_verified_canonical_vulnerabilities_not_produced_by_any_non_autonomous_source_on_target",
    }


@router.post("/research/launch")
async def launch_research_episode(req: ResearchLaunchRequest):
    """Launch or reopen a server-defined, subject-bound autonomous mission."""
    expected_subject_types = {
        "target_hunt": {"target"},
        "verify_finding": {"finding"},
        "close_asm_gaps": {"target", "asm"},
    }
    if req.subject_type not in expected_subject_types[req.mission_profile]:
        raise HTTPException(status_code=400, detail="Mission profile does not support this subject type")

    launch_profile = dict(RESEARCH_LAUNCH_PROFILES[req.intensity])
    planner_mode = _research_launch_planner_mode(req)
    autopilot_enabled = planner_mode == "configured_ai"
    if autopilot_enabled:
        if not _research_configured_planner_ready():
            raise HTTPException(status_code=409, detail="Autonomous planner is not configured in AI settings")
    if launch_profile["execution_mode"] == "gated" and not _ai_ops_execute_enabled():
        raise HTTPException(status_code=409, detail="Autonomous active execution is disabled by server policy")

    subject_uuid = _uuid_or_400(req.subject_id, "research subject id")
    finding: Any = None
    async with _pool().acquire() as conn:
        if req.subject_type == "finding":
            finding = await conn.fetchrow(
                """
                SELECT f.id, f.target_id, f.title, f.severity,
                       f.tool AS category, f.tool, f.cwe,
                       f.source, f.ai_target_id,
                       t.url AS target_url
                FROM findings f
                JOIN targets t ON t.id=f.target_id AND t.is_active=true
                WHERE f.id=$1
                """,
                subject_uuid,
            )
            if not finding:
                raise HTTPException(status_code=404, detail="Web finding subject not found")
            if not _research_finding_is_web(finding):
                raise HTTPException(status_code=400, detail="AI Gate, AI Session, and Model Intake findings use dedicated replay workflows")
            target_id = finding["target_id"]
            target_url = str(finding["target_url"] or "")
        else:
            target_id = subject_uuid
            target = await conn.fetchrow(
                "SELECT id, url FROM targets WHERE id=$1 AND is_active=true",
                target_id,
            )
            if not target:
                raise HTTPException(status_code=404, detail="Active target subject not found")
            target_url = str(target["url"] or "")

        if not req.force_new:
            existing = await conn.fetchrow(
                """
                SELECT * FROM research_episodes
                WHERE target_id=$1
                  AND planner->'mission'->>'profile'=$2
                  AND planner->'mission'->'subject'->>'type'=$3
                  AND planner->'mission'->'subject'->>'id'=$4
                  AND execution_mode=$5
                  AND COALESCE(planner->>'launch_intensity', 'unknown')=$6
                  AND status NOT IN ('completed','cancelled','failed','budget_exhausted','blocked')
                ORDER BY created_at DESC
                LIMIT 1
                """,
                target_id,
                req.mission_profile,
                req.subject_type,
                str(subject_uuid),
                launch_profile["execution_mode"],
                req.intensity,
            )
            if existing:
                return await _reuse_research_launch_episode(
                    conn,
                    existing=existing,
                    req=req,
                    launch_profile=launch_profile,
                    target_id=target_id,
                    target_url=target_url,
                )

        if req.subject_type == "finding":
            active_retest = await conn.fetchrow(
                """
                SELECT id, status FROM finding_verifications
                WHERE finding_id=$1 AND status IN ('queued','running')
                ORDER BY created_at DESC LIMIT 1
                """,
                subject_uuid,
            )
            if active_retest:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "error": "finding_retest_already_active",
                        "retest_id": str(active_retest["id"]),
                        "status": str(active_retest["status"]),
                        "ui_path": f"/findings/{subject_uuid}",
                    },
                )

    budget_limits = dict(launch_profile["budget_limits"])
    max_steps = int(launch_profile["max_steps"])
    if req.mission_profile == "verify_finding":
        if req.intensity == "analyze":
            max_steps = 4
            budget_limits.update({
                "steps": 4, "actions": 3, "active_actions": 0, "requests": 0,
                "seconds": 300, "model_tokens": 40000,
            })
        else:
            # One proof replay is enough for a finding-focused mission. The controller must
            # observe that result before any follow-up reasoning.
            max_steps = 6
            budget_limits.update({
                "steps": 6, "actions": 5, "active_actions": 1, "requests": 25,
                "seconds": 900, "model_tokens": 75000,
            })
        title = str(finding["title"] or "finding")[:300]
        objective = (
            f"Determine whether finding {subject_uuid} ({title}) is reproducible and current. "
            "Inspect this exact finding first, run at most one bounded deterministic/tiered retest "
            "when authorized, wait for its proof result, then stop with the verdict, remaining "
            "uncertainty, and recommended next step. Do not launch unrelated target-wide work."
        )
    elif req.mission_profile == "close_asm_gaps":
        objective = (
            "Improve this target's most important ASM coverage gaps. Inspect current gaps and "
            "activity, choose the next bounded ASM action, wait for each result, avoid duplicate "
            "actions, and stop when no decision-relevant gap can be improved within budget."
        )
    else:
        objective = (
            "Find and verify the highest-impact security weaknesses on this target. Prioritize "
            "authorization, injection, sensitive-data exposure, and workflow abuse. Learn from "
            "each completed action, never repeat an identical no-progress action, and stop when "
            "the budget is exhausted or no valuable bounded action remains."
        )
    if req.objective_override:
        objective = req.objective_override.strip()
    if req.budget_limits_override:
        for key in RESEARCH_BUDGET_KEYS:
            if key not in req.budget_limits_override:
                continue
            try:
                budget_limits[key] = min(
                    int(budget_limits.get(key) or 0),
                    max(0, int(req.budget_limits_override[key])),
                )
            except (TypeError, ValueError):
                continue
        max_steps = min(max_steps, max(1, int(budget_limits.get("steps") or 1)))

    allowed_families = []
    if launch_profile["execution_mode"] == "gated":
        allowed_families = list(_research_intensity_campaign_families(req.intensity))
    if req.allowed_families_override:
        allowed_families = [str(item).strip() for item in req.allowed_families_override if str(item).strip()]
    if req.mission_profile == "target_hunt" and allowed_families:
        allowed_families = _validate_research_intensity_families(req.intensity, allowed_families)
    if finding:
        family = _arsenal_routes._research_finding_family(finding)
        allowed_families = [family] if family else []

    if req.mission_profile == "target_hunt" and req.intensity == "deep_hunt":
        # Deep Hunt may self-provision two managed principals via the app's own signup so
        # two-principal BOLA workflows are reachable without hand-configured credentials. Opt-in
        # (target metadata_json.auto_provisioning.enabled); best-effort; never blocks a launch.
        try:
            provisioning = await _research_maybe_auto_provision_principals(
                target_id,
                approval_receipt_id=req.approval_receipt_id,
                created_by=req.created_by,
                require_second_user="bola" in allowed_families,
            )
            logger.info(
                "deep_hunt principal bootstrap for target %s: %s",
                target_id,
                provisioning.get("action"),
            )
        except Exception:
            # A valid approval permits provisioning but does not make target-specific
            # signup failures fatal; the observation exposes missing principals.
            logger.warning("deep_hunt auto-provisioning failed for target %s", target_id, exc_info=True)

    if req.mission_profile == "target_hunt":
        # Seed the hunt with DAST-residue / application-graph leads (auth-boundary edges and
        # producer->consumer object flows persisted from prior scans) so the loop investigates
        # unexplained residue rather than re-verifying findings the scanner already reported.
        # The observation ranks with require_residue=True, so without these leads the ranked
        # board is empty and the planner degrades to generic scanning. Best-effort: the graph
        # only exists after a prior scan, and seeding must never block a launch.
        try:
            await _targets.generate_application_graph_hypotheses(
                str(target_id),
                created_by=f"hunt_launch:{req.created_by or 'operator'}",
            )
        except Exception:
            logger.warning("Hunt graph residue seeding failed for target %s", target_id, exc_info=True)
        try:
            # The graph is often empty until a two-user resource-map scan runs; the endpoint
            # inventory always has surface, so seed BOLA/mass-assignment leads from it too.
            await _targets.generate_endpoint_inventory_hypotheses(
                str(target_id),
                created_by=f"hunt_launch:{req.created_by or 'operator'}",
            )
        except Exception:
            logger.warning("Hunt inventory residue seeding failed for target %s", target_id, exc_info=True)

    create_request = ResearchEpisodeRequest(
        target_id=str(target_id),
        objective=objective,
        planner={
            "kind": _research_planner_kind(planner_mode),
            "mode": planner_mode,
            "created_by": req.created_by,
            "launch_intensity": req.intensity,
            "dedupe_launch": not req.force_new,
            # Server-authored marker used by the campaign-only active-slot uniqueness index. It
            # intentionally does not constrain legacy/manual mission campaigns.
            "campaign_autopilot": bool(req.campaign_id),
            # Opt-in ReAct hunt loop (only meaningful with the server AI provider).
            "agent_loop": bool(req.agent_loop and planner_mode == "configured_ai"),
        },
        execution_mode=launch_profile["execution_mode"],
        max_risk_tier=launch_profile["max_risk_tier"],
        allowed_families=allowed_families,
        max_steps=max_steps,
        budget_limits=budget_limits,
        approval_receipt_id=req.approval_receipt_id,
        campaign_id=req.campaign_id,
        subject_type=req.subject_type,
        subject_id=str(subject_uuid),
        mission_profile=req.mission_profile,
        created_by=req.created_by,
        autopilot=autopilot_enabled,
    )
    try:
        detail = await create_research_episode(create_request)
    except asyncpg.UniqueViolationError:
        # A concurrent identical one-click launch won the partial unique index race. Reuse its
        # durable mission instead of creating duplicate work.
        if req.force_new:
            raise
        async with _pool().acquire() as conn:
            existing = await conn.fetchrow(
                """
                SELECT * FROM research_episodes
                WHERE target_id=$1
                  AND planner->'mission'->>'profile'=$2
                  AND planner->'mission'->'subject'->>'type'=$3
                  AND planner->'mission'->'subject'->>'id'=$4
                  AND execution_mode=$5
                  AND planner->>'launch_intensity'=$6
                  AND planner->>'dedupe_launch'='true'
                  AND status NOT IN ('completed','cancelled','failed','budget_exhausted','blocked')
                ORDER BY created_at DESC LIMIT 1
                """,
                target_id,
                req.mission_profile,
                req.subject_type,
                str(subject_uuid),
                launch_profile["execution_mode"],
                req.intensity,
            )
            if not existing:
                raise
            return await _reuse_research_launch_episode(
                conn,
                existing=existing,
                req=req,
                launch_profile=launch_profile,
                target_id=target_id,
                target_url=target_url,
            )
    detail["reused"] = False
    detail["ui_path"] = f"/deep-hunt?episode_id={detail['episode']['id']}"
    return detail


@router.post("/research/campaigns/launch")
async def launch_research_campaign(req: ResearchCampaignLaunchRequest):
    """Launch a durable sequence of autonomous episodes from minimal operator input."""
    target_uuid = _uuid_or_400(req.target_id, "target id")
    planner_mode = _normalize_research_planner_mode(
        req.planner_mode,
        default=_normalize_research_planner_mode(
            _load_effective_automation_settings().get("default_research_planner_mode"),
        ),
    )
    if planner_mode == "configured_ai" and not _research_configured_planner_ready():
        raise HTTPException(
            status_code=409,
            detail="Stored-provider planning was selected, but no AI provider is configured",
        )
    unsupported_families = sorted({
        str(item).strip().lower() for item in req.allowed_families if str(item).strip()
    } - RESEARCH_CAMPAIGN_FAMILIES)
    if unsupported_families:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported autonomous research families: {', '.join(unsupported_families)}",
        )
    requested_families = list(dict.fromkeys(
        str(item).strip().lower() for item in req.allowed_families if str(item).strip()
    ))
    gated_campaign = RESEARCH_LAUNCH_PROFILES[req.intensity]["execution_mode"] == "gated"
    if gated_campaign and "allowed_families" in req.model_fields_set and not requested_families:
        raise HTTPException(
            status_code=400,
            detail="At least one vulnerability family is required for a gated research campaign",
        )
    if gated_campaign and "allowed_families" not in req.model_fields_set:
        requested_families = list(_research_intensity_campaign_families(req.intensity))
    if gated_campaign:
        requested_families = _validate_research_intensity_families(req.intensity, requested_families)
    deadline = datetime.now(timezone.utc) + timedelta(hours=req.duration_hours)
    metadata = {
        "autonomous_research": {
            "intensity": req.intensity,
            "planner_mode": planner_mode,
            "agent_loop": bool(req.agent_loop and planner_mode == "configured_ai"),
            "deadline_at": deadline.isoformat(),
            "max_episodes": req.max_episodes,
            "budget_limits": _research_campaign_budget_limits(
                req.intensity, req.max_episodes, req.budget_limits,
            ),
            "preflight_budget_used": _research_normalize_budget_used({}),
            "budget_used": _research_normalize_budget_used({}),
            "remaining_budget": _research_campaign_budget_limits(
                req.intensity, req.max_episodes, req.budget_limits,
            ),
            "approval_receipt_id": req.approval_receipt_id,
            "objective": req.objective,
            "allowed_families": requested_families,
            "require_all_requested_families": "allowed_families" in req.model_fields_set,
            "effective_families": [],
            "episodes_started": 0,
            "preflight_state": "pending" if gated_campaign else "not_required",
            "preflight_attempts": 0,
            "preflight_scan_id": None,
            "last_paused_episode_id": None,
            "last_error": None,
        }
    }
    async with _pool().acquire() as conn:
        target = await conn.fetchrow("SELECT id, url FROM targets WHERE id=$1 AND is_active=true", target_uuid)
        if not target:
            raise HTTPException(status_code=404, detail="Active target not found")
        campaign = await conn.fetchrow(
            """
            INSERT INTO campaigns (
                name, objective, campaign_type, target_id, target_scope, risk_tier,
                planner, status, metadata_json, created_by
            ) VALUES ($1,$2,'autonomous_research',$3,$4::jsonb,$5,$6::jsonb,'paused',$7::jsonb,$8)
            RETURNING *
            """,
            f"Autonomous research: {urllib.parse.urlparse(str(target['url'])).hostname}"[:200],
            req.objective or "Continuously find and verify net-new security weaknesses until the campaign ceiling is reached.",
            target_uuid,
            json.dumps({"target_id": str(target_uuid), "url": str(target["url"])}),
            RESEARCH_LAUNCH_PROFILES[req.intensity]["max_risk_tier"],
            json.dumps({
                "kind": _research_planner_kind(planner_mode),
                "mode": planner_mode,
                "campaign": True,
            }),
            json.dumps(metadata),
            req.created_by,
        )
    campaign_id = str(campaign["id"])
    campaign_requirements = _arsenal_routes._research_family_readiness_requirements(
        set(requested_families),
        gated=gated_campaign,
    )
    if req.intensity == "deep_hunt" and campaign_requirements["primary_credentials"]:
        try:
            provisioning = await _research_maybe_auto_provision_principals(
                target_uuid,
                approval_receipt_id=req.approval_receipt_id,
                created_by=req.created_by,
                require_second_user=bool(campaign_requirements["second_user"]),
            )
            logger.info(
                "deep_hunt campaign principal bootstrap for target %s: %s",
                target_uuid,
                provisioning.get("action"),
            )
        except Exception:
            # Readiness remains fail-closed and will surface the precise credential blocker.
            logger.warning(
                "deep_hunt campaign auto-provisioning failed for target %s",
                target_uuid,
                exc_info=True,
            )
    repair = await _research_campaign_self_repair(campaign_id)
    readiness = repair.get("readiness") if isinstance(repair.get("readiness"), dict) else {}
    if not readiness.get("ready"):
        repaired_campaign = repair.get("campaign") or _arsenal_routes._public_campaign_row(campaign)
        preflight_scan_id = repair.get("scan_id") or (
            ((repaired_campaign.get("metadata_json") or {}).get("autonomous_research") or {}).get("preflight_scan_id")
        )
        return {
            "campaign": repaired_campaign,
            "episode": None,
            "readiness": readiness,
            "preflight": {
                "action": repair.get("action"),
                "scan_id": preflight_scan_id,
                "status": "queued" if preflight_scan_id else repair.get("action"),
            },
            "ui_path": f"/scans/{preflight_scan_id}" if preflight_scan_id else "/deep-hunt",
        }
    async with _pool().acquire() as conn:
        await _materialize_research_invariant_hypotheses(conn, campaign["target_id"])
        current_campaign = await conn.fetchrow("SELECT * FROM campaigns WHERE id=$1", campaign["id"])
        budget = await _arsenal_routes._research_campaign_budget_snapshot(conn, current_campaign)
        episode_budget_limits = _research_campaign_episode_budget_limits(req.intensity, budget["remaining"])
        current_payload = row_to_dict(current_campaign)
        current_metadata = _decode_json_value(current_payload.get("metadata_json")) or {}
        current_config = (
            current_metadata.get("autonomous_research")
            if isinstance(current_metadata.get("autonomous_research"), dict)
            else {}
        )
        current_config.update({
            "budget_limits": budget["limits"],
            "budget_used": budget["used"],
            "remaining_budget": budget["remaining"],
            "effective_families": list(
                (readiness.get("surface") or {}).get("executable_families") or []
            ),
        })
        current_metadata["autonomous_research"] = current_config
        campaign = await conn.fetchrow(
            "UPDATE campaigns SET status=$2, metadata_json=$3::jsonb, updated_at=NOW() WHERE id=$1 RETURNING *",
            campaign["id"],
            "active" if _research_campaign_episode_budget_available(episode_budget_limits) else "paused",
            json.dumps(current_metadata, default=str),
        )
    if not _research_campaign_episode_budget_available(episode_budget_limits):
        return {
            "campaign": _arsenal_routes._public_campaign_row(campaign),
            "episode": None,
            "readiness": readiness,
            "stop_reason": "campaign_budget_exhausted",
            "ui_path": "/deep-hunt",
        }
    try:
        episode = await launch_research_episode(ResearchLaunchRequest(
            subject_type="target",
            subject_id=str(target_uuid),
            mission_profile="target_hunt",
            intensity=req.intensity,
            approval_receipt_id=req.approval_receipt_id,
            planner_mode=planner_mode,
            autopilot=planner_mode == "configured_ai",
            force_new=True,
            created_by=req.created_by,
            campaign_id=campaign_id,
            objective_override=req.objective,
            allowed_families_override=list(
                (readiness.get("surface") or {}).get("executable_families") or []
            ),
            budget_limits_override=episode_budget_limits,
            agent_loop=bool(req.agent_loop and planner_mode == "configured_ai"),
        ))
    except asyncpg.UniqueViolationError:
        # Finding 2: the campaign supervisor's 30s tick raced this launch and already started episode #1
        # (the partial unique index on the active-campaign episode fired). That is the desired outcome,
        # not a failure -- adopt the running episode instead of pausing the campaign and returning 500.
        async with _pool().acquire() as conn:
            existing = await conn.fetchrow(
                "SELECT id FROM research_episodes WHERE campaign_id=$1 ORDER BY created_at ASC LIMIT 1",
                campaign["id"],
            )
            updated = await conn.fetchrow(
                """
                UPDATE campaigns SET
                    metadata_json=jsonb_set(metadata_json, '{autonomous_research,episodes_started}', '1'::jsonb, true),
                    updated_at=NOW() WHERE id=$1 RETURNING *
                """,
                campaign["id"],
            )
            detail = await _research_episode_detail(conn, str(existing["id"])) if existing else {}
        episode = detail.get("episode") if isinstance(detail, dict) else None
        return {
            "campaign": _arsenal_routes._public_campaign_row(updated),
            "episode": episode,
            "ui_path": (episode or {}).get("ui_path") or (f"/research/episodes/{existing['id']}" if existing else None),
            "note": "campaign_supervisor_started_first_episode",
        }
    except Exception as exc:
        async with _pool().acquire() as conn:
            await conn.execute(
                """
                UPDATE campaigns SET status='paused',
                    metadata_json=jsonb_set(metadata_json, '{autonomous_research,last_error}', to_jsonb($2::text), true),
                    updated_at=NOW() WHERE id=$1
                """,
                campaign["id"], str(exc)[:500],
            )
        raise
    async with _pool().acquire() as conn:
        updated = await conn.fetchrow(
            """
            UPDATE campaigns SET
                metadata_json=jsonb_set(metadata_json, '{autonomous_research,episodes_started}', '1'::jsonb, true),
                updated_at=NOW() WHERE id=$1 RETURNING *
            """,
            campaign["id"],
        )
    return {"campaign": _arsenal_routes._public_campaign_row(updated), "episode": episode, "ui_path": episode.get("ui_path")}


@router.post("/research/campaigns/{campaign_id}/control")
async def control_research_campaign(campaign_id: str, req: ResearchCampaignControlRequest):
    campaign_uuid = _uuid_or_400(campaign_id, "campaign id")
    async with _pool().acquire() as conn:
        campaign = await conn.fetchrow(
            "SELECT * FROM campaigns WHERE id=$1 AND campaign_type='autonomous_research'",
            campaign_uuid,
        )
        if not campaign:
            raise HTTPException(status_code=404, detail="Autonomous research campaign not found")
        current_status = str(campaign.get("status") or "")
        if req.action == "resume" and current_status in {"completed", "cancelled"}:
            raise HTTPException(
                status_code=409,
                detail=f"A {current_status} research campaign cannot be resumed; launch a new campaign",
            )
        campaign_metadata = _decode_json_value(campaign.get("metadata_json")) or {}
        research_config = (
            campaign_metadata.get("autonomous_research")
            if isinstance(campaign_metadata.get("autonomous_research"), dict)
            else {}
        )
        preflight_scan_id = str(research_config.get("preflight_scan_id") or "") or None
        active_rows = await conn.fetch(
            """
            SELECT id FROM research_episodes WHERE campaign_id=$1
              AND status NOT IN ('completed','cancelled','failed','budget_exhausted','blocked')
            """,
            campaign_uuid,
        )
        status = {"pause": "paused", "resume": "active", "cancel": "cancelled"}[req.action]
        reset_exhausted_preflight = bool(
            req.action == "resume"
            and current_status == "paused"
            and research_config.get("last_error") == "authenticated_coverage_readiness_exhausted"
        )
        if reset_exhausted_preflight:
            history = (
                list(research_config.get("preflight_history") or [])
                if isinstance(research_config.get("preflight_history"), list)
                else []
            )
            history.append({
                "scan_id": preflight_scan_id,
                "attempts": int(research_config.get("preflight_attempts") or 0),
                "state": research_config.get("preflight_state"),
                "reason": research_config.get("last_error"),
                "reset_at": datetime.now(timezone.utc).isoformat(),
                "reset_by": req.created_by,
            })
            research_config.update({
                "preflight_state": "pending",
                "preflight_scan_id": None,
                "preflight_job_id": None,
                "preflight_claim_id": None,
                "preflight_started_at": None,
                "preflight_attempts": 0,
                "preflight_resume_resets": int(research_config.get("preflight_resume_resets") or 0) + 1,
                "preflight_history": history[-10:],
                "readiness": {},
                "last_error": None,
            })
            campaign_metadata["autonomous_research"] = research_config
            updated = await conn.fetchrow(
                """
                UPDATE campaigns SET status=$2, metadata_json=$3::jsonb,
                    updated_at=NOW() WHERE id=$1 RETURNING *
                """,
                campaign_uuid,
                status,
                json.dumps(campaign_metadata, default=str),
            )
        elif req.action == "resume" and current_status == "paused" and research_config.get("last_error"):
            resume_history = (
                list(research_config.get("resume_history") or [])
                if isinstance(research_config.get("resume_history"), list)
                else []
            )
            resume_history.append({
                "reason": str(research_config.get("last_error"))[:500],
                "resumed_at": datetime.now(timezone.utc).isoformat(),
                "resumed_by": req.created_by,
            })
            research_config.update({
                "last_error": None,
                "resume_history": resume_history[-20:],
            })
            campaign_metadata["autonomous_research"] = research_config
            updated = await conn.fetchrow(
                """
                UPDATE campaigns SET status=$2, metadata_json=$3::jsonb,
                    updated_at=NOW() WHERE id=$1 RETURNING *
                """,
                campaign_uuid,
                status,
                json.dumps(campaign_metadata, default=str),
            )
        else:
            updated = await conn.fetchrow(
                "UPDATE campaigns SET status=$2, updated_at=NOW() WHERE id=$1 RETURNING *",
                campaign_uuid, status,
            )
        if req.action in {"pause", "resume"} and active_rows:
            resume_autopilot = (
                req.action == "resume"
                and str(research_config.get("planner_mode") or "configured_ai") == "configured_ai"
            )
            await conn.execute(
                """
                UPDATE research_episodes SET autopilot_enabled=$2,
                    autopilot_error=CASE WHEN $2 THEN NULL ELSE autopilot_error END,
                    updated_at=NOW() WHERE id=ANY($1::uuid[])
                """,
                [row["id"] for row in active_rows], resume_autopilot,
            )
    cancelled: list[str] = []
    cancelled_preflight_scan_ids: list[str] = []
    failed_preflight_scan_ids: list[str] = []
    if req.action == "cancel":
        for row in active_rows:
            try:
                await cancel_research_episode(str(row["id"]))
                cancelled.append(str(row["id"]))
            except HTTPException as exc:
                if exc.status_code not in {404, 409}:
                    raise
        if preflight_scan_id:
            try:
                await cancel_scan(preflight_scan_id)
                cancelled_preflight_scan_ids.append(preflight_scan_id)
            except HTTPException as exc:
                # A terminal scan is already safely stopped; only surface genuine cancellation failures.
                if exc.status_code not in {404, 409}:
                    failed_preflight_scan_ids.append(preflight_scan_id)
            except Exception:
                failed_preflight_scan_ids.append(preflight_scan_id)
    return {
        "campaign": _arsenal_routes._public_campaign_row(updated),
        "action": req.action,
        "affected_episode_ids": [str(row["id"]) for row in active_rows],
        "cancelled_episode_ids": cancelled,
        "cancelled_preflight_scan_ids": cancelled_preflight_scan_ids,
        "failed_preflight_scan_ids": failed_preflight_scan_ids,
    }


@router.get("/research/episodes")
async def list_research_episodes(
    target_id: Optional[str] = Query(None),
    campaign_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
):
    params: list[Any] = []
    clauses: list[str] = []
    if target_id:
        params.append(_uuid_or_400(target_id, "target id"))
        clauses.append(f"target_id=${len(params)}")
    if campaign_id:
        params.append(_uuid_or_400(campaign_id, "campaign id"))
        clauses.append(f"campaign_id=${len(params)}")
    if status:
        params.append(status)
        clauses.append(f"status=${len(params)}")
    params.append(limit)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            f"SELECT * FROM research_episodes{where} ORDER BY created_at DESC LIMIT ${len(params)}",
            *params,
        )
    return {"episodes": [_public_research_episode_row(row) for row in rows], "count": len(rows)}


@router.get("/research/episodes/{episode_id}")
async def get_research_episode(episode_id: str):
    async with _pool().acquire() as conn:
        return await _research_episode_detail(conn, episode_id)


@router.post("/research/episodes/{episode_id}/observe")
async def refresh_research_observation(episode_id: str, req: ResearchObservationRequest):
    async with _pool().acquire() as conn:
        async with conn.transaction():
            row = await _research_episode_or_404(conn, episode_id, for_update=True)
            episode = _public_research_episode_row(row)
            if episode.get("terminal") or episode.get("cancel_requested"):
                raise HTTPException(status_code=409, detail="Terminal or cancelled episodes cannot create observations")
            if str(episode.get("status") or "") not in {"awaiting_planner", "awaiting_input"}:
                raise HTTPException(status_code=409, detail="Episode is waiting for an action result")
            if row.get("lease_owner") and row.get("lease_expires_at"):
                lease_active = await conn.fetchval("SELECT $1::timestamptz > NOW()", row["lease_expires_at"])
                if lease_active:
                    raise HTTPException(status_code=409, detail="Episode planner currently holds the observation lease")
            observation_count = await conn.fetchval(
                "SELECT COUNT(*) FROM research_observations WHERE episode_id=$1", row["id"]
            )
            if observation_count >= RESEARCH_MAX_OBSERVATIONS_PER_EPISODE:
                raise HTTPException(
                    status_code=429,
                    detail=f"Research episode observation limit reached ({RESEARCH_MAX_OBSERVATIONS_PER_EPISODE})",
                )
            observation = await _build_research_observation(
                conn,
                row,
                previous_command_result_id=req.previous_command_result_id,
            )
        return {"observation": observation, **(await _research_episode_detail(conn, episode_id))}


@router.post("/research/episodes/{episode_id}/cancel")
async def cancel_research_episode(episode_id: str):
    scan_ids: list[str] = []
    workflow_ids: list[str] = []
    cancelled_retest_ids: list[str] = []
    continuing_retest_ids: list[str] = []
    async with _pool().acquire() as conn:
        async with conn.transaction():
            row = await _research_episode_or_404(conn, episode_id, for_update=True)
            episode = _public_research_episode_row(row)
            if episode.get("terminal"):
                return await _research_episode_detail(conn, episode_id)
            scan_rows = await conn.fetch(
                """
                SELECT DISTINCT s.id AS scan_id
                FROM research_decisions rd
                LEFT JOIN command_results cr ON cr.id = rd.command_result_id
                JOIN scans s ON (
                    s.id = cr.scan_id
                    OR s.options->>'research_dispatch_correlation' = (
                        'research_episode:' || rd.episode_id::text || ':decision:' || rd.id::text
                    )
                )
                WHERE rd.episode_id=$1 AND s.status IN ('pending','queued','running')
                """,
                row["id"],
            )
            scan_ids = [str(item["scan_id"]) for item in scan_rows if item["scan_id"]]
            workflow_rows = await conn.fetch(
                """
                SELECT DISTINCT rd.action->'parameters'->>'workflow_id' AS workflow_id
                FROM research_decisions rd
                WHERE rd.episode_id=$1 AND rd.status='dispatching'
                  AND rd.action->>'command'='experiment.workflow'
                """,
                row["id"],
            )
            workflow_ids = [
                str(item["workflow_id"]) for item in workflow_rows if item.get("workflow_id")
            ]
            retest_rows = await conn.fetch(
                """
                SELECT DISTINCT fv.id, fv.status, fv.finding_id
                FROM research_decisions rd
                LEFT JOIN command_results cr ON cr.id=rd.command_result_id
                JOIN finding_verifications fv ON (
                    fv.id::text=cr.result_json->>'retest_id'
                    OR fv.requested_by=(
                        'research_episode:' || rd.episode_id::text || ':decision:' || rd.id::text
                    )
                )
                WHERE rd.episode_id=$1 AND fv.status IN ('queued','running')
                """,
                row["id"],
            )
            queued_retest_ids = [item["id"] for item in retest_rows if item["status"] == "queued"]
            continuing_retest_ids = [str(item["id"]) for item in retest_rows if item["status"] == "running"]
            if queued_retest_ids:
                cancelled = await conn.fetch(
                    """
                    UPDATE finding_verifications
                    SET status='cancelled', result_status='cancelled', verdict='cancelled',
                        verdict_reason='Parent research episode cancelled before retest started.',
                        completed_at=NOW(), updated_at=NOW()
                    WHERE id=ANY($1::uuid[]) AND status='queued'
                    RETURNING id
                    """,
                    queued_retest_ids,
                )
                cancelled_retest_ids = [str(item["id"]) for item in cancelled]
                cancelled_finding_ids = [
                    item["finding_id"] for item in retest_rows
                    if item["status"] == "queued" and str(item["id"]) in set(cancelled_retest_ids)
                ]
                if cancelled_finding_ids:
                    await conn.execute(
                        """
                        UPDATE findings
                        SET last_verification_status='cancelled', updated_at=NOW()
                        WHERE id=ANY($1::uuid[])
                        """,
                        cancelled_finding_ids,
                    )
            await conn.execute(
                """
                UPDATE research_episodes
                SET cancel_requested=true, status='cancelled', stop_reason='operator_cancelled',
                    autopilot_enabled=false, lease_expires_at=NULL,
                    version=version+1, updated_at=NOW()
                WHERE id=$1
                """,
                row["id"],
            )
            await conn.execute(
                """
                UPDATE research_decisions
                SET status='blocked', validation_errors=(validation_errors || '["episode_cancelled"]'::jsonb),
                    updated_at=NOW()
                WHERE episode_id=$1 AND status='dispatching'
                """,
                row["id"],
            )
            await _record_research_event(
                conn,
                row["id"],
                event_type="episode_cancelled",
                status="cancelled",
                summary="Research episode cancelled by operator",
                details={
                    "linked_scan_ids": scan_ids,
                    "linked_workflow_ids": workflow_ids,
                    "cancelled_retest_ids": cancelled_retest_ids,
                    "continuing_retest_ids": continuing_retest_ids,
                },
            )
    cancelled_scans: list[str] = []
    cancelled_workflow_ids: list[str] = []
    completed_workflow_ids: list[str] = []
    for workflow_id in workflow_ids:
        event = _active_workflow_cancellations.get(workflow_id)
        if event:
            event.set()
            cancelled_workflow_ids.append(workflow_id)
        else:
            completed_workflow_ids.append(workflow_id)
    cancel_failed_scan_ids: list[str] = []
    for scan_id in scan_ids:
        try:
            await cancel_scan(scan_id)
            cancelled_scans.append(scan_id)
        except Exception:
            cancel_failed_scan_ids.append(scan_id)
            continue
    async with _pool().acquire() as conn:
        if cancel_failed_scan_ids:
            await _record_research_event(
                conn,
                _uuid_or_400(episode_id, "episode id"),
                event_type="scan_cancellation_failed",
                status="failed",
                summary="One or more linked scans could not be cancelled",
                details={"scan_ids": cancel_failed_scan_ids},
            )
        detail = await _research_episode_detail(conn, episode_id)
    detail["cancelled_scan_ids"] = cancelled_scans
    detail["cancelled_workflow_ids"] = cancelled_workflow_ids
    detail["completed_workflow_ids"] = completed_workflow_ids
    detail["cancel_failed_scan_ids"] = cancel_failed_scan_ids
    detail["cancelled_retest_ids"] = cancelled_retest_ids
    detail["continuing_retest_ids"] = continuing_retest_ids
    return detail


@router.post("/research/episodes/{episode_id}/settle")
async def settle_research_episode(episode_id: str):
    """Attach a completed async scan/retest result without polling or planning another step."""
    async with _pool().acquire() as conn:
        async with conn.transaction():
            row = await _research_episode_or_404(conn, episode_id, for_update=True)
            episode = _public_research_episode_row(row)
            if episode.get("terminal"):
                return {"settled": False, "reason": "episode_terminal", **(await _research_episode_detail(conn, episode_id))}
            if str(episode.get("status") or "") != "awaiting_observation":
                return {"settled": False, "reason": "episode_not_waiting", **(await _research_episode_detail(conn, episode_id))}
            settlement = await _settle_research_awaiting_observation(conn, row)
        return {**settlement, **(await _research_episode_detail(conn, episode_id))}


@router.post("/research/episodes/{episode_id}/decisions")
async def submit_research_decision(episode_id: str, req: _settings_routes.ResearchDecisionRequest):
    dispatch_request: _arsenal_routes.ArsenalExecuteRequest | None = None
    decision_id: uuid.UUID | None = None
    cost: dict[str, Any] | None = None
    normalized: dict[str, Any] = {}
    mode = "shadow"
    idempotency_key = ""
    inferable_request = False

    async with _pool().acquire() as conn:
        async with conn.transaction():
            episode_row = await _research_episode_or_404(conn, episode_id, for_update=True)
            episode = _public_research_episode_row(episode_row)
            if episode.get("terminal") or episode.get("cancel_requested"):
                raise HTTPException(status_code=409, detail="Research episode is terminal or cancelled")
            if (
                str((req.planner or {}).get("created_by") or "") == "server_autopilot"
                and not episode.get("autopilot_enabled")
            ):
                raise HTTPException(status_code=409, detail="Research autopilot was paused before dispatch")
            if episode.get("status") != "awaiting_planner":
                raise HTTPException(status_code=409, detail="Research episode is not awaiting a planner decision")
            observation_row = await conn.fetchrow(
                "SELECT * FROM research_observations WHERE id=$1 AND episode_id=$2",
                _uuid_or_400(req.observation_id, "observation id"),
                episode_row["id"],
            )
            if not observation_row or str(episode.get("current_observation_id") or "") != str(observation_row["id"]):
                raise HTTPException(status_code=409, detail="Decision must reference the current episode observation")
            observation = _public_research_observation_row(observation_row)
            observation_pack = observation.get("observation_pack") or {}
            raw = req.model_dump(mode="json", exclude={"planner", "model_tokens_used", "execute", "idempotency_key"})
            binding_errors = _research_canonicalize_action_shape(raw)
            # Freelance experiments: the planner often reasons up a hypothesis from the discovered
            # surface and designs a valid experiment for it, but omits hypothesis_id (the lead is not
            # on the seeded board). Bind a matching ranked lead, or create a tracked planner-derived
            # hypothesis, so valid experiments are not rejected for provenance alone.
            # Live create-MA materialization is deliberately deferred to the already-authorized
            # Arsenal dispatch. Decision validation, idempotency checks, semantic policy, and budget
            # checks are pure with respect to the target; rejected or replayed decisions cannot send
            # registration requests or hold this row lock across target I/O.
            binding_errors.extend(
                await _research_autobind_hypothesis(conn, episode, raw, observation_pack)
            )
            catalog = _research_command_catalog()
            normalized, errors, warnings, cost = _research_validate_decision(
                raw,
                episode=episode,
                observation={
                    "id": str(observation_row["id"]),
                    "context_hash": observation_row["context_hash"],
                    "proposable_commands": observation_pack.get("proposable_commands") or [],
                },
                command_catalog=catalog,
            )
            errors.extend(binding_errors)
            if _arsenal_routes._contains_forbidden_context_key(req.planner):
                errors.append("planner_metadata_contains_secret_field")
            model_limit = int((episode.get("budget_limits") or {}).get("model_tokens") or 0)
            model_used = int((episode.get("budget_used") or {}).get("model_tokens") or 0)
            if model_used + req.model_tokens_used > model_limit:
                errors.append("budget_exhausted:model_tokens")
            campaign_budget = None
            if episode.get("campaign_id"):
                campaign_row = await conn.fetchrow(
                    "SELECT * FROM campaigns WHERE id=$1",
                    _optional_uuid(episode.get("campaign_id")),
                )
                if campaign_row:
                    campaign_budget = await _arsenal_routes._research_campaign_budget_snapshot(conn, campaign_row)
            command = catalog.get(normalized.get("action", {}).get("command") or "")
            if normalized.get("decision") == "execute_action" and command:
                launch_intensity = str((episode.get("planner") or {}).get("launch_intensity") or "")
                if launch_intensity and int((episode.get("remaining_budget") or {}).get("steps") or 0) <= 1:
                    errors.append("budget_reserved_for_conclusion")
                params, parameter_errors = await _research_prepare_action(conn, episode, normalized, command)
                normalized["action"]["parameters"] = params
                errors.extend(parameter_errors)
                cost = _research_parameterized_action_cost(command, params, cost)
                errors.extend(_research_budget_violations(
                    episode.get("budget_limits"), episode.get("budget_used"), cost
                ))
                if campaign_budget:
                    aggregate_cost = {**(cost or {}), "model_tokens": req.model_tokens_used}
                    errors.extend(_research_campaign_budget_violations(
                        campaign_budget["limits"], campaign_budget["used"], aggregate_cost,
                    ))
                if await _research_is_consecutive_duplicate_action(
                    conn,
                    episode_row["id"],
                    normalized.get("action") or {},
                ):
                    errors.append("repeated_action_without_state_change")
                errors.extend(await _research_semantic_policy_violations(
                    conn,
                    episode,
                    normalized.get("action") or {},
                ))
                mode = str(episode.get("execution_mode") or "read_only")
                if mode == "read_only" and command.get("name") in GATED_RESEARCH_COMMANDS:
                    errors.append("gated_command_forbidden_in_read_only_episode")
                if mode == "gated" and command.get("name") in GATED_RESEARCH_COMMANDS:
                    if not episode.get("approval_receipt_id") or not episode.get("scope_receipt_id"):
                        errors.append("episode_approval_missing")
                    if not _ai_ops_execute_enabled():
                        errors.append("execution_feature_disabled")
            elif campaign_budget:
                errors.extend(_research_campaign_budget_violations(
                    campaign_budget["limits"], campaign_budget["used"],
                    {"model_tokens": req.model_tokens_used},
                ))
            if normalized.get("decision") == "request_input":
                inferable_request = _settings_routes._research_requested_input_is_in_observation(
                    normalized.get("requested_input"),
                    observation_pack,
                )
                if inferable_request:
                    errors.append("operator_input_unnecessary:use_selected_hypothesis_contract")
            errors = list(dict.fromkeys(errors))
            warnings = list(dict.fromkeys(warnings))
            key_material = {
                "episode_id": str(episode_row["id"]),
                "observation_id": str(observation_row["id"]),
                "client_key": req.idempotency_key,
                "decision": None if req.idempotency_key else normalized,
            }
            idempotency_key = _research_canonical_hash(key_material)
            existing = await conn.fetchrow("SELECT * FROM research_decisions WHERE idempotency_key=$1", idempotency_key)
            if existing:
                return {
                    "accepted": existing["status"] not in {"rejected", "blocked", "failed"},
                    "idempotent_replay": True,
                    "decision": _public_research_decision_row(existing),
                    **(await _research_episode_detail(conn, episode_id)),
                }
            decision_sequence = int(await conn.fetchval(
                "SELECT COALESCE(MAX(sequence), 0) + 1 FROM research_decisions WHERE episode_id=$1",
                episode_row["id"],
            ))
            status = "rejected" if errors else "accepted"
            hypothesis_id = _optional_uuid(normalized.get("hypothesis_id"))
            if hypothesis_id:
                bound_hypothesis = await conn.fetchrow(
                    "SELECT source, metadata_json FROM hypotheses WHERE id=$1 AND target_id=$2",
                    hypothesis_id,
                    episode_row["target_id"],
                )
                if not bound_hypothesis:
                    errors.append("hypothesis_not_found_for_target")
                    status = "rejected"
                    hypothesis_id = None
                elif normalized.get("action", {}).get("command") in {"experiment.http_diff", "experiment.workflow"}:
                    metadata = _decode_json_value(bound_hypothesis.get("metadata_json")) or {}
                    source = str(bound_hypothesis.get("source") or "").strip().lower()
                    residue_backed = source in {"app_graph", "benchmark", "dast", "scan", "scanner", "asm"} or bool(
                        metadata.get("unexplained_residue") or metadata.get("graph_edge_id")
                        or metadata.get("edge_id") or metadata.get("source_scan_id")
                        or metadata.get("baseline_scan_id")
                    )
                    if not residue_backed:
                        errors.append("experiment_hypothesis_must_be_backed_by_dast_residue_or_graph")
                        status = "rejected"
            decision_row = await conn.fetchrow(
                """
                INSERT INTO research_decisions (
                    episode_id, observation_id, sequence, decision_version, planner,
                    decision_type, hypothesis_id, action, expected_signal, falsifier,
                    reason, confidence, requested_input, stop_reason, status,
                    validation_errors, validation_warnings, policy_result, idempotency_key
                ) VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8::jsonb,$9,$10,$11,$12,$13,$14,$15,$16::jsonb,$17::jsonb,$18::jsonb,$19)
                RETURNING *
                """,
                episode_row["id"], observation_row["id"], decision_sequence,
                RESEARCH_DECISION_VERSION, json.dumps(_arsenal_routes._bounded_research_payload(req.planner or {})),
                normalized.get("decision"), hypothesis_id, json.dumps(normalized.get("action") or {}),
                normalized.get("expected_signal"), normalized.get("falsifier"), normalized.get("reason"),
                normalized.get("confidence") or 0, normalized.get("requested_input"), normalized.get("stop_reason"),
                status, json.dumps(errors), json.dumps(warnings),
                json.dumps({"execution_mode": mode, "model_tokens_used": req.model_tokens_used}), idempotency_key,
            )
            decision_id = decision_row["id"]
            used = _research_normalize_budget_used(episode.get("budget_used") or {})
            used["model_tokens"] += req.model_tokens_used
            if errors:
                next_status = "budget_exhausted" if any(item.startswith("budget_exhausted:") for item in errors) else "awaiting_planner"
                await conn.execute(
                    """
                    UPDATE research_episodes
                    SET status=$2, current_decision_id=$3, budget_used=$4::jsonb,
                        stop_reason=CASE WHEN $2='budget_exhausted' THEN 'budget_exhausted' ELSE stop_reason END,
                        version=version+1, updated_at=NOW()
                    WHERE id=$1
                    """,
                    episode_row["id"], next_status, decision_id, json.dumps(used),
                )
                await _record_research_event(
                    conn, episode_row["id"], event_type="decision_rejected", status=status,
                    summary="Planner decision rejected by deterministic policy", observation_id=observation_row["id"],
                    decision_id=decision_id, details={"validation_errors": errors},
                )
                if inferable_request and next_status == "awaiting_planner":
                    # Keep the same episode and turn the rejected request into a
                    # durable tool-style observation.  The next planner turn sees
                    # both the concrete contract and why operator escalation was
                    # unnecessary; the campaign supervisor never gets an
                    # ``awaiting_input`` episode to reap/restart.
                    refreshed = await conn.fetchrow(
                        "SELECT * FROM research_episodes WHERE id=$1",
                        episode_row["id"],
                    )
                    await _build_research_observation(
                        conn,
                        refreshed,
                        previous_result={
                            "execution_blocked_reason": "operator_input_resolved_from_observation",
                            "result": {
                                "status": "context_available",
                                "reason": "Use selected_hypothesis_contracts; no operator input is required.",
                            },
                        },
                        next_status="awaiting_planner",
                    )
                return {
                    "accepted": False,
                    "decision": _public_research_decision_row(decision_row),
                    **(await _research_episode_detail(conn, episode_id)),
                }

            if normalized["decision"] == "stop":
                used["steps"] += 1
                await conn.execute(
                    """
                    UPDATE research_episodes
                    SET status='completed', current_decision_id=$2, step_count=step_count+1,
                        budget_used=$3::jsonb, stop_reason=$4, version=version+1, updated_at=NOW()
                    WHERE id=$1
                    """,
                    episode_row["id"], decision_id, json.dumps(used), normalized.get("stop_reason"),
                )
                await _record_research_event(
                    conn, episode_row["id"], event_type="episode_stopped", status="completed",
                    summary=normalized.get("stop_reason") or "Planner stopped episode", observation_id=observation_row["id"],
                    decision_id=decision_id,
                )
                return {"accepted": True, "decision": _public_research_decision_row(decision_row), **(await _research_episode_detail(conn, episode_id))}

            if normalized["decision"] == "request_input":
                used["steps"] += 1
                await conn.execute(
                    """
                    UPDATE research_episodes
                    SET status='awaiting_input', current_decision_id=$2, step_count=step_count+1,
                        budget_used=$3::jsonb, requested_input=$4, version=version+1, updated_at=NOW()
                    WHERE id=$1
                    """,
                    episode_row["id"], decision_id, json.dumps(used), normalized.get("requested_input"),
                )
                await _record_research_event(
                    conn, episode_row["id"], event_type="input_requested", status="awaiting_input",
                    summary=normalized.get("requested_input") or "Planner requested operator input",
                    observation_id=observation_row["id"], decision_id=decision_id,
                )
                return {"accepted": True, "decision": _public_research_decision_row(decision_row), **(await _research_episode_detail(conn, episode_id))}

            command = catalog[normalized["action"]["command"]]
            effective_cost = dict(cost or {})
            if mode == "shadow" or not req.execute:
                effective_cost["active_actions"] = 0
                effective_cost["requests"] = 0
                effective_cost["seconds"] = 0
            effective_cost["model_tokens"] = req.model_tokens_used
            await conn.execute(
                """
                UPDATE research_episodes
                SET status='dispatching', current_decision_id=$2, version=version+1, updated_at=NOW()
                WHERE id=$1
                """,
                episode_row["id"], decision_id,
            )
            await conn.execute(
                "UPDATE research_decisions SET status='dispatching', policy_result=$2::jsonb, updated_at=NOW() WHERE id=$1",
                decision_id,
                json.dumps({"execution_mode": mode, "cost_reserved": effective_cost, "model_tokens_used": req.model_tokens_used}),
            )
            await _record_research_event(
                conn, episode_row["id"], event_type="decision_accepted", status="dispatching",
                summary=f"Accepted one-step action {command['name']}", observation_id=observation_row["id"],
                decision_id=decision_id, details={"command": command["name"], "cost_reserved": effective_cost},
            )
            cost = effective_cost
            if mode != "shadow" and req.execute:
                confirmations: list[str] = []
                if episode.get("approval_receipt_id"):
                    approval_row = await conn.fetchrow("SELECT * FROM approval_receipts WHERE id=$1", episode["approval_receipt_id"])
                    if approval_row:
                        confirmations = list(_arsenal_routes._public_approval_receipt_row(approval_row).get("confirmations") or [])
                dispatch_request = _arsenal_routes.ArsenalExecuteRequest(
                    command=command["name"],
                    parameters=normalized["action"]["parameters"],
                    execute=True,
                    confirmations=confirmations,
                    approval_receipt_id=str(episode.get("approval_receipt_id") or "") or None,
                    scope_receipt_id=str(episode.get("scope_receipt_id") or "") or None,
                    created_by=f"research_episode:{episode_id}:decision:{decision_id}",
                    campaign_id=str(episode.get("campaign_id") or "") or None,
                    research_hypothesis_id=str(normalized.get("hypothesis_id") or "") or None,
                )

    if dispatch_request is None:
        dispatch_result: dict[str, Any] = {
            "command": normalized.get("action", {}).get("command"),
            "dispatched": False,
            "dry_run": True,
            "execution_blocked_reason": "shadow_mode" if mode == "shadow" else "execute_not_requested",
        }
    else:
        try:
            dispatch_result = await _arsenal_routes._arsenal_execute_detached(dispatch_request)
        except HTTPException as exc:
            dispatch_result = {
                "command": dispatch_request.command,
                "dispatched": False,
                "dry_run": False,
                "execution_blocked_reason": "arsenal_rejected",
                "error": _arsenal_routes._bounded_research_payload(exc.detail),
            }
        except Exception as exc:
            dispatch_result = {
                "command": dispatch_request.command,
                "dispatched": False,
                "dry_run": False,
                "execution_blocked_reason": "arsenal_error",
                "error": type(exc).__name__,
            }

    command_result = dispatch_result.get("command_result") if isinstance(dispatch_result.get("command_result"), dict) else {}
    command_result_id = command_result.get("id") or dispatch_result.get("operation_id")
    dispatched = bool(dispatch_result.get("dispatched"))
    async_ref = _research_dispatch_async_ref(dispatch_result) if dispatched else None
    decision_status = "dispatching" if async_ref else ("completed" if dispatched or mode == "shadow" else "blocked")
    cancelled_during_settlement = False
    settlement_already_recovered = False
    compensation_scan_id: str | None = None
    compensation_error: str | None = None
    async with _pool().acquire() as conn:
        async with conn.transaction():
            episode_row = await _research_episode_or_404(conn, episode_id, for_update=True)
            episode = _public_research_episode_row(episode_row)
            same_decision = str(episode.get("current_decision_id") or "") == str(decision_id)
            if str(episode.get("status") or "") == "awaiting_observation" and same_decision:
                # Stale-dispatch recovery already attached/settled the durable receipt. The
                # original slow adapter may still return; make that return idempotent.
                await conn.execute(
                    """
                    UPDATE research_decisions
                    SET command_result_id=COALESCE(command_result_id, $2), updated_at=NOW()
                    WHERE id=$1
                    """,
                    decision_id,
                    _optional_uuid(command_result_id),
                )
                settlement_already_recovered = True
            elif episode.get("cancel_requested") or str(episode.get("status") or "") != "dispatching" or not same_decision:
                settled_cost = dict(cost or {})
                if not dispatched and mode != "shadow":
                    settled_cost["active_actions"] = 0
                    settled_cost["requests"] = 0
                    settled_cost["seconds"] = 0
                used = _research_apply_cost(episode.get("budget_used") or {}, settled_cost)
                await conn.execute(
                    """
                    UPDATE research_decisions
                    SET status='blocked', command_result_id=$2, policy_result=$3::jsonb, updated_at=NOW()
                    WHERE id=$1
                    """,
                    decision_id,
                    _optional_uuid(command_result_id),
                    json.dumps({
                        "cancelled_before_settlement": True,
                        "async_work": async_ref,
                        "cost_settled": settled_cost,
                        "observation_summary": _arsenal_routes._bounded_research_payload(dispatch_result),
                    }),
                )
                await conn.execute(
                    """
                    UPDATE research_episodes
                    SET step_count=step_count+1, budget_used=$2::jsonb,
                        version=version+1, updated_at=NOW()
                    WHERE id=$1
                    """,
                    episode_row["id"],
                    json.dumps(used),
                )
                if async_ref and async_ref.get("kind") == "finding_retest":
                    cancelled_finding_id = await conn.fetchval(
                        """
                        UPDATE finding_verifications
                        SET status='cancelled', result_status='cancelled', verdict='cancelled',
                            verdict_reason='Research episode cancelled during dispatch.',
                            completed_at=NOW(), updated_at=NOW()
                        WHERE id=$1 AND status='queued'
                        RETURNING finding_id
                        """,
                        _optional_uuid(async_ref.get("id")),
                    )
                    if cancelled_finding_id:
                        await conn.execute(
                            """
                            UPDATE findings f
                            SET last_verification_status='cancelled', updated_at=NOW()
                            WHERE f.id=$1
                              AND NOT EXISTS (
                                  SELECT 1 FROM finding_verifications active
                                  WHERE active.finding_id=f.id AND active.status IN ('queued','running')
                              )
                              AND (
                                  SELECT latest.id FROM finding_verifications latest
                                  WHERE latest.finding_id=f.id
                                  ORDER BY latest.created_at DESC LIMIT 1
                              )=$2
                            """,
                            cancelled_finding_id,
                            _optional_uuid(async_ref.get("id")),
                        )
                elif async_ref and async_ref.get("kind") == "scan":
                    compensation_scan_id = str(async_ref.get("id"))
                await _record_research_event(
                    conn,
                    episode_row["id"],
                    event_type="dispatch_compensated",
                    status="cancelled",
                    summary="Recorded compensation for work returned after its dispatch lease was no longer current",
                    decision_id=decision_id,
                    command_result_id=command_result_id,
                    details={
                        "async_work": async_ref,
                        "cost_settled": settled_cost,
                        "episode_status": episode.get("status"),
                        "same_decision": same_decision,
                    },
                )
                cancelled_during_settlement = True
            else:
                settled_cost = dict(cost or {})
                if not dispatched and mode != "shadow":
                    # A rejected/busy/no-op adapter may consume a planner step, but it did not spend
                    # target requests, active-action capacity, or execution time.
                    settled_cost["active_actions"] = 0
                    settled_cost["requests"] = 0
                    settled_cost["seconds"] = 0
                used = _research_apply_cost(episode.get("budget_used") or {}, settled_cost)
                next_step = int(episode.get("step_count") or 0) + 1
                max_steps = int((episode.get("budget_limits") or {}).get("steps") or 1)
                terminal = next_step >= max_steps
                next_status = "budget_exhausted" if terminal else "awaiting_planner"
                stop_reason = "max_steps_reached_without_conclusion" if terminal else None
                policy_result = {
                    "execution_mode": mode,
                    "dispatched": dispatched,
                    "execution_blocked_reason": dispatch_result.get("execution_blocked_reason"),
                    "cost_settled": settled_cost,
                    "async_work": async_ref,
                    "observation_summary": _arsenal_routes._bounded_research_payload(dispatch_result),
                }
                await conn.execute(
                    """
                    UPDATE research_decisions
                    SET status=$2, command_result_id=$3, policy_result=$4::jsonb, updated_at=NOW()
                    WHERE id=$1
                    """,
                    decision_id, decision_status, _optional_uuid(command_result_id), json.dumps(policy_result),
                )
                await conn.execute(
                    """
                    UPDATE research_episodes
                    SET status='awaiting_observation', step_count=$2, budget_used=$3::jsonb,
                        stop_reason=COALESCE($4, stop_reason), version=version+1, updated_at=NOW()
                    WHERE id=$1
                    """,
                    episode_row["id"], next_step, json.dumps(used), stop_reason,
                )
                await _record_research_hypothesis_outcome(
                    conn,
                    decision_id=decision_id,
                    command_result=command_result,
                )
                if async_ref:
                    await _record_research_event(
                        conn, episode_row["id"], event_type="action_waiting", status="awaiting_observation",
                        summary=f"Waiting for {async_ref['kind']} {async_ref['id']}",
                        decision_id=decision_id, command_result_id=command_result_id,
                        details={"dispatched": True, "async_work": async_ref},
                    )
                else:
                    await _record_research_event(
                        conn, episode_row["id"], event_type="action_observed", status=decision_status,
                        summary=f"Observed {normalized.get('action', {}).get('command')}: {'dispatched' if dispatched else 'not dispatched'}",
                        decision_id=decision_id, command_result_id=command_result_id,
                        details={"dispatched": dispatched, "blocked_reason": dispatch_result.get("execution_blocked_reason")},
                    )
                    refreshed = await conn.fetchrow("SELECT * FROM research_episodes WHERE id=$1", episode_row["id"])
                    await _build_research_observation(
                        conn,
                        refreshed,
                        previous_result=dispatch_result,
                        previous_command_result_id=command_result_id,
                        next_status=next_status,
                    )
    if cancelled_during_settlement and compensation_scan_id:
        try:
            await cancel_scan(compensation_scan_id)
        except Exception as exc:
            compensation_error = f"scan cancellation failed ({type(exc).__name__})"
        async with _pool().acquire() as conn:
            async with conn.transaction():
                await _record_research_event(
                    conn,
                    _uuid_or_400(episode_id, "episode id"),
                    event_type="dispatch_compensation_result",
                    status="failed" if compensation_error else "cancelled",
                    summary=(
                        "Failed to cancel scan queued during episode cancellation"
                        if compensation_error
                        else "Cancelled scan queued during episode cancellation"
                    ),
                    decision_id=decision_id,
                    command_result_id=command_result_id,
                    details={"scan_id": compensation_scan_id, "error": compensation_error},
                )
    async with _pool().acquire() as conn:
        detail = await _research_episode_detail(conn, episode_id)
    if settlement_already_recovered:
        return {
            "accepted": True,
            "recovered_settlement": True,
            "dispatched": dispatched,
            "decision_id": str(decision_id),
            **detail,
        }
    if cancelled_during_settlement:
        return {
            "accepted": False,
            "dispatch_compensation_scan_id": compensation_scan_id,
            "dispatch_compensation_error": compensation_error,
            **detail,
        }
    return {"accepted": True, "dispatched": dispatched, "decision_id": str(decision_id), **detail}


@router.post("/research/episodes/{episode_id}/plan-step")
async def plan_research_episode_step(episode_id: str, req: ResearchPlannerStepRequest):
    owner = f"manual-planner:{os.getpid()}:{uuid.uuid4()}"
    async with _pool().acquire() as conn:
        claimed = await conn.fetchval(
            """
            UPDATE research_episodes
            SET lease_owner=$2,
                lease_expires_at=NOW()+make_interval(secs => $3),
                updated_at=NOW()
            WHERE id=$1 AND status='awaiting_planner'
              AND (lease_expires_at IS NULL OR lease_expires_at < NOW())
            RETURNING id
            """,
            _uuid_or_400(episode_id, "episode id"), owner, RESEARCH_AUTOPILOT_LEASE_SECONDS,
        )
    if not claimed:
        raise HTTPException(status_code=409, detail="Episode planner is already running or not ready")
    heartbeat_stop = asyncio.Event()
    heartbeat_task = asyncio.create_task(
        _research_lease_heartbeat(_pool(), episode_id, owner, heartbeat_stop)
    )
    try:
        return await _plan_research_episode_step(episode_id, req)
    finally:
        heartbeat_stop.set()
        await heartbeat_task
        async with _pool().acquire() as conn:
            await conn.execute(
                "UPDATE research_episodes SET lease_owner=NULL, lease_expires_at=NULL WHERE id=$1 AND lease_owner=$2",
                _uuid_or_400(episode_id, "episode id"), owner,
            )


@router.put("/research/episodes/{episode_id}/autopilot")
async def set_research_episode_autopilot(episode_id: str, req: ResearchAutopilotRequest):
    episode_uuid = _uuid_or_400(episode_id, "episode id")
    async with _pool().acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow("SELECT * FROM research_episodes WHERE id=$1 FOR UPDATE", episode_uuid)
            if not row:
                raise HTTPException(status_code=404, detail="Research episode not found")
            current_mode = _research_episode_planner_mode(row)
            planner_mode = str(req.planner_mode or ("configured_ai" if req.enabled else current_mode))
            if req.enabled and planner_mode != "configured_ai":
                raise HTTPException(
                    status_code=400,
                    detail="Only configured_ai uses server autopilot; agent planners submit decisions directly",
                )
            if req.enabled and not _research_configured_planner_ready():
                raise HTTPException(
                    status_code=409,
                    detail="Stored-provider planning cannot resume until AI settings are configured",
                )
            if req.enabled and str(row["status"]) not in {"awaiting_planner", "awaiting_observation"}:
                raise HTTPException(status_code=409, detail="Only a planning/waiting episode can resume autopilot")
            if req.enabled and row.get("lease_owner") and row.get("lease_expires_at"):
                lease_active = await conn.fetchval("SELECT $1::timestamptz > NOW()", row["lease_expires_at"])
                if lease_active:
                    raise HTTPException(status_code=409, detail="Episode planner is already active")
            updated = await conn.fetchrow(
                """
                UPDATE research_episodes
                SET autopilot_enabled=$2,
                    planner=jsonb_set(
                        jsonb_set(planner, '{mode}', to_jsonb($3::text), true),
                        '{kind}', to_jsonb($4::text), true
                    ),
                    autopilot_error=CASE WHEN $2 THEN NULL ELSE autopilot_error END,
                    autopilot_consecutive_failures=CASE WHEN $2 THEN 0 ELSE autopilot_consecutive_failures END,
                    lease_owner=CASE
                        WHEN $2 AND (lease_expires_at IS NULL OR lease_expires_at < NOW()) THEN NULL
                        ELSE lease_owner
                    END,
                    lease_expires_at=CASE
                        WHEN $2 AND (lease_expires_at IS NULL OR lease_expires_at < NOW()) THEN NULL
                        ELSE lease_expires_at
                    END,
                    updated_at=NOW()
                WHERE id=$1
                RETURNING *
                """,
                episode_uuid, req.enabled, planner_mode, _research_planner_kind(planner_mode),
            )
            if row.get("campaign_id") and req.planner_mode:
                await conn.execute(
                    """
                    UPDATE campaigns
                    SET planner=jsonb_set(
                            jsonb_set(planner, '{mode}', to_jsonb($2::text), true),
                            '{kind}', to_jsonb($3::text), true
                        ),
                        metadata_json=jsonb_set(
                            metadata_json,
                            '{autonomous_research,planner_mode}',
                            to_jsonb($2::text),
                            true
                        ),
                        updated_at=NOW()
                    WHERE id=$1 AND campaign_type='autonomous_research'
                    """,
                    row["campaign_id"], planner_mode, _research_planner_kind(planner_mode),
                )
            await _record_research_event(
                conn,
                episode_uuid,
                event_type="autopilot_resumed" if req.enabled else "autopilot_paused",
                status=str(updated["status"]) if req.enabled else "paused",
                summary="Server autopilot resumed" if req.enabled else "Server autopilot paused by operator",
                details={"created_by": req.created_by, "planner_mode": planner_mode},
            )
            return await _research_episode_detail(conn, str(updated["id"]))
class ResearchEpisodeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str
    objective: str = Field(min_length=1, max_length=2000)
    planner: dict[str, Any] = Field(default_factory=lambda: {"kind": "local_agent", "agent": "codex"})
    execution_mode: str = Field(default="read_only", pattern="^(shadow|read_only|gated)$")
    max_risk_tier: str = Field(default="read_only", pattern="^(read_only|passive|active|intrusive|credential|dangerous)$")
    allowed_families: list[str] = Field(default_factory=list, max_length=25)
    max_steps: int = Field(default=5, ge=1, le=25)
    budget_limits: dict[str, Any] = Field(default_factory=dict)
    scope_receipt_id: Optional[str] = None
    approval_receipt_id: Optional[str] = None
    operation_plan_id: Optional[str] = None
    campaign_id: Optional[str] = None
    subject_type: str = Field(default="target", pattern="^(target|finding|asm)$")
    subject_id: Optional[str] = Field(default=None, max_length=200)
    mission_profile: str = Field(
        default="target_hunt",
        pattern="^(target_hunt|verify_finding|close_asm_gaps)$",
    )
    created_by: Optional[str] = Field(default="research_agent_operator", max_length=120)
    autopilot: bool = False


class ResearchLaunchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject_type: str = Field(pattern="^(target|finding|asm)$")
    subject_id: str = Field(min_length=1, max_length=200)
    mission_profile: str = Field(pattern="^(target_hunt|verify_finding|close_asm_gaps)$")
    intensity: str = Field(default="hunt", pattern="^(analyze|hunt|relentless|deep_hunt)$")
    approval_receipt_id: Optional[str] = None
    planner_mode: Optional[str] = Field(
        default=None,
        pattern="^(configured_ai|agent|local_codex)$",
    )
    autopilot: bool = True
    force_new: bool = False
    created_by: Optional[str] = Field(default="research_launch_api", max_length=120)
    campaign_id: Optional[str] = None
    objective_override: Optional[str] = Field(default=None, min_length=1, max_length=2000)
    allowed_families_override: list[str] = Field(default_factory=list, max_length=25)
    budget_limits_override: dict[str, Any] = Field(default_factory=dict)
    # Opt-in: run the LLM-driven ReAct hunt loop for this episode instead of the menu
    # planner. Only honored with configured_ai (the loop uses the server AI provider).
    agent_loop: bool = False




async def _research_maybe_auto_provision_principals(
    target_id: Any,
    *,
    approval_receipt_id: Any,
    created_by: str | None,
    require_second_user: bool,
) -> dict[str, Any]:
    """Best-effort managed-principal bootstrap shared by episode and campaign launches."""
    target_uuid = _optional_uuid(target_id)
    async with _targets._AUTO_PROVISION_SEMAPHORE:
        async with _pool().acquire() as conn:
            target = await conn.fetchrow(
                "SELECT id, url, is_active, metadata_json FROM targets WHERE id=$1",
                target_uuid,
            )
            if not target or not target.get("is_active"):
                return {"action": "skipped", "reason": "target_inactive"}
            config = _targets._auto_provisioning_config(dict(target))
            if not config.get("enabled"):
                return {"action": "skipped", "reason": "auto_provisioning_disabled"}
            principal_rows = await conn.fetch(
                """
                SELECT p.auth_state, p.credential_profile, p.is_active,
                       EXISTS (
                         SELECT 1 FROM target_credential_profiles cp
                         WHERE cp.target_id=p.target_id
                           AND lower(cp.name)=lower(p.credential_profile)
                           AND cp.is_active=true
                           AND (cp.expires_at IS NULL OR cp.expires_at > NOW())
                       ) AS credential_configured
                FROM target_principals p
                WHERE p.target_id=$1 AND p.is_active=true
                """,
                target_uuid,
            )
            signals = _arsenal_routes._target_credential_precondition_signals(
                [row_to_dict(row) for row in principal_rows]
            )
            ready = signals.get("primary_credentials") == "configured" and (
                not require_second_user
                or signals.get("second_user_credentials") == "configured"
            )
            if ready:
                return {"action": "reused", "credential_signals": signals}
            # Validate before the first outbound signup request. Episode creation validates
            # again later, but that cannot authorize an already-performed side effect.
            approval = await _validate_approval_receipt_for_action(
                conn,
                approval_receipt_id,
                target_url=str(target["url"]),
                target_id=target_uuid,
                action_name="target.principals.auto_provision",
                command="target.principals.auto_provision",
                risk_tier="credential",
                created_by=created_by,
                always_require_receipt=True,
            )
            provisioned = await _targets._auto_provision_principals(
                conn,
                target_uuid,
                str(target["url"]),
                config,
            )
            command_result = await _record_command_result(
                conn,
                command="target.principals.auto_provision",
                status="completed",
                risk_tier="credential",
                operator_message=f"Provisioned or reused {len(provisioned)} managed test principals",
                scope_receipt_id=str((approval or {}).get("scope_receipt_id") or "") or None,
                approval_receipt_id=approval_receipt_id,
                result_json={"target_id": str(target_uuid), "principals": provisioned},
                created_by=created_by,
            )
            return {
                "action": "provisioned",
                "principals": provisioned,
                "command_result_id": command_result.get("id"),
            }


RESEARCH_MISSION_COMMANDS: dict[str, set[str] | None] = {
    # None means the normal bounded research allowlist for the target.
    "target_hunt": None,
    "verify_finding": {"target.get", "finding.get", "finding.retest"},
    "close_asm_gaps": {
        "target.get", "target.principals", "target.principal_matrix",
        "asm.activity", "asm.gaps", "asm.improve", "asm.recon", "asm.test",
    },
}


def _research_configured_planner_ready() -> bool:
    settings = _load_effective_ai_settings()
    return all(
        str(settings.get(key) or "").strip()
        for key in ("ai_url", "ai_api_key", "ai_model")
    )


def _research_episode_planner_mode(episode: Any) -> str:
    payload = row_to_dict(episode) if episode is not None else {}
    planner = _decode_json_value(payload.get("planner")) or {}
    mode = str(planner.get("mode") or "").strip()
    if mode in RESEARCH_PLANNER_MODES:
        return mode
    return "configured_ai" if bool(payload.get("autopilot_enabled")) else "agent"


def _research_launch_planner_mode(req: ResearchLaunchRequest) -> str:
    if req.planner_mode in RESEARCH_PLANNER_MODES:
        return str(req.planner_mode)
    # Backward compatibility for existing launch clients that only know the autopilot boolean.
    return "configured_ai" if req.autopilot else "agent"


def _research_planner_kind(mode: str) -> str:
    return {
        "configured_ai": "configured_ai",
        "local_codex": "local_agent",
        "agent": "interactive_agent",
    }.get(mode, "interactive_agent")


def _research_campaign_budget_limits(
    intensity: str, max_episodes: int, overrides: Any = None,
) -> dict[str, int]:
    profile = RESEARCH_LAUNCH_PROFILES.get(intensity) or RESEARCH_LAUNCH_PROFILES["deep_hunt"]
    episodes = max(1, min(100, int(max_episodes or 1)))
    per_episode = profile["budget_limits"]
    # Readiness scans are campaign work too. Reserve room for the bounded maximum attempts so the
    # default aggregate cap does not make a one-episode campaign consume its entire action budget
    # before the actual research episode starts.
    limits = {
        key: int(per_episode.get(key) or 0) * episodes
        + int(RESEARCH_PREFLIGHT_RESERVED_COST.get(key) or 0) * RESEARCH_PREFLIGHT_MAX_ATTEMPTS
        for key in RESEARCH_BUDGET_KEYS
    }
    raw = overrides if isinstance(overrides, dict) else {}
    for key in RESEARCH_BUDGET_KEYS:
        if key not in raw:
            continue
        try:
            limits[key] = max(0, min(limits[key], int(raw[key])))
        except (TypeError, ValueError):
            continue
    return limits


def _research_campaign_budget_violations(limits: Any, used: Any, cost: Any) -> list[str]:
    limit_map = limits if isinstance(limits, dict) else {}
    used_map = _research_normalize_budget_used(used)
    cost_map = _research_normalize_budget_used(cost)
    return [
        f"campaign_budget_exhausted:{key}"
        for key in RESEARCH_BUDGET_KEYS
        if int(used_map.get(key) or 0) + int(cost_map.get(key) or 0)
        > int(limit_map.get(key) or 0)
    ]


def _research_campaign_episode_budget_limits(intensity: str, remaining: Any) -> dict[str, int]:
    profile = RESEARCH_LAUNCH_PROFILES.get(intensity) or RESEARCH_LAUNCH_PROFILES["deep_hunt"]
    available = remaining if isinstance(remaining, dict) else {}
    return {
        key: min(int(profile["budget_limits"].get(key) or 0), int(available.get(key) or 0))
        for key in RESEARCH_BUDGET_KEYS
    }


def _research_campaign_episode_budget_available(value: Any) -> bool:
    limits = value if isinstance(value, dict) else {}
    return bool(
        int(limits.get("steps") or 0) >= 2
        and int(limits.get("actions") or 0) >= 1
        and int(limits.get("model_tokens") or 0) > 0
    )


def _research_finding_is_web(finding: Any) -> bool:
    if not finding:
        return False
    source = str(finding.get("source") or "scan").strip().lower()
    tool = str(finding.get("tool") or "").strip().lower()
    return (
        not finding.get("ai_target_id")
        and source not in {"ai_gate", "ai_session", "model_intake"}
        and tool != "model_intake"
    )


def _public_research_decision_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    for key in ("planner", "action", "validation_errors", "validation_warnings", "policy_result"):
        payload[key] = _decode_json_value(payload.get(key)) or ([] if key.startswith("validation_") else {})
    return payload


_active_workflow_cancellations: dict[str, asyncio.Event] = {}


async def _research_episode_or_404(conn, episode_id: str, *, for_update: bool = False):
    episode_uuid = _uuid_or_400(episode_id, "research episode id")
    suffix = " FOR UPDATE" if for_update else ""
    row = await conn.fetchrow(f"SELECT * FROM research_episodes WHERE id=$1{suffix}", episode_uuid)
    if not row:
        raise HTTPException(status_code=404, detail="Research episode not found")
    return row


def _research_command_catalog() -> dict[str, dict[str, Any]]:
    return _arsenal_routes._operation_plan_allowed_commands()


async def _settle_research_awaiting_observation(conn, episode_row: Any) -> dict[str, Any]:
    episode = _public_research_episode_row(episode_row)
    if str(episode.get("status") or "") != "awaiting_observation" or episode.get("cancel_requested"):
        return {"settled": False, "reason": "episode_not_waiting"}
    active_work = await _research_async_work(conn, episode_row["id"], active_only=True)
    if active_work:
        return {"settled": False, "reason": "work_active", "waiting_on": active_work}
    result_context = await _research_latest_action_result(conn, episode_row["id"])
    terminal = int(episode.get("step_count") or 0) >= int(
        (episode.get("budget_limits") or {}).get("steps") or 1
    )
    # Exhausting action capacity is not a successful conclusion. Launch profiles reserve a
    # final planner turn so the model can synthesize the observed evidence and explicitly stop.
    # Legacy episodes that spend their last step on work end as incomplete, never "completed".
    next_status = "budget_exhausted" if terminal else "awaiting_planner"
    command_result = (
        result_context.get("command_result")
        if isinstance(result_context.get("command_result"), dict)
        else {}
    )
    decision_context = (
        result_context.get("decision")
        if isinstance(result_context.get("decision"), dict)
        else {}
    )
    linked_work = result_context.get("linked_work") or []
    observed_decision_status = _research_linked_work_outcome(linked_work) or "completed"
    command_result_id = command_result.get("id")
    await conn.execute(
        """
        UPDATE research_decisions
        SET status='completed', updated_at=NOW()
        WHERE episode_id=$1 AND status='dispatching' AND command_result_id=$2
        """,
        episode_row["id"], _optional_uuid(command_result_id),
    )
    if command_result_id:
        await conn.execute(
            """
            UPDATE campaign_actions
            SET status=$2,
                result_json=COALESCE(result_json, '{}'::jsonb) || $3::jsonb,
                updated_at=NOW()
            WHERE command_result_id=$1
              AND status IN ('planned','approved','queued','running','retest_scheduled')
            """,
            _optional_uuid(command_result_id),
            observed_decision_status,
            json.dumps({
                "linked_work_status": observed_decision_status,
                "linked_work": [
                    {key: item.get(key) for key in ("kind", "id", "status") if item.get(key) is not None}
                    for item in linked_work[:20]
                    if isinstance(item, dict)
                ],
            }),
        )
    # Link findings produced by hunt-driven scans back to the campaign ledger and stamp
    # research provenance on the finding rows, so they are distinguishable from organic
    # DAST output. Idempotent; no-op when nothing new settled.
    await backfill_campaign_scan_finding_links(conn)
    await _record_research_hypothesis_outcome(
        conn,
        decision_id=decision_context.get("id"),
        command_result=command_result,
    )
    await _record_research_event(
        conn,
        episode_row["id"],
        event_type="action_observed",
        status=observed_decision_status,
        summary=(
            "Observed completed asynchronous action"
            if observed_decision_status == "completed"
            else f"Observed asynchronous action outcome: {observed_decision_status}"
        ),
        command_result_id=command_result_id,
        details={"linked_work": linked_work},
    )
    await _build_research_observation(
        conn,
        episode_row,
        previous_result=result_context,
        previous_command_result_id=command_result_id,
        next_status=next_status,
    )
    return {
        "settled": True,
        "next_status": next_status,
        "command_result_id": command_result_id,
        "result_context": result_context,
    }


def _research_dispatch_async_ref(dispatch_result: Any) -> dict[str, Any] | None:
    if not isinstance(dispatch_result, dict):
        return None
    command_result = dispatch_result.get("command_result")
    if not isinstance(command_result, dict):
        command_result = {}
    scan_id = command_result.get("scan_id")
    result_json = command_result.get("result_json") if isinstance(command_result.get("result_json"), dict) else {}
    retest_id = result_json.get("retest_id")
    status = str(command_result.get("status") or "")
    if scan_id and status in {"planned", "approved", "queued", "running"}:
        return {"kind": "scan", "id": str(scan_id), "status": status}
    if retest_id and status in {"retest_scheduled", "queued", "running"}:
        return {"kind": "finding_retest", "id": str(retest_id), "status": status}
    return None


async def _research_prepare_action(
    conn,
    episode: dict[str, Any],
    decision: dict[str, Any],
    command: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    params = dict(decision.get("action", {}).get("parameters") or {})
    errors: list[str] = []
    target_id = str(episode.get("target_id") or "")
    mission = _research_mission(episode)
    subject = mission.get("subject") if isinstance(mission.get("subject"), dict) else {}
    schema = command.get("parameters_schema") if isinstance(command.get("parameters_schema"), dict) else {}
    unknown = sorted(set(params) - set(schema))
    errors.extend(f"action_parameter_not_declared:{name}" for name in unknown)
    if command.get("name") in TARGET_BOUND_COMMANDS:
        supplied_target_id = str(params.get("target_id") or "").strip()
        if supplied_target_id and supplied_target_id != target_id:
            errors.append("action_target_id_mismatch")
        params["target_id"] = target_id
    if command.get("name") == "scan.focused_family":
        target_url = await conn.fetchval("SELECT url FROM targets WHERE id=$1", uuid.UUID(target_id))
        if not target_url:
            errors.append("target_not_found")
        else:
            supplied_target = str(params.get("target") or "").strip()
            if supplied_target and supplied_target != str(target_url):
                errors.append("action_target_url_mismatch")
            params["target"] = str(target_url)
        raw_endpoints = params.get("custom_endpoints")
        if raw_endpoints is not None:
            if not isinstance(raw_endpoints, list) or not 1 <= len(raw_endpoints) <= 20:
                errors.append("focused_scan_custom_endpoints_invalid")
            else:
                endpoints = [_research_normalize_focused_endpoint(item) for item in raw_endpoints]
                if any(item is None for item in endpoints):
                    errors.append("focused_scan_custom_endpoint_outside_target")
                else:
                    params["custom_endpoints"] = list(dict.fromkeys(str(item) for item in endpoints))
        family = str(params.get("check_family") or "").strip().lower()
        for field, allowed_family in (
            ("custom_sqli_payloads", "sqli"),
            ("custom_xss_payloads", "xss"),
        ):
            payloads, valid_payloads = _research_normalize_injection_payloads(params.get(field))
            if not valid_payloads:
                errors.append(f"{field}_invalid")
            elif payloads and family != allowed_family:
                errors.append(f"{field}_requires_{allowed_family}_family")
            elif field in params:
                params[field] = payloads
    if command.get("name") in {"finding.get", "finding.retest"}:
        focused_finding_id = (
            str(subject.get("id") or "").strip()
            if str(subject.get("type") or "") == "finding"
            else ""
        )
        finding_id = str(params.get("finding_id") or "").strip()
        if focused_finding_id:
            if finding_id and finding_id != focused_finding_id:
                errors.append("action_finding_id_mismatch")
            finding_id = focused_finding_id
            params["finding_id"] = focused_finding_id
        if not finding_id:
            errors.append("finding_id_required")
        else:
            try:
                finding_uuid = uuid.UUID(finding_id)
            except ValueError:
                errors.append("finding_id_must_be_uuid")
            else:
                finding_row = await conn.fetchrow(
                    "SELECT target_id, tool AS category, tool, title, cwe FROM findings WHERE id=$1",
                    finding_uuid,
                )
                if str((finding_row or {}).get("target_id") or "") != target_id:
                    errors.append("finding_outside_episode_target")
                finding_family = _arsenal_routes._research_finding_family(finding_row)
                allowed_families = {str(item) for item in episode.get("allowed_families") or []}
                if allowed_families and finding_family and finding_family not in allowed_families:
                    errors.append("finding_family_not_allowed")
                if command.get("name") == "finding.retest":
                    active_retest = await conn.fetchval(
                        """
                        SELECT id FROM finding_verifications
                        WHERE finding_id=$1 AND status IN ('queued','running')
                        ORDER BY created_at DESC LIMIT 1
                        """,
                        finding_uuid,
                    )
                    if active_retest:
                        errors.append("finding_retest_already_active")
                    elif await _research_campaign_retest_cap_reached(
                        conn,
                        episode.get("campaign_id"),
                        finding_uuid,
                    ):
                        errors.append("finding_retest_campaign_cap_reached")
    if command.get("name") in {"scan.result", "deployment.decision"}:
        scan_id = str(params.get("scan_id") or "").strip()
        if not scan_id:
            errors.append("scan_id_required")
        else:
            try:
                scan_uuid = uuid.UUID(scan_id)
            except ValueError:
                errors.append("scan_id_must_be_uuid")
            else:
                scan_target = await conn.fetchval("SELECT target_id FROM scans WHERE id=$1", scan_uuid)
                if str(scan_target or "") != target_id:
                    errors.append("scan_outside_episode_target")
    allowed_families = {
        str(item).strip().lower()
        for item in episode.get("allowed_families") or []
        if str(item).strip()
    }
    check_family = str(params.get("check_family") or "").strip()
    proof_family = str(params.get("proof_family") or "").strip()
    if command.get("name") == "scan.focused_family" and not check_family:
        errors.append("check_family_required")
    if (
        command.get("name") in {"asm.improve", "asm.test"}
        and not check_family
        and allowed_families
    ):
        asm_families = allowed_families & RESEARCH_ASM_FAMILIES
        if len(asm_families) == 1:
            check_family = next(iter(asm_families))
            params["check_family"] = check_family
        elif asm_families != RESEARCH_ASM_FAMILIES:
            errors.append("check_family_required_for_scoped_episode")
    if allowed_families and check_family and not _research_family_is_allowed(check_family, allowed_families):
        errors.append("action_family_not_allowed")
    if (
        allowed_families
        and command.get("name") in {"experiment.http_diff", "experiment.workflow"}
        and proof_family
        and not _research_family_is_allowed(proof_family, allowed_families)
    ):
        errors.append("action_family_not_allowed")
    if command.get("name") in {"experiment.http_diff", "experiment.workflow"}:
        steps = params.get("steps") if isinstance(params.get("steps"), list) else []
        destructive_methods = sorted({
            str(step.get("method") or "GET").strip().upper()
            for step in steps
            if isinstance(step, dict)
            and str(step.get("method") or "GET").strip().upper() in (
                {"POST", "PUT", "PATCH", "DELETE"}
                if command.get("name") == "experiment.http_diff" else
                {"PUT", "PATCH", "DELETE"}
            )
        })
        # Cleanup-safe writes are permitted only for a credential-tier experiment.workflow: to
        # actually EXPLOIT state-changing bugs (mass_assignment, write-BOLA, workflow abuse) the loop
        # must be able to mutate. normalize_workflow already forces a cleanup/rollback step and a
        # `restored` assertion after any mutation, so the write is gated by proven restoration.
        # http_diff has no restoration contract and stays read-only.
        writes_allowed = (
            command.get("name") == "experiment.workflow"
            and str(episode.get("max_risk_tier") or "") == "credential"
        )
        if destructive_methods and not writes_allowed:
            errors.append(
                "autonomous_experiment_destructive_method_forbidden:"
                + ",".join(destructive_methods)
            )
        errors.extend(await _research_workflow_surface_violations(
            conn,
            target_id,
            params,
        ))
    errors.extend(f"model_control_field_forbidden:{path}" for path in _research_forbidden_control_paths(params))
    if _research_action_contains_secret_material(params):
        errors.append("action_parameters_contain_secret_field")
    if _find_hidden_local_agent_execution_requests(params):
        errors.append("action_parameters_contain_hidden_execution_request")
    if _json_size_bytes(params) > 4096:
        errors.append("action_parameters_too_large")
    bounded_errors: list[str] = []
    _validate_bounded_agent_parameters(params, path="action.parameters", errors=bounded_errors)
    errors.extend(bounded_errors)
    errors.extend(_validate_command_parameters(command, params))
    return params, list(dict.fromkeys(errors))


async def _research_is_consecutive_duplicate_action(
    conn,
    episode_id: str | uuid.UUID,
    action: dict[str, Any],
) -> bool:
    previous_rows = await conn.fetch(
        """
        SELECT rd.action, rd.status, rd.policy_result, rd.command_result_id,
               cr.finding_ids AS cr_finding_ids
        FROM research_decisions rd
        JOIN research_episodes re ON re.id=rd.episode_id
        LEFT JOIN command_results cr ON cr.id=rd.command_result_id
        WHERE rd.decision_type='execute_action'
          AND rd.status IN ('accepted','dispatching','completed','blocked')
          AND (
              rd.episode_id=$1 OR (
                  re.campaign_id IS NOT NULL
                  AND re.campaign_id=(SELECT campaign_id FROM research_episodes WHERE id=$1)
              )
          )
        ORDER BY rd.created_at DESC
        LIMIT 2000
        """,
        _optional_uuid(episode_id),
    )
    if not previous_rows:
        return False
    comparable = _arsenal_routes._research_action_dedupe_comparable(action)
    fingerprint = _research_canonical_hash(comparable)
    intervening_state_change = False
    for row in previous_rows:
        previous_action = _decode_json_value(row["action"]) or {}
        previous_comparable = _arsenal_routes._research_action_dedupe_comparable(previous_action)
        if _research_canonical_hash(previous_comparable) == fingerprint:
            return not intervening_state_change
        # A truly intervening state change requires the gated command to have actually PRODUCED a result
        # (a finding), not merely to have been dispatched. A failed/partial command that changed nothing
        # must NOT reset the duplicate guard -- otherwise the "failed A -> partial B -> failed A" loop the
        # audit flagged repeats forever. The 2,000-row window covers the maximum bounded campaign
        # decision volume and matches the campaign exhaustion ledger, preventing short-window rollover.
        # asyncpg returns JSONB as encoded text unless a custom codec is installed. ``bool("[]")`` is
        # true, so testing the raw column would treat every empty finding list as progress and reopen
        # the failed-A -> partial-B -> failed-A loop. Decode before deciding whether B made progress.
        produced_finding = bool(_decode_json_value(row.get("cr_finding_ids")) or [])
        if previous_comparable["command"] in GATED_RESEARCH_COMMANDS and produced_finding:
            intervening_state_change = True
    return False


def _research_parameterized_action_cost(
    command: dict[str, Any],
    parameters: dict[str, Any],
    base_cost: dict[str, Any] | None,
) -> dict[str, int]:
    """Reserve conservative target-work units for queued operations.

    The worker's exact HTTP count is not available at dispatch time, so these are explicit
    reservation units, not a false claim of exact network metering.
    """
    cost = {key: max(0, int(value or 0)) for key, value in (base_cost or {}).items()}
    name = str(command.get("name") or "")
    if name == "scan.focused_family":
        endpoint_count = max(1, len(parameters.get("custom_endpoints") or []))
        payload_count = max(
            10,
            len(parameters.get("custom_sqli_payloads") or []),
            len(parameters.get("custom_xss_payloads") or []),
        )
        cost["requests"] = max(
            cost.get("requests", 0),
            min(500, endpoint_count * payload_count),
        )
        cost["seconds"] = max(cost.get("seconds", 0), 600)
    elif name in {"asm.test", "asm.improve"}:
        try:
            batch_size = max(1, min(int(parameters.get("batch_size") or 50), 100))
        except (TypeError, ValueError):
            batch_size = 50
        cost["requests"] = max(cost.get("requests", 0), batch_size)
        cost["seconds"] = max(cost.get("seconds", 0), 180)
    elif name == "asm.recon":
        cost["requests"] = max(cost.get("requests", 0), 25)
        cost["seconds"] = max(cost.get("seconds", 0), 180)
    elif name == "finding.retest":
        cost["requests"] = max(cost.get("requests", 0), 4)
        cost["seconds"] = max(cost.get("seconds", 0), 120)
    return cost








RESEARCH_CAMPAIGN_FAMILIES = frozenset({
    *RESEARCH_ASM_FAMILIES,
    "mass_assignment",
    "workflow",
    "data_exposure",
    "access_control",
    "field_constraint",
})


def _research_intensity_campaign_families(intensity: Any) -> tuple[str, ...]:
    """Families with a real executable proof path at an intensity's risk ceiling."""
    profile = RESEARCH_LAUNCH_PROFILES.get(str(intensity or ""), {})
    if str(profile.get("max_risk_tier") or "") == "credential":
        return RESEARCH_DEFAULT_CAMPAIGN_FAMILIES
    if str(profile.get("execution_mode") or "") == "gated":
        return tuple(sorted(RESEARCH_ASM_FAMILIES))
    return ()


def _validate_research_intensity_families(intensity: Any, families: list[str]) -> list[str]:
    normalized = list(dict.fromkeys(
        str(item).strip().lower() for item in families if str(item).strip()
    ))
    supported = set(_research_intensity_campaign_families(intensity))
    unavailable = sorted(set(normalized) - supported)
    if unavailable:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Families require a higher research intensity: {', '.join(unavailable)}. "
                "Use deep_hunt for credential-bound workflow proof."
            ),
        )
    return normalized


async def _record_research_hypothesis_outcome(
    conn: Any,
    *,
    decision_id: Any,
    command_result: Any,
) -> dict[str, Any] | None:
    """Persist experiment learning on the bound hypothesis exactly once."""
    decision = await conn.fetchrow(
        "SELECT id, hypothesis_id, action FROM research_decisions WHERE id=$1",
        _optional_uuid(decision_id),
    )
    if not decision or not decision.get("hypothesis_id"):
        return None
    outcome = _arsenal_routes._research_experiment_outcome(decision.get("action"), command_result)
    if not outcome:
        return None
    hypothesis = await conn.fetchrow(
        "SELECT id, status, metadata_json FROM hypotheses WHERE id=$1 FOR UPDATE",
        decision["hypothesis_id"],
    )
    if not hypothesis:
        return None
    metadata = _decode_json_value(hypothesis.get("metadata_json")) or {}
    history = metadata.get("research_outcomes") if isinstance(metadata.get("research_outcomes"), list) else []
    decision_key = str(decision["id"])
    if any(str(item.get("decision_id") or "") == decision_key for item in history if isinstance(item, dict)):
        return outcome
    attempts = int(metadata.get("attempt_count") or 0) + 1
    failures = int(metadata.get("prior_failures") or 0)
    if outcome["outcome"] in {"inconclusive", "blocked"}:
        failures += 1
    metadata.update({
        "attempt_count": attempts,
        "prior_failures": failures,
        "last_outcome": outcome["outcome"],
        "last_outcome_reason": outcome.get("reason"),
        "research_outcomes": [
            *history,
            {
                **outcome,
                "decision_id": decision_key,
                "recorded_at": datetime.now(timezone.utc).isoformat(),
            },
        ][-20:],
    })
    current_status = str(hypothesis.get("status") or "open")
    next_status = current_status
    terminal_reason = None
    if current_status not in {"promoted", "dead", "exhausted"}:
        if outcome["outcome"] == "refuted" and outcome.get("deterministic_refutation"):
            next_status = "refuted"
            terminal_reason = "deterministic_experiment_refutation"
        elif outcome["outcome"] in {"verified", "supported_unverified"}:
            # Verified promotion normally sets promoted in the workflow
            # transaction.  Preserve that terminal status if it already did.
            next_status = "supported"
        elif outcome["outcome"] in {"inconclusive", "blocked"}:
            same_failure_count = sum(
                1
                for item in [*history, outcome]
                if isinstance(item, dict)
                and item.get("outcome") in {"inconclusive", "blocked"}
                and item.get("failure_class") == outcome.get("failure_class")
            )
            if same_failure_count >= RESEARCH_INCONCLUSIVE_ACTUATOR_LIMIT:
                next_status = "exhausted"
                terminal_reason = (
                    f"experiment_actuator_exhausted:{outcome.get('failure_class') or 'unknown'}"
                )
            else:
                next_status = "open"
    await conn.execute(
        """
        UPDATE hypotheses
        SET status=$2, metadata_json=$3::jsonb,
            terminal_reason=COALESCE($4, terminal_reason),
            version=version+1, updated_at=NOW()
        WHERE id=$1
        """,
        hypothesis["id"],
        next_status,
        json.dumps(metadata),
        terminal_reason,
    )
    return outcome


async def _research_semantic_policy_violations(
    conn: Any,
    episode: dict[str, Any],
    action: dict[str, Any],
) -> list[str]:
    snapshot = await _research_campaign_exhaustion_snapshot(
        conn,
        episode.get("id"),
        episode.get("campaign_id"),
    )
    errors: list[str] = []
    command = str(action.get("command") or "")
    if command in _arsenal_routes.RESEARCH_RECON_COMMANDS and int(snapshot.get("recon_actions") or 0) >= RESEARCH_RECON_ACTION_CAP:
        errors.append("campaign_recon_cap_reached")
    dimension = _arsenal_routes._research_action_semantic_dimension(action)
    if dimension and int((snapshot.get("falsification_counts") or {}).get(dimension) or 0) >= RESEARCH_SEMANTIC_FALSIFICATION_LIMIT:
        errors.append(f"semantic_dimension_exhausted:{dimension}")
    if dimension and any(
        str(actuator).startswith(f"{dimension}:")
        for actuator in snapshot.get("exhausted_inconclusive_actuators") or []
    ):
        errors.append(f"experiment_actuator_exhausted:{dimension}")
    if _research_action_vulnerability_keys(action) & await _arsenal_routes._research_known_vulnerability_keys(conn, episode.get("target_id")):
        errors.append("known_vulnerability_already_covered")
    return errors


async def _research_campaign_self_repair(campaign_id: Any) -> dict[str, Any]:
    """Queue one focused, principal-coherent readiness scan at a time.

    BOLA resource mapping requires user1 and user2 in the same execution.  Do
    not use auth-state shards here: they are useful for breadth accounting but
    structurally incapable of producing cross-principal graph edges.
    """
    campaign_uuid = _optional_uuid(campaign_id)
    async with _pool().acquire() as conn:
        campaign = await conn.fetchrow("SELECT * FROM campaigns WHERE id=$1", campaign_uuid)
        if not campaign:
            raise HTTPException(status_code=404, detail="Research campaign not found")
        readiness = await _arsenal_routes._research_campaign_readiness(conn, campaign)
        payload = row_to_dict(campaign)
        metadata = _decode_json_value(payload.get("metadata_json")) or {}
        config = metadata.get("autonomous_research") if isinstance(metadata.get("autonomous_research"), dict) else {}
        if readiness["ready"] or readiness["state"] == "waiting":
            if readiness["ready"] and not config.get("preflight_scan_id") and readiness.get("preflight_scan"):
                config.update({
                    "preflight_state": "completed",
                    "preflight_scan_id": str(readiness["preflight_scan"].get("id") or "") or None,
                    "preflight_kind": "reused_recent_authenticated_graph",
                    "readiness": readiness,
                })
                metadata["autonomous_research"] = config
                campaign = await conn.fetchrow(
                    "UPDATE campaigns SET metadata_json=$2::jsonb, updated_at=NOW() WHERE id=$1 RETURNING *",
                    campaign_uuid,
                    json.dumps(metadata, default=str),
                )
                return {
                    "action": "reused_authenticated_graph_preflight",
                    "readiness": readiness,
                    "campaign": _arsenal_routes._public_campaign_row(campaign),
                }
            return {"action": "none", "readiness": readiness, "campaign": _arsenal_routes._public_campaign_row(campaign)}
        retry_after_raw = str(config.get("preflight_retry_after") or "").strip()
        if retry_after_raw:
            try:
                retry_after = datetime.fromisoformat(retry_after_raw.replace("Z", "+00:00"))
                if retry_after.tzinfo is None:
                    retry_after = retry_after.replace(tzinfo=timezone.utc)
            except ValueError:
                retry_after = datetime.min.replace(tzinfo=timezone.utc)
            if retry_after > datetime.now(timezone.utc):
                return {
                    "action": "transient_retry_wait",
                    "retry_after": retry_after.isoformat(),
                    "readiness": readiness,
                    "campaign": _arsenal_routes._public_campaign_row(campaign),
                }
        if readiness["state"] == "blocked":
            config["readiness"] = readiness
            config["last_error"] = ",".join(readiness["blockers"])
            metadata["autonomous_research"] = config
            updated = await conn.fetchrow(
                "UPDATE campaigns SET status='paused', metadata_json=$2::jsonb, updated_at=NOW() WHERE id=$1 RETURNING *",
                campaign_uuid,
                json.dumps(metadata, default=str),
            )
            return {"action": "blocked", "readiness": readiness, "campaign": _arsenal_routes._public_campaign_row(updated)}
        stale_queueing_claim = _research_preflight_claim_is_stale(config)
        attempts = max(
            0,
            int(config.get("preflight_attempts") or 0) - (1 if stale_queueing_claim else 0),
        )
        if attempts >= RESEARCH_PREFLIGHT_MAX_ATTEMPTS:
            config["readiness"] = readiness
            config["last_error"] = "authenticated_coverage_readiness_exhausted"
            metadata["autonomous_research"] = config
            updated = await conn.fetchrow(
                "UPDATE campaigns SET status='paused', metadata_json=$2::jsonb, updated_at=NOW() WHERE id=$1 RETURNING *",
                campaign_uuid,
                json.dumps(metadata, default=str),
            )
            return {"action": "exhausted", "readiness": readiness, "campaign": _arsenal_routes._public_campaign_row(updated)}
        budget = await _arsenal_routes._research_campaign_budget_snapshot(conn, campaign)
        preflight_budget_before = _research_normalize_budget_used(
            config.get("preflight_budget_used") or {}
        )
        if stale_queueing_claim:
            preflight_budget_before = _research_subtract_cost(
                preflight_budget_before, RESEARCH_PREFLIGHT_RESERVED_COST,
            )
            budget["used"] = _research_subtract_cost(
                budget.get("used") or {}, RESEARCH_PREFLIGHT_RESERVED_COST,
            )
            budget["remaining"] = _research_campaign_budget_remaining(
                budget["limits"], budget["used"],
            )
        preflight_budget_used = _research_apply_cost(
            preflight_budget_before,
            RESEARCH_PREFLIGHT_RESERVED_COST,
        )
        aggregate_after_claim = {
            key: int(budget["used"].get(key) or 0) + int(RESEARCH_PREFLIGHT_RESERVED_COST.get(key) or 0)
            for key in RESEARCH_BUDGET_KEYS
        }
        budget_violations = [
            key for key in RESEARCH_BUDGET_KEYS
            if aggregate_after_claim[key] > int(budget["limits"].get(key) or 0)
        ]
        if budget_violations:
            config.update({
                "budget_limits": budget["limits"],
                "budget_used": budget["used"],
                "remaining_budget": budget["remaining"],
                "last_error": "campaign_budget_exhausted:" + ",".join(budget_violations),
            })
            metadata["autonomous_research"] = config
            updated = await conn.fetchrow(
                "UPDATE campaigns SET status='paused', metadata_json=$2::jsonb, updated_at=NOW() WHERE id=$1 RETURNING *",
                campaign_uuid,
                json.dumps(metadata, default=str),
            )
            return {
                "action": "campaign_budget_exhausted",
                "readiness": readiness,
                "campaign": _arsenal_routes._public_campaign_row(updated),
            }
        preflight_claim_id = str(uuid.uuid4())
        config.update({
            "preflight_state": "queueing",
            "preflight_claim_id": preflight_claim_id,
            "preflight_retry_after": None,
            "preflight_attempts": attempts + 1,
            "preflight_started_at": datetime.now(timezone.utc).isoformat(),
            "readiness": readiness,
            "budget_limits": budget["limits"],
            "preflight_budget_used": preflight_budget_used,
            "budget_used": aggregate_after_claim,
            "remaining_budget": _research_campaign_budget_remaining(
                budget["limits"], aggregate_after_claim,
            ),
        })
        metadata["autonomous_research"] = config
        claimed = await conn.fetchrow(
            """
            UPDATE campaigns SET metadata_json=$2::jsonb, status='active', updated_at=NOW()
            WHERE id=$1 AND status <> 'cancelled'
              AND (
                COALESCE(metadata_json #>> '{autonomous_research,preflight_state}', '')
                    NOT IN ('queueing','running')
                OR (
                  metadata_json #>> '{autonomous_research,preflight_state}' = 'queueing'
                  AND COALESCE(
                    NULLIF(metadata_json #>> '{autonomous_research,preflight_started_at}', '')::timestamptz,
                    '-infinity'::timestamptz
                  ) < NOW() - INTERVAL '2 minutes'
                )
                OR (
                  metadata_json #>> '{autonomous_research,preflight_state}' = 'running'
                  AND EXISTS (
                    SELECT 1 FROM scans linked_preflight
                    WHERE linked_preflight.id::text =
                          metadata_json #>> '{autonomous_research,preflight_scan_id}'
                      AND linked_preflight.status IN ('completed','failed','cancelled')
                  )
                )
              )
            RETURNING *
            """,
            campaign_uuid,
            json.dumps(metadata, default=str),
        )
        if not claimed:
            current = await conn.fetchrow("SELECT * FROM campaigns WHERE id=$1", campaign_uuid)
            return {
                "action": "preflight_claim_lost",
                "readiness": readiness,
                "campaign": _arsenal_routes._public_campaign_row(current),
            }
        target = await conn.fetchrow("SELECT id, url FROM targets WHERE id=$1 AND is_active=true", campaign["target_id"])
        if not target:
            raise HTTPException(status_code=404, detail="Active target not found")
        # DISTINCT then order: Postgres forbids an ORDER BY expression (the object-route-first
        # priority CASE) that is not in a SELECT DISTINCT list, so dedupe in a subquery and rank
        # outside it. Prior form raised InvalidColumnReferenceError and 500'd every gated launch.
        endpoint_rows = await conn.fetch(
            """
            SELECT method, path FROM (
                -- Dedupe by (method, path) only: the worklist below uses just "METHOD path",
                -- so keeping param_shape in DISTINCT spent LIMIT slots on duplicate method/path pairs.
                SELECT DISTINCT method, path
                FROM target_endpoints
                WHERE target_id=$1 AND COALESCE(test_status, '') <> 'gone'
                  AND (
                    $2::boolean=false
                    OR COALESCE(auth_state, '') IN ('user1','user2')
                  )
            ) e
            ORDER BY
              CASE
                WHEN path ~ '/(\\{[^/{}]+\\}|:[A-Za-z_][A-Za-z0-9_]*|[0-9]+)(/|$)' THEN 0
                WHEN upper(method)='GET' THEN 1
                ELSE 2
              END,
              path, method
            LIMIT 150
            """,
            campaign["target_id"],
            bool((readiness.get("required") or {}).get("primary_credentials")),
        )

    families = {
        str(item).strip().lower()
        for item in config.get("allowed_families") or []
        if str(item).strip()
    }
    # ``auth`` is a Hunt/research objective, not a canonical Scan family. An
    # authenticated surface refresh uses the Scan ``recon`` family with the
    # exact saved principal references; BOLA remains the cross-principal proof
    # family. Never leak the research taxonomy into Scan admission.
    focus_family = next(
        (family for family in ("bola", "sqli", "xss") if family in families),
        (
            "recon"
            if "auth" in families
            or (readiness.get("required") or {}).get("primary_credentials")
            else "all"
        ),
    )
    custom_endpoints = []
    for row in endpoint_rows:
        method = str(row.get("method") or "GET").strip().upper()
        path = str(row.get("path") or "").strip()
        if path:
            custom_endpoints.append(f"{method} {path}")

    try:
        queued = await _arsenal_routes._submit_scan(_targets.ScanInternalCompatibilityRequest(
            target=str(target["url"]),
            budget_profile="thorough",
            policy={
                "preset": "standard_active" if focus_family == "all" else "custom",
                "active_testing": True,
                "include_families": ([] if focus_family == "all" else [focus_family]),
            },
            advanced=ScanAdvancedLimits(
                include_families=[] if focus_family == "all" else [focus_family],
            ),
            approval_receipt_id=config.get("approval_receipt_id"),
            options=_research_preflight_scan_options(
                focus_family=focus_family,
                custom_endpoints=custom_endpoints,
                approval_receipt_id=config.get("approval_receipt_id"),
            ),
        ))
    except Exception as exc:
        transient = _research_preflight_error_is_transient(exc)
        async with _pool().acquire() as conn:
            campaign = await conn.fetchrow("SELECT * FROM campaigns WHERE id=$1", campaign_uuid)
            if str(campaign.get("status") or "") == "cancelled":
                return {
                    "action": "cancelled_during_preflight_queue",
                    "readiness": readiness,
                    "campaign": _arsenal_routes._public_campaign_row(campaign),
                }
            payload = row_to_dict(campaign)
            metadata = _decode_json_value(payload.get("metadata_json")) or {}
            config = metadata.get("autonomous_research") if isinstance(metadata.get("autonomous_research"), dict) else {}
            config.update({
                "preflight_state": "pending" if transient else "failed",
                "preflight_attempts": attempts if transient else attempts + 1,
                "preflight_budget_used": preflight_budget_before,
                "budget_used": budget["used"],
                "remaining_budget": _research_campaign_budget_remaining(
                    budget["limits"], budget["used"],
                ),
                "preflight_retry_after": (
                    datetime.now(timezone.utc)
                    + timedelta(seconds=RESEARCH_PREFLIGHT_TRANSIENT_RETRY_SECONDS)
                ).isoformat() if transient else None,
                "last_error": (
                    f"transient_preflight_queue_failure:{str(exc)[:450]}"
                    if transient else str(exc)[:500]
                ),
            })
            metadata["autonomous_research"] = config
            updated = await conn.fetchrow(
                """
                UPDATE campaigns SET status=$4, metadata_json=$2::jsonb, updated_at=NOW()
                WHERE id=$1
                  AND metadata_json #>> '{autonomous_research,preflight_claim_id}'=$3
                RETURNING *
                """,
                campaign_uuid,
                json.dumps(metadata, default=str),
                preflight_claim_id,
                "active" if transient else "paused",
            )
        return {
            "action": "retry_transient" if transient else "failed",
            "error": str(exc)[:500], "readiness": readiness,
            "campaign": _arsenal_routes._public_campaign_row(updated or campaign),
        }

    async with _pool().acquire() as conn:
        campaign = await conn.fetchrow("SELECT * FROM campaigns WHERE id=$1", campaign_uuid)
        payload = row_to_dict(campaign)
        metadata = _decode_json_value(payload.get("metadata_json")) or {}
        config = metadata.get("autonomous_research") if isinstance(metadata.get("autonomous_research"), dict) else {}
        config.update({
            "preflight_state": "running",
            "preflight_scan_id": queued.get("scan_id"),
            "preflight_job_id": queued.get("job_id"),
            "surface_before_preflight": readiness.get("surface") or {},
            "preflight_kind": "focused_two_principal_graph" if focus_family == "bola" else "focused_authenticated_family",
            "preflight_family": focus_family,
            "preflight_endpoint_count": len(custom_endpoints),
            "last_error": None,
            "preflight_retry_after": None,
        })
        metadata["autonomous_research"] = config
        updated = await conn.fetchrow(
            """
            UPDATE campaigns SET status='active', metadata_json=$2::jsonb, updated_at=NOW()
            WHERE id=$1 AND status <> 'cancelled'
              AND metadata_json #>> '{autonomous_research,preflight_claim_id}'=$3
            RETURNING *
            """,
            campaign_uuid,
            json.dumps(metadata, default=str),
            preflight_claim_id,
        )
        current = updated or campaign
    if not updated:
        try:
            await cancel_scan(str(queued.get("scan_id")))
        except Exception:
            logger.warning(
                "Could not cancel preflight %s after campaign control raced queue completion",
                queued.get("scan_id"),
                exc_info=True,
            )
        return {
            "action": "cancelled_during_preflight_queue",
            "scan_id": queued.get("scan_id"),
            "job_id": queued.get("job_id"),
            "readiness": readiness,
            "campaign": _arsenal_routes._public_campaign_row(current),
        }
    return {
        "action": "queued_authenticated_graph_preflight",
        "scan_id": queued.get("scan_id"),
        "job_id": queued.get("job_id"),
        "readiness": readiness,
        "campaign": _arsenal_routes._public_campaign_row(updated),
    }


async def _materialize_research_invariant_hypotheses(conn: Any, target_id: Any) -> int:
    """Make approved typed invariants enter the same ranked backlog as scanner residue."""
    rows = await conn.fetch(
        "SELECT * FROM target_invariant_contracts WHERE target_id=$1 AND status='approved' ORDER BY updated_at DESC",
        _optional_uuid(target_id),
    )
    materialized = 0
    for row in rows:
        await _arsenal_routes._upsert_hypothesis(
            conn,
            _targets._invariant_hypothesis_request(
                str(target_id),
                _targets._public_target_invariant_contract_row(row),
                created_by="research_campaign_readiness",
            ),
        )
        materialized += 1
    return materialized


async def _reuse_research_launch_episode(
    conn,
    *,
    existing: Any,
    req: ResearchLaunchRequest,
    launch_profile: dict[str, Any],
    target_id: uuid.UUID,
    target_url: str,
) -> dict[str, Any]:
    if str(existing["status"]) == "awaiting_input":
        raise HTTPException(
            status_code=409,
            detail={
                "error": "existing_episode_requires_input",
                "episode_id": str(existing["id"]),
                "ui_path": f"/deep-hunt?episode_id={existing['id']}",
            },
        )
    approval_id: uuid.UUID | None = None
    scope_id: str | None = None
    if launch_profile["execution_mode"] == "gated":
        approval = await _validate_approval_receipt_for_action(
            conn,
            req.approval_receipt_id,
            target_url=target_url,
            target_id=target_id,
            action_name="research_episode.resume",
            command="research.episode",
            risk_tier=launch_profile["max_risk_tier"],
            created_by=req.created_by,
            always_require_receipt=True,
        )
        approval_id = _optional_uuid(req.approval_receipt_id)
        scope_id = str(approval.get("scope_receipt_id") or "") or None
    updated = await conn.fetchrow(
        """
        UPDATE research_episodes
        SET approval_receipt_id=COALESCE($2, approval_receipt_id),
            scope_receipt_id=COALESCE($3, scope_receipt_id),
            autopilot_enabled=$4,
            planner=jsonb_set(
                jsonb_set(planner, '{mode}', to_jsonb($5::text), true),
                '{kind}', to_jsonb($6::text), true
            ),
            autopilot_error=NULL,
            autopilot_consecutive_failures=0, updated_at=NOW()
        WHERE id=$1
        RETURNING *
        """,
        existing["id"],
        approval_id,
        scope_id,
        _research_launch_planner_mode(req) == "configured_ai",
        _research_launch_planner_mode(req),
        _research_planner_kind(_research_launch_planner_mode(req)),
    )
    detail = await _research_episode_detail(conn, str(updated["id"]))
    detail["reused"] = True
    detail["ui_path"] = f"/deep-hunt?episode_id={updated['id']}"
    return detail




def _research_canonicalize_action_shape(raw: dict[str, Any]) -> list[str]:
    errors = _research_canonicalize_workflow_wrapper(raw)
    errors.extend(_research_canonicalize_experiment_steps_alias(raw))
    errors.extend(_research_canonicalize_hypothesis_binding(raw))
    return list(dict.fromkeys(errors))


async def _research_autobind_hypothesis(
    conn, episode: dict[str, Any], raw: dict[str, Any], observation_pack: dict[str, Any],
) -> list[str]:
    """Bind an experiment decision to a tracked hypothesis, mutating ``raw`` in place.

    An ``experiment.*`` decision must carry a hypothesis_id (for provenance + promotion), but the
    planner frequently omits it. Bind an existing ranked live-surface lead of the same complete
    vulnerability identity. Freelance routes fail closed: a model cannot manufacture the residue
    that later authorizes its own active experiment.
    """
    action = raw.get("action") if isinstance(raw.get("action"), dict) else {}
    command = str(action.get("command") or "")
    if command not in {"experiment.workflow", "experiment.http_diff"}:
        return []
    params = action.get("parameters") if isinstance(action.get("parameters"), dict) else {}
    # The workflow runtime requires a UUID workflow_id; the planner routinely omits it or invents a
    # non-UUID (the templates don't show it), which the arsenal rejects as "Invalid workflow id".
    # Supply a valid one so the experiment is dispatched instead of blocked.
    if command == "experiment.workflow":
        try:
            uuid.UUID(str(params.get("workflow_id") or "").strip())
        except ValueError:
            params["workflow_id"] = str(uuid.uuid4())
            action["parameters"] = params
    family = family_proof.canonical_family(params.get("proof_family") or "workflow")
    route = None
    selected_step: dict[str, Any] = {}
    steps = [step for step in (params.get("steps") or []) if isinstance(step, dict)]
    preferred_labels: set[str] = set()
    preferred_predicates = {
        "bola": {"cross_principal_access"},
        "auth_bypass": {"unauthenticated_control"},
        "data_exposure": {"sensitive_value_present"},
        "mass_assignment": {"forbidden_field_accepted"},
        "access_control": {"forbidden_role_access"},
        "field_constraint": {"constraint_violation_persisted"},
        "workflow": {"transition_invariant_broken"},
    }.get(family, set())
    for assertion in (params.get("assertions") or []):
        if isinstance(assertion, dict) and assertion.get("predicate") in preferred_predicates:
            preferred_labels.update(str(assertion.get(key) or "") for key in ("step", "candidate") if assertion.get(key))
    def _in_preferred(step: dict[str, Any]) -> bool:
        return str(step.get("label") or "") in preferred_labels
    # For mutation-based families the vulnerability identity is the state-changing endpoint the
    # forbidden field is assigned to (the lead's POST/PUT/PATCH route), NOT the GET step an assertion
    # reads it back on. Binding on the read step derives (GET, /orders/all/{id}) and can never match a
    # (POST, /orders/{id}) mass_assignment lead -- the experiment_hypothesis_not_on_ranked_live_surface
    # rejection seen for grok's mass_assignment experiments. Prefer the mutation step for those families.
    mutation_family = family in {"mass_assignment", "field_constraint", "workflow"}
    def _is_state_changing(step: dict[str, Any]) -> bool:
        return str(step.get("method") or "").upper() in {"POST", "PUT", "PATCH", "DELETE"}
    def _mutation_binding_priority(step: dict[str, Any]) -> tuple[int, int, int]:
        label = str(step.get("label") or "").strip().lower()
        explicitly_mutating = bool(
            re.search(r"(?:^|[_-])(mutat|transition|violat|attack|candidate)", label)
        )
        return (
            0 if explicitly_mutating else 1,
            0 if _in_preferred(step) else 1,
            0 if str(step.get("checkpoint") or "").lower() == "mutation" else 1,
        )
    if mutation_family and any(_is_state_changing(step) for step in steps):
        ordered_steps = (
            sorted(
                (s for s in steps if _is_state_changing(s)),
                key=_mutation_binding_priority,
            )
            + [s for s in steps if not _is_state_changing(s)]
        )
    else:
        ordered_steps = [s for s in steps if _in_preferred(s)] + [s for s in steps if not _in_preferred(s)]
    for step in ordered_steps:
        if isinstance(step, dict) and step.get("path"):
            route = _arsenal_routes._canonical_vulnerability_route(step.get("path"))
            if route:
                selected_step = step
                break
    if not route:
        route = _arsenal_routes._canonical_vulnerability_route(params.get("route") or params.get("url"))
    method = str(selected_step.get("method") or params.get("method") or "GET").upper()
    target_id = str(episode.get("target_id") or "")
    if not target_id or not route:
        return ["experiment_hypothesis_route_missing"]
    assertion_predicates = [
        str(assertion.get("predicate"))
        for assertion in (params.get("assertions") or [])
        if isinstance(assertion, dict) and assertion.get("predicate")
    ]
    vulnerability_dimensions = _arsenal_routes._research_vulnerability_dimensions(
        params.get("proof_family") or family,
        params,
        selected_step,
        {"predicates": assertion_predicates},
    )
    candidate_key = _arsenal_routes._canonical_vulnerability_key(
        family=family,
        route=route,
        method=method,
        dimensions=vulnerability_dimensions,
    )
    if not candidate_key:
        return ["experiment_hypothesis_identity_incomplete"]
    # Bind only an existing ranked lead whose complete vulnerability identity matches.
    ranked = (observation_pack.get("current_surface") or {}).get("ranked_hypotheses") or []
    supplied_hypothesis_id = str(raw.get("hypothesis_id") or "").strip()
    if supplied_hypothesis_id:
        # An explicit hypothesis id is already the strongest provenance binding the planner can
        # provide.  The ranked board was filtered against the current live endpoint inventory, so
        # accept that exact row when the experiment still targets its canonical family + operation.
        # Do not require the action's derived dimensional hash to equal the stored lead's hash:
        # assertions and server-bound variable names legitimately refine those dimensions when the
        # planner turns a graph lead into a typed workflow (for example, a BOLA lead with
        # ``object_key=transaction_id`` becomes a four-step principal-variable workflow).  Requiring
        # complete hash equality made a visibly ranked lead impossible to execute and caused the
        # autopilot rejection loop seen in campaign 96f94c01-41dc-4917-a48c-6aa93ee5e0c2.
        for entry in ranked:
            hypothesis = entry.get("hypothesis") if isinstance(entry, dict) else None
            if not isinstance(hypothesis, dict) or str(hypothesis.get("id") or "") != supplied_hypothesis_id:
                continue
            contract = _arsenal_routes._research_hypothesis_experiment_contract(hypothesis)
            contract_family = family_proof.canonical_family(
                contract.get("family") or hypothesis.get("family")
            )
            contract_route = _arsenal_routes._canonical_vulnerability_route(contract.get("route"))
            contract_method = str(contract.get("method") or "").upper()
            if (
                contract_family != family
                or not contract_route
                or contract_route != route
                or (contract_method and contract_method != method)
            ):
                return ["experiment_hypothesis_not_on_ranked_live_surface"]
            raw["hypothesis_id"] = supplied_hypothesis_id
            return []
        # Size-compaction can drop ranked_hypotheses from the persisted pack while KEEPING the derived
        # selected_hypothesis_contracts (the authoritative leads the planner is explicitly told to use,
        # and which the compactor preserves as mandatory control data). Bind an explicit id against
        # those too, so a visibly-selected live lead stays executable even when the ranked board was
        # compacted away -- otherwise the gate rejects every experiment against an empty board, the
        # exact experiment_hypothesis_not_on_ranked_live_surface spin observed on crAPI.
        for contract in (observation_pack.get("selected_hypothesis_contracts") or []):
            if not isinstance(contract, dict) or str(contract.get("hypothesis_id") or "") != supplied_hypothesis_id:
                continue
            contract_route = _arsenal_routes._canonical_vulnerability_route(contract.get("route"))
            contract_method = str(contract.get("method") or "").upper()
            if (
                family_proof.canonical_family(contract.get("family")) != family
                or not contract_route
                or contract_route != route
                or (contract_method and contract_method != method)
            ):
                return ["experiment_hypothesis_not_on_ranked_live_surface"]
            raw["hypothesis_id"] = supplied_hypothesis_id
            return []
        # Compaction can drop BOTH the ranked board and the selected contracts from an oversized pack
        # (grok's large crAPI packs). The planner still legitimately references an id it read in an
        # earlier observation, so resolve it straight from the durable hypotheses table: bind only a
        # live, actionable lead on THIS target whose canonical family+route+method matches the
        # experiment -- the same identity check the board branches enforce, just DB-sourced when the
        # board was compacted away. Fail-closed: no such live lead -> reject.
        lead_uuid = _optional_uuid(supplied_hypothesis_id)
        target_uuid = _optional_uuid(target_id)
        if lead_uuid is not None and target_uuid is not None:
            row = await conn.fetchrow(
                """
                SELECT source, family, next_test_action, metadata_json
                FROM hypotheses
                WHERE id=$1 AND target_id=$2
                  AND status IN ('open','claimed','testing','supported')
                """,
                lead_uuid,
                target_uuid,
            )
            if row is not None:
                lead = {
                    "source": row.get("source"),
                    "family": row["family"],
                    "next_test_action": _decode_json_value(row["next_test_action"]),
                    "metadata_json": _decode_json_value(row["metadata_json"]),
                }
                contract = _arsenal_routes._research_hypothesis_experiment_contract(lead)
                contract_route = _arsenal_routes._canonical_vulnerability_route(contract.get("route"))
                contract_method = str(contract.get("method") or "").upper()
                live_operation = str(lead.get("source") or "").strip().lower() == "invariant"
                if not live_operation:
                    # Route-target the liveness lookup. A blanket LIMIT 2000 over a large inventory can
                    # omit the very endpoint being bound (e.g. POST /api/Users ranked ~900th), which
                    # wrongly rejected a live create lead. Prefix-filter to the lead's route first.
                    route_prefix = str(contract_route or "").split("/{id}")[0].rstrip("/")
                    endpoint_rows = await conn.fetch(
                        """
                        SELECT method, path
                        FROM target_endpoints
                        WHERE target_id=$1
                          AND COALESCE(test_status, '') <> 'gone'
                          AND COALESCE(last_http_status, 0) NOT IN (404, 410)
                          AND COALESCE(unreachable_streak, 0) < 2
                          AND ($2 = '' OR path LIKE $2 || '%')
                        LIMIT 2000
                        """,
                        target_uuid,
                        route_prefix,
                    )
                    live_operation = any(
                        _arsenal_routes._canonical_vulnerability_route(endpoint.get("path")) == contract_route
                        and (
                            not contract_method
                            or str(endpoint.get("method") or "GET").upper() == contract_method
                        )
                        for endpoint in endpoint_rows
                    )
                if (
                    family_proof.canonical_family(contract.get("family") or lead.get("family")) == family
                    and contract_route
                    and contract_route == route
                    and (not contract_method or contract_method == method)
                    and live_operation
                ):
                    raw["hypothesis_id"] = supplied_hypothesis_id
                    return []
        return ["experiment_hypothesis_not_on_ranked_live_surface"]

    # When the planner omitted the id, autobinding stays deliberately stricter: only an exact
    # complete vulnerability identity can select a hypothesis on its behalf.
    for entry in ranked:
        hypothesis = entry.get("hypothesis") if isinstance(entry, dict) else None
        if not isinstance(hypothesis, dict) or not hypothesis.get("id"):
            continue
        if family_proof.canonical_family(hypothesis.get("family")) != family:
            continue
        if _arsenal_routes._research_hypothesis_vulnerability_key(hypothesis) == candidate_key:
            raw["hypothesis_id"] = str(hypothesis["id"])
            return []
    # The exact dimensional hash legitimately diverges when the planner refines a sparse residue lead
    # into a typed workflow (extra assertions/variables). When the id was omitted, still bind to a
    # visibly ranked or selected lead of the SAME family+route+method: that is a real live-surface lead
    # the board showed the planner, not a manufactured route, so it meets the residue requirement (the
    # same match the supplied-id branch already accepts) without a brittle full-hash equality.
    for contract in (
        list(observation_pack.get("selected_hypothesis_contracts") or [])
        + [entry.get("hypothesis") for entry in ranked if isinstance(entry, dict)]
    ):
        if not isinstance(contract, dict):
            continue
        if family_proof.canonical_family(contract.get("family")) != family:
            continue
        if _arsenal_routes._canonical_vulnerability_route(contract.get("route")) != route:
            continue
        contract_method = str(contract.get("method") or "").upper()
        if contract_method and contract_method != method:
            continue
        bind_id = str(contract.get("hypothesis_id") or contract.get("id") or "").strip()
        if bind_id:
            raw["hypothesis_id"] = bind_id
            return []
    return ["experiment_hypothesis_not_on_ranked_live_surface"]


async def _plan_research_episode_step(episode_id: str, req: ResearchPlannerStepRequest):
    async with _pool().acquire() as conn:
        detail = await _research_episode_detail(conn, episode_id)
    episode = detail.get("episode") or {}
    if episode.get("terminal") or episode.get("status") != "awaiting_planner":
        raise HTTPException(status_code=409, detail="Episode is not awaiting a planner decision")
    observation = detail.get("current_observation")
    if not isinstance(observation, dict):
        raise HTTPException(status_code=409, detail="Episode has no current observation")
    settings = _load_effective_ai_settings()
    ai_url = str(settings.get("ai_url") or "").strip()
    ai_key = str(settings.get("ai_api_key") or "").strip()
    ai_model = str(settings.get("ai_model") or "").strip()
    if not ai_url or not ai_key or not ai_model:
        raise HTTPException(status_code=409, detail="Configured AI provider is not ready")
    call_provider = _settings_routes._load_research_ai_provider()
    if not call_provider:
        raise HTTPException(status_code=503, detail="Shared AI provider client is unavailable")
    messages = _settings_routes._research_planner_messages(observation)
    remaining_model_units = int((episode.get("remaining_budget") or {}).get("model_tokens") or 0)
    prompt_bytes = sum(len(str(item.get("content") or "").encode("utf-8")) for item in messages)
    prompt_reservation = max(1, (prompt_bytes + 2) // 3)
    if remaining_model_units <= prompt_reservation + 128:
        async with _pool().acquire() as conn:
            async with conn.transaction():
                changed = await _mark_research_model_budget_exhausted(
                    conn,
                    episode_id=episode_id,
                    observation_id=str(observation.get("id") or ""),
                    summary="Remaining model budget cannot fit another bounded planner prompt",
                    details={
                        "remaining_model_units": remaining_model_units,
                        "prompt_reservation": prompt_reservation,
                    },
                )
            if not changed:
                raise HTTPException(status_code=409, detail="Planner observation is no longer current")
            detail = await _research_episode_detail(conn, episode_id)
        return {"accepted": False, "planner_call": {"error": "model_token_budget_exhausted"}, **detail}
    observation_pack = observation.get("observation_pack") if isinstance(observation.get("observation_pack"), dict) else {}
    command_names = [
        str(item.get("name") or "")
        for item in observation_pack.get("proposable_commands") or []
        if isinstance(item, dict) and item.get("proposable") and item.get("name")
    ]
    failure_meta: dict[str, Any] = {}
    response, error, latency_ms = await call_provider(
        ai_url=ai_url,
        ai_api_key=ai_key,
        model=ai_model,
        messages=messages,
        timeout_seconds=req.timeout_seconds,
        max_tokens=req.max_tokens,
        temperature=0.1,
        json_schema=_settings_routes._research_decision_json_schema(
            command_names,
            observation_id=str(observation.get("id") or ""),
            context_hash=str(observation.get("context_hash") or ""),
        ),
        fallback_models=settings.get("ai_model_fallback"),
        overall_budget_seconds=req.timeout_seconds,
        response_validator=lambda value: _settings_routes._research_provider_contract_error(value, observation),
        token_budget=remaining_model_units,
        failure_meta_sink=failure_meta,
        use_circuit_breaker=False,
    )
    if error or not isinstance(response, dict):
        error_text = str(error or "invalid response")[:500]
        async with _pool().acquire() as conn:
            async with conn.transaction():
                failure = await _record_research_planner_failure(
                    conn,
                    episode_id=episode_id,
                    observation_id=str(observation.get("id") or ""),
                    error=error_text,
                    failure_meta=failure_meta,
                    force_budget_exhausted="token budget" in error_text.lower(),
                )
            if not failure:
                raise HTTPException(status_code=409, detail="Planner observation is no longer current")
            if failure["status"] == "budget_exhausted":
                detail = await _research_episode_detail(conn, episode_id)
                return {
                    "accepted": False,
                    "planner_call": {
                        "error": error_text[:300],
                        "provider": _arsenal_routes._bounded_research_payload(failure_meta),
                    },
                    **detail,
                }
        raise HTTPException(status_code=502, detail=f"Research planner failed: {error_text[:300]}")
    provider_meta = response.pop("_provider_meta", {}) if isinstance(response.get("_provider_meta"), dict) else {}
    output_bytes = len(json.dumps(response, default=str).encode("utf-8"))
    estimated_tokens = max(1, (prompt_bytes + output_bytes + 3) // 4)
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
    model_tokens_used = provider_tokens or estimated_tokens
    bound_response = _settings_routes._bind_research_decision_to_observation(response, observation)
    harness_repairs = bound_response.pop("_harness_repairs", [])
    actual_model = str(provider_meta.get("model_used") or provider_meta.get("model") or ai_model)[:200]
    actual_mode = str(provider_meta.get("mode_used") or provider_meta.get("mode") or "unknown")[:80]
    try:
        decision_req = _settings_routes.ResearchDecisionRequest(
            **bound_response,
            planner={
                "kind": "configured_ai",
                "requested_model": ai_model[:200],
                "model": actual_model,
                "provider_mode": actual_mode,
                "provider_kind": str(provider_meta.get("provider_kind") or "unknown")[:80],
                "parse_method": str(provider_meta.get("parse_method") or "unknown")[:80],
                "fallback_index": max(0, int(provider_meta.get("fallback_index") or 0)),
                "mode_index": max(0, int(provider_meta.get("mode_index") or 0)),
                "attempt_index": max(0, int(provider_meta.get("attempt_index") or 0)),
                "finish_reason": str(provider_meta.get("finish_reason") or "")[:80] or None,
                "schema_validated": bool(provider_meta.get("schema_validated")),
                "reasoning_present": bool(provider_meta.get("reasoning_present")),
                "harness_repairs": [str(item)[:100] for item in harness_repairs[:20]],
                "usage": _arsenal_routes._bounded_research_payload(usage),
                "latency_ms": latency_ms,
                "metering_quality": "provider" if provider_tokens else "estimated",
                "created_by": req.created_by,
            },
            model_tokens_used=model_tokens_used,
            execute=req.execute,
        )
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail={"error": "planner_decision_schema_invalid", "violations": exc.errors()}) from exc
    result = await submit_research_decision(episode_id, decision_req)
    result["planner_call"] = {
        "requested_model": ai_model[:200],
        "model": actual_model,
        "provider_mode": actual_mode,
        "latency_ms": latency_ms,
        "model_tokens": model_tokens_used,
        "metering_quality": "provider" if provider_tokens else "estimated",
        "harness_repairs": harness_repairs,
    }
    return result


async def _research_lease_heartbeat(
    pool: Any,
    episode_id: str,
    owner: str,
    stop: asyncio.Event,
) -> None:
    """Keep a short lease alive; process death now becomes recoverable in about 30 seconds."""
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=RESEARCH_AUTOPILOT_HEARTBEAT_SECONDS)
            break
        except asyncio.TimeoutError:
            pass
        async with pool.acquire() as conn:
            refreshed = await conn.fetchval(
                """
                UPDATE research_episodes
                SET lease_expires_at=NOW()+make_interval(secs => $3), updated_at=NOW()
                WHERE id=$1 AND lease_owner=$2
                RETURNING id
                """,
                uuid.UUID(episode_id),
                owner,
                RESEARCH_AUTOPILOT_LEASE_SECONDS,
            )
        if not refreshed:
            break
RESEARCH_LAUNCH_PROFILES: dict[str, dict[str, Any]] = {
    "analyze": {
        "execution_mode": "read_only", "max_risk_tier": "read_only",
        "max_steps": 8,
        "budget_limits": {
            "steps": 8, "actions": 7, "active_actions": 0, "requests": 0, "wire_requests": 0,
            "seconds": 600, "model_tokens": 75000,
        },
    },
    "hunt": {
        "execution_mode": "gated", "max_risk_tier": "active",
        "max_steps": 15,
        "budget_limits": {
            "steps": 15, "actions": 14, "active_actions": 6, "requests": 250, "wire_requests": 1800,
            "seconds": 1800, "model_tokens": 150000,
        },
    },
    "relentless": {
        "execution_mode": "gated", "max_risk_tier": "active",
        "max_steps": 25,
        "budget_limits": {
            "steps": 25, "actions": 24, "active_actions": 10, "requests": 500, "wire_requests": 2700,
            "seconds": 3600, "model_tokens": 250000,
        },
    },
    "deep_hunt": {
        "execution_mode": "gated", "max_risk_tier": "credential",
        "max_steps": 25,
        "budget_limits": {
            "steps": 25, "actions": 24, "active_actions": 12, "requests": 500, "wire_requests": 3600,
            "seconds": 3600, "model_tokens": 500000,
        },
    },
}








def _research_campaign_budget_remaining(limits: Any, used: Any) -> dict[str, int]:
    limit_map = limits if isinstance(limits, dict) else {}
    used_map = _research_normalize_budget_used(used)
    return {
        key: max(0, int(limit_map.get(key) or 0) - int(used_map.get(key) or 0))
        for key in RESEARCH_BUDGET_KEYS
    }


def _public_research_episode_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    for key in ("planner", "allowed_families", "budget_limits", "budget_used"):
        payload[key] = _decode_json_value(payload.get(key)) or ([] if key == "allowed_families" else {})
    payload["remaining_budget"] = _research_remaining_budget(
        payload.get("budget_limits") or {}, payload.get("budget_used") or {}
    )
    payload["terminal"] = str(payload.get("status") or "") in TERMINAL_EPISODE_STATUSES
    payload["execution_enabled"] = (
        payload.get("execution_mode") != "shadow"
        and (payload.get("execution_mode") == "read_only" or _ai_ops_execute_enabled())
    )
    mission = _research_mission(payload)
    payload["mission_profile"] = mission.get("profile") or "target_hunt"
    payload["subject"] = mission.get("subject") or {"type": "target", "id": payload.get("target_id")}
    payload["allowed_commands"] = mission.get("allowed_commands") or []
    return payload


async def _research_async_work(
    conn,
    episode_id: str | uuid.UUID,
    *,
    active_only: bool = True,
) -> list[dict[str, Any]]:
    episode_uuid = _optional_uuid(episode_id)
    scan_status_clause = "AND s.status IN ('pending','queued','running')" if active_only else ""
    retest_status_clause = "AND fv.status IN ('queued','running')" if active_only else ""
    scan_rows = await conn.fetch(
        f"""
        SELECT DISTINCT s.id, s.status, s.progress, s.current_phase, s.scan_type,
               s.findings_count, s.score, s.grade, s.error_message, s.created_at,
               s.completed_at, cr.id AS command_result_id
        FROM research_decisions rd
        JOIN command_results cr ON cr.id=rd.command_result_id
        JOIN scans s ON s.id=cr.scan_id
        WHERE rd.episode_id=$1 {scan_status_clause}
        ORDER BY s.created_at DESC
        """,
        episode_uuid,
    )
    retest_rows = await conn.fetch(
        f"""
        SELECT DISTINCT fv.id, fv.status, fv.verdict, fv.result_status, fv.confidence,
               fv.finding_id, fv.error_message, fv.created_at, fv.completed_at,
               cr.id AS command_result_id
        FROM research_decisions rd
        JOIN command_results cr ON cr.id=rd.command_result_id
        JOIN finding_verifications fv ON fv.id::text=cr.result_json->>'retest_id'
        WHERE rd.episode_id=$1 {retest_status_clause}
        ORDER BY fv.created_at DESC
        """,
        episode_uuid,
    )
    work: list[dict[str, Any]] = []
    for row in scan_rows:
        item = row_to_dict(row)
        item["kind"] = "scan"
        item["ui_path"] = f"/scans/{item['id']}"
        work.append(_arsenal_routes._bounded_research_payload(item))
    for row in retest_rows:
        item = row_to_dict(row)
        item["kind"] = "finding_retest"
        item["ui_path"] = f"/findings/{item['finding_id']}"
        work.append(_arsenal_routes._bounded_research_payload(item))
    return sorted(work, key=lambda item: str(item.get("created_at") or ""), reverse=True)


async def _research_latest_action_result(conn, episode_id: str | uuid.UUID) -> dict[str, Any]:
    decision_row = await conn.fetchrow(
        """
        SELECT * FROM research_decisions
        WHERE episode_id=$1 AND command_result_id IS NOT NULL
        ORDER BY sequence DESC
        LIMIT 1
        """,
        _optional_uuid(episode_id),
    )
    if not decision_row:
        return {}
    decision = _public_research_decision_row(decision_row)
    command_result_row = await conn.fetchrow(
        "SELECT * FROM command_results WHERE id=$1",
        decision_row["command_result_id"],
    )
    command_result = _arsenal_routes._public_command_result_row(command_result_row) if command_result_row else None
    work = await _research_async_work(conn, episode_id, active_only=False)
    linked_id = str(decision_row["command_result_id"])
    linked_work = [item for item in work if str(item.get("command_result_id") or "") == linked_id]
    return _arsenal_routes._bounded_research_payload({
        "decision": {
            "id": decision.get("id"),
            "sequence": decision.get("sequence"),
            "status": decision.get("status"),
            "action": decision.get("action") or {},
            "expected_signal": decision.get("expected_signal"),
            "falsifier": decision.get("falsifier"),
        },
        "command_result": command_result or {},
        "linked_work": linked_work,
    })


def _research_linked_work_outcome(linked_work: Any) -> str | None:
    """Collapse terminal linked work into the operator-visible action outcome."""
    statuses = [
        str(item.get("status") or "").strip().lower()
        for item in linked_work or []
        if isinstance(item, dict) and str(item.get("status") or "").strip()
    ]
    if not statuses:
        return None
    if any(status in {"failed", "error"} for status in statuses):
        return "failed"
    if any(status == "cancelled" for status in statuses):
        return "cancelled"
    if any(status in {"partial", "degraded"} for status in statuses):
        return "partial"
    if all(status == "completed" for status in statuses):
        return "completed"
    return None


async def _research_episode_detail(conn, episode_id: str) -> dict[str, Any]:
    episode_row = await _research_episode_or_404(conn, episode_id)
    episode = _public_research_episode_row(episode_row)
    observations = await conn.fetch(
        "SELECT * FROM research_observations WHERE episode_id=$1 ORDER BY sequence DESC LIMIT 50",
        episode_row["id"],
    )
    decisions = await conn.fetch(
        "SELECT * FROM research_decisions WHERE episode_id=$1 ORDER BY sequence DESC LIMIT 50",
        episode_row["id"],
    )
    events = await conn.fetch(
        "SELECT * FROM research_events WHERE episode_id=$1 ORDER BY sequence DESC LIMIT 100",
        episode_row["id"],
    )
    waiting_on = await _research_async_work(conn, episode_row["id"], active_only=True)
    current_observation = next(
        (
            _public_research_observation_row(row)
            for row in observations
            if str(row["id"]) == str(episode.get("current_observation_id") or "")
        ),
        None,
    )
    if current_observation is None and episode.get("current_observation_id"):
        current_row = await conn.fetchrow(
            "SELECT * FROM research_observations WHERE id=$1 AND episode_id=$2",
            _optional_uuid(episode.get("current_observation_id")),
            episode_row["id"],
        )
        current_observation = _public_research_observation_row(current_row) if current_row else None
    return {
        "episode": episode,
        "current_observation": current_observation,
        "observations": [_public_research_observation_row(row) for row in observations],
        "decisions": [_public_research_decision_row(row) for row in decisions],
        "events": [_public_research_event_row(row) for row in events],
        "waiting_on": waiting_on,
    }


def _research_forbidden_control_paths(value: Any, path: str = "$") -> list[str]:
    forbidden = {
        "approval_receipt_id", "scope_receipt_id", "confirmations", "execute",
        "campaign_id", "operation_plan_id", "runtime_scope_guard",
    }
    hits: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).strip().lower()
            child = f"{path}.{normalized or '<empty>'}"
            if normalized in forbidden and nested not in (None, "", [], {}):
                hits.append(child)
            hits.extend(_research_forbidden_control_paths(nested, child))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            hits.extend(_research_forbidden_control_paths(nested, f"{path}[{index}]"))
    return hits


def _research_normalize_focused_endpoint(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text or len(text) > 1000 or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return None
    parts = text.split(None, 2)
    if parts and parts[0].upper() in _RESEARCH_FOCUSED_ENDPOINT_METHODS:
        if len(parts) < 2:
            return None
        method, path = parts[0].upper(), parts[1]
        suffix = f" {parts[2]}" if len(parts) > 2 else ""
    else:
        method, path = "GET", parts[0] if parts else ""
        suffix = f" {parts[1]}" if len(parts) > 1 else ""
    if not path.startswith("/") or path.startswith("//") or "://" in path:
        return None
    return f"{method} {path}{suffix}"[:1000]


def _research_normalize_injection_payloads(value: Any) -> tuple[list[str], bool]:
    if value is None:
        return [], True
    if not isinstance(value, list) or len(value) > 16:
        return [], False
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str):
            return [], False
        text = item.strip()
        if not text or len(text) > 500 or any(ch in text for ch in ("\r", "\n", "\x00")):
            return [], False
        if text not in normalized:
            normalized.append(text)
    return normalized, True


def _research_action_contains_secret_material(value: Any, *, in_request_body: bool = False) -> bool:
    """Reject secret values while permitting typed, unresolved body placeholders.

    A body field named ``token`` is common on legitimate login and recovery
    schemas. The model still cannot provide its value: only a server-resolved
    variable or visibly synthetic template marker is accepted.
    """
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).strip().lower()
            child_in_body = in_request_body or normalized in {"json_body", "form_body"}
            if normalized in _get("FORBIDDEN_AGENT_CONTEXT_KEYS"):
                placeholder = (
                    child_in_body
                    and isinstance(nested, str)
                    and (
                        bool(re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_.-]*\}", nested.strip()))
                        or bool(re.fullmatch(r"<[A-Za-z_][A-Za-z0-9_.-]*>", nested.strip()))
                        or nested.strip() == "***"
                    )
                )
                if not placeholder:
                    return True
            if _research_action_contains_secret_material(nested, in_request_body=child_in_body):
                return True
    elif isinstance(value, list):
        return any(
            _research_action_contains_secret_material(item, in_request_body=in_request_body)
            for item in value
        )
    return False


async def _research_workflow_surface_violations(
    conn: Any,
    target_id: str,
    parameters: dict[str, Any],
) -> list[str]:
    """Fail closed when a planner invents a method/path or targets auth plumbing."""
    http_steps = [
        step for step in parameters.get("steps") or []
        if isinstance(step, dict) and str(step.get("kind") or "http").lower() == "http"
    ]
    if not http_steps:
        return []
    rows = await conn.fetch(
        """
        SELECT upper(method) AS method, path
        FROM target_endpoints
        WHERE target_id=$1 AND COALESCE(test_status, '') <> 'gone'
        """,
        _optional_uuid(target_id),
    )
    live_surface = {
        (
            str(row.get("method") or "").upper(),
            _arsenal_routes._canonical_vulnerability_route(row.get("path")),
        )
        for row in rows
        if row.get("path")
    }
    # Object-instance siblings (/collection/{id}) of an on-surface create collection (POST /collection)
    # are valid read-back / cleanup targets for a create-based mass_assignment even when the crawler
    # never captured a concrete /collection/{id}. The family proof gates whether the object actually
    # reads back, so accepting the sibling here cannot mint a false finding -- it only lets the
    # create-MA experiment run. Scoped to mass_assignment and to the sibling of a real create collection.
    create_collections = {
        route for (method, route) in live_surface
        if method == "POST" and route and not route.endswith("/{id}")
    }
    errors: list[str] = []
    family = family_proof.canonical_family(parameters.get("proof_family"))
    for index, step in enumerate(http_steps):
        method = str(step.get("method") or "GET").strip().upper()
        raw_path = step.get("path") or step.get("route")
        route = _arsenal_routes._canonical_vulnerability_route(raw_path)
        label = str(step.get("label") or index)[:80]
        if family == "mass_assignment" and _targets._research_auth_session_route(raw_path):
            errors.append(f"mass_assignment_auth_session_route_forbidden:{label}")
        on_surface = bool(route) and (method, route) in live_surface
        if (
            not on_surface and family == "mass_assignment" and route
            and route.endswith("/{id}") and route[: -len("/{id}")] in create_collections
        ):
            on_surface = True
        if not on_surface:
            errors.append(f"experiment_step_method_not_on_surface:{label}:{method}:{route or '<missing>'}")
    return list(dict.fromkeys(errors))


async def _research_campaign_retest_cap_reached(
    conn: Any,
    campaign_id: Any,
    finding_id: Any,
) -> bool:
    """Allow one completed retest per finding until genuinely newer evidence arrives."""
    if not campaign_id:
        return False
    return bool(await conn.fetchval(
        """
        SELECT COALESCE((
            SELECT f.last_seen_at IS NULL OR f.last_seen_at <= prior.completed_at
            FROM findings f
            JOIN LATERAL (
                SELECT fv.completed_at
                FROM research_decisions rd
                JOIN research_episodes re ON re.id=rd.episode_id
                JOIN command_results cr ON cr.id=rd.command_result_id
                JOIN finding_verifications fv
                  ON fv.id::text=cr.result_json->>'retest_id'
                WHERE re.campaign_id=$1
                  AND fv.finding_id=f.id
                  AND fv.status='completed'
                  AND fv.completed_at IS NOT NULL
                ORDER BY fv.completed_at DESC
                LIMIT 1
            ) prior ON true
            WHERE f.id=$2
        ), false)
        """,
        _optional_uuid(campaign_id),
        _optional_uuid(finding_id),
    ))










def _research_preflight_claim_is_stale(config: Any, *, now: datetime | None = None) -> bool:
    payload = config if isinstance(config, dict) else {}
    if str(payload.get("preflight_state") or "") != "queueing":
        return False
    raw_started = str(payload.get("preflight_started_at") or "").strip()
    if not raw_started:
        return True
    try:
        started = datetime.fromisoformat(raw_started.replace("Z", "+00:00"))
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
    except ValueError:
        return True
    current = now or datetime.now(timezone.utc)
    return (current - started).total_seconds() >= RESEARCH_PREFLIGHT_CLAIM_TTL_SECONDS


def _research_subtract_cost(used: Any, cost: Any) -> dict[str, int]:
    used_map = _research_normalize_budget_used(used)
    cost_map = _research_normalize_budget_used(cost)
    return {
        key: max(0, int(used_map.get(key) or 0) - int(cost_map.get(key) or 0))
        for key in RESEARCH_BUDGET_KEYS
    }


def _research_preflight_error_is_transient(exc: Exception) -> bool:
    detail = getattr(exc, "detail", None)
    error = str(detail.get("error") or "") if isinstance(detail, dict) else ""
    text = f"{error} {detail if detail is not None else exc}".lower()
    return any(token in text for token in (
        "workers_not_confirmed_current",
        "worker_fleet_not_current",
        "pending worker",
        "stale worker",
        "build-current",
    ))


def _research_action_vulnerability_keys(action: dict[str, Any]) -> set[str]:
    command = str(action.get("command") or "").strip()
    parameters = action.get("parameters") if isinstance(action.get("parameters"), dict) else {}
    if command not in {"experiment.workflow", "experiment.http_diff"}:
        return set()
    family = family_proof.canonical_family(parameters.get("proof_family") or command)
    steps_by_label: dict[str, dict[str, Any]] = {}
    for step in parameters.get("steps") or []:
        if isinstance(step, dict):
            label = str(step.get("label") or step.get("id") or "").strip()
            if label:
                steps_by_label[label] = step
    # Only the step(s) an assertion actually targets are the vulnerability under test. Setup, auth,
    # producer and cleanup steps must not make an entire workflow look 'already covered' just because
    # they touch a route that carries a known finding (the reported over-block).
    target_labels: set[str] = set()
    for assertion in parameters.get("assertions") or []:
        if not isinstance(assertion, dict):
            continue
        for ref_key in ("step", "candidate"):
            ref = str(assertion.get(ref_key) or "").strip()
            if ref:
                target_labels.add(ref)
        for ref in assertion.get("steps") or []:
            text = str(ref or "").strip()
            if text:
                target_labels.add(text)
    keys: set[str] = set()

    assertion_predicates = sorted({
        str(assertion.get("predicate") or "").strip().lower()
        for assertion in parameters.get("assertions") or []
        if isinstance(assertion, dict) and assertion.get("predicate")
    })

    def _add(route: Any, method: Any, step: dict[str, Any] | None = None) -> None:
        # A concrete candidate matches only the same concrete method. Unknown-method candidates use
        # the wildcard key, but a methodless historic finding must never suppress every known method.
        key = _arsenal_routes._canonical_vulnerability_key(
            family=parameters.get("proof_family") or family,
            route=route,
            method=method,
            dimensions=_arsenal_routes._research_vulnerability_dimensions(
                parameters.get("proof_family") or family,
                parameters,
                step or {},
                {"assertion_predicates": assertion_predicates},
            ),
        )
        if key:
            keys.add(key)

    for label in target_labels:
        step = steps_by_label.get(label)
        if step:
            _add(step.get("path") or step.get("route"), step.get("method"), step)
    _add(parameters.get("route"), parameters.get("method"), parameters)
    return keys




async def _research_campaign_exhaustion_snapshot(
    conn: Any,
    episode_id: Any,
    campaign_id: Any = None,
) -> dict[str, Any]:
    rows = await conn.fetch(
        """
        SELECT rd.action, rd.status, cr.id AS command_result_id, cr.status AS command_status,
               cr.finding_ids, cr.result_json
        FROM research_decisions rd
        JOIN research_episodes re ON re.id=rd.episode_id
        LEFT JOIN command_results cr ON cr.id=rd.command_result_id
        WHERE rd.episode_id=$1 OR ($2::uuid IS NOT NULL AND re.campaign_id=$2)
        ORDER BY rd.created_at ASC
        LIMIT 2000
        """,
        _optional_uuid(episode_id),
        _optional_uuid(campaign_id),
    )
    falsifications: dict[str, int] = {}
    inconclusive_actuators: dict[str, int] = {}
    recon_actions = 0
    experiments = 0
    for row in rows:
        action = _decode_json_value(row.get("action")) or {}
        command = str(action.get("command") or "")
        if command in _arsenal_routes.RESEARCH_RECON_COMMANDS and str(row.get("status") or "") in {
            "accepted", "dispatching", "completed", "blocked",
        }:
            recon_actions += 1
        dimension = _arsenal_routes._research_action_semantic_dimension(action)
        if not dimension or not row.get("command_result_id") or str(row.get("status") or "") != "completed":
            continue
        experiments += 1
        outcome = _arsenal_routes._research_experiment_outcome(action, row)
        if outcome and outcome.get("deterministic_refutation"):
            falsifications[dimension] = falsifications.get(dimension, 0) + 1
        elif outcome and outcome.get("outcome") in {"inconclusive", "blocked"}:
            failure_class = str(outcome.get("failure_class") or "unknown")
            actuator = f"{dimension}:{failure_class}"
            inconclusive_actuators[actuator] = inconclusive_actuators.get(actuator, 0) + 1
    return {
        "experiments": experiments,
        "recon_actions": recon_actions,
        "falsification_counts": falsifications,
        "inconclusive_actuator_counts": inconclusive_actuators,
        "exhausted_inconclusive_actuators": sorted(
            actuator
            for actuator, count in inconclusive_actuators.items()
            if count >= RESEARCH_INCONCLUSIVE_ACTUATOR_LIMIT
        ),
        "exhausted_dimensions": sorted(
            dimension
            for dimension, count in falsifications.items()
            if count >= RESEARCH_SEMANTIC_FALSIFICATION_LIMIT
        ),
        "semantic_falsification_limit": RESEARCH_SEMANTIC_FALSIFICATION_LIMIT,
        "inconclusive_actuator_limit": RESEARCH_INCONCLUSIVE_ACTUATOR_LIMIT,
        "recon_action_cap": RESEARCH_RECON_ACTION_CAP,
    }


def _research_preflight_scan_options(
    *,
    focus_family: str,
    custom_endpoints: list[str],
    approval_receipt_id: str | None,
) -> ScanOptions:
    endpoint_count = len(custom_endpoints)
    return ScanOptions(
        no_early_stop=True,
        parallel=False,
        auth_state_shards=False,
        custom_endpoints=custom_endpoints or None,
        focused_endpoints_only=bool(custom_endpoints),
        zero_rediscovery=bool(custom_endpoints),
        skip_global_checks=True,
        exploit_depth=focus_family == "bola",
        custom_budget={
            "max_urls": max(50, endpoint_count),
            "active_max_endpoints": max(20, endpoint_count),
            "active_max_seconds": max(900, min(3600, endpoint_count * 20)),
            "phase4_max_seconds": max(600, min(2400, endpoint_count * 12)),
            "max_duration_minutes": 75,
        },
        require_current_workers=True,
        approval_receipt_id=approval_receipt_id,
    )


def _research_canonicalize_hypothesis_binding(raw: dict[str, Any]) -> list[str]:
    """Move a misplaced experiment hypothesis binding into decision provenance.

    The structured response schema exposes ``hypothesis_id`` at decision level, while
    command parameter schemas intentionally do not. Some providers still duplicate it
    inside ``action.parameters``. Canonicalize the unambiguous case without weakening
    the command contract, and reject conflicting bindings instead of guessing.
    """
    action = raw.get("action") if isinstance(raw.get("action"), dict) else {}
    parameters = action.get("parameters") if isinstance(action.get("parameters"), dict) else {}
    if "hypothesis_id" not in parameters:
        return []
    nested = str(parameters.pop("hypothesis_id") or "").strip()
    action["parameters"] = parameters
    raw["action"] = action
    if not nested:
        return []
    top_level = str(raw.get("hypothesis_id") or "").strip()
    if top_level and top_level != nested:
        return ["hypothesis_id_conflict"]
    raw["hypothesis_id"] = nested
    return []


def _research_canonicalize_workflow_wrapper(raw: dict[str, Any]) -> list[str]:
    """Unwrap a provider-added ``workflow`` envelope without weakening policy.

    Some structured-output providers copy the named experiment template under
    ``action.parameters.workflow`` while keeping server-routing fields beside it.
    The envelope has no authority of its own, so an unambiguous object can be
    flattened safely. Conflicting duplicate fields remain a hard rejection.
    """
    action = raw.get("action") if isinstance(raw.get("action"), dict) else {}
    if str(action.get("command") or "") != "experiment.workflow":
        return []
    parameters = action.get("parameters") if isinstance(action.get("parameters"), dict) else {}
    if "workflow" not in parameters:
        return []
    nested = parameters.pop("workflow")
    if isinstance(nested, str):
        text = nested.strip()
        try:
            decoded = json.loads(text)
        except (TypeError, ValueError, json.JSONDecodeError):
            decoded = None
        if isinstance(decoded, (dict, list)):
            nested = decoded
        else:
            # A few providers use ``workflow`` as a redundant workflow-id alias.
            # Preserve the UUID under the declared field and let the normal command
            # schema reject any genuinely missing steps/assertions.
            try:
                nested_workflow_id = str(uuid.UUID(text))
            except (TypeError, ValueError):
                action["parameters"] = parameters
                raw["action"] = action
                return ["workflow_wrapper_must_be_object"]
            existing_workflow_id = str(parameters.get("workflow_id") or "").strip()
            if existing_workflow_id and existing_workflow_id != nested_workflow_id:
                action["parameters"] = parameters
                raw["action"] = action
                return ["workflow_parameter_conflict:workflow_id"]
            parameters["workflow_id"] = nested_workflow_id
            action["parameters"] = parameters
            raw["action"] = action
            return []
    if isinstance(nested, list):
        if not nested or not all(isinstance(step, dict) for step in nested):
            action["parameters"] = parameters
            raw["action"] = action
            return ["workflow_wrapper_must_be_object"]
        nested = {"steps": nested}
    if not isinstance(nested, dict):
        action["parameters"] = parameters
        raw["action"] = action
        return ["workflow_wrapper_must_be_object"]
    errors: list[str] = []
    for key, value in nested.items():
        if key in parameters and parameters[key] not in (None, "", [], {}):
            if parameters[key] != value:
                errors.append(f"workflow_parameter_conflict:{str(key)[:80]}")
            continue
        parameters[key] = value
    action["parameters"] = parameters
    raw["action"] = action
    return errors


def _research_canonicalize_experiment_steps_alias(raw: dict[str, Any]) -> list[str]:
    """Map the readable ``operations`` alias back to the declared ``steps`` field.

    Campaign memory used this label to describe prior work. Providers sometimes copy
    it literally into the next experiment. The alias carries no extra authority and
    every resulting step still passes the normal command schema, scope, method, body,
    restoration, and secret-field checks.
    """
    action = raw.get("action") if isinstance(raw.get("action"), dict) else {}
    if str(action.get("command") or "") not in _arsenal_routes._RESEARCH_EXPERIMENT_DEDUPE_COMMANDS:
        return []
    parameters = action.get("parameters") if isinstance(action.get("parameters"), dict) else {}
    if "operations" not in parameters:
        return []
    operations = parameters.pop("operations")
    if not isinstance(operations, list) or not operations or not all(
        isinstance(step, dict) for step in operations
    ):
        action["parameters"] = parameters
        raw["action"] = action
        return ["experiment_operations_must_be_step_list"]
    existing_steps = parameters.get("steps")
    if existing_steps not in (None, [], {}) and existing_steps != operations:
        action["parameters"] = parameters
        raw["action"] = action
        return ["experiment_steps_conflict"]
    parameters["steps"] = operations
    action["parameters"] = parameters
    raw["action"] = action
    return []


async def _mark_research_model_budget_exhausted(
    conn,
    *,
    episode_id: str,
    observation_id: str,
    summary: str,
    details: dict[str, Any],
) -> bool:
    """End only the still-current planner turn without fabricating model spend."""
    row = await conn.fetchrow(
        """
        UPDATE research_episodes
        SET status='budget_exhausted', stop_reason='model_token_budget_exhausted',
            autopilot_enabled=false, updated_at=NOW()
        WHERE id=$1 AND status='awaiting_planner' AND cancel_requested=false
          AND current_observation_id=$2
        RETURNING id
        """,
        _uuid_or_400(episode_id, "episode id"),
        _optional_uuid(observation_id),
    )
    if not row:
        return False
    await _record_research_event(
        conn,
        row["id"],
        event_type="model_budget_exhausted",
        status="budget_exhausted",
        summary=summary,
        observation_id=observation_id,
        details=details,
    )
    return True


async def _record_research_planner_failure(
    conn,
    *,
    episode_id: str,
    observation_id: str,
    error: str,
    failure_meta: dict[str, Any],
    force_budget_exhausted: bool,
) -> dict[str, Any] | None:
    """Persist failed-attempt metering against the still-current observation."""
    row = await conn.fetchrow(
        "SELECT * FROM research_episodes WHERE id=$1 FOR UPDATE",
        _uuid_or_400(episode_id, "episode id"),
    )
    if (
        not row
        or str(row["status"]) != "awaiting_planner"
        or bool(row["cancel_requested"])
        or str(row["current_observation_id"] or "") != observation_id
    ):
        return None
    episode = _public_research_episode_row(row)
    try:
        metered_units = max(0, int(failure_meta.get("planning_units_spent") or 0))
    except (TypeError, ValueError):
        metered_units = 0
    used = _research_normalize_budget_used(episode.get("budget_used") or {})
    used["model_tokens"] += metered_units
    model_limit = int((episode.get("budget_limits") or {}).get("model_tokens") or 0)
    exhausted = force_budget_exhausted or used["model_tokens"] >= model_limit
    status = "budget_exhausted" if exhausted else "awaiting_planner"
    await conn.execute(
        """
        UPDATE research_episodes
        SET status=$2, budget_used=$3::jsonb,
            stop_reason=CASE WHEN $2='budget_exhausted' THEN 'model_token_budget_exhausted' ELSE stop_reason END,
            autopilot_enabled=CASE WHEN $2='budget_exhausted' THEN false ELSE autopilot_enabled END,
            updated_at=NOW()
        WHERE id=$1
        """,
        row["id"],
        status,
        json.dumps(used),
    )
    await _record_research_event(
        conn,
        row["id"],
        event_type="planner_provider_failed",
        status=status,
        summary=(
            "Planner fallback chain reached the episode model budget"
            if exhausted
            else "Planner provider call failed before producing a valid decision"
        ),
        observation_id=observation_id,
        details={
            "error": str(error)[:500],
            "metered_model_units": metered_units,
            "provider": _arsenal_routes._bounded_research_payload(failure_meta),
        },
    )
    if not exhausted:
        refreshed = await conn.fetchrow("SELECT * FROM research_episodes WHERE id=$1", row["id"])
        await _build_research_observation(
            conn,
            refreshed,
            previous_result={
                "execution_blocked_reason": "planner_provider_failed",
                "result": {
                    "status": "planner_provider_failed",
                    "reason": str(error)[:500],
                    "error_message": str(error)[:500],
                },
            },
            next_status="awaiting_planner",
        )
    return {"status": status, "metered_model_units": metered_units}
def _research_mission(episode: dict[str, Any]) -> dict[str, Any]:
    planner = episode.get("planner") if isinstance(episode.get("planner"), dict) else {}
    mission = planner.get("mission") if isinstance(planner.get("mission"), dict) else {}
    return mission


def _public_research_observation_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    payload["observation_pack"] = _decode_json_value(payload.get("observation_pack")) or {}
    return payload


def _public_research_event_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    payload["details"] = _decode_json_value(payload.get("details")) or {}
    return payload


async def _build_research_observation(
    conn,
    episode_row: Any,
    *,
    previous_result: Optional[dict[str, Any]] = None,
    previous_command_result_id: str | uuid.UUID | None = None,
    next_status: Optional[str] = None,
) -> dict[str, Any]:
    episode = _public_research_episode_row(episode_row)
    target_id = str(episode["target_id"])
    context_req = await _arsenal_routes._build_agent_context_pack_from_target(
        conn,
        _arsenal_routes.AgentContextPackFromTargetRequest(
            target_id=target_id,
            include_findings=True,
            include_endpoints=True,
            include_gaps=True,
            finding_limit=10,
            endpoint_limit=20,
            created_by=f"research_episode:{episode['id']}",
        ),
    )
    # Research prompts consume the same canonical redaction path as persisted agent context packs;
    # replay examples may originate from harvested traffic and must not carry tokens or credentials.
    context = _arsenal_routes._canonical_agent_context_pack(context_req)
    surface_context = dict(context.get("current_surface")) if isinstance(context.get("current_surface"), dict) else {}
    campaign_preflight_scan_id = ""
    if episode.get("campaign_id"):
        try:
            campaign_row = await _savepoint_fetchrow(
                conn,
                "SELECT metadata_json FROM campaigns WHERE id=$1",
                _optional_uuid(episode.get("campaign_id")),
            )
            campaign_metadata = _decode_json_value((campaign_row or {}).get("metadata_json")) or {}
            campaign_config = (
                campaign_metadata.get("autonomous_research")
                if isinstance(campaign_metadata.get("autonomous_research"), dict)
                else {}
            )
            campaign_preflight_scan_id = str(campaign_config.get("preflight_scan_id") or "")
        except Exception:
            campaign_preflight_scan_id = ""
    if campaign_preflight_scan_id:
        graph = surface_context.get("attack_graph") if isinstance(surface_context.get("attack_graph"), dict) else {}
        provenance_scan_ids = [campaign_preflight_scan_id]
        try:
            provenance_rows = await _arsenal_routes._savepoint_fetch(
                conn,
                """
                SELECT id FROM scans
                WHERE id=COALESCE(
                    (SELECT parent_scan_id FROM scans WHERE id=$1), $1
                )
                   OR parent_scan_id=COALESCE(
                    (SELECT parent_scan_id FROM scans WHERE id=$1), $1
                )
                ORDER BY id
                """,
                _optional_uuid(campaign_preflight_scan_id),
            )
            provenance_scan_ids = [str(row["id"]) for row in provenance_rows] or provenance_scan_ids
        except Exception:
            provenance_scan_ids = [campaign_preflight_scan_id]
        provenance_set = set(provenance_scan_ids)
        surface_context["attack_graph"] = _research_graph_with_preflight_provenance(
            graph,
            preflight_scan_id=campaign_preflight_scan_id,
            provenance_scan_ids=provenance_set,
        )
    allowed_families = {
        str(item).strip().lower()
        for item in episode.get("allowed_families") or []
        if str(item).strip()
    }
    recent_actions = await _research_recent_actions(conn, episode["id"], episode.get("campaign_id"))
    excluded_hypothesis_ids = {
        str(item.get("hypothesis_id"))
        for item in recent_actions
        if _research_decision_hypothesis_is_excluded(item)
    }
    ranked_hypotheses = [
        entry
        for entry in (surface_context.get("ranked_hypotheses") or [])
        if isinstance(entry, dict)
        and isinstance(entry.get("hypothesis"), dict)
        and _research_family_is_allowed(entry["hypothesis"].get("family"), allowed_families)
        and str(entry["hypothesis"].get("id") or "") not in excluded_hypothesis_ids
    ]
    surface_context["ranked_hypotheses"] = ranked_hypotheses
    hypothesis_summaries = [
        item
        for item in (context.get("hypotheses_summary") or [])
        if isinstance(item, dict) and _research_family_is_allowed(item.get("family"), allowed_families)
        and str(item.get("id") or "") not in excluded_hypothesis_ids
    ]
    selected_hypothesis_contracts = _research_selected_hypothesis_contracts(
        ranked_hypotheses,
        allowed_families,
    )
    inferred_planning_contracts = _research_inferred_planning_contracts(
        selected_hypothesis_contracts,
    )
    approved_invariant_contracts = [
        item for item in (surface_context.get("approved_invariant_contracts") or [])
        if isinstance(item, dict) and item.get("status") == "approved"
    ][:25]
    commands = _research_command_views(episode)
    recommended_actions = _research_recommended_actions(
        context.get("findings_summary") or [],
        commands,
        allowed_families,
        recent_actions,
    )
    mission = _research_mission(episode)
    focus = await _research_focus_snapshot(conn, episode)
    if str(focus.get("latest_retest_status") or "") in {"queued", "running"}:
        for projected in commands:
            if projected.get("name") != "finding.retest":
                continue
            projected["proposable"] = False
            projected["currently_executable"] = False
            projected["blocked_by"] = list(dict.fromkeys([
                *(projected.get("blocked_by") or []),
                "finding_retest_already_active",
            ]))
    exhaustion = await _research_campaign_exhaustion_snapshot(
        conn,
        episode["id"],
        episode.get("campaign_id"),
    )
    # D1 (steer, don't pause): surface the concrete {command, parameters} already tried this campaign
    # (executed, or rejected as a no-state-change repeat) as an explicit exclusion list, so the planner
    # picks a DIFFERENT actionable lead instead of re-proposing the same action until the 3-strike
    # autopilot breaker trips. Campaign-scoped via recent_actions, so it persists across episodes.
    excluded_actions: list[dict[str, Any]] = []
    _seen_excluded: set[str] = set()
    for _item in recent_actions:
        _action = _item.get("action") if isinstance(_item.get("action"), dict) else {}
        _command_name = str(_action.get("command") or "").strip()
        if not _command_name:
            continue
        if not _research_decision_action_is_excluded(_item):
            continue
        _comparable = _arsenal_routes._research_action_dedupe_comparable(_action)
        _signature = _research_canonical_hash(_comparable)
        if _signature in _seen_excluded:
            continue
        _seen_excluded.add(_signature)
        planner_projection = _research_action_planner_projection(_action)
        if _item.get("hypothesis_id"):
            planner_projection["hypothesis_id"] = str(_item["hypothesis_id"])
        validation_errors = [
            str(error)[:200]
            for error in (_item.get("validation_errors") or [])[:12]
            if str(error).strip()
        ]
        if validation_errors:
            planner_projection["validation_errors"] = validation_errors
        excluded_actions.append(planner_projection)
    current_gaps = _reconcile_research_gap_recommendations(
        context.get("current_gaps") or [],
        excluded_actions,
    )
    sequence = int(await conn.fetchval(
        "SELECT COALESCE(MAX(sequence), -1) + 1 FROM research_observations WHERE episode_id=$1",
        episode["id"],
    ))
    pack = {
        "observation_version": RESEARCH_OBSERVATION_VERSION,
        "episode_id": str(episode["id"]),
        "episode_version": int(episode.get("version") or 1) + 1,
        "sequence": sequence,
        "objective": episode.get("objective"),
        "execution_mode": episode.get("execution_mode"),
        "max_risk_tier": episode.get("max_risk_tier"),
        "allowed_families": episode.get("allowed_families") or [],
        "mission": mission,
        "focus": focus,
        "target_summary": context.get("target_summary") or {},
        "current_surface": surface_context,
        "current_gaps": current_gaps,
        "hypotheses_summary": hypothesis_summaries,
        "selected_hypothesis_contracts": selected_hypothesis_contracts,
        "findings_summary": context.get("findings_summary") or [],
        "known_preconditions": context.get("known_preconditions") or {},
        # Operator-approved policy statements are high-value hypothesis oracles, but they remain
        # planning-only until a family-specific deterministic verifier binds live evidence to them.
        "approved_invariant_contracts": approved_invariant_contracts,
        "inferred_planning_contracts": inferred_planning_contracts,
        # Avoid the generic secret redactor treating the word "tokens" as credential material.
        # This is a numeric planning budget, not a token value.
        "remaining_budget": {
            ("model_units" if key == "model_tokens" else key): value
            for key, value in (episode.get("remaining_budget") or {}).items()
        },
        "proposable_commands": commands,
        "recommended_actions": recommended_actions,
        "recent_actions": recent_actions,
        "excluded_actions": excluded_actions,
        "campaign_exhaustion": exhaustion,
        # D3: universal steering (no app-specific facts) toward token efficiency + prerequisite
        # adaptation. Addresses the observed failures where the planner re-ran inventory queries and
        # retried a create that its target's precondition (e.g. a required captcha token) rejected.
        "planner_guidance": [
            "The discovered surface, endpoints, current_gaps, and hypotheses in this observation are "
            "already current -- do NOT spend an action re-running discovery/inventory you already have; "
            "prefer a concrete test. Anything in excluded_actions was already tried, so choose something new.",
            "If a create/mutation step failed with a client error (4xx) or an experiment stayed "
            "unverified because an object could not be created, do NOT retry the same create. Either "
            "first call an endpoint that produces the missing input (producer->consumer chaining), or "
            "target a different existing object/endpoint.",
            "Approved invariant contracts are operator policy oracles for choosing hypotheses and "
            "experiments. They do not themselves prove a finding: promotion still requires a supported "
            "deterministic family verifier and independent live reproduction.",
            "Inferred planning contracts are non-authoritative hypotheses only: they may help select a "
            "test, but never satisfy approval, execution, or finding-promotion requirements.",
            "Prefer a high-priority recommended_actions retest or focused SQLi/XSS actuator over a "
            "workflow lead whose provability_blockers include a missing readback route or object reference.",
            "Do not test a semantic dimension or actuator listed as exhausted in campaign_exhaustion. "
            "Three independent falsifications or equivalent harness failures retire that exact actuator; "
            "when no non-exhausted hypothesis remains, stop with the evidence instead of restarting recon.",
            "Do not propose an experiment in a family listed in current_surface.exhausted_families: every "
            "lead there is already an owned finding and will be suppressed. Pivot to a family that still has "
            "fresh ranked leads (e.g. mass_assignment, data_exposure, auth_bypass); if none remain, stop.",
            "For a ranked lead, use selected_hypothesis_contracts as the authoritative route/request "
            "shape. Do not ask the operator for request fields or examples already present there.",
            "For a mass_assignment experiment, the forbidden field must be a genuine privilege marker: "
            "substitute the template's <forbidden_field>/<forbidden_value> with an entry from the template's "
            "forbidden_field_candidates (e.g. role=admin, isAdmin=true, verified=true), preferring a field "
            "that already appears in the resource's own read response. A benign field cannot prove the bug -- "
            "the proof only fires when a persisted privilege elevation is accepted and a lower-privilege "
            "control is rejected.",
        ],
        "previous_observation": _research_previous_result_digest(previous_result or {}),
        "planner_contract": {
            "select_exactly_one": True,
            "allowed_decisions": ["execute_action", "request_input", "stop"],
            "receipts_must_not_be_supplied": True,
            "raw_shell_forbidden": True,
            "secrets_forbidden": True,
            "verified_finding_claims_forbidden": True,
            "expected_signal_and_falsifier_required_for_actions": True,
            "identical_consecutive_actions_forbidden": True,
            "excluded_actions_must_not_be_repeated": True,
            "invariant_contracts_are_planning_only": True,
            "invariant_contracts_cannot_directly_promote_findings": True,
            "selected_hypothesis_contract_is_authoritative": True,
            "hypothesis_id_is_top_level_decision_provenance": True,
        },
    }
    pack = _compact_research_observation_pack(pack)
    context_hash = _research_canonical_hash(pack)
    pack["context_hash"] = context_hash
    row = await conn.fetchrow(
        """
        INSERT INTO research_observations (
            episode_id, sequence, observation_version, context_hash,
            episode_version, observation_pack, previous_command_result_id
        ) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7)
        RETURNING *
        """,
        episode["id"],
        sequence,
        RESEARCH_OBSERVATION_VERSION,
        context_hash,
        int(episode.get("version") or 1) + 1,
        json.dumps(pack),
        _optional_uuid(previous_command_result_id),
    )
    status = next_status or "awaiting_planner"
    update_result = await conn.execute(
        """
        UPDATE research_episodes
        SET current_observation_id=$2, status=$3,
            requested_input=CASE WHEN $3='awaiting_planner' THEN NULL ELSE requested_input END,
            version=version+1, updated_at=NOW()
        WHERE id=$1 AND cancel_requested=false
          AND status NOT IN ('completed','cancelled','failed','budget_exhausted','blocked')
        """,
        episode["id"],
        row["id"],
        status,
    )
    if update_result == "UPDATE 0":
        await conn.execute("DELETE FROM research_observations WHERE id=$1", row["id"])
        raise HTTPException(status_code=409, detail="Episode changed before observation could be attached")
    await _record_research_event(
        conn,
        episode["id"],
        event_type="observation_created",
        status=status,
        summary=f"Created bounded observation {sequence}",
        observation_id=row["id"],
        command_result_id=previous_command_result_id,
        details={"context_hash": context_hash, "proposable_count": sum(1 for item in commands if item.get("proposable"))},
    )
    return _public_research_observation_row(row)


_RESEARCH_FOCUSED_ENDPOINT_METHODS = frozenset({
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
})




async def _savepoint_fetchrow(conn: Any, query: str, *args: Any):
    async with _arsenal_routes._optional_database_savepoint(conn):
        return await conn.fetchrow(query, *args)


def _research_command_views(episode: dict[str, Any]) -> list[dict[str, Any]]:
    mode = str(episode.get("execution_mode") or "read_only")
    has_approval = bool(episode.get("approval_receipt_id") and episode.get("scope_receipt_id"))
    gate_enabled = _ai_ops_execute_enabled()
    mission = _research_mission(episode)
    profile = str(mission.get("profile") or "target_hunt")
    configured_allowlist = mission.get("allowed_commands")
    profile_allowlist = RESEARCH_MISSION_COMMANDS.get(profile)
    allowed_commands = (
        {str(item) for item in configured_allowlist if str(item)}
        if isinstance(configured_allowlist, list)
        else profile_allowlist
    )
    views: list[dict[str, Any]] = []
    for command in _research_command_catalog().values():
        name = str(command.get("name") or "")
        if name not in READ_ONLY_RESEARCH_COMMANDS and name not in GATED_RESEARCH_COMMANDS:
            continue
        if allowed_commands is not None and name not in allowed_commands:
            continue
        view = _research_command_projection(
            command,
            max_risk_tier=str(episode.get("max_risk_tier") or "read_only"),
            has_approval=has_approval,
            execution_feature_enabled=gate_enabled,
        )
        parameter_schema = (
            _research_autonomous_parameter_schema(
                name,
                dict(view.get("parameters_schema") or {}),
                allow_cleanup_safe_writes=(
                    str(episode.get("max_risk_tier") or "") == "credential"
                ),
            )
            if isinstance(view.get("parameters_schema"), dict)
            else {}
        )
        server_supplied = []
        for control_name in ("approval_receipt_id", "scope_receipt_id", "confirmations", "execute"):
            if control_name in parameter_schema:
                parameter_schema.pop(control_name, None)
                server_supplied.append(control_name)
        if name in TARGET_BOUND_COMMANDS and "target_id" in parameter_schema:
            parameter_schema.pop("target_id", None)
            server_supplied.append("target_id")
        if name == "scan.focused_family" and "target" in parameter_schema:
            parameter_schema.pop("target", None)
            server_supplied.append("target")
        subject = mission.get("subject") if isinstance(mission.get("subject"), dict) else {}
        if (
            name in {"finding.get", "finding.retest"}
            and str(subject.get("type") or "") == "finding"
            and "finding_id" in parameter_schema
        ):
            parameter_schema.pop("finding_id", None)
            server_supplied.append("finding_id")
        view["parameters_schema"] = parameter_schema
        if name in {"experiment.http_diff", "experiment.workflow"}:
            view["autonomous_constraints"] = ([
                "PUT, PATCH, and DELETE require Hunt, a cleanup/rollback step after mutation, a typed restoration assertion, and successful independent replay.",
            ] if name == "experiment.workflow" and str(episode.get("max_risk_tier") or "") == "credential" else [
                (
                    "POST, PUT, PATCH, and DELETE are unavailable in HTTP diff because it has no restoration contract; use a typed workflow or focused family scan."
                    if name == "experiment.http_diff" else
                    "DELETE, PUT, and PATCH are unavailable at this tier; use Hunt with typed cleanup and restoration assertions."
                ),
            ])
        view["server_supplied_parameters"] = sorted(set(server_supplied))
        blocked = list(view.get("blocked_by") or [])
        if mode == "shadow":
            blocked = [reason for reason in blocked if reason not in {"approval_receipt_missing", "execution_feature_disabled"}]
            blocked.append("shadow_mode_no_dispatch")
            view["currently_executable"] = False
            view["proposable"] = not any(
                reason.startswith("catalog_status:") or reason == "risk_exceeds_episode"
                for reason in blocked
            )
        elif mode == "read_only" and name in GATED_RESEARCH_COMMANDS:
            blocked.append("episode_mode_read_only")
            view["proposable"] = False
            view["currently_executable"] = False
        projected_cost = _research_parameterized_action_cost(
            command,
            {},
            _research_action_cost(command),
        )
        view["reserved_cost"] = projected_cost
        budget_blocks = _research_budget_violations(
            episode.get("budget_limits") or {},
            episode.get("budget_used") or {},
            projected_cost,
        )
        launch_intensity = str((episode.get("planner") or {}).get("launch_intensity") or "")
        if launch_intensity and int((episode.get("remaining_budget") or {}).get("steps") or 0) <= 1:
            budget_blocks.append("budget_reserved_for_conclusion")
        if budget_blocks:
            blocked.extend(budget_blocks)
            view["proposable"] = False
            view["currently_executable"] = False
        view["blocked_by"] = list(dict.fromkeys(blocked))
        views.append(view)
    return sorted(views, key=lambda item: (not item.get("proposable"), item.get("name") or ""))


async def _research_recent_actions(
    conn, episode_id: str | uuid.UUID, campaign_id: str | uuid.UUID | None = None,
) -> list[dict[str, Any]]:
    rows = await conn.fetch(
        """
        SELECT rd.sequence, rd.decision_type, rd.status, rd.action, rd.reason,
               rd.hypothesis_id,
               rd.expected_signal, rd.falsifier, rd.validation_errors,
               rd.command_result_id, cr.status AS command_status, cr.scan_id,
               cr.result_json, cr.finding_ids, cr.operator_message
        FROM research_decisions rd
        LEFT JOIN command_results cr ON cr.id=rd.command_result_id
        JOIN research_episodes re ON re.id=rd.episode_id
        WHERE rd.episode_id=$1 OR ($2::uuid IS NOT NULL AND re.campaign_id=$2)
        ORDER BY rd.created_at DESC
        LIMIT 200
        """,
        _optional_uuid(episode_id),
        _optional_uuid(campaign_id),
    )
    actions: list[dict[str, Any]] = []
    for row in rows:
        item = row_to_dict(row)
        item["action"] = _decode_json_value(item.get("action")) or {}
        item["validation_errors"] = _decode_json_value(item.get("validation_errors")) or []
        result_json = _decode_json_value(item.get("result_json")) or {}
        rj = result_json if isinstance(result_json, dict) else {}
        replay = rj.get("replay") if isinstance(rj.get("replay"), dict) else {}
        family_proof = rj.get("family_proof") if isinstance(rj.get("family_proof"), dict) else {}
        promotion = rj.get("promotion") if isinstance(rj.get("promotion"), dict) else {}
        workflow_result = rj.get("workflow") if isinstance(rj.get("workflow"), dict) else {}
        operator_message = item.pop("operator_message", None)
        # Surface the first FAILING observation (method/path/status + scrubbed body_sample) so the planner
        # sees the ROOT cause -- e.g. "POST /Feedbacks 500, captchaId missing" -- not just "restoration not
        # verified". This is the concrete detail a producer->consumer recovery needs.
        failure_detail = None
        # Inspect both executions. The first run normally has observations even when it is clean, so
        # ``first or replay`` silently hid failures that occurred only during the independent replay.
        for _obs in [
            *(workflow_result.get("observations") or []),
            *(replay.get("observations") or []),
        ]:
            if not isinstance(_obs, dict):
                continue
            _resp = _obs.get("response") if isinstance(_obs.get("response"), dict) else {}
            _status = _resp.get("status")
            if _obs.get("error") or (isinstance(_status, int) and _status >= 400):
                _req = _obs.get("request") if isinstance(_obs.get("request"), dict) else {}
                failure_detail = {
                    "step": _obs.get("label"),
                    "method": _req.get("method"),
                    "path": _req.get("path"),
                    "status": _status,
                    "error": _obs.get("error"),
                    "body_sample": (str(_resp.get("body_sample"))[:200] if _resp.get("body_sample") else None),
                }
                break
        experiment_outcome = _arsenal_routes._research_experiment_outcome(
            item["action"],
            {
                "status": item.get("command_status"),
                "result_json": rj,
                "finding_ids": item.get("finding_ids"),
            },
        )
        item["result"] = {
            "status": item.pop("command_status", None),
            "scan_id": item.pop("scan_id", None),
            "retest_id": rj.get("retest_id"),
            # The AUTHORITATIVE proof state is family_proof.verdict / the promotion outcome -- NOT
            # replay.proof_state, which is always the pre-promotion placeholder "unverified_workflow_signal"
            # (would otherwise tell the planner "unverified" even for a promoted, verified finding).
            "proof_state": (
                family_proof.get("verdict")
                or promotion.get("proof_state")
                or replay.get("proof_state")
                or rj.get("proof_state")
            ),
            # Why it did not verify (nested under replay/promotion/family_proof); operator_message is a
            # COLUMN; failure_detail carries the concrete failing request for producer->consumer recovery.
            "failure_reason": (
                replay.get("replay_blocked_reason")
                or promotion.get("reason")
                or family_proof.get("reason")
            ),
            "failure_detail": failure_detail,
            "operator_message": (str(operator_message)[:300] if operator_message else None),
            "scientific_outcome": (experiment_outcome or {}).get("outcome"),
        }
        item.pop("finding_ids", None)
        item.pop("result_json", None)
        actions.append(_arsenal_routes._bounded_research_payload(item))
    return actions


def _reconcile_research_gap_recommendations(
    gaps: Any,
    excluded_actions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Remove structured recommendations that deterministic duplicate policy will reject."""
    excluded_parameterless = {
        str(item.get("command") or "").strip()
        for item in excluded_actions
        if isinstance(item, dict)
        and str(item.get("command") or "").strip()
        and not (item.get("parameters") if isinstance(item.get("parameters"), dict) else {})
    }
    reconciled: list[dict[str, Any]] = []
    for raw_gap in gaps if isinstance(gaps, list) else []:
        if not isinstance(raw_gap, dict):
            continue
        gap = dict(raw_gap)
        recommendation = str(gap.get("next_safe_command") or "").strip()
        if recommendation and recommendation in excluded_parameterless:
            gap.pop("next_safe_command", None)
            gap["recommendation_state"] = "already_attempted_without_state_change"
        reconciled.append(gap)
    return reconciled


async def _research_focus_snapshot(conn, episode: dict[str, Any]) -> dict[str, Any]:
    mission = _research_mission(episode)
    subject = mission.get("subject") if isinstance(mission.get("subject"), dict) else {}
    if str(subject.get("type") or "") != "finding" or not subject.get("id"):
        return {}
    try:
        finding_id = uuid.UUID(str(subject["id"]))
    except (TypeError, ValueError):
        return {"type": "finding", "id": str(subject.get("id") or ""), "status": "invalid_subject"}
    row = await conn.fetchrow(
        """
        SELECT f.id, f.target_id, f.title, f.severity, f.status,
               f.tool AS category, f.tool, f.cwe, f.url,
               COALESCE(f.evidence->>'param', f.evidence->>'parameter') AS param,
               f.description, f.first_seen_at, f.last_seen_at,
               f.last_verification_verdict, f.last_verified_at,
               fv.id AS latest_retest_id, fv.status AS latest_retest_status,
               fv.verdict AS latest_retest_verdict, fv.confidence AS latest_retest_confidence,
               fv.completed_at AS latest_retest_completed_at
        FROM findings f
        LEFT JOIN LATERAL (
            SELECT id, status, verdict, confidence, completed_at
            FROM finding_verifications
            WHERE finding_id=f.id
            ORDER BY created_at DESC
            LIMIT 1
        ) fv ON true
        WHERE f.id=$1 AND f.target_id=$2
        """,
        finding_id,
        _optional_uuid(episode.get("target_id")),
    )
    if not row:
        return {"type": "finding", "id": str(finding_id), "status": "not_found"}
    snapshot = row_to_dict(row)
    snapshot["type"] = "finding"
    snapshot["family"] = _arsenal_routes._research_finding_family(snapshot)
    return _arsenal_routes._bounded_research_payload(snapshot)


def _research_inferred_planning_contracts(contracts: Any) -> list[dict[str, Any]]:
    """Derive hypothesis oracles without granting approval or promotion authority."""
    inferred: list[dict[str, Any]] = []
    for contract in contracts if isinstance(contracts, list) else []:
        if not isinstance(contract, dict) or not contract.get("route"):
            continue
        family = family_proof.canonical_family(contract.get("family"))
        if family not in {"bola", "mass_assignment", "access_control"}:
            continue
        inferred.append({
            "source_hypothesis_id": contract.get("hypothesis_id"),
            "contract_kind": "ownership" if family == "bola" else "mutation_boundary",
            "method": contract.get("method"),
            "path": contract.get("route"),
            "status": "inferred",
            "planning_authority": True,
            "execution_authority": False,
            "promotion_authority": False,
            "verification_required": True,
        })
    return inferred[:8]


def _research_recommended_actions(
    findings: Any,
    commands: Any,
    allowed_families: Any,
    recent_actions: Any = None,
) -> list[dict[str, Any]]:
    proposable = {
        str(item.get("name") or "")
        for item in commands if isinstance(item, dict) and item.get("proposable")
    }
    recommendations: list[dict[str, Any]] = []
    prior_retest_ids = {
        str(((item.get("action") or {}).get("parameters") or {}).get("finding_id") or "")
        for item in (recent_actions if isinstance(recent_actions, list) else [])
        if isinstance(item, dict)
        if str((item.get("action") or {}).get("command") or "") == "finding.retest"
        and str(item.get("status") or "") in {"accepted", "dispatching", "completed"}
    }
    if "finding.retest" in proposable:
        for finding in findings if isinstance(findings, list) else []:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity") or "").lower()
            verdict = str(finding.get("last_verification_verdict") or "").lower()
            if severity not in {"critical", "high"} or verdict in {"exploited", "likely_fixed", "fixed"}:
                continue
            finding_id = str(finding.get("id") or "")
            if finding_id and finding_id not in prior_retest_ids:
                recommendations.append({
                    "priority": "high",
                    "reason": "unverified_high_severity_residue",
                    "command": "finding.retest",
                    "parameters": {"finding_id": finding_id},
                })
    if "scan.focused_family" in proposable:
        for family in ("sqli", "xss"):
            if _research_family_is_allowed(family, allowed_families):
                recommendations.append({
                    "priority": "high",
                    "reason": "executable_deterministic_injection_actuator",
                    "command": "scan.focused_family",
                    "parameters": {"check_family": family},
                })
    return recommendations[:6]


def _research_previous_result_digest(value: Any) -> dict[str, Any]:
    result = value if isinstance(value, dict) else {}
    raw_error = result.get("error")
    if isinstance(raw_error, dict):
        error_digest: Any = {
            key: str(raw_error.get(key) or "")[:800]
            for key in ("error", "violation", "message", "reason", "detail")
            if raw_error.get(key) not in (None, "", [], {})
        }
    elif raw_error not in (None, ""):
        error_digest = str(raw_error)[:800]
    else:
        error_digest = None
    command_result = result.get("command_result") if isinstance(result.get("command_result"), dict) else {}
    result_json = (
        command_result.get("result_json")
        if isinstance(command_result.get("result_json"), dict)
        else {}
    )
    nested = result.get("result") if isinstance(result.get("result"), dict) else {}
    digest = {
        "command": result.get("command"),
        "dispatched": result.get("dispatched"),
        "execution_blocked_reason": result.get("execution_blocked_reason"),
        "error": error_digest,
        "operation_id": result.get("operation_id"),
        "command_result": {
            key: command_result.get(key)
            for key in (
                "id", "status", "command", "scan_id", "finding_ids", "hypothesis_ids",
                "evidence_object_ids", "next_action", "operator_message",
            )
            if command_result.get(key) not in (None, "", [], {})
        },
        "result_summary": {
            key: nested.get(key)
            for key in (
                "action", "reason", "status", "scan_id", "retest_id", "finding_id",
                "coverage", "recommendation", "recommended_campaigns", "family_coverage",
                "verification_summary", "findings_count", "score", "grade", "error_message",
            )
            if nested.get(key) not in (None, "", [], {})
        },
    }
    typed_result_json = {
        key: result_json.get(key)
        for key in (
            "target_id", "selected_action", "status", "reason", "scan_id", "retest_id",
            "finding_id", "batch_size", "stale_days", "check_family", "endpoint_filter",
            "mode", "finding_type", "scan_type", "findings_count", "score", "grade",
            "verification_summary", "family_coverage", "recommendation",
        )
        if result_json.get(key) not in (None, "", [], {})
    }
    if typed_result_json:
        digest["command_result"]["result_json"] = typed_result_json
    command_name = str(result.get("command") or command_result.get("command") or "")
    durable_read_result = result_json.get("result")
    read_source = nested or durable_read_result
    if command_name in READ_ONLY_RESEARCH_COMMANDS and read_source not in (None, "", [], {}):
        digest["read_result"] = _research_read_result_projection(read_source)
    experiment_source = nested
    if command_name == "experiment.http_diff" and not experiment_source.get("experiment"):
        experiment_source = result_json
    if command_name == "experiment.workflow" and not experiment_source.get("workflow"):
        experiment_source = result_json
    if command_name in {"experiment.http_diff", "experiment.workflow"}:
        digest["experiment_result"] = _research_experiment_projection(experiment_source)
    # _research_latest_action_result is already a digest; retain its useful typed links.
    if isinstance(result.get("decision"), dict):
        digest["decision"] = result["decision"]
    if isinstance(result.get("linked_work"), list):
        digest["linked_work"] = result["linked_work"][:10]
    return _arsenal_routes._bounded_research_payload(digest)


def _research_selected_hypothesis_contracts(
    ranked_hypotheses: Any,
    allowed_families: set[str] | list[str],
    *,
    limit: int = 5,
) -> list[dict[str, Any]]:
    contracts: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in ranked_hypotheses if isinstance(ranked_hypotheses, list) else []:
        hypothesis = entry.get("hypothesis") if isinstance(entry, dict) else None
        if not isinstance(hypothesis, dict) or not _research_family_is_allowed(
            hypothesis.get("family"), allowed_families
        ):
            continue
        contract = _arsenal_routes._research_hypothesis_experiment_contract(hypothesis)
        hypothesis_id = str(contract.get("hypothesis_id") or "")
        if not hypothesis_id or hypothesis_id in seen:
            continue
        seen.add(hypothesis_id)
        contracts.append(contract)
        if len(contracts) >= max(1, min(int(limit or 5), 10)):
            break
    return contracts


def _research_decision_action_is_excluded(item: Any) -> bool:
    """Return whether a prior decision is deterministic no-progress campaign memory."""
    decision = item if isinstance(item, dict) else {}
    if str(decision.get("status") or "") in {"accepted", "dispatching", "completed"}:
        return True
    validation_errors = {
        str(error).strip()
        for error in (decision.get("validation_errors") or [])
        if str(error).strip()
    }
    return bool(validation_errors & {
        "known_vulnerability_already_covered",
        "repeated_action_without_state_change",
        "campaign_recon_cap_reached",
        "finding_retest_campaign_cap_reached",
    }) or any(
        error.startswith(("semantic_dimension_exhausted:", "experiment_actuator_exhausted:"))
        for error in validation_errors
    )


def _research_decision_hypothesis_is_excluded(item: Any) -> bool:
    """Return whether a rejected decision makes its exact hypothesis non-actionable.

    A mechanically repeated action can still leave room for another experiment on the
    same hypothesis. A known vulnerability or an exhausted semantic dimension cannot:
    keeping that lead on the ranked board makes the planner spend turns proposing work
    the deterministic novelty gate must reject.
    """
    decision = item if isinstance(item, dict) else {}
    if not decision.get("hypothesis_id"):
        return False
    validation_errors = {
        str(error).strip()
        for error in (decision.get("validation_errors") or [])
        if str(error).strip()
    }
    return "known_vulnerability_already_covered" in validation_errors or any(
        error.startswith(("semantic_dimension_exhausted:", "experiment_actuator_exhausted:"))
        for error in validation_errors
    )


def _compact_research_observation_pack(pack: dict[str, Any]) -> dict[str, Any]:
    # Redact once, then bound the already-redacted tree. Calling
    # _bounded_research_payload recursively re-runs whole-subtree redaction at every
    # level, which turns a merely large schema into superlinear CPU work.
    redacted = _arsenal_routes._redact_agent_payload(pack)

    def _bound_once(value: Any, depth: int = 0) -> Any:
        if depth > 16:
            return "[truncated]"
        if isinstance(value, dict):
            return {
                str(key)[:120]: _bound_once(nested, depth + 1)
                for key, nested in list(value.items())[:80]
            }
        if isinstance(value, (list, tuple)):
            return [_bound_once(item, depth + 1) for item in value[:100]]
        if isinstance(value, str):
            return value[:4000]
        if isinstance(value, (int, float)) or value is None:
            return value
        return str(value)[:4000]

    bounded = _bound_once(redacted)

    # _build_research_observation adds a 64-character context_hash after compaction.
    # Reserve enough room for that key (including JSON punctuation) so the persisted
    # observation, rather than only this intermediate value, remains below 48 KiB.
    context_hash_reserve = 96
    payload_limit = RESEARCH_OBSERVATION_MAX_BYTES - context_hash_reserve
    if _json_size_bytes(bounded) <= payload_limit:
        return bounded

    def _text(value: Any, limit: int = 240) -> str:
        return str(value or "")[:limit]

    def _scalars(
        value: Any,
        keys: tuple[str, ...],
        *,
        text_limit: int = 240,
    ) -> dict[str, Any]:
        source = value if isinstance(value, dict) else {}
        result: dict[str, Any] = {}
        for key in keys:
            nested = source.get(key)
            if nested in (None, "", [], {}):
                continue
            if isinstance(nested, (str, bytes)):
                result[key] = _text(nested, text_limit)
            elif isinstance(nested, (int, float, bool)):
                result[key] = nested
            else:
                result[key] = _text(nested, text_limit)
        return result

    def _string_list(value: Any, *, count: int, item_limit: int = 120) -> list[str]:
        if not isinstance(value, (list, tuple)):
            return []
        return [_text(item, item_limit) for item in value[:count] if item not in (None, "")]

    def _schema_projection(value: Any, depth: int = 0) -> dict[str, Any]:
        """Retain decision-relevant JSON Schema shape without copying arbitrary annotations."""
        source = value if isinstance(value, dict) else {}
        if depth > 6:
            return {}
        schema_keywords = {
            "type", "format", "const", "minimum", "maximum", "exclusiveMinimum",
            "exclusiveMaximum", "minLength", "maxLength", "minItems", "maxItems",
            "additionalProperties", "enum", "required", "properties", "items",
            "oneOf", "anyOf", "allOf", "if", "then", "else", "not",
            "pattern", "default",
        }
        # Arsenal exposes a flat property map rather than a full {type, properties} schema.
        # Preserve that real contract shape when observations must be compacted.
        if depth == 0 and source and not (set(source) & schema_keywords):
            return {
                _text(name, 80): _schema_projection(schema, depth + 1)
                for name, schema in list(source.items())[:20]
                if isinstance(schema, dict)
            }
        projected = _scalars(
            source,
            (
                "type", "format", "const", "minimum", "maximum", "exclusiveMinimum",
                "exclusiveMaximum", "minLength", "maxLength", "minItems", "maxItems",
                "additionalProperties", "pattern", "default",
            ),
            text_limit=120,
        )
        if isinstance(source.get("enum"), list):
            projected["enum"] = [
                item if isinstance(item, (int, float, bool)) else _text(item, 80)
                for item in source["enum"][:8]
            ]
        required = _string_list(source.get("required"), count=20, item_limit=80)
        if required:
            projected["required"] = required
        properties = source.get("properties") if isinstance(source.get("properties"), dict) else {}
        if properties:
            projected["properties"] = {
                _text(name, 80): _schema_projection(schema, depth + 1)
                for name, schema in list(properties.items())[:20]
            }
        items = _schema_projection(source.get("items"), depth + 1)
        if items:
            projected["items"] = items
        for combinator in ("oneOf", "anyOf", "allOf"):
            branches = source.get(combinator) if isinstance(source.get(combinator), list) else []
            projected_branches = [
                branch
                for branch in (
                    _schema_projection(item, depth + 1) for item in branches[:6]
                )
                if branch
            ]
            if projected_branches:
                projected[combinator] = projected_branches
        for conditional in ("if", "then", "else", "not"):
            branch = source.get(conditional)
            if isinstance(branch, dict):
                # Empty schemas are meaningful (for example ``not: {}``), so
                # retain the keyword even when projection yields an empty map.
                projected[conditional] = _schema_projection(branch, depth + 1)
        return projected

    mission_source = bounded.get("mission") if isinstance(bounded.get("mission"), dict) else {}
    subject_source = (
        mission_source.get("subject") if isinstance(mission_source.get("subject"), dict) else {}
    )
    mission = _scalars(mission_source, ("profile",), text_limit=120)
    mission["subject"] = _scalars(
        subject_source,
        ("type", "id", "target_id", "family", "status", "title"),
        text_limit=300,
    )
    mission_commands = _string_list(
        mission_source.get("allowed_commands"), count=40, item_limit=120
    )
    if mission_commands:
        mission["allowed_commands"] = mission_commands

    focus = _scalars(
        bounded.get("focus"),
        (
            "type", "id", "target_id", "title", "severity", "status", "category", "tool",
            "cwe", "url", "param", "family", "last_verification_verdict", "last_verified_at",
            "latest_retest_id", "latest_retest_status", "latest_retest_verdict",
            "latest_retest_confidence", "latest_retest_completed_at",
        ),
        text_limit=500,
    )

    budget_source = (
        bounded.get("remaining_budget") if isinstance(bounded.get("remaining_budget"), dict) else {}
    )
    remaining_budget = _scalars(
        budget_source,
        ("steps", "actions", "active_actions", "requests", "seconds", "model_units"),
        text_limit=80,
    )
    # Preserve future numeric budget dimensions too, while bounding adversarial keys.
    for key, value in list(budget_source.items())[:20]:
        key = _text(key, 80)
        if key not in remaining_budget and isinstance(value, (int, float, bool)):
            remaining_budget[key] = value

    actions: list[dict[str, Any]] = []
    for raw_action in list(bounded.get("recent_actions") or [])[:6]:
        if not isinstance(raw_action, dict):
            continue
        digest = _scalars(
            raw_action,
            ("sequence", "decision_type", "status", "command_result_id", "hypothesis_id"),
            text_limit=160,
        )
        action = raw_action.get("action") if isinstance(raw_action.get("action"), dict) else {}
        action_digest = _bound_once(_research_action_planner_projection(action), 1)
        if action_digest:
            digest["action"] = action_digest
        validation_errors = _string_list(
            raw_action.get("validation_errors"), count=12, item_limit=200,
        )
        if validation_errors:
            digest["validation_errors"] = validation_errors
        result = raw_action.get("result") if isinstance(raw_action.get("result"), dict) else {}
        result_digest = _scalars(
            result,
            ("status", "scan_id", "retest_id", "proof_state", "scientific_outcome",
             "failure_reason", "failure_detail", "operator_message"),
            text_limit=200,
        )
        if result_digest:
            digest["result"] = result_digest
        actions.append(digest)

    command_sources = [
        item for item in list(bounded.get("proposable_commands") or [])[:25]
        if isinstance(item, dict) and item.get("name")
    ]
    commands: list[dict[str, Any]] = []
    for item in command_sources:
        command = _scalars(
            item,
            ("name", "risk_tier", "proposable", "currently_executable"),
            text_limit=160,
        )
        if isinstance(item.get("reserved_cost"), dict):
            command["reserved_cost"] = _scalars(
                item["reserved_cost"],
                ("steps", "actions", "active_actions", "requests", "seconds", "model_tokens"),
                text_limit=80,
            )
        server_supplied = _string_list(
            item.get("server_supplied_parameters"), count=12, item_limit=80
        )
        blocked_by = _string_list(item.get("blocked_by"), count=8, item_limit=120)
        autonomous_constraints = _string_list(
            item.get("autonomous_constraints"), count=4, item_limit=300
        )
        if server_supplied:
            command["server_supplied_parameters"] = server_supplied
        if blocked_by:
            command["blocked_by"] = blocked_by
        if autonomous_constraints:
            command["autonomous_constraints"] = autonomous_constraints
        commands.append(command)

    compacted: dict[str, Any] = _scalars(
        bounded,
        (
            "observation_version", "episode_id", "episode_version", "sequence", "objective",
            "execution_mode", "max_risk_tier",
        ),
        text_limit=800,
    )
    contract_digest: list[dict[str, Any]] = []
    for raw_contract in list(bounded.get("selected_hypothesis_contracts") or [])[:5]:
        if not isinstance(raw_contract, dict):
            continue
        projected = _scalars(
            raw_contract,
            (
                "hypothesis_id", "family", "title", "method", "route", "request_fields",
                "request_example", "readable_route", "provability_score",
                "create_based", "readback_route", "cleanup_route",
                "attempt_count", "prior_failures", "last_outcome",
            ),
            text_limit=1200,
        )
        required_principals = _string_list(
            raw_contract.get("required_principals"), count=8, item_limit=100
        )
        if required_principals:
            projected["required_principals"] = required_principals
        available_methods = _string_list(
            raw_contract.get("available_methods"), count=8, item_limit=16
        )
        provability_blockers = _string_list(
            raw_contract.get("provability_blockers"), count=8, item_limit=100
        )
        if available_methods:
            projected["available_methods"] = available_methods
        if provability_blockers:
            projected["provability_blockers"] = provability_blockers
        if isinstance(raw_contract.get("next_test_action"), dict):
            projected["next_test_action"] = _bound_once(raw_contract["next_test_action"], 1)
        if projected:
            contract_digest.append(projected)

    compacted.update({
        "allowed_families": _string_list(bounded.get("allowed_families"), count=20, item_limit=80),
        "mission": mission,
        "focus": focus,
        "remaining_budget": remaining_budget,
        "recent_actions": actions,
        "proposable_commands": commands,
        # Mandatory: a selected hypothesis without its concrete request shape
        # is not executable and must never be presented as actionable.
        "selected_hypothesis_contracts": contract_digest,
        "observation_compaction": {
            "applied": True,
            "max_bytes": RESEARCH_OBSERVATION_MAX_BYTES,
            "context_hash_reserve_bytes": context_hash_reserve,
        },
    })

    def _add_if_fits(key: str, value: Any) -> None:
        if value in (None, "", [], {}):
            return
        compacted[key] = value
        if _json_size_bytes(compacted) > payload_limit:
            compacted.pop(key, None)

    # D1: preserve the explicit exclusion list even in the oversized-observation fallback so the
    # planner is still steered away from repeating already-tried actions.
    excluded_digest: list[dict[str, Any]] = []
    for raw_excluded in list(bounded.get("excluded_actions") or [])[:30]:
        if not isinstance(raw_excluded, dict):
            continue
        entry = _bound_once(raw_excluded, 1)
        if entry:
            excluded_digest.append(entry)
    if excluded_digest:
        compacted["excluded_actions"] = []
        for entry in excluded_digest:
            compacted["excluded_actions"].append(entry)
            if _json_size_bytes(compacted) > payload_limit:
                compacted["excluded_actions"].pop()
                break
        if not compacted["excluded_actions"]:
            compacted.pop("excluded_actions", None)
    _add_if_fits(
        "campaign_exhaustion",
        _bound_once(bounded.get("campaign_exhaustion") or {}, 3),
    )
    _add_if_fits(
        "planner_guidance",
        _string_list(bounded.get("planner_guidance"), count=8, item_limit=400),
    )
    _add_if_fits(
        "recommended_actions",
        _bound_once(list(bounded.get("recommended_actions") or [])[:6], 3),
    )
    _add_if_fits(
        "inferred_planning_contracts",
        _bound_once(list(bounded.get("inferred_planning_contracts") or [])[:8], 3),
    )

    invariant_digest: list[dict[str, Any]] = []
    for raw_contract in list(bounded.get("approved_invariant_contracts") or [])[:12]:
        if not isinstance(raw_contract, dict):
            continue
        contract = _scalars(
            raw_contract,
            (
                "id", "version", "contract_kind", "title", "subject_role", "action", "resource",
                "method", "path", "field_name", "operator", "expected_access", "status",
                "planning_authority", "promotion_authority", "verification_required",
            ),
            text_limit=300,
        )
        for key in ("expected_value", "conditions"):
            if raw_contract.get(key) not in (None, "", [], {}):
                contract[key] = _bound_once(raw_contract[key], 2)
        raw_plan = raw_contract.get("verification_plan")
        if isinstance(raw_plan, dict):
            contract["verification_plan"] = {
                **_scalars(
                    raw_plan,
                    (
                        "verifier", "proof_family", "deterministic_family_supported",
                        "ready_to_execute", "requires_two_live_executions",
                        "requires_restoration", "promotion_authority", "promotion_gate",
                    ),
                    text_limit=160,
                ),
                "required_inputs": _string_list(raw_plan.get("required_inputs"), count=12, item_limit=100),
                "missing_inputs": _string_list(raw_plan.get("missing_inputs"), count=12, item_limit=100),
            }
        if contract:
            invariant_digest.append(contract)
    _add_if_fits("approved_invariant_contracts", invariant_digest)

    target_summary = _scalars(
        bounded.get("target_summary"),
        ("target_id", "url", "root_domain", "name", "environment", "status"),
        text_limit=500,
    )
    _add_if_fits("target_summary", target_summary)

    surface_source = (
        bounded.get("current_surface") if isinstance(bounded.get("current_surface"), dict) else {}
    )
    surface = _scalars(
        surface_source,
        ("asm_enabled", "asm_last_test_at", "asm_last_recon_at"),
        text_limit=200,
    )
    for key in ("coverage", "endpoint_counts"):
        if isinstance(surface_source.get(key), dict):
            surface[key] = _scalars(
                surface_source[key], tuple(list(surface_source[key].keys())[:20]), text_limit=120
            )
    endpoint_samples = []
    for endpoint in list(surface_source.get("sample_endpoints") or [])[:8]:
        projected = _scalars(
            endpoint,
            ("method", "path", "url", "route", "status", "source", "content_type",
             "param_shape", "replay_spec", "auth_state"),
            text_limit=300,
        )
        if projected:
            endpoint_samples.append(projected)
    if endpoint_samples:
        surface["sample_endpoints"] = endpoint_samples
    ranked = []
    for entry in list(surface_source.get("ranked_hypotheses") or [])[:6]:
        hypothesis = entry.get("hypothesis") if isinstance(entry, dict) and isinstance(entry.get("hypothesis"), dict) else {}
        projected = _scalars(
            entry,
            ("hypothesis_id", "priority", "decision", "reason", "request_cost"),
            text_limit=320,
        )
        projected["hypothesis"] = _scalars(
            hypothesis,
            ("id", "title", "family", "severity_guess", "confidence", "status", "dedupe_key"),
            text_limit=320,
        )
        # Keep the dedupe route+method so a compacted ranked lead is still bindable by the autobind
        # (family+route+method identity) -- dropping it forced the planner to work from memory.
        hyp_metadata = hypothesis.get("metadata_json") if isinstance(hypothesis.get("metadata_json"), dict) else {}
        hyp_dims = hyp_metadata.get("dedupe_dimensions") if isinstance(hyp_metadata.get("dedupe_dimensions"), dict) else {}
        dims_projected = _scalars(hyp_dims, ("route", "method", "object_key"), text_limit=200)
        if dims_projected:
            projected["hypothesis"]["metadata_json"] = {"dedupe_dimensions": dims_projected}
        next_test = hypothesis.get("next_test_action")
        if isinstance(next_test, dict):
            projected["hypothesis"]["next_test_action"] = _bound_once(next_test, 1)
        if projected:
            ranked.append(projected)
    if ranked:
        surface["ranked_hypotheses"] = ranked
    graph_source = surface_source.get("attack_graph") if isinstance(surface_source.get("attack_graph"), dict) else {}
    graph = {
        "nodes": [
            _scalars(item, ("node_type", "node_key", "label", "scan_id", "last_seen_at"), text_limit=240)
            for item in list(graph_source.get("nodes") or [])[:20]
            if isinstance(item, dict)
        ],
        "edges": [
            _scalars(item, ("src_key", "edge_type", "dst_key", "scan_id", "last_seen_at"), text_limit=240)
            for item in list(graph_source.get("edges") or [])[:25]
            if isinstance(item, dict)
        ],
        "truncated": bool(graph_source.get("truncated")),
        "provenance_scan_id": str(graph_source.get("provenance_scan_id") or "")[:80] or None,
    }
    provenance_source = (
        graph_source.get("preflight_provenance")
        if isinstance(graph_source.get("preflight_provenance"), dict)
        else {}
    )
    if provenance_source:
        graph["preflight_provenance"] = {
            "scan_ids": _string_list(provenance_source.get("scan_ids"), count=30, item_limit=80),
            **_scalars(provenance_source, ("node_count", "edge_count"), text_limit=80),
        }
    if graph["nodes"] or graph["edges"]:
        surface["attack_graph"] = graph
    recent_scans = []
    for scan in list(surface_source.get("recent_scans") or [])[:12]:
        if not isinstance(scan, dict):
            continue
        projected = _scalars(
            scan,
            (
                "id", "parent_scan_id", "scan_role", "scan_type", "run_kind", "status",
                "current_phase", "findings_count", "score", "grade", "created_at", "updated_at",
            ),
            text_limit=180,
        )
        if isinstance(scan.get("intent"), dict):
            projected["intent"] = _scalars(
                scan["intent"], tuple(scan["intent"].keys()), text_limit=120,
            )
        if isinstance(scan.get("result_summary"), dict):
            projected["result_summary"] = _scalars(
                scan["result_summary"], tuple(scan["result_summary"].keys()), text_limit=120,
            )
        recent_scans.append(projected)
    if recent_scans:
        surface["recent_scans"] = recent_scans
    # Steer the planner off already-owned families even in the compacted fallback.
    exhausted_families = _string_list(surface_source.get("exhausted_families"), count=12, item_limit=40)
    if exhausted_families:
        surface["exhausted_families"] = exhausted_families
    _add_if_fits("current_surface", surface)

    hypotheses = []
    for hypothesis in list(bounded.get("hypotheses_summary") or [])[:5]:
        projected = _scalars(
            hypothesis,
            (
                "id", "claim", "title", "family", "status", "route", "path", "priority",
                "severity_guess", "confidence", "dedupe_key", "evidence_strength",
                "next_action", "blocked_by",
            ),
            text_limit=320,
        )
        if isinstance(hypothesis.get("next_test_action"), dict):
            projected["next_test_action"] = _bound_once(hypothesis["next_test_action"], 1)
        if projected:
            hypotheses.append(projected)
    _add_if_fits("hypotheses_summary", hypotheses)

    findings = []
    for finding in list(bounded.get("findings_summary") or [])[:8]:
        projected = _scalars(
            finding,
            (
                "id", "title", "severity", "status", "category", "tool", "cwe", "url",
                "family", "proof_state", "last_verification_verdict", "last_verified_at",
            ),
            text_limit=400,
        )
        if projected:
            findings.append(projected)
    _add_if_fits("findings_summary", findings)

    gaps = []
    for gap in list(bounded.get("current_gaps") or [])[:8]:
        projected = _scalars(
            gap,
            (
                "kind", "family", "status", "count", "completed", "attempts", "stale",
                "recommendation", "next_safe_command", "reason",
            ),
            text_limit=300,
        )
        if projected:
            gaps.append(projected)
    _add_if_fits("current_gaps", gaps)

    _add_if_fits(
        "known_preconditions",
        _scalars(
            bounded.get("known_preconditions"),
            tuple(list((bounded.get("known_preconditions") or {}).keys())[:20])
            if isinstance(bounded.get("known_preconditions"), dict) else (),
            text_limit=160,
        ),
    )
    _add_if_fits(
        "previous_observation",
        _research_previous_result_digest(bounded.get("previous_observation") or {}),
    )
    _add_if_fits(
        "planner_contract",
        _scalars(
            bounded.get("planner_contract"),
            tuple(list((bounded.get("planner_contract") or {}).keys())[:20])
            if isinstance(bounded.get("planner_contract"), dict) else (),
            text_limit=120,
        ),
    )

    # Descriptions materially improve model command selection, but command names and gates are
    # mandatory. Admit descriptions opportunistically so wide UTF-8 text never evicts commands.
    for index, source in enumerate(command_sources):
        description = _text(source.get("description"), 200)
        if not description:
            continue
        compacted["proposable_commands"][index]["description"] = description
        if _json_size_bytes(compacted) > payload_limit:
            compacted["proposable_commands"][index].pop("description", None)

    # Add decision-relevant parameter schemas in command priority order only while
    # they fit. Command names remain available even when an adversarial schema is
    # too large to include.
    for index, source in enumerate(command_sources):
        schema = _schema_projection(source.get("parameters_schema"))
        if not schema:
            continue
        compacted["proposable_commands"][index]["parameters_schema"] = schema
        if _json_size_bytes(compacted) > payload_limit:
            compacted["proposable_commands"][index].pop("parameters_schema", None)

    # Fixed-width projections above should already fit comfortably. This final
    # deterministic safety valve makes the byte ceiling an invariant even if new
    # fields or unusually wide UTF-8 values are introduced later.
    if _json_size_bytes(compacted) > payload_limit:
        for item in reversed(compacted["proposable_commands"]):
            item.pop("parameters_schema", None)
            item.pop("description", None)
            if _json_size_bytes(compacted) <= payload_limit:
                break
    while _json_size_bytes(compacted) > payload_limit and compacted["proposable_commands"]:
        compacted["proposable_commands"].pop()
    while _json_size_bytes(compacted) > payload_limit and len(compacted["recent_actions"]) > 1:
        compacted["recent_actions"].pop()
    if _json_size_bytes(compacted) > payload_limit:
        compacted["mission"].pop("allowed_commands", None)
        compacted["focus"] = _scalars(
            compacted.get("focus"),
            (
                "type", "id", "target_id", "status", "family", "last_verification_verdict",
                "latest_retest_id", "latest_retest_status", "latest_retest_verdict",
            ),
            text_limit=160,
        )
    if _json_size_bytes(compacted) > payload_limit:
        # All remaining values are fixed-width identity, verdict, budget, and action
        # digests. A programming error is preferable to persisting an oversized pack.
        raise ValueError("research observation compaction exceeded the 48 KiB byte limit")
    return compacted


def _research_graph_with_preflight_provenance(
    graph: dict[str, Any], *, preflight_scan_id: str, provenance_scan_ids: set[str],
) -> dict[str, Any]:
    """Annotate a graph without discarding historical or parallel-shard intelligence."""
    nodes = [item for item in graph.get("nodes") or [] if isinstance(item, dict)]
    edges = [item for item in graph.get("edges") or [] if isinstance(item, dict)]
    return {
        **graph,
        # Provenance is an annotation, not a destructive filter; parallel parents commonly persist
        # graph records under child shard scan ids, while older scans remain useful hypothesis input.
        "provenance_scan_id": preflight_scan_id,
        "preflight_provenance": {
            "scan_ids": sorted(provenance_scan_ids),
            "node_count": sum(
                1 for item in nodes if str(item.get("scan_id") or "") in provenance_scan_ids
            ),
            "edge_count": sum(
                1 for item in edges if str(item.get("scan_id") or "") in provenance_scan_ids
            ),
        },
    }


def _research_family_is_allowed(family: Any, allowed_families: set[str] | list[str]) -> bool:
    allowed = {
        str(item).strip().lower().replace("-", "_").replace(" ", "_")
        for item in allowed_families or []
        if str(item).strip()
    }
    return not allowed or bool(_research_family_scope_keys(family) & allowed)


def _research_action_planner_projection(action: Any) -> dict[str, Any]:
    """Project an action into readable, value-free campaign memory.

    Mechanical dedupe deliberately hashes workflow structure, but those hashes are
    useless to a planner. Preserve the exact operation shape, assertion contract, and
    server-bound variable names while omitting request values and volatile workflow IDs.
    """
    payload = action if isinstance(action, dict) else {}
    command = str(payload.get("command") or "").strip()
    params = payload.get("parameters") if isinstance(payload.get("parameters"), dict) else {}
    if command not in _arsenal_routes._RESEARCH_EXPERIMENT_DEDUPE_COMMANDS:
        projected_params = {
            key: params.get(key)
            for key in (
                "check_family", "finding_id", "endpoint_filter", "batch_size", "stale_days",
                "exploit_depth", "mode", "scan_type", "route", "method",
            )
            if params.get(key) not in (None, "", [], {})
        }
        return {"command": command, "parameters": projected_params}

    operations: list[dict[str, Any]] = []
    for step in params.get("steps") or []:
        if not isinstance(step, dict):
            continue
        operation = {
            "label": str(step.get("label") or step.get("id") or "")[:80] or None,
            "method": str(step.get("method") or "GET").upper()[:12],
            "route": _arsenal_routes._canonical_vulnerability_route(step.get("path") or step.get("route")),
            "principal": str(step.get("principal") or step.get("role") or "")[:80] or None,
            "checkpoint": str(step.get("checkpoint") or "")[:40] or None,
            "query_keys": sorted(str(key)[:80] for key in (step.get("query") or {}).keys())
            if isinstance(step.get("query"), dict) else [],
            "body_fields": sorted({
                str(key)[:80]
                for body_key in ("json_body", "form_body")
                for key in ((step.get(body_key) or {}).keys() if isinstance(step.get(body_key), dict) else [])
            }),
        }
        operations.append({key: value for key, value in operation.items() if value not in (None, "", [], {})})

    assertions = []
    for assertion in params.get("assertions") or []:
        if not isinstance(assertion, dict):
            continue
        projected = {
            key: assertion.get(key)
            for key in ("type", "predicate", "step", "control", "candidate", "steps")
            if assertion.get(key) not in (None, "", [], {})
        }
        if projected:
            assertions.append(projected)

    principal_variables = [
        {
            key: item.get(key)
            for key in ("name", "principal", "ref")
            if item.get(key) not in (None, "")
        }
        for item in params.get("principal_variables") or []
        if isinstance(item, dict)
    ]
    projected_params: dict[str, Any] = {
        "proof_family": str(params.get("proof_family") or params.get("family") or "").strip().lower(),
        "steps": operations[:8],
        "assertions": assertions[:16],
        "principal_variables": principal_variables[:8],
    }
    return {
        "command": command,
        "parameters": {
            key: value for key, value in projected_params.items()
            if value not in (None, "", [], {})
        },
    }
def _research_autonomous_parameter_schema(
    name: str,
    schema: dict[str, Any],
    *,
    allow_cleanup_safe_writes: bool = False,
) -> dict[str, Any]:
    projected = copy.deepcopy(schema)
    if name not in {"experiment.http_diff", "experiment.workflow"}:
        return projected

    def constrain_methods(value: Any) -> None:
        if isinstance(value, dict):
            enum = value.get("enum")
            if isinstance(enum, list) and any(
                str(item).upper() in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
                for item in enum
            ):
                forbidden = (
                    {"POST", "PUT", "PATCH", "DELETE"}
                    if name == "experiment.http_diff" else
                    {"PUT", "PATCH", "DELETE"}
                )
                value["enum"] = [item for item in enum if str(item).upper() not in forbidden]
            for nested in value.values():
                constrain_methods(nested)
        elif isinstance(value, list):
            for nested in value:
                constrain_methods(nested)

    if not (name == "experiment.workflow" and allow_cleanup_safe_writes):
        constrain_methods(projected)
    return projected




def _research_experiment_projection(source: Any) -> dict[str, Any]:
    """Keep experiment conclusions and receipts, never response bodies or credentials."""
    payload = source if isinstance(source, dict) else {}
    experiment = payload.get("experiment") if isinstance(payload.get("experiment"), dict) else {}
    if not experiment and isinstance(payload.get("workflow"), dict):
        experiment = payload["workflow"]
    observations: list[dict[str, Any]] = []
    for item in list(experiment.get("observations") or [])[:16]:
        if not isinstance(item, dict):
            continue
        request = item.get("request") if isinstance(item.get("request"), dict) else {}
        response = item.get("response") if isinstance(item.get("response"), dict) else {}
        projected = {
            key: item.get(key)
            for key in ("label", "kind", "principal", "checkpoint", "success", "error")
            if item.get(key) not in (None, "", [], {})
        }
        for key, value in {
            "method": request.get("method"),
            "path": request.get("path"),
            "status": response.get("status") or item.get("status"),
        }.items():
            if value not in (None, ""):
                projected[key] = value
        if projected:
            observations.append(projected)
    projection = {
        key: experiment.get(key)
        for key in (
            "version", "objective", "expected_signal", "falsifier", "step_count",
            "request_count", "cancelled", "principal_receipts",
            "principal_variable_receipts", "comparisons",
        )
        if experiment.get(key) not in (None, "", [], {})
    }
    if observations:
        projection["observations"] = observations
    for key in (
        "workflow_id", "evidence_instance_id", "tool_receipt_id", "proof_state",
        "findings_created", "verified_findings_created", "family_proof", "promotion",
    ):
        if payload.get(key) not in (None, "", [], {}):
            projection[key] = payload.get(key)
    return _arsenal_routes._bounded_research_payload(projection)


def _research_read_result_projection(source: Any, *, depth: int = 0) -> Any:
    """Keep enough durable read evidence for a later planner turn to reason from.

    Read adapters can return large scans, graphs, or finding collections. Persist the
    redacted result once, then give observations a smaller deterministic projection so
    a useful sample survives the global observation byte cap.
    """
    if depth > 5:
        return "[truncated]"
    bounded = _arsenal_routes._bounded_research_payload(source)
    if isinstance(bounded, dict):
        return {
            str(key)[:120]: _research_read_result_projection(value, depth=depth + 1)
            for key, value in list(bounded.items())[:40]
        }
    if isinstance(bounded, list):
        return [_research_read_result_projection(item, depth=depth + 1) for item in bounded[:25]]
    if isinstance(bounded, str):
        return bounded[:1200]
    return bounded


def _research_family_scope_keys(family: Any) -> set[str]:
    """Return campaign-scope names equivalent to a proof/hypothesis family.

    Campaign launch intentionally exposes the four public DAST families while
    deterministic workflow proof uses canonical names such as ``auth_bypass``
    and ``injection``.  Keep that translation in one fail-closed predicate so
    context selection and execution policy cannot drift apart.
    """
    raw = str(family or "").strip().lower().replace("-", "_").replace(" ", "_")
    canonical = family_proof.canonical_family(raw)
    keys = {raw, canonical}
    if canonical == "auth_bypass" or raw == "auth":
        keys.add("auth")
    if canonical == "injection":
        keys.update({"sqli", "xss"})
    if canonical == "bola":
        keys.update({"bola", "idor"})
    return {key for key in keys if key}








@router.post("/experiments/workflows/{workflow_id}/cancel")
async def cancel_workflow_experiment(workflow_id: str):
    workflow_uuid = _uuid_or_400(workflow_id, "workflow id")
    event = _active_workflow_cancellations.get(str(workflow_uuid))
    if not event:
        raise HTTPException(status_code=404, detail="Active workflow not found")
    event.set()
    return {"workflow_id": str(workflow_uuid), "cancel_requested": True, "finding_created": False}
