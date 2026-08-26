"""Command Arsenal routes.

Extracted verbatim from the api.py monolith. The Arsenal is the operator-facing
command plane: command/contract catalogs, scope previews and approval receipts,
operation plans, command results, campaigns and campaign actions, the hypothesis
lifecycle, refuter reviews, tool receipts, agent context packs, and decision
traces.

The Arsenal is a DISPATCHER: ``/arsenal/execute`` and the campaign-action routes
fan out into product domains that still live in api.py (evidence retention, the
local-agent surface, the authz replay, the workflow experiments). Those targets
are deliberately NOT absorbed here -- they are injected by the composition root
as lazily-resolved callables so each keeps its own home, and so the later
per-domain extractions do not have to claw code back out of this module.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
import fnmatch
import secrets
from urllib.parse import urlparse
import asyncio
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import time
from typing import Any, Callable, Optional, Sequence
import urllib.parse
import uuid

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

try:
    import adjudicate
    import asm_inventory
    import check_registry
    import family_proof
    import hypothesis_lifecycle
    import hypothesis_scheduler
    import invariant_contracts
    from command_arsenal import (
        describe_commands as describe_arsenal_commands,
        describe_contracts as describe_arsenal_contracts,
        describe_tools as describe_arsenal_tools,
        validate_command_parameters as _validate_command_parameters,
    )
    from redaction import redact_sensitive
    from research_agent import canonical_hash as _research_canonical_hash
except ModuleNotFoundError:  # package import in host-side tests
    from .. import (
        adjudicate,
        asm_inventory,
        check_registry,
        family_proof,
        hypothesis_lifecycle,
        hypothesis_scheduler,
        invariant_contracts,
    )
    from ..command_arsenal import (
        describe_commands as describe_arsenal_commands,
        describe_contracts as describe_arsenal_contracts,
        describe_tools as describe_arsenal_tools,
        validate_command_parameters as _validate_command_parameters,
    )
    from ..redaction import redact_sensitive
    from ..research_agent import canonical_hash as _research_canonical_hash


try:
    from evidence_routes.router import EvidenceInstanceRequest, _validate_evidence_retention_preview_payload
    from action_scope import _decode_json_value, evaluate_scope, receipt_to_dict
    from api_utils import LEGACY_SCAN_WRITE_FIELDS, _ARSENAL_CREATED_BY_CONTEXT, _clean_string_list, _int_or_none, _json_safe_row, _optional_uuid, _uuid_or_400, utc_now, utc_now_iso
    from http_experiment import ExperimentContractError, execute_experiment
    from request_models import HypothesisRequest, ScanAdvancedLimits, ScanOptions
    from research_agent import RISK_TIER_ORDER
    from retest_contract import infer_type_from_title_tool
    from serialization import row_to_dict
    from workflow_experiment import WorkflowContractError, normalize_workflow, validate_principal_contexts
    from ai_targets import router as _ai_targets
    from exposure import router as _exposure
    from finding_exceptions import router as _finding_exceptions
    from finding_routes import router as _finding_routes
    from model_intake import router as _model_intake
    from operations import router as _operations
    from targets import router as _targets
except ModuleNotFoundError:  # package import in host-side tests
    from ..evidence_routes.router import EvidenceInstanceRequest, _validate_evidence_retention_preview_payload
    from ..action_scope import _decode_json_value, evaluate_scope, receipt_to_dict
    from ..api_utils import LEGACY_SCAN_WRITE_FIELDS, _ARSENAL_CREATED_BY_CONTEXT, _clean_string_list, _int_or_none, _json_safe_row, _optional_uuid, _uuid_or_400, utc_now, utc_now_iso
    from ..http_experiment import ExperimentContractError, execute_experiment
    from ..request_models import HypothesisRequest, ScanAdvancedLimits, ScanOptions
    from ..research_agent import RISK_TIER_ORDER
    from ..retest_contract import infer_type_from_title_tool
    from ..serialization import row_to_dict
    from ..workflow_experiment import WorkflowContractError, normalize_workflow, validate_principal_contexts
    from ..ai_targets import router as _ai_targets
    from ..exposure import router as _exposure
    from ..finding_exceptions import router as _finding_exceptions
    from ..finding_routes import router as _finding_routes
    from ..model_intake import router as _model_intake
    from ..operations import router as _operations
    from ..targets import router as _targets


router = APIRouter()

_pool_provider: Callable[[], Any] | None = None
_deps: dict[str, Callable[..., Any]] = {}


SOURCE_INGEST_VERSION = "source_ingest_hypothesis_v1"
REFUTER_FINDING_DELTA_MIN_BASELINE = 2   # need at least this many prior scans for a baseline
RESEARCH_SURFACE_MIN_EXECUTABLE_ROUTES = 1
SOURCE_INGEST_DEFAULT_IGNORED_PATHS = (
    ".git/",
    "node_modules/",
    "vendor/",
    "dist/",
    "build/",
    "coverage/",
    "__pycache__/",
)
SOURCE_INGEST_HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
PLANNER_HYPOTHESIS_VERSION = "planner_action_hypothesis_v1"
BENCHMARK_HYPOTHESIS_VERSION = "benchmark_followup_hypothesis_v1"
BENCHMARK_FAMILY_CWE = {
    "sqli": "CWE-89",
    "nosqli": "CWE-943",
    "xss": "CWE-79",
    "bola": "CWE-639",
    "broken_access_control": "CWE-285",
    "sensitive_exposure": "CWE-200",
    "path_traversal": "CWE-22",
    "jwt": "CWE-347",
}
BENCHMARK_PROOF_SURFACE = {
    "browser": "browser_runtime_probe",
    "verified": "runtime_probe",
    "deterministic": "runtime_probe",
}
REFUTER_VERDICT_BASES = {"deterministic_replay", "cryptographic", "parser_protocol", "human_approved_review"}
RESEARCH_SURFACE_MIN_UNIQUE_ROUTES = 20
RESEARCH_SURFACE_MIN_AUTHENTICATED_ROUTES = 5
REFUTER_FINDING_DELTA_MIN_ABSOLUTE = 5   # latest must exceed baseline median by at least this
REFUTER_FINDING_DELTA_MULTIPLIER = 2.0   # and (for non-zero baselines) be at least this many x
REFUTER_BENCHMARK_DELTA_MIN_BASELINE = 2
REFUTER_BENCHMARK_RECALL_DELTA = 0.25
REFUTER_BENCHMARK_VERIFIED_DELTA = 2
_RESEARCH_EXPERIMENT_DEDUPE_COMMANDS = {"experiment.http_diff", "experiment.workflow"}





def configure_arsenal_router(
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

def _results_dir() -> Any:
    return _dep("results_dir")()

def EvidenceRetentionSweepRequest(*a: Any, **k: Any) -> Any:
    return _get("EvidenceRetentionSweepRequest")(*a, **k)

def LocalAgentPlanParseRequest(*a: Any, **k: Any) -> Any:
    return _get("LocalAgentPlanParseRequest")(*a, **k)

def LocalAgentPlanRequest(*a: Any, **k: Any) -> Any:
    return _get("LocalAgentPlanRequest")(*a, **k)

def LocalAgentTestRequest(*a: Any, **k: Any) -> Any:
    return _get("LocalAgentTestRequest")(*a, **k)

def _ai_ops_execute_enabled(*a: Any, **k: Any) -> Any:
    return _get("_ai_ops_execute_enabled")(*a, **k)

def _arsenal_action_state(*a: Any, **k: Any) -> Any:
    return _get("_arsenal_action_state")(*a, **k)

def _bounded_research_payload(*a: Any, **k: Any) -> Any:
    return _get("_bounded_research_payload")(*a, **k)

def _canonical_vulnerability_key(*a: Any, **k: Any) -> Any:
    return _get("_canonical_vulnerability_key")(*a, **k)

def _canonical_vulnerability_route(*a: Any, **k: Any) -> Any:
    return _get("_canonical_vulnerability_route")(*a, **k)

def _contains_forbidden_context_key(*a: Any, **k: Any) -> Any:
    return _get("_contains_forbidden_context_key")(*a, **k)

def _evidence_retention_preview_payload(*a: Any, **k: Any) -> Any:
    return _get("_evidence_retention_preview_payload")(*a, **k)

async def _execute_authz_replay_plan(*a: Any, **k: Any) -> Any:
    return await _get("_execute_authz_replay_plan")(*a, **k)

async def _execute_workflow_runtime(*a: Any, **k: Any) -> Any:
    return await _get("_execute_workflow_runtime")(*a, **k)

def _inject_create_mass_assignment_credentials(*a: Any, **k: Any) -> Any:
    return _get("_inject_create_mass_assignment_credentials")(*a, **k)

async def _link_command_result_to_campaign(*a: Any, **k: Any) -> Any:
    return await _get("_link_command_result_to_campaign")(*a, **k)

async def _link_command_result_to_campaign_action(*a: Any, **k: Any) -> Any:
    return await _get("_link_command_result_to_campaign_action")(*a, **k)

def _median(*a: Any, **k: Any) -> Any:
    return _get("_median")(*a, **k)

def _normalize_hypothesis_dedupe_value(*a: Any, **k: Any) -> Any:
    return _get("_normalize_hypothesis_dedupe_value")(*a, **k)

def _parse_hypothesis_time(*a: Any, **k: Any) -> Any:
    return _get("_parse_hypothesis_time")(*a, **k)

async def _promote_authz_replay_finding(*a: Any, **k: Any) -> Any:
    return await _get("_promote_authz_replay_finding")(*a, **k)

async def _promote_trusted_workflow_finding(*a: Any, **k: Any) -> Any:
    return await _get("_promote_trusted_workflow_finding")(*a, **k)

def _public_campaign_action_row(*a: Any, **k: Any) -> Any:
    return _get("_public_campaign_action_row")(*a, **k)

def _public_campaign_row(*a: Any, **k: Any) -> Any:
    return _get("_public_campaign_row")(*a, **k)

def _public_hypothesis_row(*a: Any, **k: Any) -> Any:
    return _get("_public_hypothesis_row")(*a, **k)

async def _record_blocked_command_result(*a: Any, **k: Any) -> Any:
    return await _get("_record_blocked_command_result")(*a, **k)

async def _record_command_result(*a: Any, **k: Any) -> Any:
    return await _get("_record_command_result")(*a, **k)

async def _record_evidence_instance(*a: Any, **k: Any) -> Any:
    return await _get("_record_evidence_instance")(*a, **k)

async def _record_tool_receipt(*a: Any, **k: Any) -> Any:
    return await _get("_record_tool_receipt")(*a, **k)

def _redact_agent_payload(*a: Any, **k: Any) -> Any:
    return _get("_redact_agent_payload")(*a, **k)

def _redact_agent_text(*a: Any, **k: Any) -> Any:
    return _get("_redact_agent_text")(*a, **k)

async def _research_campaign_budget_snapshot(*a: Any, **k: Any) -> Any:
    return await _get("_research_campaign_budget_snapshot")(*a, **k)

def _research_finding_family(*a: Any, **k: Any) -> Any:
    return _get("_research_finding_family")(*a, **k)

def _research_vulnerability_dimensions(*a: Any, **k: Any) -> Any:
    return _get("_research_vulnerability_dimensions")(*a, **k)

async def _resolve_workflow_principal_contexts(*a: Any, **k: Any) -> Any:
    return await _get("_resolve_workflow_principal_contexts")(*a, **k)

def _sanitize_scan_options(*a: Any, **k: Any) -> Any:
    return _get("_sanitize_scan_options")(*a, **k)

async def _server_materialize_create_ma(*a: Any, **k: Any) -> Any:
    return await _get("_server_materialize_create_ma")(*a, **k)

async def _submit_scan(*a: Any, **k: Any) -> Any:
    return await _get("_submit_scan")(*a, **k)

def _trusted_workflow_family_proof(*a: Any, **k: Any) -> Any:
    return _get("_trusted_workflow_family_proof")(*a, **k)

async def _upsert_hypothesis(*a: Any, **k: Any) -> Any:
    return await _get("_upsert_hypothesis")(*a, **k)

async def _validate_approval_receipt_for_action(*a: Any, **k: Any) -> Any:
    return await _get("_validate_approval_receipt_for_action")(*a, **k)

async def evidence_export_bundle(*a: Any, **k: Any) -> Any:
    return await _get("evidence_export_bundle")(*a, **k)

async def evidence_export_manifest(*a: Any, **k: Any) -> Any:
    return await _get("evidence_export_manifest")(*a, **k)

async def evidence_retention_sweep(*a: Any, **k: Any) -> Any:
    return await _get("evidence_retention_sweep")(*a, **k)

async def get_evidence_object(*a: Any, **k: Any) -> Any:
    return await _get("get_evidence_object")(*a, **k)

def get_redis(*a: Any, **k: Any) -> Any:
    return _get("get_redis")(*a, **k)

async def get_scan_deployment_decision(*a: Any, **k: Any) -> Any:
    return await _get("get_scan_deployment_decision")(*a, **k)

async def get_scan_result(*a: Any, **k: Any) -> Any:
    return await _get("get_scan_result")(*a, **k)

async def list_evidence_instances(*a: Any, **k: Any) -> Any:
    return await _get("list_evidence_instances")(*a, **k)

async def local_agent_dry_run_plan(*a: Any, **k: Any) -> Any:
    return await _get("local_agent_dry_run_plan")(*a, **k)

async def local_agent_parse_candidate_plan(*a: Any, **k: Any) -> Any:
    return await _get("local_agent_parse_candidate_plan")(*a, **k)

async def local_agent_test(*a: Any, **k: Any) -> Any:
    return await _get("local_agent_test")(*a, **k)

async def local_agents(*a: Any, **k: Any) -> Any:
    return await _get("local_agents")(*a, **k)

async def record_evidence_instance(*a: Any, **k: Any) -> Any:
    return await _get("record_evidence_instance")(*a, **k)

__all__ = ["configure_arsenal_router", "router"]
@router.get("/arsenal/commands")
async def arsenal_commands():
    """Read-only Command Arsenal schema for UI, REST clients, AI Ops, and future MCP."""
    return describe_arsenal_commands()


@router.get("/arsenal/contracts")
async def arsenal_contracts():
    """Read-only mission, context, trace, receipt, hypothesis, and evidence-instance contracts."""
    return describe_arsenal_contracts()


@router.post("/arsenal/scope/preview")
async def arsenal_scope_preview(req: ScopePreviewRequest):
    """Validate and persist a scope receipt preview without queueing or executing work."""
    target_uuid = None
    if req.target_id:
        try:
            target_uuid = uuid.UUID(str(req.target_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="target_id must be a UUID when supplied")
    receipt = evaluate_scope(
        req.url,
        allowed_hosts=req.allowed_hosts,
        allowed_root_domains=req.allowed_root_domains,
        environment=req.environment,
        redirect_urls=req.redirect_urls,
        target_id=str(target_uuid) if target_uuid else None,
    )
    payload = receipt_to_dict(receipt)
    async with _pool().acquire() as conn:
        await conn.execute(
            """
            INSERT INTO scope_receipts
                (id, target_id, input_scope, normalized_scope, verdict, blocked_by, warnings,
                 checks, environment, allowed_hosts, allowed_root_domains, redirect_destinations)
            VALUES ($1,$2,$3::jsonb,$4::jsonb,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9,$10::jsonb,$11::jsonb,$12::jsonb)
            ON CONFLICT (id) DO UPDATE SET
                target_id = EXCLUDED.target_id,
                input_scope = EXCLUDED.input_scope,
                normalized_scope = EXCLUDED.normalized_scope,
                verdict = EXCLUDED.verdict,
                blocked_by = EXCLUDED.blocked_by,
                warnings = EXCLUDED.warnings,
                checks = EXCLUDED.checks,
                environment = EXCLUDED.environment,
                allowed_hosts = EXCLUDED.allowed_hosts,
                allowed_root_domains = EXCLUDED.allowed_root_domains,
                redirect_destinations = EXCLUDED.redirect_destinations,
                created_at = NOW()
            """,
            payload["receipt_id"],
            target_uuid,
            json.dumps(payload["input_scope"]),
            json.dumps(payload["normalized_scope"]),
            payload["verdict"],
            json.dumps(payload["blocked_by"]),
            json.dumps(payload["warnings"]),
            json.dumps(payload["checks"]),
            payload["environment"],
            json.dumps(payload["allowed_hosts"]),
            json.dumps(payload["allowed_root_domains"]),
            json.dumps(payload["redirect_destinations"]),
        )
    return {"scope_receipt": payload, "persisted": True, "execution_enabled": False}


@router.post("/arsenal/approvals")
async def arsenal_create_approval(req: ApprovalReceiptRequest):
    """Persist an approval or denial receipt for an existing scope receipt without executing work."""
    approved_by = str(req.approved_by or "").strip() or None
    denial_reason = str(req.denial_reason or "").strip() or None
    if bool(approved_by) == bool(denial_reason):
        raise HTTPException(status_code=400, detail="Provide exactly one of approved_by or denial_reason")

    confirmations = [str(item).strip() for item in req.confirmations if str(item).strip()]
    if approved_by and "confirm_authorized" not in confirmations:
        raise HTTPException(status_code=400, detail="confirm_authorized is required for approval receipts")

    async with _pool().acquire() as conn:
        scope_row = await conn.fetchrow("SELECT * FROM scope_receipts WHERE id=$1", req.scope_receipt_id)
        if not scope_row:
            raise HTTPException(status_code=404, detail="Scope receipt not found")
        scope = _public_scope_receipt_row(scope_row)
        if approved_by and scope.get("verdict") == "blocked":
            raise HTTPException(status_code=400, detail="Blocked scope receipts cannot be approved")
        if approved_by and scope.get("verdict") == "needs_approval" and "confirm_scope_reviewed" not in confirmations:
            raise HTTPException(status_code=400, detail="confirm_scope_reviewed is required for needs_approval scope receipts")
        action_name = str(req.action_name or "").strip() or None
        action_context = dict(req.action_context or {})
        stored_expires_at = req.expires_at
        if action_name == "evidence.retention_sweep":
            if not approved_by:
                raise HTTPException(status_code=400, detail="Retention preview bindings are only valid on approvals")
            if req.risk_tier != "dangerous":
                raise HTTPException(status_code=400, detail="Evidence deletion approval requires dangerous risk tier")
            try:
                preview_uuid = uuid.UUID(str(action_context.get("preview_id") or ""))
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="Retention approval requires a valid preview_id") from exc
            preview_row = await conn.fetchrow(
                "SELECT * FROM evidence_retention_previews WHERE id=$1",
                preview_uuid,
            )
            if not preview_row:
                raise HTTPException(status_code=404, detail="Retention preview not found")
            preview = _evidence_retention_preview_payload(preview_row)
            _validate_evidence_retention_preview_payload(preview)
            expected_context = {
                "preview_id": preview["preview_id"],
                "preview_hash": preview["preview_hash"],
                "target_id": preview["target_id"],
            }
            if any(str(action_context.get(key) or "") != str(value) for key, value in expected_context.items()):
                raise HTTPException(status_code=400, detail="Retention approval context does not match the preview")
            if str(scope.get("target_id") or "") != preview["target_id"]:
                raise HTTPException(status_code=400, detail="Retention approval scope must match the preview target")
            expires_at = _parse_hypothesis_time(req.expires_at)
            preview_expires_at = _parse_hypothesis_time(preview.get("expires_at"))
            now = datetime.now(timezone.utc)
            if not expires_at or not preview_expires_at or expires_at <= now or expires_at > preview_expires_at:
                raise HTTPException(
                    status_code=400,
                    detail="Retention approval must expire no later than the bound preview",
                )
            action_context = expected_context
            stored_expires_at = expires_at
        row = await conn.fetchrow(
            """
            INSERT INTO approval_receipts
                (scope_receipt_id, risk_tier, confirmations, action_name, action_context,
                 approved_by, denial_reason, expires_at)
            VALUES ($1,$2,$3::jsonb,$4,$5::jsonb,$6,$7,$8)
            RETURNING *
            """,
            req.scope_receipt_id,
            req.risk_tier,
            json.dumps(confirmations),
            action_name,
            json.dumps(action_context, sort_keys=True),
            approved_by,
            denial_reason,
            stored_expires_at,
        )
    return {
        "approval_receipt": _public_approval_receipt_row(row),
        "scope_receipt": scope,
        "execution_enabled": False,
    }


@router.post("/arsenal/approvals/{approval_receipt_id}/revoke")
async def arsenal_revoke_approval(
    approval_receipt_id: str,
    req: ApprovalReceiptRevocationRequest,
):
    """Irreversibly revoke reusable target-bound authority without executing work."""
    approval_uuid = _uuid_or_400(approval_receipt_id, "approval receipt id")
    revoked_by = req.revoked_by.strip()
    reason = req.reason.strip()
    async with _pool().acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE approval_receipts
            SET status='revoked', revoked_at=NOW(), revoked_by=$2,
                revocation_reason=$3
            WHERE id=$1 AND status='active' AND approved_by IS NOT NULL
            RETURNING *
            """,
            approval_uuid,
            revoked_by,
            reason,
        )
        if row is None:
            row = await conn.fetchrow(
                "SELECT * FROM approval_receipts WHERE id=$1",
                approval_uuid,
            )
            if row is None:
                raise HTTPException(status_code=404, detail="Approval receipt not found")
            public = _public_approval_receipt_row(row)
            if public.get("status") != "revoked":
                raise HTTPException(
                    status_code=409,
                    detail="Only active approval receipts can be revoked",
                )
        public = _public_approval_receipt_row(row)
    return {
        "approval_receipt": public,
        "revoked": True,
        "execution_enabled": False,
    }


@router.post("/arsenal/plans")
async def arsenal_create_operation_plan(req: OperationPlanRequest):
    """Validate and persist a dry-run OperationPlan without executing any action."""
    async with _pool().acquire() as conn:
        return await _persist_operation_plan(conn, req)


@router.get("/arsenal/plans")
async def arsenal_operation_plans(limit: int = Query(20, ge=1, le=100)):
    """Read recent dry-run OperationPlan records."""
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT * FROM operation_plans
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
        )
    return {
        "operation_plans": [_public_operation_plan_row(row) for row in rows],
        "execution_enabled": False,
        "count": len(rows),
    }


@router.get("/arsenal/command-results")
async def arsenal_command_results(limit: int = Query(20, ge=1, le=100)):
    """Read recent Command Arsenal audit records for queued/blocked product actions."""
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT *
            FROM command_results
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
        )
    return {
        "command_results": [_public_command_result_row(row) for row in rows],
        "execution_enabled": False,
        "count": len(rows),
    }


@router.get("/arsenal/campaign-actions")
async def arsenal_campaign_actions(
    limit: int = Query(20, ge=1, le=100),
    target_id: Optional[str] = Query(None, description="Filter actions to one target."),
):
    """Read recent campaign/action execution audit records.

    These rows are action ledger entries only. They do not prove findings and
    they do not execute anything; state-changing work still flows through the
    existing product routes and receipt gates.
    """
    target_uuid = None
    if target_id:
        try:
            target_uuid = uuid.UUID(str(target_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="target_id must be a UUID")
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT ca.*,
                   s.status AS scan_status,
                   s.target_url AS scan_target_url,
                   s.target_id AS scan_target_id
            FROM campaign_actions ca
            LEFT JOIN scans s ON ca.scan_id = s.id
            WHERE ($2::uuid IS NULL OR ca.target_id = $2 OR s.target_id = $2)
            ORDER BY ca.created_at DESC
            LIMIT $1
            """,
            limit,
            target_uuid,
        )
    actions = []
    for row in rows:
        action = _public_campaign_action_row(row)
        if action.get("scan_status"):
            action["live_scan_status"] = _operations._timeline_scan_status(action.get("scan_status"))
        if not action.get("target_id") and action.get("scan_target_id"):
            action["target_id"] = action.get("scan_target_id")
        if not action.get("target_url") and action.get("scan_target_url"):
            action["target_url"] = action.get("scan_target_url")
        actions.append(action)
    return {
        "campaign_actions": actions,
        "execution_enabled": False,
        "count": len(actions),
    }


@router.post("/arsenal/campaign-actions/{campaign_action_id}/authz-replay")
async def arsenal_execute_authz_replay(
    campaign_action_id: str,
    req: AuthzReplayExecuteRequest,
):
    """Execute a planned authz replay through the gated Arsenal dispatcher."""
    return await _arsenal_execute_detached(ArsenalExecuteRequest(
        command="authz.replay_plan",
        parameters={
            "campaign_action_id": campaign_action_id,
            "session_id": req.session_id,
            "created_by": req.created_by,
        },
        execute=req.execute,
        confirmations=req.confirmations,
        approval_receipt_id=req.approval_receipt_id,
        created_by=req.created_by,
        campaign_action_id=campaign_action_id,
    ))


@router.post("/arsenal/campaign-actions/{campaign_action_id}/authz-promote")
async def arsenal_promote_authz_replay(
    campaign_action_id: str,
    req: AuthzReplayPromoteRequest,
):
    """Explicitly promote a reviewed authz replay through the same receipt gate."""
    return await _arsenal_execute_detached(ArsenalExecuteRequest(
        command="authz.promote_replay_finding",
        parameters={
            "campaign_action_id": campaign_action_id,
            "created_by": req.created_by,
        },
        execute=req.execute,
        confirmations=req.confirmations,
        approval_receipt_id=req.approval_receipt_id,
        created_by=req.created_by,
        campaign_action_id=campaign_action_id,
    ))


@router.post("/arsenal/campaigns")
async def arsenal_create_campaign(req: CampaignRequest):
    """Create a mission campaign record. No work is queued and no finding is created."""
    async with _pool().acquire() as conn:
        campaign = await _persist_campaign(conn, req)
    return {"campaign": campaign, "execution_enabled": False}


@router.get("/arsenal/campaigns")
async def arsenal_campaigns(
    limit: int = Query(20, ge=1, le=100),
    target_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """Read recent mission campaign records."""
    target_uuid = None
    if target_id:
        try:
            target_uuid = uuid.UUID(str(target_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="target_id must be a UUID")
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT * FROM campaigns
            WHERE ($2::uuid IS NULL OR target_id = $2)
              AND ($3::text IS NULL OR status = $3)
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
            target_uuid,
            status,
        )
        campaign_ids = [row["id"] for row in rows]
        live_impact = await _campaign_live_finding_impact(conn, campaign_ids)
    campaigns = []
    for row in rows:
        campaign = _public_campaign_row(row)
        campaign["deployment_impact"] = live_impact.get(row["id"], _campaign_deployment_impact([]))
        campaigns.append(campaign)
    return {
        "campaigns": campaigns,
        "execution_enabled": False,
        "count": len(rows),
    }


@router.get("/arsenal/campaigns/{campaign_id}")
async def arsenal_campaign_detail(campaign_id: str, action_limit: int = Query(50, ge=1, le=200)):
    """Read one campaign plus a rollup of its linked action ledger and finding impact."""
    try:
        campaign_uuid = uuid.UUID(str(campaign_id))
    except ValueError:
        raise HTTPException(status_code=400, detail="campaign_id must be a UUID")
    async with _pool().acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM campaigns WHERE id=$1", campaign_uuid)
        if not row:
            raise HTTPException(status_code=404, detail="Campaign not found")
        total_action_count = int(await conn.fetchval(
            "SELECT COUNT(*) FROM campaign_actions WHERE mission_campaign_id = $1",
            campaign_uuid,
        ) or 0)
        action_rows = await conn.fetch(
            """
            SELECT ca.*, s.status AS linked_scan_status
            FROM campaign_actions ca
            LEFT JOIN scans s ON s.id = ca.scan_id
            WHERE ca.mission_campaign_id = $1
            ORDER BY ca.created_at DESC
            LIMIT $2
            """,
            campaign_uuid,
            action_limit,
        )
        actions = []
        for action_row in action_rows:
            action_data = row_to_dict(action_row)
            linked_scan_status = action_data.pop("linked_scan_status", None)
            action = _public_campaign_action_row(action_data)
            action["status"] = _campaign_action_effective_status(
                action.get("status"), linked_scan_status,
            )
            actions.append(action)
        impact_by_campaign = await _campaign_live_finding_impact(conn, [campaign_uuid])
        status_rows = await conn.fetch(
            """
            SELECT effective_status AS status, COUNT(*) AS count
            FROM (
                SELECT CASE
                    WHEN ca.status IN ('planned','approved','queued','running','retest_scheduled')
                     AND s.status IN ('completed','failed','cancelled','partial')
                    THEN s.status
                    ELSE COALESCE(ca.status, 'unknown')
                END AS effective_status
                FROM campaign_actions ca
                LEFT JOIN scans s ON s.id = ca.scan_id
                WHERE ca.mission_campaign_id = $1
            ) AS effective_actions
            GROUP BY effective_status
            """,
            campaign_uuid,
        )
        research_yield = (
            await _research_campaign_yield_metrics(conn, row)
            if str(row.get("campaign_type") or "") == "autonomous_research"
            else None
        )
        research_readiness = (
            await _research_campaign_readiness(conn, row)
            if str(row.get("campaign_type") or "") == "autonomous_research"
            else None
        )
    status_rollup = {str(item["status"]): int(item["count"]) for item in status_rows}
    deployment_impact = impact_by_campaign.get(campaign_uuid, _campaign_deployment_impact([]))
    campaign = _public_campaign_row(row)
    campaign["deployment_impact"] = deployment_impact
    if research_readiness is not None:
        # Readiness stored in campaign metadata is an audit snapshot from the
        # last supervisor pass.  Overlay the current read-only calculation in
        # the response so paused runs never advertise stale pre-fix coverage.
        metadata = dict(campaign.get("metadata_json") or {})
        research_metadata = dict(metadata.get("autonomous_research") or {})
        research_metadata["readiness"] = research_readiness
        metadata["autonomous_research"] = research_metadata
        campaign["metadata_json"] = metadata
    return {
        "campaign": campaign,
        "actions": actions,
        "action_count": len(actions),
        "total_action_count": total_action_count,
        "status_rollup": status_rollup,
        "deployment_impact": deployment_impact,
        "research_yield": research_yield,
        "research_readiness": research_readiness,
        "execution_enabled": False,
    }


@router.post("/arsenal/campaigns/{campaign_id}/actions")
async def arsenal_link_campaign_action(campaign_id: str, req: CampaignActionLinkRequest):
    """Link an existing command-result/action-ledger row to a mission campaign.

    This is a bookkeeping link only. It does not execute work, change proof state,
    or create findings; it stamps mission_campaign_id onto the existing action row.
    """
    try:
        campaign_uuid = uuid.UUID(str(campaign_id))
    except ValueError:
        raise HTTPException(status_code=400, detail="campaign_id must be a UUID")
    command_result_uuid = _optional_uuid(req.command_result_id)
    campaign_action_uuid = _optional_uuid(req.campaign_action_id)
    if not command_result_uuid and not campaign_action_uuid:
        raise HTTPException(status_code=400, detail="Provide command_result_id or campaign_action_id")
    async with _pool().acquire() as conn:
        if not await conn.fetchval("SELECT 1 FROM campaigns WHERE id=$1", campaign_uuid):
            raise HTTPException(status_code=404, detail="Campaign not found")
        if campaign_action_uuid:
            row = await conn.fetchrow(
                "UPDATE campaign_actions SET mission_campaign_id=$1, updated_at=NOW() WHERE id=$2 RETURNING *",
                campaign_uuid,
                campaign_action_uuid,
            )
        else:
            row = await conn.fetchrow(
                "UPDATE campaign_actions SET mission_campaign_id=$1, updated_at=NOW() WHERE command_result_id=$2 RETURNING *",
                campaign_uuid,
                command_result_uuid,
            )
        if not row:
            raise HTTPException(status_code=404, detail="No matching campaign action to link")
    return {
        "campaign_id": str(campaign_uuid),
        "linked_action": _public_campaign_action_row(row),
        "execution_enabled": False,
    }


@router.post("/arsenal/execute")
async def arsenal_execute(req: ArsenalExecuteRequest):
    """Execute a Command Arsenal product command by name through its existing handler.

    Read-only/dry-run commands dispatch directly. State-changing commands require
    execute=true, their required confirmations, a valid approval receipt, and the gated-execution
    policy (enabled by default); otherwise they dry-run with a recorded blocked/approval_required
    audit row. Raw shell and arbitrary execution are not
    representable — only catalog commands with a wired adapter run.

    Optionally pass campaign_id to link the resulting command_result's campaign
    action to a §7 mission campaign (must already exist); this is a best-effort
    bookkeeping stamp, same as POST /arsenal/campaigns/{campaign_id}/actions.
    """
    return await _arsenal_execute_detached(req)


@router.get("/arsenal/hypotheses")
async def arsenal_hypotheses(
    limit: int = Query(20, ge=1, le=100),
    target_id: Optional[str] = Query(None, description="Filter hypotheses to one target."),
    status: Optional[str] = Query(None, description="Filter by hypothesis status."),
):
    """Read deduped hypotheses/leads. Hypotheses are not findings."""
    target_uuid = None
    if target_id:
        try:
            target_uuid = uuid.UUID(str(target_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="target_id must be a UUID")
    if status and status not in {"open", "claimed", "testing", "supported", "refuted", "blocked", "exhausted", "promoted", "dead"}:
        raise HTTPException(status_code=400, detail="invalid hypothesis status")
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT *
            FROM hypotheses
            WHERE ($2::uuid IS NULL OR target_id = $2)
              AND (
                $3::text IS NULL
                OR status = $3
                OR (
                  $3::text = 'open'
                  AND status IN ('claimed','testing')
                  AND claim_lease_expires_at IS NOT NULL
                  AND claim_lease_expires_at < NOW()
                )
              )
            ORDER BY
              CASE
                WHEN status = 'open' THEN 0
                WHEN status IN ('claimed','testing') AND claim_lease_expires_at < NOW() THEN 0
                WHEN status = 'supported' THEN 1
                WHEN status = 'claimed' THEN 2
                ELSE 3
              END,
              updated_at DESC
            LIMIT $1
            """,
            limit,
            target_uuid,
            status,
        )
    return {
        "hypotheses": [_public_hypothesis_row(row) for row in rows],
        "execution_enabled": False,
        "count": len(rows),
    }


@router.get("/arsenal/hypotheses/schedule")
async def arsenal_schedule_hypotheses(
    target_id: Optional[str] = Query(None, description="Rank actionable hypotheses for one target."),
    limit: int = Query(50, ge=1, le=200),
    remaining_requests: Optional[int] = Query(None, ge=0, description="Defer leads whose request_cost exceeds this."),
    auth_available: bool = Query(False, description="Whether primary auth is available for this target."),
):
    """Deterministic, explainable ranking of actionable hypotheses (Wave 6).

    `priority = impact + boundary_value + novelty + evidence_strength + reachability
    - request_cost - prior_failures - blocker_penalty`. Read-only — schedules and executes nothing;
    terminal/blocked/exhausted leads are excluded and over-budget leads are deferred.
    """
    target_uuid = None
    if target_id:
        try:
            target_uuid = uuid.UUID(str(target_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="target_id must be a UUID")
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM hypotheses WHERE ($1::uuid IS NULL OR target_id = $1) ORDER BY updated_at DESC LIMIT 200",
            target_uuid,
        )
    hyps = [_public_hypothesis_row(row) for row in rows]
    completed = [
        str(h.get("dedupe_key"))
        for h in hyps
        if str(h.get("effective_status") or h.get("status")) in {"refuted", "promoted", "dead", "exhausted"}
        and h.get("dedupe_key")
    ]
    result = hypothesis_scheduler.rank_hypotheses(
        hyps,
        context={
            "completed_dimensions": completed,
            "auth_available": bool(auth_available),
            "remaining_requests": remaining_requests,
        },
    )
    by_id = {str(h.get("id")): h for h in hyps}
    result["scheduled"] = [{**entry, "hypothesis": by_id.get(str(entry["hypothesis_id"]))} for entry in result["scheduled"][:limit]]
    result["execution_enabled"] = False
    return result


@router.get("/arsenal/family-proof/contracts")
async def arsenal_family_proof_contracts():
    """The registry-authoritative family proof contracts (Wave 5). Read-only."""
    return {
        "version": family_proof.FAMILY_PROOF_VERSION,
        "families": family_proof.supported_families(),
        "contracts": family_proof.FAMILY_CONTRACTS,
        "aliases": family_proof.FAMILY_ALIASES,
        "verdicts": sorted(family_proof.VERDICTS),
        "execution_enabled": False,
    }


@router.post("/arsenal/family-proof/evaluate")
async def arsenal_family_proof_evaluate(req: FamilyProofHandoffRequest):
    """Evaluate caller-asserted family evidence as a non-promotable preflight.

    This public endpoint does not execute a verifier, so its booleans are claims rather than proof.
    It records a signal receipt but cannot return ``verified``/``refuted`` or promotable evidence.
    Trusted live handoffs must use the family actuator and promotion gate instead.
    """
    verdict = family_proof.evaluate_claim_preflight(req.family, req.evidence)
    proof_state = {
        "verified": "verified",
        "supported_unverified": "suspected",
        "refuted": "inconclusive",
        "inconclusive": "inconclusive",
        "blocked": "unverified",
    }.get(verdict["verdict"], "unverified")
    strength = "signal"
    target_uuid = _uuid_or_400(req.target_id, "target id") if req.target_id else None
    evidence_id = None
    async with _pool().acquire() as conn:
        async with conn.transaction():
            ev_result = await _record_evidence_instance(conn, EvidenceInstanceRequest(
                target_id=str(target_uuid) if target_uuid else None,
                concrete_url=req.concrete_url,
                principal_pair=req.principals if isinstance(req.principals, dict) else {},
                tool_receipt_id=(req.tool_receipt_ids[0] if req.tool_receipt_ids else None),
                proof_state=proof_state,
                evidence_strength=strength,
                proof_observation={
                    "family": verdict["family"],
                    "cwe": verdict["cwe"],
                    "verdict": verdict["verdict"],
                    "reason": verdict["reason"],
                    "requirements": verdict["requirements"],
                    "met": verdict["met"],
                    "missing": verdict["missing"],
                    "experiment_id": req.experiment_id,
                },
                metadata_json={
                    "family_proof_version": verdict["version"],
                    "evidence_strength": strength,
                    "promotable": verdict["promotable"],
                    "reexecuted_at_handoff": verdict.get("reexecuted_at_handoff"),
                    "trust_boundary": "caller_asserted_preflight",
                    "finding_created": False,
                },
                created_by=req.created_by or "family_proof_handoff",
            ))
            evidence = ev_result.get("evidence_instance") or {}
            evidence_id = str(evidence.get("id")) if evidence.get("id") else None
    return {
        **verdict,
        "proof_state": proof_state,
        "evidence_strength": strength,
        "evidence_instance_id": evidence_id,
        "findings_created": 0,
        "execution_enabled": False,
    }


@router.get("/arsenal/hypotheses/situation-report")
async def arsenal_hypothesis_situation_report(
    limit: int = Query(5, ge=1, le=25),
    target_id: Optional[str] = Query(None, description="Filter report to one target."),
    requester: Optional[str] = Query(None, description="Claim owner/requester to summarize owned work for."),
    include_graph: bool = Query(True, description="Include bounded application-graph context for hypothesis targets."),
):
    """Return bounded hypothesis context without exposing the full board by default."""
    target_uuid = None
    if target_id:
        try:
            target_uuid = uuid.UUID(str(target_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="target_id must be a UUID")
    async with _pool().acquire() as conn:
        return await _targets._load_hypothesis_situation_report(
            conn,
            limit=limit,
            target_uuid=target_uuid,
            requester=requester,
            include_graph=include_graph,
        )


@router.post("/arsenal/hypotheses")
async def arsenal_record_hypothesis(req: HypothesisRequest):
    """Record or endorse a deduped lead without creating or promoting findings."""
    async with _pool().acquire() as conn:
        return await _upsert_hypothesis(conn, req)


@router.post("/arsenal/hypotheses/source-ingest")
async def arsenal_generate_hypotheses_from_source(req: SourceIngestRequest):
    """Record source/spec hints as hypotheses only.

    Source facts can enrich the worklist, but they cannot queue scanner work,
    create findings, or satisfy runtime proof contracts.
    """
    target_uuid = None
    if req.target_id:
        try:
            target_uuid = uuid.UUID(str(req.target_id))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="target_id must be a UUID") from exc
    created: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    generated_hints, file_skips, source_file_summary = _source_files_to_hints(
        req.files,
        source_label=req.source_label,
        max_files=req.max_files,
        max_file_bytes=req.max_file_bytes,
        ignored_paths=req.ignored_paths,
        parse_timeout_ms=req.parse_timeout_ms,
        max_hints=max(0, 50 - len(req.hints)),
    )
    hints = list(req.hints) + generated_hints
    skipped.extend({"source": "file_ingest", **item} for item in file_skips)
    async with _pool().acquire() as conn:
        if target_uuid and not await conn.fetchval("SELECT 1 FROM targets WHERE id=$1", target_uuid):
            raise HTTPException(status_code=404, detail="Target not found")
        for index, hint in enumerate(hints):
            hypothesis_req, skip = _source_hint_to_hypothesis_request(
                hint,
                target_id=str(target_uuid) if target_uuid else None,
                source_label=req.source_label,
                created_by=req.created_by,
            )
            if skip:
                skipped.append({"index": index, **skip})
                continue
            if not hypothesis_req:
                skipped.append({"index": index, "reason": "no_hypothesis_generated"})
                continue
            result = await _upsert_hypothesis(conn, hypothesis_req)
            created.append(result["hypothesis"])
    return {
        "hypotheses": created,
        "created_or_endorsed": len(created),
        "skipped": skipped,
        "skipped_count": len(skipped),
        "source_label": req.source_label,
        "source_file_summary": source_file_summary,
        "execution_enabled": False,
        "findings_created": 0,
        "queued_scans": 0,
        "runtime_proof_required": True,
    }


@router.post("/arsenal/hypotheses/from-plan")
async def arsenal_generate_hypotheses_from_plan(req: PlannerHypothesisRequest):
    """Record saved planner actions as hypotheses only.

    Planner output remains a signal source. This route requires a persisted
    OperationPlan and cannot queue scanner work, create findings, or satisfy
    runtime proof contracts.
    """
    async with _pool().acquire() as conn:
        return await _generate_hypotheses_from_operation_plan(conn, req)


@router.post("/arsenal/hypotheses/from-benchmark")
async def arsenal_generate_hypotheses_from_benchmark(req: BenchmarkHypothesisRequest):
    """Record benchmark scorecard follow-ups as hypotheses only.

    Benchmark misses become worklist leads. This route cannot queue scanner work,
    create findings, or satisfy runtime proof contracts.
    """
    async with _pool().acquire() as conn:
        return await _generate_hypotheses_from_benchmark_followups(conn, req)


@router.post("/arsenal/hypotheses/{hypothesis_id}/claim")
async def arsenal_claim_hypothesis(hypothesis_id: str, req: HypothesisClaimRequest):
    """Claim a hypothesis with compare-and-set leasing.

    Terminal hypotheses are not claimable. Expired claims become claimable again.
    """
    try:
        hypothesis_uuid = uuid.UUID(str(hypothesis_id))
    except ValueError:
        raise HTTPException(status_code=400, detail="hypothesis_id must be a UUID")
    lease_expires_at = datetime.now(timezone.utc) + timedelta(seconds=req.lease_seconds)
    async with _pool().acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE hypotheses
            SET status = 'claimed',
                claim_owner = $3,
                claim_lease_expires_at = $4,
                version = version + 1,
                updated_at = NOW()
            WHERE id = $1
              AND version = $2
              AND status NOT IN ('refuted','promoted','dead','blocked','exhausted')
              AND (
                claim_lease_expires_at IS NULL
                OR claim_lease_expires_at < NOW()
                OR claim_owner = $3
              )
            RETURNING *
            """,
            hypothesis_uuid,
            req.expected_version,
            req.owner.strip(),
            lease_expires_at,
        )
        if row:
            return {
                "hypothesis": _public_hypothesis_row(row),
                "claimed": True,
                "execution_enabled": False,
            }
        current = await conn.fetchrow("SELECT id, status, version, claim_owner, claim_lease_expires_at FROM hypotheses WHERE id=$1", hypothesis_uuid)
    if not current:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    raise HTTPException(
        status_code=409,
        detail={
            "error": "hypothesis_not_claimable",
            "status": current["status"],
            "version": current["version"],
            "claim_owner": current["claim_owner"],
            "claim_lease_expires_at": current["claim_lease_expires_at"],
        },
    )


@router.post("/arsenal/hypotheses/{hypothesis_id}/transition")
async def arsenal_transition_hypothesis(hypothesis_id: str, req: HypothesisTransitionRequest):
    """Gated hypothesis lifecycle transition (Wave 4).

    Enforces legal edges (`hypothesis_lifecycle`), requires a falsifier + expected signal before
    `testing`, and requires a deterministic `refuted_by` for a `refuted` transition (the negative
    gate of §4.1). Optimistic version guard; no finding is created or promoted here.
    """
    try:
        hypothesis_uuid = uuid.UUID(str(hypothesis_id))
    except ValueError:
        raise HTTPException(status_code=400, detail="hypothesis_id must be a UUID")
    to_state = str(req.to or "").strip().lower()
    async with _pool().acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM hypotheses WHERE id=$1", hypothesis_uuid)
        if not row:
            raise HTTPException(status_code=404, detail="Hypothesis not found")
        hyp = _public_hypothesis_row(row)
        # Legality is based on the persisted state. A time-derived effective status must not enable
        # an edge the versioned row itself cannot take.
        from_state = hyp.get("status")
        ok, reason = hypothesis_lifecycle.evaluate_transition(
            from_state,
            to_state,
            next_test_action=hyp.get("next_test_action"),
            metadata=hyp.get("metadata_json"),
        )
        if not ok:
            raise HTTPException(
                status_code=409,
                detail={"error": "illegal_transition", "reason": reason, "from": from_state, "to": to_state},
            )
        if to_state == "promoted":
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "promotion_requires_proof_reconciliation",
                    "reason": "use the approval-gated hypothesis proof reconciliation path",
                },
            )
        refuted_by = req.refuted_by if isinstance(req.refuted_by, dict) else {}
        if to_state in hypothesis_lifecycle.REFUTING_TARGETS:
            gate_ok, gate_reason = adjudicate.require_deterministic_refutation({
                "verdict_basis": refuted_by.get("basis") or refuted_by.get("verdict_basis"),
                "refuted_by": refuted_by,
            })
            if not gate_ok:
                raise HTTPException(
                    status_code=422,
                    detail={"error": "refutation_not_deterministic", "reason": gate_reason},
                )
            verification_id = str(refuted_by.get("verification_id") or "").strip()
            if not verification_id:
                raise HTTPException(
                    status_code=422,
                    detail={"error": "refutation_reference_not_verified", "reason": "verification_id_required"},
                )
            reference_valid = await _refuter_verification_reference_valid(
                conn,
                verification_id=verification_id,
                finding_uuid=None,
                target_uuid=_optional_uuid(hyp.get("target_id")),
                hypothesis=hyp,
            )
            if not reference_valid:
                raise HTTPException(
                    status_code=422,
                    detail={"error": "refutation_reference_not_verified", "reason": "verification_not_bound_to_hypothesis_proof"},
                )
        meta_patch: dict[str, Any] = {
            "last_transition": {
                "from": from_state,
                "to": to_state,
                "reason": req.reason or None,
                "by": req.created_by,
                "at": datetime.now(timezone.utc).isoformat(),
            }
        }
        if to_state in hypothesis_lifecycle.REFUTING_TARGETS:
            meta_patch["refuted_by"] = {
                key: refuted_by.get(key)
                for key in ("verification_id", "basis", "ref")
                if refuted_by.get(key)
            }
        if req.blockers:
            meta_patch["blockers"] = _clean_string_list(req.blockers, max_items=20)
        terminal_reason = (req.reason or f"transition:{to_state}")[:500]
        updated = await conn.fetchrow(
            """
            UPDATE hypotheses
            SET status = $3,
                terminal_reason = CASE WHEN $3 IN ('refuted','promoted','dead','exhausted','blocked')
                    THEN $4 ELSE terminal_reason END,
                claim_owner = CASE WHEN $3 IN ('refuted','promoted','dead','exhausted')
                    THEN NULL ELSE claim_owner END,
                claim_lease_expires_at = CASE WHEN $3 IN ('refuted','promoted','dead','exhausted')
                    THEN NULL ELSE claim_lease_expires_at END,
                metadata_json = metadata_json || $5::jsonb,
                version = version + 1,
                updated_at = NOW()
            WHERE id = $1 AND version = $2 AND status = $6
            RETURNING *
            """,
            hypothesis_uuid,
            req.expected_version,
            to_state,
            terminal_reason,
            json.dumps(meta_patch),
            from_state,
        )
        if not updated:
            current = await conn.fetchrow("SELECT status, version FROM hypotheses WHERE id=$1", hypothesis_uuid)
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "version_conflict",
                    "status": current["status"] if current else None,
                    "version": current["version"] if current else None,
                },
            )
    return {
        "hypothesis": _public_hypothesis_row(updated),
        "transitioned": True,
        "from": from_state,
        "to": to_state,
        "execution_enabled": False,
    }


@router.post("/arsenal/hypotheses/{hypothesis_id}/signals")
async def arsenal_append_hypothesis_signal(hypothesis_id: str, req: HypothesisSignalRequest):
    """Append an endorsement/refutation signal to a hypothesis.

    Signals are lead-board context only. They do not update findings, proof
    state, severity, or deployment gates.
    """
    async with _pool().acquire() as conn:
        return await _append_hypothesis_signal(conn, hypothesis_id, req)


@router.post("/arsenal/hypotheses/{hypothesis_id}/plan-campaign")
async def arsenal_plan_hypothesis_campaign(hypothesis_id: str, req: HypothesisCampaignPlanRequest):
    """Plan campaign work from a hypothesis without queueing or proving anything."""
    async with _pool().acquire() as conn:
        # Atomic: campaign insert + action insert + hypothesis link must not leave an
        # orphan campaign/action if a later write fails. HTTPExceptions roll back cleanly.
        async with conn.transaction():
            return await _plan_campaign_from_hypothesis(conn, hypothesis_id, req)


@router.post("/arsenal/hypotheses/{hypothesis_id}/reconcile-proof")
async def arsenal_reconcile_hypothesis_proof(hypothesis_id: str, req: HypothesisProofReconcileRequest):
    """Reconcile existing deterministic action proof without creating a finding."""
    async with _pool().acquire() as conn:
        async with conn.transaction():
            return await _reconcile_hypothesis_proof(conn, hypothesis_id, req)


@router.get("/arsenal/refuter-reviews")
async def arsenal_refuter_reviews(
    limit: int = Query(20, ge=1, le=100),
    subject_type: Optional[str] = Query(None),
    subject_id: Optional[str] = Query(None),
):
    """Read durable refuter signals/verdicts without changing findings."""
    if subject_type and subject_type not in {"finding", "hypothesis", "target", "ai_gate_scan", "model_intake", "benchmark", "planner", "deployment_gate", "parser_output", "manual"}:
        raise HTTPException(status_code=400, detail="invalid subject_type")
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT *
            FROM refuter_reviews
            WHERE ($2::text IS NULL OR subject_type = $2)
              AND ($3::text IS NULL OR subject_id = $3)
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
            subject_type,
            subject_id,
        )
    return {
        "refuter_reviews": [_public_refuter_review_row(row) for row in rows],
        "count": len(rows),
        "execution_enabled": False,
    }


@router.get("/arsenal/findings/{finding_id}/refuter-panel")
async def arsenal_finding_refuter_panel(
    finding_id: str,
    min_panel: int = Query(2, ge=1, le=10),
):
    """Adjudicate the refuter-review panel for a finding (strict majority, ties → survive).

    Read-only: gathers the finding's durable refuter reviews and runs the shared deterministic
    adjudicator (`api/adjudicate.py`). Uncorroborated refute votes fail-safe downgrade; only a strict
    majority of corroborated refutes dismisses. Changes no finding.
    """
    async with _pool().acquire() as conn:
        finding_row = await _ai_targets.get_finding_record(conn, finding_id)
        finding_uuid = None
        if finding_row:
            try:
                finding_uuid = uuid.UUID(str(finding_row["id"]))
            except (KeyError, TypeError, ValueError):
                finding_uuid = None
        rows = await conn.fetch(
            """
            SELECT *
            FROM refuter_reviews
            WHERE subject_type = 'finding' AND (finding_id::text = $1 OR subject_id = $1)
            ORDER BY created_at DESC
            LIMIT 50
            """,
            finding_id,
        )
        reviews = [_public_refuter_review_row(row) for row in rows]
        votes: list[dict[str, Any]] = []
        for review in reviews:
            vote = adjudicate.vote_from_review(review)
            if vote.get("refuter_verdict") == "refuted":
                counter = review.get("counterevidence") if isinstance(review.get("counterevidence"), dict) else {}
                target_uuid = None
                try:
                    target_uuid = _optional_uuid(review.get("target_id"))
                except ValueError:
                    pass
                valid = await _refuter_verification_reference_valid(
                    conn,
                    verification_id=counter.get("verification_id"),
                    finding_uuid=finding_uuid,
                    target_uuid=target_uuid,
                )
                if not valid:
                    vote["tool_receipt_ids"] = []
                    vote["evidence_object_ids"] = []
                    vote["cite"] = {"observed": False, "mitigation": ""}
            votes.append(vote)
    panel = adjudicate.adjudicate_panel(votes, min_panel=min_panel)
    return {
        "finding_id": finding_id,
        "panel": panel,
        "review_count": len(reviews),
        "reviews": reviews,
        "execution_enabled": False,
    }


@router.get("/arsenal/refuter-reviews/summary")
async def arsenal_refuter_review_summary(
    limit: int = Query(20, ge=1, le=100),
    finding_window: int = Query(200, ge=1, le=1000),
):
    """Summarize weak/high-impact claims that should be challenged.

    This is a read-only trigger worklist. It does not create refuter reviews,
    update findings, or alter proof/deployment state.
    """
    async with _pool().acquire() as conn:
        return await _load_refuter_work_summary(conn, limit=limit, finding_window=finding_window)


@router.post("/arsenal/refuter-reviews/queue-from-summary")
async def arsenal_queue_refuter_reviews_from_summary(req: RefuterReviewQueueRequest):
    """Record signal-only refuter review work from the current weak-claim summary.

    This turns suggested review requests into durable refuter review rows. It
    still does not execute scanners, update findings, alter proof state, or
    change deployment gates.
    """
    async with _pool().acquire() as conn:
        async with conn.transaction():
            summary = await _load_refuter_work_summary(conn, limit=req.limit, finding_window=req.finding_window)
            review_requests = _refuter_review_requests_from_summary(
                summary,
                include_integrity_signals=req.include_integrity_signals,
                created_by=req.created_by,
            )
            created: list[dict[str, Any]] = []
            created_integrity = 0
            for review_request in review_requests:
                result = await _record_refuter_review(conn, review_request)
                created.append(result["refuter_review"])
                if review_request.metadata_json.get("queued_integrity_signal") is True:
                    created_integrity += 1
    return {
        "created": len(created),
        "created_integrity_signals": created_integrity,
        "created_finding_reviews": len(created) - created_integrity,
        "skipped_already_reviewed": summary["summary"]["already_reviewed_count"],
        "unreviewed_count": summary["summary"]["unreviewed_count"],
        "refuter_reviews": created,
        "summary": summary["summary"],
        "execution_enabled": False,
        "findings_updated": 0,
        "hypotheses_updated": 0,
    }


@router.post("/arsenal/refuter-reviews/{refuter_review_id}/execute")
async def arsenal_execute_refuter_review_plan(refuter_review_id: str, req: RefuterReviewExecuteRequest):
    """Execute the next planned refuter automation step through existing gated primitives.

    This can queue deterministic retests or AI Gate finding replays, or produce
    a Model Intake trust preview. It records refuter execution metadata and a
    command audit row, but it does not directly update finding proof state,
    severity, hypotheses, or deployment gates.
    """
    return await _arsenal_execute_detached(ArsenalExecuteRequest(
        command="refuter_review.execute_plan",
        parameters={
            "refuter_review_id": refuter_review_id,
            "step_id": req.step_id,
            "requested_by": req.requested_by,
            "confirm_production": req.confirm_production,
        },
        execute=req.execute,
        confirmations=req.confirmations,
        approval_receipt_id=req.approval_receipt_id,
        created_by=req.requested_by,
    ))


@router.post("/arsenal/refuter-reviews/{refuter_review_id}/derive-verdict")
async def arsenal_derive_refuter_review_verdict(refuter_review_id: str, req: RefuterReviewDeriveVerdictRequest):
    """Record a refuter signal/verdict from a completed verification row.

    Deterministic verification rows can produce proof-backed refuter verdicts.
    AI-driven rows are recorded as signal-only context unless a human-approved
    review records a verdict separately.
    """
    return await _arsenal_execute_detached(ArsenalExecuteRequest(
        command="refuter_review.derive_verdict",
        parameters={
            "refuter_review_id": refuter_review_id,
            "verification_id": req.verification_id,
            "created_by": req.created_by,
        },
        execute=req.execute,
        confirmations=req.confirmations,
        approval_receipt_id=req.approval_receipt_id,
        created_by=req.created_by,
    ))


@router.post("/arsenal/refuter-reviews")
async def arsenal_record_refuter_review(req: RefuterReviewRequest):
    """Record a refuter signal or proof-backed verdict.

    Signals are counterevidence context only. Verdicts require deterministic,
    cryptographic, parser/protocol, or explicit human-approved-review basis and
    still do not directly update findings, hypotheses, proof state, or gates.
    """
    async with _pool().acquire() as conn:
        return await _record_refuter_review(conn, req)


@router.get("/arsenal/tool-receipts")
async def arsenal_tool_receipts(
    limit: int = Query(20, ge=1, le=100),
    tool_name: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """Read durable receipts for existing tools/executors."""
    if status and status not in {"success", "failed", "timeout", "skipped", "waived", "parser_error", "recorded"}:
        raise HTTPException(status_code=400, detail="invalid tool receipt status")
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT *
            FROM tool_receipts
            WHERE ($2::text IS NULL OR tool_name = $2)
              AND ($3::text IS NULL OR status = $3)
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
            tool_name,
            status,
        )
    return {
        "tool_receipts": [_public_tool_receipt_row(row) for row in rows],
        "count": len(rows),
        "execution_enabled": False,
    }


@router.post("/arsenal/tool-receipts")
async def arsenal_record_tool_receipt(req: ToolReceiptRequest):
    """Record a tool/executor receipt without running tools or creating findings."""
    async with _pool().acquire() as conn:
        return await _record_tool_receipt(conn, req)


@router.post("/arsenal/context-packs")
async def arsenal_create_agent_context_pack(req: AgentContextPackRequest):
    """Validate and persist a bounded AgentContextPack without exposing execution power."""
    async with _pool().acquire() as conn:
        return await _persist_agent_context_pack(conn, req)


@router.post("/arsenal/context-packs/from-target")
async def arsenal_create_agent_context_pack_from_target(req: AgentContextPackFromTargetRequest):
    """Generate and persist a bounded AgentContextPack from stored target facts."""
    async with _pool().acquire() as conn:
        generated = await _build_agent_context_pack_from_target(conn, req)
        response = await _persist_agent_context_pack(conn, generated)
    response["generated_from"] = {"target_id": req.target_id, "source": "target_facts"}
    return response


@router.get("/arsenal/context-packs")
async def arsenal_agent_context_packs(limit: int = Query(20, ge=1, le=100)):
    """Read recent bounded AgentContextPack records."""
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT * FROM agent_context_packs
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
        )
    return {
        "context_packs": [_public_agent_context_pack_row(row) for row in rows],
        "execution_enabled": False,
        "count": len(rows),
    }


@router.post("/arsenal/decision-traces")
async def arsenal_create_agent_decision_trace(req: AgentDecisionTraceRequest):
    """Validate and persist an AgentDecisionTrace audit record without executing actions."""
    async with _pool().acquire() as conn:
        payload, errors, warnings, status = await _validate_agent_decision_trace(conn, req)
        operation_plan_id = uuid.UUID(payload["operation_plan_id"]) if payload.get("operation_plan_id") else None
        context_pack_id = uuid.UUID(payload["context_pack_id"]) if payload.get("context_pack_id") else None
        row = await conn.fetchrow(
            """
            INSERT INTO agent_decision_traces (
                operation_plan_id, context_pack_id, planner, context_hash, command_schema_version,
                steps, final_rationale, redaction_profile, validation_errors,
                validation_warnings, status, created_by
            ) VALUES (
                $1,$2,$3::jsonb,$4,$5,
                $6::jsonb,$7,$8,$9::jsonb,
                $10::jsonb,$11,$12
            )
            RETURNING *
            """,
            operation_plan_id,
            context_pack_id,
            json.dumps(payload.get("planner") or {}),
            payload["context_hash"],
            payload["command_schema_version"],
            json.dumps(payload.get("steps") or []),
            str(payload.get("final_rationale") or "").strip() or None,
            payload["redaction_profile"],
            json.dumps(errors),
            json.dumps(warnings),
            status,
            str(payload.get("created_by") or "").strip() or None,
        )
    return {
        "decision_trace": _public_agent_decision_trace_row(row),
        "execution_enabled": False,
        "validated": not errors,
    }


@router.get("/arsenal/decision-traces")
async def arsenal_agent_decision_traces(limit: int = Query(20, ge=1, le=100)):
    """Read recent AgentDecisionTrace audit records."""
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT * FROM agent_decision_traces
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
        )
    return {
        "decision_traces": [_public_agent_decision_trace_row(row) for row in rows],
        "execution_enabled": False,
        "count": len(rows),
    }


@router.get("/arsenal/tools")
async def arsenal_tools(
    probe_versions: bool = Query(False, description="Run short read-only version probes for installed tools."),
):
    """Read-only status catalog for already-integrated tool adapters."""
    return describe_arsenal_tools(probe_versions=bool(probe_versions))
class ScopePreviewRequest(BaseModel):
    url: str
    target_id: Optional[str] = None
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_root_domains: list[str] = Field(default_factory=list)
    environment: str = Field(default="production")
    redirect_urls: list[str] = Field(default_factory=list)


class ApprovalReceiptRequest(BaseModel):
    scope_receipt_id: str
    risk_tier: str = Field(pattern="^(active|intrusive|credential|dangerous)$")
    confirmations: list[str] = Field(default_factory=list)
    action_name: Optional[str] = Field(default=None, max_length=160)
    action_context: dict[str, Any] = Field(default_factory=dict)
    approved_by: Optional[str] = None
    denial_reason: Optional[str] = None
    expires_at: Optional[datetime] = None


class ApprovalReceiptRevocationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revoked_by: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=2_000)


class OperationPlanAction(BaseModel):
    command: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk_tier: Optional[str] = Field(
        default=None,
        pattern="^(read_only|passive|active|intrusive|credential|dangerous)$",
    )
    scope_receipt_id: Optional[str] = None
    approval_receipt_id: Optional[str] = None
    reason: Optional[str] = None


class AgentDecisionTraceStep(BaseModel):
    kind: str
    command: Optional[str] = None
    status: str = Field(default="planned")
    reason: Optional[str] = None
    refs: list[str] = Field(default_factory=list)


class OperationPlanRequest(BaseModel):
    objective: str
    planner: dict[str, Any] = Field(default_factory=dict)
    context_hash: str
    target_scope: dict[str, Any] = Field(default_factory=dict)
    risk_tier: str = Field(pattern="^(read_only|passive|active|intrusive|credential|dangerous)$")
    allowed_families: list[str] = Field(default_factory=list)
    disallowed_families: list[str] = Field(default_factory=list)
    budget: dict[str, Any] = Field(default_factory=dict)
    constraints: dict[str, Any] = Field(default_factory=dict)
    missing_inputs: list[str] = Field(default_factory=list)
    confirmations: list[str] = Field(default_factory=list)
    actions: list[OperationPlanAction] = Field(default_factory=list)
    stop_conditions: list[str] = Field(default_factory=list)
    success_criteria: list[str] = Field(default_factory=list)
    scope_receipt_id: Optional[str] = None
    approval_receipt_id: Optional[str] = None
    created_by: Optional[str] = None


class AgentContextPackRequest(BaseModel):
    context_version: str = Field(default="2026-07-05.v1")
    target_id: Optional[str] = None
    context_hash: str
    target_summary: dict[str, Any] = Field(default_factory=dict)
    current_surface: dict[str, Any] = Field(default_factory=dict)
    current_gaps: list[dict[str, Any]] = Field(default_factory=list)
    hypotheses_summary: list[dict[str, Any]] = Field(default_factory=list)
    findings_summary: list[dict[str, Any]] = Field(default_factory=list)
    allowed_commands: list[str] = Field(default_factory=list)
    disallowed_commands: list[dict[str, Any]] = Field(default_factory=list)
    known_preconditions: dict[str, Any] = Field(default_factory=dict)
    redaction_profile: str = Field(default="agent-plan-default")
    created_by: Optional[str] = None


class AgentContextPackFromTargetRequest(BaseModel):
    target_id: str
    created_by: Optional[str] = None
    include_findings: bool = True
    include_endpoints: bool = True
    include_gaps: bool = True
    finding_limit: int = Field(default=10, ge=0, le=25)
    endpoint_limit: int = Field(default=12, ge=0, le=50)


class HypothesisProofReconcileRequest(BaseModel):
    expected_version: int = Field(ge=1)
    campaign_action_id: Optional[str] = None
    approval_receipt_id: str
    created_by: Optional[str] = Field(default="hypothesis_proof_reconciler", max_length=120)


class SourceIngestRequest(BaseModel):
    target_id: Optional[str] = None
    source_label: str = Field(default="operator_source_ingest", max_length=120)
    hints: list[SourceIngestHint] = Field(default_factory=list, max_length=50)
    files: list[SourceIngestFile] = Field(default_factory=list, max_length=100)
    max_files: int = Field(default=25, ge=1, le=100)
    max_file_bytes: int = Field(default=65536, ge=1024, le=262144)
    ignored_paths: list[str] = Field(default_factory=list, max_length=50)
    parse_timeout_ms: int = Field(default=1000, ge=100, le=5000)
    created_by: Optional[str] = None


class PlannerHypothesisRequest(BaseModel):
    operation_plan_id: str
    created_by: Optional[str] = None
    max_actions: int = Field(default=25, ge=1, le=50)


class BenchmarkHypothesisRequest(BaseModel):
    target_id: Optional[str] = None
    benchmark: str = Field(default="benchmark", max_length=120)
    scorecard_id: Optional[str] = Field(default=None, max_length=200)
    scorecard_scan_id: Optional[str] = Field(default=None, max_length=120)
    followups: list[BenchmarkFollowupHypothesisItem] = Field(default_factory=list, min_length=1, max_length=100)
    created_by: Optional[str] = None


class CampaignRequest(BaseModel):
    objective: str = Field(min_length=1, max_length=500)
    campaign_type: str = Field(pattern="^(continuous_asm|authenticated_dast|api_authz|ai_red_team|model_intake|benchmark|incident_retest|source_informed_dast|finding_retest|focused_family)$")
    name: Optional[str] = Field(default=None, max_length=200)
    target_id: Optional[str] = None
    target_scope: dict[str, Any] = Field(default_factory=dict)
    risk_tier: str = Field(default="read_only", pattern="^(read_only|passive|active|intrusive|credential|dangerous)$")
    policy_profile: Optional[str] = None
    planner: dict[str, Any] = Field(default_factory=dict)
    operation_plan_id: Optional[str] = None
    context_hash: Optional[str] = None
    status: str = Field(default="planned", pattern="^(planned|active|paused|completed|cancelled)$")
    deployment_impact: dict[str, Any] = Field(default_factory=dict)
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    created_by: Optional[str] = None


class CampaignActionLinkRequest(BaseModel):
    command_result_id: Optional[str] = None
    campaign_action_id: Optional[str] = None


class ArsenalExecuteRequest(BaseModel):
    """Invoke a Command Arsenal product command by name through its existing
    handler. Never a shell/arbitrary-code runner: only catalog commands with a
    wired adapter run, and state-changing commands stay behind the same
    confirmation + approval-receipt + execution-flag gate as the AI Ops router."""

    command: str = Field(min_length=1, max_length=120)
    parameters: dict[str, Any] = Field(default_factory=dict)
    execute: bool = False
    confirmations: list[str] = Field(default_factory=list)
    approval_receipt_id: Optional[str] = None
    scope_receipt_id: Optional[str] = None
    created_by: Optional[str] = None
    campaign_id: Optional[str] = None
    campaign_action_id: Optional[str] = None
    research_hypothesis_id: Optional[str] = None


class AuthzReplayExecuteRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=200)
    execute: bool = False
    confirmations: list[str] = Field(default_factory=list)
    approval_receipt_id: Optional[str] = None
    created_by: Optional[str] = Field(default="authz_replay_operator", max_length=120)


class AuthzReplayPromoteRequest(BaseModel):
    execute: bool = False
    confirmations: list[str] = Field(default_factory=list)
    approval_receipt_id: Optional[str] = None
    created_by: Optional[str] = Field(default="authz_replay_operator", max_length=120)


class HypothesisClaimRequest(BaseModel):
    owner: str = Field(min_length=1, max_length=120)
    expected_version: int = Field(ge=1)
    lease_seconds: int = Field(default=1800, ge=60, le=86400)


class HypothesisCampaignPlanRequest(BaseModel):
    campaign_id: Optional[str] = None
    campaign_name: Optional[str] = Field(default=None, max_length=200)
    operator_message: Optional[str] = Field(default=None, max_length=500)
    created_by: Optional[str] = None


class HypothesisSignalRequest(BaseModel):
    signal_type: str = Field(pattern="^(endorsement|refutation)$")
    source: str = Field(min_length=1, max_length=80)
    reason: Optional[str] = None
    evidence_object_ids: list[str] = Field(default_factory=list)
    tool_receipt_ids: list[str] = Field(default_factory=list)
    confidence_delta: Optional[float] = Field(default=None, ge=-1, le=1)
    status_hint: Optional[str] = Field(default=None, pattern="^(support|question|weaken|refute)$")
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    created_by: Optional[str] = None


class RefuterReviewRequest(BaseModel):
    subject_type: str = Field(pattern="^(finding|hypothesis|target|ai_gate_scan|model_intake|benchmark|planner|deployment_gate|parser_output|manual)$")
    subject_id: Optional[str] = None
    target_id: Optional[str] = None
    finding_id: Optional[str] = None
    hypothesis_id: Optional[str] = None
    campaign_id: Optional[str] = None
    trigger_reason: str = Field(min_length=1, max_length=500)
    refuter_signal: str = Field(default="question", pattern="^(support|question|weaken|refute)$")
    refuter_verdict: Optional[str] = Field(default=None, pattern="^(supported|weakened|refuted|inconclusive)$")
    verdict_basis: str = Field(default="signal_only", pattern="^(signal_only|deterministic_replay|cryptographic|parser_protocol|human_approved_review)$")
    confidence_delta: Optional[float] = Field(default=None, ge=-1, le=1)
    evidence_object_ids: list[str] = Field(default_factory=list)
    tool_receipt_ids: list[str] = Field(default_factory=list)
    counterevidence: dict[str, Any] = Field(default_factory=dict)
    notes: Optional[str] = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    created_by: Optional[str] = None


class RefuterReviewQueueRequest(BaseModel):
    limit: int = Field(default=20, ge=1, le=100)
    finding_window: int = Field(default=200, ge=1, le=1000)
    include_integrity_signals: bool = False
    created_by: Optional[str] = Field(default="refuter_auto_queue", max_length=120)


class RefuterReviewExecuteRequest(BaseModel):
    execute: bool = False
    confirmations: list[str] = Field(default_factory=list)
    approval_receipt_id: Optional[str] = None
    step_id: Optional[str] = None
    requested_by: Optional[str] = Field(default="refuter_executor", max_length=120)
    confirm_production: bool = False


class RefuterReviewDeriveVerdictRequest(BaseModel):
    execute: bool = False
    confirmations: list[str] = Field(default_factory=list)
    approval_receipt_id: Optional[str] = None
    verification_id: Optional[str] = None
    created_by: Optional[str] = Field(default="refuter_verdict_derive", max_length=120)


class ToolReceiptRequest(BaseModel):
    tool_name: str = Field(min_length=1, max_length=120)
    capability_name: Optional[str] = Field(default=None, max_length=160)
    adapter_name: Optional[str] = Field(default=None, max_length=160)
    tool_version: Optional[str] = None
    adapter_version: str = "2026-07-05.v1"
    command_hash: Optional[str] = None
    redacted_argv: list[Any] = Field(default_factory=list)
    worker_build: Optional[str] = None
    container_image: Optional[str] = None
    target_scope: dict[str, Any] = Field(default_factory=dict)
    scope_receipt_id: Optional[str] = None
    approval_receipt_id: Optional[str] = None
    policy_profile_id: Optional[str] = None
    status: str = Field(default="recorded", pattern="^(success|failed|timeout|skipped|waived|parser_error|recorded)$")
    parser_status: str = Field(default="not_run", pattern="^(not_run|parsed|partial|failed|not_applicable)$")
    exit_code: Optional[int] = None
    timed_out: bool = False
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    stdout_evidence_object_id: Optional[str] = None
    stderr_evidence_object_id: Optional[str] = None
    parsed_evidence_instance_ids: list[str] = Field(default_factory=list)
    budget_json: dict[str, Any] = Field(default_factory=dict)
    partial: bool = False
    output_artifact_id: Optional[str] = None
    hunt_id: Optional[str] = None
    redaction_summary: Optional[str] = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    created_by: Optional[str] = None




class AgentDecisionTraceRequest(BaseModel):
    operation_plan_id: Optional[str] = None
    context_pack_id: Optional[str] = None
    planner: dict[str, Any] = Field(default_factory=dict)
    context_hash: str
    command_schema_version: str = Field(default="unknown")
    steps: list[AgentDecisionTraceStep] = Field(default_factory=list)
    final_rationale: Optional[str] = None
    redaction_profile: str = Field(default="agent-trace-default")
    created_by: Optional[str] = None


class FamilyProofHandoffRequest(BaseModel):
    family: str = Field(min_length=1, max_length=80)
    evidence: dict[str, Any] = Field(default_factory=dict)
    target_id: Optional[str] = None
    concrete_url: Optional[str] = None
    experiment_id: Optional[str] = None
    tool_receipt_ids: list[str] = Field(default_factory=list)
    principals: dict[str, Any] = Field(default_factory=dict)
    created_by: Optional[str] = Field(default=None, max_length=120)


class HypothesisTransitionRequest(BaseModel):
    to: str = Field(pattern="^(open|claimed|testing|supported|refuted|blocked|exhausted|promoted|dead)$")
    expected_version: int = Field(ge=1)
    reason: Optional[str] = Field(default=None, max_length=1000)
    refuted_by: dict[str, Any] = Field(default_factory=dict)
    blockers: list[str] = Field(default_factory=list)
    created_by: Optional[str] = Field(default=None, max_length=120)
def _public_scope_receipt_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    for key in (
        "input_scope",
        "normalized_scope",
        "blocked_by",
        "warnings",
        "checks",
        "allowed_hosts",
        "allowed_root_domains",
        "redirect_destinations",
    ):
        payload[key] = _decode_json_value(payload.get(key))
    return payload


def _public_approval_receipt_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    payload["confirmations"] = _decode_json_value(payload.get("confirmations")) or []
    payload["action_context"] = _decode_json_value(payload.get("action_context")) or {}
    payload["status"] = str(payload.get("status") or "active")
    return payload


def _public_operation_plan_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    for key in (
        "planner",
        "target_scope",
        "actions",
        "confirmations",
        "missing_inputs",
        "stop_conditions",
        "success_criteria",
        "validation_errors",
        "validation_warnings",
        "plan_json",
    ):
        payload[key] = _decode_json_value(payload.get(key))
    payload["execution_enabled"] = False
    return payload


def _public_command_result_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    for key in (
        "finding_ids",
        "hypothesis_ids",
        "evidence_object_ids",
        "tool_receipt_ids",
        "promoted_finding_ids",
        "blocked_by",
        "result_json",
    ):
        payload[key] = _decode_json_value(payload.get(key)) or ([] if key != "result_json" else {})
    return payload


def _campaign_action_effective_status(status: Any, linked_scan_status: Any) -> str:
    """Overlay terminal linked-scan truth onto a stale asynchronous ledger state."""
    stored = str(status or "unknown").strip().lower() or "unknown"
    linked = str(linked_scan_status or "").strip().lower()
    if (
        stored in {"planned", "approved", "queued", "running", "retest_scheduled"}
        and linked in {"completed", "failed", "cancelled", "partial"}
    ):
        return linked
    return stored


def _public_agent_context_pack_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    for key in (
        "target_summary",
        "current_surface",
        "current_gaps",
        "hypotheses_summary",
        "findings_summary",
        "allowed_commands",
        "disallowed_commands",
        "known_preconditions",
        "context_pack",
        "validation_errors",
        "validation_warnings",
    ):
        payload[key] = _decode_json_value(payload.get(key))
    payload["execution_enabled"] = False
    return payload


def _public_agent_decision_trace_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    for key in (
        "planner",
        "steps",
        "validation_errors",
        "validation_warnings",
    ):
        payload[key] = _decode_json_value(payload.get(key))
    payload["execution_enabled"] = False
    return payload


async def _persist_agent_context_pack(conn, req: AgentContextPackRequest) -> dict[str, Any]:
    payload, errors, warnings, status = await _validate_agent_context_pack(conn, req)
    target_id = uuid.UUID(payload["target_id"]) if payload.get("target_id") else None
    row = await conn.fetchrow(
        """
        INSERT INTO agent_context_packs (
            context_version, target_id, context_hash, target_summary, current_surface,
            current_gaps, hypotheses_summary, findings_summary, allowed_commands,
            disallowed_commands, known_preconditions, redaction_profile, context_pack,
            validation_errors, validation_warnings, status, created_by
        ) VALUES (
            $1,$2,$3,$4::jsonb,$5::jsonb,
            $6::jsonb,$7::jsonb,$8::jsonb,$9::jsonb,
            $10::jsonb,$11::jsonb,$12,$13::jsonb,
            $14::jsonb,$15::jsonb,$16,$17
        )
        RETURNING *
        """,
        payload["context_version"],
        target_id,
        payload["context_hash"],
        json.dumps(payload.get("target_summary") or {}),
        json.dumps(payload.get("current_surface") or {}),
        json.dumps(payload.get("current_gaps") or []),
        json.dumps(payload.get("hypotheses_summary") or []),
        json.dumps(payload.get("findings_summary") or []),
        json.dumps(payload.get("allowed_commands") or []),
        json.dumps(payload.get("disallowed_commands") or []),
        json.dumps(payload.get("known_preconditions") or {}),
        payload["redaction_profile"],
        json.dumps(payload.get("context_pack") or {}),
        json.dumps(errors),
        json.dumps(warnings),
        status,
        str(payload.get("created_by") or "").strip() or None,
    )
    return {
        "context_pack": _public_agent_context_pack_row(row),
        "execution_enabled": False,
        "validated": not errors,
    }


async def _build_agent_context_pack_from_target(conn, req: AgentContextPackFromTargetRequest) -> AgentContextPackRequest:
    target_uuid = _uuid_or_400(req.target_id, "target id")
    target = await conn.fetchrow(
        """
        SELECT id, url, name, root_domain, is_active, last_scanned_at, last_score, last_grade,
               asm_enabled, asm_config, asm_last_test_at, asm_last_recon_at, metadata_json
        FROM targets
        WHERE id = $1
        """,
        target_uuid,
    )
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    target_payload = _json_safe_row(target)
    metadata = _decode_json_value(target_payload.get("metadata_json")) or {}
    try:
        target_origins = await _target_web_origins(conn, target_uuid, target_payload.get("url"))
    except Exception:
        target_origins = _normalized_web_origins(target_payload.get("url"))
    coverage = await asm_inventory.coverage_summary(conn, str(target_uuid))
    endpoint_counts = await conn.fetch(
        """
        SELECT COALESCE(auth_state, 'unknown') AS auth_state,
               COALESCE(test_status, 'unknown') AS test_status,
               COUNT(*) AS count
        FROM target_endpoints
        WHERE target_id = $1 AND COALESCE(test_status, '') <> 'gone'
        GROUP BY COALESCE(auth_state, 'unknown'), COALESCE(test_status, 'unknown')
        ORDER BY count DESC
        LIMIT 20
        """,
        target_uuid,
    )
    # B1: which collected artifacts feed the surface (crawl / har / js / ffuf / openapi / manual),
    # so the planner can see observability coverage at a glance — e.g. no JS-derived endpoints means
    # client-side routes are unexplored; no HAR means authenticated traffic was never captured.
    endpoint_source_counts: list[Any] = []
    try:
        async with _optional_database_savepoint(conn):
            endpoint_source_counts = await conn.fetch(
                """
                SELECT COALESCE(NULLIF(source, ''), 'unknown') AS source, COUNT(*) AS count
                FROM target_endpoints
                WHERE target_id = $1 AND COALESCE(test_status, '') <> 'gone'
                GROUP BY COALESCE(NULLIF(source, ''), 'unknown')
                ORDER BY count DESC
                LIMIT 12
                """,
                target_uuid,
            )
    except Exception:
        endpoint_source_counts = []
    sample_endpoints = []
    if req.include_endpoints and req.endpoint_limit > 0:
        endpoint_rows = await conn.fetch(
            """
            SELECT method, path, param_shape, replay_spec, param_location, auth_state, test_status,
                   last_attempt_status, last_verdict, priority_score, last_seen_at, last_tested_at
            FROM target_endpoints
            WHERE target_id = $1
              AND COALESCE(test_status, '') <> 'gone'
              AND COALESCE(last_http_status, 0) NOT IN (404, 410)
              AND COALESCE(unreachable_streak, 0) < 2
            ORDER BY priority_score DESC, last_seen_at DESC
            LIMIT $2
            """,
            target_uuid,
            req.endpoint_limit,
        )
        # param_shape (field names) + replay_spec (an example request incl. a valid body) let the
        # planner author a WORKING create/mutation step instead of an empty body the app 500s on.
        sample_endpoints = []
        for row in endpoint_rows:
            item = _json_safe_row(row)
            if item.get("replay_spec") is not None:
                item["replay_spec"] = str(item["replay_spec"])[:300]
            sample_endpoints.append(item)

    principal_summary: dict[str, Any] = {"principals": [], "expectations": [], "role_counts": {}, "tenant_counts": {}}
    try:
        async with _optional_database_savepoint(conn):
            principal_rows = await conn.fetch(
                """
                SELECT p.id, p.label, p.role, p.tenant_id, p.auth_state,
                       p.credential_profile, p.is_active, p.metadata_json,
                       EXISTS (
                         SELECT 1 FROM target_credential_profiles cp
                         WHERE cp.target_id = p.target_id
                           AND lower(cp.name) = lower(p.credential_profile)
                           AND cp.is_active = true
                           AND (cp.expires_at IS NULL OR cp.expires_at > NOW())
                       ) AS credential_configured
                FROM target_principals p
                WHERE p.target_id = $1 AND p.is_active = true
                ORDER BY p.role, p.label
                LIMIT 20
                """,
                target_uuid,
            )
            principals = [_targets._public_target_principal_row(row) for row in principal_rows]
            expectation_rows = await conn.fetch(
                """
                SELECT e.id, e.method, e.path, e.param_shape, e.param_location,
                       e.principal_role, e.tenant_id, e.expected_access, e.expected_http_status,
                       e.expectation_source, p.label AS principal_label, p.auth_state AS principal_auth_state
                FROM target_endpoint_expectations e
                LEFT JOIN target_principals p ON p.id = e.principal_id
                WHERE e.target_id = $1
                ORDER BY e.updated_at DESC
                LIMIT 25
                """,
                target_uuid,
            )
            role_counts = Counter(str(item.get("role") or "unknown") for item in principals)
            tenant_counts = Counter(str(item.get("tenant_id") or "none") for item in principals)
            principal_summary = {
                "principals": principals,
                "expectations": [_targets._public_target_endpoint_expectation_row(row) for row in expectation_rows],
                "role_counts": dict(role_counts),
                "tenant_counts": dict(tenant_counts),
            }
    except Exception:
        principal_summary = {"principals": [], "expectations": [], "role_counts": {}, "tenant_counts": {}}

    approved_invariant_contracts: list[dict[str, Any]] = []
    try:
        async with _optional_database_savepoint(conn):
            invariant_rows = await conn.fetch(
                """
                SELECT * FROM target_invariant_contracts
                WHERE target_id=$1 AND status='approved'
                ORDER BY updated_at DESC
                LIMIT 25
                """,
                target_uuid,
            )
            approved_invariant_contracts = [
                invariant_contracts.planner_projection(_targets._public_target_invariant_contract_row(row))
                for row in invariant_rows
            ]
    except Exception:
        # Upgraded instances build schema before serving requests, but fail closed during a rolling
        # migration: no invariant is safer than treating an unavailable/draft rule as authoritative.
        approved_invariant_contracts = []

    # A3: auto-drafted (and manually drafted) invariant CANDIDATES — review-only hints for the
    # planner, kept strictly separate from the approved rules above. A draft has no authority:
    # only an operator approval turns a candidate into a contract the binder can use.
    invariant_candidate_contracts: list[dict[str, Any]] = []
    try:
        async with _optional_database_savepoint(conn):
            candidate_rows = await conn.fetch(
                """
                SELECT contract_kind, title, method, path, field_name, subject_role,
                       expected_access, source, metadata_json, updated_at
                FROM target_invariant_contracts
                WHERE target_id=$1 AND status='draft'
                ORDER BY updated_at DESC
                LIMIT 15
                """,
                target_uuid,
            )
            invariant_candidate_contracts = [
                {
                    "contract_kind": str(row["contract_kind"] or ""),
                    "title": str(row["title"] or "")[:160],
                    "method": row["method"],
                    "path": row["path"],
                    "field_name": row["field_name"],
                    "subject_role": row["subject_role"],
                    "expected_access": row["expected_access"],
                    "source": row["source"],
                    "approvable": bool(((_decode_json_value(row["metadata_json"]) or {})).get("approvable")),
                    "approval_errors": (((_decode_json_value(row["metadata_json"]) or {})).get("approval_errors") or [])[:4],
                }
                for row in candidate_rows
            ]
    except Exception:
        invariant_candidate_contracts = []

    findings_summary: list[dict[str, Any]] = []
    if req.include_findings and req.finding_limit > 0:
        finding_rows = await conn.fetch(
            """
            SELECT id, title, severity, status, tool, url,
                   last_verification_verdict,
                   last_seen_at AS last_seen,
                   first_seen_at AS first_seen
            FROM findings
            WHERE target_id = $1
              AND status IN ('active','resolved','accepted_risk','false_positive')
            ORDER BY
              CASE status WHEN 'active' THEN 0 WHEN 'accepted_risk' THEN 1
                          WHEN 'resolved' THEN 2 ELSE 3 END,
              CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
              last_seen_at DESC NULLS LAST
            LIMIT $2
            """,
            target_uuid,
            req.finding_limit,
        )
        for row in finding_rows:
            finding = _json_safe_row(row)
            finding["category"] = finding.get("tool")
            finding.update(_finding_routes.finding_proof_fields(finding))
            findings_summary.append(finding)

    hypotheses_summary: list[dict[str, Any]] = []
    ranked_hypotheses: list[dict[str, Any]] = []
    attack_graph: dict[str, Any] = {"nodes": [], "edges": [], "truncated": False}
    recent_scans: list[dict[str, Any]] = []
    try:
        hypothesis_rows = await _savepoint_fetch(
            conn,
            """
            WITH family_ranked AS (
                SELECT h.*,
                       ROW_NUMBER() OVER (
                           PARTITION BY COALESCE(NULLIF(lower(h.family), ''), 'unknown')
                           ORDER BY
                             CASE WHEN h.source IN ('app_graph','benchmark','dast','scan','scanner','asm')
                                    OR lower(COALESCE(h.metadata_json->>'unexplained_residue', '')) IN ('true','1','yes','on')
                                    OR h.metadata_json ? 'graph_edge_id'
                                    OR h.metadata_json ? 'edge_id'
                                    OR h.metadata_json ? 'source_scan_id'
                                    OR h.metadata_json ? 'baseline_scan_id'
                                  THEN 0 ELSE 1 END,
                             h.confidence DESC, h.updated_at DESC
                       ) AS family_rank
                FROM hypotheses h
                WHERE h.target_id = $1
                  AND h.status IN ('open','claimed','testing','supported')
            )
            SELECT id, target_id, source, family, cwe, title, description,
                   severity_guess, confidence,
                   dedupe_key, status, version, claim_owner, claim_lease_expires_at,
                   smoke_score, evidence_object_ids, tool_receipt_ids,
                   next_test_action, metadata_json, endorsements, refutations,
                   updated_at
            FROM family_ranked
            ORDER BY family_rank, confidence DESC, updated_at DESC
            LIMIT 500
            """,
            target_uuid,
        )
        hypothesis_candidates = [_public_hypothesis_row(row) for row in hypothesis_rows]
        live_endpoint_rows = await _savepoint_fetch(
            conn,
            """
            SELECT te.method, te.path
            FROM target_endpoints te
            WHERE te.target_id=$1
              AND COALESCE(te.test_status, '') <> 'gone'
              -- Row-level: this method-row isn't itself a hard soft-404 (404/410) or server error (5xx).
              -- A 400 is deliberately NOT excluded: it means the route EXISTS and rejected input, so it
              -- is reachable surface, not a phantom.
              AND COALESCE(te.last_http_status, 0) NOT IN (404, 410, 500, 501, 502, 503, 504)
              AND COALESCE(te.unreachable_streak, 0) < 2
              -- Method-aware phantom exclusion. Some SPAs/APIs answer inferred, non-existent routes with a
              -- soft-404: a 500 "unexpected path" body (or a 404/410) instead of a hard 404. Such routes get
              -- ranked as app_graph leads and burn every experiment as inconclusive. unreachable_streak
              -- counts only connection failures, so these never retire to 'gone'. BUT the collapse must stay
              -- method-aware: a method-row that itself returned a concrete status (last_http_status IS NOT
              -- NULL -- includes 2xx/3xx/400/401/403/405) is proven reachable and is kept regardless of a
              -- sibling method's soft-404. Only a never-probed (NULL) method on the same path is dropped
              -- when a sibling method returned a hard soft-404 / server error -- i.e. don't invent a POST on
              -- a path whose only real evidence is a phantom GET. (External-audit — phantom leads.)
              AND (
                  te.last_http_status IS NOT NULL
                  OR NOT EXISTS (
                      SELECT 1 FROM target_endpoints ph
                      WHERE ph.target_id=te.target_id AND ph.path=te.path
                        AND ph.last_http_status IN (404, 410, 500, 501, 502, 503, 504))
              )
            ORDER BY te.path, te.method
            LIMIT 2000
            """,
            target_uuid,
        )
        live_surface = {
            (
                str(row.get("method") or "GET").upper(),
                _canonical_vulnerability_route(row.get("path")) or str(row.get("path") or ""),
            )
            for row in live_endpoint_rows
            if row.get("path")
        }
        hypothesis_candidates = [
            item for item in hypothesis_candidates
            if _research_hypothesis_matches_live_surface(item, live_surface)
        ]
        # Novelty memory: the candidate pool holds only actionable (open/claimed/testing/supported)
        # rows, so completed dimensions must be read from the terminal rows directly -- otherwise
        # every dimension looks novel forever and the scheduler keeps re-proposing dead leads.
        completed_rows = await _savepoint_fetch(
            conn,
            """
            SELECT dedupe_key FROM hypotheses
            WHERE target_id = $1
              AND status IN ('refuted','promoted','dead','exhausted')
              AND dedupe_key IS NOT NULL
            ORDER BY updated_at DESC
            LIMIT 200
            """,
            target_uuid,
        )
        completed_dimensions = [str(row["dedupe_key"]) for row in completed_rows if row["dedupe_key"]]
        async with _optional_database_savepoint(conn):
            known_vulnerability_keys = await _research_known_vulnerability_keys(conn, target_uuid)
        async with _optional_database_savepoint(conn):
            known_coverage_keys = await _research_known_coverage_keys(conn, target_uuid)
        # Planner context should lead with the same residue-backed candidates selected by the
        # deterministic scheduler. Fill any spare slots with the original ordering for useful
        # context, but never let high-confidence generic noise crowd all scheduled residue out.
        hypotheses_summary, ranked_hypotheses = _select_research_hypothesis_context(
            hypothesis_candidates,
            completed_dimensions=completed_dimensions,
            auth_available=any(
                bool(item.get("credential_configured"))
                for item in principal_summary.get("principals", [])
            ),
            known_vulnerability_keys=known_vulnerability_keys,
            known_coverage_keys=known_coverage_keys,
        )
        graph_nodes = await _savepoint_fetch(
            conn,
            """
            SELECT node_type, node_key, label, scan_id, last_seen_at
            FROM application_graph_nodes
            WHERE target_id=$1 AND last_seen_at >= NOW() - INTERVAL '30 days'
            ORDER BY last_seen_at DESC, node_type, node_key
            LIMIT 30
            """,
            target_uuid,
        )
        graph_edges = await _savepoint_fetch(
            conn,
            """
            SELECT src_key, edge_type, dst_key, scan_id, last_seen_at
            FROM application_graph_edges
            WHERE target_id=$1 AND last_seen_at >= NOW() - INTERVAL '30 days'
            ORDER BY last_seen_at DESC, edge_type, src_key, dst_key
            LIMIT 40
            """,
            target_uuid,
        )
        attack_graph = {
            "nodes": [_json_safe_row(row) for row in graph_nodes],
            "edges": [_json_safe_row(row) for row in graph_edges],
            "truncated": len(graph_nodes) == 30 or len(graph_edges) == 40,
        }
    except Exception:
        hypotheses_summary = []
        ranked_hypotheses = []
        attack_graph = {"nodes": [], "edges": [], "truncated": False}

    try:
        async with _optional_database_savepoint(conn):
            scan_rows = await conn.fetch(
                """
                SELECT id, parent_scan_id, scan_role, scan_type, run_kind, status, target_url,
                       current_phase, findings_count, score, grade, options, result,
                       created_at,
                       COALESCE(completed_at, started_at, created_at) AS updated_at
                FROM scans
                WHERE target_id=$1
                  AND status IN ('completed','failed','cancelled')
                  AND (scan_role IS NULL OR scan_role <> 'shard')
                ORDER BY created_at DESC
                LIMIT 12
                """,
                target_uuid,
            )
            for row in scan_rows:
                scan = _json_safe_row(row)
                options = _sanitize_scan_options(scan.pop("options", None)) or {}
                result = _decode_json_value(scan.pop("result", None)) or {}
                discovery = result.get("discovery") if isinstance(result.get("discovery"), dict) else {}
                verification = (
                    result.get("verification_summary")
                    if isinstance(result.get("verification_summary"), dict)
                    else {}
                )
                scan["intent"] = {
                    key: options.get(key)
                    for key in (
                        "check_family", "asm_check_family", "auth_state", "kind",
                        "budget_profile", "exploit_depth", "parallel", "shard_strategy",
                    )
                    if options.get(key) not in (None, "", [], {})
                }
                scan["result_summary"] = {
                    "verified": verification.get("verified"),
                    "suspected": verification.get("suspected"),
                    "unproven_critical_high": verification.get("unproven_critical_high"),
                    "discovered_url_count": (
                        discovery.get("url_count") or discovery.get("total_urls")
                        or len(discovery.get("urls") or [])
                    ),
                    "partial": bool((result.get("scan_metadata") or {}).get("partial"))
                    if isinstance(result.get("scan_metadata"), dict) else False,
                }
                recent_scans.append(scan)
    except Exception:
        recent_scans = []

    current_gaps: list[dict[str, Any]] = []
    if req.include_gaps:
        current_gaps.append({
            "kind": "asm_coverage",
            "coverage": coverage,
        })
        untested = int(coverage.get("untested") or 0) if isinstance(coverage, dict) else 0
        stale = int(coverage.get("stale") or 0) if isinstance(coverage, dict) else 0
        if untested:
            current_gaps.append({"kind": "untested_endpoints", "count": untested, "next_safe_command": "asm.gaps"})
        if stale:
            current_gaps.append({"kind": "stale_endpoints", "count": stale, "next_safe_command": "asm.gaps"})

    worker_freshness = "unknown"
    try:
        worker_build_raw = get_redis().hgetall("shakerscan:worker_build") or {}
        worker_freshness = "registered" if worker_build_raw else "unknown"
    except Exception:
        worker_freshness = "unknown"

    allowed_commands, disallowed_commands = _active_commands_for_context()
    target_summary = {
        "target_id": str(target_uuid),
        "url": target_payload.get("url"),
        "origins": target_origins,
        "name": target_payload.get("name"),
        "root_domain": target_payload.get("root_domain"),
        "is_active": bool(target_payload.get("is_active")),
        "environment": metadata.get("environment") or metadata.get("env") or "unknown",
        "owner": metadata.get("owner") or metadata.get("asset_owner") or "unknown",
        "last_scanned_at": target_payload.get("last_scanned_at"),
        "last_score": target_payload.get("last_score"),
        "last_grade": target_payload.get("last_grade"),
    }
    current_surface = {
        "asm_enabled": bool(target_payload.get("asm_enabled")),
        "asm_last_test_at": target_payload.get("asm_last_test_at"),
        "asm_last_recon_at": target_payload.get("asm_last_recon_at"),
        "coverage": coverage,
        "endpoint_counts": [_json_safe_row(row) for row in endpoint_counts],
        "endpoint_source_counts": [_json_safe_row(row) for row in endpoint_source_counts],
        "sample_endpoints": sample_endpoints,
        "principal_matrix": principal_summary,
        "approved_invariant_contracts": approved_invariant_contracts,
        "invariant_candidate_contracts": invariant_candidate_contracts,
        "ranked_hypotheses": ranked_hypotheses,
        "known_vulnerability_count": len(known_vulnerability_keys) if 'known_vulnerability_keys' in locals() else 0,
        # Families whose every lead is already an owned finding — the planner should pivot away from
        # these to a net-new family rather than re-proposing suppressed leads.
        "exhausted_families": _research_exhausted_families(
            hypothesis_candidates, known_vulnerability_keys if 'known_vulnerability_keys' in locals() else set(),
        ),
        "attack_graph": attack_graph,
        # Bounded history includes normal DAST parents and internal ASM activities. Findings,
        # endpoint inventory, and graph remain the detailed canonical surfaces above.
        "recent_scans": recent_scans,
    }
    credential_preconditions = _target_credential_precondition_signals(
        principal_summary.get("principals", []),
        metadata,
    )
    known_preconditions = {
        "workers": worker_freshness,
        **credential_preconditions,
        "principal_roles": sorted(principal_summary.get("role_counts", {}).keys()),
        "principal_tenants": sorted(principal_summary.get("tenant_counts", {}).keys()),
        "scope": "target-bound",
    }
    hash_payload = {
        "target_summary": target_summary,
        "current_surface": current_surface,
        "current_gaps": current_gaps,
        "hypotheses_summary": hypotheses_summary,
        "findings_summary": findings_summary,
        "allowed_commands": allowed_commands,
        "disallowed_commands": disallowed_commands,
        "known_preconditions": known_preconditions,
    }
    return AgentContextPackRequest(
        target_id=str(target_uuid),
        context_hash=_canonical_context_hash(hash_payload),
        target_summary=target_summary,
        current_surface=current_surface,
        current_gaps=current_gaps,
        findings_summary=findings_summary,
        hypotheses_summary=hypotheses_summary,
        allowed_commands=allowed_commands,
        disallowed_commands=disallowed_commands,
        known_preconditions=known_preconditions,
        redaction_profile="agent-plan-generated-target",
        created_by=req.created_by,
    )


async def _validate_agent_decision_trace(conn, req: AgentDecisionTraceRequest) -> tuple[dict[str, Any], list[str], list[str], str]:
    original = req.model_dump(mode="json")
    payload = _canonical_agent_decision_trace(req)
    errors: list[str] = []
    warnings: list[str] = []
    if not re.fullmatch(r"[a-f0-9]{64}", str(payload.get("context_hash") or "")):
        errors.append("context_hash_must_be_sha256_hex")
    if _contains_forbidden_context_key(original):
        errors.append("decision_trace_contains_forbidden_raw_or_secret_field")
    if not payload.get("steps"):
        errors.append("steps_required")
    commands = _operation_plan_allowed_commands()
    for index, step in enumerate(payload.get("steps") or []):
        command_name = step.get("command")
        if command_name and command_name not in commands:
            errors.append(f"step_{index}_unknown_command:{command_name}")
        if step.get("kind") == "executed_action":
            errors.append(f"step_{index}_executed_action_not_allowed_in_dry_run_trace")
    context_pack_id = str(payload.get("context_pack_id") or "").strip()
    if context_pack_id:
        try:
            context_uuid = uuid.UUID(context_pack_id)
        except ValueError:
            errors.append("context_pack_id_must_be_uuid")
        else:
            context_row = await conn.fetchrow("SELECT * FROM agent_context_packs WHERE id=$1", context_uuid)
            if not context_row:
                errors.append("context_pack_not_found")
            elif str(context_row["context_hash"] or "").lower() != payload["context_hash"]:
                errors.append("context_pack_hash_mismatch")
            payload["context_pack_id"] = str(context_uuid)
    else:
        payload["context_pack_id"] = None
        warnings.append("context_pack_id_missing")
    operation_plan_id = str(payload.get("operation_plan_id") or "").strip()
    if operation_plan_id:
        try:
            plan_uuid = uuid.UUID(operation_plan_id)
        except ValueError:
            errors.append("operation_plan_id_must_be_uuid")
        else:
            plan_row = await conn.fetchrow("SELECT context_hash FROM operation_plans WHERE id=$1", plan_uuid)
            if not plan_row:
                errors.append("operation_plan_not_found")
            elif str(plan_row["context_hash"] or "").lower() != payload["context_hash"]:
                errors.append("operation_plan_hash_mismatch")
            payload["operation_plan_id"] = str(plan_uuid)
    else:
        payload["operation_plan_id"] = None
    if not payload.get("final_rationale"):
        warnings.append("final_rationale_empty")
    return payload, errors, warnings, "invalid" if errors else "recorded"


async def _persist_operation_plan(conn, req: OperationPlanRequest) -> dict[str, Any]:
    payload, errors, warnings, status = await _validate_operation_plan(conn, req)
    scope_id = str(payload.get("scope_receipt_id") or "").strip() or None
    approval_id = str(payload.get("approval_receipt_id") or "").strip() or None
    row = await conn.fetchrow(
        """
        INSERT INTO operation_plans (
            objective, planner, context_hash, target_scope, risk_tier, actions,
            confirmations, missing_inputs, stop_conditions, success_criteria,
            status, validation_errors, validation_warnings, scope_receipt_id,
            approval_receipt_id, plan_json, created_by
        ) VALUES (
            $1,$2::jsonb,$3,$4::jsonb,$5,$6::jsonb,
            $7::jsonb,$8::jsonb,$9::jsonb,$10::jsonb,
            $11,$12::jsonb,$13::jsonb,$14,$15,$16::jsonb,$17
        )
        RETURNING *
        """,
        payload["objective"],
        json.dumps(payload.get("planner") or {}),
        payload["context_hash"],
        json.dumps(payload.get("target_scope") or {}),
        payload["risk_tier"],
        json.dumps(payload.get("actions") or []),
        json.dumps(payload.get("confirmations") or []),
        json.dumps(payload.get("missing_inputs") or []),
        json.dumps(payload.get("stop_conditions") or []),
        json.dumps(payload.get("success_criteria") or []),
        status,
        json.dumps(errors),
        json.dumps(warnings),
        scope_id,
        uuid.UUID(approval_id) if approval_id else None,
        json.dumps(payload),
        str(payload.get("created_by") or "").strip() or None,
    )
    return {
        "operation_plan": _public_operation_plan_row(row),
        "execution_enabled": False,
        "validated": not errors,
    }


def _source_files_to_hints(
    files: Sequence[SourceIngestFile | dict[str, Any]],
    *,
    source_label: str,
    max_files: int,
    max_file_bytes: int,
    ignored_paths: Sequence[str] | None,
    parse_timeout_ms: int,
    max_hints: int = 50,
) -> tuple[list[SourceIngestHint], list[dict[str, Any]], dict[str, Any]]:
    started = time.monotonic()
    deadline = started + max(0.1, float(parse_timeout_ms) / 1000.0)
    hints: list[SourceIngestHint] = []
    skipped: list[dict[str, Any]] = []
    processed = 0
    for index, item in enumerate(files or []):
        if index >= max_files:
            skipped.append({"index": index, "reason": "max_files_exceeded"})
            continue
        if time.monotonic() > deadline:
            skipped.append({"index": index, "reason": "parse_timeout"})
            break
        payload = item.model_dump(mode="json") if isinstance(item, SourceIngestFile) else dict(item or {})
        path = str(payload.get("path") or "").strip()
        content = str(payload.get("content") or "")
        if not path:
            skipped.append({"index": index, "reason": "missing_path"})
            continue
        if _source_ingest_path_ignored(path, ignored_paths):
            skipped.append({"index": index, "path": path, "reason": "ignored_path"})
            continue
        size = len(content.encode("utf-8", "ignore"))
        if size > max_file_bytes:
            skipped.append({"index": index, "path": path, "size_bytes": size, "reason": "file_too_large"})
            continue
        processed += 1
        generated = []
        lower_path = path.lower()
        if lower_path.endswith(".json"):
            generated.extend(_openapi_file_hints(path, content, source_label))
        generated.extend(_route_file_hints(path, content, source_label, payload.get("language")))
        if not generated:
            skipped.append({"index": index, "path": path, "reason": "no_source_hints_extracted"})
            continue
        remaining = max_hints - len(hints)
        hints.extend(generated[:remaining])
        if len(generated) > remaining:
            skipped.append({"index": index, "path": path, "reason": "max_hints_exceeded", "generated": len(generated)})
        if len(hints) >= max_hints:
            break
    return hints, skipped, {
        "files_seen": len(files or []),
        "files_processed": processed,
        "hints_generated": len(hints),
        "max_files": max_files,
        "max_file_bytes": max_file_bytes,
        "parse_timeout_ms": parse_timeout_ms,
        "ignored_path_count": len([item for item in skipped if item.get("reason") == "ignored_path"]),
        "execution_enabled": False,
        "runtime_proof_required": True,
    }


def _source_hint_to_hypothesis_request(
    hint: SourceIngestHint | dict[str, Any],
    *,
    target_id: str | None,
    source_label: str,
    created_by: str | None,
) -> tuple[HypothesisRequest | None, dict[str, Any] | None]:
    hint_payload = hint.model_dump(mode="json") if isinstance(hint, SourceIngestHint) else dict(hint or {})
    route = _source_hint_route(hint_payload)
    kind = str(hint_payload.get("kind") or "route").strip().lower()
    if kind not in {"package_manifest", "iac_resource"} and not route:
        return None, {"reason": "missing_route_or_path", "hint_kind": kind, "operation_id": hint_payload.get("operation_id")}

    try:
        family, cwe, rationale, action, requires = _source_hint_family_and_action(hint_payload, target_id=target_id)
    except Exception as exc:
        return None, {"reason": "hint_mapping_failed", "error": str(exc), "hint_kind": kind}

    method = str(hint_payload.get("method") or "GET").strip().upper()
    hint_metadata = hint_payload.get("metadata_json") if isinstance(hint_payload.get("metadata_json"), dict) else {}
    subject_hint = (
        route
        or hint_payload.get("operation_id")
        or hint_payload.get("title")
        or hint_metadata.get("package")
        or hint_metadata.get("package_name")
        or hint_metadata.get("resource")
        or hint_metadata.get("resource_id")
        or hint_metadata.get("name")
        or kind
    )
    parameters = _clean_string_list(hint_payload.get("parameters"), max_items=50)
    body_paths = _clean_string_list(hint_payload.get("body_paths"), max_items=50)
    object_keys = _clean_string_list(hint_payload.get("object_keys"), max_items=20)
    tenant_keys = _clean_string_list(hint_payload.get("tenant_keys"), max_items=20)
    parameter_path = parameters[0] if parameters else None
    body_path = body_paths[0] if body_paths else None
    proof_surface = str(action.get("proof_surface") or "runtime_proof_required")
    dedupe_dimensions = {
        "method": method,
        "route": subject_hint,
        "object_key": object_keys[0] if object_keys else None,
        "tenant": tenant_keys[0] if tenant_keys else None,
        "parameter_path": parameter_path,
        "body_path": body_path,
        "proof_surface": proof_surface,
    }
    dedupe_dimensions = {key: value for key, value in dedupe_dimensions.items() if value}
    metadata = _redact_agent_payload({
        "source_ingest_version": SOURCE_INGEST_VERSION,
        "source_label": source_label,
        "source_only": True,
        "runtime_proof_required": True,
        "hint_kind": kind,
        "operation_id": hint_payload.get("operation_id"),
        "risk_hints": _clean_string_list(hint_payload.get("risk_hints"), max_items=20),
        "parameters": parameters,
        "body_paths": body_paths,
        "object_keys": object_keys,
        "tenant_keys": tenant_keys,
        "roles": _clean_string_list(hint_payload.get("roles"), max_items=20),
        "auth_required": hint_payload.get("auth_required"),
        "rationale": rationale,
        "requires": requires,
        "dedupe_dimensions": dedupe_dimensions,
        "hint_metadata": hint_metadata,
    })
    title = (
        str(hint_payload.get("title") or "").strip()
        or f"Source hint: {family.replace('_', ' ')} on {method} {subject_hint}"
    )
    description = (
        str(hint_payload.get("description") or "").strip()
        or f"{rationale} Source/spec facts are planning context only and do not satisfy runtime proof."
    )
    return HypothesisRequest(
        source="source_ingest",
        family=family,
        dedupe_key="source-ingest-placeholder",
        dedupe_dimensions=dedupe_dimensions,
        target_id=target_id,
        cwe=cwe,
        title=title,
        description=description,
        severity_guess=hint_payload.get("severity_guess") or ("high" if family in {"bola", "ssrf", "lfi", "dangerous_upload"} else "medium"),
        confidence=float(hint_payload.get("confidence") if hint_payload.get("confidence") is not None else 0.35),
        next_test_action=action,
        endorsement={
            "source": "source_ingest",
            "source_label": source_label,
            "created_by": created_by,
            "confidence": hint_payload.get("confidence"),
            "runtime_proof_required": True,
        },
        metadata_json=metadata,
        created_by=created_by,
    ), None


async def _generate_hypotheses_from_operation_plan(conn, req: PlannerHypothesisRequest) -> dict[str, Any]:
    try:
        plan_uuid = uuid.UUID(str(req.operation_plan_id))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="operation_plan_id must be a UUID") from exc
    row = await conn.fetchrow("SELECT * FROM operation_plans WHERE id=$1", plan_uuid)
    if not row:
        raise HTTPException(status_code=404, detail="Operation plan not found")
    plan = _public_operation_plan_row(row)
    actions = plan.get("actions") if isinstance(plan.get("actions"), list) else []
    created_by = str(req.created_by or plan.get("created_by") or "ai_planner").strip() or "ai_planner"
    hypotheses: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for index, action in enumerate(actions[: req.max_actions]):
        if not isinstance(action, dict):
            skipped.append({"reason": "action_not_object", "action_index": index})
            continue
        hypothesis_req, skip = _planner_action_to_hypothesis_request(
            plan,
            action,
            operation_plan_id=str(plan_uuid),
            action_index=index,
            created_by=created_by,
        )
        if skip:
            skipped.append(skip)
            continue
        if not hypothesis_req:
            skipped.append({"reason": "no_hypothesis_generated", "action_index": index})
            continue
        result = await _upsert_hypothesis(conn, hypothesis_req)
        hypotheses.append(result["hypothesis"])
    if len(actions) > req.max_actions:
        skipped.append({"reason": "max_actions_exceeded", "skipped_count": len(actions) - req.max_actions})
    return {
        "operation_plan_id": str(plan_uuid),
        "hypotheses": hypotheses,
        "created_or_endorsed": len(hypotheses),
        "skipped": skipped,
        "skipped_count": len(skipped),
        "execution_enabled": False,
        "findings_created": 0,
        "queued_scans": 0,
        "runtime_proof_required": True,
    }


async def _generate_hypotheses_from_benchmark_followups(conn, req: BenchmarkHypothesisRequest) -> dict[str, Any]:
    target_uuid: uuid.UUID | None = None
    if req.target_id:
        try:
            target_uuid = uuid.UUID(str(req.target_id))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="target_id must be a UUID") from exc
        if not await conn.fetchval("SELECT 1 FROM targets WHERE id=$1", target_uuid):
            raise HTTPException(status_code=404, detail="Target not found")
    created_by = str(req.created_by or "benchmark").strip() or "benchmark"
    hypotheses: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for index, item in enumerate(req.followups):
        hypothesis_req, skip = _benchmark_followup_to_hypothesis_request(
            item,
            target_id=str(target_uuid) if target_uuid else None,
            benchmark=req.benchmark,
            scorecard_id=req.scorecard_id,
            scorecard_scan_id=req.scorecard_scan_id,
            created_by=created_by,
        )
        if skip:
            skipped.append({"index": index, **skip})
            continue
        if not hypothesis_req:
            skipped.append({"index": index, "reason": "no_hypothesis_generated"})
            continue
        result = await _upsert_hypothesis(conn, hypothesis_req)
        hypotheses.append(result["hypothesis"])
    return {
        "benchmark": req.benchmark,
        "scorecard_id": req.scorecard_id,
        "scorecard_scan_id": req.scorecard_scan_id,
        "hypotheses": hypotheses,
        "created_or_endorsed": len(hypotheses),
        "skipped": skipped,
        "skipped_count": len(skipped),
        "execution_enabled": False,
        "findings_created": 0,
        "queued_scans": 0,
        "runtime_proof_required": True,
    }


async def _append_hypothesis_signal(conn, hypothesis_id: str, req: HypothesisSignalRequest) -> dict[str, Any]:
    try:
        hypothesis_uuid = uuid.UUID(str(hypothesis_id))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="hypothesis_id must be a UUID") from exc
    signal = _canonical_hypothesis_signal(req)
    column = "endorsements" if signal["signal_type"] == "endorsement" else "refutations"
    row = await conn.fetchrow(
        f"""
        UPDATE hypotheses
        SET {column} = {column} || jsonb_build_array($2::jsonb),
            version = version + 1,
            updated_at = NOW()
        WHERE id = $1
        RETURNING *
        """,
        hypothesis_uuid,
        json.dumps(signal),
    )
    if not row:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    return {
        "hypothesis": _public_hypothesis_row(row),
        "signal": signal,
        "execution_enabled": False,
        "findings_updated": 0,
    }


async def _load_refuter_work_summary(conn, *, limit: int = 20, finding_window: int = 200) -> dict[str, Any]:
    findings = await conn.fetch(
        """
        SELECT *
        FROM findings
        WHERE status = 'active'
          AND (
            severity IN ('critical', 'high')
            OR source IN ('ai_gate', 'model_intake')
            OR ai_target_id IS NOT NULL
            OR tool = 'model_intake'
          )
        ORDER BY
          CASE severity
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 4
            ELSE 5
          END,
          last_seen_at DESC NULLS LAST,
          first_seen_at DESC NULLS LAST
        LIMIT $1
        """,
        finding_window,
    )
    reviews = await conn.fetch(
        """
        SELECT subject_type, subject_id, finding_id
        FROM refuter_reviews
        ORDER BY created_at DESC
        LIMIT $1
        """,
        max(finding_window, limit),
    )
    # Recent operator-facing web-DAST scans per target (newest first, shards excluded) for
    # the finding-delta integrity heuristic. Windowed per target so the scan set is bounded.
    scan_rows = await conn.fetch(
        """
        SELECT target_id, target_url, scan_id, findings_count
        FROM (
            SELECT target_id, target_url, id AS scan_id, findings_count,
                   ROW_NUMBER() OVER (PARTITION BY target_id ORDER BY created_at DESC) AS rn
            FROM scans
            WHERE status = 'completed'
              AND run_kind = 'web_dast'
              AND target_id IS NOT NULL
              AND (scan_role IS NULL OR scan_role <> 'shard')
        ) ranked
        WHERE rn <= $1
        ORDER BY target_id, rn
        """,
        REFUTER_FINDING_DELTA_MIN_BASELINE + 4,
    )
    integrity_signals = _finding_delta_refuter_signals(
        _finding_delta_target_stats(scan_rows), limit=limit
    )
    benchmark_signals = _benchmark_win_delta_refuter_signals(
        _load_benchmark_scorecard_artifacts(limit=max(limit, 10)),
        limit=limit,
    )
    integrity_signals = list(integrity_signals) + list(benchmark_signals)
    return _refuter_work_summary(findings, reviews, limit=limit, integrity_signals=integrity_signals)


def _refuter_review_requests_from_summary(
    summary: dict[str, Any],
    *,
    include_integrity_signals: bool = False,
    created_by: str | None = "refuter_auto_queue",
) -> list[RefuterReviewRequest]:
    requests: list[RefuterReviewRequest] = []
    for candidate in summary.get("candidates") or []:
        if not isinstance(candidate, dict) or candidate.get("already_reviewed"):
            continue
        recommended = candidate.get("recommended_review") if isinstance(candidate.get("recommended_review"), dict) else {}
        if not recommended:
            continue
        metadata = {
            "queued_from_summary": True,
            "trigger_type": candidate.get("trigger_type"),
            "trigger_reasons": candidate.get("trigger_reasons") or [],
            "source": candidate.get("source"),
            "tool": candidate.get("tool"),
            "proof_state": candidate.get("proof_state"),
            "automation_plan": candidate.get("automation_plan") if isinstance(candidate.get("automation_plan"), dict) else {},
        }
        requests.append(
            RefuterReviewRequest(
                subject_type=str(recommended.get("subject_type") or candidate.get("subject_type") or "finding"),
                subject_id=recommended.get("subject_id") or candidate.get("subject_id"),
                target_id=candidate.get("target_id"),
                finding_id=recommended.get("finding_id") or candidate.get("finding_id"),
                trigger_reason=str(recommended.get("trigger_reason") or "; ".join(candidate.get("trigger_reasons") or [])),
                refuter_signal=str(recommended.get("refuter_signal") or "question"),
                verdict_basis=str(recommended.get("verdict_basis") or "signal_only"),
                metadata_json=metadata,
                created_by=created_by,
            )
        )
    if include_integrity_signals:
        for signal in summary.get("integrity_signals") or []:
            if not isinstance(signal, dict) or signal.get("already_reviewed"):
                continue
            subject_type = str(signal.get("subject_type") or "manual")
            if subject_type not in {"target", "benchmark"}:
                subject_type = "manual"
            subject_id = str(signal.get("subject_id") or "").strip() or None
            if not subject_id:
                continue
            requests.append(
                RefuterReviewRequest(
                    subject_type=subject_type,
                    subject_id=subject_id,
                    target_id=signal.get("target_id"),
                    trigger_reason=str(
                        signal.get("review_hint")
                        or "; ".join(signal.get("trigger_reasons") or [])
                        or signal.get("trigger_type")
                        or "integrity signal requires review"
                    ),
                    refuter_signal="question",
                    verdict_basis="signal_only",
                    metadata_json={
                        "queued_from_summary": True,
                        "queued_integrity_signal": True,
                        "trigger_type": signal.get("trigger_type"),
                        "trigger_reasons": signal.get("trigger_reasons") or [],
                        "integrity_signal": signal,
                        "execution_enabled": False,
                    },
                    created_by=created_by,
                )
            )
    return requests


async def _refuter_verification_reference_valid(
    conn,
    *,
    verification_id: Any,
    finding_uuid: uuid.UUID | None,
    target_uuid: uuid.UUID | None,
    hypothesis: dict[str, Any] | None = None,
) -> bool:
    """Re-derive a terminal refutation from its durable verification, never from stored labels."""
    if not verification_id or (finding_uuid is None and not hypothesis):
        return False
    try:
        verification_uuid = uuid.UUID(str(verification_id))
    except ValueError:
        return False
    row = await conn.fetchrow(
        """
        SELECT * FROM finding_verifications
        WHERE id=$1 AND ($2::uuid IS NULL OR finding_id=$2)
          AND ($3::uuid IS NULL OR target_id=$3)
        """,
        verification_uuid,
        finding_uuid,
        target_uuid,
    )
    verification = row_to_dict(row) if row else {}
    if not verification or str(verification.get("status") or "").lower() != "completed":
        return False
    if hypothesis:
        verification_finding_id = _optional_uuid(verification.get("finding_id"))
        hypothesis_target_id = _optional_uuid(hypothesis.get("target_id"))
        if verification_finding_id is None or hypothesis_target_id is None:
            return False
        finding_row = await conn.fetchrow("SELECT * FROM findings WHERE id=$1", verification_finding_id)
        finding = row_to_dict(finding_row) if finding_row else {}
        if (
            not finding
            or _optional_uuid(finding.get("target_id")) != hypothesis_target_id
            or not _hypothesis_family_matches_finding(hypothesis, finding)
            or not _hypothesis_subject_matches_finding(hypothesis, finding)
        ):
            return False
    outcome = _refuter_review_from_verification_outcome(verification)
    proof_backed = bool(
        _decode_json_value(verification.get("proof"))
        or _decode_json_value(verification.get("artifacts"))
    )
    return bool(
        outcome.get("deterministic_basis") is True
        and outcome.get("refuter_verdict") == "refuted"
        and proof_backed
    )


async def _record_refuter_review(conn, req: RefuterReviewRequest) -> dict[str, Any]:
    payload = _canonical_refuter_review(req)
    try:
        target_uuid = _optional_uuid(payload.get("target_id"))
        finding_uuid = _optional_uuid(payload.get("finding_id"))
        hypothesis_uuid = _optional_uuid(payload.get("hypothesis_id"))
        campaign_uuid = _optional_uuid(payload.get("campaign_id"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="target_id, finding_id, hypothesis_id, and campaign_id must be UUIDs when provided") from exc
    if payload["subject_type"] == "finding" and not (finding_uuid or payload.get("subject_id")):
        raise HTTPException(status_code=400, detail="finding refuter review requires finding_id or subject_id")
    if payload["subject_type"] == "hypothesis" and not (hypothesis_uuid or payload.get("subject_id")):
        raise HTTPException(status_code=400, detail="hypothesis refuter review requires hypothesis_id or subject_id")
    if payload.get("refuter_verdict") == "refuted":
        counter = payload.get("counterevidence") if isinstance(payload.get("counterevidence"), dict) else {}
        verification_id = str(counter.get("verification_id") or "").strip()
        reference_valid = bool(
            payload.get("subject_type") == "finding"
            and await _refuter_verification_reference_valid(
                conn,
                verification_id=verification_id,
                finding_uuid=finding_uuid,
                target_uuid=target_uuid,
            )
        )
        if not reference_valid:
            payload["metadata_json"] = {
                **(payload.get("metadata_json") or {}),
                "negative_gate": {
                    "downgraded": True,
                    "reason": "refute_reference_not_verified",
                    "original_verdict": "refuted",
                    "verification_id": verification_id or None,
                },
            }
            payload["refuter_verdict"] = "inconclusive"
            payload["refuter_signal"] = "question"
            payload["status"] = "verdict_recorded"
    row = await conn.fetchrow(
        """
        INSERT INTO refuter_reviews (
            subject_type, subject_id, target_id, finding_id, hypothesis_id, campaign_id,
            trigger_reason, refuter_signal, refuter_verdict, verdict_basis,
            confidence_delta, evidence_object_ids, tool_receipt_ids, counterevidence,
            notes, status, metadata_json, created_by
        ) VALUES (
            $1,$2,$3,$4,$5,$6,
            $7,$8,$9,$10,
            $11,$12::jsonb,$13::jsonb,$14::jsonb,
            $15,$16,$17::jsonb,$18
        )
        RETURNING *
        """,
        payload["subject_type"],
        payload.get("subject_id"),
        target_uuid,
        finding_uuid,
        hypothesis_uuid,
        campaign_uuid,
        payload["trigger_reason"],
        payload["refuter_signal"],
        payload.get("refuter_verdict"),
        payload["verdict_basis"],
        payload.get("confidence_delta"),
        json.dumps(payload.get("evidence_object_ids") or []),
        json.dumps(payload.get("tool_receipt_ids") or []),
        json.dumps(payload.get("counterevidence") or {}),
        payload.get("notes"),
        payload["status"],
        json.dumps(payload.get("metadata_json") or {}),
        payload.get("created_by"),
    )
    return {
        "refuter_review": _public_refuter_review_row(row),
        "execution_enabled": False,
        "findings_updated": 0,
        "hypotheses_updated": 0,
    }


def _public_tool_receipt_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    for key in ("redacted_argv", "parsed_evidence_instance_ids"):
        payload[key] = _decode_json_value(payload.get(key)) or []
    for key in ("target_scope", "budget_json", "metadata_json"):
        payload[key] = _redact_agent_payload(_decode_json_value(payload.get(key)) or {})
    payload["execution_enabled"] = False
    payload["findings_created"] = 0
    payload["verified_findings_created"] = 0
    return payload


async def _persist_campaign(conn, req: CampaignRequest) -> dict[str, Any]:
    """Validate and persist a §7 mission campaign record.

    A campaign is the operating wrapper over ASM/scan/AI Gate/Model Intake/retest
    actions. It is a planning/audit record only: creating one queues no work and
    creates no findings.
    """
    target_uuid = None
    if req.target_id:
        try:
            target_uuid = uuid.UUID(str(req.target_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="target_id must be a UUID when supplied")
        if not await conn.fetchval("SELECT 1 FROM targets WHERE id=$1", target_uuid):
            raise HTTPException(status_code=404, detail="Target not found")
    plan_uuid = None
    if req.operation_plan_id:
        try:
            plan_uuid = uuid.UUID(str(req.operation_plan_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="operation_plan_id must be a UUID when supplied")
        if not await conn.fetchval("SELECT 1 FROM operation_plans WHERE id=$1", plan_uuid):
            raise HTTPException(status_code=404, detail="Operation plan not found")
    context_hash = str(req.context_hash or "").strip().lower() or None
    if context_hash and not re.fullmatch(r"[a-f0-9]{64}", context_hash):
        raise HTTPException(status_code=400, detail="context_hash must be sha256 hex when supplied")

    row = await conn.fetchrow(
        """
        INSERT INTO campaigns (
            name, objective, campaign_type, target_id, target_scope, risk_tier,
            policy_profile, planner, operation_plan_id, context_hash, status,
            deployment_impact, metadata_json, created_by
        ) VALUES (
            $1,$2,$3,$4,$5::jsonb,$6,
            $7,$8::jsonb,$9,$10,$11,
            $12::jsonb,$13::jsonb,$14
        )
        RETURNING *
        """,
        str(req.name or "").strip() or None,
        req.objective.strip(),
        req.campaign_type,
        target_uuid,
        json.dumps(_redact_agent_payload(req.target_scope or {})),
        req.risk_tier,
        str(req.policy_profile or "").strip() or None,
        json.dumps(_redact_agent_payload(req.planner or {})),
        plan_uuid,
        context_hash,
        req.status,
        json.dumps(req.deployment_impact or {}),
        json.dumps(_redact_agent_payload(req.metadata_json or {})),
        str(req.created_by or "").strip() or None,
    )
    return _public_campaign_row(row)


async def _reconcile_hypothesis_proof(
    conn: Any,
    hypothesis_id: str,
    req: HypothesisProofReconcileRequest,
) -> dict[str, Any]:
    """Promote a hypothesis only by linking proof-backed findings from its action."""
    hypothesis_uuid = _uuid_or_400(hypothesis_id, "hypothesis id")
    hypothesis_row = await conn.fetchrow("SELECT * FROM hypotheses WHERE id=$1", hypothesis_uuid)
    if not hypothesis_row:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    hypothesis = _public_hypothesis_row(hypothesis_row)
    if int(hypothesis.get("version") or 0) != req.expected_version:
        raise HTTPException(status_code=409, detail={"error": "hypothesis_version_conflict", "version": hypothesis.get("version")})
    if hypothesis.get("effective_status") in {"refuted", "dead"}:
        raise HTTPException(status_code=409, detail="Refuted or dead hypotheses cannot be promoted")

    target_uuid = _optional_uuid(hypothesis.get("target_id"))
    if not target_uuid:
        raise HTTPException(status_code=400, detail="Proof reconciliation requires a target-bound hypothesis")
    target_row = await conn.fetchrow("SELECT id, url FROM targets WHERE id=$1", target_uuid)
    if not target_row:
        raise HTTPException(status_code=404, detail="Target not found")
    await _validate_approval_receipt_for_action(
        conn,
        req.approval_receipt_id,
        target_url=str(row_to_dict(target_row).get("url") or "").strip() or None,
        target_id=target_uuid,
        action_name="hypothesis.reconcile_proof",
        command="hypothesis.reconcile_proof",
        risk_tier="active",
        created_by=req.created_by,
        always_require_receipt=True,
    )

    action_uuid = _optional_uuid(req.campaign_action_id or hypothesis.get("campaign_action_id"))
    if not action_uuid:
        raise HTTPException(status_code=400, detail="Hypothesis has no campaign action to reconcile")
    action_row = await conn.fetchrow(
        """
        SELECT ca.*, cr.command AS executed_command,
               cr.status AS executed_status,
               cr.finding_ids AS executed_finding_ids,
               cr.result_json AS executed_result_json
        FROM campaign_actions ca
        LEFT JOIN command_results cr ON cr.id = ca.command_result_id
        WHERE ca.id=$1
        """,
        action_uuid,
    )
    if not action_row:
        raise HTTPException(status_code=404, detail="Campaign action not found")
    action = _public_campaign_action_row(action_row)
    linked_hypotheses = {str(item) for item in action.get("hypothesis_ids") or []}
    if str(hypothesis_uuid) not in linked_hypotheses and str(hypothesis.get("campaign_action_id") or "") != str(action_uuid):
        raise HTTPException(status_code=409, detail="Campaign action is not linked to this hypothesis")
    if _optional_uuid(action.get("target_id")) != target_uuid:
        raise HTTPException(status_code=409, detail="Campaign action target does not match hypothesis target")

    executed_finding_ids = _clean_string_list(_decode_json_value(action_row.get("executed_finding_ids")) or [], max_items=200)
    candidate_ids = _clean_string_list((action.get("finding_ids") or []) + executed_finding_ids, max_items=200)
    candidate_uuids = [_optional_uuid(item) for item in candidate_ids]
    candidate_uuids = [item for item in candidate_uuids if item]
    scan_uuid = _optional_uuid(action.get("scan_id"))
    scan_status = None
    if scan_uuid:
        scan_status = await conn.fetchval("SELECT status FROM scans WHERE id=$1", scan_uuid)
    if scan_uuid:
        finding_rows = await conn.fetch(
            """
            SELECT id, target_id, scan_id, fingerprint, title, tool, cwe, severity,
                   status, url, evidence, request, response,
                   last_verification_status, last_verification_verdict,
                   last_verification_confidence, updated_at
            FROM findings
            WHERE scan_id=$1 OR id=ANY($2::uuid[])
            ORDER BY updated_at DESC
            LIMIT 200
            """,
            scan_uuid,
            candidate_uuids,
        )
    elif candidate_uuids:
        finding_rows = await conn.fetch(
            """
            SELECT id, target_id, scan_id, fingerprint, title, tool, cwe, severity,
                   status, url, evidence, request, response,
                   last_verification_status, last_verification_verdict,
                   last_verification_confidence, updated_at
            FROM findings
            WHERE id=ANY($1::uuid[])
            ORDER BY updated_at DESC
            LIMIT 200
            """,
            candidate_uuids,
        )
    else:
        finding_rows = []

    executed_result = _decode_json_value(action_row.get("executed_result_json")) or {}
    verification_ids = _hypothesis_verification_ids(executed_result)
    verification_rows = []
    if verification_ids:
        verification_rows = await conn.fetch(
            """
            SELECT id, finding_id, status, verdict, verification_mode, proof, artifacts
            FROM finding_verifications
            WHERE id=ANY($1::uuid[])
            """,
            list(verification_ids),
        )
    verified_by_retest = {
        str(row["finding_id"])
        for row in verification_rows
        if str(row.get("status") or "").lower() == "completed"
        and str(row.get("verdict") or "").lower() == "exploited"
        and str(row.get("verification_mode") or "deterministic").lower() == "deterministic"
    }
    executed_command = str(action_row.get("executed_command") or "").strip()
    direct_proof_command = executed_command in {"authz.promote_replay_finding"}

    promoted: list[dict[str, Any]] = []
    rejected_counts: Counter[str] = Counter()
    for row in finding_rows:
        finding = row_to_dict(row)
        finding_id = str(finding.get("id") or "")
        if _optional_uuid(finding.get("target_id")) != target_uuid:
            rejected_counts["target_mismatch"] += 1
            continue
        if _finding_routes.finding_proof_fields(finding).get("proof_state") != "verified":
            rejected_counts["deterministic_proof_missing"] += 1
            continue
        scan_provenance = bool(
            scan_uuid
            and _optional_uuid(finding.get("scan_id")) == scan_uuid
            and str(scan_status or "").lower() == "completed"
        )
        retest_provenance = finding_id in verified_by_retest
        direct_provenance = bool(direct_proof_command and finding_id in set(candidate_ids))
        if not (scan_provenance or retest_provenance or direct_provenance):
            rejected_counts["action_provenance_missing"] += 1
            continue
        if not _hypothesis_family_matches_finding(hypothesis, finding):
            rejected_counts["family_mismatch"] += 1
            continue
        if not _hypothesis_dimensions_match_finding(hypothesis, finding):
            rejected_counts["dedupe_dimensions_mismatch"] += 1
            continue
        promoted.append({
            "finding_id": finding_id,
            "fingerprint": finding.get("fingerprint"),
            "proof_state": "verified",
            "proof_provenance": (
                "campaign_scan" if scan_provenance else "deterministic_retest" if retest_provenance else "gated_authz_promotion"
            ),
        })

    promoted_ids = [item["finding_id"] for item in promoted]
    evidence_rows = []
    if promoted_ids:
        evidence_rows = await conn.fetch(
            "SELECT id FROM evidence_objects WHERE finding_id=ANY($1::uuid[]) ORDER BY created_at DESC LIMIT 200",
            [uuid.UUID(item) for item in promoted_ids],
        )
    evidence_ids = [str(row["id"]) for row in evidence_rows]
    reconciliation = {
        "reconciled_at": datetime.now(timezone.utc).isoformat(),
        "campaign_action_id": str(action_uuid),
        "command_result_id": str(action.get("command_result_id") or "") or None,
        "scan_id": str(scan_uuid) if scan_uuid else None,
        "scan_status": scan_status,
        "candidate_count": len(finding_rows),
        "promoted_finding_ids": promoted_ids,
        "promotions": promoted,
        "rejected_counts": dict(rejected_counts),
        "proof_required": "existing deterministic verified finding with exact action provenance",
        "finding_created": False,
    }
    update_status = "promoted" if promoted_ids else str(hypothesis.get("status") or "open")
    terminal_reason = "deterministic_action_proof_reconciled" if promoted_ids else hypothesis.get("terminal_reason")
    updated_row = await conn.fetchrow(
        """
        UPDATE hypotheses
        SET status=$1,
            promoted_finding_ids=(
                SELECT COALESCE(jsonb_agg(DISTINCT value), '[]'::jsonb)
                FROM jsonb_array_elements_text(promoted_finding_ids || $2::jsonb) AS value
            ),
            evidence_object_ids=(
                SELECT COALESCE(jsonb_agg(DISTINCT value), '[]'::jsonb)
                FROM jsonb_array_elements_text(evidence_object_ids || $3::jsonb) AS value
            ),
            tool_receipt_ids=(
                SELECT COALESCE(jsonb_agg(DISTINCT value), '[]'::jsonb)
                FROM jsonb_array_elements_text(tool_receipt_ids || $4::jsonb) AS value
            ),
            metadata_json=metadata_json || $5::jsonb,
            terminal_reason=$6,
            claim_owner=CASE WHEN $1='promoted' THEN NULL ELSE claim_owner END,
            claim_lease_expires_at=CASE WHEN $1='promoted' THEN NULL ELSE claim_lease_expires_at END,
            version=version+1,
            updated_at=NOW()
        WHERE id=$7 AND version=$8 AND status NOT IN ('refuted','dead')
        RETURNING *
        """,
        update_status,
        json.dumps(promoted_ids),
        json.dumps(evidence_ids),
        json.dumps(action.get("tool_receipt_ids") or []),
        json.dumps({"latest_proof_reconciliation": reconciliation}),
        terminal_reason,
        hypothesis_uuid,
        req.expected_version,
    )
    if not updated_row:
        raise HTTPException(status_code=409, detail="Hypothesis changed while proof was being reconciled")
    result_status = "completed" if promoted_ids else "partial"
    command_result = await _record_command_result(
        conn,
        command="hypothesis.reconcile_proof",
        status=result_status,
        risk_tier="active",
        approval_receipt_id=req.approval_receipt_id,
        finding_ids=promoted_ids,
        hypothesis_ids=[str(hypothesis_uuid)],
        evidence_object_ids=evidence_ids,
        tool_receipt_ids=_clean_string_list(action.get("tool_receipt_ids"), max_items=200),
        result_json={"proof_reconciliation": reconciliation},
        operator_message=(
            f"Promoted hypothesis from {len(promoted_ids)} deterministic proof-backed finding(s)."
            if promoted_ids
            else "No exact deterministic proof-backed finding was eligible; hypothesis remains open."
        ),
        next_action=f"/findings/{promoted_ids[0]}" if promoted_ids else "/settings/arsenal?tab=hypotheses",
        created_by=req.created_by,
    )
    return {
        "status": result_status,
        "promoted": bool(promoted_ids),
        "hypothesis": _public_hypothesis_row(updated_row),
        "proof_reconciliation": reconciliation,
        "command_result": command_result,
        "operation_id": command_result.get("id"),
        "findings_created": 0,
        "execution_enabled": True,
    }


async def _plan_campaign_from_hypothesis(
    conn,
    hypothesis_id: str,
    req: HypothesisCampaignPlanRequest,
) -> dict[str, Any]:
    """Create a campaign/action plan from a hypothesis without executing work."""
    hypothesis_uuid = _uuid_or_400(hypothesis_id, "hypothesis id")
    hypothesis_row = await conn.fetchrow("SELECT * FROM hypotheses WHERE id=$1", hypothesis_uuid)
    if not hypothesis_row:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    hypothesis = _public_hypothesis_row(hypothesis_row)
    if hypothesis.get("effective_status") in {"refuted", "promoted", "dead"}:
        raise HTTPException(status_code=400, detail="Terminal hypotheses cannot be planned into campaigns")
    next_test_action = hypothesis.get("next_test_action") if isinstance(hypothesis.get("next_test_action"), dict) else {}
    command = str(next_test_action.get("command") or "").strip()
    if not command:
        raise HTTPException(status_code=400, detail="Hypothesis has no next_test_action command to plan")

    created_by = str(req.created_by or hypothesis.get("created_by") or "hypothesis.plan_campaign").strip()
    target_id = str(hypothesis.get("target_id") or "").strip() or None
    target_uuid = _optional_uuid(target_id)
    risk_tier = _risk_tier_for_hypothesis_action(hypothesis, next_test_action)
    campaign_uuid = _optional_uuid(req.campaign_id)
    if campaign_uuid:
        campaign_row = await conn.fetchrow("SELECT * FROM campaigns WHERE id=$1", campaign_uuid)
        if not campaign_row:
            raise HTTPException(status_code=404, detail="Campaign not found")
        campaign = _public_campaign_row(campaign_row)
    else:
        title = str(hypothesis.get("title") or hypothesis.get("family") or "Hypothesis").strip()
        campaign = await _persist_campaign(conn, CampaignRequest(
            objective=f"Plan deterministic proof work for hypothesis {hypothesis_uuid}",
            name=req.campaign_name or f"Hypothesis: {title[:120]}",
            campaign_type=_campaign_type_for_hypothesis_family(hypothesis.get("family")),
            target_id=target_id,
            target_scope={
                "hypothesis_id": str(hypothesis_uuid),
                "dedupe_key": hypothesis.get("dedupe_key"),
                "dedupe_dimensions": (hypothesis.get("metadata_json") or {}).get("dedupe_dimensions")
                    or hypothesis.get("dedupe_dimensions")
                    or {},
            },
            risk_tier=risk_tier,
            planner={
                "source": "hypothesis.plan_campaign",
                "next_test_action": next_test_action,
            },
            metadata_json={
                "hypothesis_id": str(hypothesis_uuid),
                "hypothesis_family": hypothesis.get("family"),
                "hypothesis_source": hypothesis.get("source"),
            },
            created_by=created_by,
        ))
        campaign_uuid = uuid.UUID(str(campaign["id"]))

    result_json = {
        "hypothesis_id": str(hypothesis_uuid),
        "planned_action": _redact_agent_payload(next_test_action),
        "authz_replay_plan": _authz_replay_plan_from_hypothesis_action(hypothesis, next_test_action),
        "proof_state": "planned_not_executed",
        "finding_created": False,
        "scan_queued": False,
    }
    action_row = await conn.fetchrow(
        """
        INSERT INTO campaign_actions (
            campaign_id, operation_plan_id, command_result_id, target_id,
            scope_receipt_id, approval_receipt_id, scan_id, command,
            action_name, status, dry_run, risk_tier, finding_ids,
            hypothesis_ids, evidence_object_ids, tool_receipt_ids,
            blocked_by, next_action, operator_message, result_json, created_by,
            mission_campaign_id
        ) VALUES (
            $1,$2,$3,$4,
            $5,$6,$7,$8,
            $9,$10,$11,$12,$13::jsonb,
            $14::jsonb,$15::jsonb,$16::jsonb,
            $17::jsonb,$18,$19,$20::jsonb,$21,
            $22
        )
        RETURNING *
        """,
        None,
        None,
        None,
        target_uuid,
        None,
        None,
        None,
        command,
        command,
        "planned",
        True,
        risk_tier,
        json.dumps([]),
        json.dumps([str(hypothesis_uuid)]),
        json.dumps([]),
        json.dumps([]),
        json.dumps([]),
        command,
        str(req.operator_message or "Planned from hypothesis next_test_action; no execution performed.").strip(),
        json.dumps(result_json),
        created_by,
        campaign_uuid,
    )
    action = _public_campaign_action_row(action_row)
    updated_hypothesis_row = await conn.fetchrow(
        """
        UPDATE hypotheses
        SET campaign_action_id=$1,
            metadata_json = metadata_json || $2::jsonb,
            updated_at=NOW()
        WHERE id=$3
        RETURNING *
        """,
        _optional_uuid(action.get("id")),
        json.dumps({
            "planned_campaign_id": str(campaign_uuid),
            "planned_campaign_action_id": action.get("id"),
            "planned_from_next_test_action": True,
        }),
        hypothesis_uuid,
    )
    return {
        "campaign": campaign,
        "campaign_action": action,
        "hypothesis": _public_hypothesis_row(updated_hypothesis_row) if updated_hypothesis_row else hypothesis,
        "execution_enabled": False,
        "findings_created": 0,
        "scans_queued": 0,
    }


def _campaign_deployment_impact(
    finding_rows: Sequence[Any],
    *,
    partial: bool = False,
) -> dict[str, Any]:
    """Roll up the findings a campaign surfaced by severity/status.

    This is a factual rollup, NOT the authoritative deployment decision: the real gate
    applies policy profiles, exceptions, and proof state. `estimated_default_blockers`
    counts active critical/high findings (the default block threshold) and is labelled as
    an estimate so it is never mistaken for the gate verdict.
    """
    by_severity: dict[str, int] = {}
    by_status: dict[str, int] = {}
    active_count = 0
    active_blocking = 0
    for row in finding_rows or []:
        data = row_to_dict(row)
        severity = str(data.get("severity") or "unknown").lower()
        finding_status = str(data.get("status") or "unknown").lower()
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_status[finding_status] = by_status.get(finding_status, 0) + 1
        if finding_status == "active":
            active_count += 1
            if severity in {"critical", "high"}:
                active_blocking += 1
    return {
        "linked_finding_count": sum(by_status.values()),
        "active_finding_count": active_count,
        "by_severity": by_severity,
        "by_status": by_status,
        "estimated_default_blockers": active_blocking,
        "blocks_deployment_estimate": active_blocking > 0,
        "partial": bool(partial),
    }


async def _campaign_live_finding_impact(
    conn: Any,
    campaign_ids: Sequence[uuid.UUID],
) -> dict[uuid.UUID, dict[str, Any]]:
    """Compute current finding impact across every linked campaign action."""
    if not campaign_ids:
        return {}
    rows = await conn.fetch(
        """
        SELECT ca.mission_campaign_id,
               linked.finding_id,
               f.id,
               f.severity,
               f.status
        FROM campaign_actions ca
        CROSS JOIN LATERAL jsonb_array_elements_text(
            COALESCE(ca.finding_ids, '[]'::jsonb)
        ) AS linked(finding_id)
        LEFT JOIN findings f ON f.id::text = linked.finding_id
        WHERE ca.mission_campaign_id = ANY($1::uuid[])
        """,
        list(campaign_ids),
    )
    grouped: dict[uuid.UUID, list[dict[str, Any]]] = {campaign_id: [] for campaign_id in campaign_ids}
    unresolved: set[uuid.UUID] = set()
    seen: dict[uuid.UUID, set[str]] = {campaign_id: set() for campaign_id in campaign_ids}
    for row in rows:
        campaign_id = row["mission_campaign_id"]
        if isinstance(campaign_id, str):
            try:
                campaign_id = uuid.UUID(campaign_id)
            except ValueError:
                continue
        data = row_to_dict(row)
        if campaign_id not in grouped:
            continue
        finding_id = str(data.get("finding_id") or "")
        if not data.get("id"):
            unresolved.add(campaign_id)
            continue
        if finding_id in seen[campaign_id]:
            continue
        seen[campaign_id].add(finding_id)
        grouped[campaign_id].append(data)
    return {
        campaign_id: _campaign_deployment_impact(
            grouped[campaign_id], partial=campaign_id in unresolved
        )
        for campaign_id in campaign_ids
    }


async def _arsenal_execute_detached(req: ArsenalExecuteRequest) -> dict[str, Any]:
    async with _pool().acquire() as conn:
        _command, status, risk_tier = await _validate_arsenal_execute_request(conn, req)
        await _validate_campaign_action_for_execution(conn, req)

    readonly = _arsenal_readonly_adapters()
    gated = _arsenal_gated_adapters()

    # Evidence retention has a read-only preview contract even though consuming
    # that preview is dangerous. The public route uses this detached gateway, so
    # dispatch the preview before the state-changing execution gate just as the
    # in-connection helper does.
    if req.command == "evidence.retention_sweep" and req.parameters.get("dry_run", True) is not False:
        result = await gated[req.command](req.parameters, None)
        durable_result = _bounded_research_payload(result)
        async with _pool().acquire() as conn:
            cr = await _record_command_result(
                conn,
                command=req.command,
                status="completed",
                risk_tier="read_only",
                dry_run=True,
                target_id=req.parameters.get("target_id"),
                operator_message="Created a target-scoped immutable evidence-retention preview",
                result_json={
                    "dispatched": True,
                    "via": "arsenal.execute",
                    "result": durable_result,
                },
                created_by=req.created_by,
            )
            await _link_command_result_to_campaign(conn, req.campaign_id, cr["id"])
            linked_action = await _link_command_result_to_campaign_action(conn, req.campaign_action_id, cr)
        return {
            "command": req.command,
            "dispatched": True,
            "dry_run": True,
            "result": result,
            "operation_id": cr["id"],
            "command_result": cr,
            "action_state": _arsenal_action_state(
                req,
                _command,
                catalog_status=status,
                risk_tier="read_only",
                phase="completed",
                dispatched=True,
                dry_run=True,
                execution_enabled=False,
                operation_id=cr["id"],
                command_result=cr,
                missing_confirmations=[],
                adapter_status="dispatched",
            ),
            "campaign_action": linked_action,
            "execution_enabled": False,
        }

    if req.command in readonly and status in {"read_only", "dry_run"}:
        result = await readonly[req.command](req.parameters)
        durable_result = _bounded_research_payload(result)
        async with _pool().acquire() as conn:
            cr = await _record_command_result(
                conn,
                command=req.command,
                status="completed",
                risk_tier=risk_tier,
                operator_message=f"Executed {req.command} via arsenal execution gateway",
                result_json={
                    "dispatched": True,
                    "via": "arsenal.execute",
                    "result": durable_result,
                },
                created_by=req.created_by,
            )
            await _link_command_result_to_campaign(conn, req.campaign_id, cr["id"])
            linked_action = await _link_command_result_to_campaign_action(conn, req.campaign_action_id, cr)
        return {
            "command": req.command,
            "dispatched": True,
            "dry_run": False,
            "result": result,
            "operation_id": cr["id"],
            "command_result": cr,
            "action_state": _arsenal_action_state(
                req,
                _command,
                catalog_status=status,
                risk_tier=risk_tier,
                phase="completed",
                dispatched=True,
                dry_run=False,
                execution_enabled=True,
                operation_id=cr["id"],
                command_result=cr,
                adapter_status="dispatched",
            ),
            "campaign_action": linked_action,
            "execution_enabled": True,
        }

    if status in {"read_only", "dry_run"}:
        async with _pool().acquire() as conn:
            return await _arsenal_adapter_pending_response(
                conn,
                req,
                _command,
                catalog_status=status,
                risk_tier=risk_tier,
            )

    required_confs = list(_command.get("required_confirmations") or ())
    missing_confs = [c for c in required_confs if c not in (req.confirmations or [])]
    gate_on = _ai_ops_execute_enabled()
    blocked_reason = None
    if not req.execute:
        blocked_reason = "execute_not_requested"
    elif missing_confs:
        blocked_reason = f"missing_confirmation:{missing_confs[0]}"
    elif not gate_on:
        blocked_reason = "AI_OPS_ROUTER_EXECUTE_ENABLED_disabled"
    if blocked_reason:
        result_status = "approval_required" if blocked_reason in {"execute_not_requested"} or blocked_reason.startswith("missing_confirmation") else "blocked"
        async with _pool().acquire() as conn:
            cr = await _record_blocked_command_result(
                conn,
                action_name=req.command,
                command=req.command,
                risk_tier=risk_tier,
                status=result_status,
                blocked_by=[blocked_reason],
                operator_message=f"Did not execute {req.command}: {blocked_reason}",
                created_by=req.created_by,
            )
            await _link_command_result_to_campaign(conn, req.campaign_id, cr["id"] if cr else None)
            linked_action = await _link_command_result_to_campaign_action(conn, req.campaign_action_id, cr)
        return {
            "command": req.command,
            "dispatched": False,
            "dry_run": True,
            "execution_blocked_reason": blocked_reason,
            "operation_id": cr["id"] if cr else None,
            "command_result": cr,
            "action_state": _arsenal_action_state(
                req,
                _command,
                catalog_status=status,
                risk_tier=risk_tier,
                phase=result_status,
                dispatched=False,
                dry_run=True,
                execution_enabled=False,
                operation_id=cr["id"] if cr else None,
                command_result=cr,
                blocked_reason=blocked_reason,
                gate_enabled=gate_on,
                missing_confirmations=missing_confs,
                adapter_status="not_dispatched",
            ),
            "campaign_action": linked_action,
            "execution_enabled": False,
        }

    async with _pool().acquire() as conn:
        await _validate_approval_receipt_for_action(
            conn,
            req.approval_receipt_id,
            target_url=str(req.parameters.get("target") or "").strip() or None,
            target_id=req.parameters.get("target_id"),
            action_name=req.command,
            command=req.command,
            risk_tier=risk_tier,
            created_by=req.created_by,
        )

    adapter = gated.get(req.command)
    if not adapter:
        async with _pool().acquire() as conn:
            cr = await _record_blocked_command_result(
                conn,
                action_name=req.command,
                command=req.command,
                risk_tier=risk_tier,
                status="blocked",
                blocked_by=["dispatch_adapter_pending"],
                operator_message=f"{req.command} passed the execution gate but has no gateway dispatch adapter yet; use its dedicated route",
                created_by=req.created_by,
            )
            await _link_command_result_to_campaign(conn, req.campaign_id, cr["id"] if cr else None)
            linked_action = await _link_command_result_to_campaign_action(conn, req.campaign_action_id, cr)
        return {
            "command": req.command,
            "dispatched": False,
            "dry_run": False,
            "execution_blocked_reason": "dispatch_adapter_pending",
            "operation_id": cr["id"] if cr else None,
            "command_result": cr,
            "action_state": _arsenal_action_state(
                req,
                _command,
                catalog_status=status,
                risk_tier=risk_tier,
                phase="blocked",
                dispatched=False,
                dry_run=False,
                execution_enabled=False,
                operation_id=cr["id"] if cr else None,
                command_result=cr,
                blocked_reason="dispatch_adapter_pending",
                gate_enabled=gate_on,
                missing_confirmations=[],
                adapter_status="pending",
            ),
            "campaign_action": linked_action,
            "execution_enabled": False,
        }

    context_token = _ARSENAL_CREATED_BY_CONTEXT.set(req.created_by)
    try:
        # Keep research provenance byte-for-byte equivalent to the ordinary
        # execution gateway.  The detached path is used by autopilot so it
        # must not drop the hypothesis id required by trusted promotion.
        adapter_parameters = dict(req.parameters)
        if req.research_hypothesis_id:
            adapter_parameters["_research_hypothesis_id"] = req.research_hypothesis_id
        result = await adapter(adapter_parameters, req.approval_receipt_id)
    finally:
        _ARSENAL_CREATED_BY_CONTEXT.reset(context_token)
    operation_id = result.get("operation_id") if isinstance(result, dict) else None
    command_result = None
    async with _pool().acquire() as conn:
        await _link_command_result_to_campaign(conn, req.campaign_id, operation_id)
        command_result = await _command_result_response_row(conn, operation_id)
        linked_action = await _link_command_result_to_campaign_action(conn, req.campaign_action_id, command_result)
    dispatched = bool(operation_id)
    blocked_reason = None if dispatched else "adapter_returned_no_operation_receipt"
    return {
        "command": req.command,
        "dispatched": dispatched,
        "dry_run": False,
        "execution_blocked_reason": blocked_reason,
        "result": result,
        "operation_id": operation_id,
        "command_result": command_result,
        "action_state": _arsenal_action_state(
            req,
            _command,
            catalog_status=status,
            risk_tier=risk_tier,
            phase=str(result.get("status") or "dispatched") if isinstance(result, dict) else "dispatched",
            dispatched=dispatched,
            dry_run=False,
            execution_enabled=dispatched,
            operation_id=operation_id,
            command_result=command_result,
            gate_enabled=gate_on,
            missing_confirmations=[],
            blocked_reason=blocked_reason,
            adapter_status="dispatched" if dispatched else "no_operation_receipt",
        ),
        "campaign_action": linked_action,
        "execution_enabled": dispatched,
    }


async def _research_campaign_readiness(conn: Any, campaign: Any) -> dict[str, Any]:
    """Fail-closed launch gate for authenticated autonomous hunting."""
    payload = row_to_dict(campaign)
    metadata = _decode_json_value(payload.get("metadata_json")) or {}
    config = metadata.get("autonomous_research") if isinstance(metadata.get("autonomous_research"), dict) else {}
    target_id = _optional_uuid(payload.get("target_id"))
    intensity = str(config.get("intensity") or "deep_hunt")
    gated = _get("RESEARCH_LAUNCH_PROFILES").get(intensity, {}).get("execution_mode") == "gated"
    families = {str(item).strip().lower() for item in config.get("allowed_families") or [] if str(item).strip()}
    requirements = _research_family_readiness_requirements(families, gated=gated)
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
        target_id,
    )
    principals = [row_to_dict(row) for row in principal_rows]
    signals = _target_credential_precondition_signals(principals)
    invariant_counts: dict[str, int] = {}
    try:
        invariant_row = await conn.fetchrow(
            """
            SELECT COUNT(*) FILTER (WHERE contract_kind='access_control')::int AS access_control,
                   COUNT(*) FILTER (WHERE contract_kind='field_constraint')::int AS field_constraint,
                   COUNT(*) FILTER (WHERE contract_kind='workflow_transition')::int AS workflow
            FROM target_invariant_contracts
            WHERE target_id=$1 AND status='approved'
            """,
            target_id,
        )
        invariant_counts = {
            key: int((invariant_row or {}).get(key) or 0)
            for key in ("access_control", "field_constraint", "workflow")
        }
    except Exception:
        # Rolling migrations and test doubles fail closed: invariant-only families are unavailable.
        invariant_counts = {"access_control": 0, "field_constraint": 0, "workflow": 0}
    surface = await conn.fetchrow(
        """
        SELECT COUNT(*)::int AS inventory_rows,
               COUNT(DISTINCT upper(method) || ' ' || path)::int AS unique_routes,
               COUNT(DISTINCT upper(method) || ' ' || path)
                   FILTER (WHERE auth_state IN ('user1','user2'))::int AS authenticated_routes,
               COUNT(DISTINCT upper(method) || ' ' || path)
                   FILTER (WHERE auth_state='user2')::int AS second_user_routes,
               COUNT(DISTINCT upper(method) || ' ' || path)
                   FILTER (
                     WHERE auth_state IN ('user1','user2')
                       AND (
                         upper(method)='GET'
                         OR COALESCE(param_shape, '') <> ''
                         OR COALESCE(replay_spec, '') <> ''
                       )
                   )::int AS executable_routes,
               COUNT(DISTINCT upper(method) || ' ' || path)
                   FILTER (
                     WHERE upper(method)='GET'
                        OR COALESCE(param_shape, '') <> ''
                        OR COALESCE(replay_spec, '') <> ''
                   )::int AS all_executable_routes,
               COUNT(DISTINCT upper(method) || ' ' || path)
                   FILTER (
                     WHERE auth_state IN ('user1','user2')
                       AND path ~ '/(\\{[^/{}]+\\}|:[A-Za-z_][A-Za-z0-9_]*|[0-9]+)(/|$)'
                   )::int AS object_routes,
               COUNT(DISTINCT upper(method) || ' ' || path)
                   FILTER (
                     WHERE auth_state IN ('user1','user2')
                       AND upper(method) IN ('POST','PUT','PATCH')
                       AND (COALESCE(param_shape, '') <> '' OR COALESCE(replay_spec, '') <> '')
                   )::int AS mutation_routes,
               COUNT(DISTINCT upper(method) || ' ' || path)
                   FILTER (
                     WHERE COALESCE(param_shape, '') <> '' OR COALESCE(replay_spec, '') <> ''
                   )::int AS parameterized_routes,
               MAX(last_seen_at) AS latest_inventory_seen_at
        FROM target_endpoints
        WHERE target_id=$1 AND COALESCE(test_status, '') <> 'gone'
        """,
        target_id,
    )
    preflight_scan_id = _optional_uuid(config.get("preflight_scan_id"))
    preflight = None
    reused_preflight = False
    if preflight_scan_id:
        preflight = await conn.fetchrow(
            "SELECT id, status, current_phase, error_message, created_at, completed_at FROM scans WHERE id=$1 AND target_id=$2",
            preflight_scan_id,
            target_id,
        )
    elif gated:
        # Reuse recent target-bound work only when its durable provenance meets
        # the selected families' needs. Public injection/data campaigns do not
        # require a two-principal graph; BOLA still does.
        preflight = await conn.fetchrow(
            """
            SELECT s.id, s.status, s.current_phase, s.error_message, s.created_at, s.completed_at
            FROM scans s
            WHERE s.target_id=$1 AND s.status='completed'
              AND (s.scan_role IS NULL OR s.scan_role <> 'shard')
              AND s.completed_at >= NOW() - INTERVAL '24 hours'
              AND EXISTS (
                SELECT 1 FROM target_endpoints e
                WHERE e.target_id=$1 AND e.last_seen_scan_id IN (
                    SELECT family.id FROM scans family
                    WHERE family.id=s.id OR family.parent_scan_id=s.id
                )
                  AND (
                    $2::boolean=false
                    OR e.auth_state IN ('user1','user2')
                  )
                  AND (
                    $3::boolean=false
                    OR e.auth_state='user2'
                  )
              )
              AND (
                $3::boolean=false
                OR EXISTS (
                  SELECT 1 FROM application_graph_edges edge
                  WHERE edge.target_id=$1 AND edge.scan_id IN (
                      SELECT family.id FROM scans family
                      WHERE family.id=s.id OR family.parent_scan_id=s.id
                  )
                    AND edge.edge_type='auth_boundary'
                    AND COALESCE(edge.attributes->>'source_principal','') <> ''
                    AND COALESCE(edge.attributes->>'excluded_principal','') <> ''
                    AND edge.attributes->>'source_principal' <> edge.attributes->>'excluded_principal'
                )
              )
            ORDER BY s.completed_at DESC
            LIMIT 1
            """,
            target_id,
            bool(requirements["primary_credentials"]),
            bool(requirements["second_user"]),
        )
        if preflight:
            preflight_scan_id = _optional_uuid(preflight.get("id"))
            reused_preflight = True
    fresh_surface = await conn.fetchrow(
        """
        SELECT COUNT(DISTINCT upper(method) || ' ' || path)::int AS fresh_unique_routes,
               COUNT(DISTINCT upper(method) || ' ' || path)
                   FILTER (WHERE auth_state IN ('user1','user2'))::int AS fresh_authenticated_routes,
               COUNT(DISTINCT upper(method) || ' ' || path)
                   FILTER (WHERE auth_state='user2')::int AS fresh_second_user_routes,
               COUNT(DISTINCT upper(method) || ' ' || path)
                   FILTER (
                     WHERE auth_state IN ('user1','user2')
                       AND (
                         upper(method)='GET'
                         OR COALESCE(param_shape, '') <> ''
                         OR COALESCE(replay_spec, '') <> ''
                       )
                   )::int AS fresh_executable_routes,
               COUNT(DISTINCT upper(method) || ' ' || path)
                   FILTER (
                     WHERE upper(method)='GET'
                        OR COALESCE(param_shape, '') <> ''
                        OR COALESCE(replay_spec, '') <> ''
                   )::int AS fresh_all_executable_routes,
               COUNT(DISTINCT upper(method) || ' ' || path)
                   FILTER (
                     WHERE auth_state IN ('user1','user2')
                       AND path ~ '/(\\{[^/{}]+\\}|:[A-Za-z_][A-Za-z0-9_]*|[0-9]+)(/|$)'
                   )::int AS fresh_object_routes,
               COUNT(DISTINCT upper(method) || ' ' || path)
                   FILTER (
                     WHERE auth_state IN ('user1','user2')
                       AND upper(method) IN ('POST','PUT','PATCH')
                       AND (COALESCE(param_shape, '') <> '' OR COALESCE(replay_spec, '') <> '')
                   )::int AS fresh_mutation_routes,
               COUNT(DISTINCT upper(method) || ' ' || path)
                   FILTER (
                     WHERE COALESCE(param_shape, '') <> '' OR COALESCE(replay_spec, '') <> ''
                   )::int AS fresh_parameterized_routes
        FROM target_endpoints
        WHERE target_id=$1 AND last_seen_scan_id IN (
            SELECT id FROM scans
            WHERE id=COALESCE((SELECT parent_scan_id FROM scans WHERE id=$2::uuid), $2::uuid)
               OR parent_scan_id=COALESCE((SELECT parent_scan_id FROM scans WHERE id=$2::uuid), $2::uuid)
        )
        """,
        target_id,
        preflight_scan_id,
    )
    graph = await conn.fetchrow(
        """
        SELECT COUNT(*) FILTER (WHERE node_type='route')::int AS route_nodes,
               COUNT(*) FILTER (
                   WHERE node_type='route' AND scan_id IN (
                       SELECT id FROM scans
                       WHERE id=COALESCE((SELECT parent_scan_id FROM scans WHERE id=$2::uuid), $2::uuid)
                          OR parent_scan_id=COALESCE((SELECT parent_scan_id FROM scans WHERE id=$2::uuid), $2::uuid)
                   )
               )::int AS fresh_route_nodes,
               MAX(last_seen_at) AS latest_graph_seen_at,
               (SELECT COUNT(*)::int FROM application_graph_edges WHERE target_id=$1) AS edge_count,
               (SELECT COUNT(*)::int FROM application_graph_edges
                  WHERE target_id=$1 AND scan_id IN (
                      SELECT id FROM scans
                      WHERE id=COALESCE((SELECT parent_scan_id FROM scans WHERE id=$2::uuid), $2::uuid)
                         OR parent_scan_id=COALESCE((SELECT parent_scan_id FROM scans WHERE id=$2::uuid), $2::uuid)
                  )) AS fresh_edge_count,
               (SELECT COUNT(*)::int FROM application_graph_edges
                  WHERE target_id=$1 AND scan_id IN (
                      SELECT id FROM scans
                      WHERE id=COALESCE((SELECT parent_scan_id FROM scans WHERE id=$2::uuid), $2::uuid)
                         OR parent_scan_id=COALESCE((SELECT parent_scan_id FROM scans WHERE id=$2::uuid), $2::uuid)
                  )
                    AND edge_type='auth_boundary'
                    AND COALESCE(attributes->>'source_principal','') <> ''
                    AND COALESCE(attributes->>'excluded_principal','') <> ''
                    AND attributes->>'source_principal' <> attributes->>'excluded_principal'
               ) AS fresh_auth_boundary_edges
        FROM application_graph_nodes WHERE target_id=$1
        """,
        target_id,
        preflight_scan_id,
    )
    surface_payload = {
        **(row_to_dict(surface) if surface else {}),
        **(row_to_dict(fresh_surface) if fresh_surface else {}),
        **(row_to_dict(graph) if graph else {}),
    }
    before = config.get("surface_before_preflight") if isinstance(config.get("surface_before_preflight"), dict) else {}
    executable_routes = int(surface_payload.get("executable_routes") or 0)
    all_executable_routes = int(surface_payload.get("all_executable_routes") or 0)
    object_routes = int(surface_payload.get("object_routes") or 0)
    mutation_routes = int(surface_payload.get("mutation_routes") or 0)
    parameterized_routes = int(surface_payload.get("parameterized_routes") or 0)
    fresh_route_nodes = int(surface_payload.get("fresh_route_nodes") or 0)
    fresh_edge_count = int(surface_payload.get("fresh_edge_count") or 0)
    # A BOLA-usable graph needs a FRESH cross-principal auth_boundary edge (source_principal !=
    # excluded_principal), not merely any new edge -- a lone producer/produces edge or a stale
    # boundary must not open the gate. Counting any edge_type let readiness pass with no real
    # two-principal surface (the reported fail-open).
    fresh_auth_boundary_edges = int(surface_payload.get("fresh_auth_boundary_edges") or 0)
    family_executable_routes = (
        int(surface_payload.get("fresh_executable_routes") or 0) if gated else executable_routes
    )
    family_all_executable_routes = (
        int(surface_payload.get("fresh_all_executable_routes") or 0) if gated else all_executable_routes
    )
    family_object_routes = (
        int(surface_payload.get("fresh_object_routes") or 0) if gated else object_routes
    )
    family_second_user_routes = (
        int(surface_payload.get("fresh_second_user_routes") or 0)
        if gated else int(surface_payload.get("second_user_routes") or 0)
    )
    family_mutation_routes = (
        int(surface_payload.get("fresh_mutation_routes") or 0) if gated else mutation_routes
    )
    family_parameterized_routes = (
        int(surface_payload.get("fresh_parameterized_routes") or 0) if gated else parameterized_routes
    )
    executable_families: list[str] = []
    if "auth" in families and family_executable_routes > 0:
        executable_families.append("auth")
    if (
        "bola" in families
        and family_object_routes > 0
        and family_second_user_routes > 0
        and fresh_auth_boundary_edges > 0
    ):
        executable_families.append("bola")
    for injection_family in ("sqli", "xss"):
        if injection_family in families and family_parameterized_routes > 0:
            executable_families.append(injection_family)
    # Mass-assignment leads come from the persistent endpoint inventory (any authenticated write route
    # with a captured body), NOT from a fresh two-principal preflight like BOLA. A BOLA-focused reused
    # preflight leaves fresh_mutation_routes=0 even when the inventory holds 100+ writable routes, which
    # wrongly drops the whole family and lets its many leads flood the pre-truncation board only to be
    # stripped later, starving executable families. The live-surface filter already discards stale/gone
    # routes, so gate on the persistent mutation surface (whole-target) instead of the fresh count.
    if "mass_assignment" in families and (family_mutation_routes > 0 or mutation_routes > 0):
        executable_families.append("mass_assignment")
    if (
        "field_constraint" in families
        and family_mutation_routes > 0
        and invariant_counts.get("field_constraint", 0) > 0
    ):
        executable_families.append("field_constraint")
    if (
        "workflow" in families
        and family_mutation_routes > 0
        and invariant_counts.get("workflow", 0) > 0
    ):
        executable_families.append("workflow")
    if "data_exposure" in families and family_executable_routes > 0:
        executable_families.append("data_exposure")
    if (
        "access_control" in families
        and family_executable_routes > 0
        and invariant_counts.get("access_control", 0) > 0
    ):
        executable_families.append("access_control")
    fresh_authenticated_routes = int(surface_payload.get("fresh_authenticated_routes") or 0)
    if gated and requirements["authenticated_preflight"]:
        # Count authenticated coverage stamped by THIS preflight, not only net-new cardinality. A
        # successful refresh of 30 existing authenticated routes is useful and fresh; an unrelated
        # concurrent/public route is not. The scan-id provenance closes both the old fail-open and the
        # same-count false-negative that repeatedly exhausted otherwise healthy auth preflights.
        meaningful_preflight_gain = bool(fresh_auth_boundary_edges > 0 or fresh_authenticated_routes > 0)
    elif gated:
        meaningful_preflight_gain = bool(
            int(surface_payload.get("fresh_unique_routes") or 0) > 0
            and (
                family_all_executable_routes > 0
                or family_parameterized_routes > 0
            )
        )
    else:
        meaningful_preflight_gain = bool(
            fresh_route_nodes > 0
            or int(surface_payload.get("unique_routes") or 0) > int(before.get("unique_routes") or 0)
            or not before
        )
    surface_payload.update({
        "executable_families": sorted(set(executable_families)),
        "unavailable_families": sorted(families - set(executable_families)),
        "approved_invariant_counts": invariant_counts,
        "meaningful_preflight_gain": meaningful_preflight_gain,
    })
    blockers: list[str] = []
    if requirements["primary_credentials"] and signals.get("primary_credentials") != "configured":
        blockers.append("primary_credentials_required")
    if gated and not config.get("approval_receipt_id"):
        blockers.append("approval_receipt_required")
    if requirements["second_user"] and signals.get("second_user_credentials") != "configured":
        blockers.append("distinct_second_user_credentials_required")
    preflight_status = str(preflight.get("status") or "missing") if preflight else "missing"
    if gated and preflight_status != "completed":
        blockers.append(
            (
                "authenticated_preflight_in_progress"
                if requirements["authenticated_preflight"] else
                "focused_preflight_in_progress"
            )
            if preflight_status in {"pending", "queued", "running"}
            else (
                "authenticated_preflight_required"
                if requirements["authenticated_preflight"] else
                "focused_preflight_required"
            )
        )
    if int(surface_payload.get("unique_routes") or 0) < int(requirements["unique_routes"]):
        blockers.append(
            "insufficient_unique_route_coverage"
            if gated else
            "read_only_campaign_requires_existing_coverage"
        )
    if requirements["authenticated_routes"] and int(surface_payload.get("authenticated_routes") or 0) < int(requirements["authenticated_routes"]):
        blockers.append("insufficient_authenticated_route_coverage")
    required_executable_count = (
        family_executable_routes if requirements["primary_credentials"]
        else family_all_executable_routes
    )
    if gated and required_executable_count < RESEARCH_SURFACE_MIN_EXECUTABLE_ROUTES:
        blockers.append(
            "no_executable_authenticated_routes"
            if requirements["primary_credentials"] else
            "no_executable_routes"
        )
    if requirements["second_user"] and int(surface_payload.get("second_user_routes") or 0) <= 0:
        blockers.append("second_user_surface_not_observed")
    if requirements["second_user"] and object_routes > 0 and fresh_auth_boundary_edges <= 0:
        blockers.append("two_principal_graph_not_materialized")
    if gated and preflight_status == "completed" and not meaningful_preflight_gain:
        blockers.append(
            "authenticated_preflight_no_material_gain"
            if requirements["authenticated_preflight"] else
            "focused_preflight_no_material_gain"
        )
    if gated and families and not executable_families:
        blockers.append("no_allowed_family_has_executable_surface")
    if gated and config.get("require_all_requested_families"):
        blockers.extend(
            f"family_surface_unavailable:{family}"
            for family in sorted(families - set(executable_families))
        )
    hard_blockers = {
        "primary_credentials_required",
        "distinct_second_user_credentials_required",
        "approval_receipt_required",
        "read_only_campaign_requires_existing_coverage",
    }
    return {
        "ready": not blockers,
        "state": "ready" if not blockers else (
            "blocked" if hard_blockers.intersection(blockers) else
            "waiting" if {
                "authenticated_preflight_in_progress", "focused_preflight_in_progress",
            }.intersection(blockers) else
            "repairable"
        ),
        "blockers": blockers,
        "credential_signals": signals,
        "surface": surface_payload,
        "preflight_scan": row_to_dict(preflight) if preflight else None,
        "reused_preflight": reused_preflight,
        "required": {
            **requirements,
            "fresh_two_principal_graph": bool(requirements["second_user"] and object_routes > 0),
        },
    }


async def _research_campaign_yield_metrics(conn: Any, campaign: Any) -> dict[str, Any]:
    payload = row_to_dict(campaign)
    campaign_id = _optional_uuid(payload.get("id"))
    target_id = _optional_uuid(payload.get("target_id"))
    episode_rows = await conn.fetch(
        "SELECT id, status, budget_used FROM research_episodes WHERE campaign_id=$1 ORDER BY created_at",
        campaign_id,
    )
    episode_ids = [row["id"] for row in episode_rows]
    decisions = []
    if episode_ids:
        decisions = await conn.fetch(
            """
            SELECT rd.action, rd.status, rd.validation_errors,
                   cr.id AS command_result_id, cr.status AS command_status,
                   cr.finding_ids, cr.result_json
            FROM research_decisions rd
            LEFT JOIN command_results cr ON cr.id=rd.command_result_id
            WHERE rd.episode_id=ANY($1::uuid[])
            ORDER BY rd.created_at
            """,
            episode_ids,
        )
    model_units = sum(
        int((_decode_json_value(row.get("budget_used")) or {}).get("model_tokens") or 0)
        for row in episode_rows
    )
    experiments = 0
    falsified = 0
    recon_actions = 0
    semantic_dimensions: set[str] = set()
    exhausted_dimensions: set[str] = set()
    falsification_counts: dict[str, int] = {}
    outcome_counts: dict[str, int] = {key: 0 for key in sorted(RESEARCH_EXPERIMENT_OUTCOMES)}
    novelty_blocks = 0
    rejected_decisions = 0
    rejection_reasons: Counter[str] = Counter()
    for row in decisions:
        action = _decode_json_value(row.get("action")) or {}
        command = str(action.get("command") or "")
        if command in RESEARCH_RECON_COMMANDS and str(row.get("status") or "") in {
            "accepted", "dispatching", "completed", "blocked",
        }:
            recon_actions += 1
        validation_errors = _decode_json_value(row.get("validation_errors")) or []
        novelty_blocks += sum(1 for error in validation_errors if str(error) == "known_vulnerability_already_covered")
        if str(row.get("status") or "") in {"rejected", "blocked", "failed"}:
            rejected_decisions += 1
            rejection_reasons.update(str(error) for error in validation_errors if str(error))
        dimension = _research_action_semantic_dimension(action)
        if not dimension:
            continue
        semantic_dimensions.add(dimension)
        if row.get("command_result_id") and str(row.get("status") or "") == "completed":
            experiments += 1
            outcome = _research_experiment_outcome(action, row)
            if outcome:
                outcome_name = str(outcome.get("outcome") or "inconclusive")
                outcome_counts[outcome_name] = outcome_counts.get(outcome_name, 0) + 1
            if outcome and outcome.get("deterministic_refutation"):
                falsified += 1
                falsification_counts[dimension] = falsification_counts.get(dimension, 0) + 1
    exhausted_dimensions.update(
        dimension for dimension, count in falsification_counts.items()
        if count >= _get("RESEARCH_SEMANTIC_FALSIFICATION_LIMIT")
    )
    # The board is offering nothing net-new: the planner keeps proposing already-owned vulnerabilities
    # (novelty-suppressed at dispatch) and nothing is actually executing. Stop cleanly and early rather
    # than burning the model budget on a covered-board spin (faster than the generic rejection ceiling).
    all_leads_already_covered = (
        novelty_blocks >= 8
        and experiments == 0
        and novelty_blocks == rejected_decisions
        and novelty_blocks >= max(8, int(len(decisions) * 0.75))
    )
    verified_findings = int(await conn.fetchval(
        """
        SELECT COUNT(*) FROM findings
        WHERE target_id=$1 AND tool='autonomous_workflow'
          AND EXISTS (
              SELECT 1
              FROM jsonb_array_elements(
                  COALESCE(evidence->'research_provenance_history', '[]'::jsonb)
              ) AS provenance
              WHERE provenance->>'campaign_id'=$2::text
          )
          AND last_verification_verdict='exploited'
        """,
        target_id,
        str(campaign_id),
    ) or 0)
    verified_scan_findings = int(await conn.fetchval(
        """
        SELECT COUNT(DISTINCT f.id)
        FROM findings f
        WHERE f.target_id=$1
          AND f.last_verification_verdict='exploited'
          AND f.scan_id IN (
              SELECT cr.scan_id
              FROM research_decisions rd
              JOIN research_episodes re ON re.id=rd.episode_id
              JOIN command_results cr ON cr.id=rd.command_result_id
              WHERE re.campaign_id=$2 AND cr.scan_id IS NOT NULL
          )
        """,
        target_id,
        campaign_id,
    ) or 0)
    verified_retest_findings = int(await conn.fetchval(
        """
        SELECT COUNT(DISTINCT fv.finding_id)
        FROM finding_verifications fv
        JOIN command_results cr ON cr.result_json->>'retest_id'=fv.id::text
        JOIN research_decisions rd ON rd.command_result_id=cr.id
        JOIN research_episodes re ON re.id=rd.episode_id
        WHERE re.campaign_id=$1
          AND fv.status='completed'
          AND fv.verdict='exploited'
        """,
        campaign_id,
    ) or 0)
    metadata = _decode_json_value(payload.get("metadata_json")) or {}
    config = metadata.get("autonomous_research") if isinstance(metadata.get("autonomous_research"), dict) else {}
    aggregate_budget = await _research_campaign_budget_snapshot(conn, campaign)
    before = config.get("surface_before_preflight") if isinstance(config.get("surface_before_preflight"), dict) else {}
    after = config.get("surface_after_preflight") if isinstance(config.get("surface_after_preflight"), dict) else {}
    # Net-new-over-DAST: campaign-attributed exact vulnerability identities
    # that no deterministic scanner finding owns.
    net_new_verified = await _research_net_new_finding_count(
        conn, target_id, campaign_id=campaign_id,
    )
    return {
        "episodes": len(episode_rows),
        "decisions": len(decisions),
        "model_units": model_units,
        "experiments": experiments,
        "falsified_experiments": falsified,
        "experiment_outcomes": outcome_counts,
        "non_scientific_experiments": outcome_counts.get("inconclusive", 0) + outcome_counts.get("blocked", 0),
        "semantic_dimensions_tested": len(semantic_dimensions),
        "exhausted_dimensions": len(exhausted_dimensions),
        "recon_actions": recon_actions,
        "novelty_suppressions": novelty_blocks,
        "rejected_decisions": rejected_decisions,
        "rejection_reasons": dict(rejection_reasons.most_common(20)),
        "verified_autonomous_findings": verified_findings,
        "verified_campaign_scan_findings": verified_scan_findings,
        "verified_campaign_retest_findings": verified_retest_findings,
        "net_new_verified_findings": net_new_verified,
        "finding_yield_per_experiment": round(verified_findings / experiments, 4) if experiments else 0.0,
        "model_units_per_verified_finding": (model_units // verified_findings) if verified_findings else None,
        "aggregate_budget": aggregate_budget,
        "surface": {
            "unique_routes_before": int(before.get("unique_routes") or 0),
            "unique_routes_after": int(after.get("unique_routes") or 0),
            "authenticated_routes_before": int(before.get("authenticated_routes") or 0),
            "authenticated_routes_after": int(after.get("authenticated_routes") or 0),
        },
        "stop_recommended": bool(
            verified_findings == 0
            and (
                all_leads_already_covered
                or (
                    experiments >= 12
                    and falsified >= max(9, int(experiments * 0.75))
                )
                or (
                    experiments >= 8
                    and outcome_counts.get("inconclusive", 0) + outcome_counts.get("blocked", 0)
                    >= max(6, int(experiments * 0.75))
                )
                or (
                    rejected_decisions >= 8
                    and rejected_decisions >= max(8, int(len(decisions) * 0.75))
                )
            )
        ),
        "stop_reason": (
            "zero_yield_falsification_ceiling"
            if experiments >= 12 and verified_findings == 0 and falsified >= max(9, int(experiments * 0.75))
            else "experiment_harness_failure_ceiling"
            if experiments >= 8 and verified_findings == 0
            and outcome_counts.get("inconclusive", 0) + outcome_counts.get("blocked", 0)
            >= max(6, int(experiments * 0.75))
            else "all_leads_already_covered"
            if verified_findings == 0 and all_leads_already_covered
            else "planner_rejection_ceiling"
            if rejected_decisions >= 8 and verified_findings == 0
            and rejected_decisions >= max(8, int(len(decisions) * 0.75))
            else None
        ),
    }


def _normalized_web_origins(primary_url: Any, values: Any = None) -> list[str]:
    """Normalize and de-duplicate concrete origins while preserving preference order."""
    candidates = values if isinstance(values, list) else []
    origins: list[str] = []
    for value in [*candidates, primary_url]:
        try:
            origin, _note = _targets.normalize_target_url(str(value or ""))
        except _targets.TargetNormalizationError:
            continue
        if origin and origin not in origins:
            origins.append(origin)
    return origins


async def _target_web_origins(conn: Any, target_id: uuid.UUID, primary_url: Any) -> list[str]:
    """Return most-recently scanned concrete origins for one host-level web target."""
    rows = await conn.fetch(
        """
        SELECT target_url, MAX(created_at) AS last_seen
        FROM scans
        WHERE target_id=$1 AND run_kind='web_dast'
        GROUP BY target_url
        ORDER BY last_seen DESC
        LIMIT 32
        """,
        target_id,
    )
    return _normalized_web_origins(primary_url, [row["target_url"] for row in rows])


class SourceIngestFile(BaseModel):
    path: str = Field(min_length=1, max_length=500)
    content: str = Field(default="", max_length=262144)
    language: Optional[str] = Field(default=None, max_length=80)


def _target_credential_precondition_signals(
    principals: list[dict[str, Any]],
    metadata: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Derive credential readiness from secret-profile references, not identities."""
    metadata = metadata or {}
    profile_by_auth_state = {
        str(item.get("auth_state") or "").strip(): str(item.get("credential_profile") or "").strip()
        for item in principals
        if item.get("is_active", True)
        and item.get("credential_configured") is True
        and str(item.get("auth_state") or "").strip() in {"user1", "user2"}
        and str(item.get("credential_profile") or "").strip()
    }
    primary_profile = profile_by_auth_state.get("user1")
    alternate_profile = profile_by_auth_state.get("user2")
    primary_legacy = bool(metadata.get("auth") or metadata.get("credential_profile"))
    alternate_legacy = bool(metadata.get("second_user") or metadata.get("user2"))
    return {
        "primary_credentials": "configured" if primary_profile or primary_legacy else "unknown",
        "second_user_credentials": (
            "configured"
            if (primary_profile and alternate_profile and primary_profile.lower() != alternate_profile.lower()) or alternate_legacy
            else "unknown"
        ),
    }


async def _validate_agent_context_pack(conn, req: AgentContextPackRequest) -> tuple[dict[str, Any], list[str], list[str], str]:
    original = req.model_dump(mode="json")
    payload = _canonical_agent_context_pack(req)
    errors: list[str] = []
    warnings: list[str] = []
    if not re.fullmatch(r"[a-f0-9]{64}", str(payload.get("context_hash") or "")):
        errors.append("context_hash_must_be_sha256_hex")
    if _contains_forbidden_context_key(original):
        errors.append("context_pack_contains_forbidden_raw_or_secret_field")
    target_uuid = None
    target_id = str(payload.get("target_id") or "").strip()
    if target_id:
        try:
            target_uuid = uuid.UUID(target_id)
        except ValueError:
            errors.append("target_id_must_be_uuid")
        else:
            exists = await conn.fetchval("SELECT 1 FROM targets WHERE id=$1", target_uuid)
            if not exists:
                errors.append("target_not_found")
    commands = _operation_plan_allowed_commands()
    for name in payload.get("allowed_commands") or []:
        if name not in commands:
            errors.append(f"allowed_command_unknown:{name}")
    for item in payload.get("disallowed_commands") or []:
        if isinstance(item, dict):
            command = str(item.get("command") or "").strip()
            if command and command not in commands:
                warnings.append(f"disallowed_command_unknown:{command}")
    if not payload.get("target_summary"):
        warnings.append("target_summary_empty")
    if not payload.get("allowed_commands"):
        warnings.append("allowed_commands_empty")
    payload["target_id"] = str(target_uuid) if target_uuid else None
    payload["context_pack"] = {
        "context_version": payload["context_version"],
        "target_summary": payload.get("target_summary") or {},
        "current_surface": payload.get("current_surface") or {},
        "current_gaps": payload.get("current_gaps") or [],
        "hypotheses_summary": payload.get("hypotheses_summary") or [],
        "findings_summary": payload.get("findings_summary") or [],
        "allowed_commands": payload.get("allowed_commands") or [],
        "disallowed_commands": payload.get("disallowed_commands") or [],
        "known_preconditions": payload.get("known_preconditions") or {},
        "redaction_profile": payload["redaction_profile"],
        "context_hash": payload["context_hash"],
    }
    return payload, errors, warnings, "invalid" if errors else "recorded"


def _canonical_context_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _active_commands_for_context() -> tuple[list[str], list[dict[str, Any]]]:
    commands = _operation_plan_allowed_commands()
    allowed: list[str] = []
    disallowed: list[dict[str, Any]] = []
    for name, command in sorted(commands.items()):
        status = str(command.get("status") or "")
        if status in {"read_only", "dry_run"}:
            allowed.append(name)
        else:
            disallowed.append({
                "command": name,
                "reason": f"{status}:{command.get('risk_tier') or 'unknown'}",
            })
    return allowed, disallowed


def _select_research_hypothesis_context(
    candidates: list[dict[str, Any]],
    *,
    completed_dimensions: list[str],
    auth_available: bool,
    known_vulnerability_keys: set[str] | None = None,
    known_coverage_keys: set[str] | None = None,
    limit: int = 10,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Rank a broad candidate pool, then return a bounded planner-visible work board.

    Exact v3 identity suppresses already-owned vulnerabilities. Coarse
    family+method+route coverage is only a ranking hint: distinct fields,
    parameters, roles, tenants, or invariants on one operation remain huntable.
    """
    bounded_limit = max(1, min(int(limit or 10), 25))
    known = known_vulnerability_keys or set()
    known_coverage = known_coverage_keys or set()

    def _is_uncovered(item: dict[str, Any]) -> bool:
        exact = _research_hypothesis_vulnerability_key(item)
        if exact and exact in known:
            return False
        return True

    candidates = [item for item in candidates if _is_uncovered(item)]
    schedule = hypothesis_scheduler.rank_hypotheses(
        candidates,
        context={
            "completed_dimensions": completed_dimensions,
            "auth_available": auth_available,
            "require_residue": True,
        },
    )
    by_id = {str(item.get("id")): item for item in candidates}
    scheduled = list(schedule.get("scheduled") or [])
    scheduled_position = {id(entry): index for index, entry in enumerate(scheduled)}

    # Family balance: the richest family (e.g. 100+ mass_assignment leads) would otherwise take every
    # board slot and starve data_exposure / bfla / bola. Float the highest-priority lead of EACH family
    # to the front -- so the bounded board and the top-N selected contracts span families -- then append
    # the rest in priority order. Deterministic and priority-preserving within each group.
    def _entry_family(entry: dict[str, Any]) -> str:
        hypothesis = by_id.get(str(entry.get("hypothesis_id"))) or {}
        return family_proof.canonical_family(hypothesis.get("family")) or "?"

    # Prefer a not-yet-covered operation within each family, but retain covered
    # operations because a different exact dimension on that route can still be
    # a distinct vulnerability.
    by_family_entries: dict[str, list[dict[str, Any]]] = {}
    family_order: list[str] = []
    for entry in scheduled:
        family = _entry_family(entry)
        if family not in by_family_entries:
            family_order.append(family)
            by_family_entries[family] = []
        by_family_entries[family].append(entry)
    for entries in by_family_entries.values():
        entries.sort(
            key=lambda entry: (
                _research_hypothesis_coverage_key(
                    by_id.get(str(entry.get("hypothesis_id"))) or {}
                ) in known_coverage,
                -_research_hypothesis_provability(
                    by_id.get(str(entry.get("hypothesis_id"))) or {}
                )[0],
                scheduled_position.get(id(entry), len(scheduled)),
            )
        )

    family_firsts: list[dict[str, Any]] = []
    family_rest: list[dict[str, Any]] = []
    for family in family_order:
        entries = by_family_entries[family]
        if entries:
            family_firsts.append(entries[0])
            family_rest.extend(entries[1:])
    family_firsts.sort(
        key=lambda entry: (
            _research_hypothesis_coverage_key(
                by_id.get(str(entry.get("hypothesis_id"))) or {}
            ) in known_coverage,
            family_order.index(_entry_family(entry)),
        )
    )
    family_rest.sort(
        key=lambda entry: (
            _research_hypothesis_coverage_key(
                by_id.get(str(entry.get("hypothesis_id"))) or {}
            ) in known_coverage,
            scheduled_position.get(id(entry), len(scheduled)),
        )
    )
    balanced = family_firsts + family_rest

    ranked = [
        {
            **entry,
            "provability_score": _research_hypothesis_provability(
                by_id.get(str(entry.get("hypothesis_id"))) or {}
            )[0],
            "provability_blockers": _research_hypothesis_provability(
                by_id.get(str(entry.get("hypothesis_id"))) or {}
            )[1],
            "hypothesis": by_id.get(str(entry.get("hypothesis_id"))),
        }
        for entry in balanced[:bounded_limit]
    ]
    ranked_order = [
        str(entry.get("hypothesis_id"))
        for entry in ranked
        if entry.get("hypothesis_id")
    ]
    ranked_ids = set(ranked_order)
    summaries = [by_id[item_id] for item_id in ranked_order if item_id in by_id]
    summaries.extend(item for item in candidates if str(item.get("id")) not in ranked_ids)
    return summaries[:bounded_limit], ranked


def _research_hypothesis_matches_live_surface(
    hypothesis: Any,
    live_surface: set[tuple[str, str]],
) -> bool:
    """Reject route-bound leads whose route is absent from the current non-gone inventory."""
    item = hypothesis if isinstance(hypothesis, dict) else {}
    if str(item.get("source") or "").strip().lower() == "invariant":
        return True
    contract = _research_hypothesis_experiment_contract(item)
    route = _canonical_vulnerability_route(contract.get("route"))
    if not route:
        return True
    method = str(contract.get("method") or "").upper()
    if method:
        return (method, route) in live_surface
    return any(candidate_route == route for _, candidate_route in live_surface)


@asynccontextmanager
async def _optional_database_savepoint(conn: Any):
    """Keep best-effort context reads from poisoning an enclosing transaction.

    ``create_research_episode`` builds its first observation atomically. Optional
    rolling-migration reads are allowed to fall back, but PostgreSQL leaves the
    whole transaction aborted after a caught statement error unless that read ran
    in a nested savepoint. Test doubles without transaction support remain usable.
    """
    transaction = getattr(conn, "transaction", None)
    if callable(transaction):
        async with transaction():
            yield
        return
    yield


async def _savepoint_fetch(conn: Any, query: str, *args: Any):
    async with _optional_database_savepoint(conn):
        return await conn.fetch(query, *args)


def _canonical_agent_decision_trace(req: AgentDecisionTraceRequest) -> dict[str, Any]:
    payload = req.model_dump(mode="json")
    payload["context_hash"] = str(payload.get("context_hash") or "").strip().lower()
    payload["command_schema_version"] = str(payload.get("command_schema_version") or "").strip() or "unknown"
    payload["redaction_profile"] = str(payload.get("redaction_profile") or "").strip() or "agent-trace-default"
    payload["planner"] = _redact_agent_payload(payload.get("planner") or {})
    payload["steps"] = [
        {
            "kind": str(step.get("kind") or "").strip(),
            "command": str(step.get("command") or "").strip() or None,
            "status": str(step.get("status") or "planned").strip() or "planned",
            "reason": _redact_agent_text(str(step.get("reason") or "").strip()) if step.get("reason") else None,
            "refs": [str(ref).strip() for ref in step.get("refs", []) if str(ref).strip()],
        }
        for step in payload.get("steps", [])
        if str(step.get("kind") or "").strip()
    ]
    if payload.get("final_rationale"):
        payload["final_rationale"] = _redact_agent_text(str(payload.get("final_rationale") or ""))
    return payload


async def _validate_operation_plan(conn, req: OperationPlanRequest) -> tuple[dict[str, Any], list[str], list[str], str]:
    payload = _canonical_operation_plan(req)
    errors: list[str] = []
    warnings: list[str] = []
    objective = str(payload.get("objective") or "").strip()
    if not objective:
        errors.append("objective_required")
    if not re.fullmatch(r"[a-f0-9]{64}", str(payload.get("context_hash") or "")):
        errors.append("context_hash_must_be_sha256_hex")
    if not payload.get("target_scope"):
        warnings.append("target_scope_empty")
    if not payload.get("actions"):
        errors.append("actions_required")
    if not payload.get("stop_conditions"):
        warnings.append("stop_conditions_empty")
    if not payload.get("success_criteria"):
        warnings.append("success_criteria_empty")

    commands = _operation_plan_allowed_commands()
    plan_risk = str(payload.get("risk_tier") or "read_only")
    plan_risk_rank = RISK_TIER_ORDER.get(plan_risk, 999)
    confirmations = set(payload.get("confirmations") or [])
    needs_approval = False

    for index, action in enumerate(payload.get("actions") or []):
        command_name = str(action.get("command") or "")
        command = commands.get(command_name)
        if not command:
            errors.append(f"action_{index}_unknown_command:{command_name}")
            continue
        command_risk = str(action.get("risk_tier") or command.get("risk_tier") or "read_only")
        if RISK_TIER_ORDER.get(command_risk, 999) > plan_risk_rank:
            errors.append(f"action_{index}_risk_exceeds_plan:{command_name}")
        for required in command.get("required_confirmations") or []:
            if str(required).startswith("confirm_") and required not in confirmations:
                if required == "confirm_production_when_applicable":
                    warnings.append(f"action_{index}_may_need_production_confirmation:{command_name}")
                else:
                    errors.append(f"action_{index}_missing_confirmation:{required}")
        if command.get("status") == "gated":
            needs_approval = True
            if not (action.get("approval_receipt_id") or payload.get("approval_receipt_id")):
                errors.append(f"action_{index}_missing_approval_receipt:{command_name}")

    scope_id = str(payload.get("scope_receipt_id") or "").strip()
    approval_id = str(payload.get("approval_receipt_id") or "").strip()
    if scope_id:
        scope_row = await conn.fetchrow("SELECT * FROM scope_receipts WHERE id=$1", scope_id)
        if not scope_row:
            errors.append("scope_receipt_not_found")
        else:
            scope = _public_scope_receipt_row(scope_row)
            if scope.get("verdict") == "blocked":
                errors.append("scope_receipt_blocked")
            if scope.get("verdict") == "needs_approval":
                needs_approval = True
    elif needs_approval:
        errors.append("scope_receipt_required_for_gated_actions")

    if approval_id:
        try:
            approval_uuid = uuid.UUID(approval_id)
        except ValueError:
            errors.append("approval_receipt_id_must_be_uuid")
        else:
            approval_row = await conn.fetchrow("SELECT * FROM approval_receipts WHERE id=$1", approval_uuid)
            if not approval_row:
                errors.append("approval_receipt_not_found")
            else:
                approval = _public_approval_receipt_row(approval_row)
                if not approval.get("approved_by") or approval.get("denial_reason"):
                    errors.append("approval_receipt_not_approved")
                if scope_id and str(approval.get("scope_receipt_id") or "") != scope_id:
                    errors.append("approval_receipt_scope_mismatch")
                if "confirm_authorized" not in set(approval.get("confirmations") or []):
                    errors.append("approval_receipt_missing_confirm_authorized")
                expires_at = approval_row["expires_at"]
                if expires_at:
                    now = datetime.now(timezone.utc)
                    if expires_at.tzinfo is None:
                        now = utc_now()
                    if expires_at <= now:
                        errors.append("approval_receipt_expired")
    elif needs_approval:
        errors.append("approval_receipt_required_for_gated_actions")

    status = "blocked" if errors else ("approved" if approval_id else "planned")
    return payload, errors, warnings, status




def _source_ingest_path_ignored(path: str, ignored_paths: Sequence[Any] | None = None) -> bool:
    normalized = str(path or "").strip().replace("\\", "/").lstrip("./")
    patterns = list(SOURCE_INGEST_DEFAULT_IGNORED_PATHS) + [str(item or "").strip().replace("\\", "/") for item in (ignored_paths or []) if str(item or "").strip()]
    for pattern in patterns:
        if pattern.endswith("/") and (normalized.startswith(pattern) or f"/{pattern}" in normalized):
            return True
        if fnmatch.fnmatch(normalized, pattern):
            return True
    return False


def _openapi_file_hints(path: str, content: str, source_label: str) -> list[SourceIngestHint]:
    try:
        spec = json.loads(content)
    except Exception:
        return []
    if not isinstance(spec, dict) or not (spec.get("openapi") or spec.get("swagger")):
        return []
    hints: list[SourceIngestHint] = []
    paths = spec.get("paths") if isinstance(spec.get("paths"), dict) else {}
    for route, operations in paths.items():
        if not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            if str(method).lower() not in SOURCE_INGEST_HTTP_METHODS or not isinstance(operation, dict):
                continue
            params = [
                str(param.get("name"))
                for param in (operation.get("parameters") or [])
                if isinstance(param, dict) and param.get("name")
            ]
            body_paths: list[str] = []
            request_body = operation.get("requestBody") if isinstance(operation.get("requestBody"), dict) else {}
            media = request_body.get("content") if isinstance(request_body.get("content"), dict) else {}
            for media_obj in media.values():
                if isinstance(media_obj, dict):
                    body_paths.extend(_schema_property_paths(media_obj.get("schema"), max_paths=20 - len(body_paths)))
                if len(body_paths) >= 20:
                    break
            risks, object_keys, tenant_keys = _source_ingest_risk_hints(
                route=str(route),
                method=str(method),
                parameters=params,
                body_paths=body_paths,
                content=json.dumps(operation, default=str)[:20000],
            )
            hints.append(SourceIngestHint(
                kind="openapi_operation",
                method=str(method).upper(),
                path=str(route),
                operation_id=str(operation.get("operationId") or "")[:200] or None,
                title=str(operation.get("summary") or operation.get("operationId") or "")[:200] or None,
                description=str(operation.get("description") or "")[:1000] or None,
                risk_hints=risks or ["source_informed_review"],
                parameters=params[:50],
                body_paths=body_paths[:50],
                object_keys=object_keys,
                tenant_keys=tenant_keys,
                auth_required=bool(operation.get("security") or spec.get("security")),
                metadata_json={"source_file": path, "source_label": source_label, "source_parser": "openapi_json_v1"},
            ))
    return hints


def _route_file_hints(path: str, content: str, source_label: str, language: str | None = None) -> list[SourceIngestHint]:
    hints: list[SourceIngestHint] = []
    route_patterns = (
        re.compile(r"\b(?:app|router|route|server)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)['\"]", re.I),
        re.compile(r"@(?:Get|Post|Put|Patch|Delete)\s*\(\s*['\"]([^'\"]+)['\"]", re.I),
    )
    for pattern in route_patterns:
        for match in pattern.finditer(content[:100000]):
            if len(hints) >= 50:
                return hints
            if len(match.groups()) == 2:
                method, route = match.group(1), match.group(2)
            else:
                method, route = "GET", match.group(1)
            params = re.findall(r"[:{]([A-Za-z_][A-Za-z0-9_]*)(?:}|(?=/|$))", route)
            nearby = content[max(0, match.start() - 1200): min(len(content), match.end() + 2200)]
            body_paths = [f"$.{name}" for name in sorted(set(re.findall(r"\b(?:body|req\.body|request\.body)\.([A-Za-z_][A-Za-z0-9_]*)", nearby)))[:20]]
            risks, object_keys, tenant_keys = _source_ingest_risk_hints(
                route=route,
                method=method,
                parameters=params,
                body_paths=body_paths,
                content=nearby,
            )
            hints.append(SourceIngestHint(
                kind="backend_route",
                method=str(method).upper(),
                path=route,
                risk_hints=risks or ["source_informed_review"],
                parameters=params[:50],
                body_paths=body_paths[:50],
                object_keys=object_keys,
                tenant_keys=tenant_keys,
                metadata_json={
                    "source_file": path,
                    "source_label": source_label,
                    "source_parser": "backend_route_regex_v1",
                    "language": language,
                },
            ))
    return hints


def _source_hint_route(hint: dict[str, Any]) -> str | None:
    route = _normalize_hypothesis_dedupe_value(hint.get("route") or hint.get("path"))
    if not route:
        return None
    if route.startswith(("http://", "https://")):
        try:
            parsed = urlparse(route)
            route = parsed.path or "/"
        except Exception:
            pass
    if not route.startswith("/") and str(hint.get("kind") or "") not in {"package_manifest", "iac_resource"}:
        route = "/" + route
    return route


def _source_hint_family_and_action(
    hint: dict[str, Any],
    *,
    target_id: str | None,
) -> tuple[str, str | None, str, dict[str, Any], list[str]]:
    risks = {str(item or "").strip().lower().replace("-", "_").replace(" ", "_") for item in hint.get("risk_hints") or []}
    kind = str(hint.get("kind") or "route").strip().lower()
    method = str(hint.get("method") or "GET").strip().upper()
    route = _source_hint_route(hint)
    object_keys = _clean_string_list(hint.get("object_keys"), max_items=20)
    tenant_keys = _clean_string_list(hint.get("tenant_keys"), max_items=20)
    body_paths = _clean_string_list(hint.get("body_paths"), max_items=50)
    params = _clean_string_list(hint.get("parameters"), max_items=50)
    cwe = str(hint.get("cwe") or "").strip() or None
    requires: list[str] = []

    if risks & {"bola", "idor", "bfla", "bopla", "access_control", "object_auth", "tenant_boundary"} or object_keys or tenant_keys:
        family = "bola" if (object_keys or risks & {"bola", "idor", "object_auth"}) else "auth"
        cwe = cwe or ("CWE-639" if family == "bola" else "CWE-285")
        requires.extend(["primary_auth", "second_user_auth"] if family == "bola" else ["primary_auth"])
        action = {
            "command": "asm.improve",
            "parameters": {
                "target_id": target_id,
                "check_family": "bola" if family == "bola" else "auth",
                "exploit_depth": family == "bola",
                "endpoint_hint": {"method": method, "route": route},
            },
            "requires": requires,
            "proof_surface": "runtime_authz_replay",
            "source_only": True,
        }
        return family, cwe, "Source/spec hint suggests an authorization boundary that needs runtime replay.", action, requires

    if risks & {"sqli", "sql_injection", "nosql", "nosql_injection"}:
        action = {
            "command": "asm.improve",
            "parameters": {"target_id": target_id, "check_family": "sqli", "endpoint_hint": {"method": method, "route": route}},
            "requires": [],
            "proof_surface": "runtime_probe",
            "source_only": True,
        }
        return "sqli", cwe or "CWE-89", "Source/spec hint suggests injectable request data that needs runtime SQLi/NoSQL proof.", action, []

    if risks & {"xss", "stored_xss", "reflected_xss", "dom_xss"}:
        action = {
            "command": "asm.improve",
            "parameters": {"target_id": target_id, "check_family": "xss", "endpoint_hint": {"method": method, "route": route}},
            "requires": [],
            "proof_surface": "browser_runtime_probe",
            "source_only": True,
        }
        return "xss", cwe or "CWE-79", "Source/spec hint suggests reflected/stored/client-side data flow that needs browser proof.", action, []

    if risks & {"ssrf", "server_side_request_forgery"}:
        action = {
            "command": "scan.focused_family",
            "parameters": {"target_id": target_id, "family": "ssrf", "endpoint_hint": {"method": method, "route": route}},
            "requires": ["lab_or_deep_intent", "approval_receipt"],
            "proof_surface": "runtime_callback_or_response",
            "source_only": True,
        }
        return "ssrf", cwe or "CWE-918", "Source/spec hint suggests outbound fetch behavior; proof requires a gated runtime callback/response check.", action, ["lab_or_deep_intent", "approval_receipt"]

    if risks & {"lfi", "path_traversal", "file_read", "file_path"}:
        action = {
            "command": "scan.focused_family",
            "parameters": {"target_id": target_id, "family": "lfi", "endpoint_hint": {"method": method, "route": route}},
            "requires": ["lab_or_deep_intent", "approval_receipt"],
            "proof_surface": "runtime_file_evidence",
            "source_only": True,
        }
        return "lfi", cwe or "CWE-22", "Source/spec hint suggests file path handling that needs gated runtime proof.", action, ["lab_or_deep_intent", "approval_receipt"]

    if risks & {"mass_assignment", "overposting"} or body_paths:
        action = {
            "command": "hypothesis.plan_campaign",
            "parameters": {"target_id": target_id, "family": "mass_assignment", "endpoint_hint": {"method": method, "route": route}},
            "requires": ["workflow_context", "auth_context"],
            "proof_surface": "runtime_workflow_state_change",
            "source_only": True,
        }
        return "mass_assignment", cwe or "CWE-915", "Source/spec hint suggests writable body fields that need workflow proof.", action, ["workflow_context", "auth_context"]

    if risks & {"dangerous_upload", "upload", "unrestricted_file_upload"}:
        action = {
            "command": "hypothesis.plan_campaign",
            "parameters": {"target_id": target_id, "family": "dangerous_upload", "endpoint_hint": {"method": method, "route": route}},
            "requires": ["lab_or_deep_intent", "auth_context"],
            "proof_surface": "runtime_upload_handling",
            "source_only": True,
        }
        return "dangerous_upload", cwe or "CWE-434", "Source/spec hint suggests upload handling that needs gated workflow proof.", action, ["lab_or_deep_intent", "auth_context"]

    if kind == "ai_tool_endpoint" or risks & {"ai_tool", "agent_tool", "rag", "mcp"}:
        action = {
            "command": "ai_gate.scan",
            "parameters": {"target_id": target_id, "target_hint": {"method": method, "route": route}, "probe_pack": "shaker-agent-abuse"},
            "requires": ["ai_target_registration", "production_confirmation_when_applicable"],
            "proof_surface": "ai_gate_probe_transcript",
            "source_only": True,
        }
        return "ai_tool_boundary", cwe or "CWE-284", "Source/spec hint suggests an AI/tool boundary that needs AI Gate replay.", action, ["ai_target_registration"]

    if risks & {"secret", "credential", "token", "private_key"}:
        action = {
            "command": "hypothesis.plan_campaign",
            "parameters": {"target_id": target_id, "family": "secret_exposure", "source_hint_kind": kind},
            "requires": ["redacted_source_evidence", "runtime_or_artifact_confirmation"],
            "proof_surface": "redacted_runtime_or_artifact_evidence",
            "source_only": True,
        }
        return "secret_exposure", cwe or "CWE-798", "Source/spec hint suggests secret exposure; runtime/artifact confirmation is still required.", action, ["redacted_source_evidence"]

    action = {
        "command": "hypothesis.plan_campaign",
        "parameters": {"target_id": target_id, "family": "source_informed_review", "endpoint_hint": {"method": method, "route": route}},
        "requires": ["manual_triage"],
        "proof_surface": "runtime_proof_required",
        "source_only": True,
    }
    return "source_informed_review", cwe, "Source/spec hint requires bounded manual or planner triage before runtime testing.", action, ["manual_triage"]


def _planner_action_to_hypothesis_request(
    plan: dict[str, Any],
    action: dict[str, Any],
    *,
    operation_plan_id: str,
    action_index: int,
    created_by: str | None,
) -> tuple[HypothesisRequest | None, dict[str, Any] | None]:
    command = str(action.get("command") or "").strip()
    parameters = action.get("parameters") if isinstance(action.get("parameters"), dict) else {}
    if not command:
        return None, {"reason": "missing_command", "action_index": action_index}
    if command in {"finding.retest", "deployment.decision", "target.get", "finding.get", "mission.timeline"}:
        return None, {"reason": "command_not_hypothesis_seed", "command": command, "action_index": action_index}

    family, cwe, proof_surface, rationale, requires = _planner_action_family_and_proof(command, parameters)
    if not family:
        return None, {"reason": "unsupported_or_incomplete_action", "command": command, "action_index": action_index, "rationale": rationale}

    target_id = _target_id_from_plan_action(plan, parameters)
    method, route = _endpoint_hint_from_parameters(parameters)
    if not route and command in {"asm.improve", "asm.test", "scan.focused_family"}:
        route = str(parameters.get("path_hint") or parameters.get("route_hint") or "").strip() or None
    dedupe_dimensions = {
        "method": method,
        "route": route,
        "object_key": parameters.get("object_key") or parameters.get("object_id_key"),
        "principal_actor": parameters.get("principal_actor") or parameters.get("source_principal"),
        "principal_other": parameters.get("principal_other") or parameters.get("excluded_principal"),
        "tenant": parameters.get("tenant") or parameters.get("tenant_id"),
        "parameter_path": parameters.get("parameter_path") or parameters.get("param"),
        "body_path": parameters.get("body_path"),
        "proof_surface": proof_surface,
    }
    dedupe_dimensions = {key: value for key, value in dedupe_dimensions.items() if value}
    if dedupe_dimensions:
        dedupe_key = "ai-planner-placeholder"
    else:
        params_hash = hashlib.sha256(
            json.dumps(_redact_agent_payload(parameters), sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        dedupe_key = f"ai_planner_action|command={command}|family={family}|target={target_id or 'none'}|params={params_hash}"

    planner = plan.get("planner") if isinstance(plan.get("planner"), dict) else {}
    missing_inputs = _clean_string_list(plan.get("missing_inputs"), max_items=25)
    action_reason = str(action.get("reason") or "").strip()
    confidence = 0.55 if action_reason else 0.45
    if missing_inputs:
        confidence = min(confidence, 0.4)
    risk_tier = str(action.get("risk_tier") or plan.get("risk_tier") or "read_only")
    severity = "high" if family in {"bola", "ssrf", "dangerous_upload", "lfi", "path_traversal"} else "medium"
    endpoint_label = f"{method or ''} {route or ''}".strip()
    title_suffix = f" on {endpoint_label}" if endpoint_label else ""
    required_inputs = list(dict.fromkeys([*requires, *missing_inputs]))
    next_action = _redact_agent_payload({
        "command": command,
        "parameters": parameters,
        "requires": required_inputs,
        "proof_surface": proof_surface,
        "source_only": True,
        "operation_plan_id": operation_plan_id,
        "action_index": action_index,
    })
    return HypothesisRequest(
        source="ai_planner",
        family=family,
        dedupe_key=dedupe_key,
        dedupe_dimensions=dedupe_dimensions,
        target_id=target_id,
        cwe=cwe,
        title=f"Planner lead: {family.replace('_', ' ')}{title_suffix}",
        description=f"{rationale} Planner output is a work signal only and cannot create findings or satisfy proof.",
        severity_guess=severity,
        confidence=confidence,
        next_test_action=next_action,
        endorsement={
            "source": "ai_planner",
            "operation_plan_id": operation_plan_id,
            "action_index": action_index,
            "command": command,
            "reason": action_reason or None,
            "runtime_proof_required": True,
        },
        metadata_json={
            "planner_hypothesis_version": PLANNER_HYPOTHESIS_VERSION,
            "operation_plan_id": operation_plan_id,
            "action_index": action_index,
            "command": command,
            "planner": planner,
            "risk_tier": risk_tier,
            "missing_inputs": missing_inputs,
            "requires": requires,
            "source_only": True,
            "runtime_proof_required": True,
            "dedupe_dimensions": dedupe_dimensions,
        },
        created_by=created_by or str(plan.get("created_by") or "ai_planner").strip() or "ai_planner",
    ), None


def _benchmark_followup_to_hypothesis_request(
    item: BenchmarkFollowupHypothesisItem | dict[str, Any],
    *,
    target_id: str | None,
    benchmark: str,
    scorecard_id: str | None,
    scorecard_scan_id: str | None,
    created_by: str | None,
) -> tuple[HypothesisRequest | None, dict[str, Any] | None]:
    payload = item.model_dump(mode="json") if isinstance(item, BenchmarkFollowupHypothesisItem) else dict(item or {})
    expectation_id = str(payload.get("expectation_id") or "").strip()
    family = str(payload.get("family") or "").strip().lower().replace("-", "_").replace(" ", "_")
    if not expectation_id:
        return None, {"reason": "missing_expectation_id"}
    if not family:
        return None, {"reason": "missing_family", "expectation_id": expectation_id}
    route = _normalize_hypothesis_dedupe_value(payload.get("route"))
    proof_required = str(payload.get("proof_required") or "deterministic").strip().lower()
    proof_surface = BENCHMARK_PROOF_SURFACE.get(proof_required, "runtime_proof_required")
    min_severity = str(payload.get("min_severity") or "").strip().lower() or None
    severity = min_severity if min_severity in {"critical", "high", "medium", "low", "info"} else (
        "high" if family in {"bola", "sqli", "nosqli", "xss"} else "medium"
    )
    blocked_by = _clean_string_list(payload.get("blocked_by"), max_items=25)
    operator_hints = _clean_string_list(payload.get("operator_hints"), max_items=25)
    action = (
        payload.get("next_test_action")
        if isinstance(payload.get("next_test_action"), dict) and payload.get("next_test_action")
        else payload.get("blocked_action_template")
        if isinstance(payload.get("blocked_action_template"), dict) and payload.get("blocked_action_template")
        else None
    )
    requires = list(dict.fromkeys([
        *blocked_by,
        *(operator_hints if family in {"bola", "broken_access_control"} else []),
    ]))
    if action:
        next_action = _redact_agent_payload({
            **action,
            "requires": list(dict.fromkeys([*requires, *_clean_string_list(action.get("requires"), max_items=25)])),
            "proof_surface": proof_surface,
            "source_only": True,
            "benchmark": benchmark,
            "expectation_id": expectation_id,
        })
    else:
        next_action = {
            "command": "hypothesis.plan_campaign",
            "parameters": {
                "target_id": target_id,
                "family": family,
                "benchmark": benchmark,
                "expectation_id": expectation_id,
                "endpoint_hint": {"route": route} if route else {},
            },
            "requires": list(dict.fromkeys([*requires, "detector_or_executor_implementation"])),
            "proof_surface": proof_surface,
            "source_only": True,
        }

    dedupe_dimensions = {
        "route": route or expectation_id,
        "proof_surface": proof_surface,
    }
    if family == "bola":
        dedupe_dimensions["principal_actor"] = "user2"
        dedupe_dimensions["principal_other"] = "user1"
    dedupe_dimensions = {key: value for key, value in dedupe_dimensions.items() if value}
    item_benchmark = str(payload.get("benchmark") or benchmark or "benchmark").strip() or "benchmark"
    status = str(payload.get("status") or "ready").strip().lower()
    reason = str(payload.get("reason") or "").strip() or ("blocked" if blocked_by else "missing_verified_benchmark_expectation")
    metadata = _redact_agent_payload({
        "benchmark_hypothesis_version": BENCHMARK_HYPOTHESIS_VERSION,
        "benchmark": item_benchmark,
        "scorecard_id": scorecard_id,
        "scorecard_scan_id": scorecard_scan_id,
        "expectation_id": expectation_id,
        "benchmark_followup_status": status,
        "benchmark_followup_reason": reason,
        "proof_required": proof_required,
        "proof_surface": proof_surface,
        "min_severity": min_severity,
        "operator_hints": operator_hints,
        "blocked_by": blocked_by,
        "developer_note": payload.get("developer_note"),
        "source_only": True,
        "runtime_proof_required": True,
        "dedupe_dimensions": dedupe_dimensions,
        "followup_metadata": payload.get("metadata_json") if isinstance(payload.get("metadata_json"), dict) else {},
    })
    route_suffix = f" on {route}" if route else ""
    title = f"Benchmark miss: {family.replace('_', ' ')} {expectation_id}{route_suffix}"
    description = (
        f"{item_benchmark} scorecard missed expected {family} evidence ({expectation_id}). "
        "This is a benchmark work signal only; deterministic runtime proof is still required before any finding or gate can change."
    )
    confidence = 0.65 if action and not blocked_by else 0.45 if blocked_by else 0.35
    return HypothesisRequest(
        source="benchmark",
        family=family,
        dedupe_key="benchmark-followup-placeholder",
        dedupe_dimensions=dedupe_dimensions,
        target_id=target_id,
        cwe=BENCHMARK_FAMILY_CWE.get(family),
        title=title,
        description=description,
        severity_guess=severity,
        confidence=confidence,
        next_test_action=next_action,
        endorsement={
            "source": "benchmark",
            "benchmark": item_benchmark,
            "scorecard_id": scorecard_id,
            "scorecard_scan_id": scorecard_scan_id,
            "expectation_id": expectation_id,
            "runtime_proof_required": True,
        },
        metadata_json=metadata,
        created_by=created_by or "benchmark",
    ), None


def _canonical_hypothesis_signal(req: HypothesisSignalRequest) -> dict[str, Any]:
    payload = req.model_dump(mode="json")
    signal = {
        "signal_type": str(payload.get("signal_type") or "").strip(),
        "source": str(payload.get("source") or "").strip(),
        "reason": _redact_agent_text(str(payload.get("reason") or "").strip()) if payload.get("reason") else None,
        "evidence_object_ids": _clean_string_list(payload.get("evidence_object_ids"), max_items=100),
        "tool_receipt_ids": _clean_string_list(payload.get("tool_receipt_ids"), max_items=100),
        "confidence_delta": payload.get("confidence_delta"),
        "status_hint": payload.get("status_hint"),
        "metadata_json": _redact_agent_payload(payload.get("metadata_json") or {}),
        "created_by": str(payload.get("created_by") or "").strip() or None,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    return redact_sensitive(signal, redact_strings=True, scrub_text=True)


def _public_refuter_review_row(row: Any) -> dict[str, Any]:
    payload = row_to_dict(row)
    for key in ("evidence_object_ids", "tool_receipt_ids"):
        payload[key] = _decode_json_value(payload.get(key)) or []
    for key in ("counterevidence", "metadata_json"):
        payload[key] = _redact_agent_payload(_decode_json_value(payload.get(key)) or {})
    payload["execution_enabled"] = False
    payload["findings_updated"] = 0
    payload["hypotheses_updated"] = 0
    return payload




def _finding_delta_target_stats(scan_rows: Sequence[Any]) -> list[dict[str, Any]]:
    """Group completed-scan rows (ordered newest-first per target) into per-target stats."""
    by_target: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for row in scan_rows or []:
        data = row_to_dict(row)
        target_id = str(data.get("target_id") or "").strip()
        if not target_id:
            continue
        entry = by_target.get(target_id)
        if entry is None:
            entry = {
                "target_id": target_id,
                "target_url": data.get("target_url"),
                "latest_scan_id": str(data.get("scan_id") or data.get("id") or "").strip() or None,
                "recent_finding_counts": [],
            }
            by_target[target_id] = entry
            order.append(target_id)
        entry["recent_finding_counts"].append(int(data.get("findings_count") or 0))
    return [by_target[target_id] for target_id in order]


def _finding_delta_refuter_signals(
    target_stats: Sequence[dict[str, Any]],
    *,
    limit: int = 20,
) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    for stat in target_stats or []:
        if not isinstance(stat, dict):
            continue
        signal = _finding_delta_refuter_signal(stat)
        if signal:
            signals.append(signal)
    signals.sort(key=lambda item: -float(item.get("absolute_delta") or 0))
    bounded = max(1, min(int(limit or 20), 100))
    return signals[:bounded]


def _benchmark_win_delta_refuter_signals(
    artifacts: Sequence[Any],
    *,
    limit: int = 20,
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in _benchmark_scorecard_rows(artifacts):
        grouped.setdefault(str(row.get("benchmark") or ""), []).append(row)
    signals = [
        signal
        for benchmark, rows in grouped.items()
        if benchmark
        for signal in [_benchmark_win_delta_refuter_signal({"benchmark": benchmark, "rows": rows})]
        if signal
    ]
    signals.sort(key=lambda item: (-float(item.get("expected_recall_delta") or 0), str(item.get("benchmark") or "")))
    bounded = max(1, min(int(limit or 20), 100))
    return signals[:bounded]


def _load_benchmark_scorecard_artifacts(*, limit: int = 20) -> list[dict[str, Any]]:
    runs_dir = _results_dir() / "benchmark-runs"
    try:
        paths = sorted(
            (p for p in runs_dir.glob("benchmark-*.json") if p.is_file()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[:max(1, min(int(limit or 20), 100))]
    except OSError:
        return []
    artifacts: list[dict[str, Any]] = []
    for path in paths:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(payload, dict):
            payload = dict(payload)
            payload["artifact_path"] = str(path)
            artifacts.append(payload)
    return artifacts


def _refuter_work_summary(
    findings: Sequence[Any],
    reviews: Sequence[Any] = (),
    *,
    limit: int = 20,
    integrity_signals: Sequence[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    reviewed_subjects: set[tuple[str, str]] = set()
    for review in reviews:
        row = row_to_dict(review)
        subject_type = str(row.get("subject_type") or "")
        subject_id = str(row.get("subject_id") or row.get("finding_id") or "")
        if subject_type and subject_id:
            reviewed_subjects.add((subject_type, subject_id))

    candidates: list[dict[str, Any]] = []
    for finding in findings:
        candidate = _finding_refuter_trigger(row_to_dict(finding))
        if not candidate:
            continue
        key = (str(candidate.get("subject_type") or ""), str(candidate.get("subject_id") or ""))
        candidate["already_reviewed"] = key in reviewed_subjects
        candidates.append(candidate)

    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    candidates.sort(
        key=lambda item: (
            bool(item.get("already_reviewed")),
            -severity_rank.get(str(item.get("severity") or ""), 0),
            str(item.get("title") or ""),
        )
    )
    bounded_limit = max(1, min(int(limit or 20), 100))
    trigger_counts = Counter(reason for item in candidates for reason in item.get("trigger_reasons", []))
    type_counts = Counter(str(item.get("trigger_type") or "unknown") for item in candidates)
    unreviewed = [item for item in candidates if not item.get("already_reviewed")]
    # Integrity signals stay separate from finding candidates. They become durable
    # review work only when queue-from-summary explicitly opts in.
    integrity = [dict(signal) for signal in (integrity_signals or []) if isinstance(signal, dict)]
    for signal in integrity:
        key = (str(signal.get("subject_type") or ""), str(signal.get("subject_id") or ""))
        signal["already_reviewed"] = key in reviewed_subjects
    return {
        "summary": {
            "candidate_count": len(candidates),
            "unreviewed_count": len(unreviewed),
            "already_reviewed_count": len(candidates) - len(unreviewed),
            "trigger_counts": dict(trigger_counts),
            "trigger_type_counts": dict(type_counts),
            "integrity_signal_count": len(integrity),
            "limit": bounded_limit,
        },
        "candidates": candidates[:bounded_limit],
        "integrity_signals": integrity[:bounded_limit],
        "execution_enabled": False,
        "findings_updated": 0,
        "hypotheses_updated": 0,
    }


def _canonical_refuter_review(req: RefuterReviewRequest) -> dict[str, Any]:
    payload = req.model_dump(mode="json")
    verdict = str(payload.get("refuter_verdict") or "").strip() or None
    basis = str(payload.get("verdict_basis") or "signal_only").strip()
    if verdict and basis not in REFUTER_VERDICT_BASES:
        raise HTTPException(
            status_code=400,
            detail="refuter_verdict requires deterministic_replay, cryptographic, parser_protocol, or human_approved_review basis",
        )
    if basis != "signal_only" and not verdict:
        raise HTTPException(status_code=400, detail="non-signal refuter basis requires refuter_verdict")
    canonical = {
        "subject_type": str(payload.get("subject_type") or "").strip(),
        "subject_id": str(payload.get("subject_id") or "").strip() or None,
        "target_id": str(payload.get("target_id") or "").strip() or None,
        "finding_id": str(payload.get("finding_id") or "").strip() or None,
        "hypothesis_id": str(payload.get("hypothesis_id") or "").strip() or None,
        "campaign_id": str(payload.get("campaign_id") or "").strip() or None,
        "trigger_reason": _redact_agent_text(str(payload.get("trigger_reason") or "").strip()),
        "refuter_signal": str(payload.get("refuter_signal") or "question").strip(),
        "refuter_verdict": verdict,
        "verdict_basis": basis,
        "confidence_delta": payload.get("confidence_delta"),
        "evidence_object_ids": _clean_string_list(payload.get("evidence_object_ids"), max_items=100),
        "tool_receipt_ids": _clean_string_list(payload.get("tool_receipt_ids"), max_items=100),
        "counterevidence": _redact_agent_payload(payload.get("counterevidence") or {}),
        "notes": _redact_agent_text(str(payload.get("notes") or "").strip()) if payload.get("notes") else None,
        "metadata_json": _redact_agent_payload(payload.get("metadata_json") or {}),
        "created_by": str(payload.get("created_by") or "").strip() or None,
        "status": "verdict_recorded" if verdict else "recorded",
    }
    return _apply_refuter_negative_gate(canonical)


def _refuter_review_from_verification_outcome(verification: dict[str, Any]) -> dict[str, Any]:
    verdict = str(verification.get("verdict") or "").strip().lower()
    result_status = str(verification.get("result_status") or "").strip().lower()
    status = str(verification.get("status") or "").strip().lower()
    mode = str(verification.get("verification_mode") or "deterministic").strip().lower()
    errored = status == "failed" or verdict == "error" or result_status == "error"
    deterministic_basis = mode != "ai_driven" and not errored
    if verdict == "exploited":
        signal, refuter_verdict, confidence_delta = "support", "supported", 0.25
        observation = "replay_reproduced"
    elif verdict == "false_positive":
        signal, refuter_verdict, confidence_delta = "refute", "refuted", -0.75
        observation = "false_positive"
    elif verdict == "likely_fixed":
        signal, refuter_verdict, confidence_delta = "weaken", "weakened", -0.5
        observation = "not_reproduced"
    elif verdict in {"blocked_by_security", "out_of_scope_internal"}:
        signal, refuter_verdict, confidence_delta = "weaken", "weakened", -0.35
        observation = verdict
    elif verdict == "likely_vulnerable":
        signal, refuter_verdict, confidence_delta = "support", "inconclusive", 0.1
        observation = "partial_evidence"
    elif verdict in {"inconclusive", "error"} or result_status in {"inconclusive", "error"}:
        signal, refuter_verdict, confidence_delta = "question", "inconclusive", 0.0
        observation = verdict or result_status or "inconclusive"
    else:
        signal, refuter_verdict, confidence_delta = "question", "inconclusive", 0.0
        observation = "unknown"

    basis = "deterministic_replay" if deterministic_basis else "signal_only"
    if not deterministic_basis:
        refuter_verdict = None
    return {
        "refuter_signal": signal,
        "refuter_verdict": refuter_verdict,
        "verdict_basis": basis,
        "confidence_delta": confidence_delta,
        "observation": observation,
        "deterministic_basis": deterministic_basis,
    }


def _campaign_type_for_hypothesis_family(family: Any) -> str:
    normalized = str(family or "").strip().lower()
    if normalized in {"bola", "bfla", "bopla", "idor", "auth", "authorization", "tenant"}:
        return "api_authz"
    if normalized in {"ai_gate", "prompt_injection", "rag", "mcp"}:
        return "ai_red_team"
    if normalized.startswith("model_intake") or normalized in {"model", "trust_preview"}:
        return "model_intake"
    return "focused_family"


def _risk_tier_for_hypothesis_action(hypothesis: dict[str, Any], next_test_action: dict[str, Any]) -> str:
    parameters = next_test_action.get("parameters") if isinstance(next_test_action.get("parameters"), dict) else {}
    family = str(parameters.get("check_family") or hypothesis.get("family") or "").strip().lower()
    if family in {"bola", "bfla", "bopla", "idor", "auth", "authorization", "tenant"}:
        return "credential"
    command = str(next_test_action.get("command") or "").strip()
    if command in {"asm.improve", "asm.test", "scan.submit", "finding.retest"}:
        return "active"
    return "read_only"


def _authz_replay_plan_from_hypothesis_action(
    hypothesis: dict[str, Any],
    next_test_action: dict[str, Any],
) -> dict[str, Any]:
    """Derive a non-executing deterministic replay contract from principal facts."""
    matrix = next_test_action.get("principal_matrix") if isinstance(next_test_action.get("principal_matrix"), dict) else {}
    matched = matrix.get("matched_principals") if isinstance(matrix.get("matched_principals"), dict) else {}
    primary = matched.get("primary") if isinstance(matched.get("primary"), dict) else {}
    alternate = matched.get("alternate") if isinstance(matched.get("alternate"), dict) else {}
    expectations = [
        item for item in (matrix.get("matching_expectations") or [])
        if isinstance(item, dict)
    ][:10]
    metadata = hypothesis.get("metadata_json") if isinstance(hypothesis.get("metadata_json"), dict) else {}
    dims = metadata.get("dedupe_dimensions") if isinstance(metadata.get("dedupe_dimensions"), dict) else {}
    first_expectation = expectations[0] if expectations else {}
    route_candidate = str(dims.get("route") or "").strip()
    concrete_path = route_candidate if route_candidate and not _authz_replay_path_is_template(route_candidate) else None
    preconditions = matrix.get("precondition_signals") if isinstance(matrix.get("precondition_signals"), dict) else {}
    missing_preconditions = [
        name for name, state in preconditions.items()
        if str(state or "").strip().lower() != "configured"
    ]
    expected_access = [
        {
            "method": item.get("method"),
            "path": item.get("path"),
            "principal_label": item.get("principal_label"),
            "principal_role": item.get("principal_role"),
            "principal_auth_state": item.get("principal_auth_state"),
            "tenant_id": item.get("tenant_id"),
            "expected_access": item.get("expected_access"),
            "expected_http_status": item.get("expected_http_status"),
            "concrete_path": concrete_path,
        }
        for item in expectations
    ]
    return {
        "mode": "deterministic_authz_replay",
        "executable": False,
        "proof_state": "planned_not_executed",
        "method": first_expectation.get("method") or dims.get("method"),
        "path": first_expectation.get("path") or dims.get("route"),
        "concrete_path": concrete_path,
        "object_key": dims.get("object_key"),
        "principal_pair": {
            "primary": {
                "label": primary.get("label"),
                "role": primary.get("role"),
                "auth_state": primary.get("auth_state"),
                "tenant_id": primary.get("tenant_id"),
            } if primary else None,
            "alternate": {
                "label": alternate.get("label"),
                "role": alternate.get("role"),
                "auth_state": alternate.get("auth_state"),
                "tenant_id": alternate.get("tenant_id"),
            } if alternate else None,
        },
        "expected_access": expected_access,
        "missing_preconditions": missing_preconditions,
        "source": "hypothesis_principal_matrix",
    }


def _hypothesis_family_matches_finding(hypothesis: dict[str, Any], finding: dict[str, Any]) -> bool:
    raw_family = str(hypothesis.get("family") or "").strip().lower().replace("-", "_")
    evidence = _decode_json_value(finding.get("evidence")) or {}
    inferred = str(infer_type_from_title_tool(finding.get("title"), finding.get("tool")) or "").lower()
    if raw_family in {"nosql", "nosqli", "nosql_injection"}:
        return inferred == "nosqli"
    if raw_family in {"sqli", "sql", "sql_injection"}:
        return inferred == "sqli"

    family_aliases = {
        "idor": "bola",
        "bfla": "bola",
        "bopla": "bola",
        "object_authorization": "bola",
        "authentication": "auth",
        "access_control": "auth",
        "cross_site_scripting": "xss",
        "massassignment": "mass_assignment",
    }
    normalized = family_aliases.get(raw_family, check_registry.normalize_check_family(raw_family, allow_all=False) or raw_family)
    if normalized == "bola" and inferred in {"bola", "idor"}:
        return True
    if normalized == "xss" and inferred == "xss":
        return True
    if normalized == "jwt" and inferred == "jwt":
        return True

    spec = check_registry.get_check_family(normalized)
    title = str(finding.get("title") or "").strip().lower()
    tool = str(finding.get("tool") or "").strip().lower()
    cwe = str(finding.get("cwe") or "").strip().upper()
    if spec and (
        tool in {item.lower() for item in spec.finding_tools}
        or cwe in {item.upper() for item in spec.finding_cwes}
        or any(marker.lower() in title for marker in spec.finding_title_markers)
    ):
        return True

    tokens = _hypothesis_structured_values(
        evidence,
        {"family", "category", "finding_type", "probe_family", "check_family", "type"},
    )
    tokens.update({tool, inferred})
    normalized_tokens = {
        family_aliases.get(token.lower().replace("-", "_"), token.lower().replace("-", "_"))
        for token in tokens
    }
    return normalized in normalized_tokens


def _hypothesis_dimensions_match_finding(hypothesis: dict[str, Any], finding: dict[str, Any]) -> bool:
    metadata = hypothesis.get("metadata_json") if isinstance(hypothesis.get("metadata_json"), dict) else {}
    dimensions = metadata.get("dedupe_dimensions") if isinstance(metadata.get("dedupe_dimensions"), dict) else {}
    if not _hypothesis_route_matches_finding(dimensions.get("route"), finding):
        return False
    evidence = _decode_json_value(finding.get("evidence")) or {}
    request = _decode_json_value(finding.get("request")) or {}
    expected_method = str(dimensions.get("method") or "").strip().upper()
    if expected_method:
        observed_methods = {
            value.upper()
            for value in _hypothesis_structured_values([evidence, request], {"method", "http_method"})
        }
        if not observed_methods or expected_method not in observed_methods:
            return False
    for dimension_name, observed_keys in (
        ("parameter_path", {"parameter", "param", "parameter_path"}),
        ("body_path", {"body_path", "parameter_path", "parameter", "param"}),
        ("object_key", {"object_key", "object_id", "resource_id", "id_field"}),
    ):
        expected_value = str(dimensions.get(dimension_name) or "").strip().lower()
        if not expected_value:
            continue
        observed_values = {
            value.strip().lower()
            for value in _hypothesis_structured_values([evidence, request], observed_keys)
        }
        if expected_value not in observed_values:
            return False
    return True


def _hypothesis_subject_matches_finding(hypothesis: dict[str, Any], finding: dict[str, Any]) -> bool:
    """Require an exact durable subject link, not merely same target/family."""
    metadata = hypothesis.get("metadata_json") if isinstance(hypothesis.get("metadata_json"), dict) else {}
    next_action = hypothesis.get("next_test_action") if isinstance(hypothesis.get("next_test_action"), dict) else {}
    hypothesis_refs = _hypothesis_structured_values(
        [metadata, next_action, hypothesis.get("promoted_finding_ids") or []],
        {"finding_id", "finding_fingerprint", "scanner_finding_id", "source_finding_id"},
    )
    finding_refs = {
        str(value).strip()
        for value in (
            finding.get("id"), finding.get("fingerprint"), finding.get("source_finding_id")
        )
        if value
    }
    if hypothesis_refs & finding_refs:
        return True
    dimensions = metadata.get("dedupe_dimensions") if isinstance(metadata.get("dedupe_dimensions"), dict) else {}
    has_route = bool(str(dimensions.get("route") or "").strip())
    has_subject_dimension = any(
        bool(str(dimensions.get(key) or "").strip())
        for key in ("parameter_path", "body_path", "object_key")
    )
    return bool(has_route and has_subject_dimension and _hypothesis_dimensions_match_finding(hypothesis, finding))


def _hypothesis_verification_ids(value: Any, *, depth: int = 4) -> set[uuid.UUID]:
    ids: set[uuid.UUID] = set()
    if depth < 0:
        return ids
    if isinstance(value, dict):
        for key, nested in list(value.items())[:100]:
            if str(key).strip().lower() in {"verification_id", "retest_id"}:
                try:
                    ids.add(uuid.UUID(str(nested)))
                except (TypeError, ValueError):
                    pass
            ids.update(_hypothesis_verification_ids(nested, depth=depth - 1))
    elif isinstance(value, list):
        for nested in value[:100]:
            ids.update(_hypothesis_verification_ids(nested, depth=depth - 1))
    return ids


def _arsenal_readonly_adapters() -> dict[str, Any]:
    return {
        "campaign.list": _arsenal_dispatch_campaign_list,
        "command_result.list": _arsenal_dispatch_command_result_list,
        "mission.timeline": _arsenal_dispatch_mission_timeline,
        "tool.status": _arsenal_dispatch_tool_status,
        "local_agent.list": _arsenal_dispatch_local_agent_list,
        "local_agent.plan_dry_run": _arsenal_dispatch_local_agent_plan_dry_run,
        "local_agent.parse_plan": _arsenal_dispatch_local_agent_parse_plan,
        "local_agent.test": _arsenal_dispatch_local_agent_test,
        "scope.preview": _arsenal_dispatch_scope_preview,
        "target.list": _arsenal_dispatch_target_list,
        "target.get": _arsenal_dispatch_target_get,
        "target.principals": _arsenal_dispatch_target_principals,
        "target.principal_matrix": _arsenal_dispatch_target_principal_matrix,
        "target.invariants": _arsenal_dispatch_target_invariants,
        "target.invariant.compile": _arsenal_dispatch_target_invariant_compile,
        "target.invariant.verification_plan": _arsenal_dispatch_target_invariant_verification_plan,
        "target.invariant.generate_hypotheses": _arsenal_dispatch_target_invariant_hypotheses,
        "exposure.graph.get": _arsenal_dispatch_exposure_graph_get,
        "asm.gaps": _arsenal_dispatch_asm_gaps,
        "asm.activity": _arsenal_dispatch_asm_activity,
        "scan.result": _arsenal_dispatch_scan_result,
        "finding.list": _arsenal_dispatch_finding_list,
        "finding.get": _arsenal_dispatch_finding_get,
        "operation_plan.list": _arsenal_dispatch_operation_plan_list,
        "operation_plan.preview": _arsenal_dispatch_operation_plan_preview,
        "agent_context_pack.list": _arsenal_dispatch_agent_context_pack_list,
        "agent_context_pack.record": _arsenal_dispatch_agent_context_pack_record,
        "agent_context_pack.generate_from_target": _arsenal_dispatch_agent_context_pack_generate_from_target,
        "agent_decision_trace.list": _arsenal_dispatch_agent_decision_trace_list,
        "agent_decision_trace.record": _arsenal_dispatch_agent_decision_trace_record,
        "hypothesis.list": _arsenal_dispatch_hypothesis_list,
        "hypothesis.situation_report": _arsenal_dispatch_hypothesis_situation_report,
        "hypothesis.record": _arsenal_dispatch_hypothesis_record,
        "hypothesis.generate_from_source": _arsenal_dispatch_hypothesis_generate_from_source,
        "hypothesis.generate_from_plan": _arsenal_dispatch_hypothesis_generate_from_plan,
        "hypothesis.generate_from_benchmark": _arsenal_dispatch_hypothesis_generate_from_benchmark,
        "hypothesis.claim": _arsenal_dispatch_hypothesis_claim,
        "hypothesis.signal": _arsenal_dispatch_hypothesis_signal,
        "hypothesis.plan_campaign": _arsenal_dispatch_hypothesis_plan_campaign,
        "hypothesis.generate_from_graph": _arsenal_dispatch_hypothesis_generate_from_graph,
        "campaign.get": _arsenal_dispatch_campaign_get,
        "campaign_action.list": _arsenal_dispatch_campaign_action_list,
        "campaign.create": _arsenal_dispatch_campaign_create,
        "campaign.link_action": _arsenal_dispatch_campaign_link_action,
        "ai_target.list": _arsenal_dispatch_ai_target_list,
        "ai_gate.target_history_export": _arsenal_dispatch_ai_gate_target_history_export,
        "model_intake.trust_preview": _arsenal_dispatch_model_intake_trust_preview,
        "model_intake.evidence_export": _arsenal_dispatch_model_intake_evidence_export,
        "evidence.get": _arsenal_dispatch_evidence_get,
        "evidence.export_manifest": _arsenal_dispatch_evidence_export_manifest,
        "evidence.export_bundle": _arsenal_dispatch_evidence_export_bundle,
        "evidence_instance.list": _arsenal_dispatch_evidence_instance_list,
        "evidence_instance.record": _arsenal_dispatch_evidence_instance_record,
        "tool_receipt.list": _arsenal_dispatch_tool_receipt_list,
        "tool_receipt.record": _arsenal_dispatch_tool_receipt_record,
        "deployment.decision": _arsenal_dispatch_deployment_decision,
        "refuter_review.list": _arsenal_dispatch_refuter_review_list,
        "refuter_review.summary": _arsenal_dispatch_refuter_review_summary,
        "refuter_review.record": _arsenal_dispatch_refuter_review_record,
        "refuter_review.queue_from_summary": _arsenal_dispatch_refuter_review_queue_from_summary,
    }


def _arsenal_gated_adapters() -> dict[str, Any]:
    return {
        "asm.improve": _arsenal_dispatch_asm_improve,
        "asm.test": _arsenal_dispatch_asm_test,
        "asm.recon": _arsenal_dispatch_asm_recon,
        "finding.retest": _arsenal_dispatch_finding_retest,
        "scan.focused_family": _arsenal_dispatch_scan_focused_family,
        "ai_gate.scan": _arsenal_dispatch_ai_gate_scan,
        "ai_gate.replay_probe": _arsenal_dispatch_ai_gate_replay_probe,
        "model_intake.scan": _arsenal_dispatch_model_intake_scan,
        "finding_exception.lifecycle_sweep": _arsenal_dispatch_finding_exception_lifecycle_sweep,
        "evidence.retention_sweep": _arsenal_dispatch_evidence_retention_sweep,
        "refuter_review.execute_plan": _arsenal_dispatch_refuter_review_execute_plan,
        "refuter_review.derive_verdict": _arsenal_dispatch_refuter_review_derive_verdict,
        "authz.replay_plan": _arsenal_dispatch_authz_replay_plan,
        "authz.promote_replay_finding": _arsenal_dispatch_authz_promote_replay_finding,
        "target.principal_matrix.record": _arsenal_dispatch_target_principal_matrix_record,
        "target.invariant_contract.record": _arsenal_dispatch_target_invariant_record,
        "target.invariant_contract.approve": _arsenal_dispatch_target_invariant_approve,
        "target.invariant_contract.retire": _arsenal_dispatch_target_invariant_retire,
        "hypothesis.reconcile_proof": _arsenal_dispatch_hypothesis_reconcile_proof,
        "experiment.http_diff": _arsenal_dispatch_http_diff,
        "experiment.workflow": _arsenal_dispatch_workflow,
    }


async def _validate_campaign_action_for_execution(conn, req: ArsenalExecuteRequest) -> dict[str, Any] | None:
    if not req.campaign_action_id:
        return None
    try:
        action_uuid = uuid.UUID(str(req.campaign_action_id))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="campaign_action_id must be a UUID") from exc
    row = await conn.fetchrow("SELECT * FROM campaign_actions WHERE id=$1", action_uuid)
    if not row:
        raise HTTPException(status_code=404, detail="Campaign action not found")
    action = _public_campaign_action_row(row)
    planned_command = str(action.get("command") or action.get("action_name") or "").strip()
    result_json = action.get("result_json") if isinstance(action.get("result_json"), dict) else {}
    replay = result_json.get("authz_replay") if isinstance(result_json.get("authz_replay"), dict) else {}
    promotes_completed_replay = (
        req.command == "authz.promote_replay_finding"
        and planned_command == "authz.replay_plan"
        and bool(replay)
    )
    if planned_command and planned_command != req.command and not promotes_completed_replay:
        raise HTTPException(status_code=409, detail="campaign_action_id command does not match requested command")
    if req.campaign_id and row.get("mission_campaign_id"):
        try:
            requested_campaign = uuid.UUID(str(req.campaign_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="campaign_id must be a UUID")
        if uuid.UUID(str(row.get("mission_campaign_id"))) != requested_campaign:
            raise HTTPException(status_code=409, detail="campaign_action_id belongs to a different campaign")
    return action


async def _command_result_response_row(conn, command_result_id) -> dict[str, Any] | None:
    if not command_result_id:
        return None
    try:
        command_result_uuid = uuid.UUID(str(command_result_id))
    except (TypeError, ValueError):
        return None
    try:
        row = await conn.fetchrow("SELECT * FROM command_results WHERE id=$1", command_result_uuid)
    except Exception:
        return None
    return _public_command_result_row(row) if row else None


async def _validate_arsenal_execute_request(conn, req: ArsenalExecuteRequest) -> tuple[dict[str, Any], str, str]:
    if req.campaign_id:
        try:
            campaign_uuid = uuid.UUID(str(req.campaign_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="campaign_id must be a UUID")
        if not await conn.fetchval("SELECT 1 FROM campaigns WHERE id=$1", campaign_uuid):
            raise HTTPException(status_code=404, detail="Campaign not found")

    commands = _operation_plan_allowed_commands()
    command = commands.get(req.command)
    if not command:
        raise HTTPException(status_code=400, detail=f"Unknown Command Arsenal command: {req.command}")
    status = str(command.get("status") or "")
    risk_tier = str(command.get("risk_tier") or "read_only")
    if status in {"catalog_only", "out_of_scope", "contract"}:
        raise HTTPException(status_code=400, detail=f"Command '{req.command}' is not executable (status={status})")
    parameter_errors = _validate_command_parameters(command, req.parameters)
    if parameter_errors:
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_arsenal_parameters", "violations": parameter_errors},
        )
    return command, status, risk_tier


async def _arsenal_adapter_pending_response(
    conn,
    req: ArsenalExecuteRequest,
    command_spec: dict[str, Any],
    *,
    catalog_status: str,
    risk_tier: str,
    created_by: str | None = None,
) -> dict[str, Any]:
    cr = await _record_blocked_command_result(
        conn,
        action_name=req.command,
        command=req.command,
        risk_tier=risk_tier,
        status="blocked",
        blocked_by=["dispatch_adapter_pending"],
        operator_message=f"{req.command} is catalogued as {catalog_status} but has no gateway dispatch adapter yet",
        created_by=created_by if created_by is not None else req.created_by,
    )
    await _link_command_result_to_campaign(conn, req.campaign_id, cr["id"] if cr else None)
    linked_action = await _link_command_result_to_campaign_action(conn, req.campaign_action_id, cr)
    return {
        "command": req.command,
        "dispatched": False,
        "dry_run": True,
        "execution_blocked_reason": "dispatch_adapter_pending",
        "operation_id": cr["id"] if cr else None,
        "command_result": cr,
        "action_state": _arsenal_action_state(
            req,
            command_spec,
            catalog_status=catalog_status,
            risk_tier=risk_tier,
            phase="blocked",
            dispatched=False,
            dry_run=True,
            execution_enabled=False,
            operation_id=cr["id"] if cr else None,
            command_result=cr,
            blocked_reason="dispatch_adapter_pending",
            missing_confirmations=[],
            adapter_status="pending",
        ),
        "campaign_action": linked_action,
        "execution_enabled": False,
    }




def _research_family_readiness_requirements(families: set[str], *, gated: bool) -> dict[str, Any]:
    """Derive launch prerequisites from the selected families, not the campaign tier."""
    primary = bool(gated and families.intersection(RESEARCH_PRIMARY_CREDENTIAL_FAMILIES))
    second_user = bool(gated and families.intersection(RESEARCH_SECOND_USER_FAMILIES))
    minimum_routes = (
        RESEARCH_SURFACE_MIN_UNIQUE_ROUTES if second_user
        else RESEARCH_SURFACE_MIN_AUTHENTICATED_ROUTES if primary
        else RESEARCH_SURFACE_MIN_EXECUTABLE_ROUTES
    )
    return {
        "primary_credentials": primary,
        "second_user": second_user,
        "authenticated_preflight": primary,
        "unique_routes": minimum_routes,
        "authenticated_routes": RESEARCH_SURFACE_MIN_AUTHENTICATED_ROUTES if primary else 0,
        "executable_routes": RESEARCH_SURFACE_MIN_EXECUTABLE_ROUTES if gated else 0,
    }


def _research_exhausted_families(
    candidates: list[dict[str, Any]], known_vulnerability_keys: set[str] | None,
) -> list[str]:
    """Families whose every candidate has the same exact identity as an owned finding.

    Coarse operation coverage is deliberately insufficient here because one route
    may contain distinct parameter, field, role, tenant, or invariant failures.
    """
    known = known_vulnerability_keys or set()
    if not known:
        return []
    by_family: dict[str, list[bool]] = {}
    for item in candidates:
        if not isinstance(item, dict):
            continue
        family = family_proof.canonical_family(item.get("family"))
        if not family:
            continue
        identity = _research_hypothesis_vulnerability_key(item)
        by_family.setdefault(family, []).append(bool(identity and identity in known))
    return sorted(family for family, flags in by_family.items() if flags and all(flags))


def _research_action_semantic_dimension(action: dict[str, Any]) -> str | None:
    """Collapse volatile ids/prose while retaining method, payload, principal, and assertions."""
    command = str(action.get("command") or "").strip()
    parameters = action.get("parameters") if isinstance(action.get("parameters"), dict) else {}
    if command not in {"experiment.workflow", "experiment.http_diff"}:
        return None
    routes: set[str] = set()
    for step in parameters.get("steps") or []:
        if not isinstance(step, dict):
            continue
        route = _canonical_vulnerability_route(step.get("path") or step.get("route"))
        if route:
            routes.add(route)
    direct_route = _canonical_vulnerability_route(parameters.get("route"))
    if direct_route:
        routes.add(direct_route)
    if not routes:
        return None
    comparable = _research_action_dedupe_comparable(action)
    material = {
        "version": "semantic-experiment-v2",
        "routes": sorted(routes),
        "experiment": comparable,
    }
    return _research_canonical_hash(material)


RESEARCH_RECON_COMMANDS = frozenset({
    "asm.gaps",
    "asm.recon",
    "target.get",
    "target.graph",
    "target.principal_matrix",
    "hypothesis.list",
    "hypothesis.generate_from_graph",
})


RESEARCH_EXPERIMENT_OUTCOMES = frozenset({
    "verified", "refuted", "supported_unverified", "inconclusive", "blocked",
})


def _research_experiment_outcome(action: Any, command_result: Any) -> dict[str, Any] | None:
    """Normalize a completed experiment into a scientific outcome.

    Absence of a finding is not refutation.  Only a deterministic family-proof
    ``refuted`` verdict counts as falsification; transport/runtime failures and
    missing proof stay visible as blocked/inconclusive.
    """
    action_payload = action if isinstance(action, dict) else _decode_json_value(action) or {}
    command = str(action_payload.get("command") or "")
    if command not in {"experiment.http_diff", "experiment.workflow"}:
        return None
    result = command_result if isinstance(command_result, dict) else row_to_dict(command_result)
    result_json = _decode_json_value(result.get("result_json")) or {}
    proof = result_json.get("family_proof") if isinstance(result_json.get("family_proof"), dict) else {}
    if not proof:
        nested = result_json.get("workflow") if isinstance(result_json.get("workflow"), dict) else {}
        proof = nested.get("family_proof") if isinstance(nested.get("family_proof"), dict) else {}
    verdict = str(proof.get("verdict") or "").strip().lower()
    finding_ids = _decode_json_value(result.get("finding_ids")) or []
    if finding_ids or verdict == "verified":
        outcome = "verified"
    elif verdict in RESEARCH_EXPERIMENT_OUTCOMES:
        outcome = verdict
    else:
        status = str(result.get("command_status") or result.get("status") or "").strip().lower()
        proof_state = str(
            result_json.get("proof_state")
            or (result_json.get("experiment") or {}).get("proof_state")
            or ""
        ).strip().lower()
        if status in {"blocked", "approval_required", "failed", "cancelled", "error", "partial"}:
            outcome = "blocked"
        elif proof_state in {"supported", "supported_unverified", "likely_vulnerable"}:
            outcome = "supported_unverified"
        else:
            outcome = "inconclusive"
    failure_class, failed_predicates = _research_experiment_failure_detail(result_json)
    if outcome == "blocked" and not failure_class:
        failure_class = "dispatch_or_policy_blocked"
    elif outcome == "inconclusive" and not failure_class:
        failure_class = "proof_evidence_missing"
    return {
        "outcome": outcome,
        "reason": str(
            proof.get("reason")
            or result_json.get("failure_reason")
            or result.get("command_status")
            or result.get("status")
            or ""
        )[:500],
        "family": str(proof.get("family") or (action_payload.get("parameters") or {}).get("proof_family") or "")[:80],
        "deterministic_refutation": outcome == "refuted" and bool(proof.get("refuted_by")),
        "failure_class": failure_class,
        "failed_predicates": failed_predicates[:16],
    }


async def _research_known_vulnerability_keys(conn: Any, target_id: Any) -> set[str]:
    rows = await conn.fetch(
        """
        SELECT tool, cwe, title, url, evidence, request
        FROM findings
        WHERE target_id=$1
          AND status IN ('active','resolved','accepted_risk')
        ORDER BY last_seen_at DESC
        LIMIT 2000
        """,
        _optional_uuid(target_id),
    )
    return {
        key
        for key in (_finding_vulnerability_key(row) for row in rows)
        if key
    }


async def _research_known_coverage_keys(conn: Any, target_id: Any) -> set[str]:
    """Coarse family+method+route coverage keys of already-owned findings (see _canonical_coverage_key).

    Used only to keep already-found vulnerabilities off the hunt board so net-new families surface;
    dispatch still checks the exact v3 key via _research_known_vulnerability_keys.
    """
    rows = await conn.fetch(
        """
        SELECT tool, cwe, title, url, evidence, request
        FROM findings
        WHERE target_id=$1
          AND status IN ('active','resolved','accepted_risk')
        ORDER BY last_seen_at DESC
        LIMIT 2000
        """,
        _optional_uuid(target_id),
    )
    return {
        key
        for key in (_finding_coverage_key(row) for row in rows)
        if key
    }


async def _research_net_new_finding_count(
    conn: Any,
    target_id: Any,
    *,
    campaign_id: Any = None,
    tool: str = "autonomous_workflow",
    verdict: str | None = "exploited",
) -> int:
    """Count distinct exact findings from ``tool`` not owned by another tool.

    When a campaign is supplied, only findings carrying that campaign's durable
    research provenance count. This prevents a new campaign inheriting credit
    from earlier target hunts.
    """
    rows = await conn.fetch(
        """
        SELECT tool, cwe, title, url, evidence, request, last_verification_verdict
        FROM findings
        WHERE target_id=$1 AND status IN ('active','resolved','accepted_risk')
        """,
        _optional_uuid(target_id),
    )
    other_keys: set[str] = set()
    tool_rows: list[dict[str, Any]] = []
    campaign_text = str(campaign_id or "").strip()
    for row in rows:
        finding = row_to_dict(row)
        if str(finding.get("tool") or "") == tool:
            if campaign_text:
                evidence = _decode_json_value(finding.get("evidence")) or {}
                provenance_items = (
                    evidence.get("research_provenance_history")
                    if isinstance(evidence, dict)
                    and isinstance(evidence.get("research_provenance_history"), list)
                    else []
                )
                if isinstance(evidence, dict) and isinstance(evidence.get("research_provenance"), dict):
                    provenance_items = [*provenance_items, evidence["research_provenance"]]
                if not any(
                    isinstance(item, dict)
                    and str(item.get("campaign_id") or "") == campaign_text
                    for item in provenance_items
                ):
                    continue
            tool_rows.append(finding)
        else:
            key = _finding_vulnerability_key(finding)
            if key:
                other_keys.add(key)
    net_new_keys: set[str] = set()
    for finding in tool_rows:
        if verdict and str(finding.get("last_verification_verdict") or "") != verdict:
            continue
        key = _finding_vulnerability_key(finding)
        if key and key not in other_keys:
            net_new_keys.add(key)
    return len(net_new_keys)






class SourceIngestHint(BaseModel):
    kind: str = Field(default="route", pattern="^(route|endpoint|openapi_operation|graphql_field|package_manifest|frontend_route|backend_route|iac_resource|ai_tool_endpoint)$")
    method: Optional[str] = Field(default=None, max_length=16)
    path: Optional[str] = Field(default=None, max_length=500)
    route: Optional[str] = Field(default=None, max_length=500)
    operation_id: Optional[str] = Field(default=None, max_length=200)
    title: Optional[str] = Field(default=None, max_length=200)
    description: Optional[str] = Field(default=None, max_length=1000)
    risk_hints: list[str] = Field(default_factory=list, max_length=20)
    parameters: list[str] = Field(default_factory=list, max_length=50)
    body_paths: list[str] = Field(default_factory=list, max_length=50)
    object_keys: list[str] = Field(default_factory=list, max_length=20)
    tenant_keys: list[str] = Field(default_factory=list, max_length=20)
    roles: list[str] = Field(default_factory=list, max_length=20)
    auth_required: Optional[bool] = None
    cwe: Optional[str] = Field(default=None, max_length=40)
    severity_guess: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    confidence: float = Field(default=0.35, ge=0, le=1)
    metadata_json: dict[str, Any] = Field(default_factory=dict)


class BenchmarkFollowupHypothesisItem(BaseModel):
    benchmark: Optional[str] = Field(default=None, max_length=120)
    expectation_id: str = Field(min_length=1, max_length=200)
    family: str = Field(min_length=1, max_length=80)
    route: Optional[str] = Field(default=None, max_length=500)
    proof_required: Optional[str] = Field(default=None, max_length=80)
    min_severity: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    status: str = Field(default="ready", max_length=80)
    reason: Optional[str] = Field(default=None, max_length=200)
    operator_hints: list[str] = Field(default_factory=list, max_length=25)
    blocked_by: list[str] = Field(default_factory=list, max_length=25)
    next_test_action: Optional[dict[str, Any]] = None
    blocked_action_template: Optional[dict[str, Any]] = None
    developer_note: Optional[str] = Field(default=None, max_length=1000)
    metadata_json: dict[str, Any] = Field(default_factory=dict)


def _operation_plan_allowed_commands() -> dict[str, dict[str, Any]]:
    try:
        catalog = describe_arsenal_commands()
    except Exception:
        return {}
    return {
        str(item.get("name")): item
        for item in catalog.get("commands", [])
        if isinstance(item, dict) and item.get("name")
    }


def _canonical_operation_plan(req: OperationPlanRequest) -> dict[str, Any]:
    payload = req.model_dump(mode="json")
    payload["objective"] = str(payload.get("objective") or "").strip()
    payload["context_hash"] = str(payload.get("context_hash") or "").strip().lower()
    payload["confirmations"] = [
        str(item).strip() for item in payload.get("confirmations", []) if str(item).strip()
    ]
    payload["missing_inputs"] = [
        str(item).strip() for item in payload.get("missing_inputs", []) if str(item).strip()
    ]
    payload["stop_conditions"] = [
        str(item).strip() for item in payload.get("stop_conditions", []) if str(item).strip()
    ]
    payload["success_criteria"] = [
        str(item).strip() for item in payload.get("success_criteria", []) if str(item).strip()
    ]
    payload["actions"] = [
        {
            **action,
            "command": str(action.get("command") or "").strip(),
            "parameters": redact_sensitive(action.get("parameters") or {}, redact_strings=True, scrub_text=True),
        }
        for action in payload.get("actions", [])
        if str(action.get("command") or "").strip()
    ]
    payload["planner"] = redact_sensitive(payload.get("planner") or {}, redact_strings=True, scrub_text=True)
    payload["target_scope"] = redact_sensitive(payload.get("target_scope") or {}, redact_strings=True, scrub_text=True)
    payload["budget"] = redact_sensitive(payload.get("budget") or {}, redact_strings=True, scrub_text=True)
    payload["constraints"] = redact_sensitive(payload.get("constraints") or {}, redact_strings=True, scrub_text=True)
    return payload


def _canonical_agent_context_pack(req: AgentContextPackRequest) -> dict[str, Any]:
    payload = req.model_dump(mode="json")
    payload["context_version"] = str(payload.get("context_version") or "").strip() or "2026-07-05.v1"
    payload["context_hash"] = str(payload.get("context_hash") or "").strip().lower()
    payload["redaction_profile"] = str(payload.get("redaction_profile") or "").strip() or "agent-plan-default"
    payload["allowed_commands"] = [
        str(item).strip() for item in payload.get("allowed_commands", []) if str(item).strip()
    ]
    payload["target_summary"] = _redact_agent_payload(payload.get("target_summary") or {})
    payload["current_surface"] = _redact_agent_payload(payload.get("current_surface") or {})
    payload["current_gaps"] = _redact_agent_payload(payload.get("current_gaps") or [])
    payload["hypotheses_summary"] = _redact_agent_payload(payload.get("hypotheses_summary") or [])
    payload["findings_summary"] = _redact_agent_payload(payload.get("findings_summary") or [])
    payload["disallowed_commands"] = _redact_agent_payload(payload.get("disallowed_commands") or [])
    payload["known_preconditions"] = _redact_agent_payload(payload.get("known_preconditions") or {})
    return payload






def _source_ingest_risk_hints(
    *,
    route: str | None,
    method: str,
    parameters: Sequence[str] = (),
    body_paths: Sequence[str] = (),
    content: str = "",
) -> tuple[list[str], list[str], list[str]]:
    route_l = str(route or "").lower()
    method_l = str(method or "GET").lower()
    names = [str(item or "").strip().lower() for item in list(parameters or []) + list(body_paths or [])]
    content_l = content[:20000].lower()
    risks: set[str] = set()
    object_keys: set[str] = set()
    tenant_keys: set[str] = set()
    if any(name in {"id", "user_id", "userid", "order_id", "account_id", "customer_id"} or name.endswith(".id") for name in names) or re.search(r"/[:{]?(?:id|user_id|order_id|account_id)[}:]?", route_l):
        risks.add("idor")
        object_keys.add("id")
    if any("tenant" in name or "org" in name or "workspace" in name for name in names) or any(token in route_l for token in ("tenant", "org", "workspace")):
        risks.add("tenant_boundary")
        tenant_keys.add("tenant")
    if any(name in {"q", "query", "search", "filter", "sort"} or "search" in name for name in names) or any(token in route_l for token in ("search", "query")):
        risks.update({"sqli", "xss"})
    if any(token in content_l for token in ("innerhtml", "dangerouslysetinnerhtml", "document.write", "v-html")):
        risks.add("xss")
    if any(token in content_l for token in ("select *", "where ", "findone(", "sequelize.query", "rawquery", "$where")):
        risks.add("sqli")
    if method_l in {"post", "put", "patch"} and any(
        key in name for name in names for key in ("admin", "role", "permission", "is_admin", "isadmin", "authorit")
    ):
        risks.add("mass_assignment")
    if "upload" in route_l or any("file" in name for name in names):
        risks.add("dangerous_upload")
    if any(token in content_l for token in ("requests.get(", "http.get(", "fetch(", "axios.get(", "urlopen(")) and any(name in {"url", "uri", "callback", "webhook"} or "url" in name for name in names):
        risks.add("ssrf")
    return sorted(risks), sorted(object_keys), sorted(tenant_keys)


def _schema_property_paths(schema: Any, *, prefix: str = "$", max_paths: int = 30) -> list[str]:
    if not isinstance(schema, dict) or max_paths <= 0:
        return []
    props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    paths: list[str] = []
    for name, nested in props.items():
        if len(paths) >= max_paths:
            break
        current = f"{prefix}.{name}"
        paths.append(current)
        paths.extend(_schema_property_paths(nested, prefix=current, max_paths=max_paths - len(paths)))
    return paths[:max_paths]




def _target_id_from_plan_action(plan: dict[str, Any], parameters: dict[str, Any]) -> str | None:
    target_scope = plan.get("target_scope") if isinstance(plan.get("target_scope"), dict) else {}
    for value in (
        parameters.get("target_id"),
        target_scope.get("target_id"),
        target_scope.get("id"),
    ):
        text = str(value or "").strip()
        if text:
            return text
    return None


def _endpoint_hint_from_parameters(parameters: dict[str, Any]) -> tuple[str | None, str | None]:
    hint = parameters.get("endpoint_hint") if isinstance(parameters.get("endpoint_hint"), dict) else {}
    method = (
        hint.get("method")
        or parameters.get("method")
        or parameters.get("http_method")
    )
    route = (
        hint.get("route")
        or hint.get("path")
        or parameters.get("route")
        or parameters.get("path")
        or parameters.get("endpoint")
    )
    method_text = str(method or "").strip().upper() or None
    route_text = _normalize_hypothesis_dedupe_value(route)
    if route_text and route_text.startswith(("http://", "https://")):
        try:
            parsed = urlparse(route_text)
            route_text = parsed.path or "/"
        except Exception:
            pass
    if route_text and not route_text.startswith("/"):
        route_text = "/" + route_text
    return method_text, route_text


def _planner_action_family_and_proof(command: str, parameters: dict[str, Any]) -> tuple[str | None, str | None, str, str, list[str]]:
    family_raw = (
        parameters.get("check_family")
        or parameters.get("family")
        or parameters.get("vulnerability_family")
        or parameters.get("probe_family")
    )
    family = str(family_raw or "").strip().lower().replace("-", "_").replace(" ", "_")
    requires: list[str] = []
    cwe: str | None = None
    proof_surface = "runtime_proof_required"
    rationale = "Planner suggested follow-up work that still requires deterministic runtime proof."

    if command in {"asm.improve", "asm.test"}:
        if family in {"bola", "idor"}:
            requires = ["primary_auth", "second_user_auth"]
            return "bola", "CWE-639", "runtime_authz_replay", "Planner suggested BOLA/IDOR coverage that requires two-principal runtime replay.", requires
        if family in {"auth", "authorization", "bfla", "bopla", "access_control"}:
            requires = ["primary_auth"]
            return "auth", "CWE-285", "runtime_authz_replay", "Planner suggested authorization coverage that requires authenticated runtime replay.", requires
        if family in {"sqli", "sql_injection", "nosql", "nosql_injection"}:
            return "sqli", "CWE-89", "runtime_probe", "Planner suggested injection coverage that requires runtime SQLi/NoSQL proof.", []
        if family in {"xss", "stored_xss", "reflected_xss", "dom_xss"}:
            return "xss", "CWE-79", "browser_runtime_probe", "Planner suggested XSS coverage that requires browser/runtime proof.", []
        if family:
            return family, cwe, proof_surface, rationale, requires
        return None, None, proof_surface, "ASM action did not include a supported check_family.", []

    if command == "scan.focused_family":
        if not family:
            return None, None, proof_surface, "Focused-family action did not include a family.", []
        cwe_map = {
            "ssrf": "CWE-918",
            "lfi": "CWE-22",
            "path_traversal": "CWE-22",
            "dangerous_upload": "CWE-434",
            "upload": "CWE-434",
            "sqli": "CWE-89",
            "xss": "CWE-79",
        }
        proof_map = {
            "ssrf": "runtime_callback_or_response",
            "lfi": "runtime_file_evidence",
            "path_traversal": "runtime_file_evidence",
            "dangerous_upload": "runtime_upload_handling",
            "upload": "runtime_upload_handling",
            "sqli": "runtime_probe",
            "xss": "browser_runtime_probe",
        }
        requires = ["approval_receipt"] if family in {"ssrf", "lfi", "path_traversal", "dangerous_upload", "upload"} else []
        return family, cwe_map.get(family), proof_map.get(family, "runtime_probe"), f"Planner suggested focused {family} proof work.", requires

    if command in {"ai_gate.scan", "ai_gate.replay_probe"}:
        pack = str(parameters.get("probe_pack") or parameters.get("probe_id") or "ai_gate").strip()
        return "ai_gate", "CWE-284", "ai_gate_probe_transcript", f"Planner suggested AI Gate coverage ({pack}) that needs probe transcript evidence.", ["ai_target_registration"]

    if command in {"model_intake.trust_preview", "model_intake.scan"}:
        return "model_intake_trust", None, "model_intake_trust_evidence", "Planner suggested Model Intake trust work that requires checksum/signature/policy evidence.", ["artifact_reference"]

    if command == "hypothesis.plan_campaign":
        if not family:
            family = "planned_followup"
        return family, None, proof_surface, "Planner suggested turning a hypothesis into a campaign plan; proof still requires the planned action to execute later.", ["hypothesis_id"]

    return None, None, proof_surface, f"Command {command} is not converted into a hypothesis.", []










def _finding_refuter_trigger(finding: dict[str, Any]) -> dict[str, Any] | None:
    payload = row_to_dict(finding)
    payload.update(_finding_routes.finding_proof_fields(payload))
    status = str(payload.get("status") or "").lower()
    severity = str(payload.get("severity") or "").lower()
    source = str(payload.get("source") or "").lower()
    tool = str(payload.get("tool") or "").lower()
    proof_state = str(payload.get("proof_state") or "").lower()
    ai_source = str(payload.get("ai_classification_source") or "").lower()
    evidence = _decode_json_value(payload.get("evidence")) or {}
    if not isinstance(evidence, dict):
        evidence = {}

    reasons: list[str] = []
    trigger_type = "finding"
    if status == "active" and severity in {"critical", "high"} and proof_state != "verified":
        reasons.append("critical_high_weak_or_suspected_proof")
    if source == "ai_gate" or payload.get("ai_target_id"):
        trigger_type = "ai_gate_semantic_or_control_claim"
        semantic_only = (
            ai_source in {"provider", "semantic", "ai_judge", "llm_judge"}
            and proof_state != "verified"
        )
        deterministic_markers = bool(
            evidence.get("deterministic_evidence")
            or evidence.get("deterministic_proof")
            or evidence.get("matched_markers")
            or evidence.get("expected_finding")
        )
        if semantic_only or not deterministic_markers:
            reasons.append("ai_gate_semantic_or_weak_deterministic_claim")
    if source == "model_intake" or tool == "model_intake":
        trigger_type = "model_intake_trust_claim"
        signature_verified = bool(
            evidence.get("signature_verified")
            or evidence.get("signature_trusted_root")
            or evidence.get("trusted_key_verified")
        )
        checksum_verified = bool(evidence.get("checksum_verified") or evidence.get("sha256_verified"))
        if not (signature_verified or checksum_verified):
            reasons.append("model_intake_metadata_without_trust_anchor")
    parser_status = str(
        payload.get("parser_status")
        or evidence.get("parser_status")
        or evidence.get("tool_parser_status")
        or ""
    ).lower()
    parser_promoted = bool(
        evidence.get("parser_promoted")
        or evidence.get("promoted_by_parser")
        or payload.get("promoted_by_parser")
    )
    if parser_promoted or parser_status in {"partial", "failed", "parser_error"}:
        if trigger_type == "finding":
            trigger_type = "parser_output_claim"
        reasons.append("parser_promoted_or_degraded_output")
    deployment_gating = bool(
        payload.get("blocks_deployment")
        or evidence.get("blocks_deployment")
        or evidence.get("deployment_gate_blocker")
        or evidence.get("deployment_decision_blocker")
    )
    if deployment_gating and proof_state != "verified":
        if trigger_type == "finding":
            trigger_type = "deployment_gate_claim"
        reasons.append("deployment_gating_claim_without_verified_proof")
    if not reasons:
        return None

    finding_id = str(payload.get("id") or payload.get("fingerprint") or "")
    automation_plan = _refuter_automation_plan_for_finding(
        payload,
        evidence,
        trigger_type=trigger_type,
        reasons=reasons,
    )
    return {
        "subject_type": "finding",
        "subject_id": finding_id,
        "finding_id": finding_id if payload.get("id") else None,
        "target_id": str(payload.get("target_id")) if payload.get("target_id") else None,
        "title": payload.get("title"),
        "severity": severity or None,
        "source": source or None,
        "tool": tool or None,
        "proof_state": proof_state or None,
        "trigger_type": trigger_type,
        "trigger_reasons": reasons,
        "recommended_review": {
            "subject_type": "finding",
            "subject_id": finding_id,
            "finding_id": finding_id if payload.get("id") else None,
            "trigger_reason": "; ".join(reasons),
            "refuter_signal": "question",
            "verdict_basis": "signal_only",
        },
        "automation_plan": automation_plan,
        "execution_enabled": False,
        "findings_updated": 0,
    }


def _finding_delta_refuter_signal(target_stat: dict[str, Any]) -> dict[str, Any] | None:
    """Flag a target whose latest scan produced an unusually large finding delta.

    This is an integrity *signal*, never a verdict: it is surfaced for review only and
    cannot mutate findings, proof state, hypotheses, or gates. It exists to catch the
    exact regression class this refuter layer is meant to catch — a sudden jump in a
    target's finding count that may be a detector regression or contamination rather than
    a real exposure change.
    """
    counts = [int(c) for c in (target_stat.get("recent_finding_counts") or []) if c is not None]
    if len(counts) < REFUTER_FINDING_DELTA_MIN_BASELINE + 1:
        return None
    latest = counts[0]
    baseline = counts[1:]
    baseline_median = _median(baseline)
    absolute_delta = latest - baseline_median
    if absolute_delta < REFUTER_FINDING_DELTA_MIN_ABSOLUTE:
        return None
    # The absolute floor already gates the zero/near-zero baseline case; only apply the
    # multiplier test when there is a non-trivial baseline to multiply against.
    if baseline_median > 0 and latest < baseline_median * REFUTER_FINDING_DELTA_MULTIPLIER:
        return None
    target_id = str(target_stat.get("target_id") or "").strip() or None
    return {
        "subject_type": "target",
        "subject_id": target_id,
        "target_id": target_id,
        "target_url": target_stat.get("target_url"),
        "latest_scan_id": str(target_stat.get("latest_scan_id") or "").strip() or None,
        "latest_finding_count": latest,
        "baseline_median": baseline_median,
        "baseline_finding_counts": baseline,
        "absolute_delta": absolute_delta,
        "trigger_type": "finding_delta_spike",
        "trigger_reasons": ["unusually_large_finding_delta"],
        "review_hint": (
            f"Latest scan reported {latest} findings vs a recent baseline median of "
            f"{baseline_median:g}. Confirm this is a real exposure change, not a detector "
            "regression, contamination, or benchmark-fitting artifact, before trusting new claims."
        ),
        "execution_enabled": False,
        "findings_updated": 0,
    }


def _benchmark_scorecard_rows(artifacts: Sequence[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for artifact in artifacts or []:
        data = artifact if isinstance(artifact, dict) else {}
        if data.get("artifact_type") != "benchmark_scorecard_run":
            continue
        artifact_id = str(data.get("artifact_path") or data.get("artifact_id") or data.get("path") or "").strip() or None
        artifact_status = str(data.get("artifact_status") or "").strip()
        targets = data.get("targets") if isinstance(data.get("targets"), list) else []
        for target in targets:
            if not isinstance(target, dict):
                continue
            scorecard = target.get("scorecards", {}).get("post_retest") if isinstance(target.get("scorecards"), dict) else None
            if not isinstance(scorecard, dict):
                scorecard = target
            benchmark = str(scorecard.get("target") or target.get("target") or data.get("target") or "").strip()
            if not benchmark:
                continue
            try:
                recall = float(scorecard.get("expected_recall"))
            except (TypeError, ValueError):
                continue
            rows.append({
                "benchmark": benchmark,
                "artifact_id": artifact_id,
                "artifact_status": artifact_status,
                "scan_id": str(scorecard.get("scan_id") or target.get("scan_id") or "").strip() or None,
                "phase": scorecard.get("phase") or target.get("phase") or "post_retest",
                "expected_recall": recall,
                "verified_high_critical": int(scorecard.get("verified_high_critical") or target.get("verified_high_critical") or 0),
                "passed": bool(target.get("passed") or data.get("artifact_status") == "passed_benchmark_scorecard"),
            })
    return rows


def _benchmark_win_delta_refuter_signal(benchmark_stat: dict[str, Any]) -> dict[str, Any] | None:
    rows = [row for row in (benchmark_stat.get("rows") or []) if isinstance(row, dict)]
    if len(rows) < REFUTER_BENCHMARK_DELTA_MIN_BASELINE + 1:
        return None
    latest = rows[0]
    baseline = rows[1:]
    baseline_recalls = [float(row.get("expected_recall") or 0.0) for row in baseline]
    baseline_verified = [int(row.get("verified_high_critical") or 0) for row in baseline]
    latest_recall = float(latest.get("expected_recall") or 0.0)
    latest_verified = int(latest.get("verified_high_critical") or 0)
    baseline_recall_median = _median(baseline_recalls)
    baseline_verified_median = _median(baseline_verified)
    recall_delta = latest_recall - baseline_recall_median
    verified_delta = latest_verified - baseline_verified_median
    reasons: list[str] = []
    if recall_delta >= REFUTER_BENCHMARK_RECALL_DELTA:
        reasons.append("benchmark_recall_win_delta")
    if verified_delta >= REFUTER_BENCHMARK_VERIFIED_DELTA:
        reasons.append("benchmark_verified_high_critical_win_delta")
    if not reasons:
        return None
    benchmark = str(benchmark_stat.get("benchmark") or latest.get("benchmark") or "").strip()
    return {
        "subject_type": "benchmark",
        "subject_id": benchmark,
        "benchmark": benchmark,
        "latest_artifact": latest.get("artifact_id"),
        "latest_scan_id": latest.get("scan_id"),
        "latest_expected_recall": latest_recall,
        "latest_verified_high_critical": latest_verified,
        "baseline_expected_recall_median": baseline_recall_median,
        "baseline_verified_high_critical_median": baseline_verified_median,
        "expected_recall_delta": round(recall_delta, 4),
        "verified_high_critical_delta": verified_delta,
        "baseline_artifacts": [row.get("artifact_id") for row in baseline if row.get("artifact_id")],
        "trigger_type": "benchmark_scorecard_win_delta",
        "trigger_reasons": reasons,
        "review_hint": (
            f"{benchmark} benchmark scorecard improved from recall median "
            f"{baseline_recall_median:.2f} to {latest_recall:.2f}. Verify this is a "
            "universal detector improvement, not stale fleet effects, contamination, or benchmark fitting."
        ),
        "execution_enabled": False,
        "findings_updated": 0,
    }


def _apply_refuter_negative_gate(canonical: dict[str, Any]) -> dict[str, Any]:
    """Symmetric negative gate: a terminal REFUTE must be deterministically corroborated.

    The mirror of "no LLM output can create a finding": no refutation can dismiss one unless a
    deterministic re-run observed the claimed mitigation. Uses the shared pure ``adjudicate`` module
    so the live path and any offline recompute cannot drift. An uncorroborated ``refuted`` verdict
    fail-safe downgrades to non-refuting and records the reason — a hallucinated refutation must
    never bury a real finding, because dedupe would then block re-discovery. Supported/weakened/
    inconclusive verdicts pass through unchanged.
    """
    checked = adjudicate.citecheck_vote({
        "refuter_verdict": canonical.get("refuter_verdict"),
        "verdict_basis": canonical.get("verdict_basis"),
        "tool_receipt_ids": canonical.get("tool_receipt_ids"),
        "evidence_object_ids": canonical.get("evidence_object_ids"),
        "cite": {"observed": _refuter_counterevidence_corroborates(canonical.get("counterevidence"))},
    })
    if checked["downgraded"]:
        canonical["metadata_json"] = {
            **(canonical.get("metadata_json") or {}),
            "negative_gate": {
                "downgraded": True,
                "reason": checked["reason"],
                "original_verdict": canonical.get("refuter_verdict"),
                "original_signal": canonical.get("refuter_signal"),
            },
        }
        canonical["refuter_verdict"] = "inconclusive"
        canonical["refuter_signal"] = "question"
    return canonical


def _authz_replay_path_is_template(path: Any) -> bool:
    raw = urllib.parse.unquote(str(path or "").strip())
    if not raw:
        return False
    return bool(
        re.search(r"\{[^{}\/]+\}", raw)
        or re.search(r"(?:^|/):[A-Za-z_][A-Za-z0-9_]*(?:/|$)", raw)
        or re.search(r"(?:^|/)\*(?:/|$)", raw)
    )


def _hypothesis_structured_values(value: Any, keys: set[str], *, depth: int = 5) -> set[str]:
    values: set[str] = set()
    if depth < 0:
        return values
    if isinstance(value, dict):
        for key, nested in list(value.items())[:100]:
            if str(key).strip().lower() in keys:
                if isinstance(nested, (str, int, float)):
                    values.add(str(nested).strip())
                elif isinstance(nested, list):
                    values.update(str(item).strip() for item in nested[:50] if isinstance(item, (str, int, float)))
            values.update(_hypothesis_structured_values(nested, keys, depth=depth - 1))
    elif isinstance(value, list):
        for nested in value[:100]:
            values.update(_hypothesis_structured_values(nested, keys, depth=depth - 1))
    return {item for item in values if item}


def _hypothesis_route_matches_finding(route: Any, finding: dict[str, Any]) -> bool:
    expected = str(route or "").strip()
    if not expected:
        return True
    expected = re.sub(r"^[A-Z]{2,12}\s+", "", expected)
    parsed_expected = urllib.parse.urlparse(expected)
    expected_path = parsed_expected.path if parsed_expected.scheme or parsed_expected.netloc else expected.split("?", 1)[0]
    actual_url = str(finding.get("url") or "").strip()
    parsed_actual = urllib.parse.urlparse(actual_url)
    actual_path = parsed_actual.path if parsed_actual.scheme or parsed_actual.netloc else actual_url.split("?", 1)[0]
    if not expected_path or not actual_path:
        return False
    expected_segments = [item for item in expected_path.strip("/").split("/") if item]
    actual_segments = [item for item in actual_path.strip("/").split("/") if item]
    if len(expected_segments) != len(actual_segments):
        return False
    placeholder = re.compile(r"^(?:\{[^{}]+\}|:[A-Za-z_][A-Za-z0-9_]*|<[^<>]+>|\*)$")
    return all(
        placeholder.fullmatch(expected_segment) is not None
        or urllib.parse.unquote(expected_segment).lower() == urllib.parse.unquote(actual_segment).lower()
        for expected_segment, actual_segment in zip(expected_segments, actual_segments)
    )


async def _arsenal_dispatch_campaign_list(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_campaigns(limit=_int_or_none(p.get("limit")) or 20, target_id=p.get("target_id"), status=p.get("status"))


async def _arsenal_dispatch_command_result_list(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_command_results(limit=_int_or_none(p.get("limit")) or 20)


async def _arsenal_dispatch_mission_timeline(p: dict[str, Any]) -> dict[str, Any]:
    return await _operations.mission_timeline(limit=_int_or_none(p.get("limit")) or 50, target_id=p.get("target_id"))


async def _arsenal_dispatch_tool_status(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_tools(probe_versions=bool(p.get("probe_versions")))


async def _arsenal_dispatch_local_agent_list(p: dict[str, Any]) -> dict[str, Any]:
    return await local_agents(probe_versions=bool(p.get("probe_versions")))


async def _arsenal_dispatch_target_list(p: dict[str, Any]) -> dict[str, Any]:
    return await _targets.list_targets(
        limit=_int_or_none(p.get("limit")) or 100,
        offset=_int_or_none(p.get("offset")) or 0,
        include_inactive=bool(p.get("include_inactive")),
    )


async def _arsenal_dispatch_target_get(p: dict[str, Any]) -> dict[str, Any]:
    target_id = str(p.get("target_id") or "").strip()
    if not target_id:
        raise HTTPException(status_code=400, detail="target.get requires a target_id parameter")
    return await _targets.get_target(target_id)


async def _arsenal_dispatch_target_principals(p: dict[str, Any]) -> dict[str, Any]:
    target_id = str(p.get("target_id") or "").strip()
    if not target_id:
        raise HTTPException(status_code=400, detail="target.principals requires a target_id parameter")
    return await _targets.list_target_principals(target_id, include_inactive=bool(p.get("include_inactive")))


async def _arsenal_dispatch_target_principal_matrix(p: dict[str, Any]) -> dict[str, Any]:
    target_id = str(p.get("target_id") or "").strip()
    if not target_id:
        raise HTTPException(status_code=400, detail="target.principal_matrix requires a target_id parameter")
    return await _targets.list_target_principal_matrix(target_id, limit=_int_or_none(p.get("limit")) or 200)


async def _arsenal_dispatch_target_invariants(p: dict[str, Any]) -> dict[str, Any]:
    target_id = str(p.get("target_id") or "").strip()
    if not target_id:
        raise HTTPException(status_code=400, detail="target.invariants requires a target_id parameter")
    return await _targets.list_target_invariant_contracts(
        target_id,
        include_drafts=bool(p.get("include_drafts", True)),
    )


async def _arsenal_dispatch_target_invariant_compile(p: dict[str, Any]) -> dict[str, Any]:
    target_id = str(p.get("target_id") or "").strip()
    if not target_id:
        raise HTTPException(status_code=400, detail="target.invariant.compile requires a target_id parameter")
    fields = {k: v for k, v in p.items() if k in _targets.TargetInvariantCompileRequest.model_fields and v is not None}
    fields["persist_drafts"] = False
    fields.pop("approval_receipt_id", None)
    return await _targets.compile_target_invariant_rule(target_id, _targets.TargetInvariantCompileRequest(**fields))


async def _arsenal_dispatch_target_invariant_verification_plan(p: dict[str, Any]) -> dict[str, Any]:
    target_id = str(p.get("target_id") or "").strip()
    contract_id = str(p.get("contract_id") or "").strip()
    if not target_id or not contract_id:
        raise HTTPException(
            status_code=400,
            detail="target.invariant.verification_plan requires target_id and contract_id parameters",
        )
    return await _targets.get_target_invariant_verification_plan(target_id, contract_id)


async def _arsenal_dispatch_target_invariant_hypotheses(p: dict[str, Any]) -> dict[str, Any]:
    target_id = str(p.get("target_id") or "").strip()
    if not target_id:
        raise HTTPException(
            status_code=400,
            detail="target.invariant.generate_hypotheses requires a target_id parameter",
        )
    return await _targets.generate_target_invariant_hypotheses(
        target_id,
        _targets.TargetInvariantHypothesisRequest(created_by=p.get("created_by") or "arsenal.execute"),
    )


async def _arsenal_dispatch_target_principal_matrix_record(
    p: dict[str, Any], approval_receipt_id: str | None,
) -> dict[str, Any]:
    target_id = str(p.get("target_id") or "").strip()
    if not target_id:
        raise HTTPException(status_code=400, detail="target.principal_matrix.record requires a target_id parameter")
    fields = {k: v for k, v in p.items() if k in _arsenal_model_fields(_targets.TargetEndpointExpectationRequest) and v is not None}
    fields["approval_receipt_id"] = approval_receipt_id or p.get("approval_receipt_id")
    return await _targets.upsert_target_principal_matrix(target_id, _targets.TargetEndpointExpectationRequest(**fields))


async def _arsenal_dispatch_target_invariant_record(
    p: dict[str, Any], approval_receipt_id: str | None,
) -> dict[str, Any]:
    target_id = str(p.get("target_id") or "").strip()
    if not target_id:
        raise HTTPException(status_code=400, detail="target.invariant_contract.record requires a target_id parameter")
    fields = {k: v for k, v in p.items() if k in _arsenal_model_fields(_targets.TargetInvariantContractCreate) and v is not None}
    fields["approval_receipt_id"] = approval_receipt_id or p.get("approval_receipt_id")
    return await _targets.create_target_invariant_contract(target_id, _targets.TargetInvariantContractCreate(**fields))


async def _arsenal_dispatch_target_invariant_approve(
    p: dict[str, Any], approval_receipt_id: str | None,
) -> dict[str, Any]:
    target_id = str(p.get("target_id") or "").strip()
    contract_id = str(p.get("contract_id") or "").strip()
    if not target_id or not contract_id:
        raise HTTPException(
            status_code=400,
            detail="target.invariant_contract.approve requires target_id and contract_id parameters",
        )
    fields = {k: v for k, v in p.items() if k in _arsenal_model_fields(_targets.TargetInvariantContractApproval) and v is not None}
    fields["approval_receipt_id"] = approval_receipt_id or p.get("approval_receipt_id")
    return await _targets.approve_target_invariant_contract(
        target_id,
        contract_id,
        _targets.TargetInvariantContractApproval(**fields),
    )


async def _arsenal_dispatch_target_invariant_retire(
    p: dict[str, Any], approval_receipt_id: str | None,
) -> dict[str, Any]:
    target_id = str(p.get("target_id") or "").strip()
    contract_id = str(p.get("contract_id") or "").strip()
    if not target_id or not contract_id:
        raise HTTPException(
            status_code=400,
            detail="target.invariant_contract.retire requires target_id and contract_id parameters",
        )
    fields = {k: v for k, v in p.items() if k in _arsenal_model_fields(_targets.TargetInvariantContractRetire) and v is not None}
    fields["approval_receipt_id"] = approval_receipt_id or p.get("approval_receipt_id")
    return await _targets.retire_target_invariant_contract(
        target_id,
        contract_id,
        _targets.TargetInvariantContractRetire(**fields),
    )


async def _arsenal_dispatch_exposure_graph_get(p: dict[str, Any]) -> dict[str, Any]:
    return await _exposure.exposure_graph(
        focus=p.get("focus"),
        include_resolved=bool(p.get("include_resolved")),
        limit=_int_or_none(p.get("limit")) or 500,
    )


async def _arsenal_dispatch_asm_gaps(p: dict[str, Any]) -> dict[str, Any]:
    target_id = str(p.get("target_id") or "").strip()
    if not target_id:
        raise HTTPException(status_code=400, detail="asm.gaps requires a target_id parameter")
    return await _ai_targets.asm_gaps(target_id)


async def _arsenal_dispatch_asm_activity(p: dict[str, Any]) -> dict[str, Any]:
    target_id = str(p.get("target_id") or "").strip()
    if not target_id:
        raise HTTPException(status_code=400, detail="asm.activity requires a target_id parameter")
    return await _targets.asm_activity(target_id, limit=_int_or_none(p.get("limit")) or 20)


async def _arsenal_dispatch_scan_result(p: dict[str, Any]) -> dict[str, Any]:
    scan_id = str(p.get("scan_id") or "").strip()
    if not scan_id:
        raise HTTPException(status_code=400, detail="scan.result requires a scan_id parameter")
    return await get_scan_result(scan_id)


async def _arsenal_dispatch_finding_list(p: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "severity", "status", "source_type", "target_id", "ai_target_id",
        "scan_id", "root_domain", "verification_verdict", "verification_mode",
        "verified_only", "search", "seen_within_days", "first_seen_within_days",
        "resolved_within_days", "sort_by", "sort_order", "limit", "offset",
    }
    query = {k: v for k, v in p.items() if k in allowed and v is not None}
    return await _finding_routes.list_findings(
        _ArsenalQueryRequest(query),
        severity=p.get("severity"),
        status=p.get("status"),
        source_type=p.get("source_type"),
        target_id=p.get("target_id"),
        ai_target_id=p.get("ai_target_id"),
        scan_id=p.get("scan_id"),
        root_domain=p.get("root_domain"),
        verification_verdict=p.get("verification_verdict"),
        verification_mode=p.get("verification_mode"),
        verified_only=bool(p.get("verified_only")),
        search=p.get("search"),
        seen_within_days=_int_or_none(p.get("seen_within_days")),
        first_seen_within_days=_int_or_none(p.get("first_seen_within_days")),
        resolved_within_days=_int_or_none(p.get("resolved_within_days")),
        sort_by=p.get("sort_by"),
        sort_order=p.get("sort_order") or "desc",
        limit=_int_or_none(p.get("limit")) or 100,
        offset=_int_or_none(p.get("offset")) or 0,
    )


async def _arsenal_dispatch_finding_get(p: dict[str, Any]) -> dict[str, Any]:
    finding_id = str(p.get("finding_id") or "").strip()
    if not finding_id:
        raise HTTPException(status_code=400, detail="finding.get requires a finding_id parameter")
    return await _finding_routes.get_finding(finding_id)


async def _arsenal_dispatch_operation_plan_list(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_operation_plans(limit=_int_or_none(p.get("limit")) or 20)


async def _arsenal_dispatch_operation_plan_preview(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_create_operation_plan(OperationPlanRequest(**p))


async def _arsenal_dispatch_agent_context_pack_list(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_agent_context_packs(limit=_int_or_none(p.get("limit")) or 20)


async def _arsenal_dispatch_agent_context_pack_record(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_create_agent_context_pack(AgentContextPackRequest(**p))


async def _arsenal_dispatch_agent_context_pack_generate_from_target(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_create_agent_context_pack_from_target(AgentContextPackFromTargetRequest(**p))


async def _arsenal_dispatch_agent_decision_trace_list(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_agent_decision_traces(limit=_int_or_none(p.get("limit")) or 20)


async def _arsenal_dispatch_agent_decision_trace_record(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_create_agent_decision_trace(AgentDecisionTraceRequest(**p))


async def _arsenal_dispatch_hypothesis_list(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_hypotheses(limit=_int_or_none(p.get("limit")) or 20, target_id=p.get("target_id"), status=p.get("status"))


async def _arsenal_dispatch_hypothesis_situation_report(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_hypothesis_situation_report(
        limit=_int_or_none(p.get("limit")) or 5,
        target_id=p.get("target_id"),
        requester=p.get("requester"),
    )


async def _arsenal_dispatch_hypothesis_record(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_record_hypothesis(HypothesisRequest(**p))


async def _arsenal_dispatch_hypothesis_generate_from_source(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_generate_hypotheses_from_source(SourceIngestRequest(**p))


async def _arsenal_dispatch_hypothesis_generate_from_plan(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_generate_hypotheses_from_plan(PlannerHypothesisRequest(**p))


async def _arsenal_dispatch_hypothesis_generate_from_benchmark(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_generate_hypotheses_from_benchmark(BenchmarkHypothesisRequest(**p))


async def _arsenal_dispatch_hypothesis_claim(p: dict[str, Any]) -> dict[str, Any]:
    hypothesis_id = str(p.get("hypothesis_id") or "").strip()
    if not hypothesis_id:
        raise HTTPException(status_code=400, detail="hypothesis.claim requires a hypothesis_id parameter")
    fields = {k: v for k, v in p.items() if k in _arsenal_model_fields(HypothesisClaimRequest) and v is not None}
    return await arsenal_claim_hypothesis(hypothesis_id, HypothesisClaimRequest(**fields))


async def _arsenal_dispatch_hypothesis_signal(p: dict[str, Any]) -> dict[str, Any]:
    hypothesis_id = str(p.get("hypothesis_id") or "").strip()
    if not hypothesis_id:
        raise HTTPException(status_code=400, detail="hypothesis.signal requires a hypothesis_id parameter")
    fields = {k: v for k, v in p.items() if k in _arsenal_model_fields(HypothesisSignalRequest) and v is not None}
    return await arsenal_append_hypothesis_signal(hypothesis_id, HypothesisSignalRequest(**fields))


async def _arsenal_dispatch_hypothesis_plan_campaign(p: dict[str, Any]) -> dict[str, Any]:
    hypothesis_id = str(p.get("hypothesis_id") or "").strip()
    if not hypothesis_id:
        raise HTTPException(status_code=400, detail="hypothesis.plan_campaign requires a hypothesis_id parameter")
    fields = {k: v for k, v in p.items() if k in _arsenal_model_fields(HypothesisCampaignPlanRequest) and v is not None}
    return await arsenal_plan_hypothesis_campaign(hypothesis_id, HypothesisCampaignPlanRequest(**fields))


async def _arsenal_dispatch_hypothesis_reconcile_proof(
    p: dict[str, Any], approval_receipt_id: str | None,
) -> dict[str, Any]:
    hypothesis_id = str(p.get("hypothesis_id") or "").strip()
    if not hypothesis_id:
        raise HTTPException(status_code=400, detail="hypothesis.reconcile_proof requires a hypothesis_id parameter")
    fields = {k: v for k, v in p.items() if k in _arsenal_model_fields(HypothesisProofReconcileRequest) and v is not None}
    fields["approval_receipt_id"] = approval_receipt_id or p.get("approval_receipt_id")
    async with _pool().acquire() as conn:
        async with conn.transaction():
            return await _reconcile_hypothesis_proof(conn, hypothesis_id, HypothesisProofReconcileRequest(**fields))


async def _arsenal_dispatch_hypothesis_generate_from_graph(p: dict[str, Any]) -> dict[str, Any]:
    target_id = str(p.get("target_id") or "").strip()
    if not target_id:
        raise HTTPException(status_code=400, detail="hypothesis.generate_from_graph requires a target_id parameter")
    return await _targets.generate_application_graph_hypotheses(target_id, created_by=p.get("created_by") or "arsenal.execute")


async def _arsenal_dispatch_campaign_get(p: dict[str, Any]) -> dict[str, Any]:
    campaign_id = str(p.get("campaign_id") or "").strip()
    if not campaign_id:
        raise HTTPException(status_code=400, detail="campaign.get requires a campaign_id parameter")
    return await arsenal_campaign_detail(campaign_id, action_limit=_int_or_none(p.get("action_limit")) or 50)


async def _arsenal_dispatch_campaign_action_list(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_campaign_actions(limit=_int_or_none(p.get("limit")) or 20, target_id=p.get("target_id"))


async def _arsenal_dispatch_campaign_create(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_create_campaign(CampaignRequest(**p))


async def _arsenal_dispatch_campaign_link_action(p: dict[str, Any]) -> dict[str, Any]:
    campaign_id = str(p.get("campaign_id") or "").strip()
    if not campaign_id:
        raise HTTPException(status_code=400, detail="campaign.link_action requires a campaign_id parameter")
    fields = {k: v for k, v in p.items() if k in _arsenal_model_fields(CampaignActionLinkRequest) and v is not None}
    return await arsenal_link_campaign_action(campaign_id, CampaignActionLinkRequest(**fields))


async def _arsenal_dispatch_ai_target_list(p: dict[str, Any]) -> dict[str, Any]:
    return await _ai_targets.list_ai_targets(
        include_inactive=bool(p.get("include_inactive")),
        include_demo=bool(p.get("include_demo")),
        limit=_int_or_none(p.get("limit")) or 100,
        offset=_int_or_none(p.get("offset")) or 0,
    )


async def _arsenal_dispatch_ai_gate_target_history_export(p: dict[str, Any]) -> dict[str, Any]:
    target_id = str(p.get("target_id") or "").strip()
    if not target_id:
        raise HTTPException(status_code=400, detail="ai_gate.target_history_export requires a target_id parameter")
    return await _ai_targets.get_ai_target_campaign_history_export(target_id, limit=_int_or_none(p.get("limit")) or 12)


async def _arsenal_dispatch_model_intake_trust_preview(p: dict[str, Any]) -> dict[str, Any]:
    profile = str(p.get("policy_profile") or "production").strip() or "production"
    trust_mode = str(p.get("trust_mode") or "saved_anchor").strip() or "saved_anchor"
    return {
        "trust_preview": {
            "policy_profile": profile,
            "trust_mode": trust_mode,
            "ui_path": f"/model-intake?remediate=trust&policy_profile={urllib.parse.quote(profile)}&trust_mode={urllib.parse.quote(trust_mode)}",
        },
        "execution_enabled": False,
    }


async def _arsenal_dispatch_model_intake_evidence_export(p: dict[str, Any]) -> dict[str, Any]:
    scan_id = str(p.get("scan_id") or "").strip()
    if not scan_id:
        raise HTTPException(status_code=400, detail="model_intake.evidence_export requires a scan_id parameter")
    return await _model_intake.get_model_intake_evidence_export(scan_id)


async def _arsenal_dispatch_evidence_get(p: dict[str, Any]) -> dict[str, Any]:
    if p.get("evidence_id"):
        return await get_evidence_object(str(p.get("evidence_id")))
    finding_id = str(p.get("finding_id") or "").strip()
    if not finding_id:
        raise HTTPException(status_code=400, detail="evidence.get requires finding_id or evidence_id")
    return await _finding_routes.list_finding_evidence(finding_id)


async def _arsenal_dispatch_evidence_export_manifest(p: dict[str, Any]) -> dict[str, Any]:
    return await evidence_export_manifest(
        finding_id=p.get("finding_id"),
        scan_id=p.get("scan_id"),
        retention_class=p.get("retention_class"),
        limit=_int_or_none(p.get("limit")) or 200,
    )


async def _arsenal_dispatch_evidence_export_bundle(p: dict[str, Any]) -> dict[str, Any]:
    return await evidence_export_bundle(
        finding_id=p.get("finding_id"),
        scan_id=p.get("scan_id"),
        retention_class=p.get("retention_class"),
        limit=_int_or_none(p.get("limit")) or 200,
        record_event=bool(p.get("record_event")),
    )


async def _arsenal_dispatch_evidence_instance_list(p: dict[str, Any]) -> dict[str, Any]:
    return await list_evidence_instances(
        finding_id=p.get("finding_id"),
        tool_receipt_id=p.get("tool_receipt_id"),
        limit=_int_or_none(p.get("limit")) or 50,
    )


async def _arsenal_dispatch_evidence_instance_record(p: dict[str, Any]) -> dict[str, Any]:
    allowed = _arsenal_model_fields(EvidenceInstanceRequest)
    return await record_evidence_instance(EvidenceInstanceRequest(**{k: v for k, v in p.items() if k in allowed and v is not None}))


async def _arsenal_dispatch_tool_receipt_list(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_tool_receipts(
        limit=_int_or_none(p.get("limit")) or 20,
        tool_name=p.get("tool_name"),
        status=p.get("status"),
    )


async def _arsenal_dispatch_tool_receipt_record(p: dict[str, Any]) -> dict[str, Any]:
    allowed = _arsenal_model_fields(ToolReceiptRequest)
    return await arsenal_record_tool_receipt(ToolReceiptRequest(**{k: v for k, v in p.items() if k in allowed and v is not None}))


async def _arsenal_dispatch_deployment_decision(p: dict[str, Any]) -> dict[str, Any]:
    scan_id = str(p.get("scan_id") or "").strip()
    if not scan_id:
        raise HTTPException(status_code=400, detail="deployment.decision requires a scan_id parameter")
    return await get_scan_deployment_decision(scan_id)


async def _arsenal_dispatch_local_agent_plan_dry_run(p: dict[str, Any]) -> dict[str, Any]:
    return await local_agent_dry_run_plan(LocalAgentPlanRequest(**p))


async def _arsenal_dispatch_local_agent_parse_plan(p: dict[str, Any]) -> dict[str, Any]:
    return await local_agent_parse_candidate_plan(LocalAgentPlanParseRequest(**p))


async def _arsenal_dispatch_local_agent_test(p: dict[str, Any]) -> dict[str, Any]:
    return await local_agent_test(LocalAgentTestRequest(**p))


async def _arsenal_dispatch_scope_preview(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_scope_preview(ScopePreviewRequest(**p))


async def _arsenal_dispatch_refuter_review_list(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_refuter_reviews(
        limit=_int_or_none(p.get("limit")) or 20,
        subject_type=p.get("subject_type"),
        subject_id=p.get("subject_id"),
    )


async def _arsenal_dispatch_refuter_review_summary(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_refuter_review_summary(
        limit=_int_or_none(p.get("limit")) or 20,
        finding_window=_int_or_none(p.get("finding_window")) or 200,
    )


async def _arsenal_dispatch_refuter_review_record(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_record_refuter_review(RefuterReviewRequest(**p))


async def _arsenal_dispatch_refuter_review_queue_from_summary(p: dict[str, Any]) -> dict[str, Any]:
    return await arsenal_queue_refuter_reviews_from_summary(RefuterReviewQueueRequest(
        limit=_int_or_none(p.get("limit")) or 20,
        finding_window=_int_or_none(p.get("finding_window")) or 200,
        include_integrity_signals=bool(p.get("include_integrity_signals", False)),
        created_by=p.get("created_by") or "arsenal_execute",
    ))


async def _arsenal_dispatch_refuter_review_derive_verdict(p: dict[str, Any], approval_receipt_id: str | None) -> dict[str, Any]:
    refuter_review_id = str(p.get("refuter_review_id") or "").strip()
    if not refuter_review_id:
        raise HTTPException(status_code=400, detail="refuter_review.derive_verdict requires a refuter_review_id parameter")
    async with _pool().acquire() as conn:
        result = await _derive_refuter_review_verdict(
            conn,
            refuter_review_id=refuter_review_id,
            verification_id=p.get("verification_id"),
            created_by=p.get("created_by") or "arsenal_execute",
        )
        if approval_receipt_id:
            result["approval_receipt_id"] = approval_receipt_id
        return result


async def _arsenal_dispatch_refuter_review_execute_plan(p: dict[str, Any], approval_receipt_id: str | None) -> dict[str, Any]:
    refuter_review_id = str(p.get("refuter_review_id") or "").strip()
    if not refuter_review_id:
        raise HTTPException(status_code=400, detail="refuter_review.execute_plan requires a refuter_review_id parameter")
    async with _pool().acquire() as conn:
        return await _execute_refuter_review_plan(
            conn,
            refuter_review_id=refuter_review_id,
            approval_receipt_id=approval_receipt_id or p.get("approval_receipt_id"),
            step_id=p.get("step_id"),
            requested_by=p.get("requested_by") or p.get("created_by") or "arsenal_execute",
            confirm_production=bool(p.get("confirm_production")),
        )


async def _arsenal_dispatch_asm_improve(p: dict[str, Any], approval_receipt_id: str | None) -> dict[str, Any]:
    target_id = str(p.get("target_id") or "").strip()
    if not target_id:
        raise HTTPException(status_code=400, detail="asm.improve requires a target_id parameter")
    fields = {k: p[k] for k in ("batch_size", "stale_days", "exploit_depth", "check_family", "endpoint_filter") if p.get(k) is not None}
    body = _targets.AsmImproveRequest(approval_receipt_id=approval_receipt_id or p.get("approval_receipt_id"), **fields)
    return await _ai_targets.asm_improve(target_id, body)


async def _arsenal_dispatch_asm_test(p: dict[str, Any], approval_receipt_id: str | None) -> dict[str, Any]:
    target_id = str(p.get("target_id") or "").strip()
    if not target_id:
        raise HTTPException(status_code=400, detail="asm.test requires a target_id parameter")
    fields = {k: p[k] for k in ("batch_size", "stale_days", "exploit_depth", "check_family", "endpoint_filter") if p.get(k) is not None}
    body = _targets.AsmTestRequest(approval_receipt_id=approval_receipt_id or p.get("approval_receipt_id"), **fields)
    return await _targets.asm_test(target_id, body)


async def _arsenal_dispatch_asm_recon(p: dict[str, Any], approval_receipt_id: str | None) -> dict[str, Any]:
    target_id = str(p.get("target_id") or "").strip()
    if not target_id:
        raise HTTPException(status_code=400, detail="asm.recon requires a target_id parameter")
    fields = {k: p[k] for k in ("budget_profile",) if p.get(k) is not None}
    body = _targets.AsmReconRequest(approval_receipt_id=approval_receipt_id or p.get("approval_receipt_id"), **fields)
    return await _targets.asm_recon(target_id, body)


async def _arsenal_dispatch_finding_retest(p: dict[str, Any], approval_receipt_id: str | None) -> dict[str, Any]:
    finding_id = str(p.get("finding_id") or "").strip()
    if not finding_id:
        raise HTTPException(status_code=400, detail="finding.retest requires a finding_id parameter")
    fields = {
        k: p[k]
        for k in ("finding_type", "target", "original_url", "param", "payload", "method", "request_body", "requested_by")
        if p.get(k) is not None
    }
    fields["requested_by"] = (
        str(p.get("requested_by") or _ARSENAL_CREATED_BY_CONTEXT.get() or "api")[:200]
    )
    body = _finding_routes.FindingRetestRequest(approval_receipt_id=approval_receipt_id or p.get("approval_receipt_id"), **fields)
    return await _finding_routes.retest_finding(finding_id, body, mode=p.get("mode"))


async def _arsenal_dispatch_ai_gate_scan(p: dict[str, Any], approval_receipt_id: str | None) -> dict[str, Any]:
    target_id = str(p.get("target_id") or "").strip()
    if not target_id:
        raise HTTPException(status_code=400, detail="ai_gate.scan requires a target_id parameter")
    fields = {
        k: p[k]
        for k in ("probe_pack", "scan_profile", "environment", "confirm_production", "ai_judge_enabled", "semantic_judge_enabled")
        if p.get(k) is not None
    }
    body = _ai_targets.AITargetScanRequest(approval_receipt_id=approval_receipt_id or p.get("approval_receipt_id"), **fields)
    return await _ai_targets.scan_ai_target(target_id, body)


async def _arsenal_dispatch_scan_focused_family(p: dict[str, Any], approval_receipt_id: str | None) -> dict[str, Any]:
    target = str(p.get("target") or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="scan.focused_family requires a target parameter")
    check_family = str(p.get("check_family") or "").strip()
    if not check_family:
        raise HTTPException(status_code=400, detail="scan.focused_family requires a check_family parameter")
    option_payload = dict(p.get("options") or {}) if isinstance(p.get("options"), dict) else {}
    allowed = _arsenal_model_fields(ScanOptions)
    for key, value in p.items():
        if key in allowed and value is not None:
            option_payload[key] = value
    if option_payload.get("custom_endpoints"):
        # Execute a planner-selected operation through the deterministic DAST worker without
        # rediscovery or unrelated global checks diluting the hypothesis test.
        option_payload.update({
            "focused_endpoints_only": True,
            "zero_rediscovery": True,
            "skip_global_checks": True,
            "no_early_stop": True,
            "parallel": False,
            "require_current_workers": True,
        })
    for key in LEGACY_SCAN_WRITE_FIELDS:
        option_payload.pop(key, None)
    body = _targets.ScanInternalCompatibilityRequest(
        target=target,
        name=p.get("name"),
        budget_profile="thorough",
        policy={
            "preset": "standard_active" if check_family == "all" else "custom",
            "active_testing": True,
            "include_families": ([] if check_family == "all" else [check_family]),
        },
        advanced=ScanAdvancedLimits(
            include_families=[] if check_family == "all" else [check_family],
        ),
        approval_receipt_id=approval_receipt_id or p.get("approval_receipt_id"),
        options=ScanOptions(**option_payload),
    )
    return await _submit_scan(body)


async def _arsenal_dispatch_ai_gate_replay_probe(p: dict[str, Any], approval_receipt_id: str | None) -> dict[str, Any]:
    scan_id = str(p.get("scan_id") or "").strip()
    if not scan_id:
        raise HTTPException(status_code=400, detail="ai_gate.replay_probe requires a scan_id parameter")
    fields = {
        k: p[k]
        for k in ("mode", "probe_family", "probe_id", "transcript_index", "requested_by", "confirm_production")
        if p.get(k) is not None
    }
    body = _ai_targets.AIScanReplayRequest(approval_receipt_id=approval_receipt_id or p.get("approval_receipt_id"), **fields)
    return await _ai_targets.replay_ai_scan(scan_id, body)


async def _arsenal_dispatch_model_intake_scan(p: dict[str, Any], approval_receipt_id: str | None) -> dict[str, Any]:
    artifact_url = str(p.get("artifact_url") or "").strip()
    if not artifact_url:
        raise HTTPException(status_code=400, detail="model_intake.scan requires an artifact_url parameter")
    allowed = _arsenal_model_fields(_model_intake.ModelIntakeScanRequest)
    fields = {k: v for k, v in p.items() if k in allowed and v is not None}
    fields["artifact_url"] = artifact_url
    fields["approval_receipt_id"] = approval_receipt_id or p.get("approval_receipt_id")
    body = _model_intake.ModelIntakeScanRequest(**fields)
    return await _model_intake.scan_model_intake(body)


async def _arsenal_dispatch_evidence_retention_sweep(p: dict[str, Any], approval_receipt_id: str | None) -> dict[str, Any]:
    if p.get("dry_run", True) is False:
        fields = {
            "dry_run": False,
            "preview_id": p.get("preview_id"),
            "approval_receipt_id": approval_receipt_id or p.get("approval_receipt_id"),
        }
    else:
        allowed = set(_get("EVIDENCE_RETENTION_PREVIEW_FIELDS")) | {"dry_run"}
        fields = {k: v for k, v in p.items() if k in allowed and v is not None}
        fields["dry_run"] = True
    body = EvidenceRetentionSweepRequest(**fields)
    return await evidence_retention_sweep(body)


async def _arsenal_dispatch_finding_exception_lifecycle_sweep(
    p: dict[str, Any], approval_receipt_id: str | None
) -> dict[str, Any]:
    allowed = _arsenal_model_fields(_finding_exceptions.FindingExceptionLifecycleSweepRequest)
    fields = {k: v for k, v in p.items() if k in allowed and v is not None}
    fields["approval_receipt_id"] = approval_receipt_id or p.get("approval_receipt_id")
    body = _finding_exceptions.FindingExceptionLifecycleSweepRequest(**fields)
    return await _finding_exceptions.finding_exception_lifecycle_sweep(body)


async def _arsenal_dispatch_authz_replay_plan(p: dict[str, Any], approval_receipt_id: str | None) -> dict[str, Any]:
    campaign_action_id = str(p.get("campaign_action_id") or "").strip()
    session_id = str(p.get("session_id") or "").strip()
    if not campaign_action_id:
        raise HTTPException(status_code=400, detail="authz.replay_plan requires a campaign_action_id parameter")
    if not session_id:
        raise HTTPException(status_code=400, detail="authz.replay_plan requires a session_id parameter")
    async with _pool().acquire() as conn:
        return await _execute_authz_replay_plan(
            conn,
            campaign_action_id=campaign_action_id,
            session_id=session_id,
            approval_receipt_id=approval_receipt_id or p.get("approval_receipt_id"),
            created_by=p.get("created_by"),
        )


async def _arsenal_dispatch_authz_promote_replay_finding(p: dict[str, Any], approval_receipt_id: str | None) -> dict[str, Any]:
    campaign_action_id = str(p.get("campaign_action_id") or "").strip()
    if not campaign_action_id:
        raise HTTPException(status_code=400, detail="authz.promote_replay_finding requires a campaign_action_id parameter")
    async with _pool().acquire() as conn:
        return await _promote_authz_replay_finding(
            conn,
            campaign_action_id=campaign_action_id,
            approval_receipt_id=approval_receipt_id or p.get("approval_receipt_id"),
            created_by=p.get("created_by"),
        )


async def _arsenal_dispatch_http_diff(p: dict[str, Any], approval_receipt_id: str | None) -> dict[str, Any]:
    target_id = str(p.get("target_id") or "").strip()
    hypothesis_id = str(p.get("_research_hypothesis_id") or "").strip() or None
    target_uuid = _uuid_or_400(target_id, "target id")
    async with _pool().acquire() as conn:
        target = await conn.fetchrow(
            "SELECT id, url, is_active, discovery_source FROM targets WHERE id=$1",
            target_uuid,
        )
    if not target or not target["is_active"]:
        raise HTTPException(status_code=404, detail="Active target not found")
    if str(target["discovery_source"] or "") == "model-intake":
        raise HTTPException(status_code=400, detail="Model Intake artifacts are not HTTP experiment targets")
    experiment_payload = {
        key: value for key, value in p.items()
        if key in {"objective", "expected_signal", "falsifier", "timeout_seconds", "steps"}
    }
    unsafe_methods = sorted({
        str(step.get("method") or "GET").strip().upper()
        for step in experiment_payload.get("steps") or []
        if isinstance(step, dict)
        and str(step.get("method") or "GET").strip().upper() not in {"GET", "HEAD", "OPTIONS"}
    })
    if unsafe_methods:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_http_experiment",
                "violation": "http_diff_state_changing_method_forbidden:" + ",".join(unsafe_methods),
            },
        )
    started_at = datetime.now(timezone.utc)
    try:
        executed = await execute_experiment(str(target["url"]), experiment_payload)
    except ExperimentContractError as exc:
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_http_experiment", "violation": str(exc)},
        ) from exc
    finished_at = datetime.now(timezone.utc)
    safe_result = _redact_agent_payload(executed)
    failed_count = sum(1 for item in safe_result.get("observations", []) if item.get("error"))
    result_status = "partial" if failed_count else "completed"
    async with _pool().acquire() as conn:
        async with conn.transaction():
            receipt_result = await _record_tool_receipt(conn, ToolReceiptRequest(
                tool_name="experiment.http_diff",
                adapter_version="2026-07-12.v2",
                redacted_argv=["experiment.http_diff", str(target_uuid), f"steps:{safe_result.get('request_count', 0)}"],
                target_scope={"target_id": str(target_uuid), "target_url": str(target["url"]), "same_origin_only": True},
                approval_receipt_id=approval_receipt_id,
                status="failed" if failed_count == safe_result.get("step_count") else "success",
                parser_status="parsed",
                started_at=started_at.isoformat(),
                finished_at=finished_at.isoformat(),
                redaction_summary="Credential headers forbidden; response samples bounded and redacted.",
                metadata_json={
                    "version": safe_result.get("version"),
                    "request_count": safe_result.get("request_count"),
                    "failed_count": failed_count,
                    "comparisons": safe_result.get("comparisons") or [],
                    "finding_created": False,
                    "proof_state": "unverified_experiment_signal",
                    "hypothesis_id": hypothesis_id,
                },
                created_by="research_http_experiment",
            ))
            receipt = receipt_result.get("tool_receipt") or {}
            evidence_result = await _record_evidence_instance(conn, EvidenceInstanceRequest(
                target_id=str(target_uuid),
                concrete_url=str(target["url"]),
                request_response_refs=[
                    f"{item.get('request', {}).get('method')} {item.get('request', {}).get('path')}"
                    for item in safe_result.get("observations", [])
                ],
                proof_observation={
                    "objective": safe_result.get("objective"),
                    "expected_signal": safe_result.get("expected_signal"),
                    "falsifier": safe_result.get("falsifier"),
                    "observations": safe_result.get("observations") or [],
                    "comparisons": safe_result.get("comparisons") or [],
                },
                tool_receipt_id=str(receipt.get("id")) if receipt.get("id") else None,
                proof_state="unverified",
                metadata_json={
                    "experiment_version": safe_result.get("version"),
                    "finding_created": False,
                    "promotion_allowed": False,
                    "hypothesis_id": hypothesis_id,
                },
                created_by="research_http_experiment",
            ))
            evidence = evidence_result.get("evidence_instance") or {}
            command_result = await _record_command_result(
                conn,
                command="experiment.http_diff",
                status=result_status,
                risk_tier="active",
                approval_receipt_id=approval_receipt_id,
                tool_receipt_ids=[str(receipt.get("id"))] if receipt.get("id") else [],
                operator_message=(
                    "Completed bounded HTTP differential experiment; signal remains unverified."
                    if not failed_count else
                    "HTTP differential experiment completed with request errors; signal remains unverified."
                ),
                result_json={
                    "experiment": safe_result,
                    "hypothesis_id": hypothesis_id,
                    "evidence_instance_id": str(evidence.get("id")) if evidence.get("id") else None,
                    "tool_receipt_id": str(receipt.get("id")) if receipt.get("id") else None,
                    "findings_created": 0,
                    "verified_findings_created": 0,
                },
                created_by="research_http_experiment",
            )
    return {
        "status": result_status,
        "operation_id": command_result["id"],
        "experiment": safe_result,
        "evidence_instance_id": str(evidence.get("id")) if evidence.get("id") else None,
        "tool_receipt_id": str(receipt.get("id")) if receipt.get("id") else None,
        "findings_created": 0,
        "verified_findings_created": 0,
        "proof_state": "unverified_experiment_signal",
    }


async def _arsenal_dispatch_workflow(p: dict[str, Any], approval_receipt_id: str | None) -> dict[str, Any]:
    target_uuid = _uuid_or_400(str(p.get("target_id") or ""), "target id")
    hypothesis_id = str(p.get("_research_hypothesis_id") or "").strip() or None
    workflow_uuid = _uuid_or_400(str(p.get("workflow_id") or ""), "workflow id")
    workflow_id = str(workflow_uuid)
    if workflow_id in _get("_active_workflow_cancellations"):
        raise HTTPException(status_code=409, detail="Workflow is already active")
    invariant_contract: dict[str, Any] | None = None
    async with _pool().acquire() as conn:
        target = await conn.fetchrow(
            "SELECT id, url, is_active, discovery_source FROM targets WHERE id=$1",
            target_uuid,
        )
        if not target or not target["is_active"]:
            raise HTTPException(status_code=404, detail="Active target not found")
        if str(target["discovery_source"] or "") == "model-intake":
            raise HTTPException(status_code=400, detail="Model Intake artifacts are not workflow targets")
        # A create-based mass_assignment lead selected WITHOUT a planner-supplied workflow is materialized
        # server-side: probe the create surface for its real body/envelope, then build the workflow. This
        # is what makes an unattended deep_hunt promote registration mass_assignment -- the planner only
        # selects the lead. No-op when the planner supplied steps or the lead is not create-based MA.
        await _server_materialize_create_ma(
            conn,
            str(target["url"]),
            target_uuid,
            p,
            hypothesis_id,
            approval_receipt_id,
        )
        materialization = (
            p.get("_server_materialization")
            if isinstance(p.get("_server_materialization"), dict)
            else {}
        )
        workflow_payload = {
            key: value for key, value in p.items()
            if key in {
                "objective", "expected_signal", "falsifier", "proof_family",
                "principal_variables", "assertions", "timeout_seconds", "steps",
            }
        }
        try:
            normalized = normalize_workflow(str(target["url"]), workflow_payload)
            used_slots = {
                *{step["principal"] for step in normalized["steps"]},
                *{item["principal"] for item in normalized.get("principal_variables") or []},
            }
            principal_contexts = await _resolve_workflow_principal_contexts(conn, target_uuid, used_slots)
            validate_principal_contexts(principal_contexts, used_slots)
        except WorkflowContractError as exc:
            raise HTTPException(status_code=422, detail={"error": "invalid_workflow", "violation": str(exc)}) from exc
        if hypothesis_id:
            hypothesis_uuid = _optional_uuid(hypothesis_id)
            if not hypothesis_uuid:
                raise HTTPException(status_code=422, detail="Research hypothesis id is invalid")
            hypothesis_row = await conn.fetchrow(
                "SELECT id, target_id, source, family, metadata_json FROM hypotheses WHERE id=$1 AND target_id=$2",
                hypothesis_uuid,
                target_uuid,
            )
            if hypothesis_row and str(hypothesis_row.get("source") or "") == "invariant":
                hypothesis_metadata = _decode_json_value(hypothesis_row.get("metadata_json")) or {}
                invariant_id = _optional_uuid(hypothesis_metadata.get("invariant_contract_id"))
                if not invariant_id:
                    raise HTTPException(status_code=422, detail="Invariant hypothesis is missing its approved contract binding")
                invariant_row = await conn.fetchrow(
                    "SELECT * FROM target_invariant_contracts WHERE id=$1 AND target_id=$2 AND status='approved'",
                    invariant_id,
                    target_uuid,
                )
                if not invariant_row:
                    raise HTTPException(status_code=422, detail="Invariant contract is absent, retired, or not approved")
                invariant_contract = _targets._public_target_invariant_contract_row(invariant_row)
                invariant_plan = invariant_contracts.verification_plan(invariant_contract)
                if not invariant_plan.get("deterministic_family_supported"):
                    raise HTTPException(status_code=422, detail="Invariant contract has no deterministic live binder")
                expected_family = family_proof.canonical_family(invariant_plan.get("proof_family"))
                if family_proof.canonical_family(normalized.get("proof_family")) != expected_family:
                    raise HTTPException(status_code=422, detail="Workflow proof family does not match the approved invariant contract")
                if not invariant_contract.get("method") or not invariant_contract.get("path"):
                    raise HTTPException(status_code=422, detail="Invariant contract requires an exact method and route before execution")
        protected_endpoint_rows = await conn.fetch(
            """
            SELECT method, path, auth_state FROM target_endpoints
            WHERE target_id=$1 AND COALESCE(auth_state,'') NOT IN ('', 'anonymous', 'public', 'unknown')
            """,
            target_uuid,
        )
        denied_expectation_rows = await conn.fetch(
            """
            SELECT method, path, principal_role, tenant_id
            FROM target_endpoint_expectations
            WHERE target_id=$1 AND expected_access='deny'
            """,
            target_uuid,
        )

    def annotate_trusted_route_expectations(result: dict[str, Any]) -> None:
        protected = {
            (str(row["method"] or "").upper(), _canonical_vulnerability_route(row["path"]))
            for row in protected_endpoint_rows
        }
        trusted_protected_routes = []
        for observation in (result.get("observations") or []):
            if not isinstance(observation, dict):
                continue
            request = observation.get("request") if isinstance(observation.get("request"), dict) else {}
            method = str(request.get("method") or "").upper()
            path = str(request.get("path") or "")
            route = _canonical_vulnerability_route(path)
            if (method, route) in protected:
                observation["trusted_protected_resource"] = True
                trusted_protected_routes.append({"method": method, "path": path})
            principal = str(observation.get("principal") or "anonymous").lower()
            context = principal_contexts.get(principal) if isinstance(principal_contexts.get(principal), dict) else {}
            role = str(context.get("role") or "").lower()
            tenant = str(context.get("tenant_id") or "").lower()
            observation["trusted_denied_access"] = any(
                method == str(row.get("method") or "").upper()
                and route == _canonical_vulnerability_route(row.get("path"))
                and (not row.get("principal_role") or role == str(row.get("principal_role") or "").lower())
                and (not row.get("tenant_id") or tenant == str(row.get("tenant_id") or "").lower())
                for row in denied_expectation_rows
            )
        result["trusted_protected_routes"] = trusted_protected_routes

    cancel_event = asyncio.Event()
    _get("_active_workflow_cancellations")[workflow_id] = cancel_event
    started_at = datetime.now(timezone.utc)
    try:
        _inject_create_mass_assignment_credentials(principal_contexts, normalized)
        executed = await _execute_workflow_runtime(
            str(target["url"]),
            workflow_payload,
            normalized,
            principal_contexts,
            cancel_event,
        )
        annotate_trusted_route_expectations(executed)
        # Never replay a state-changing workflow whose first run failed to restore target state.
        # The first-run evidence remains available as unverified signal, but a second run would only
        # compound residue and cannot satisfy the VERIFIED handoff contract.
        if executed.get("restoration_verified") is not True:
            replayed = {
                "proof_family": executed.get("proof_family"),
                "observations": [], "assertion_results": [],
                "restoration_verified": False,
                "replay_blocked_reason": "first_execution_restoration_not_verified",
            }
        else:
            _inject_create_mass_assignment_credentials(principal_contexts, normalized)
            replayed = await _execute_workflow_runtime(
                str(target["url"]),
                workflow_payload,
                normalized,
                principal_contexts,
                cancel_event,
            )
            annotate_trusted_route_expectations(replayed)
    except WorkflowContractError as exc:
        raise HTTPException(status_code=422, detail={"error": "workflow_execution_failed", "violation": str(exc)}) from exc
    finally:
        _get("_active_workflow_cancellations").pop(workflow_id, None)

    finished_at = datetime.now(timezone.utc)
    safe_result = _redact_agent_payload(executed)
    safe_replay = _redact_agent_payload(replayed)
    # Derive the proof from the RAW results so the server-computed sensitive-value categories
    # (and full status/principal/comparison signals) survive redaction. The proof object itself
    # carries only predicate labels + booleans, never raw response values.
    trusted_proof = _trusted_workflow_family_proof(
        executed,
        replayed,
        invariant_contract=invariant_contract,
        normalized=normalized,
    )
    failed_count = sum(1 for item in safe_result.get("observations", []) if item.get("error"))
    result_status = "partial" if failed_count or safe_result.get("cancelled") else "completed"
    async with _pool().acquire() as conn:
        async with conn.transaction():
            receipt_result = await _record_tool_receipt(conn, ToolReceiptRequest(
                tool_name="experiment.workflow",
                adapter_version="2026-07-12.v1",
                redacted_argv=["experiment.workflow", str(target_uuid), workflow_id, f"steps:{safe_result.get('step_count', 0)}"],
                target_scope={"target_id": str(target_uuid), "target_url": str(target["url"]), "same_origin_only": True},
                approval_receipt_id=approval_receipt_id,
                status="failed" if failed_count == safe_result.get("step_count") else "success",
                parser_status="parsed",
                started_at=started_at.isoformat(),
                finished_at=finished_at.isoformat(),
                redaction_summary="Managed credentials resolved in memory; persisted workflow values are bounded and redacted.",
                metadata_json={
                    "workflow_id": workflow_id,
                    "version": safe_result.get("version"),
                    "step_count": safe_result.get("step_count"),
                    "request_count": safe_result.get("request_count"),
                    "replay_request_count": safe_replay.get("request_count"),
                    "principal_receipts": safe_result.get("principal_receipts") or [],
                    "cancelled": safe_result.get("cancelled"),
                    "finding_created": False,
                    "proof_state": "verified" if trusted_proof.get("promotable") else "unverified_workflow_signal",
                    "family_proof": trusted_proof,
                    "hypothesis_id": hypothesis_id,
                    "server_materialization": materialization,
                    "invariant_contract_id": (
                        str(invariant_contract.get("id")) if invariant_contract else None
                    ),
                },
                created_by="research_principal_workflow",
            ))
            receipt = receipt_result.get("tool_receipt") or {}
            evidence_result = await _record_evidence_instance(conn, EvidenceInstanceRequest(
                target_id=str(target_uuid),
                concrete_url=str(target["url"]),
                request_response_refs=[
                    f"{item.get('kind')}:{item.get('label')}:{item.get('principal')}"
                    for item in safe_result.get("observations", [])
                ],
                proof_observation={
                    "workflow_id": workflow_id,
                    "objective": safe_result.get("objective"),
                    "expected_signal": safe_result.get("expected_signal"),
                    "falsifier": safe_result.get("falsifier"),
                    "principal_receipts": safe_result.get("principal_receipts") or [],
                    "observations": safe_result.get("observations") or [],
                    "comparisons": safe_result.get("comparisons") or [],
                    "assertion_results": safe_result.get("assertion_results") or [],
                    "replay_assertion_results": safe_replay.get("assertion_results") or [],
                    "family_proof": trusted_proof,
                },
                tool_receipt_id=str(receipt.get("id")) if receipt.get("id") else None,
                proof_state="verified" if trusted_proof.get("promotable") else "unverified",
                metadata_json={"workflow_version": safe_result.get("version"), "finding_created": False, "promotion_allowed": bool(trusted_proof.get("promotable")), "hypothesis_id": hypothesis_id, "invariant_contract_id": str(invariant_contract.get("id")) if invariant_contract else None, "reproduction_count": 2},
                created_by="research_principal_workflow",
            ))
            evidence = evidence_result.get("evidence_instance") or {}
            promotion = await _promote_trusted_workflow_finding(
                conn,
                target_uuid=target_uuid,
                target_url=str(target["url"]),
                hypothesis_id=hypothesis_id or "",
                workflow_id=workflow_id,
                proof=trusted_proof,
                first=safe_result,
                replay=safe_replay,
                evidence_instance_id=str(evidence.get("id")) if evidence.get("id") else None,
                tool_receipt_id=str(receipt.get("id")) if receipt.get("id") else None,
            )
            finding_ids = [promotion["finding_id"]] if promotion else []
            if receipt.get("id"):
                await conn.execute(
                    """
                    UPDATE tool_receipts
                    SET metadata_json = metadata_json || $2::jsonb
                    WHERE id=$1
                    """,
                    uuid.UUID(str(receipt["id"])),
                    json.dumps({
                        "finding_created": bool(promotion and promotion.get("status") == "created"),
                        "finding_id": promotion.get("finding_id") if promotion else None,
                        "proof_state": "verified" if promotion else "unverified_workflow_signal",
                    }),
                )
            command_result = await _record_command_result(
                conn,
                command="experiment.workflow",
                status=result_status,
                risk_tier="credential",
                approval_receipt_id=approval_receipt_id,
                finding_ids=finding_ids,
                hypothesis_ids=[hypothesis_id] if hypothesis_id else [],
                tool_receipt_ids=[
                    receipt_id for receipt_id in (
                        str(receipt.get("id")) if receipt.get("id") else None,
                        str(materialization.get("tool_receipt_id"))
                        if materialization.get("tool_receipt_id") else None,
                    )
                    if receipt_id
                ],
                operator_message=(
                    "Independent replay passed deterministic proof and created or refreshed a verified finding."
                    if promotion else
                    "Principal-bound workflow completed; proof remained unverified or was safely refuted."
                ),
                result_json={
                    "workflow": safe_result,
                    "replay": safe_replay,
                    "family_proof": trusted_proof,
                    "promotion": promotion,
                    "hypothesis_id": hypothesis_id,
                    "evidence_instance_id": str(evidence.get("id")) if evidence.get("id") else None,
                    "tool_receipt_id": str(receipt.get("id")) if receipt.get("id") else None,
                    "server_materialization": materialization,
                    "findings_created": 1 if promotion and promotion.get("status") == "created" else 0,
                    "verified_findings_created": 1 if promotion else 0,
                },
                created_by="research_principal_workflow",
            )
    return {
        "status": result_status,
        "operation_id": command_result["id"],
        "workflow_id": workflow_id,
        "workflow": safe_result,
        "replay": safe_replay,
        "family_proof": trusted_proof,
        "promotion": promotion,
        "evidence_instance_id": str(evidence.get("id")) if evidence.get("id") else None,
        "tool_receipt_id": str(receipt.get("id")) if receipt.get("id") else None,
        "server_materialization": materialization,
        "findings_created": 1 if promotion and promotion.get("status") == "created" else 0,
        "verified_findings_created": 1 if promotion else 0,
        "proof_state": "verified" if promotion else "unverified_workflow_signal",
    }


def _research_hypothesis_provability(item: Any) -> tuple[int, list[str]]:
    """Score whether a lead can produce bounded, independently checkable proof."""
    hypothesis = item if isinstance(item, dict) else {}
    metadata = hypothesis.get("metadata_json") if isinstance(hypothesis.get("metadata_json"), dict) else {}
    contract = _research_hypothesis_experiment_contract(hypothesis)
    family = family_proof.canonical_family(contract.get("family"))
    method = str(contract.get("method") or "").upper()
    route = str(contract.get("route") or "")
    available_methods = {
        str(value).upper() for value in metadata.get("available_methods") or [] if str(value).strip()
    }
    score = 0
    blockers: list[str] = []
    if route:
        score += 2
    else:
        blockers.append("route_missing")
    if method:
        score += 1
    if contract.get("request_fields") or contract.get("request_example"):
        score += 2
    if _targets._ID_PATH_SEGMENT.search(route):
        score += 2
    if family == "bola":
        if set(contract.get("required_principals") or []) >= {"primary_auth", "second_user_auth"}:
            score += 2
        else:
            blockers.append("two_principal_context_missing")
    if family in {"mass_assignment", "field_constraint", "workflow"}:
        if method in {"POST", "PUT", "PATCH"}:
            score += 1
        # A create (POST /collection) reads back on the paired child route /collection/{id}, not its own
        # route, so readback_route/readable_route (not just same-route GET) evidences a readback.
        if "GET" in available_methods or metadata.get("readable_route") or metadata.get("readback_route"):
            score += 3
        else:
            blockers.append("readback_route_missing")
        # Create-based restoration is best-effort (the create template always attempts a DELETE and the
        # two-run proof accepts an unrestorable create), so a missing cleanup route neither blocks nor
        # penalizes the lead; a real DELETE route is a small provability bonus for cleaner restoration.
        if metadata.get("create_based") and metadata.get("cleanup_route"):
            score += 1
    if _targets._research_auth_session_route(route):
        score -= 8
        blockers.append("auth_session_shape")
    return score, blockers


def _research_action_dedupe_comparable(action: Any) -> dict[str, Any]:
    """Reduce a planner action to its STABLE dedupe identity.

    For a bounded workflow experiment the planner (and _research_autobind_hypothesis) stamps a
    fresh workflow_id and re-words objective/falsifier on every attempt, so hashing the raw
    parameters lets a mechanically identical test slip past the duplicate guard forever -- the
    observed "same auth_bypass ~43x against one route" spin that burned a 2M-token marathon to 0
    findings. Collapse an experiment to (family, canonical step routes+methods+principals,
    assertion predicates); everything ephemeral or merely descriptive is dropped so a genuine
    re-run of the same test matches. Non-experiment commands keep raw {command, parameters}.
    """
    payload = action if isinstance(action, dict) else {}
    command = str(payload.get("command") or "").strip()
    params = payload.get("parameters") if isinstance(payload.get("parameters"), dict) else {}
    if command not in _RESEARCH_EXPERIMENT_DEDUPE_COMMANDS:
        return {"command": command, "parameters": params}
    steps = params.get("steps") if isinstance(params.get("steps"), list) else []
    # Canonical step identity = every semantic field of the step (including checkpoint) with mutable
    # labels removed and every label reference resolved to the referenced step's content identity.
    # ``checkpoint`` is execution semantics, not presentation: before/mutation/cleanup/action changes
    # both what the runtime permits and what proof/restoration means. ``compare_to`` is a label
    # reference, so retaining its raw text would let a mechanically identical workflow bypass dedupe
    # merely by renaming its steps.
    step_base_identity: dict[str, str] = {}
    base_steps: list[tuple[dict[str, Any], dict[str, Any], str]] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        identity = {key: value for key, value in step.items() if key not in {"label", "id", "compare_to"}}
        identity["route"] = _canonical_vulnerability_route(step.get("path") or step.get("route"))
        identity.pop("path", None)
        base_hash = _research_canonical_hash(identity)
        label = str(step.get("label") or step.get("id") or "").strip()
        if label:
            step_base_identity[label] = base_hash
        base_steps.append((step, identity, label))

    def _resolve_base_step(ref: Any) -> str | None:
        text = str(ref or "").strip()
        if not text:
            return None
        return step_base_identity.get(text, f"unbound:{text}")

    step_identity: dict[str, str] = {}
    canonical_steps: list[str] = []
    for step, identity, label in base_steps:
        identity = {**identity, "compare_to": _resolve_base_step(step.get("compare_to"))}
        identity_hash = _research_canonical_hash(identity)
        if label:
            step_identity[label] = identity_hash
        canonical_steps.append(identity_hash)

    def _resolve_step(ref: Any) -> str | None:
        text = str(ref or "").strip()
        if not text:
            return None
        return step_identity.get(text, f"unbound:{text}")

    assertions = params.get("assertions") if isinstance(params.get("assertions"), list) else []
    canonical_assertions = sorted(
        _research_canonical_hash({
            "type": str(a.get("type") or "").strip(),
            "predicate": str(a.get("predicate") or "").strip().lower(),
            "values": sorted(a.get("values")) if isinstance(a.get("values"), list) else a.get("values"),
            "step": _resolve_step(a.get("step")),
            "control": _resolve_step(a.get("control")),
            "candidate": _resolve_step(a.get("candidate")),
            "steps": sorted(x for x in (_resolve_step(s) for s in a.get("steps")) if x)
            if isinstance(a.get("steps"), list) else None,
        })
        for a in assertions
        if isinstance(a, dict)
    )
    principal_variables = sorted(
        _research_canonical_hash({
            "principal": str(item.get("principal") or "").strip().lower(),
            "ref": str(item.get("ref") or "").strip().lower(),
        })
        for item in params.get("principal_variables") or []
        if isinstance(item, dict)
    )
    return {
        "command": command,
        "parameters": {
            "proof_family": str(params.get("proof_family") or params.get("family") or "").strip().lower(),
            "steps": canonical_steps,
            "assertions": canonical_assertions,
            "principal_variables": principal_variables,
        },
    }


def _finding_vulnerability_key(value: Any) -> str | None:
    finding, family, route, method, dedupe_dimensions, evidence, request = _finding_family_route_method(value)
    computed = _canonical_vulnerability_key(
        family=family,
        route=route,
        method=method,
        dimensions=_research_vulnerability_dimensions(
            family,
            dedupe_dimensions if isinstance(evidence, dict) else {},
            evidence,
            finding,
            request if isinstance(request, dict) else {},
        ),
    )
    if computed:
        return computed
    # Keep opaque legacy/manual evidence attributable only when structured family/route data is absent.
    # Recompute whenever possible so legacy explicit hashes cannot bypass the v3 dimensional key.
    explicit = str((evidence or {}).get("canonical_vulnerability_key") or "").strip().lower()
    return explicit if re.fullmatch(r"[a-f0-9]{64}", explicit) else None


def _finding_coverage_key(value: Any) -> str | None:
    _finding, family, route, method, _dims, _evidence, _request = _finding_family_route_method(value)
    return _canonical_coverage_key(family=family, route=route, method=method)






RESEARCH_PRIMARY_CREDENTIAL_FAMILIES = frozenset({
    "auth", "bola", "mass_assignment", "workflow", "data_exposure",
    "access_control", "field_constraint",
})


RESEARCH_SECOND_USER_FAMILIES = frozenset({"bola"})


def _research_hypothesis_vulnerability_key(hypothesis: dict[str, Any]) -> str | None:
    metadata = hypothesis.get("metadata_json") if isinstance(hypothesis.get("metadata_json"), dict) else {}
    metadata_dimensions = metadata.get("dedupe_dimensions") if isinstance(metadata.get("dedupe_dimensions"), dict) else {}
    direct_dimensions = hypothesis.get("dedupe_dimensions") if isinstance(hypothesis.get("dedupe_dimensions"), dict) else {}
    dimensions = {**metadata_dimensions, **direct_dimensions}
    return _canonical_vulnerability_key(
        family=hypothesis.get("family"),
        route=_research_hypothesis_route(hypothesis),
        method=dimensions.get("method") or metadata.get("method"),
        dimensions=_research_vulnerability_dimensions(
            hypothesis.get("family"),
            dimensions,
            metadata,
            hypothesis.get("next_test_action") if isinstance(hypothesis.get("next_test_action"), dict) else {},
        ),
    )


def _research_hypothesis_coverage_key(hypothesis: dict[str, Any]) -> str | None:
    """Coarse family+method+route coverage key for a hunt lead (see _canonical_coverage_key)."""
    metadata = hypothesis.get("metadata_json") if isinstance(hypothesis.get("metadata_json"), dict) else {}
    metadata_dimensions = metadata.get("dedupe_dimensions") if isinstance(metadata.get("dedupe_dimensions"), dict) else {}
    direct_dimensions = hypothesis.get("dedupe_dimensions") if isinstance(hypothesis.get("dedupe_dimensions"), dict) else {}
    dimensions = {**metadata_dimensions, **direct_dimensions}
    return _canonical_coverage_key(
        family=hypothesis.get("family"),
        route=_research_hypothesis_route(hypothesis),
        method=dimensions.get("method") or metadata.get("method"),
    )


def _research_experiment_failure_detail(result_json: Any) -> tuple[str | None, list[str]]:
    payload = result_json if isinstance(result_json, dict) else {}
    workflow = payload.get("workflow") if isinstance(payload.get("workflow"), dict) else {}
    replay = payload.get("replay") if isinstance(payload.get("replay"), dict) else {}
    observations = [
        *(workflow.get("observations") or []),
        *(payload.get("observations") or []),
        *(replay.get("observations") or []),
    ]
    failed_predicates = sorted({
        str(assertion.get("predicate") or assertion.get("type") or "")[:120]
        for source in (workflow, payload, replay)
        for assertion in (source.get("assertion_results") or [])
        if isinstance(assertion, dict) and assertion.get("passed") is False
        and (assertion.get("predicate") or assertion.get("type"))
    })
    reason = " ".join(str(value or "") for value in (
        payload.get("failure_reason"),
        replay.get("replay_blocked_reason"),
        (payload.get("family_proof") or {}).get("reason")
        if isinstance(payload.get("family_proof"), dict) else "",
    )).lower()
    if "restor" in reason or "before_after_state" in failed_predicates:
        return "restoration_failed", failed_predicates
    if "baseline" in reason:
        return "baseline_failed", failed_predicates
    if "privileg" in reason or "elevation" in reason:
        return "no_privilege_elevation", failed_predicates
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        response = observation.get("response") if isinstance(observation.get("response"), dict) else {}
        status = response.get("status")
        if observation.get("error"):
            return "transport_or_runtime_error", failed_predicates
        if isinstance(status, int) and status >= 400:
            checkpoint = str(observation.get("checkpoint") or "")
            return (
                "baseline_request_failed" if checkpoint == "before"
                else "mutation_request_failed" if checkpoint == "mutation"
                else "workflow_step_failed"
            ), failed_predicates
    if failed_predicates:
        return "proof_predicates_failed", failed_predicates
    return ("proof_evidence_missing" if reason else None), failed_predicates
def _refuter_automation_plan_for_finding(
    payload: dict[str, Any],
    evidence: dict[str, Any],
    *,
    trigger_type: str,
    reasons: Sequence[str],
) -> dict[str, Any]:
    finding_id = str(payload.get("id") or payload.get("fingerprint") or "")
    target_id = str(payload.get("target_id")) if payload.get("target_id") else None
    source = str(payload.get("source") or "").lower()
    tool = str(payload.get("tool") or "").lower()
    category = str(payload.get("category") or payload.get("cwe") or "").lower()
    url_hint = (
        payload.get("url")
        or evidence.get("url")
        or evidence.get("target_url")
        or evidence.get("endpoint")
        or evidence.get("concrete_url")
    )
    request_hint = payload.get("request") or evidence.get("request") or evidence.get("raw_request")
    replayable = bool(finding_id and (url_hint or request_hint or target_id))

    steps: list[dict[str, Any]] = [{
        "id": "review_claim_basis",
        "label": "Review stored claim basis",
        "mode": "record_only",
        "command": "refuter_review.record",
        "verdict_basis_after_execution": "signal_only",
        "requires": ["finding_record"],
        "counterevidence_goal": "Identify the specific proof gap or benign explanation before any replay.",
    }]

    if source == "ai_gate" or payload.get("ai_target_id"):
        steps.append({
            "id": "replay_ai_gate_probe",
            "label": "Replay the original AI Gate probe context",
            "mode": "planned_not_executed",
            "command": "ai_gate.replay_probe",
            "verdict_basis_after_execution": "deterministic_replay",
            "requires": ["ai_target_id", "probe_id_or_transcript_index", "production_confirmation_when_applicable"],
            "counterevidence_goal": "Show the deterministic detector no longer fires, transcript was semantic-only, or control evidence explains the hit.",
        })
    elif source == "model_intake" or tool == "model_intake":
        steps.append({
            "id": "verify_model_trust_material",
            "label": "Re-check checksum, signature, and trust-anchor material",
            "mode": "planned_not_executed",
            "command": "model_intake.trust_preview",
            "verdict_basis_after_execution": "cryptographic",
            "requires": ["artifact_hash_or_metadata", "signature_or_trusted_key_when_available"],
            "counterevidence_goal": "Prove the metadata claim is unsupported, cryptographically anchored, or superseded by trusted approval evidence.",
        })
    else:
        steps.append({
            "id": "deterministic_retest",
            "label": "Run the smallest deterministic finding retest",
            "mode": "planned_not_executed",
            "command": "finding.retest",
            "verdict_basis_after_execution": "deterministic_replay",
            "requires": ["finding_id", "scope_receipt_if_policy_requires", "approval_receipt_if_policy_requires"],
            "counterevidence_goal": "Replay the minimal request and show fixed, blocked, non-reproducible, or non-vulnerable behavior.",
        })

    if any(token in category for token in ("639", "bola", "idor", "auth", "access", "bfla")) or any(
        reason in {"critical_high_weak_or_suspected_proof", "ai_gate_semantic_or_weak_deterministic_claim"}
        for reason in reasons
    ):
        steps.append({
            "id": "check_auth_context",
            "label": "Verify auth, principal, tenant, and object ownership context",
            "mode": "planned_not_executed",
            "command": "asm.improve",
            "verdict_basis_after_execution": "deterministic_replay",
            "requires": ["primary_auth", "second_user_auth_for_bola_or_idor", "object_identifier"],
            "counterevidence_goal": "Show the original claim used the wrong principal, stale object, missing tenant boundary, or unauthenticated context.",
        })

    benign_explanations = [
        "target behavior changed since the original observation",
        "the original evidence was partial, parser-only, semantic-only, or missing a replayable request",
    ]
    if any("auth" in reason or "principal" in reason or "bola" in reason for reason in reasons):
        benign_explanations.extend([
            "the replay used the wrong or unauthenticated principal",
            "the object identifier was public, shared, stale, or not owned by the asserted principal",
        ])
    if any("parser" in reason for reason in reasons):
        benign_explanations.extend([
            "the parser promoted severity from incomplete output",
            "the tool receipt shows timeout, parser failure, or missing proof-critical stdout/stderr",
        ])
    if any("deployment" in reason for reason in reasons):
        benign_explanations.append("a deployment gate counted a weak or exception-covered claim as blocking evidence")

    return {
        "status": "planned_not_executed",
        "execution_enabled": False,
        "recommended_basis": steps[-1].get("verdict_basis_after_execution") if steps else "signal_only",
        "record_only_until_executed": True,
        "subject": {
            "subject_type": "finding",
            "subject_id": finding_id or None,
            "finding_id": finding_id if payload.get("id") else None,
            "target_id": target_id,
            "trigger_type": trigger_type,
        },
        "minimal_reproducer": _redact_agent_payload({
            "available": replayable,
            "has_url": bool(url_hint),
            "has_request": bool(request_hint),
            "url_sample": str(url_hint)[:300] if url_hint else None,
        }),
        "steps": steps[:5],
        "counterevidence_bundle": {
            "review_questions": [
                "What exact proof state, request, response, principal, and object made this claim security-relevant?",
                "Can the smallest deterministic replay reproduce the same impact now?",
                "Is there parser/protocol, cryptographic, or human-approved-review evidence strong enough for a verdict?",
            ],
            "benign_explanations_to_test": benign_explanations[:8],
            "required_evidence_refs": [
                "finding_id",
                "evidence_object_id_or_instance_id",
                "tool_receipt_id_when_parser_or_external_tool_output_is_involved",
                "verification_id_after_replay",
            ],
            "verdict_paths": {
                "supported": "deterministic replay or cryptographic/parser evidence reproduces the claim",
                "weakened": "replay is blocked, stale, partial, or no longer demonstrates the original impact",
                "refuted": "deterministic replay shows false positive or benign behavior",
                "inconclusive": "proof-critical evidence is missing or ambiguous",
            },
        },
        "counterevidence_schema": {
            "observed_behavior": "fixed|blocked|non_reproducible|benign_explanation|still_vulnerable|inconclusive",
            "basis": "signal_only|deterministic_replay|cryptographic|parser_protocol|human_approved_review",
            "artifact_refs": ["evidence_object_id", "tool_receipt_id"],
            "notes": "redacted analyst or automation notes",
        },
    }












def _refuter_counterevidence_corroborates(counterevidence: Any) -> bool:
    """A refutation is corroborated when a deterministic re-run actually observed the mitigation.

    For ShakerScan that evidence lives in the verification proof / artifacts / replay commands (or an
    explicit observed cite) — the HTTP-behaviour analogue of "the cited guard exists in source".
    """
    if not isinstance(counterevidence, dict):
        return False
    if counterevidence.get("proof") or counterevidence.get("artifacts") or counterevidence.get("replay_commands"):
        return True
    cite = counterevidence.get("cite")
    return isinstance(cite, dict) and bool(cite.get("observed"))


async def _execute_refuter_review_plan(
    conn,
    *,
    refuter_review_id: str,
    approval_receipt_id: str | None = None,
    step_id: str | None = None,
    requested_by: str | None = "refuter_executor",
    confirm_production: bool = False,
) -> dict[str, Any]:
    try:
        review_uuid = uuid.UUID(str(refuter_review_id))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="refuter_review_id must be a UUID")

    review_row = await conn.fetchrow("SELECT * FROM refuter_reviews WHERE id=$1", review_uuid)
    if not review_row:
        raise HTTPException(status_code=404, detail="Refuter review not found")
    review = _public_refuter_review_row(review_row)
    if review.get("subject_type") != "finding":
        raise HTTPException(status_code=400, detail="Only finding refuter reviews support automated execution")
    finding_ref = str(review.get("finding_id") or review.get("subject_id") or "").strip()
    if not finding_ref:
        raise HTTPException(status_code=400, detail="Refuter review is missing finding context")

    finding_row = await _ai_targets.get_finding_record(conn, finding_ref)
    if not finding_row:
        raise HTTPException(status_code=404, detail="Finding not found for refuter review")
    finding = row_to_dict(finding_row)
    metadata = review.get("metadata_json") if isinstance(review.get("metadata_json"), dict) else {}
    automation_plan = _refuter_finding_automation_plan(finding, metadata)
    planned_step = _select_refuter_automation_step(automation_plan, step_id=step_id)

    source = str(finding.get("source") or "").lower()
    tool = str(finding.get("tool") or "").lower()
    delegated_command = str(planned_step.get("command") or "")
    execution_kind = "deterministic_retest"
    delegated_result: dict[str, Any]
    status = "completed"

    if source == "ai_gate" or finding.get("ai_target_id"):
        delegated_command = "ai_gate.finding_replay"
        execution_kind = "ai_gate_finding_replay"
        delegated_result = await _ai_targets.retest_ai_finding(
            str(finding["id"]),
            _ai_targets.AIFindingRetestRequest(
                mode="same_probe",
                requested_by=requested_by or "refuter_executor",
                confirm_production=confirm_production,
                approval_receipt_id=approval_receipt_id,
            ),
        )
        status = str(delegated_result.get("status") or "queued")
    elif source == "model_intake" or tool == "model_intake":
        delegated_command = "model_intake.trust_preview"
        execution_kind = "model_intake_trust_preview"
        delegated_result = await _arsenal_dispatch_model_intake_trust_preview({
            "policy_profile": metadata.get("policy_profile") or "production",
            "trust_mode": metadata.get("trust_mode") or "saved_anchor",
        })
        status = "completed"
    else:
        delegated_command = "finding.retest"
        delegated_result = await _finding_routes.retest_finding(
            str(finding["id"]),
            _finding_routes.FindingRetestRequest(
                requested_by=requested_by or "refuter_executor",
                approval_receipt_id=approval_receipt_id,
            ),
            mode="deterministic",
        )
        status = str(delegated_result.get("status") or "queued")

    execution_event = _redact_agent_payload({
        "executed_at": utc_now_iso(),
        "status": status,
        "execution_kind": execution_kind,
        "planned_step_id": planned_step.get("id"),
        "planned_command": planned_step.get("command"),
        "delegated_command": delegated_command,
        "delegated_operation_id": delegated_result.get("operation_id") if isinstance(delegated_result, dict) else None,
        "retest_id": delegated_result.get("retest_id") if isinstance(delegated_result, dict) else None,
        "scan_id": delegated_result.get("scan_id") if isinstance(delegated_result, dict) else None,
        "ui_url": delegated_result.get("ui_url") if isinstance(delegated_result, dict) else None,
        "verdict_pending": True,
        "verdict_recording_command": "refuter_review.record",
    })
    updated_metadata = {
        **metadata,
        "automation_plan": automation_plan,
        "latest_refuter_execution": execution_event,
    }
    updated_row = await conn.fetchrow(
        """
        UPDATE refuter_reviews
        SET metadata_json=$2::jsonb, updated_at=NOW()
        WHERE id=$1
        RETURNING *
        """,
        review_uuid,
        json.dumps(updated_metadata),
    )
    command_result = await _record_command_result(
        conn,
        command="refuter_review.execute_plan",
        status="retest_scheduled" if status == "queued" else status,
        risk_tier="active",
        finding_ids=[str(finding["id"])],
        approval_receipt_id=approval_receipt_id,
        operator_message=f"Executed refuter automation step {execution_event['planned_step_id']} for finding {finding.get('title') or finding['id']}",
        result_json={
            "refuter_review_id": str(review_uuid),
            "finding_id": str(finding["id"]),
            "execution": execution_event,
            "delegated_result": delegated_result,
            "findings_updated_by_refuter": 0,
            "hypotheses_updated_by_refuter": 0,
        },
        next_action=str(delegated_result.get("ui_url") or f"/findings/{finding['id']}") if isinstance(delegated_result, dict) else f"/findings/{finding['id']}",
        created_by=requested_by or "refuter_executor",
    )
    return {
        "refuter_review": _public_refuter_review_row(updated_row),
        "executed_step": planned_step,
        "delegated_command": delegated_command,
        "delegated_result": delegated_result,
        "status": "retest_scheduled" if status == "queued" else status,
        "operation_id": command_result["id"],
        "command_result": command_result,
        "execution_enabled": True,
        "findings_updated": 0,
        "hypotheses_updated": 0,
        "verdict_pending": True,
    }


async def _derive_refuter_review_verdict(
    conn,
    *,
    refuter_review_id: str,
    verification_id: str | None = None,
    created_by: str | None = "refuter_verdict_derive",
) -> dict[str, Any]:
    try:
        review_uuid = uuid.UUID(str(refuter_review_id))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="refuter_review_id must be a UUID")
    review_row = await conn.fetchrow("SELECT * FROM refuter_reviews WHERE id=$1", review_uuid)
    if not review_row:
        raise HTTPException(status_code=404, detail="Refuter review not found")
    review = _public_refuter_review_row(review_row)
    if review.get("subject_type") != "finding":
        raise HTTPException(status_code=400, detail="Only finding refuter reviews can derive verdicts from finding verifications")
    finding_ref = str(review.get("finding_id") or review.get("subject_id") or "").strip()
    if not finding_ref:
        raise HTTPException(status_code=400, detail="Refuter review is missing finding context")
    try:
        finding_uuid = uuid.UUID(finding_ref)
    except ValueError:
        finding_row = await _ai_targets.get_finding_record(conn, finding_ref)
        if not finding_row:
            raise HTTPException(status_code=404, detail="Finding not found for refuter review")
        finding_uuid = uuid.UUID(str(finding_row["id"]))

    metadata = review.get("metadata_json") if isinstance(review.get("metadata_json"), dict) else {}
    latest_execution = metadata.get("latest_refuter_execution") if isinstance(metadata.get("latest_refuter_execution"), dict) else {}
    linked_retest_id = str(latest_execution.get("retest_id") or latest_execution.get("verification_id") or "").strip()
    selected_verification_id = str(verification_id or linked_retest_id or "").strip()

    if selected_verification_id:
        try:
            verification_uuid = uuid.UUID(selected_verification_id)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="verification_id must be a UUID")
        verification_row = await conn.fetchrow(
            """
            SELECT *
            FROM finding_verifications
            WHERE id=$1 AND finding_id=$2
            """,
            verification_uuid,
            finding_uuid,
        )
    else:
        raise HTTPException(status_code=409, detail="Refuter review has no linked retest verification; execute the review plan first or provide verification_id")
    if not verification_row:
        raise HTTPException(status_code=404, detail="Completed refuter verification not found")
    verification = row_to_dict(verification_row)
    if str(verification.get("status") or "").lower() not in {"completed", "failed"}:
        raise HTTPException(status_code=409, detail="Refuter verification has not completed")

    outcome = _refuter_review_from_verification_outcome(verification)
    proof = _decode_json_value(verification.get("proof")) or {}
    artifacts = _decode_json_value(verification.get("artifacts")) or {}
    replay_commands = _decode_json_value(verification.get("replay_commands")) or []
    counterevidence = _redact_agent_payload({
        "verification_id": str(verification.get("id")),
        "verification_status": verification.get("status"),
        "result_status": verification.get("result_status"),
        "verdict": verification.get("verdict"),
        "verdict_reason": verification.get("verdict_reason"),
        "verification_mode": verification.get("verification_mode") or "deterministic",
        "proof": proof,
        "artifacts": artifacts,
        "replay_commands": replay_commands,
    })
    result = await _record_refuter_review(conn, RefuterReviewRequest(
        subject_type="finding",
        subject_id=str(review.get("subject_id") or finding_uuid),
        target_id=review.get("target_id"),
        finding_id=str(finding_uuid),
        trigger_reason=f"Derived from completed verification {verification.get('id')}",
        refuter_signal=outcome["refuter_signal"],
        refuter_verdict=outcome["refuter_verdict"],
        verdict_basis=outcome["verdict_basis"],
        confidence_delta=outcome["confidence_delta"],
        counterevidence=counterevidence,
        notes=(
            "Verification result recorded as a refuter signal only; proof-backed verdicts require "
            "completed deterministic replay, cryptographic, parser/protocol, or human-approved-review basis."
            if not outcome["deterministic_basis"]
            else None
        ),
        metadata_json={
            "derived_from_refuter_review_id": str(review_uuid),
            "derived_from_verification_id": str(verification.get("id")),
            "derived_observation": outcome["observation"],
            "deterministic_basis": outcome["deterministic_basis"],
        },
        created_by=created_by,
    ))
    # Reconcile the execute->derive handshake: mark the source review's pending retest
    # resolved so verdict_pending is no longer a dangling flag. create_missing=false keeps
    # this a no-op when the review has no latest_refuter_execution (explicit verification_id).
    await conn.execute(
        """
        UPDATE refuter_reviews
        SET metadata_json = jsonb_set(
                jsonb_set(
                    COALESCE(metadata_json, '{}'::jsonb),
                    '{latest_refuter_execution,verdict_pending}', 'false'::jsonb, false
                ),
                '{latest_refuter_execution,verdict_derived_verification_id}',
                to_jsonb($2::text), false
            ),
            updated_at = NOW()
        WHERE id = $1
        """,
        review_uuid,
        str(verification.get("id")),
    )
    return {
        **result,
        "source_refuter_review_id": str(review_uuid),
        "verification_id": str(verification.get("id")),
        "verdict_pending": False,
        "derived_outcome": outcome,
        "execution_enabled": False,
        "findings_updated": 0,
        "hypotheses_updated": 0,
    }


class _ArsenalQueryRequest:
    def __init__(self, query_params: dict[str, Any]):
        self.query_params = query_params


def _arsenal_model_fields(model_cls) -> set[str]:
    fields = getattr(model_cls, "model_fields", None)
    if isinstance(fields, dict):
        return set(fields)
    fields = getattr(model_cls, "__fields__", None)
    if isinstance(fields, dict):
        return set(fields)
    return set()


def _research_hypothesis_experiment_contract(hypothesis: Any) -> dict[str, Any]:
    """Project one stored lead into the minimum executable planner contract.

    This is deliberately separate from the general hypothesis summary.  The
    selected lead's route and request shape are mandatory control data, not
    optional descriptive metadata that compaction may discard.
    """
    item = hypothesis if isinstance(hypothesis, dict) else {}
    metadata = item.get("metadata_json") if isinstance(item.get("metadata_json"), dict) else {}
    dedupe = metadata.get("dedupe_dimensions") if isinstance(metadata.get("dedupe_dimensions"), dict) else {}
    next_test = item.get("next_test_action") if isinstance(item.get("next_test_action"), dict) else {}
    family = str(item.get("family") or "").strip().lower()
    route = str(dedupe.get("route") or metadata.get("route") or item.get("route") or item.get("path") or "").strip()
    method = str(dedupe.get("method") or metadata.get("method") or "").strip().upper()
    request_fields = metadata.get("request_fields")
    if isinstance(request_fields, str):
        request_fields = ",".join(
            field.strip()
            for field in request_fields.split(",")
            if field.strip().lower() not in _get("FORBIDDEN_AGENT_CONTEXT_KEYS")
        ) or None
    elif isinstance(request_fields, list):
        request_fields = [
            field for field in request_fields
            if str(field).strip().lower() not in _get("FORBIDDEN_AGENT_CONTEXT_KEYS")
        ] or None
    request_example = metadata.get("request_example")
    if isinstance(request_example, str) and re.search(
        r"(?i)(?:authorization|authorization_header|auth_header|bearer_token|cookie|cookies|"
        r"private_key|raw_private_key|raw_request|raw_response|raw_transcript|raw_transcripts|"
        r"secret|token)[\"']?\s*[:=]",
        request_example,
    ):
        request_example = None
    invariant_contract = metadata.get("invariant_contract") if isinstance(metadata.get("invariant_contract"), dict) else None
    required_principals = list(next_test.get("requires") or []) if isinstance(next_test.get("requires"), list) else []
    if family_proof.canonical_family(family) == "bola":
        required_principals = list(dict.fromkeys([*required_principals, "primary_auth", "second_user_auth"]))
    elif family in {"auth", "auth_bypass"}:
        required_principals = list(dict.fromkeys([*required_principals, "primary_auth"]))
    contract = {
        "hypothesis_id": str(item.get("id") or ""),
        "family": family,
        "title": str(item.get("title") or "")[:300],
        "method": method or None,
        "route": route or None,
        "request_fields": request_fields,
        "request_example": request_example,
        "required_principals": required_principals,
        "next_test_action": next_test,
        "attempt_count": int(metadata.get("attempt_count") or 0),
        "prior_failures": int(metadata.get("prior_failures") or 0),
        "last_outcome": metadata.get("last_outcome"),
        "invariant_contract": invariant_contract,
        "available_methods": metadata.get("available_methods"),
        "readable_route": metadata.get("readable_route"),
        "create_based": bool(metadata.get("create_based")) or None,
        "readback_route": metadata.get("readback_route"),
        "cleanup_route": metadata.get("cleanup_route"),
        "provability_score": metadata.get("provability_score"),
        "provability_blockers": metadata.get("provability_blockers"),
    }
    return {key: value for key, value in contract.items() if value not in (None, "", [], {})}




def _canonical_coverage_key(*, family: Any, route: Any, method: Any = None) -> str | None:
    """Coarse family+method+route coverage key (dimension-less).

    The exact v3 vulnerability key folds in fine-grained dimensions, so a DAST finding and a
    residue lead on the SAME endpoint hash differently whenever the lead's sparse dimensions can't
    reproduce the finding's enriched ones — which lets already-owned BOLA leads slip onto the hunt
    board and monopolize it. This coarse key deliberately drops dimensions so "same family + method
    + route as an existing finding" is enough to recognise coverage at ranking time. The precise v3
    key still guards dispatch, so this only affects board ordering, never promotion.
    """
    canonical_family = family_proof.canonical_family(family)
    canonical_route = _canonical_vulnerability_route(route)
    if not canonical_family or not canonical_route:
        return None
    canonical_method = str(method or "").strip().upper() or "*"
    return hashlib.sha256(
        f"coverage:v1|{canonical_family}|{canonical_method}|{canonical_route}".encode()
    ).hexdigest()


def _finding_family_route_method(value: Any) -> tuple[dict[str, Any], Any, Any, Any, dict[str, Any], Any, Any]:
    """Extract (finding, family, route, method, dedupe_dimensions, evidence, request) from a finding.

    Shared by the exact vulnerability key and the coarse coverage key so both agree on identity —
    in particular the smart_bola/smart_authz method fallback below, without which a covered BOLA
    finding's method would be unknown and never match a GET residue lead's coverage key.
    """
    finding = row_to_dict(value) if value is not None and not isinstance(value, dict) else dict(value or {})
    evidence = _decode_json_value(finding.get("evidence")) or {}
    family = _research_finding_family(finding)
    route = finding.get("url")
    method = finding.get("method")
    dedupe_dimensions: dict[str, Any] = {}
    if isinstance(evidence, dict):
        dedupe_dimensions = evidence.get("dedupe_dimensions") if isinstance(evidence.get("dedupe_dimensions"), dict) else {}
        route = dedupe_dimensions.get("route") or evidence.get("route") or evidence.get("path") or route
        method = dedupe_dimensions.get("method") or evidence.get("method") or method
        # Backward compatibility for SUSPECTED rows written before route/method were persisted at the
        # top level. Only this finding's cited tool evidence is stored in tool_evidence.
        if not method or not route:
            legacy_operations: list[tuple[str, str]] = []
            for item in evidence.get("tool_evidence") or []:
                if not isinstance(item, dict):
                    continue
                try:
                    payload = json.loads(str(item.get("content") or "{}"))
                except (TypeError, ValueError):
                    continue
                request_view = payload.get("request") if isinstance(payload, dict) else None
                if not isinstance(request_view, dict):
                    continue
                candidate_route = str(request_view.get("path") or "").strip()
                candidate_method = str(request_view.get("method") or "").strip().upper()
                if candidate_route and candidate_method:
                    operation = (candidate_route, candidate_method)
                    if operation not in legacy_operations:
                        legacy_operations.append(operation)
            # Never bind an old multi-request finding to whichever control happened to be cited
            # first. Only an unambiguous legacy operation is safe to auto-verify.
            if len(legacy_operations) == 1:
                route = route or legacy_operations[0][0]
                method = method or legacy_operations[0][1]
        if not method:
            consumer = str(evidence.get("consumer_endpoint") or "").strip()
            consumer_match = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+", consumer, re.IGNORECASE)
            if consumer_match:
                method = consumer_match.group(1)
    request = _decode_json_value(finding.get("request"))
    if not method and isinstance(request, dict):
        method = request.get("method")
    if not method and isinstance(request, str):
        request_match = re.match(r"^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+", request, re.IGNORECASE)
        if request_match:
            method = request_match.group(1)
    if not method:
        title_match = re.search(
            r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b",
            str(finding.get("title") or ""),
            re.IGNORECASE,
        )
        if title_match:
            method = title_match.group(1)
    if not method and str(finding.get("tool") or "").lower() in {"smart_bola", "smart_authz"}:
        # Backward compatibility for findings written before those deterministic GET replays stamped
        # their method into evidence. Write replays have always carried PATCH; the remaining historic
        # cross-principal/unauthenticated smart BOLA findings are GET probes by construction.
        proof_type = str((evidence or {}).get("proof_type") or "").lower()
        if "write" not in proof_type:
            method = "GET"
    return finding, family, route, method, dedupe_dimensions, evidence, request


def _research_hypothesis_route(hypothesis: dict[str, Any]) -> str | None:
    metadata = hypothesis.get("metadata_json") if isinstance(hypothesis.get("metadata_json"), dict) else {}
    metadata_dimensions = metadata.get("dedupe_dimensions") if isinstance(metadata.get("dedupe_dimensions"), dict) else {}
    direct_dimensions = hypothesis.get("dedupe_dimensions") if isinstance(hypothesis.get("dedupe_dimensions"), dict) else {}
    dimensions = {**metadata_dimensions, **direct_dimensions}
    next_action = hypothesis.get("next_test_action") if isinstance(hypothesis.get("next_test_action"), dict) else {}
    parameters = next_action.get("parameters") if isinstance(next_action.get("parameters"), dict) else {}
    return _canonical_vulnerability_route(
        dimensions.get("route")
        or metadata.get("route")
        or parameters.get("route")
        or hypothesis.get("route")
    )
def _select_refuter_automation_step(
    automation_plan: dict[str, Any],
    *,
    step_id: str | None = None,
    preferred_commands: Sequence[str] = ("finding.retest", "ai_gate.replay_probe", "model_intake.trust_preview"),
) -> dict[str, Any]:
    steps = [step for step in (automation_plan.get("steps") or []) if isinstance(step, dict)]
    if step_id:
        for step in steps:
            if str(step.get("id") or "") == step_id:
                return step
        raise HTTPException(status_code=400, detail="Requested refuter automation step was not found")
    for command in preferred_commands:
        for step in steps:
            if str(step.get("command") or "") == command:
                return step
    raise HTTPException(status_code=400, detail="Refuter review has no executable automation step")


def _refuter_finding_automation_plan(finding: dict[str, Any], review_metadata: dict[str, Any]) -> dict[str, Any]:
    existing = review_metadata.get("automation_plan")
    if isinstance(existing, dict) and isinstance(existing.get("steps"), list):
        return existing
    evidence = _decode_json_value(finding.get("evidence")) or {}
    if not isinstance(evidence, dict):
        evidence = {}
    trigger = _finding_refuter_trigger(finding)
    if trigger and isinstance(trigger.get("automation_plan"), dict):
        return trigger["automation_plan"]
    return _refuter_automation_plan_for_finding(
        finding,
        evidence,
        trigger_type="finding",
        reasons=[str(finding.get("trigger_reason") or "manual_refuter_execution")],
    )


