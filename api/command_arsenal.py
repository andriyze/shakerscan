"""Read-only Command Arsenal and tool-status catalog.

This module is intentionally schema/inspection only. It does not execute product
actions or external tools beyond optional version probes for already-integrated
tool binaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
import shutil
import subprocess
from typing import Any


ARSENAL_SCHEMA_VERSION = "2026-07-05.v1"

COMMAND_STATUSES = (
    "contract",
    "read_only",
    "dry_run",
    "gated",
    "proof_backed",
    "experimental",
    "catalog_only",
    "out_of_scope",
)

RISK_TIERS = ("read_only", "passive", "active", "intrusive", "credential", "dangerous")

TOOL_STATUSES = ("catalog_only", "wired", "installed", "runnable", "gated", "waived", "disabled")

CONTRACT_NAMES = (
    "OperationPlan",
    "AgentContextPack",
    "AgentDecisionTrace",
    "ScopeReceipt",
    "ApprovalReceipt",
    "CommandResult",
    "ToolReceipt",
    "CampaignAction",
    "Hypothesis",
    "EvidenceInstance",
)


@dataclass(frozen=True)
class ArsenalCommand:
    name: str
    family: str
    description: str
    status: str
    risk_tier: str
    method: str
    path: str
    scope_fields: tuple[str, ...] = ()
    parameters_schema: dict[str, Any] = field(default_factory=dict)
    required_confirmations: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ()
    evidence_contract: tuple[str, ...] = ()
    redaction_contract: tuple[str, ...] = ()
    timeout_seconds: int = 30


@dataclass(frozen=True)
class ToolAdapterSpec:
    tool_name: str
    family: str
    description: str
    risk_tier: str
    status: str
    binaries: tuple[str, ...] = ()
    version_args: tuple[str, ...] = ("--version",)
    common_paths: tuple[str, ...] = ()
    evidence_parser: str | None = None
    proof_contract: str | None = None
    retest_contract: str | None = None
    redaction_rules: tuple[str, ...] = ("authorization headers", "cookies", "tokens", "private keys")
    timeout_seconds: int = 5


@dataclass(frozen=True)
class LocalAgentSpec:
    agent: str
    display_name: str
    binaries: tuple[str, ...]
    version_args: tuple[str, ...]
    auth_artifact_paths: tuple[str, ...]
    supports_headless_prompt: bool
    supports_read_only_mode: bool
    supports_json_mode: bool
    supports_timeout: bool
    supports_workdir_isolation: bool
    supports_network_disable: bool
    max_prompt_bytes: int
    max_output_bytes: int
    risk_notes: tuple[str, ...]


COMMANDS: tuple[ArsenalCommand, ...] = (
    ArsenalCommand(
        name="target.list",
        family="inventory",
        description="List configured targets.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/targets",
        evidence_contract=("target_rows",),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="target.get",
        family="inventory",
        description="Get one target and recent scan metadata.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/targets/{target_id}",
        scope_fields=("target_id",),
        parameters_schema={"target_id": {"type": "string", "format": "uuid"}},
        evidence_contract=("target_record",),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="target.principals",
        family="inventory",
        description="Read role/tenant principals configured for one web/API target.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/targets/{target_id}/principals",
        scope_fields=("target_id",),
        parameters_schema={
            "target_id": {"type": "string", "format": "uuid"},
            "include_inactive": {"type": "boolean"},
        },
        evidence_contract=("target_principal_rows", "role_counts", "tenant_counts"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="target.principal_matrix",
        family="inventory",
        description="Read endpoint x principal/role expectations for authorization planning without queueing tests.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/targets/{target_id}/principal-matrix",
        scope_fields=("target_id",),
        parameters_schema={
            "target_id": {"type": "string", "format": "uuid"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
        },
        evidence_contract=("target_principal_rows", "endpoint_expectation_rows", "expected_access"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="target.principal_matrix.record",
        family="inventory",
        description="Record a non-executing endpoint principal expectation for future authz campaigns.",
        status="dry_run",
        risk_tier="read_only",
        method="POST",
        path="/targets/{target_id}/principal-matrix",
        scope_fields=("target_id",),
        parameters_schema={
            "target_id": {"type": "string", "format": "uuid"},
            "endpoint_id": {"type": "string", "format": "uuid"},
            "method": {"type": "string"},
            "path": {"type": "string"},
            "principal_id": {"type": "string", "format": "uuid"},
            "principal_role": {"type": "string"},
            "tenant_id": {"type": "string"},
            "expected_access": {"type": "string", "enum": ["allow", "deny", "requires_role", "unknown"]},
        },
        evidence_contract=("endpoint_expectation_row", "principal_ref", "expected_access"),
        redaction_contract=("metadata_json",),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="exposure.graph.get",
        family="inventory",
        description="Read the exposure graph built from existing targets, scans, AI targets, model artifacts, and findings.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/exposure/graph",
        evidence_contract=("graph_nodes", "graph_edges"),
        timeout_seconds=30,
    ),
    ArsenalCommand(
        name="asm.gaps",
        family="asm",
        description="Explain remaining Continuous ASM gaps and recommended campaigns for one target.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/targets/{target_id}/asm/gaps",
        scope_fields=("target_id",),
        parameters_schema={"target_id": {"type": "string", "format": "uuid"}},
        evidence_contract=("coverage_gaps", "scheduler_state", "recommended_campaigns"),
        timeout_seconds=20,
    ),
    ArsenalCommand(
        name="asm.activity",
        family="asm",
        description="Read recent Continuous ASM recon/test activity and the target campaign timeline.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/targets/{target_id}/asm/activity",
        scope_fields=("target_id",),
        parameters_schema={"target_id": {"type": "string", "format": "uuid"}},
        evidence_contract=("activity_rows", "scheduler_state", "timeline"),
        timeout_seconds=20,
    ),
    ArsenalCommand(
        name="asm.improve",
        family="asm",
        description="Queue or preview the next Continuous ASM action for one target.",
        status="gated",
        risk_tier="active",
        method="POST",
        path="/targets/{target_id}/asm/improve",
        scope_fields=("target_id",),
        parameters_schema={
            "target_id": {"type": "string", "format": "uuid"},
            "batch_size": {"type": "integer", "minimum": 1, "maximum": 1000},
            "check_family": {"type": "string", "enum": ["all", "sqli", "xss", "auth", "bola"]},
            "exploit_depth": {"type": "boolean"},
            "approval_receipt_id": {"type": "string", "format": "uuid"},
        },
        required_confirmations=("confirm_authorized",),
        evidence_contract=("scan_id", "scheduler_state", "attempt_ledger"),
        redaction_contract=("auth_header", "cookies", "credential.secret"),
        timeout_seconds=30,
    ),
    ArsenalCommand(
        name="scan.result",
        family="scans",
        description="Read scan status and stored result JSON.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/scans/{scan_id}/result",
        scope_fields=("scan_id",),
        parameters_schema={"scan_id": {"type": "string", "format": "uuid"}},
        evidence_contract=("scan_result", "quality_metrics", "proof_state"),
        timeout_seconds=20,
    ),
    ArsenalCommand(
        name="scan.focused_family",
        family="scans",
        description="Submit a focused DAST family campaign through existing scan submission gates.",
        status="gated",
        risk_tier="active",
        method="POST",
        path="/scans",
        scope_fields=("target", "target_id", "root_domain"),
        parameters_schema={
            "target": {"type": "string"},
            "target_id": {"type": "string", "format": "uuid"},
            "check_family": {"type": "string", "enum": ["sqli", "xss", "auth", "bola"]},
            "approval_receipt_id": {"type": "string", "format": "uuid"},
        },
        required_confirmations=("confirm_authorized",),
        evidence_contract=("scan_id", "check_family", "report_invariants"),
        redaction_contract=("auth_header", "cookies", "credential.secret"),
        timeout_seconds=30,
    ),
    ArsenalCommand(
        name="finding.list",
        family="findings",
        description="List findings with filters and proof-state fields.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/findings",
        parameters_schema={"status": {"type": "string"}, "severity": {"type": "string"}},
        evidence_contract=("finding_rows", "proof_state"),
        timeout_seconds=20,
    ),
    ArsenalCommand(
        name="finding.get",
        family="findings",
        description="Read one finding by id or fingerprint.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/findings/{finding_id}",
        scope_fields=("finding_id",),
        parameters_schema={"finding_id": {"type": "string"}},
        evidence_contract=("finding_record", "proof_state", "retest_hints"),
        timeout_seconds=20,
    ),
    ArsenalCommand(
        name="finding.retest",
        family="findings",
        description="Queue deterministic or AI-assisted retest for one finding through existing retest gates.",
        status="gated",
        risk_tier="active",
        method="POST",
        path="/findings/{finding_id}/retest",
        scope_fields=("finding_id",),
        parameters_schema={
            "finding_id": {"type": "string"},
            "mode": {"type": "string", "enum": ["deterministic", "ai"]},
            "approval_receipt_id": {"type": "string", "format": "uuid"},
        },
        required_confirmations=("confirm_authorized",),
        evidence_contract=("retest_id", "proof", "artifacts"),
        redaction_contract=("auth_header", "cookies", "request", "response"),
        timeout_seconds=30,
    ),
    ArsenalCommand(
        name="ai_target.list",
        family="ai_gate",
        description="List configured AI Gate targets and control metadata.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/ai/targets",
        evidence_contract=("ai_target_rows", "control_metadata"),
        timeout_seconds=20,
    ),
    ArsenalCommand(
        name="ai_gate.replay_probe",
        family="ai_gate",
        description="Queue focused AI Gate replay using original target/profile/probe context.",
        status="gated",
        risk_tier="active",
        method="POST",
        path="/ai/scans/{scan_id}/replay",
        scope_fields=("scan_id",),
        parameters_schema={
            "scan_id": {"type": "string", "format": "uuid"},
            "mode": {"type": "string", "enum": ["skipped", "errors", "family", "transcript", "all"]},
            "confirm_production": {"type": "boolean"},
            "approval_receipt_id": {"type": "string", "format": "uuid"},
        },
        required_confirmations=("confirm_authorized", "confirm_production_when_applicable"),
        evidence_contract=("scan_id", "replay_plan", "production_gate"),
        redaction_contract=("transcript", "credential.secret"),
        timeout_seconds=30,
    ),
    ArsenalCommand(
        name="model_intake.trust_preview",
        family="model_intake",
        description="Preview Model Intake trust mode and policy readiness in the UI before queueing a scan.",
        status="read_only",
        risk_tier="read_only",
        method="CLIENT",
        path="/settings/model-intake",
        parameters_schema={"policy_profile": {"type": "string"}, "trust_mode": {"type": "string"}},
        evidence_contract=("trust_preview", "policy_requirements"),
        redaction_contract=("signature_public_key", "trusted_key_material"),
        timeout_seconds=20,
    ),
    ArsenalCommand(
        name="model_intake.scan",
        family="model_intake",
        description="Queue a Model Intake artifact check through existing policy and artifact-fetch gates.",
        status="gated",
        risk_tier="passive",
        method="POST",
        path="/model-intake/scan",
        scope_fields=("artifact_url", "metadata_url", "model_card_url"),
        parameters_schema={
            "artifact_url": {"type": "string"},
            "trust_anchor_ids": {"type": "array"},
            "approval_receipt_id": {"type": "string", "format": "uuid"},
        },
        required_confirmations=("confirm_authorized",),
        evidence_contract=("scan_id", "artifact_digest", "signature_status"),
        redaction_contract=("signature_public_key", "trusted_key_material"),
        timeout_seconds=30,
    ),
    ArsenalCommand(
        name="evidence.get",
        family="evidence",
        description="Read redacted durable evidence objects for a finding.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/findings/{finding_id}/evidence",
        scope_fields=("finding_id",),
        parameters_schema={"finding_id": {"type": "string"}},
        evidence_contract=("evidence_objects", "content_sha256", "storage_uri"),
        timeout_seconds=20,
    ),
    ArsenalCommand(
        name="evidence.export_manifest",
        family="evidence",
        description="Read a content-free evidence export manifest with hashes, storage URIs, retention classes, and integrity status.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/evidence/export-manifest",
        scope_fields=("finding_id", "scan_id", "retention_class"),
        parameters_schema={
            "finding_id": {"type": "string", "format": "uuid"},
            "scan_id": {"type": "string", "format": "uuid"},
            "retention_class": {"type": "string", "enum": ["standard", "short", "audit", "legal_hold", "sensitive"]},
            "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
        },
        evidence_contract=("manifest_hash", "content_sha256", "storage_uri", "retention_class", "storage_integrity"),
        timeout_seconds=20,
    ),
    ArsenalCommand(
        name="evidence.retention_sweep",
        family="evidence",
        description="Preview or execute bounded evidence-object retention cleanup; dry-run by default and legal_hold is never selected.",
        status="dry_run",
        risk_tier="read_only",
        method="POST",
        path="/evidence/retention/sweep",
        parameters_schema={
            "dry_run": {"type": "boolean", "default": True},
            "older_than_days": {"type": "integer", "minimum": 0, "maximum": 3650},
            "retention_class": {"type": "string", "enum": ["standard", "short", "audit", "legal_hold", "sensitive"]},
            "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
            "delete_local_files": {"type": "boolean", "default": True},
        },
        evidence_contract=("retention_candidates", "deleted_count", "local_file_results"),
        timeout_seconds=30,
    ),
    ArsenalCommand(
        name="evidence_instance.list",
        family="evidence",
        description="Read concrete evidence instances split from canonical findings.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/evidence/instances",
        scope_fields=("finding_id", "tool_receipt_id"),
        parameters_schema={
            "finding_id": {"type": "string", "format": "uuid"},
            "tool_receipt_id": {"type": "string", "format": "uuid"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 200},
        },
        evidence_contract=("evidence_instance_rows", "proof_observation", "tool_receipt_id"),
        timeout_seconds=20,
    ),
    ArsenalCommand(
        name="evidence_instance.record",
        family="evidence",
        description="Record a concrete evidence instance without updating finding proof state.",
        status="dry_run",
        risk_tier="read_only",
        method="POST",
        path="/evidence/instances",
        scope_fields=("finding_id", "evidence_object_id", "tool_receipt_id"),
        parameters_schema={
            "finding_id": {"type": "string", "format": "uuid"},
            "evidence_object_id": {"type": "string", "format": "uuid"},
            "tool_receipt_id": {"type": "string", "format": "uuid"},
            "proof_state": {"type": "string", "enum": ["verified", "suspected", "unverified", "refuted", "inconclusive"]},
            "retention_policy": {"type": "string", "enum": ["standard", "short", "audit", "legal_hold", "sensitive"]},
        },
        evidence_contract=("evidence_instance_row", "content_hash", "redaction_profile"),
        redaction_contract=("concrete_url", "payload_variant", "proof_observation", "metadata_json"),
        timeout_seconds=20,
    ),
    ArsenalCommand(
        name="tool_receipt.list",
        family="evidence",
        description="Read durable receipts for existing tools/executors.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/arsenal/tool-receipts",
        scope_fields=("tool_name", "status"),
        parameters_schema={
            "tool_name": {"type": "string"},
            "status": {"type": "string", "enum": ["success", "failed", "timeout", "skipped", "waived", "parser_error", "recorded"]},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
        },
        evidence_contract=("tool_receipt_rows", "parser_status", "command_hash"),
        timeout_seconds=20,
    ),
    ArsenalCommand(
        name="tool_receipt.record",
        family="evidence",
        description="Record an existing tool/executor receipt without running tools or creating findings.",
        status="dry_run",
        risk_tier="read_only",
        method="POST",
        path="/arsenal/tool-receipts",
        scope_fields=("scope_receipt_id", "approval_receipt_id", "policy_profile_id"),
        parameters_schema={
            "tool_name": {"type": "string"},
            "adapter_version": {"type": "string"},
            "redacted_argv": {"type": "array"},
            "status": {"type": "string", "enum": ["success", "failed", "timeout", "skipped", "waived", "parser_error", "recorded"]},
            "parser_status": {"type": "string", "enum": ["not_run", "parsed", "partial", "failed", "not_applicable"]},
        },
        evidence_contract=("tool_receipt_row", "command_hash", "parser_status", "artifact_refs"),
        redaction_contract=("redacted_argv", "target_scope", "metadata_json", "redaction_summary"),
        timeout_seconds=20,
    ),
    ArsenalCommand(
        name="deployment.decision",
        family="governance",
        description="Read deployment gate decision for a scan and policy profile.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/scans/{scan_id}/deployment-decision",
        scope_fields=("scan_id",),
        parameters_schema={"scan_id": {"type": "string", "format": "uuid"}, "policy_profile_id": {"type": "string"}},
        evidence_contract=("decision", "blocking_findings", "exceptions"),
        timeout_seconds=20,
    ),
    ArsenalCommand(
        name="tool.status",
        family="tool_status",
        description="Read installed/runnable/waived/catalog status for integrated adapters.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/arsenal/tools",
        evidence_contract=("tool_status_rows", "release_gate"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="local_agent.list",
        family="planner",
        description="Read local planner capability records without reading auth artifacts or executing prompts.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/agents/local",
        parameters_schema={"probe_versions": {"type": "boolean"}},
        evidence_contract=("local_agent_capability_rows",),
        redaction_contract=("auth_artifact_contents", "environment_api_keys"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="local_agent.plan_dry_run",
        family="planner",
        description="Persist a local-agent-labeled dry-run OperationPlan from a saved AgentContextPack without spawning a local agent.",
        status="dry_run",
        risk_tier="read_only",
        method="POST",
        path="/agents/local/plan",
        scope_fields=("context_pack_id",),
        parameters_schema={
            "agent": {"type": "string", "enum": ["codex", "claude-code", "opencode", "hermes"]},
            "context_pack_id": {"type": "string", "format": "uuid"},
            "objective": {"type": "string"},
        },
        evidence_contract=("operation_plan", "context_pack", "local_agent_capability"),
        redaction_contract=("context_pack", "environment_api_keys", "auth_artifact_contents"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="local_agent.test",
        family="planner",
        description="Run a bounded harmless local-agent capability ping without sending prompts or enabling planner execution.",
        status="dry_run",
        risk_tier="read_only",
        method="POST",
        path="/agents/local/test",
        parameters_schema={
            "agent": {"type": "string", "enum": ["codex", "claude-code", "opencode", "hermes"]},
            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 10},
            "max_output_bytes": {"type": "integer", "minimum": 128, "maximum": 8000},
        },
        evidence_contract=("local_agent_capability", "ping_result", "environment_redaction"),
        redaction_contract=("environment_api_keys", "auth_artifact_contents", "prompts"),
        timeout_seconds=10,
    ),
    ArsenalCommand(
        name="scope.preview",
        family="governance",
        description="Validate and persist a fail-closed scope receipt preview without executing work.",
        status="dry_run",
        risk_tier="read_only",
        method="POST",
        path="/arsenal/scope/preview",
        parameters_schema={
            "url": {"type": "string"},
            "allowed_hosts": {"type": "array", "items": {"type": "string"}},
            "allowed_root_domains": {"type": "array", "items": {"type": "string"}},
            "environment": {"type": "string"},
            "redirect_urls": {"type": "array", "items": {"type": "string"}},
        },
        evidence_contract=("scope_receipt", "blocked_by", "checks"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="operation_plan.list",
        family="governance",
        description="Read recent dry-run OperationPlan records.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/arsenal/plans",
        parameters_schema={"limit": {"type": "integer", "minimum": 1, "maximum": 100}},
        evidence_contract=("operation_plan_rows", "validation_errors", "validation_warnings"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="operation_plan.preview",
        family="governance",
        description="Validate and persist a dry-run OperationPlan without executing any action.",
        status="dry_run",
        risk_tier="read_only",
        method="POST",
        path="/arsenal/plans",
        scope_fields=("target_scope", "scope_receipt_id", "approval_receipt_id"),
        parameters_schema={
            "objective": {"type": "string"},
            "context_hash": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
            "risk_tier": {"type": "string", "enum": ["read_only", "passive", "active", "intrusive", "credential", "dangerous"]},
            "actions": {"type": "array"},
            "scope_receipt_id": {"type": "string"},
            "approval_receipt_id": {"type": "string", "format": "uuid"},
        },
        evidence_contract=("operation_plan", "validation_errors", "validation_warnings"),
        redaction_contract=("parameters", "target_scope", "planner"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="command_result.list",
        family="governance",
        description="Read recent Command Arsenal result/audit records for queued, partial, or blocked product actions.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/arsenal/command-results",
        parameters_schema={"limit": {"type": "integer", "minimum": 1, "maximum": 100}},
        evidence_contract=("command_result_rows", "operation_ids", "receipt_refs", "blocked_reasons"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="campaign_action.list",
        family="governance",
        description="Read recent campaign/action execution records derived from product actions and command results.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/arsenal/campaign-actions",
        scope_fields=("target_id",),
        parameters_schema={
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            "target_id": {"type": "string", "format": "uuid"},
        },
        evidence_contract=("campaign_action_rows", "command_result_refs", "receipt_refs", "blocked_reasons"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="hypothesis.list",
        family="governance",
        description="Read deduped claimable/refutable hypotheses that have not become findings.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/arsenal/hypotheses",
        scope_fields=("target_id",),
        parameters_schema={
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            "target_id": {"type": "string", "format": "uuid"},
            "status": {"type": "string", "enum": ["open", "claimed", "testing", "supported", "refuted", "promoted", "dead"]},
        },
        evidence_contract=("hypothesis_rows", "claim_state", "proof_refs"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="hypothesis.situation_report",
        family="governance",
        description="Read a bounded hypothesis situation report with hot unclaimed leads, owned claims, blockers, terminal leads, and missing preconditions.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/arsenal/hypotheses/situation-report",
        scope_fields=("target_id", "requester"),
        parameters_schema={
            "limit": {"type": "integer", "minimum": 1, "maximum": 25},
            "target_id": {"type": "string", "format": "uuid"},
            "requester": {"type": "string"},
        },
        evidence_contract=(
            "hottest_unclaimed",
            "requester_claims",
            "avoid_resurfacing",
            "live_blockers",
            "missing_preconditions",
        ),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="hypothesis.record",
        family="governance",
        description="Record or endorse a deduped hypothesis without creating a finding or queueing work.",
        status="dry_run",
        risk_tier="read_only",
        method="POST",
        path="/arsenal/hypotheses",
        scope_fields=("target_id", "campaign_id", "campaign_action_id"),
        parameters_schema={
            "source": {"type": "string", "enum": ["app_graph", "source_ingest", "ai_planner", "scanner_signal", "ai_gate", "model_intake", "manual"]},
            "family": {"type": "string"},
            "dedupe_key": {"type": "string"},
            "dedupe_dimensions": {
                "type": "object",
                "properties": {
                    "method": {"type": "string"},
                    "route": {"type": "string"},
                    "object_key": {"type": "string"},
                    "principal_actor": {"type": "string"},
                    "principal_other": {"type": "string"},
                    "tenant": {"type": "string"},
                    "parameter_path": {"type": "string"},
                    "body_path": {"type": "string"},
                    "proof_surface": {"type": "string"},
                },
            },
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        },
        evidence_contract=("hypothesis_row", "endorsement", "dedupe_key"),
        redaction_contract=("description", "next_test_action", "metadata_json"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="hypothesis.claim",
        family="governance",
        description="Claim a hypothesis using compare-and-set leasing; does not queue scanner work.",
        status="dry_run",
        risk_tier="read_only",
        method="POST",
        path="/arsenal/hypotheses/{hypothesis_id}/claim",
        scope_fields=("hypothesis_id",),
        parameters_schema={
            "hypothesis_id": {"type": "string", "format": "uuid"},
            "owner": {"type": "string"},
            "expected_version": {"type": "integer", "minimum": 1},
            "lease_seconds": {"type": "integer", "minimum": 60, "maximum": 86400},
        },
        evidence_contract=("hypothesis_row", "claim_state", "version"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="hypothesis.signal",
        family="governance",
        description="Append an endorsement or refutation signal to a hypothesis without changing findings or gates.",
        status="dry_run",
        risk_tier="read_only",
        method="POST",
        path="/arsenal/hypotheses/{hypothesis_id}/signals",
        scope_fields=("hypothesis_id",),
        parameters_schema={
            "hypothesis_id": {"type": "string", "format": "uuid"},
            "signal_type": {"type": "string", "enum": ["endorsement", "refutation"]},
            "source": {"type": "string"},
            "status_hint": {"type": "string", "enum": ["support", "question", "weaken", "refute"]},
        },
        evidence_contract=("hypothesis_row", "endorsement_or_refutation", "version"),
        redaction_contract=("reason", "metadata_json"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="hypothesis.generate_from_graph",
        family="governance",
        description="Generate app-graph authorization hypotheses from persisted producer/object/consumer facts without queueing tests.",
        status="dry_run",
        risk_tier="read_only",
        method="POST",
        path="/targets/{target_id}/graph/hypotheses",
        scope_fields=("target_id",),
        parameters_schema={
            "target_id": {"type": "string", "format": "uuid"},
            "created_by": {"type": "string"},
        },
        evidence_contract=("hypothesis_rows", "app_graph_edges", "dedupe_key"),
        timeout_seconds=20,
    ),
    ArsenalCommand(
        name="refuter_review.list",
        family="governance",
        description="Read durable refuter signals and proof-backed verdict records without changing findings.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/arsenal/refuter-reviews",
        scope_fields=("subject_type", "subject_id"),
        parameters_schema={
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            "subject_type": {"type": "string", "enum": ["finding", "hypothesis", "ai_gate_scan", "model_intake", "benchmark", "planner", "deployment_gate", "parser_output", "manual"]},
            "subject_id": {"type": "string"},
        },
        evidence_contract=("refuter_review_rows", "refuter_signal", "refuter_verdict", "verdict_basis"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="refuter_review.summary",
        family="governance",
        description="Read a bounded worklist of weak/high-impact findings that should be challenged.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/arsenal/refuter-reviews/summary",
        parameters_schema={
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            "finding_window": {"type": "integer", "minimum": 1, "maximum": 1000},
        },
        evidence_contract=("trigger_counts", "refuter_candidates", "recommended_review"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="refuter_review.record",
        family="governance",
        description="Record a refuter signal or evidence-backed verdict without directly changing findings, proof state, or gates.",
        status="dry_run",
        risk_tier="read_only",
        method="POST",
        path="/arsenal/refuter-reviews",
        scope_fields=("target_id", "finding_id", "hypothesis_id", "campaign_id"),
        parameters_schema={
            "subject_type": {"type": "string", "enum": ["finding", "hypothesis", "ai_gate_scan", "model_intake", "benchmark", "planner", "deployment_gate", "parser_output", "manual"]},
            "subject_id": {"type": "string"},
            "refuter_signal": {"type": "string", "enum": ["support", "question", "weaken", "refute"]},
            "refuter_verdict": {"type": "string", "enum": ["supported", "weakened", "refuted", "inconclusive"]},
            "verdict_basis": {"type": "string", "enum": ["signal_only", "deterministic_replay", "cryptographic", "parser_protocol", "human_approved_review"]},
        },
        evidence_contract=("refuter_review_row", "counterevidence", "evidence_refs", "tool_receipt_refs"),
        redaction_contract=("trigger_reason", "notes", "counterevidence", "metadata_json"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="mission.timeline",
        family="governance",
        description="Read the cross-product mission timeline: command results, campaign actions, recent scans, and upcoming schedules.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/timeline",
        scope_fields=("target_id",),
        parameters_schema={
            "limit": {"type": "integer", "minimum": 1, "maximum": 200},
            "target_id": {"type": "string", "format": "uuid"},
        },
        evidence_contract=("timeline_events", "campaign_action_rows", "upcoming", "statuses"),
        timeout_seconds=20,
    ),
    ArsenalCommand(
        name="agent_context_pack.list",
        family="governance",
        description="Read recent bounded AgentContextPack records.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/arsenal/context-packs",
        parameters_schema={"limit": {"type": "integer", "minimum": 1, "maximum": 100}},
        evidence_contract=("context_pack_rows", "validation_errors", "validation_warnings"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="agent_context_pack.record",
        family="governance",
        description="Validate and persist a bounded redacted AgentContextPack without executing work.",
        status="dry_run",
        risk_tier="read_only",
        method="POST",
        path="/arsenal/context-packs",
        parameters_schema={
            "context_hash": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
            "target_summary": {"type": "object"},
            "current_surface": {"type": "object"},
            "current_gaps": {"type": "array"},
            "allowed_commands": {"type": "array", "items": {"type": "string"}},
        },
        evidence_contract=("context_pack", "validation_errors", "validation_warnings"),
        redaction_contract=("target_summary", "current_surface", "findings_summary", "known_preconditions"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="agent_context_pack.generate_from_target",
        family="governance",
        description="Generate and persist a bounded AgentContextPack from stored target facts without executing work.",
        status="dry_run",
        risk_tier="read_only",
        method="POST",
        path="/arsenal/context-packs/from-target",
        scope_fields=("target_id",),
        parameters_schema={
            "target_id": {"type": "string", "format": "uuid"},
            "include_findings": {"type": "boolean"},
            "include_endpoints": {"type": "boolean"},
            "include_gaps": {"type": "boolean"},
            "finding_limit": {"type": "integer", "minimum": 0, "maximum": 25},
            "endpoint_limit": {"type": "integer", "minimum": 0, "maximum": 50},
        },
        evidence_contract=("context_pack", "target_summary", "current_surface", "current_gaps"),
        redaction_contract=("target.metadata_json", "findings_summary", "known_preconditions"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="agent_decision_trace.list",
        family="governance",
        description="Read recent AgentDecisionTrace audit records.",
        status="read_only",
        risk_tier="read_only",
        method="GET",
        path="/arsenal/decision-traces",
        parameters_schema={"limit": {"type": "integer", "minimum": 1, "maximum": 100}},
        evidence_contract=("decision_trace_rows", "validation_errors", "validation_warnings"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="agent_decision_trace.record",
        family="governance",
        description="Validate and persist a dry-run AgentDecisionTrace without executing actions.",
        status="dry_run",
        risk_tier="read_only",
        method="POST",
        path="/arsenal/decision-traces",
        parameters_schema={
            "context_hash": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
            "context_pack_id": {"type": "string", "format": "uuid"},
            "operation_plan_id": {"type": "string", "format": "uuid"},
            "planner": {"type": "object"},
            "steps": {"type": "array"},
        },
        evidence_contract=("decision_trace", "validation_errors", "validation_warnings"),
        redaction_contract=("planner", "steps", "final_rationale"),
        timeout_seconds=15,
    ),
    ArsenalCommand(
        name="approval.record",
        family="governance",
        description="Persist an approval or denial receipt for an existing scope receipt without executing work.",
        status="gated",
        risk_tier="credential",
        method="POST",
        path="/arsenal/approvals",
        scope_fields=("scope_receipt_id",),
        parameters_schema={
            "scope_receipt_id": {"type": "string"},
            "risk_tier": {"type": "string", "enum": ["active", "intrusive", "credential", "dangerous"]},
            "confirmations": {"type": "array", "items": {"type": "string"}},
            "approved_by": {"type": "string"},
            "denial_reason": {"type": "string"},
        },
        required_confirmations=("confirm_authorized",),
        evidence_contract=("approval_receipt", "scope_receipt"),
        timeout_seconds=15,
    ),
)


TOOL_ADAPTERS: tuple[ToolAdapterSpec, ...] = (
    ToolAdapterSpec("httpx", "http_probe", "ProjectDiscovery httpx HTTP probing.", "passive", "wired", ("httpx",), ("-version",), ("/opt/tools/httpx",), "httpx-json-v1", "http-observation"),
    ToolAdapterSpec("katana", "crawl", "ProjectDiscovery katana crawler.", "passive", "wired", ("katana",), ("-version",), ("/opt/tools/katana",), "katana-jsonl-v1", "crawl-observation"),
    ToolAdapterSpec("nuclei", "template_vuln_scan", "Nuclei template scanner.", "active", "wired", ("nuclei",), ("-version",), ("/opt/tools/nuclei",), "nuclei-jsonl-v1", "template-match-with-request-response", "rerun-template-or-family-on-same-surface", timeout_seconds=10),
    ToolAdapterSpec("subfinder", "subdomain_discovery", "ProjectDiscovery subfinder passive subdomain discovery.", "passive", "wired", ("subfinder",), ("-version",), ("/opt/tools/subfinder",), "subfinder-lines-v1", "passive-discovery"),
    ToolAdapterSpec("ffuf", "content_discovery", "ffuf content discovery.", "active", "wired", ("ffuf",), ("-V",), ("/opt/tools/ffuf",), "ffuf-json-v1", "content-discovery-observation"),
    ToolAdapterSpec("dalfox", "xss", "Dalfox XSS scanner.", "active", "wired", ("dalfox",), ("version",), ("/opt/tools/dalfox",), "dalfox-json-v1", "xss-reflection-or-browser-proof"),
    ToolAdapterSpec("sqlmap", "sqli", "sqlmap SQL injection verifier.", "active", "gated", ("sqlmap", "sqlmap.py"), ("--version",), ("/opt/tools/sqlmap",), "sqlmap-output-v1", "sqli-dbms-or-error-proof", "rerun-request-with-sqli-proof", timeout_seconds=10),
    ToolAdapterSpec("nmap", "port_scan", "nmap network service discovery.", "active", "gated", ("nmap",), ("--version",), ("/opt/tools/nmap",), "nmap-xml-v1", "open-port-observation"),
    ToolAdapterSpec("sslyze", "tls", "SSLyze TLS scanner.", "passive", "wired", ("sslyze",), ("--version",), ("/opt/tools/sslyze",), "sslyze-json-v1", "tls-protocol-observation"),
    ToolAdapterSpec("testssl.sh", "tls", "testssl.sh TLS scanner.", "passive", "wired", ("testssl.sh",), ("--version",), ("/opt/testssl.sh/testssl.sh",), "testssl-json-v1", "tls-protocol-observation", None, timeout_seconds=10),
    ToolAdapterSpec("playwright", "browser_proof", "Playwright browser proof execution.", "active", "wired", ("playwright",), ("--version",), (), "playwright-proof-v1", "browser-observation"),
    ToolAdapterSpec("ai_gate_probe_executor", "ai_red_team", "Internal AI Gate probe runner.", "active", "runnable", (), (), (), "ai-gate-transcript-v1", "deterministic-or-judge-evidence", "rerun-probe"),
    ToolAdapterSpec("model_intake_signature_verifier", "model_trust", "Internal cryptographic signature verifier.", "passive", "runnable", (), (), (), "model-intake-summary-v1", "cryptographic-signature-verification"),
)


LOCAL_AGENT_SPECS: tuple[LocalAgentSpec, ...] = (
    LocalAgentSpec(
        agent="codex",
        display_name="Codex",
        binaries=("codex",),
        version_args=("--version",),
        auth_artifact_paths=("~/.codex/auth.json", "~/.codex/config.toml"),
        supports_headless_prompt=True,
        supports_read_only_mode=False,
        supports_json_mode=False,
        supports_timeout=True,
        supports_workdir_isolation=True,
        supports_network_disable=False,
        max_prompt_bytes=120_000,
        max_output_bytes=32_000,
        risk_notes=(
            "capability detection only; planner execution is not enabled",
            "auth artifacts are checked for existence only and never read",
            "no API-key environment variables may be forwarded to future planner processes",
        ),
    ),
    LocalAgentSpec(
        agent="claude-code",
        display_name="Claude Code",
        binaries=("claude", "claude-code"),
        version_args=("--version",),
        auth_artifact_paths=("~/.claude.json", "~/.claude", "~/.config/claude"),
        supports_headless_prompt=True,
        supports_read_only_mode=False,
        supports_json_mode=False,
        supports_timeout=True,
        supports_workdir_isolation=True,
        supports_network_disable=False,
        max_prompt_bytes=120_000,
        max_output_bytes=32_000,
        risk_notes=(
            "capability detection only; planner execution is not enabled",
            "auth artifacts are checked for existence only and never read",
            "json output must be post-validated because native JSON mode is not assumed",
        ),
    ),
    LocalAgentSpec(
        agent="opencode",
        display_name="OpenCode",
        binaries=("opencode",),
        version_args=("--version",),
        auth_artifact_paths=("~/.config/opencode", "~/.opencode"),
        supports_headless_prompt=True,
        supports_read_only_mode=False,
        supports_json_mode=False,
        supports_timeout=True,
        supports_workdir_isolation=True,
        supports_network_disable=False,
        max_prompt_bytes=120_000,
        max_output_bytes=32_000,
        risk_notes=(
            "capability detection only; planner execution is not enabled",
            "auth artifacts are checked for existence only and never read",
        ),
    ),
    LocalAgentSpec(
        agent="hermes",
        display_name="Hermes",
        binaries=("hermes",),
        version_args=("--version",),
        auth_artifact_paths=("~/.config/hermes", "~/.hermes"),
        supports_headless_prompt=False,
        supports_read_only_mode=False,
        supports_json_mode=False,
        supports_timeout=True,
        supports_workdir_isolation=True,
        supports_network_disable=False,
        max_prompt_bytes=64_000,
        max_output_bytes=16_000,
        risk_notes=(
            "catalog entry only unless a binary is present",
            "planner execution is not enabled",
        ),
    ),
)


def _command_to_dict(command: ArsenalCommand) -> dict[str, Any]:
    return {
        "name": command.name,
        "family": command.family,
        "description": command.description,
        "status": command.status,
        "risk_tier": command.risk_tier,
        "method": command.method,
        "path": command.path,
        "scope_fields": list(command.scope_fields),
        "parameters_schema": command.parameters_schema,
        "required_confirmations": list(command.required_confirmations),
        "required_capabilities": list(command.required_capabilities),
        "evidence_contract": list(command.evidence_contract),
        "redaction_contract": list(command.redaction_contract),
        "timeout_seconds": command.timeout_seconds,
    }


def describe_commands() -> dict[str, Any]:
    """Return the read-only command schema catalog."""
    return {
        "schema_version": ARSENAL_SCHEMA_VERSION,
        "maturity": "read_only",
        "execution_enabled": False,
        "status_labels": list(COMMAND_STATUSES),
        "risk_tiers": list(RISK_TIERS),
        "commands": [_command_to_dict(command) for command in COMMANDS],
        "result_schema": {
            "operation_id": "uuid",
            "command": "string",
            "status": "planned|blocked|approved|queued|running|completed|failed|degraded",
            "dry_run": "boolean",
            "scope_receipt_id": "uuid|null",
            "approval_id": "uuid|null",
            "campaign_id": "uuid|null",
            "scan_id": "uuid|null",
            "finding_ids": [],
            "hypothesis_ids": [],
            "evidence_object_ids": [],
            "tool_receipt_ids": [],
            "blocked_by": [],
            "next_action": "string|null",
            "operator_message": "string",
        },
    }


def describe_contracts() -> dict[str, Any]:
    """Return read-only mission/receipt contracts used by planners and operators."""
    secret_policy = {
        "default": "redacted_refs_only",
        "never_inline": [
            "api_keys",
            "authorization_headers",
            "bearer_tokens",
            "cookies",
            "private_keys",
            "raw_transcripts",
            "raw_request_bodies",
            "raw_response_bodies",
            "signing_key_material",
        ],
        "allowed_refs": [
            "target_id",
            "scan_id",
            "finding_id",
            "evidence_object_id",
            "evidence_instance_id",
            "tool_receipt_id",
            "scope_receipt_id",
            "approval_receipt_id",
        ],
    }

    contracts: dict[str, Any] = {
        "OperationPlan": {
            "status": "contract",
            "description": "Dry-run mission plan shared by UI, REST, scheduler, AI Ops Router, local planners, and future MCP.",
            "required": [
                "objective",
                "planner",
                "context_hash",
                "target_scope",
                "risk_tier",
                "actions",
                "stop_conditions",
                "success_criteria",
            ],
            "fields": {
                "objective": "operator-facing mission objective",
                "planner": {"kind": "human|ai_ops|local_agent|scheduler|ui", "name": "string", "version": "string"},
                "context_hash": "sha256 of the bounded AgentContextPack used to plan",
                "target_scope": {
                    "target_ids": ["uuid"],
                    "root_domains": ["example.com"],
                    "allowed_hosts": ["app.example.com"],
                    "allowed_schemes": ["https"],
                    "environment": "development|staging|preview|production|lab",
                },
                "risk_tier": "read_only|passive|active|intrusive|credential|dangerous",
                "allowed_families": ["sqli", "xss", "auth", "bola", "ai_gate", "model_intake"],
                "disallowed_families": ["rce", "destructive_write"],
                "budget": {"requests": "integer", "seconds": "integer", "currency_units": "number"},
                "constraints": {"rate_limit_rps": "number", "window_utc": "string", "weekday_window": "string"},
                "missing_inputs": ["second_user_auth", "trusted_key_anchor"],
                "confirmations": ["confirm_authorized", "confirm_production"],
                "actions": ["CampaignAction"],
                "stop_conditions": ["out_of_scope_redirect", "budget_exhausted", "proof_found"],
                "success_criteria": ["family_attempted", "proof_or_refutation_recorded"],
            },
            "invariants": [
                "plan is dry-run until state-changing actions receive scope and approval receipts",
                "risk_tier cannot be increased by a planner after approval",
                "AI/local-agent rationale cannot create verified findings",
            ],
        },
        "AgentContextPack": {
            "status": "contract",
            "description": "Bounded redacted context summary for planners.",
            "required": ["context_hash", "target_summary", "allowed_commands", "known_preconditions", "worker_freshness"],
            "fields": {
                "context_hash": "sha256 of canonical redacted context",
                "target_summary": {"target_id": "uuid", "url": "redacted_url", "root_domain": "example.com"},
                "surface_summary": {"endpoint_count": "integer", "api_endpoint_count": "integer", "auth_states": ["anonymous"]},
                "asm_gaps": ["scheduler_state", "family_coverage", "recommended_campaigns"],
                "hypothesis_summary": {"open": "integer", "blocked": "integer", "refuted": "integer"},
                "active_findings": [{"finding_id": "uuid", "severity": "string", "proof_state": "string", "evidence_ids": ["uuid"]}],
                "allowed_commands": ["target.get", "asm.gaps", "scan.result"],
                "disallowed_commands": ["execute_shell", "raw_browser_secret_dump"],
                "known_preconditions": ["primary_auth_present", "second_user_missing"],
                "worker_freshness": {"build_current": "boolean", "stale_count": "integer"},
            },
            "invariants": [
                "secrets and raw transcripts are excluded by default",
                "evidence is referenced by id/hash unless an explicit redaction profile allows more",
            ],
        },
        "TargetPrincipal": {
            "status": "read_only",
            "description": "Role, tenant, and auth-state identity for a web/API target; stores credential references/profiles, never raw secrets.",
            "required": ["principal_id", "target_id", "label", "role", "auth_state"],
            "fields": {
                "principal_id": "uuid",
                "target_id": "uuid",
                "label": "operator label",
                "role": "admin|user|customer|service|custom",
                "tenant_id": "tenant-a|null",
                "auth_state": "user1|user2|admin|custom authenticated state",
                "credential_profile": "reference label only; no raw credential material",
                "is_active": "boolean",
            },
            "invariants": ["principal records cannot create findings or mark proof verified"],
        },
        "EndpointPrincipalExpectation": {
            "status": "dry_run",
            "description": "Endpoint x principal/role expectation used to plan BFLA/BOLA/tenant tests before proof-backed execution.",
            "required": ["target_id", "method", "path", "expected_access"],
            "fields": {
                "target_id": "uuid",
                "endpoint_id": "uuid|null",
                "method": "GET|POST|...",
                "path": "/api/orders/{id}",
                "principal_id": "uuid|null",
                "principal_role": "admin|user|custom|null",
                "tenant_id": "tenant-a|null",
                "expected_access": "allow|deny|requires_role|unknown",
                "expected_http_status": "integer|null",
                "expectation_source": "manual|app_graph|source_ingest|ai_planner|scanner_signal",
            },
            "invariants": [
                "expectations are planning facts only and cannot create findings",
                "lower-role access becomes a finding only through deterministic proof taxonomy",
            ],
        },
        "RefuterReview": {
            "status": "dry_run",
            "description": "Durable counterevidence review for weak findings, hypotheses, AI/model claims, benchmarks, parser output, and deployment-gating claims.",
            "required": ["subject_type", "trigger_reason", "refuter_signal", "verdict_basis"],
            "fields": {
                "review_id": "uuid",
                "subject_type": "finding|hypothesis|ai_gate_scan|model_intake|benchmark|planner|deployment_gate|parser_output|manual",
                "subject_id": "uuid|string|null",
                "target_id": "uuid|null",
                "finding_id": "uuid|null",
                "hypothesis_id": "uuid|null",
                "refuter_signal": "support|question|weaken|refute",
                "refuter_verdict": "supported|weakened|refuted|inconclusive|null",
                "verdict_basis": "signal_only|deterministic_replay|cryptographic|parser_protocol|human_approved_review",
                "evidence_object_ids": ["uuid"],
                "tool_receipt_ids": ["uuid"],
                "counterevidence": "redacted structured summary",
            },
            "invariants": [
                "refuter signals can weaken, support, question, or refute context without changing findings",
                "refuter verdicts require deterministic, cryptographic, parser/protocol, or human-approved-review basis",
                "recording a refuter review cannot directly update proof_state, severity, findings, hypotheses, or deployment gates",
            ],
        },
        "AgentDecisionTrace": {
            "status": "contract",
            "description": "Durable audit trace for planner decisions without hidden chain-of-thought.",
            "required": ["trace_id", "planner", "context_hash", "command_schema_version", "events", "final_rationale"],
            "fields": {
                "trace_id": "uuid",
                "planner": {"kind": "string", "version": "string"},
                "context_hash": "sha256",
                "command_schema_version": ARSENAL_SCHEMA_VERSION,
                "events": [{"type": "proposed|rejected|blocked|approved|queued|completed|failed", "summary": "string"}],
                "missing_inputs": ["string"],
                "approval_ids": ["uuid"],
                "scope_receipt_ids": ["uuid"],
                "evidence_refs": ["uuid"],
                "final_rationale": "operator-visible concise rationale",
            },
            "forbidden_fields": ["chain_of_thought", "raw_secret", "raw_cookie", "raw_private_key"],
        },
        "ScopeReceipt": {
            "status": "contract",
            "description": "Fail-closed scope validation receipt required before future state-changing command execution.",
            "required": ["receipt_id", "input_scope", "normalized_scope", "verdict", "checks"],
            "fields": {
                "receipt_id": "uuid",
                "input_scope": {"url": "string", "target_id": "uuid|null"},
                "normalized_scope": {"scheme": "https", "host": "example.com", "port": 443},
                "verdict": "allowed|blocked|needs_approval",
                "checks": [
                    "malformed_url",
                    "scheme_relative_url",
                    "userinfo",
                    "unicode_or_punycode_confusion",
                    "trailing_dot_host",
                    "loopback_or_private_range",
                    "broad_cidr",
                    "redirect_out_of_scope",
                ],
                "blocked_by": ["string"],
            },
        },
        "ApprovalReceipt": {
            "status": "contract",
            "description": "Operator approval record for gated actions.",
            "required": ["approval_id", "scope_receipt_id", "risk_tier", "confirmations", "approved_by", "created_at"],
            "fields": {
                "approval_id": "uuid",
                "scope_receipt_id": "uuid",
                "risk_tier": "active|intrusive|credential|dangerous",
                "confirmations": ["confirm_authorized", "confirm_production", "confirm_high_risk"],
                "approved_by": "operator|api_token|scheduler_policy",
                "expires_at": "iso8601|null",
                "denial_reason": "string|null",
            },
        },
        "CommandResult": {
            "status": "contract",
            "description": "Read-only audit record for queued, partial, blocked, or completed product actions requested through Command Arsenal-compatible routes.",
            "required": ["operation_id", "command", "status", "risk_tier", "operator_message"],
            "fields": {
                "operation_id": "uuid",
                "command": "Command Arsenal command name",
                "status": "planned|blocked|approval_required|approved|queued|running|completed|partial|degraded|failed|cancelled|evidence_bound|retest_scheduled|refuter_requested",
                "dry_run": "boolean",
                "risk_tier": "read_only|passive|active|intrusive|credential|dangerous",
                "operation_plan_id": "uuid|null",
                "scope_receipt_id": "uuid|null",
                "approval_id": "uuid|null",
                "campaign_id": "uuid|null",
                "scan_id": "uuid|null",
                "finding_ids": ["uuid"],
                "hypothesis_ids": ["uuid"],
                "evidence_object_ids": ["uuid"],
                "tool_receipt_ids": ["uuid"],
                "blocked_by": ["string"],
                "next_action": "route-or-null",
                "operator_message": "concise operator-facing result",
                "result_json": "sanitized structured summary",
            },
            "invariants": [
                "command results are audit records, not proof",
                "queued command results cannot mark findings verified",
                "result_json must be redacted before persistence",
            ],
        },
        "ToolReceipt": {
            "status": "dry_run",
            "description": "Execution receipt for existing tools/executors before adding new offensive tooling.",
            "required": ["tool_name", "adapter_version", "command_hash", "scope_receipt_id", "status", "parser_status"],
            "fields": {
                "tool_name": "nuclei|sqlmap|dalfox|playwright|ai_gate_probe_executor|model_intake_signature_verifier",
                "tool_version": "string|null",
                "adapter_version": ARSENAL_SCHEMA_VERSION,
                "command_hash": "sha256 of redacted argv/config",
                "redacted_argv": ["string"],
                "worker_build": "fingerprint",
                "scope_receipt_id": "uuid|null",
                "approval_id": "uuid|null",
                "started_at": "iso8601",
                "finished_at": "iso8601|null",
                "exit_code": "integer|null",
                "timeout": "boolean",
                "stdout_artifact_ref": "evidence_object_id|null",
                "stderr_artifact_ref": "evidence_object_id|null",
                "parsed_evidence_refs": ["evidence_instance_id"],
                "parser_status": "not_run|parsed|partial|failed|not_applicable",
                "redaction_summary": "string",
            },
            "invariants": [
                "missing binary is skipped/waived, never phantom success",
                "parser failure cannot create verified findings",
                "recording a receipt cannot run a tool or create findings",
            ],
        },
        "CampaignAction": {
            "status": "contract",
            "description": "One planned or executed action inside a mission/campaign timeline.",
            "required": ["action_id", "command", "status", "risk_tier"],
            "fields": {
                "action_id": "uuid",
                "command": "Command Arsenal command name",
                "status": "planned|blocked|approved|queued|running|completed|failed|degraded|skipped",
                "risk_tier": "read_only|passive|active|intrusive|credential|dangerous",
                "blocked_by": ["missing_auth", "rate_cap", "production_gate", "scope_denied"],
                "scope_receipt_id": "uuid|null",
                "approval_id": "uuid|null",
                "tool_receipt_ids": ["uuid"],
                "evidence_refs": ["uuid"],
            },
        },
        "Hypothesis": {
            "status": "contract",
            "description": "Deduped, claimable/refutable lead that is not a finding until deterministic proof promotes it.",
            "required": ["hypothesis_id", "source", "family", "dedupe_key", "status", "claim_state"],
            "fields": {
                "hypothesis_id": "uuid",
                "source": "app_graph|source_ingest|ai_planner|scanner_signal|ai_gate|model_intake|manual",
                "family": "sqli|xss|bola|bfla|mass_assignment|jwt|ai_gate|model_intake",
                "cwe": "string|null",
                "severity_guess": "critical|high|medium|low|info|null",
                "confidence": "number",
                "dedupe_key": "stable string",
                "dedupe_dimensions": {
                    "method": "GET|POST|null",
                    "route": "/api/orders/{id}|null",
                    "object_key": "order.id|null",
                    "principal_actor": "user1|null",
                    "principal_other": "user2|null",
                    "tenant": "tenant-a|null",
                    "parameter_path": "query.id|null",
                    "body_path": "json.user.id|null",
                    "proof_surface": "runtime_authz_replay|parser|cryptographic|null",
                },
                "status": "open|claimed|testing|supported|refuted|promoted|dead",
                "effective_status": "open|claimed|testing|supported|refuted|promoted|dead",
                "claim_state": {
                    "owner": "worker|agent|null",
                    "lease_expires_at": "iso8601|null",
                    "active": "boolean",
                    "expired": "boolean",
                    "effective_status": "open|claimed|testing|supported|refuted|promoted|dead",
                },
                "claimable": "boolean",
                "evidence_refs": ["evidence_instance_id"],
                "tool_receipt_refs": ["tool_receipt_id"],
                "next_test_action": "CampaignAction|null",
                "endorsements": ["append-only support signal"],
                "refutations": ["append-only refuter signal"],
            },
            "invariants": [
                "hypotheses cannot directly alter finding proof_state or severity",
                "target/family/dedupe dimensions identify a lead across signal sources",
            ],
        },
        "EvidenceInstance": {
            "status": "dry_run",
            "description": "Concrete proof observation linked to a canonical finding and evidence object.",
            "required": ["instance_id", "finding_id", "evidence_object_id", "hash", "redaction_profile"],
            "fields": {
                "instance_id": "uuid",
                "finding_id": "uuid",
                "evidence_object_id": "uuid",
                "concrete_url": "redacted_url",
                "object_id": "string|null",
                "payload_variant": "string|null",
                "request_response_refs": ["evidence_object_id"],
                "principal_pair": {"actor": "user1", "other": "user2|null", "tenant": "tenant-a|null"},
                "proof_observation": "deterministic observation summary",
                "campaign_action_id": "uuid|null",
                "tool_receipt_id": "uuid|null",
                "redaction_profile": "default|strict|ai_transcript|model_artifact",
                "hash": "sha256",
                "retention_policy": "standard|short|audit|legal_hold",
                "proof_state": "verified|suspected|unverified|refuted|inconclusive",
            },
            "invariants": [
                "evidence instances enumerate observations but do not directly update canonical findings",
                "finding proof_state changes still require the existing proof taxonomy and promotion path",
            ],
        },
    }

    return {
        "schema_version": ARSENAL_SCHEMA_VERSION,
        "maturity": "contract_only",
        "execution_enabled": False,
        "secret_policy": secret_policy,
        "contracts": contracts,
        "contract_names": list(CONTRACT_NAMES),
    }


def _resolve_binary(spec: ToolAdapterSpec) -> tuple[str | None, str | None]:
    for path in spec.common_paths:
        if path and os.path.exists(path) and os.access(path, os.X_OK):
            return path, "common_path"
    for binary in spec.binaries:
        resolved = shutil.which(binary)
        if resolved:
            return resolved, "path"
    return None, None


def _resolve_agent_binary(spec: LocalAgentSpec) -> tuple[str | None, str | None]:
    for binary in spec.binaries:
        resolved = shutil.which(binary)
        if resolved:
            return resolved, "path"
    return None, None


def _detect_auth_artifacts(spec: LocalAgentSpec) -> tuple[bool, str, list[str]]:
    detected: list[str] = []
    for raw_path in spec.auth_artifact_paths:
        expanded = os.path.expanduser(raw_path)
        if os.path.exists(expanded):
            detected.append(raw_path)
    if detected:
        return True, "artifact-exists", detected
    return False, "none", []


def _probe_version(binary_path: str, args: tuple[str, ...], timeout_seconds: int) -> tuple[str | None, str | None]:
    if not args:
        return None, None
    try:
        proc = subprocess.run(
            [binary_path, *args],
            capture_output=True,
            text=True,
            timeout=max(1, min(timeout_seconds, 10)),
            check=False,
        )
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"
    output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    first_line = output.splitlines()[0].strip() if output else None
    if proc.returncode != 0 and not first_line:
        return None, f"version command exited {proc.returncode}"
    return first_line[:200] if first_line else None, None


_SENSITIVE_ENV_MARKERS = (
    "API_KEY",
    "AUTH",
    "BEARER",
    "CLAUDE",
    "CODEX",
    "COOKIE",
    "CREDENTIAL",
    "DEEPSEEK",
    "GEMINI",
    "GOOGLE",
    "GROQ",
    "MISTRAL",
    "OPENAI",
    "OPENROUTER",
    "PASSWORD",
    "SECRET",
    "TOKEN",
    "TOGETHER",
)


def _safe_local_agent_env() -> tuple[dict[str, str], int]:
    """Return an environment with provider credentials and secret-looking values removed."""
    safe_env: dict[str, str] = {}
    stripped_count = 0
    for key, value in os.environ.items():
        normalized = key.upper()
        if any(marker in normalized for marker in _SENSITIVE_ENV_MARKERS):
            stripped_count += 1
            continue
        safe_env[key] = value
    return safe_env, stripped_count


def _find_local_agent_spec(agent: str) -> LocalAgentSpec | None:
    normalized = (agent or "").strip().lower()
    for spec in LOCAL_AGENT_SPECS:
        if spec.agent == normalized:
            return spec
    return None


def _bounded_output(stdout: str | None, stderr: str | None, max_output_bytes: int) -> tuple[str, bool]:
    output = ((stdout or "") + ("\n" if stdout and stderr else "") + (stderr or "")).strip()
    encoded = output.encode("utf-8", errors="replace")
    if len(encoded) <= max_output_bytes:
        return output, False
    trimmed = encoded[:max_output_bytes].decode("utf-8", errors="ignore")
    return trimmed, True


def test_local_agent_capability(
    agent: str,
    *,
    timeout_seconds: int = 5,
    max_output_bytes: int = 2000,
) -> dict[str, Any]:
    """Run a harmless bounded capability ping for one configured local planner agent.

    This intentionally does not send prompts, run planner loops, read auth artifact contents,
    queue scanner work, or mutate target state. The only subprocess path is the configured
    version/capability command for a known local-agent binary.
    """
    spec = _find_local_agent_spec(agent)
    if not spec:
        raise ValueError(f"Unknown local agent: {agent}")

    timeout = max(1, min(int(timeout_seconds), 10))
    output_limit = max(128, min(int(max_output_bytes), 8000))
    capability = _local_agent_to_dict(spec, probe_versions=False)
    binary_path = capability.get("binary_path")
    auth_detected, auth_detection_method, auth_artifacts = _detect_auth_artifacts(spec)

    base: dict[str, Any] = {
        "agent": spec.agent,
        "display_name": spec.display_name,
        "ok": False,
        "status": "missing" if not binary_path else "failed",
        "reason": None,
        "binary_path": binary_path,
        "binary_detection": capability.get("binary_detection"),
        "auth_detected": auth_detected,
        "auth_detection_method": auth_detection_method,
        "auth_artifacts": auth_artifacts,
        "auth_artifact_contents_read": False,
        "planner_execution_enabled": False,
        "local_agent_spawned": False,
        "prompt_sent": False,
        "prompt_bytes_sent": 0,
        "target_state_mutated": False,
        "scanner_work_queued": False,
        "process_spawned": False,
        "timeout_seconds": timeout,
        "max_output_bytes": output_limit,
        "output": "",
        "output_truncated": False,
        "output_bytes_captured": 0,
        "version": None,
        "return_code": None,
        "timed_out": False,
        "error": None,
        "command_kind": "version_probe",
        "argv_redacted": [os.path.basename(str(binary_path)) if binary_path else spec.binaries[0], *spec.version_args],
        "environment_policy": {
            "provider_api_keys_stripped": True,
            "sensitive_values_returned": False,
            "environment_variable_names_returned": False,
            "stripped_variable_count": 0,
        },
    }

    if not binary_path:
        base["reason"] = "binary_not_detected"
        return base

    if not spec.version_args:
        base.update({"ok": True, "status": "passed", "reason": "binary_detected_no_version_command"})
        return base

    safe_env, stripped_count = _safe_local_agent_env()
    base["environment_policy"]["stripped_variable_count"] = stripped_count
    try:
        proc = subprocess.run(
            [str(binary_path), *spec.version_args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=safe_env,
        )
    except subprocess.TimeoutExpired as exc:
        output, truncated = _bounded_output(getattr(exc, "stdout", None), getattr(exc, "stderr", None), output_limit)
        base.update(
            {
                "status": "failed",
                "reason": "timeout",
                "process_spawned": True,
                "timed_out": True,
                "error": f"TimeoutExpired: command exceeded {timeout}s",
                "output": output,
                "output_truncated": truncated,
                "output_bytes_captured": len(output.encode("utf-8", errors="replace")),
            }
        )
        return base
    except Exception as exc:
        base.update(
            {
                "status": "failed",
                "reason": "probe_error",
                "error": f"{type(exc).__name__}: {exc}",
            }
        )
        return base

    output, truncated = _bounded_output(proc.stdout, proc.stderr, output_limit)
    first_line = output.splitlines()[0].strip() if output else None
    ok = proc.returncode == 0 or bool(first_line)
    base.update(
        {
            "ok": ok,
            "status": "passed" if proc.returncode == 0 else ("warning" if first_line else "failed"),
            "reason": "version_probe_completed" if ok else "version_probe_failed",
            "process_spawned": True,
            "output": output,
            "output_truncated": truncated,
            "output_bytes_captured": len(output.encode("utf-8", errors="replace")),
            "version": first_line[:200] if first_line else None,
            "return_code": proc.returncode,
        }
    )
    return base


def _local_agent_to_dict(spec: LocalAgentSpec, *, probe_versions: bool) -> dict[str, Any]:
    binary_path, binary_detection = _resolve_agent_binary(spec)
    auth_detected, auth_detection_method, auth_artifacts = _detect_auth_artifacts(spec)
    version = None
    version_probe_error = None
    if binary_path and probe_versions:
        version, version_probe_error = _probe_version(binary_path, spec.version_args, timeout_seconds=5)

    return {
        "agent": spec.agent,
        "display_name": spec.display_name,
        "binary_path": binary_path,
        "binary_detection": binary_detection,
        "version": version,
        "version_probe_error": version_probe_error,
        "auth_detected": auth_detected,
        "auth_detection_method": auth_detection_method,
        "auth_artifacts": auth_artifacts,
        "auth_artifact_contents_read": False,
        "supports_headless_prompt": spec.supports_headless_prompt,
        "supports_read_only_mode": spec.supports_read_only_mode,
        "supports_json_mode": spec.supports_json_mode,
        "supports_timeout": spec.supports_timeout,
        "supports_workdir_isolation": spec.supports_workdir_isolation,
        "supports_network_disable": spec.supports_network_disable,
        "max_prompt_bytes": spec.max_prompt_bytes,
        "max_output_bytes": spec.max_output_bytes,
        "risk_notes": list(spec.risk_notes),
        "planner_execution_enabled": False,
        "status": "available" if binary_path and auth_detected else ("installed" if binary_path else "missing"),
    }


def _tool_to_dict(spec: ToolAdapterSpec, *, probe_versions: bool) -> dict[str, Any]:
    binary_path, detection = _resolve_binary(spec)
    version = None
    probe_error = None
    status = spec.status

    if spec.binaries:
        if binary_path:
            status = "installed" if status == "wired" else status
            if probe_versions:
                version, probe_error = _probe_version(binary_path, spec.version_args, spec.timeout_seconds)
                if version and status in {"wired", "installed"}:
                    status = "runnable"
        elif status in {"wired", "gated"}:
            status = "wired"
    elif status == "runnable":
        version = "internal"

    return {
        "tool_name": spec.tool_name,
        "family": spec.family,
        "description": spec.description,
        "risk_tier": spec.risk_tier,
        "status": status,
        "expected_status": spec.status,
        "binary_path": binary_path,
        "detection": detection,
        "version": version,
        "version_probe_error": probe_error,
        "version_command": [binary_path or (spec.binaries[0] if spec.binaries else spec.tool_name), *spec.version_args]
        if spec.version_args or spec.binaries else [],
        "evidence_parser": spec.evidence_parser,
        "proof_contract": spec.proof_contract,
        "retest_contract": spec.retest_contract,
        "redaction_rules": list(spec.redaction_rules),
        "timeout_seconds": spec.timeout_seconds,
    }


def _tool_status_release_gate(tools: list[dict[str, Any]]) -> dict[str, Any]:
    """Validate the catalog does not imply phantom installed/runnable tools.

    `wired` and `gated` are allowed non-claim states: they describe ShakerScan's
    adapter contract, not the local machine's ability to run the binary.
    """
    violations: list[dict[str, Any]] = []
    runnable_claims = {"installed", "runnable"}
    non_claim_statuses = {"wired", "gated", "disabled"}

    for tool in tools:
        name = str(tool.get("tool_name") or "")
        status = str(tool.get("status") or "")
        expected_status = str(tool.get("expected_status") or "")
        binary_path = tool.get("binary_path")
        version = tool.get("version")
        version_command = tool.get("version_command") if isinstance(tool.get("version_command"), list) else []
        has_external_binary_shape = bool(version_command)
        internal_runnable = version == "internal" and not binary_path

        if status not in TOOL_STATUSES:
            violations.append({
                "tool_name": name,
                "code": "invalid_status",
                "status": status,
                "message": "tool status is not an allowed operator-visible state",
            })
        if expected_status not in TOOL_STATUSES:
            violations.append({
                "tool_name": name,
                "code": "invalid_expected_status",
                "expected_status": expected_status,
                "message": "expected status is not an allowed operator-visible state",
            })

        if status in runnable_claims and has_external_binary_shape and not binary_path and not internal_runnable:
            violations.append({
                "tool_name": name,
                "code": "phantom_binary_claim",
                "status": status,
                "message": "external adapter claims installed/runnable but no binary path resolved",
            })

        if expected_status in runnable_claims and has_external_binary_shape and not binary_path and not internal_runnable:
            violations.append({
                "tool_name": name,
                "code": "phantom_expected_status",
                "expected_status": expected_status,
                "message": "adapter configuration claims installed/runnable but the binary is missing",
            })

        if status == "runnable" and not tool.get("evidence_parser"):
            violations.append({
                "tool_name": name,
                "code": "missing_evidence_parser",
                "status": status,
                "message": "runnable adapters must declare an evidence parser",
            })
        if status == "runnable" and not tool.get("proof_contract"):
            violations.append({
                "tool_name": name,
                "code": "missing_proof_contract",
                "status": status,
                "message": "runnable adapters must declare a proof contract",
            })

    return {
        "name": "no_phantom_tools",
        "status": "pass" if not violations else "fail",
        "violations": violations,
        "checked_count": len(tools),
        "allowed_statuses": list(TOOL_STATUSES),
        "claim_statuses": sorted(runnable_claims | {"waived", "catalog_only"}),
        "non_claim_statuses": sorted(non_claim_statuses),
        "execution_enabled": False,
    }


def describe_tools(*, probe_versions: bool = False) -> dict[str, Any]:
    """Return catalog/status for currently integrated tool adapters."""
    tools = [_tool_to_dict(spec, probe_versions=probe_versions) for spec in TOOL_ADAPTERS]
    counts: dict[str, int] = {}
    for tool in tools:
        counts[str(tool["status"])] = counts.get(str(tool["status"]), 0) + 1
    release_gate = _tool_status_release_gate(tools)
    return {
        "schema_version": ARSENAL_SCHEMA_VERSION,
        "maturity": "read_only",
        "execution_enabled": False,
        "probe_versions": bool(probe_versions),
        "status_labels": list(TOOL_STATUSES),
        "release_gate": release_gate,
        "tools": tools,
        "summary": counts,
    }


def describe_local_agents(*, probe_versions: bool = False) -> dict[str, Any]:
    """Return read-only capability records for optional local planner agents."""
    agents = [_local_agent_to_dict(spec, probe_versions=probe_versions) for spec in LOCAL_AGENT_SPECS]
    counts: dict[str, int] = {}
    for agent in agents:
        counts[str(agent["status"])] = counts.get(str(agent["status"]), 0) + 1
    return {
        "schema_version": ARSENAL_SCHEMA_VERSION,
        "maturity": "read_only",
        "execution_enabled": False,
        "planner_execution_enabled": False,
        "probe_versions": bool(probe_versions),
        "auth_policy": {
            "detection_only": True,
            "auth_artifact_contents_read": False,
            "strip_provider_api_key_environment_on_future_spawn": True,
            "sensitive_values_returned": False,
        },
        "agents": agents,
        "summary": counts,
    }
