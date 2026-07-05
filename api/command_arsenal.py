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
        parameters_schema={"finding_id": {"type": "string"}, "mode": {"type": "string", "enum": ["deterministic", "ai"]}},
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
        parameters_schema={"artifact_url": {"type": "string"}, "trust_anchor_ids": {"type": "array"}},
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
        evidence_contract=("tool_status_rows",),
        timeout_seconds=15,
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
        "ToolReceipt": {
            "status": "contract",
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
                "parser_status": "not_run|parsed|partial|failed",
                "redaction_summary": "string",
            },
            "invariants": [
                "missing binary is skipped/waived, never phantom success",
                "parser failure cannot create verified findings",
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
                "status": "open|claimed|testing|supported|refuted|promoted|dead",
                "claim_state": {"owner": "worker|agent|null", "lease_expires_at": "iso8601|null"},
                "evidence_refs": ["evidence_instance_id"],
                "tool_receipt_refs": ["tool_receipt_id"],
                "next_test_action": "CampaignAction|null",
                "endorsements": ["append-only support signal"],
                "refutations": ["append-only refuter signal"],
            },
            "invariants": ["hypotheses cannot directly alter finding proof_state or severity"],
        },
        "EvidenceInstance": {
            "status": "contract",
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
            },
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


def describe_tools(*, probe_versions: bool = False) -> dict[str, Any]:
    """Return catalog/status for currently integrated tool adapters."""
    tools = [_tool_to_dict(spec, probe_versions=probe_versions) for spec in TOOL_ADAPTERS]
    counts: dict[str, int] = {}
    for tool in tools:
        counts[str(tool["status"])] = counts.get(str(tool["status"]), 0) + 1
    return {
        "schema_version": ARSENAL_SCHEMA_VERSION,
        "maturity": "read_only",
        "probe_versions": bool(probe_versions),
        "status_labels": list(TOOL_STATUSES),
        "tools": tools,
        "summary": counts,
    }
