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
