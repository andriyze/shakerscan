"""Scenario catalog for AI security and model intake workflows.

The catalog is static and deterministic so the UI, API clients, and coding
agents can agree on the same demo/prod-like test setup before a target exists.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from ai_control_requirements import AI_CONTROL_REQUIREMENTS


HONEY_BASE_URL = "https://honey.shakerscan.com"


DEMO_ONLY_AI_GATE_CONTROLS: list[dict[str, Any]] = [
    {
        "id": "threat_model",
        "label": "Threat model",
        "applies_to": "all",
        "keys": ["threat_model", "abuse_case_model", "ai_threat_model"],
    },
    {
        "id": "cloud_security_design",
        "label": "Cloud security design",
        "applies_to": "all",
        "keys": ["cloud_security_design", "network_security_design", "deployment_architecture"],
    },
]


def _catalog_control(control: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": control["id"],
        "label": control["label"],
        "applies_to": control.get("applies_to", "all"),
        "keys": list(control.get("keys") or []),
    }


AI_GATE_CONTROLS: list[dict[str, Any]] = [
    *DEMO_ONLY_AI_GATE_CONTROLS,
    *[_catalog_control(control) for control in AI_CONTROL_REQUIREMENTS],
]


MODEL_INTAKE_CONTROLS: list[dict[str, Any]] = [
    {"id": "source_reputation", "label": "Source reputation", "keys": ["source_repo", "publisher", "source_repository"]},
    {"id": "license", "label": "License review", "keys": ["license", "model_license", "license_url"]},
    {"id": "model_card", "label": "Model card", "keys": ["model_card_url", "model_card", "card_url"]},
    {"id": "training_data", "label": "Dataset/training claims", "keys": ["training_data_ref", "dataset_ref", "training_data_statement"]},
    {"id": "artifact_hash", "label": "Artifact hash", "keys": ["sha256", "expected_sha256"]},
    {"id": "signature", "label": "Signature or attestation", "keys": ["signature_url", "signature", "signed_by", "attestation_url"]},
    {"id": "unsafe_serialization", "label": "Unsafe serialization check", "keys": ["artifact_url", "format_posture"]},
    {"id": "malware_scan", "label": "Malware scan evidence", "keys": ["malware_scan_url", "malware_scan_result", "yara_scan", "av_scan"]},
    {"id": "dependencies", "label": "SBOM/dependencies", "keys": ["sbom_url", "sbom", "dependencies", "package_dependencies"]},
    {"id": "privacy_security_review", "label": "Privacy/security review", "keys": ["privacy_review", "security_review", "risk_assessment"]},
    {"id": "security_evals", "label": "Security evals", "keys": ["security_evals", "eval_report_url", "red_team_report"]},
    {"id": "deployment_restrictions", "label": "Deployment restrictions", "keys": ["deployment_restrictions", "allowed_environments", "use_restrictions"]},
    {"id": "deployment_approval", "label": "Deployment approval", "keys": ["deployment_approved", "approved_by", "approved_at"]},
    {"id": "monitoring_plan", "label": "Monitoring plan", "keys": ["monitoring_plan", "monitoring_plan_url", "incident_response_plan"]},
]


RAG_METADATA = {
    "asset_owner": "security-platform",
    "risk_tier": "high",
    "data_classification": "restricted",
    "threat_model": "rag-agent-demo-v1",
    "cloud_security_design": {
        "network": "private subnets for vector DB and control plane",
        "secrets": "managed secrets with rotation",
        "egress": "allowlisted model and telemetry endpoints",
        "logging": "centralized immutable audit logs",
    },
    "logging_policy": "centralized-audit-log-v1",
    "incident_response_plan": "ai-ir-runbook-v1",
    "governance_mapping": {
        "owasp_llm_agentic": ["LLM01", "LLM02", "LLM05", "LLM08"],
        "nist_ai_rmf": ["MAP", "MEASURE", "MANAGE", "GOVERN"],
        "iso_27001_2022": ["A.5.12", "A.5.15", "A.5.24", "A.8.28"],
    },
    "document_classification_policy": "restricted/internal/public labels required at ingestion",
    "ingestion_controls": ["source allowlist", "HTML/comment stripping", "malicious instruction canary tests"],
    "retrieval_acl_matrix": "tenant:user:document ACL enforced before vector search and after rerank",
    "metadata_filtering": ["tenant_id", "document_acl", "classification", "retention_state"],
    "vector_tenant_isolation": "per-tenant namespace plus query-time ACL filters",
    "malicious_document_tests": ["hidden instruction leakage", "corpus poisoning", "deleted document recall"],
    "source_citation_policy": "answers cite only authorized source ids",
    "retrieved_content_delimiting": "retrieved text is delimited as untrusted context",
    "no_training_on_private_docs": True,
    "data_retention_policy": "90-day prompt/trace retention, document retention follows source system",
    "enforce_ai_control_baseline": True,
}


AGENT_METADATA = {
    "asset_owner": "security-platform",
    "risk_tier": "high",
    "data_classification": "restricted",
    "threat_model": "agent-tool-abuse-v1",
    "cloud_security_design": {
        "identity": "delegated user identity with service token exchange",
        "network": "tool executors isolated from model runtime",
        "secrets": "no raw token passthrough to prompts or tools",
        "egress": "tool allowlist and transaction limits",
    },
    "logging_policy": "tool-call-audit-log-v1",
    "incident_response_plan": "agent-kill-switch-runbook-v1",
    "governance_mapping": {
        "owasp_llm_agentic": ["LLM08", "LLM10"],
        "nist_ai_rmf": ["MAP", "MEASURE", "MANAGE", "GOVERN"],
        "iso_27001_2022": ["A.5.9", "A.5.15", "A.5.16", "A.5.24", "A.8.18"],
    },
    "tool_inventory": ["account_lookup", "refund_create", "ticket_update", "mcp_file_read"],
    "per_tool_scopes": {
        "account_lookup": ["account:read"],
        "refund_create": ["refund:write"],
        "ticket_update": ["ticket:write"],
        "mcp_file_read": ["resource:read:approved"],
    },
    "delegated_identity": "user-bound OAuth token exchange",
    "token_audience_validation": True,
    "no_token_passthrough": True,
    "user_consent": True,
    "write_action_approval": True,
    "dry_run_mode": True,
    "transaction_limits": {"refund_create": {"max_amount": 100, "daily_count": 3}},
    "sandboxing": "local commands disabled unless approved in isolated sandbox",
    "audit_logs": True,
    "anomaly_detection": "tool-call volume, cost, and tenant-boundary alerts",
    "kill_switch": "runtime policy can disable all write tools",
    "enforce_ai_control_baseline": True,
}


MODEL_SAFE_METADATA = {
    "source_repo": "https://github.com/honey/model-fixtures",
    "commit_sha": "f00dbabe1234567890",
    "training_data_ref": "honey-fixtures/rag-eval-v1",
    "signature_url": f"{HONEY_BASE_URL}/model-intake/signatures/safe.sig",
    "model_card_url": f"{HONEY_BASE_URL}/model-intake/cards/safe.md",
    "attestation_url": f"{HONEY_BASE_URL}/model-intake/attestations/safe.intoto.jsonl",
    "signed_by": "sigstore:honey-ci",
    "license": "apache-2.0",
    "sbom": {"format": "cyclonedx", "components": [{"name": "tokenizer", "version": "1.0.0"}]},
    "malware_scan_result": {"engine": "fixture-yara", "status": "clean"},
    "security_evals": {"status": "passed", "suite": "rag-agent-intake-v1"},
    "privacy_review": {"status": "approved", "reviewer": "privacy"},
    "security_review": {"status": "approved", "reviewer": "security"},
    "risk_assessment": "approved for staging and controlled demos",
    "deployment_restrictions": ["staging", "demo"],
    "monitoring_plan": "model-monitoring-v1",
    "deployment_approved": True,
    "approved_by": "security",
    "approved_at": "2026-05-10T00:00:00Z",
}


def _model_preset(
    *,
    key: str,
    name: str,
    artifact_path: str,
    manifest_path: str,
    should_pass: bool,
    expected_findings: list[str],
    expected_min_severity: str,
    metadata_json: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "key": key,
        "name": name,
        "artifact_url": f"{HONEY_BASE_URL}{artifact_path}",
        "metadata_url": f"{HONEY_BASE_URL}{manifest_path}",
        "metadata_json": metadata_json or {},
        "require_deployment_approval": True,
        "require_signature": True,
        "require_hash": True,
        "require_model_governance": True,
        "max_download_bytes": 10_000_000,
        "timeout_seconds": 20,
        "should_pass": should_pass,
        "expected_findings": expected_findings,
        "expected_min_severity": expected_min_severity,
    }


AI_TEST_SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "secure-rag-agent",
        "category": "ai_gate",
        "title": "Secure RAG + Agent",
        "summary": "Threat model, prompt-injection probes, retrieval ACLs, tool authorization, logging, cloud design, and governance evidence.",
        "target_templates": [
            {
                "key": "secure-demo-query",
                "name": "Honey secure demo query",
                "target_type": "rag",
                "endpoint_url": f"{HONEY_BASE_URL}/api/secure-demo/rag-agent/query",
                "method": "POST",
                "headers_template": {"Content-Type": "application/json"},
                "request_template": {
                    "message": "{{prompt}}",
                    "session_id": "{{session_id}}",
                    "tenant_id": "tenant-a",
                    "user_id": "user-a",
                    "include_trace": True,
                },
                "response_path": "$.answer",
                "streaming_mode": "json",
                "rate_limit_rps": 2,
                "request_budget": 12,
                "token_budget": 8000,
                "metadata_json": {
                    **RAG_METADATA,
                    **AGENT_METADATA,
                    "threat_model_url": f"{HONEY_BASE_URL}/api/secure-demo/rag-agent/threat-model",
                    "governance_mapping_url": f"{HONEY_BASE_URL}/api/secure-demo/governance/mapping",
                },
                "recommended_scan": {
                    "probe_pack": "shaker-rag-lite",
                    "scan_profile": "standard",
                    "environment": "staging",
                },
            },
            {
                "key": "rag",
                "name": "Honey secure RAG",
                "target_type": "rag",
                "endpoint_url": f"{HONEY_BASE_URL}/api/v1/rag/answer",
                "method": "POST",
                "headers_template": {"Content-Type": "application/json"},
                "request_template": {
                    "message": "{{prompt}}",
                    "session_id": "{{session_id}}",
                    "tenant_id": "tenant-a",
                    "user_id": "user-a",
                },
                "response_path": "$.answer",
                "streaming_mode": "json",
                "rate_limit_rps": 2,
                "request_budget": 12,
                "token_budget": 8000,
                "metadata_json": RAG_METADATA,
                "recommended_scan": {
                    "probe_pack": "shaker-rag-lite",
                    "scan_profile": "standard",
                    "environment": "staging",
                },
            },
            {
                "key": "agent",
                "name": "Honey agent trace",
                "target_type": "agent_trace",
                "endpoint_url": f"{HONEY_BASE_URL}/api/v1/agent/trace",
                "method": "POST",
                "headers_template": {"Content-Type": "application/json"},
                "request_template": {
                    "message": "{{prompt}}",
                    "session_id": "{{session_id}}",
                    "tenant_id": "tenant-a",
                    "user_id": "user-a",
                },
                "response_path": "$",
                "streaming_mode": "json",
                "rate_limit_rps": 2,
                "request_budget": 12,
                "token_budget": 8000,
                "metadata_json": AGENT_METADATA,
                "recommended_scan": {
                    "probe_pack": "shaker-agent-abuse",
                    "scan_profile": "standard",
                    "environment": "staging",
                },
            },
            {
                "key": "mcp",
                "name": "Honey MCP trace",
                "target_type": "mcp_trace",
                "endpoint_url": f"{HONEY_BASE_URL}/api/v1/mcp/trace",
                "method": "POST",
                "headers_template": {"Content-Type": "application/json", "Accept": "application/json"},
                "request_template": {
                    "jsonrpc": "2.0",
                    "method": "tools/list",
                    "params": {"prompt": "{{prompt}}", "session_id": "{{session_id}}"},
                    "id": "{{session_id}}",
                },
                "response_path": "$.result",
                "streaming_mode": "json",
                "rate_limit_rps": 1,
                "request_budget": 8,
                "token_budget": 6000,
                "metadata_json": AGENT_METADATA,
                "recommended_scan": {
                    "probe_pack": "shaker-mcp-security",
                    "scan_profile": "smoke",
                    "environment": "staging",
                },
            },
        ],
        "readiness_controls": AI_GATE_CONTROLS,
        "test_plan": [
            {"surface": "rag", "probe_pack": "shaker-rag-lite", "scan_profile": "standard"},
            {"surface": "agent", "probe_pack": "shaker-agent-abuse", "scan_profile": "standard"},
            {"surface": "mcp", "probe_pack": "shaker-mcp-security", "scan_profile": "smoke"},
        ],
        "acceptance_signals": [
            "AI Gate transcript includes adversarial prompts, responses, detector hits, and judge output.",
            "Control evidence shows threat model, ACLs, tool scopes, logging, cloud design, and governance mapping.",
            "Unsafe Honey fixtures create deterministic findings; safe fixtures show scoped answers or refusals.",
        ],
        "honey_contract": {
            "registry_url": f"{HONEY_BASE_URL}/api/ai-gate/scenarios",
            "front_page_category": "Secure RAG / Agent / AI Gate Demo",
            "required_routes": [
                "GET /api/secure-demo/rag-agent/threat-model",
                "POST /api/secure-demo/rag-agent/query",
                "GET /api/secure-demo/rag-agent/runs/{run_id}",
                "GET /api/secure-demo/governance/mapping",
                "GET /api/ai-gate/scenarios",
                "POST /api/v1/rag/answer",
                "POST /api/v1/agent/trace",
                "POST /api/v1/mcp/trace",
            ],
        },
    },
    {
        "id": "model-intake-pipeline",
        "category": "model_intake",
        "title": "Model Intake Pipeline",
        "summary": "Model provenance, unsafe serialization, malware/pickle risk, artifact signing, and deployment approval.",
        "readiness_controls": MODEL_INTAKE_CONTROLS,
        "request_presets": [
            _model_preset(
                key="safe-signed",
                name="Honey signed safetensors",
                artifact_path="/model-intake/artifacts/safe/model.safetensors",
                manifest_path="/model-intake/manifests/safe.json",
                should_pass=True,
                expected_findings=[],
                expected_min_severity="info",
                metadata_json=MODEL_SAFE_METADATA,
            ),
            _model_preset(
                key="unsafe-pickle",
                name="Honey unsafe pickle",
                artifact_path="/model-intake/artifacts/unsafe/evil.pkl",
                manifest_path="/model-intake/manifests/evil-pickle.json",
                should_pass=False,
                expected_findings=[
                    "model_intake:unsafe_serialization",
                    "model_intake:missing_checksum",
                    "model_intake:missing_signature",
                    "model_intake:missing_provenance",
                    "model_intake:missing_model_card",
                    "model_intake:missing_deployment_approval",
                ],
                expected_min_severity="critical",
            ),
            _model_preset(
                key="torch-archive",
                name="Honey PyTorch archive",
                artifact_path="/model-intake/artifacts/unsafe/torch-model.pt",
                manifest_path="/model-intake/manifests/torch-model.json",
                should_pass=False,
                expected_findings=["model_intake:unsafe_serialization"],
                expected_min_severity="critical",
            ),
            _model_preset(
                key="embedded-executable",
                name="Honey executable bundle",
                artifact_path="/model-intake/artifacts/unsafe/bundle.zip",
                manifest_path="/model-intake/manifests/bundle.json",
                should_pass=False,
                expected_findings=["model_intake:unsafe_serialization", "model_intake:embedded_executable"],
                expected_min_severity="critical",
            ),
            _model_preset(
                key="tampered-checksum",
                name="Honey tampered checksum",
                artifact_path="/model-intake/artifacts/tampered/model.safetensors",
                manifest_path="/model-intake/manifests/tampered.json",
                should_pass=False,
                expected_findings=["model_intake:sha256_mismatch"],
                expected_min_severity="critical",
                metadata_json=MODEL_SAFE_METADATA,
            ),
            _model_preset(
                key="missing-approval",
                name="Honey unapproved ONNX",
                artifact_path="/model-intake/artifacts/unapproved/model.onnx",
                manifest_path="/model-intake/manifests/unapproved.json",
                should_pass=False,
                expected_findings=["model_intake:missing_deployment_approval"],
                expected_min_severity="high",
                metadata_json={**MODEL_SAFE_METADATA, "deployment_approved": False, "approved_by": "", "approved_at": ""},
            ),
        ],
        "acceptance_signals": [
            "Safe signed safetensors produces no findings or an A-grade result.",
            "Pickle-like and PyTorch artifacts are detected without executing model code.",
            "Tampered, unsigned, unapproved, or poorly governed artifacts produce evidence-first findings.",
        ],
        "honey_contract": {
            "registry_url": f"{HONEY_BASE_URL}/api/model-intake/scenarios",
            "front_page_category": "Model Intake Demo",
            "required_routes": [
                "GET /api/model-intake/scenarios",
                "GET /model-intake/",
                "GET /model-intake/artifacts/{scenario}/{filename}",
                "GET /model-intake/manifests/{filename}",
                "GET /model-intake/signatures/{filename}",
                "GET /model-intake/cards/{filename}",
                "POST /api/model-intake/submit",
                "GET /api/model-intake/{intake_id}",
                "POST /api/model-intake/{intake_id}/scan",
                "POST /api/model-intake/{intake_id}/approve",
                "POST /api/model-intake/{intake_id}/deploy",
            ],
            "calibration_routes": [
                "GET /model-intake/artifacts/safe/model.safetensors",
                "GET /model-intake/manifests/safe.json",
                "GET /model-intake/artifacts/unsafe/evil.pkl",
                "GET /model-intake/artifacts/unsafe/torch-model.pt",
                "GET /model-intake/artifacts/unsafe/bundle.zip",
                "GET /model-intake/artifacts/tampered/model.safetensors",
                "GET /model-intake/artifacts/unapproved/model.onnx",
            ],
        },
    },
]


def get_ai_test_scenarios() -> dict[str, Any]:
    """Return a defensive copy of the AI test scenario catalog."""
    return {
        "schema_version": "2026-05-11.ai-test-scenarios.v1",
        "scenarios": deepcopy(AI_TEST_SCENARIOS),
    }
