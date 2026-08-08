"""Normalized, content-free controlled Model Intake reports and exports."""

from __future__ import annotations

import hashlib
import html
import json
from datetime import datetime, timezone
from typing import Any, Iterable


REPORT_SCHEMA = "model-intake-corporate-report/v2"
CONTROL_STATUSES = {
    "PASS", "FAIL", "REVIEW", "INCOMPLETE", "ERROR", "NOT_RUN", "NOT_APPLICABLE",
}
DEPLOYMENT_FOLLOW_UP_CONTROL_IDS = {
    "data_plane_evaluation", "human_approvals", "deterministic_policy", "signed_admission",
}
PRODUCTION_APPROVAL_ROLES = {
    "model_security_reviewer", "ml_platform_reviewer", "release_manager",
}


CONTROL_DETAILS: dict[str, dict[str, str]] = {
    "immutable_subjects": {
        "category": "Subject identity and acquisition",
        "question": "Were the complete model artifact and repository snapshot bound to immutable SHA-256 identities?",
        "method": "Verify authoritative subject records, complete-object digests, sizes, and immutable source references.",
        "remediation": "Acquire the complete artifact and authoritative repository snapshot, then register their exact digests.",
    },
    "static_analysis": {
        "category": "Static security and supply chain",
        "question": "Did the required format, serialization, code, secret, malware, SBOM, dependency, and binary checks complete?",
        "method": "Evaluate digest-bound ShakerScan evidence produced by built-ins and applicable ModelScan, Fickling, Semgrep, and Trivy adapters.",
        "remediation": "Run every applicable required scanner against the complete snapshot with current rules/databases and resolve all non-pass results.",
    },
    "license_compliance": {
        "category": "Licensing and attribution",
        "question": "Were model, repository, dependency, dataset, and intended-use terms identified without an unresolved license-policy trigger?",
        "method": "Reconcile publisher declarations, native license fingerprints, Trivy evidence, dataset lineage, and use restrictions under the configured license policy.",
        "remediation": "Review the License BOM and notices draft, then resolve unknown, custom, reciprocal, dataset-related, conflicting, or use-case-dependent terms.",
    },
    "runtime_execution": {
        "category": "Isolated runtime",
        "question": "Is signed exact-subject runtime evidence attached?",
        "method": "Verify trusted generated runtime evidence and its expiry and subject bindings.",
        "remediation": "Run the exact deployment bundle in the approved Firecracker/KVM runner and attach its signed receipt.",
    },
    "embedding_evaluation": {
        "category": "Embedding behavior",
        "question": "Did exact-subject known-answer and embedding evaluation pass?",
        "method": "Verify generated evaluation evidence bound to the runtime and artifact digests without retaining vectors.",
        "remediation": "Run approved known-answer, stability, robustness, and embedding-quality tests against the exact subject.",
    },
    "data_plane_evaluation": {
        "category": "Application integration",
        "question": "Did the intended vector-store and knowledge-graph authorization path pass?",
        "method": "Verify trusted generated observations for ACL, tenant, graph, cache, deletion, and index/model compatibility controls.",
        "remediation": "Run the data-plane test contract with representative principals, tenants, index, graph, and deletion flows.",
    },
    "firecracker_runtime": {
        "category": "Isolated runtime",
        "question": "Did import, tokenizer, load, warmup, inference, and teardown complete in Firecracker?",
        "method": "Inspect the exact-subject runner job and each fixed guest phase result.",
        "remediation": "Complete every required phase on a ready KVM host; there is no production fallback.",
    },
    "network_isolation": {
        "category": "Runtime containment",
        "question": "Was egress prevented and were network attempts independently observed without telemetry loss?",
        "method": "Correlate guest syscall telemetry, interface inventories, no-NIC configuration, and host firewall counters.",
        "remediation": "Investigate every attempted operation or telemetry gap and rerun with complete guest and host measurements.",
    },
    "resource_envelope": {
        "category": "Runtime containment",
        "question": "Did the model remain inside the host-enforced CPU, memory, PID, file, and time envelope?",
        "method": "Verify complete host cgroup measurements and configured limits from the signed runner receipt.",
        "remediation": "Set an approved resource envelope and rerun until measurements are complete and within policy.",
    },
    "conversion_equivalence": {
        "category": "Unsafe-format remediation",
        "question": "When conversion was required, did safetensors conversion and exact equivalence pass?",
        "method": "Verify fixed conversion, tensor/numeric equivalence, embedding equivalence, new identity registration, and target rescan evidence.",
        "remediation": "Convert in Firecracker, prove equivalence, register the new digest, rescan it, and qualify the converted runtime separately.",
    },
    "frozen_evidence": {
        "category": "Evidence integrity",
        "question": "Was the complete current evidence set frozen into an immutable digest-bound manifest?",
        "method": "Verify the latest authoritative evidence-manifest record and digest.",
        "remediation": "Freeze the current exact-subject evidence after all required checks complete.",
    },
    "human_approvals": {
        "category": "Governance",
        "question": "Are required identity-separated approvals current and bound to the latest evidence?",
        "method": "Validate approver role, distinct identity, decision, evidence-manifest binding, expiry, and revocation state.",
        "remediation": "Obtain the missing independent approvals against the latest frozen evidence manifest.",
    },
    "deterministic_policy": {
        "category": "Governance",
        "question": "Did the server-owned deterministic policy allow the latest frozen evidence?",
        "method": "Verify the stored decision, policy identity, decision digest, and latest-manifest binding.",
        "remediation": "Resolve blocking policy facts, refreeze changed evidence, and evaluate the server-owned policy again.",
    },
    "signed_admission": {
        "category": "Release authority",
        "question": "Is there an active, trusted, exact-subject signed admission?",
        "method": "Cryptographically verify the statement, decision, component digests, environment, expiry, registry state, and current-record parity.",
        "remediation": "Promote only after an allow decision; configure deployment to reject missing, stale, revoked, expired, or digest-mismatched admissions.",
    },
}


SHAKERSCAN_CHECK_CATALOG: list[dict[str, Any]] = [
    {"id": "MI-01", "category": "Source", "check": "Source resolution and revision pinning", "description": "Resolve the model repository and bind the review to an immutable revision.", "implementation": "native provider adapter", "applies_when": "all sources", "evidence_controls": ["immutable_subjects"]},
    {"id": "MI-02", "category": "Acquisition", "check": "Complete acquisition", "description": "Acquire the complete artifact within byte limits and detect truncation or oversize files.", "implementation": "native streaming acquisition", "applies_when": "full review", "evidence_controls": ["immutable_subjects"]},
    {"id": "MI-03", "category": "Integrity", "check": "SHA-256 integrity", "description": "Hash the acquired artifact and compare registry or supplied digests.", "implementation": "native", "applies_when": "all artifacts", "evidence_controls": ["immutable_subjects"]},
    {"id": "MI-04", "category": "Repository", "check": "Repository completeness", "description": "Verify expected repository members with safe paths, sizes, and hashes.", "implementation": "native provider manifest", "applies_when": "provider supports authoritative snapshots", "evidence_controls": ["immutable_subjects"]},
    {"id": "MI-05", "category": "Format", "check": "Format identification", "description": "Recognize safetensors, PyTorch/pickle, ONNX, GGUF, archives, and supported formats.", "implementation": "native", "applies_when": "all artifacts", "evidence_controls": ["static_analysis"], "reported_check": "format_specific_inspection"},
    {"id": "MI-06", "category": "Format", "check": "Safetensors validation", "description": "Validate headers, tensor metadata, offsets, bounds, overlap, and structure.", "implementation": "native + official parser", "applies_when": "safetensors is present", "evidence_controls": ["static_analysis"], "reported_check": "format_specific_inspection"},
    {"id": "MI-07", "category": "Serialization", "check": "Pickle analysis", "description": "Inspect pickle opcodes and dangerous callable references without loading the model.", "implementation": "native bounded parser", "applies_when": "pickle-capable serialization is present", "evidence_controls": ["static_analysis"], "scanner_name": "python-pickletools"},
    {"id": "MI-08", "category": "Archive", "check": "Archive safety", "description": "Recursively inspect ZIP/TAR paths, nesting, expansion limits, and archive bombs.", "implementation": "native bounded parser", "applies_when": "archives are present", "evidence_controls": ["static_analysis"], "reported_check": "format_specific_inspection"},
    {"id": "MI-09", "category": "Scanner", "check": "ModelScan", "description": "Detect known unsafe or malicious model serialization patterns.", "implementation": "ModelScan adapter", "applies_when": "adapter declares applicability", "evidence_controls": ["static_analysis"], "scanner_name": "modelscan"},
    {"id": "MI-10", "category": "Scanner", "check": "Fickling", "description": "Perform semantic analysis of applicable pickle artifacts.", "implementation": "Fickling adapter", "applies_when": "Fickling supports the pickle artifact", "evidence_controls": ["static_analysis"], "scanner_name": "fickling"},
    {"id": "MI-11", "category": "Scanner", "check": "Semgrep", "description": "Review repository code for deserialization, execution, network, imports, and risky file access.", "implementation": "versioned Semgrep rules", "applies_when": "repository code is present", "evidence_controls": ["static_analysis"], "scanner_name": "semgrep"},
    {"id": "MI-12", "category": "Scanner", "check": "Trivy", "description": "Check dependencies and repository content with the packaged offline vulnerability and license data.", "implementation": "offline Trivy adapter", "applies_when": "complete repository or dependency manifests are present", "evidence_controls": ["static_analysis", "license_compliance"], "scanner_name": "trivy"},
    {"id": "MI-12A", "category": "Dependencies", "check": "Inference dependency resolution", "description": "Derive Python imports from repository code and model-card examples, then map them to the exact hash-locked Firecracker runtime without installing model-authored input.", "implementation": "native AST + reviewed runtime lock", "applies_when": "complete Python model repository", "evidence_controls": ["static_analysis"], "scanner_name": "shakerscan-runtime-dependencies"},
    {"id": "MI-12B", "category": "Scanner", "check": "OSV Scanner", "description": "Check exact resolved Python packages against a packaged offline OSV database.", "implementation": "offline OSV Scanner adapter", "applies_when": "resolved runtime dependency evidence exists", "evidence_controls": ["static_analysis"], "scanner_name": "osv-scanner"},
    {"id": "MI-12C", "category": "Scanner", "check": "pip-audit", "description": "Audit the exact fixed Firecracker Python runtime using a release-build-captured pip-audit result; never resolve or install model-authored requirements.", "implementation": "hash-bound offline pip-audit adapter", "applies_when": "resolved runtime dependency evidence matches the fixed profile", "evidence_controls": ["static_analysis"], "scanner_name": "pip-audit"},
    {"id": "MI-13", "category": "Source", "check": "Native Python AST analysis", "description": "Identify executable custom code, suspicious imports, calls, templates, and load-time behavior.", "implementation": "native AST parser", "applies_when": "Python code is present", "evidence_controls": ["static_analysis"], "scanner_name": "python-ast-security"},
    {"id": "MI-14", "category": "Dependencies", "check": "Dependency inventory", "description": "Discover declared runtime packages and assess reproducible custom-code dependency coverage.", "implementation": "native manifest reconciliation", "applies_when": "dependency declarations or custom code are present", "evidence_controls": ["static_analysis"], "reported_check": "sbom_dependencies"},
    {"id": "MI-15", "category": "Inventory", "check": "SBOM and AIBOM generation", "description": "Produce CycloneDX, SPDX, and AI inventories with explicit completeness.", "implementation": "native evidence composer", "applies_when": "scan evidence exists", "evidence_controls": ["static_analysis"], "scanner_name": "shakerscan-sbom"},
    {"id": "MI-16", "category": "Governance", "check": "License and governance metadata", "description": "Reconcile licenses, intended use, restrictions, lineage, monitoring, and review evidence.", "implementation": "native policy + Trivy license evidence", "applies_when": "full review", "evidence_controls": ["license_compliance"]},
    {"id": "MI-17", "category": "Trust", "check": "Signature and attestation verification", "description": "Validate signatures, trust anchors, subject digests, DSSE/in-toto attestations, and bindings.", "implementation": "native cryptographic verifier", "applies_when": "configured or required by policy", "evidence_controls": ["static_analysis"], "reported_check": "signature_verification"},
    {"id": "MI-18", "category": "Conversion", "check": "Unsafe-format conversion", "description": "Convert eligible pickle weights to safetensors in Firecracker.", "implementation": "fixed Firecracker converter", "applies_when": "unsafe eligible weights are present", "evidence_controls": ["conversion_equivalence"]},
    {"id": "MI-19", "category": "Conversion", "check": "Conversion equivalence", "description": "Compare tensor inventory, shapes, dtypes, values, and embeddings.", "implementation": "fixed Firecracker evaluator", "applies_when": "conversion runs", "evidence_controls": ["conversion_equivalence"]},
    {"id": "MI-20", "category": "Runtime", "check": "Isolated model loading", "description": "Import the fixed loader, tokenizer, and model inside a no-NIC Firecracker microVM.", "implementation": "Firecracker/KVM", "applies_when": "runtime qualification is required", "evidence_controls": ["runtime_execution", "firecracker_runtime"]},
    {"id": "MI-21", "category": "Runtime", "check": "Warmup and inference", "description": "Perform bounded inference with ShakerScan's fixed embedding harness.", "implementation": "Firecracker/KVM", "applies_when": "runtime qualification runs", "evidence_controls": ["firecracker_runtime"]},
    {"id": "MI-22", "category": "Evaluation", "check": "Known-answer repeatability", "description": "Calibrate an embedding digest and verify it in a separate Firecracker execution.", "implementation": "deterministic evaluator", "applies_when": "runtime qualification runs", "evidence_controls": ["embedding_evaluation"]},
    {"id": "MI-23", "category": "Containment", "check": "Network monitoring", "description": "Block egress and classify local IPC, socket activity, DNS, and outbound destination attempts.", "implementation": "guest syscall + host namespace/firewall telemetry", "applies_when": "Firecracker executes", "evidence_controls": ["network_isolation"]},
    {"id": "MI-24", "category": "Containment", "check": "Resource enforcement", "description": "Enforce and measure CPU, memory, processes, file size, and execution time.", "implementation": "host cgroup + jailer limits", "applies_when": "Firecracker executes", "evidence_controls": ["resource_envelope"]},
    {"id": "MI-25", "category": "Evidence", "check": "Evidence integrity", "description": "Bind scanner, snapshot, runtime, and component hashes into signed receipts.", "implementation": "native evidence control plane", "applies_when": "controlled review", "evidence_controls": ["frozen_evidence"]},
    {"id": "MI-26", "category": "Decision", "check": "Deterministic policy decision", "description": "Return ALLOW, BLOCK, INCOMPLETE, or REVIEW without caller or AI override.", "implementation": "server-owned policy", "applies_when": "controlled admission", "evidence_controls": ["deterministic_policy"]},
    {"id": "MI-27", "category": "Deployment follow-up", "check": "Corporate-approval gap analysis", "description": "List human, legal, privacy, publisher, production-signing, and deployed-system checks outside Model Intake.", "implementation": "native report catalog", "applies_when": "every complete report", "evidence_controls": []},
]


EXTERNAL_APPROVAL_REQUIREMENTS: list[dict[str, str]] = [
    {"id": "CORP-01", "category": "Business governance", "requirement": "Document the intended use, prohibited uses, business owner, affected users, impact tier, and organizational risk tolerance.", "why_external": "Only the organization can define acceptable use and business impact.", "typical_owner": "Business owner / AI governance", "expected_evidence": "Approved use-case and risk-classification record"},
    {"id": "CORP-02", "category": "Legal and intellectual property", "requirement": "Approve model, code, dataset, and dependency licenses, terms of use, redistribution, patent, copyright, and indemnity obligations.", "why_external": "Inventory can be automated; legal interpretation and acceptance cannot.", "typical_owner": "Legal / procurement", "expected_evidence": "Legal opinion or approved license review"},
    {"id": "CORP-03", "category": "Training data", "requirement": "Assess training/fine-tuning data lineage, collection rights, consent, quality, poisoning risk, and contractual restrictions.", "why_external": "Published declarations are not proof of dataset rights or training integrity.", "typical_owner": "Data governance / legal / model owner", "expected_evidence": "Dataset lineage and data-rights assessment"},
    {"id": "CORP-04", "category": "Privacy", "requirement": "Complete privacy impact, sensitive-data, memorization/inference, retention, residency, and cross-border transfer review.", "why_external": "The answer depends on corporate data, jurisdictions, and deployment design.", "typical_owner": "Privacy / data protection officer", "expected_evidence": "DPIA/PIA and approved data-handling controls"},
    {"id": "CORP-05", "category": "Safety, fairness, and human impact", "requirement": "Evaluate context-specific safety, harmful bias, accessibility, explainability, human oversight, and failure impact where applicable.", "why_external": "These properties require representative users, tasks, harms, and acceptance thresholds.", "typical_owner": "Responsible AI / product risk", "expected_evidence": "Use-case TEVV and residual-risk disposition"},
    {"id": "CORP-06", "category": "Fitness and capacity", "requirement": "Approve representative retrieval quality, latency, throughput, memory, availability, and cost thresholds for the intended workload.", "why_external": "ShakerScan can execute a supplied benchmark but cannot define a representative corporate benchmark.", "typical_owner": "ML platform / application owner", "expected_evidence": "Versioned benchmark, thresholds, results, and capacity plan"},
    {"id": "CORP-07", "category": "System threat model", "requirement": "Threat-model and, where warranted, red-team the complete application, ingestion pipeline, vector store, knowledge graph, APIs, identities, and downstream LLM—not only the model file.", "why_external": "Model Intake cannot infer the complete deployed architecture or its abuse cases.", "typical_owner": "Security architecture / application security", "expected_evidence": "Approved threat model and scoped security test report"},
    {"id": "CORP-08", "category": "Platform security", "requirement": "Approve production IAM, network segmentation, secrets/KMS, image and host hardening, registry controls, logging access, backup, and tenancy design.", "why_external": "These controls live in organization-operated infrastructure.", "typical_owner": "Cloud/platform security", "expected_evidence": "Deployment architecture and inherited-control assessment"},
    {"id": "CORP-09", "category": "Operational assurance", "requirement": "Implement production monitoring for availability, drift, abuse, anomalous resource/network behavior, CVEs, upstream changes, and policy/rule freshness.", "why_external": "A point-in-time intake cannot prove ongoing production operation.", "typical_owner": "MLOps / SRE / security operations", "expected_evidence": "Monitoring, alerting, ownership, and reassessment plan"},
    {"id": "CORP-10", "category": "Response and lifecycle", "requirement": "Test incident response, revocation, rollback, reindex, deletion, retention, recovery, supplier compromise, and decommissioning.", "why_external": "These are organization-specific operational processes and dependent-system actions.", "typical_owner": "Incident response / MLOps / data owner", "expected_evidence": "Tested runbooks and recovery/deletion receipts"},
    {"id": "CORP-11", "category": "Third-party risk", "requirement": "Complete publisher/vendor due diligence, support and disclosure review, ownership-change monitoring, and contractual risk treatment.", "why_external": "Repository metadata and scanner output do not establish supplier assurance.", "typical_owner": "Third-party risk / procurement", "expected_evidence": "Vendor risk assessment and monitoring decision"},
    {"id": "CORP-12", "category": "Regulatory and compliance", "requirement": "Map applicable sector, data, AI, export, records, accessibility, and assurance obligations to controls and evidence.", "why_external": "Applicability depends on entity, jurisdiction, use, users, and data.", "typical_owner": "Compliance / legal", "expected_evidence": "Applicability assessment and control mapping"},
    {"id": "CORP-13", "category": "Release authority", "requirement": "Require the real deployment path to enforce the approved exact digest and active lifecycle state; test bypass, outage, expiry, revocation, and recovery.", "why_external": "ShakerScan ships verifiers, but the organization controls whether production actually invokes one.", "typical_owner": "Release engineering / platform owner", "expected_evidence": "Deployment-enforcement acceptance receipt"},
    {"id": "CORP-14", "category": "Risk decision", "requirement": "Record residual-risk acceptance or rejection, exception scope, compensating controls, accountable owner, approver, and expiry.", "why_external": "A scanner may inform but cannot own the organization's risk decision.", "typical_owner": "Authorizing official / risk owner", "expected_evidence": "Signed risk decision and expiring exceptions"},
]


def _json(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
            return decoded if isinstance(decoded, type(default)) else default
        except json.JSONDecodeError:
            return default
    return default


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    text = str(value or "").strip()
    return text or None


def _timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _sha256(value: Any) -> bool:
    text = str(value or "").lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def _normalize_status(value: Any, *, absent: str = "NOT_RUN") -> str:
    status = str(value or "").strip().upper().replace("-", "_").replace(" ", "_")
    if not status:
        return absent
    if status in {"PASS", "PASSED", "SIGNED", "ACTIVE", "ALLOW", "APPROVED", "READY"}:
        return "PASS"
    if status in {"FAIL", "FAILED", "BLOCK", "BLOCKED", "REJECT", "REJECTED", "REVOKED", "DENIED"}:
        return "FAIL"
    if status in {"REVIEW", "WARNING", "REVIEW_REQUIRED", "AWAITING_APPROVAL", "POLICY_DECIDED"}:
        return "REVIEW"
    if status in {"INCOMPLETE", "TRUNCATED", "UNSUPPORTED", "NOT_READY", "UNAVAILABLE", "STALE"}:
        return "INCOMPLETE"
    if status in {"ERROR", "CRASHED", "TIMEOUT", "TIMED_OUT"}:
        return "ERROR"
    if status in {"NOT_RUN", "SKIPPED", "PENDING", "RUNNING", "SUBMITTED"}:
        return "NOT_RUN"
    if status in {"NOT_APPLICABLE", "N/A", "NA"}:
        return "NOT_APPLICABLE"
    if status == "COMPLETED":
        return "PASS"
    return "INCOMPLETE"


def _latest(rows: Iterable[dict[str, Any]], key: str, value: str) -> dict[str, Any] | None:
    matches = [row for row in rows if str(row.get(key) or "") == value]
    return matches[-1] if matches else None


def _evidence_control(
    submission_id: str,
    evidence: list[dict[str, Any]],
    evidence_type: str,
    label: str,
    now: datetime,
) -> dict[str, Any]:
    record = _latest(evidence, "evidence_type", evidence_type)
    if not record:
        return {
            "id": evidence_type,
            "label": label,
            "status": "NOT_RUN",
            "detail": f"No {evidence_type.replace('_', ' ')} evidence is attached.",
            "coverage": {},
            "evidence_refs": [],
        }
    status = _normalize_status(record.get("status"))
    expiry = _timestamp(record.get("expires_at"))
    if expiry is not None and expiry <= now:
        status = "INCOMPLETE"
    provenance = str(record.get("provenance_class") or "unknown")
    bindings = _json(record.get("subject_bindings"), {})
    payload = _json(record.get("payload_json"), {})
    detail = (
        f"{provenance} evidence expired at {_iso(expiry)}."
        if expiry is not None and expiry <= now
        else f"{provenance} evidence reported {record.get('status') or 'unknown'}."
    )
    additional_coverage: dict[str, Any] = {}
    if evidence_type == "embedding_evaluation" and payload:
        quality_status = payload.get("quality_status")
        containment_status = payload.get("containment_status")
        detail = (
            f"Known-answer embedding evaluation: {quality_status or 'unknown'}; "
            f"runtime containment: {containment_status or 'unknown'} (reported separately)."
        )
        additional_coverage = {
            "quality_status": quality_status,
            "containment_status": containment_status,
            "embedding_shape": payload.get("embedding_shape"),
            "benchmark_dataset_sha256": payload.get("benchmark_dataset_sha256"),
            "thresholds_sha256": payload.get("thresholds_sha256"),
            "embedding_output_sha256": payload.get("embedding_output_sha256"),
            "evaluation_blockers": payload.get("blockers") or [],
            "containment_blockers": payload.get("containment_blockers") or [],
        }
    return {
        "id": evidence_type,
        "label": label,
        "status": status,
        "detail": detail,
        "coverage": {
            "provenance_class": provenance,
            "producer_id": record.get("producer_id"),
            "builder_id": record.get("builder_id"),
            "payload_sha256": record.get("payload_sha256"),
            "subject_bindings": bindings,
            "expires_at": _iso(expiry),
            **additional_coverage,
        },
        "evidence_refs": [{
            "kind": "evidence_record",
            "id": str(record.get("id") or ""),
            "uri": f"/model-intake/submissions/{submission_id}#evidence-{record.get('id')}",
        }],
    }


def _runner_observations(job: dict[str, Any]) -> dict[str, Any]:
    result = _json(job.get("result_json"), {})
    payload = _json(result.get("payload"), {})
    return _json(payload.get("observations"), {})


def _network_summary(network: dict[str, Any]) -> dict[str, Any]:
    """Keep the report useful without copying the full syscall stream into it.

    The signed receipt remains the authoritative, complete evidence object.  A
    corporate report needs the decision-driving counts and a small sample, not
    hundreds of repetitive AF_UNIX probes emitted by framework libraries.
    """
    observed = network.get("observed_operations")
    if not isinstance(observed, list):
        # Compatibility with v1 receipts, where attempted_operations contained
        # every traced socket syscall rather than only outbound attempts.
        observed = network.get("attempted_operations")
    observed = observed if isinstance(observed, list) else []
    attempts = [
        raw for raw in observed
        if isinstance(raw, dict)
        and (
            raw.get("outbound_attempt") is True
            or (
                str(raw.get("address_family") or "") in {"AF_INET", "AF_INET6"}
                and str(raw.get("operation") or "") in {"connect", "sendto", "sendmsg"}
            )
        )
    ]
    by_family: dict[str, int] = {}
    by_operation: dict[str, int] = {}
    local_ipc_count = 0
    ip_network_count = 0
    successful_outbound_count = 0
    dns_attempt_count = 0
    for raw in observed:
        item = raw if isinstance(raw, dict) else {}
        family = str(item.get("address_family") or "UNKNOWN")
        operation = str(item.get("operation") or "unknown")
        by_family[family] = by_family.get(family, 0) + 1
        by_operation[operation] = by_operation.get(operation, 0) + 1
        if family == "AF_UNIX":
            local_ipc_count += 1
        elif family in {"AF_INET", "AF_INET6"}:
            ip_network_count += 1
    for raw in attempts:
        item = raw if isinstance(raw, dict) else {}
        if item.get("succeeded") is True:
            successful_outbound_count += 1
        if item.get("dns_related") is True or item.get("destination_port") == 53:
            dns_attempt_count += 1
    return {
        "complete": network.get("complete"),
        "event_count": network.get("event_count", len(observed)),
        "outbound_attempt_count": len(attempts),
        "successful_outbound_count": network.get("successful_outbound_count", successful_outbound_count),
        "dns_attempt_count": network.get("dns_attempt_count", dns_attempt_count),
        "local_ipc_event_count": network.get("local_ipc_event_count", local_ipc_count),
        "ip_socket_event_count": network.get("ip_socket_event_count", ip_network_count),
        "attempts_by_family": dict(sorted(by_family.items())),
        "attempts_by_operation": dict(sorted(by_operation.items())),
        "attempts_by_phase": network.get("attempts_by_phase"),
        "attempt_sample": attempts[:12],
        "attempt_sample_truncated": len(attempts) > 12,
        "overflowed": network.get("overflowed"),
        "lost_events": network.get("lost_events"),
        "guest_interfaces": network.get("guest_interfaces"),
        "host_interfaces": network.get("host_interfaces"),
        "host_firewall_drop_count": network.get("host_firewall_drop_count"),
        "telemetry_sha256": network.get("telemetry_sha256"),
    }


def _runner_timelines(jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for job in jobs:
        operation = str(job.get("operation") or "")
        observations = _runner_observations(job)
        phases = _json(observations.get("phases"), {})
        phase_rows = []
        for name, raw in phases.items():
            value = raw if isinstance(raw, dict) else {"status": raw}
            normalized = _normalize_status(value.get("status"))
            detail = value.get("error") or value.get("detail")
            # Calibration intentionally runs inference without a pre-existing
            # digest. The guest preserves that as a raw FAIL/NOT_CONFIGURED so
            # it can never be mistaken for repeat verification. In the human
            # timeline, describe the successful digest capture accurately;
            # the subsequent runtime job remains the pass/fail assertion.
            if (
                operation == "calibration"
                and str(name) == "inference"
                and observations.get("embedding_known_answers_status") == "NOT_CONFIGURED"
                and observations.get("embedding_output_sha256")
            ):
                normalized = "CALIBRATED"
                detail = "Embedding digest recorded; repeat verification is reported by the separate runtime job."
            phase_rows.append({
                "phase": str(name),
                "status": normalized,
                "raw_status": value.get("status"),
                "duration_ms": value.get("duration_ms"),
                "detail": detail,
            })
        network = _json(observations.get("network_telemetry"), {})
        resources = _json(observations.get("resource_telemetry"), {})
        output.append({
            "job_id": str(job.get("id") or ""),
            "operation": operation,
            "state": job.get("state"),
            "request_sha256": job.get("request_sha256"),
            "started_at": _iso(job.get("started_at")),
            "finished_at": _iso(job.get("finished_at")),
            "phases": phase_rows,
            "network": _network_summary(network),
            "resources": resources,
            "error": _json(job.get("error_json"), {}),
        })
    return output


def _runner_controls(
    timelines: list[dict[str, Any]],
    *,
    conversion_required: bool,
) -> list[dict[str, Any]]:
    runtime = next((item for item in reversed(timelines) if item.get("operation") == "runtime"), None)
    conversion = next((item for item in reversed(timelines) if item.get("operation") == "conversion"), None)
    if not runtime:
        runtime_control = {
            "id": "firecracker_runtime",
            "label": "Firecracker runtime execution",
            "status": "NOT_RUN",
            "detail": "No exact-subject Firecracker runtime job has completed.",
            "coverage": {},
            "evidence_refs": [],
        }
        network_control = {
            "id": "network_isolation",
            "label": "Independent network-attempt telemetry",
            "status": "NOT_RUN",
            "detail": "Runtime network telemetry was not generated.",
            "coverage": {},
            "evidence_refs": [],
        }
        resource_control = {
            "id": "resource_envelope",
            "label": "Host-enforced resource envelope",
            "status": "NOT_RUN",
            "detail": "Runtime resource telemetry was not generated.",
            "coverage": {},
            "evidence_refs": [],
        }
    else:
        phases = runtime.get("phases") or []
        state_status = _normalize_status(runtime.get("state"))
        phase_statuses = {str(item.get("status")) for item in phases}
        runtime_status = (
            "ERROR" if state_status in {"FAIL", "ERROR"}
            else "PASS" if phases and phase_statuses <= {"PASS"}
            else "INCOMPLETE"
        )
        ref = [{"kind": "runner_job", "id": runtime["job_id"]}]
        runtime_control = {
            "id": "firecracker_runtime",
            "label": "Firecracker runtime execution",
            "status": runtime_status,
            "detail": f"{len(phases)} required phase result(s) recorded for the exact subject.",
            "coverage": {"phases": len(phases), "request_sha256": runtime.get("request_sha256")},
            "evidence_refs": ref,
        }
        network = runtime.get("network") or {}
        network_summary = (
            network if "outbound_attempt_count" in network
            else _network_summary(network)
        )
        attempt_count = _integer(network_summary.get("outbound_attempt_count"))
        lost_events = _integer(network_summary.get("lost_events"))
        firewall_drops = _integer(network_summary.get("host_firewall_drop_count"))
        network_status = (
            "PASS"
            if network_summary.get("complete") is True
            and attempt_count == 0
            and network_summary.get("overflowed") is False
            and lost_events == 0
            and firewall_drops == 0
            else "FAIL"
            if (attempt_count is not None and attempt_count > 0)
            or (firewall_drops is not None and firewall_drops > 0)
            else "ERROR"
        )
        network_control = {
            "id": "network_isolation",
            "label": "Independent network-attempt telemetry",
            "status": network_status,
            "detail": (
                "No outbound or DNS connection attempt was observed; "
                f"{_integer(network_summary.get('local_ipc_event_count')) or 0} local IPC event(s) and "
                f"{_integer(network_summary.get('ip_socket_event_count')) or 0} IP socket-setup event(s) "
                "were classified with no telemetry loss."
                if network_status == "PASS"
                else "Outbound attempts or incomplete/lost telemetry require blocking review."
            ),
            "coverage": network_summary,
            "evidence_refs": ref,
        }
        resources = runtime.get("resources") or {}
        resource_status = "PASS" if resources.get("complete") is True else "ERROR"
        resource_control = {
            "id": "resource_envelope",
            "label": "Host-enforced resource envelope",
            "status": resource_status,
            "detail": "Host cgroup measurements are complete." if resource_status == "PASS" else "Host resource telemetry is incomplete.",
            "coverage": resources,
            "evidence_refs": ref,
        }
    conversion_control = {
        "id": "conversion_equivalence",
        "label": "Unsafe-format conversion and equivalence",
        "status": ("NOT_RUN" if conversion_required else "NOT_APPLICABLE") if not conversion else (
            "PASS" if _normalize_status(conversion.get("state")) == "PASS"
            and all(item.get("status") == "PASS" for item in conversion.get("phases") or [])
            else "ERROR"
        ),
        "detail": (
            "Unsafe-format conversion is required but has not run."
            if conversion_required and not conversion
            else "No conversion was required."
            if not conversion
            else "Fixed tensor and embedding equivalence phases passed; network containment is reported separately."
            if all(item.get("status") == "PASS" for item in conversion.get("phases") or [])
            else "One or more fixed conversion/equivalence phases did not pass."
        ),
        "coverage": {} if not conversion else {
            "phases": len(conversion.get("phases") or []),
            "network": conversion.get("network") or {},
        },
        "evidence_refs": [] if not conversion else [{"kind": "runner_job", "id": conversion["job_id"]}],
    }
    return [runtime_control, network_control, resource_control, conversion_control]


def _enrich_control(control: dict[str, Any]) -> dict[str, Any]:
    detail = CONTROL_DETAILS.get(str(control.get("id") or ""), {})
    return {
        **control,
        "category": detail.get("category", "Other"),
        "question": detail.get("question", str(control.get("label") or "")),
        "method": detail.get("method", "Inspect authoritative digest-bound evidence."),
        "remediation": control.get("remediation") or detail.get(
            "remediation", "Resolve the non-pass result and generate fresh authoritative evidence."
        ),
    }


def _static_check_detail(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    record = _latest(evidence, "evidence_type", "static_analysis")
    payload = _json(record.get("payload_json"), {}) if record else {}
    required = _json(payload.get("required_static_checks"), {})
    checks = _json(payload.get("checks"), {})
    scanner_results = payload.get("scanner_results") if isinstance(payload.get("scanner_results"), list) else []
    return {
        "available": bool(payload),
        "evidence_record_id": str(record.get("id") or "") if record else None,
        "required_checks": [
            {
                "id": str(name),
                "status": "PASS" if value is True else "FAIL" if value is False else "INCOMPLETE",
            }
            for name, value in sorted(required.items())
        ],
        "reported_checks": [
            {
                "id": str(name),
                "status": "PASS" if value is True else "FAIL" if value is False else "NOT_RUN",
            }
            for name, value in sorted(checks.items())
        ],
        "scanner_results": [
            {
                "name": str(item.get("name") or "unknown"),
                "status": _normalize_status(item.get("status")),
                "raw_status": item.get("status"),
                "required": bool(item.get("required")),
                "applicability": item.get("applicability"),
                "finding_count": _integer(item.get("finding_count")),
                "findings": [
                    {
                        key: finding.get(key)
                        for key in (
                            "id", "rule_id", "severity", "classification", "call",
                            "path", "line", "message", "package", "installed_version",
                            "severity_source", "import_name", "evidence_class",
                        )
                        if finding.get(key) is not None
                    }
                    for finding in item.get("findings") or []
                    if isinstance(finding, dict)
                ][:100],
                "coverage": _json(item.get("coverage"), {}),
                "version": item.get("version"),
                "rules_sha256": item.get("rules_sha256"),
                "database_sha256": item.get("database_sha256"),
            }
            for item in scanner_results if isinstance(item, dict)
        ],
        "license_compliance": _json(payload.get("license_compliance"), {}),
        "runtime_dependencies": _json(payload.get("runtime_dependencies"), {}),
        "vulnerability_summary": _json(payload.get("vulnerability_summary"), {}),
        "vulnerability_inventory": [
            item for item in payload.get("vulnerability_inventory") or []
            if isinstance(item, dict)
        ],
        "note": (
            "Per-check static evidence is available and content-free."
            if payload
            else "This evidence predates per-check report summaries; inspect the referenced scan result for scanner-level detail."
        ),
    }


def _check_catalog_with_evidence(
    controls: list[dict[str, Any]],
    static_detail: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    by_id = {str(item.get("id") or ""): item for item in controls}
    reported_checks = {
        str(item.get("id") or ""): item
        for item in _json(static_detail or {}, {}).get("reported_checks") or []
        if isinstance(item, dict)
    }
    scanner_results = {
        str(item.get("name") or "").strip().casefold(): item
        for item in _json(static_detail or {}, {}).get("scanner_results") or []
        if isinstance(item, dict)
    }
    priority = {
        "FAIL": 0, "ERROR": 1, "INCOMPLETE": 2, "NOT_RUN": 3,
        "REVIEW": 4, "PASS": 5, "NOT_APPLICABLE": 6,
    }
    rows: list[dict[str, Any]] = []
    for catalog_item in SHAKERSCAN_CHECK_CATALOG:
        related = [by_id[item] for item in catalog_item["evidence_controls"] if item in by_id]
        scanner = scanner_results.get(str(catalog_item.get("scanner_name") or "").casefold())
        reported = reported_checks.get(str(catalog_item.get("reported_check") or ""))
        if scanner:
            status = _normalize_status(scanner.get("status"))
            result_summary = (
                f"{scanner.get('name')} reported {status}; "
                f"{scanner.get('finding_count') if scanner.get('finding_count') is not None else 'unknown'} finding(s)."
            )
            evidence_basis = "scanner_result"
            execution_evidence = {
                key: scanner.get(key) for key in (
                    "name", "version", "rules_sha256", "database_sha256",
                    "finding_count", "applicability", "coverage",
                )
            }
        elif reported:
            status = _normalize_status(reported.get("status"))
            result_summary = (
                f"{catalog_item.get('check')} reported {status} in the generated static evidence."
            )
            evidence_basis = "reported_static_check"
            execution_evidence = {
                "check_id": reported.get("id"),
                "status": reported.get("status"),
            }
        elif related:
            status = min(
                (str(item.get("status") or "NOT_RUN") for item in related),
                key=lambda value: priority.get(value, 2),
            )
            result_summary = " ".join(
                f"{item.get('label')}: {item.get('status')} — {item.get('detail')}"
                for item in related
            )
            evidence_basis = "control_evidence"
            execution_evidence = {
                "control_ids": [item.get("id") for item in related],
                "evidence_refs": [
                    ref for item in related for ref in item.get("evidence_refs") or []
                ],
            }
        else:
            status = "PASS"
            result_summary = (
                f"The report includes {len(EXTERNAL_APPROVAL_REQUIREMENTS)} deployment and organization follow-up items."
            )
            evidence_basis = "report_generation"
            execution_evidence = {"external_requirement_count": len(EXTERNAL_APPROVAL_REQUIREMENTS)}
        rows.append({
            **catalog_item,
            "execution_status": status,
            "result_summary": result_summary,
            "evidence_basis": evidence_basis,
            "execution_evidence": execution_evidence,
            "evidence_statuses": [
                {"control_id": item.get("id"), "status": item.get("status")}
                for item in related
            ],
            "execution_note": (
                "This row reports submission evidence; applicability alone is never treated as proof of execution."
            ),
        })
    return rows


def _required_actions(controls: list[dict[str, Any]]) -> list[dict[str, str]]:
    priority = {"FAIL": 0, "ERROR": 1, "INCOMPLETE": 2, "NOT_RUN": 3, "REVIEW": 4}
    unresolved = [item for item in controls if str(item.get("status")) in priority]
    unresolved.sort(key=lambda item: (priority[str(item.get("status"))], str(item.get("id"))))
    return [
        {
            "control_id": str(item.get("id") or ""),
            "status": str(item.get("status") or ""),
            "action": str(item.get("remediation") or "Resolve the control and attach fresh evidence."),
        }
        for item in unresolved
    ]


def _presentation_summary(
    controls: list[dict[str, Any]],
    *,
    outcome: str,
    license_compliance: dict[str, Any],
    external_requirement_count: int,
    license_source_missing: bool = False,
) -> dict[str, Any]:
    """Build the human-facing summary without weakening machine policy semantics."""
    technical = [
        item for item in controls
        if str(item.get("id") or "") not in DEPLOYMENT_FOLLOW_UP_CONTROL_IDS
    ]
    verified = [item for item in technical if item.get("status") == "PASS"]
    needs_attention = [
        item for item in technical
        if item.get("status") in {"FAIL", "ERROR", "INCOMPLETE", "NOT_RUN", "REVIEW"}
    ]
    not_applicable = [item for item in technical if item.get("status") == "NOT_APPLICABLE"]
    follow_up = [
        item for item in controls
        if str(item.get("id") or "") in DEPLOYMENT_FOLLOW_UP_CONTROL_IDS
    ]
    headline = {
        "PASS": "Technical checks passed",
        "ALLOW": "Configured checks passed",
        "BLOCK": "Do not use this revision yet",
        "INCOMPLETE": "Review could not finish",
        "REVIEW": "Review findings before use",
        "REVIEW_REQUIRED": "Review findings before use",
    }.get(str(outcome or "").upper(), "Review results available")
    if bool(license_compliance.get("legal_review_required")):
        license_note = (
            "One or more license terms need specialist review. See the License BOM for the exact "
            "components, evidence, and reason codes."
        )
    elif license_source_missing:
        license_note = (
            "The publisher declared permissive terms, but the pinned repository did not include the "
            "license or NOTICE source text. Obtain and preserve the authoritative text before distribution."
        )
    elif license_compliance.get("policy_status") == "PASS":
        license_note = (
            "License evidence was collected and no configured policy trigger was found. "
            "See the License BOM for component-level details."
        )
    else:
        license_note = (
            "License evidence is incomplete. See the License BOM for the missing declarations "
            "or component records."
        )
    return {
        "headline": headline,
        "decision": str(outcome or ""),
        "review_boundary": (
            "This result covers the pinned model revision and the technical checks selected for this run. "
            "Deployment follow-up is listed once in the appendix."
        ),
        "license_note": license_note,
        "groups": {
            "verified": [_presentation_control(item) for item in verified],
            "needs_attention": [_presentation_control(item) for item in needs_attention],
            "not_applicable": [_presentation_control(item) for item in not_applicable],
            "deployment_follow_up": [_presentation_control(item) for item in follow_up],
        },
        "counts": {
            "verified": len(verified),
            "needs_attention": len(needs_attention),
            "not_applicable": len(not_applicable),
            "deployment_follow_up": len(follow_up),
            "organization_checklist_items": external_requirement_count,
        },
    }


def _license_control_detail(license_compliance: dict[str, Any]) -> str:
    """Translate policy vocabulary into a concise engineer-facing result."""
    policy_status = str(license_compliance.get("policy_status") or "").upper()
    missing = [str(item) for item in license_compliance.get("missing_evidence") or [] if item]
    if policy_status == "PASS" and missing:
        return (
            "The publisher declaration did not trigger policy, but the repository is missing "
            "the authoritative license or NOTICE source text."
        )
    if policy_status == "PASS":
        return "Declared and detected license evidence did not trigger the configured license policy."
    if policy_status == "BLOCK":
        return "The configured license policy rejected one or more detected terms."
    if policy_status == "REVIEW_REQUIRED":
        return "One or more detected terms need a licensing review; see the License BOM for exact components and reasons."
    return "License evidence was not complete enough to evaluate the configured policy."


def _presentation_control(item: dict[str, Any]) -> dict[str, Any]:
    status = str(item.get("status") or "")
    if status == "PASS":
        follow_up = "Completed; exact evidence and hashes are available in the detailed matrix."
    elif status == "NOT_APPLICABLE":
        follow_up = "No action is required for this revision."
    else:
        follow_up = item.get("remediation")
    return {
        "id": item.get("id"),
        "label": item.get("label"),
        "category": item.get("category"),
        "status": item.get("status"),
        "result": item.get("detail"),
        "next_step": follow_up,
    }


def build_model_intake_report(
    *,
    submission: dict[str, Any],
    subjects: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    manifests: list[dict[str, Any]],
    approvals: list[dict[str, Any]],
    policy_decisions: list[dict[str, Any]],
    admissions: list[dict[str, Any]],
    events: list[dict[str, Any]],
    runner_jobs: list[dict[str, Any]],
    agent_sessions: list[dict[str, Any]],
    admission_verification: dict[str, Any] | None = None,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    now = (generated_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    submission_id = str(submission.get("id") or "")
    environment = str(submission.get("requested_environment") or "")
    subject_map = {str(row.get("subject_kind") or ""): row for row in subjects}
    artifact = subject_map.get("artifact")
    snapshot = subject_map.get("repository_snapshot")
    source_status = (
        "PASS" if artifact and snapshot and _sha256(artifact.get("sha256")) and _sha256(snapshot.get("sha256"))
        else "INCOMPLETE"
    )
    controls = [{
        "id": "immutable_subjects",
        "label": "Complete immutable artifact and repository subjects",
        "status": source_status,
        "detail": "Artifact and repository snapshot SHA-256 subjects are present." if source_status == "PASS" else "Artifact or complete repository snapshot subject is missing.",
        "coverage": {
            "artifact_sha256": artifact.get("sha256") if artifact else None,
            "repository_snapshot_sha256": snapshot.get("sha256") if snapshot else None,
            "artifact_size_bytes": artifact.get("size_bytes") if artifact else None,
        },
        "evidence_refs": [
            {"kind": "subject", "id": str(item.get("id") or "")}
            for item in (artifact, snapshot) if item
        ],
    }]
    for evidence_type, label in (
        ("static_analysis", "Generated static analysis and supply-chain checks"),
        ("runtime_execution", "Signed runtime execution evidence"),
        ("embedding_evaluation", "Embedding known-answer and runtime evaluation"),
        ("data_plane_evaluation", "Vector-store and knowledge-graph authorization evaluation"),
    ):
        controls.append(_evidence_control(submission_id, evidence, evidence_type, label, now))
    static_record = _latest(evidence, "evidence_type", "static_analysis")
    static_payload = _json(static_record.get("payload_json"), {}) if static_record else {}
    license_compliance = _json(static_payload.get("license_compliance"), {})
    license_policy_status = str(license_compliance.get("policy_status") or "")
    static_scanner_results = (
        static_payload.get("scanner_results")
        if isinstance(static_payload.get("scanner_results"), list)
        else []
    )
    license_source_missing = any(
        finding.get("id") == "license_file_missing"
        for scanner in static_scanner_results
        if isinstance(scanner, dict)
        for finding in scanner.get("findings") or []
        if isinstance(finding, dict)
    )
    license_evidence_missing = bool(license_compliance.get("missing_evidence")) or license_source_missing
    controls.append({
        "id": "license_compliance",
        "label": "License and attribution review",
        "status": (
            "REVIEW" if license_policy_status == "PASS" and license_evidence_missing
            else "PASS" if license_policy_status == "PASS"
            else "FAIL" if license_policy_status == "BLOCK"
            else "REVIEW" if license_policy_status == "REVIEW_REQUIRED"
            else "INCOMPLETE"
        ),
        "detail": _license_control_detail({
            **license_compliance,
            "missing_evidence": (
                license_compliance.get("missing_evidence")
                or (["repository license or notice file"] if license_source_missing else [])
            ),
        }),
        "remediation": (
            "Obtain the publisher's authoritative license/NOTICE text and preserve it with the pinned revision and any distribution."
            if license_policy_status == "PASS" and license_evidence_missing
            else "Review the exact component terms and reason codes in the License BOM."
        ),
        "coverage": {
            "policy_version": license_compliance.get("policy_version"),
            "classification_counts": license_compliance.get("classification_counts") or {},
            "reason_codes": license_compliance.get("reason_codes") or [],
            "evidence_sha256": license_compliance.get("evidence_sha256"),
        },
        "evidence_refs": [] if not static_record else [{
            "kind": "evidence_record",
            "id": str(static_record.get("id") or ""),
            "uri": f"/model-intake/submissions/{submission_id}#evidence-{static_record.get('id')}",
        }],
    })
    timelines = _runner_timelines(runner_jobs)
    artifact_uri = str(artifact.get("immutable_uri") or "").lower() if artifact else ""
    conversion_required = any(
        artifact_uri.split("?", 1)[0].endswith(extension)
        for extension in (".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".joblib")
    )
    runner_controls = _runner_controls(timelines, conversion_required=conversion_required)
    controls.extend(runner_controls)
    # A runtime receipt has one overall status that also covers network/resource
    # containment and receipt trust. The report exposes containment independently,
    # so a containment-only FAIL must not be double-counted as a model-load failure.
    # An INCOMPLETE/ERROR/REVIEW receipt is different: it can mean the receipt is
    # not admissibly trusted (for example, a production run signed by the local PEM
    # development tier). Preserve that non-pass even when every guest phase ran.
    firecracker_control = next(
        (item for item in runner_controls if item.get("id") == "firecracker_runtime"),
        None,
    )
    runtime_evidence_control = next(
        (item for item in controls if item.get("id") == "runtime_execution"),
        None,
    )
    if firecracker_control and runtime_evidence_control and runtime_evidence_control.get("status") != "NOT_RUN":
        execution_status = str(firecracker_control.get("status") or "INCOMPLETE")
        receipt_overall_status = str(runtime_evidence_control.get("status") or "INCOMPLETE")
        if execution_status != "PASS":
            runtime_status = execution_status
            runtime_detail = "One or more fixed exact-subject runtime phases did not pass."
        elif receipt_overall_status in {"INCOMPLETE", "ERROR", "REVIEW", "NOT_RUN"}:
            runtime_status = receipt_overall_status
            runtime_detail = (
                f"Exact-subject runtime phases passed, but the signed runtime evidence is "
                f"{receipt_overall_status}. Inspect receipt trust and completeness; network "
                "and resource containment are reported separately."
            )
        else:
            runtime_status = "PASS"
            runtime_detail = (
                "Exact-subject model load, warmup, inference, and teardown passed; "
                "runtime containment is reported by separate network and resource controls."
            )
        runtime_evidence_control["status"] = runtime_status
        runtime_evidence_control["detail"] = runtime_detail
        runtime_evidence_control["coverage"] = {
            **_json(runtime_evidence_control.get("coverage"), {}),
            "execution_status": execution_status,
            "receipt_overall_status": receipt_overall_status,
        }
    latest_manifest = manifests[-1] if manifests else None
    controls.append({
        "id": "frozen_evidence",
        "label": "Frozen exact evidence manifest",
        "status": "PASS" if latest_manifest else "NOT_RUN",
        "detail": "Latest evidence manifest is immutable and digest-bound." if latest_manifest else "Evidence has not been frozen.",
        "coverage": {"manifest_sha256": latest_manifest.get("manifest_sha256") if latest_manifest else None},
        "evidence_refs": [] if not latest_manifest else [{"kind": "evidence_manifest", "id": str(latest_manifest.get("id") or "")}],
    })
    active_approvals = [
        item for item in approvals
        if not item.get("revoked_at")
        and str(item.get("decision") or "") == "approve"
        and bool(latest_manifest)
        and str(item.get("evidence_manifest_id") or "") == str(latest_manifest.get("id") or "")
        and (_timestamp(item.get("expires_at")) or datetime.min.replace(tzinfo=timezone.utc)) > now
    ]
    legal_review_approved = any(
        str(item.get("approved_by_role") or item.get("approval_type") or "") == "legal_reviewer"
        for item in active_approvals
    )
    license_control = next(
        (item for item in controls if item.get("id") == "license_compliance"), None,
    )
    if license_control and license_control.get("status") == "REVIEW" and legal_review_approved:
        license_control["status"] = "PASS"
        license_control["detail"] = "A designated reviewer approved the reconciled terms against the latest frozen evidence."
        license_control["coverage"] = {
            **_json(license_control.get("coverage"), {}),
            "legal_disposition": "APPROVED",
        }
    rejected = any(
        str(item.get("decision") or "") == "reject"
        and bool(latest_manifest)
        and str(item.get("evidence_manifest_id") or "") == str(latest_manifest.get("id") or "")
        for item in approvals
    )
    role_subjects = {
        str(item.get("approved_by_role") or item.get("approval_type") or ""): str(item.get("approved_by_subject") or "")
        for item in active_approvals
    }
    required_roles = PRODUCTION_APPROVAL_ROLES if environment == "production" else set()
    missing_roles = sorted(required_roles - set(role_subjects))
    approval_status = (
        "FAIL" if rejected
        else "REVIEW" if missing_roles or len({role_subjects.get(role) for role in required_roles}) < len(required_roles)
        else "PASS" if active_approvals or not required_roles
        else "REVIEW"
    )
    controls.append({
        "id": "human_approvals",
        "label": "Identity-separated human approvals",
        "status": approval_status,
        "detail": "Required approvals are current and separated." if approval_status == "PASS" else f"Missing or non-separated roles: {', '.join(missing_roles) or 'review separation/rejection'}.",
        "coverage": {"required_roles": sorted(required_roles), "approved_roles": sorted(role_subjects), "distinct_subjects": len(set(role_subjects.values()))},
        "evidence_refs": [{"kind": "approval", "id": str(item.get("id") or "")} for item in active_approvals],
    })
    latest_policy = policy_decisions[-1] if policy_decisions else None
    policy_value = str(latest_policy.get("decision") or "") if latest_policy else ""
    policy_binds_latest = bool(latest_policy and latest_manifest) and (
        str(latest_policy.get("evidence_manifest_id") or "") == str(latest_manifest.get("id") or "")
    )
    controls.append({
        "id": "deterministic_policy",
        "label": "Deterministic policy decision",
        "status": "FAIL" if latest_policy and not policy_binds_latest else _normalize_status(policy_value, absent="NOT_RUN"),
        "detail": (
            "Stored policy decision does not bind the latest evidence manifest."
            if latest_policy and not policy_binds_latest
            else f"Stored policy decision is {policy_value}."
            if latest_policy
            else "Policy has not been evaluated."
        ),
        "coverage": {
            "decision_sha256": latest_policy.get("decision_sha256") if latest_policy else None,
            "binds_latest_manifest": policy_binds_latest,
        },
        "evidence_refs": [] if not latest_policy else [{"kind": "policy_decision", "id": str(latest_policy.get("id") or "")}],
    })
    active_admission = next((
        item for item in reversed(admissions)
        if str(item.get("status")) == "active"
        and (_timestamp(item.get("expires_at")) or datetime.min.replace(tzinfo=timezone.utc)) > now
    ), None)
    controls.append({
        "id": "signed_admission",
        "label": "Active signed exact-subject admission",
        "status": "PASS" if active_admission else "NOT_RUN",
        "detail": "An active signed admission is registered." if active_admission else "No active signed admission is registered.",
        "coverage": {
            "statement_sha256": active_admission.get("statement_sha256") if active_admission else None,
            "expires_at": _iso(active_admission.get("expires_at")) if active_admission else None,
        },
        "evidence_refs": [] if not active_admission else [{"kind": "admission", "id": str(active_admission.get("id") or "")}],
    })
    controls = [_enrich_control(item) for item in controls]
    if active_admission:
        package = _json(active_admission.get("admission_package"), {})
        predicate = _json(_json(package.get("statement"), {}).get("predicate"), {})
        admission_parity = {
            "decision_matches": predicate.get("decision") == "allow",
            "deployment_bundle_sha256_matches": predicate.get("deployment_bundle", {}).get("bundle_sha256") == active_admission.get("deployment_bundle_sha256") if isinstance(predicate.get("deployment_bundle"), dict) else False,
            "evidence_manifest_sha256_matches": predicate.get("evidence_manifest_sha256") == active_admission.get("evidence_manifest_sha256"),
            "policy_decision_sha256_matches": predicate.get("policy_decision_sha256") == active_admission.get("policy_decision_sha256"),
            "latest_evidence_manifest_matches": bool(latest_manifest) and latest_manifest.get("manifest_sha256") == active_admission.get("evidence_manifest_sha256"),
            "latest_policy_decision_matches": bool(latest_policy) and latest_policy.get("decision_sha256") == active_admission.get("policy_decision_sha256"),
            "cryptographic_signature_verified": bool(admission_verification and admission_verification.get("verified") is True),
        }
    else:
        admission_parity = {
            "decision_matches": None,
            "deployment_bundle_sha256_matches": None,
            "evidence_manifest_sha256_matches": None,
            "policy_decision_sha256_matches": None,
            "latest_evidence_manifest_matches": None,
            "latest_policy_decision_matches": None,
            "cryptographic_signature_verified": None,
        }
    state = str(submission.get("state") or "")
    statuses = {control["status"] for control in controls}
    admission_mismatch = bool(active_admission) and not all(value is True for value in admission_parity.values())
    if admission_mismatch:
        outcome = "BLOCK"
        summary = "The active admission statement does not match the current authoritative records."
    elif active_admission and all(value is True for value in admission_parity.values()) and not (
        statuses & {"FAIL", "ERROR", "INCOMPLETE", "NOT_RUN", "REVIEW"}
    ):
        outcome = "ALLOW"
        summary = "The exact deployment subject has an active signed admission."
    elif state == "blocked" or policy_value == "block" or "FAIL" in statuses:
        outcome = "BLOCK"
        summary = "At least one mandatory control failed or deterministic policy blocked admission."
    elif "ERROR" in statuses or "INCOMPLETE" in statuses or "NOT_RUN" in statuses:
        outcome = "INCOMPLETE"
        summary = "Required generated evidence is missing, incomplete, or errored."
    else:
        outcome = "REVIEW"
        summary = "Generated controls are available but human review, policy, or promotion remains."
    control_counts = {status: sum(item["status"] == status for item in controls) for status in sorted(CONTROL_STATUSES)}
    performed = [item for item in controls if item["status"] in {"PASS", "FAIL", "REVIEW"}]
    not_completed = [item for item in controls if item["status"] in {"ERROR", "INCOMPLETE", "NOT_RUN"}]
    not_applicable = [item for item in controls if item["status"] == "NOT_APPLICABLE"]
    actions = _required_actions(controls)
    if outcome == "ALLOW":
        actions = [item for item in actions if item["status"] != "REVIEW"]
    key_results = [
        {
            "control_id": item["id"],
            "label": item["label"],
            "status": item["status"],
            "result": item["detail"],
        }
        for item in controls if item["status"] in {"FAIL", "ERROR", "INCOMPLETE", "NOT_RUN", "REVIEW"}
    ][:8]
    admission_expiry = _iso(active_admission.get("expires_at")) if active_admission else None
    external_requirements = [
        {**item, "status": "EXTERNAL_REQUIRED"}
        for item in EXTERNAL_APPROVAL_REQUIREMENTS
    ]
    static_detail = _static_check_detail(evidence)
    attention_findings = [
        {"scanner": item.get("name"), **finding}
        for item in static_detail.get("scanner_results") or []
        if item.get("status") in {"FAIL", "ERROR", "INCOMPLETE", "REVIEW"}
        for finding in item.get("findings") or []
        if isinstance(finding, dict)
    ]
    static_security_findings = [
        finding for finding in attention_findings
        if finding.get("id") != "license_file_missing"
    ]
    static_control = next((item for item in controls if item.get("id") == "static_analysis"), None)
    if static_control and static_security_findings:
        labels: list[str] = []
        remediation_steps: list[str] = []
        seen_locations: set[str] = set()
        for finding in sorted(
            static_security_findings,
            key=lambda item: (
                bool(str(item.get("message") or "").strip()),
                len(str(item.get("message") or item.get("call") or item.get("id") or "")),
            ),
            reverse=True,
        ):
            path = str(finding.get("path") or "")
            line = finding.get("line")
            location = f"{path}:{line}" if path and line else str(finding.get("id") or finding.get("rule_id") or "")
            if location in seen_locations:
                continue
            seen_locations.add(location)
            if finding.get("id") == "license_file_missing":
                label = "repository license/NOTICE source file is missing"
                action = (
                    "Obtain the publisher's authoritative license/NOTICE text and preserve it with the "
                    "pinned revision and any distribution."
                )
            else:
                label = str(finding.get("message") or finding.get("call") or finding.get("id") or "scanner finding")
                if path:
                    label += f" ({path}{f':{line}' if line else ''})"
                location_label = f" at {path}{f':{line}' if line else ''}" if path else ""
                action = f"Resolve {str(finding.get('message') or finding.get('call') or finding.get('id') or 'the scanner finding')}{location_label}, then rescan the new pinned revision."
            labels.append(label)
            remediation_steps.append(action)
        static_control["detail"] = (
            f"{len(labels)} review item(s): " + "; ".join(labels[:5])
            + (f"; and {len(labels) - 5} more" if len(labels) > 5 else "")
        )
        static_control["remediation"] = " ".join(remediation_steps[:5])
        actions = _required_actions(controls)
        if outcome == "ALLOW":
            actions = [item for item in actions if item["status"] != "REVIEW"]
        key_results = [
            {
                "control_id": item["id"], "label": item["label"],
                "status": item["status"], "result": item["detail"],
            }
            for item in controls
            if item["status"] in {"FAIL", "ERROR", "INCOMPLETE", "NOT_RUN", "REVIEW"}
        ][:8]
    presentation = _presentation_summary(
        controls,
        outcome=outcome,
        license_compliance=license_compliance,
        external_requirement_count=len(external_requirements),
        license_source_missing=license_source_missing,
    )
    report = {
        "schema_version": REPORT_SCHEMA,
        "generated_at": _iso(now),
        "submission": {
            "id": submission_id,
            "state": state,
            "requested_environment": environment,
            "source_kind": submission.get("source_kind"),
            "source_reference_hash": submission.get("source_reference_hash"),
            "scan_id": str(submission.get("scan_id") or "") or None,
            "created_at": _iso(submission.get("created_at")),
            "updated_at": _iso(submission.get("updated_at")),
        },
        "outcome": outcome,
        "plain_language": summary,
        "presentation": presentation,
        "executive_summary": {
            "shakerscan_decision": outcome,
            "deployable_under_configured_shakerscan_policy": outcome == "ALLOW",
            "full_corporate_approval": "NOT_DETERMINED_BY_SHAKERSCAN",
            "decision_statement": summary,
            "license_outcome": license_compliance.get("outcome") or "NOT_ASSESSED",
            "legal_disposition": "APPROVED" if legal_review_approved else "PENDING" if license_compliance.get("legal_review_required") else "NOT_REQUIRED_BY_AUTOMATION",
            "legal_review_required": bool(license_compliance.get("legal_review_required")) and not legal_review_approved,
            "authorization_scope": (
                f"Exact registered subject for the {environment or 'unspecified'} environment"
                + (f" until {admission_expiry}" if admission_expiry else "; no active admission expiry exists")
            ),
            "scope_warning": (
                "The result applies only to the pinned subject and checks evidenced by this run. "
                "Deployment follow-up remains separate."
            ),
            "coverage": {
                "total_controls": len(controls),
                "performed": len(performed),
                "passed": control_counts["PASS"],
                "failed": control_counts["FAIL"],
                "review": control_counts["REVIEW"],
                "not_completed": len(not_completed),
                "not_applicable": len(not_applicable),
                "external_corporate_requirements": len(external_requirements),
            },
            "key_results": key_results,
            "required_actions": actions[:8],
        },
        "assessment_scope": {
            "checks_performed": [item["id"] for item in performed],
            "checks_not_completed": [item["id"] for item in not_completed],
            "checks_not_applicable": [item["id"] for item in not_applicable],
            "status_semantics": {
                "performed": "PASS, FAIL, or REVIEW means the control produced a determinate result.",
                "not_completed": "ERROR, INCOMPLETE, or NOT_RUN means the control did not produce sufficient approval evidence.",
                "not_applicable": "NOT_APPLICABLE is acceptable only when applicability was explicitly resolved from subject facts.",
                "external": "EXTERNAL_REQUIRED identifies deployment or organization decisions outside this technical run.",
            },
        },
        "controls": controls,
        "control_counts": control_counts,
        "detailed_review": {
            "control_matrix": controls,
            "static_analysis_detail": static_detail,
            "license_compliance": license_compliance,
            "shakerscan_check_catalog": _check_catalog_with_evidence(controls, static_detail),
            "external_approval_requirements": external_requirements,
            "required_actions": actions,
        },
        "runner_timelines": timelines,
        "authority_bindings": {
            "latest_evidence_manifest_id": str(latest_manifest.get("id") or "") if latest_manifest else None,
            "evidence_manifest_sha256": latest_manifest.get("manifest_sha256") if latest_manifest else None,
            "latest_policy_decision_id": str(latest_policy.get("id") or "") if latest_policy else None,
            "policy_decision_sha256": latest_policy.get("decision_sha256") if latest_policy else None,
            "active_admission_id": str(active_admission.get("id") or "") if active_admission else None,
            "admission_statement_sha256": active_admission.get("statement_sha256") if active_admission else None,
            "admission_statement_parity": admission_parity,
            "admission_cryptographic_verification": {
                "verified": admission_verification.get("verified") if admission_verification else None,
                "status": admission_verification.get("status") if admission_verification else None,
                "blockers": admission_verification.get("blockers") if admission_verification else [],
                "trusted_key_fingerprints": admission_verification.get("trusted_key_fingerprints") if admission_verification else [],
            },
        },
        "activity": [{
            "id": str(item.get("id") or ""),
            "event_type": item.get("event_type"),
            "previous_state": item.get("previous_state"),
            "new_state": item.get("new_state"),
            "reason": item.get("reason"),
            "created_at": _iso(item.get("created_at")),
        } for item in events],
        "advisory_sessions": [{
            "id": str(item.get("id") or ""),
            "status": item.get("status"),
            "iteration": item.get("iteration"),
            "max_iterations": item.get("max_iterations"),
            "actions_used": item.get("actions_used"),
            "action_budget": item.get("action_budget"),
            "authority": "advisory_only",
        } for item in agent_sessions],
        "limitations": [
            "A clean static scan does not substitute for runtime, embedding-quality, or application testing.",
            "Corpus and data-plane results are authoritative only when attached as trusted generated evidence.",
            "The optional coding-agent planner is advisory and never admission authority.",
            "Use-case, data, supplier, regulatory, and operational decisions remain deployment responsibilities.",
            "Product check-catalog entries describe supported capabilities; only per-submission control and scanner evidence proves execution and applicability.",
        ],
    }
    digest_input = {key: value for key, value in report.items() if key != "generated_at"}
    report["report_sha256"] = hashlib.sha256(_canonical(digest_input)).hexdigest()
    return report


def apply_automatic_review_context(
    report: dict[str, Any],
    automatic_review: dict[str, Any],
) -> dict[str, Any]:
    """Bind the durable one-link controller result into every report format.

    The underlying submission remains the authority for evidence and admission.
    This context explains why an automatic technical workflow stopped before it
    could produce evidence, which is especially important for formats that this
    release can inspect statically but cannot load in a fixed microVM profile.
    """
    controls = report.get("controls") if isinstance(report.get("controls"), list) else []
    pending = _json(automatic_review.get("pending_controls"), [])
    timeline = _json(automatic_review.get("timeline_json"), [])
    current_step = str(automatic_review.get("current_step") or "")
    automatic = {
        "id": str(automatic_review.get("id") or ""),
        "state": automatic_review.get("state"),
        "current_step": current_step,
        "progress": _integer(automatic_review.get("progress")),
        "technical_outcome": automatic_review.get("technical_outcome"),
        "pending_controls": pending,
        "timeline": timeline,
        "authority": "technical_evidence_only",
    }
    report["automatic_review"] = automatic

    if current_step == "runtime_profile_unavailable":
        pending_runtime = next(
            (
                item for item in pending
                if isinstance(item, dict) and item.get("control") == "isolated_runtime"
            ),
            {},
        )
        action = str(
            pending_runtime.get("action")
            or "Use a release with an approved fixed Firecracker profile for this exact format, or perform a separately governed runtime qualification."
        )
        raw_detail = str(pending_runtime.get("detail") or "no fixed loader profile")
        firecracker = next(
            (item for item in controls if item.get("id") == "firecracker_runtime"),
            None,
        )
        if firecracker is not None:
            firecracker.update({
                "status": "INCOMPLETE",
                "detail": (
                    "UNSUPPORTED in this release: no fixed Firecracker loader or conversion "
                    "profile applies to the exact model format and repository."
                ),
                "coverage": {
                    **_json(firecracker.get("coverage"), {}),
                    "support_status": "UNSUPPORTED",
                    "reason": raw_detail[:500],
                },
                "remediation": action,
            })
        if str(report.get("outcome") or "") not in {"BLOCK", "FAIL"}:
            report["outcome"] = "INCOMPLETE"
            report["plain_language"] = (
                "Static inspection completed, but this release cannot perform fixed-profile "
                "isolated runtime qualification for the exact model format."
            )

    technical_controls = [
        item for item in controls
        if str(item.get("id") or "") not in DEPLOYMENT_FOLLOW_UP_CONTROL_IDS
    ]
    counts = {
        status: sum(item.get("status") == status for item in technical_controls)
        for status in sorted(CONTROL_STATUSES)
    }
    performed = [item for item in technical_controls if item.get("status") in {"PASS", "FAIL", "REVIEW"}]
    not_completed = [
        item for item in technical_controls
        if item.get("status") in {"ERROR", "INCOMPLETE", "NOT_RUN"}
    ]
    not_applicable = [item for item in technical_controls if item.get("status") == "NOT_APPLICABLE"]
    actions = _required_actions(technical_controls)
    automatic_outcome = str(automatic.get("technical_outcome") or "").upper()
    normalized_outcome = {
        "PASS": "ALLOW",
        "REVIEW_REQUIRED": "REVIEW",
        "REVIEW": "REVIEW",
        "BLOCK": "BLOCK",
        "INCOMPLETE": "INCOMPLETE",
    }.get(automatic_outcome, str(report.get("outcome") or "INCOMPLETE"))
    attention_count = sum(
        item.get("status") in {"FAIL", "ERROR", "INCOMPLETE", "NOT_RUN", "REVIEW"}
        for item in technical_controls
    )
    technical_statement = {
        "PASS": "All selected technical checks completed without blocking findings.",
        "REVIEW_REQUIRED": f"Technical checks completed; {attention_count} item(s) need review before use.",
        "REVIEW": f"Technical checks completed; {attention_count} item(s) need review before use.",
        "BLOCK": "One or more technical checks found a condition that blocks use of this revision.",
        "INCOMPLETE": "The technical review did not collect all required evidence.",
    }.get(automatic_outcome, str(report.get("plain_language") or "Technical review results are available."))
    report["outcome"] = normalized_outcome
    report["plain_language"] = technical_statement
    executive = _json(report.get("executive_summary"), {})
    executive.update({
        "shakerscan_decision": normalized_outcome,
        "deployable_under_configured_shakerscan_policy": False,
        "decision_statement": technical_statement,
        "authorization_scope": (
            "Technical review of the exact pinned revision. This is not a deployment approval; "
            "deployment follow-up is listed separately."
        ),
        "automatic_technical_review": {
            "state": automatic.get("state"),
            "current_step": current_step,
            "outcome": automatic.get("technical_outcome"),
            "pending_control_count": len(pending),
        },
        "coverage": {
            **_json(executive.get("coverage"), {}),
            "total_controls": len(technical_controls),
            "performed": len(performed),
            "passed": counts["PASS"],
            "failed": counts["FAIL"],
            "review": counts["REVIEW"],
            "not_completed": len(not_completed),
            "not_applicable": len(not_applicable),
        },
        "key_results": [
            {
                "control_id": item.get("id"),
                "label": item.get("label"),
                "status": item.get("status"),
                "result": item.get("detail"),
            }
            for item in technical_controls
            if item.get("status") in {"FAIL", "ERROR", "INCOMPLETE", "NOT_RUN", "REVIEW"}
        ][:8],
        "required_actions": actions[:8],
    })
    report["executive_summary"] = executive
    report["control_counts"] = counts
    report["assessment_scope"] = {
        **_json(report.get("assessment_scope"), {}),
        "checks_performed": [item.get("id") for item in performed],
        "checks_not_completed": [item.get("id") for item in not_completed],
        "checks_not_applicable": [item.get("id") for item in not_applicable],
    }
    detail = _json(report.get("detailed_review"), {})
    detail.update({
        "control_matrix": technical_controls,
        "shakerscan_check_catalog": _check_catalog_with_evidence(
            controls, _json(detail.get("static_analysis_detail"), {}),
        ),
        "required_actions": actions,
    })
    report["detailed_review"] = detail
    report["presentation"] = _presentation_summary(
        controls,
        outcome=automatic_outcome or normalized_outcome,
        license_compliance=_json(detail.get("license_compliance"), {}),
        external_requirement_count=len(_json(detail.get("external_approval_requirements"), [])),
        license_source_missing=any(
            finding.get("id") == "license_file_missing"
            for scanner in _json(detail.get("static_analysis_detail"), {}).get("scanner_results") or []
            if isinstance(scanner, dict)
            for finding in scanner.get("findings") or []
            if isinstance(finding, dict)
        ),
    )
    report.pop("report_sha256", None)
    digest_input = {key: value for key, value in report.items() if key != "generated_at"}
    report["report_sha256"] = hashlib.sha256(_canonical(digest_input)).hexdigest()
    return report


def render_model_intake_html(report: dict[str, Any]) -> str:
    def esc(value: Any) -> str:
        return html.escape(str(value if value is not None else ""))

    executive = _json(report.get("executive_summary"), {})
    presentation = _json(report.get("presentation"), {})
    groups = _json(presentation.get("groups"), {})
    presentation_counts = _json(presentation.get("counts"), {})
    detail = _json(report.get("detailed_review"), {})

    def control_rows(items: list[dict[str, Any]], *, empty: str) -> str:
        return "".join(
            "<tr>"
            f"<td>{esc(item.get('category'))}</td><td>{esc(item.get('label'))}</td>"
            f"<td class='status {esc(str(item.get('status') or '').lower())}'>{esc(item.get('status'))}</td>"
            f"<td>{esc(item.get('result') if 'result' in item else item.get('detail'))}</td>"
            f"<td>{esc(item.get('next_step') if 'next_step' in item else item.get('remediation'))}</td>"
            "</tr>"
            for item in items
        ) or f"<tr><td colspan='5'>{esc(empty)}</td></tr>"

    controls = report.get("controls", []) if isinstance(report.get("controls"), list) else []
    technical_controls = (
        [item for item in controls if str(item.get("id") or "") not in DEPLOYMENT_FOLLOW_UP_CONTROL_IDS]
        if report.get("automatic_review") else controls
    )
    verified_rows = control_rows(_json(groups.get("verified"), []), empty="No technical check recorded a passing result.")
    attention_rows = control_rows(_json(groups.get("needs_attention"), []), empty="No technical check needs attention.")
    not_applicable_rows = control_rows(_json(groups.get("not_applicable"), []), empty="No checks were marked not applicable.")
    rows = "".join(
        "<tr>"
        f"<td>{esc(item.get('category'))}</td><td>{esc(item.get('question'))}</td>"
        f"<td class='status {esc(str(item.get('status') or '').lower())}'>{esc(item.get('status'))}</td>"
        f"<td>{esc(item.get('detail'))}</td><td>{esc(item.get('method'))}</td>"
        f"<td><code>{esc(json.dumps(item.get('coverage') or {}, sort_keys=True, default=str))}</code></td>"
        "</tr>"
        for item in technical_controls
    )
    deployment_rows = control_rows(
        _json(groups.get("deployment_follow_up"), []),
        empty="No deployment follow-up controls were recorded.",
    )
    external_rows = "".join(
        "<tr>"
        f"<td>{esc(item.get('id'))}</td><td>{esc(item.get('category'))}</td><td>{esc(item.get('requirement'))}</td>"
        f"<td>{esc(item.get('typical_owner'))}</td><td>{esc(item.get('expected_evidence'))}</td>"
        "</tr>"
        for item in detail.get("external_approval_requirements") or []
    )
    catalog_rows = "".join(
        "<tr>"
        f"<td>{esc(item.get('id'))}</td><td>{esc(item.get('category'))}</td><td>{esc(item.get('check'))}</td>"
        f"<td class='status {esc(str(item.get('execution_status') or '').lower())}'>{esc(item.get('execution_status'))}</td>"
        f"<td>{esc(item.get('result_summary'))}</td><td>{esc(item.get('implementation'))}</td><td>{esc(item.get('applies_when'))}</td>"
        "</tr>"
        for item in detail.get("shakerscan_check_catalog") or []
    )
    phases = "".join(
        f"<tr><td>{esc(job.get('operation'))}</td><td>{esc(phase.get('phase'))}</td><td>{esc(phase.get('status'))}</td><td>{esc(phase.get('duration_ms'))}</td><td>{esc(phase.get('detail'))}</td></tr>"
        for job in report.get("runner_timelines", []) for phase in job.get("phases", [])
    ) or "<tr><td colspan='5'>No Firecracker phase evidence recorded.</td></tr>"
    static_detail = _json(detail.get("static_analysis_detail"), {})
    runtime_dependencies = _json(static_detail.get("runtime_dependencies"), {})
    runtime_profile = _json(runtime_dependencies.get("profile"), {})
    dependency_rows = "".join(
        "<tr>"
        f"<td>{esc(item.get('name'))}</td><td>{esc(item.get('version'))}</td>"
        f"<td><code>{esc(item.get('purl'))}</code></td><td>{esc(item.get('source'))}</td>"
        "</tr>"
        for item in runtime_dependencies.get("resolved_components") or []
        if isinstance(item, dict)
    ) or "<tr><td colspan='4'>No exact runtime component inventory was produced.</td></tr>"
    inferred_rows = "".join(
        "<tr>"
        f"<td>{esc(item.get('import_name'))}</td><td>{esc(item.get('distribution'))}</td>"
        f"<td>{esc(item.get('version'))}</td><td>{esc('required' if item.get('required_for_fixed_loader') else 'model-card example')}</td>"
        f"<td class='status {esc(str(item.get('resolution_status') or '').lower())}'>{esc(item.get('resolution_status'))}</td>"
        "</tr>"
        for item in runtime_dependencies.get("inferred_requirements") or []
        if isinstance(item, dict)
    ) or "<tr><td colspan='5'>No Python inference imports were discovered.</td></tr>"
    vulnerability_summary = _json(static_detail.get("vulnerability_summary"), {})
    vulnerability_rows = "".join(
        "<tr>"
        f"<td>{esc(item.get('package'))}</td><td>{esc(item.get('installed_version'))}</td>"
        f"<td><code>{esc(item.get('id'))}</code></td>"
        f"<td class='status {esc(str(item.get('severity') or '').lower())}'>{esc(item.get('severity'))}</td>"
        f"<td>{esc(', '.join(str(value) for value in item.get('sources') or []))}</td>"
        f"<td>{esc(', '.join(str(value) for value in item.get('fixed_versions') or []) or 'No fixed version reported')}</td>"
        "</tr>"
        for item in static_detail.get("vulnerability_inventory") or []
        if isinstance(item, dict)
    ) or "<tr><td colspan='6'>No known vulnerability was reported for the exact resolved runtime by the completed scanners.</td></tr>"
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Model Intake {esc(report.get('outcome'))}</title>
<style>
body{{font:14px system-ui,sans-serif;margin:32px;color:#172033}}h1{{margin-bottom:4px}}.meta{{color:#5b6475}}
.verdict{{padding:16px;border:2px solid #555;border-radius:8px;margin:20px 0}}.warning{{padding:12px;background:#fff6d8;border-left:4px solid #9a6700;margin:12px 0}}.stats{{display:flex;gap:10px;flex-wrap:wrap}}.stat{{padding:8px 12px;background:#f3f5f8;border-radius:6px}}table{{border-collapse:collapse;width:100%;margin:16px 0}}
th,td{{border:1px solid #ccd2dc;padding:8px;vertical-align:top;text-align:left}}code{{white-space:pre-wrap;word-break:break-all;font-size:11px}}
.status{{font-weight:700}}.pass{{color:#08783e}}.fail,.error{{color:#b42318}}.review,.incomplete,.not_run{{color:#9a6700}}
.no-print{{margin-right:8px}}.page-break{{break-before:page}}@media print{{.no-print{{display:none}}body{{margin:12mm}}}}
</style></head><body>
<button class="no-print" onclick="window.print()">Print / Save PDF</button>
<h1>Model Intake review</h1><div class="meta">Submission {esc(report.get('submission', {}).get('id'))} · report sha256:{esc(report.get('report_sha256'))}</div>
<h2>Summary</h2>
<div class="verdict"><strong>{esc(presentation.get('headline') or 'Review results available')}</strong><p>{esc(executive.get('decision_statement') or report.get('plain_language'))}</p><p><strong>Result:</strong> {esc(presentation.get('decision') or report.get('outcome'))}</p><p><strong>Scope:</strong> {esc(executive.get('authorization_scope'))}</p></div>
<div class="warning"><strong>Review boundary</strong><p>{esc(presentation.get('review_boundary'))}</p></div>
<div class="warning"><strong>Licensing and attribution</strong><p>{esc(presentation.get('license_note'))}</p></div>
<div class="stats"><span class="stat">{esc(presentation_counts.get('verified'))} verified</span><span class="stat">{esc(presentation_counts.get('needs_attention'))} need attention</span><span class="stat">{esc(presentation_counts.get('not_applicable'))} not applicable</span></div>
<h3>Checks that need attention</h3><table><thead><tr><th>Category</th><th>Control</th><th>Status</th><th>Result</th><th>Next step</th></tr></thead><tbody>{attention_rows}</tbody></table>
<h3>Verified checks</h3><table><thead><tr><th>Category</th><th>Control</th><th>Status</th><th>Result</th><th>Evidence / next step</th></tr></thead><tbody>{verified_rows}</tbody></table>
<h3>Checks not applicable</h3><table><thead><tr><th>Category</th><th>Control</th><th>Status</th><th>Result</th><th>Reason/next step</th></tr></thead><tbody>{not_applicable_rows}</tbody></table>
<h2 class="page-break">Deployment follow-up</h2><p>These items are not scan failures and are excluded from the technical result above.</p><table><thead><tr><th>Category</th><th>Control</th><th>Status</th><th>Current state</th><th>Next step</th></tr></thead><tbody>{deployment_rows}</tbody></table>
<details><summary>Organization checklist ({esc(presentation_counts.get('organization_checklist_items'))} items)</summary><p>Use this optional checklist when preparing the model for a specific deployment.</p><table><thead><tr><th>ID</th><th>Category</th><th>Follow-up</th><th>Typical owner</th><th>Expected evidence</th></tr></thead><tbody>{external_rows}</tbody></table></details>
<h2 class="page-break">Detailed technical review</h2>
<h3>Inference dependencies and known vulnerabilities</h3>
<p><strong>Runtime profile:</strong> {esc(runtime_profile.get('id') or 'not resolved')} · <strong>Dependency resolution:</strong> {esc(runtime_dependencies.get('status') or 'NOT_RUN')} · <strong>Known advisories:</strong> {esc(vulnerability_summary.get('total') or 0)} across {esc(vulnerability_summary.get('packages_affected') or 0)} package(s).</p>
<table><thead><tr><th>Package</th><th>Installed version</th><th>Advisory</th><th>Severity</th><th>Reported by</th><th>Fix</th></tr></thead><tbody>{vulnerability_rows}</tbody></table>
<details><summary>Derived inference imports</summary><table><thead><tr><th>Import</th><th>Resolved package</th><th>Version</th><th>Evidence</th><th>Status</th></tr></thead><tbody>{inferred_rows}</tbody></table></details>
<details><summary>Exact Firecracker runtime packages ({esc(len(runtime_dependencies.get('resolved_components') or []))})</summary><table><thead><tr><th>Package</th><th>Version</th><th>Package URL</th><th>Resolution</th></tr></thead><tbody>{dependency_rows}</tbody></table></details>
<h3>Control evidence matrix</h3><table><thead><tr><th>Category</th><th>Question</th><th>Status</th><th>Answer</th><th>Method</th><th>Coverage/evidence</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Firecracker phase timeline</h2><table><thead><tr><th>Operation</th><th>Phase</th><th>Status</th><th>Duration ms</th><th>Detail</th></tr></thead><tbody>{phases}</tbody></table>
<details><summary>Full ShakerScan check catalog</summary><p>Each row states what happened for this submission. Applicability alone is never treated as proof that a check ran.</p><table><thead><tr><th>ID</th><th>Category</th><th>Check</th><th>Result</th><th>Evidence summary</th><th>Implementation</th><th>Applicability</th></tr></thead><tbody>{catalog_rows}</tbody></table></details>
<details><summary>Evidence and authority bindings</summary><pre>{esc(json.dumps(report.get('authority_bindings') or {}, indent=2, sort_keys=True, default=str))}</pre></details>
<h2>Limitations</h2><ul>{''.join(f'<li>{esc(item)}</li>' for item in report.get('limitations', []))}</ul>
</body></html>"""


def model_intake_report_to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    controls = report.get("controls") if isinstance(report.get("controls"), list) else []
    if report.get("automatic_review"):
        controls = [
            item for item in controls
            if str(item.get("id") or "") not in DEPLOYMENT_FOLLOW_UP_CONTROL_IDS
        ]
    rules = [{
        "id": f"model-intake/{item['id']}",
        "name": item["label"],
        "shortDescription": {"text": item["label"]},
        "properties": {"normalizedStatuses": sorted(CONTROL_STATUSES)},
    } for item in controls]
    results = []
    for item in controls:
        if item.get("status") in {"PASS", "NOT_APPLICABLE"}:
            continue
        level = "error" if item.get("status") in {"FAIL", "ERROR"} else "warning"
        results.append({
            "ruleId": f"model-intake/{item['id']}",
            "level": level,
            "message": {"text": f"{item['status']}: {item['detail']}"},
            "properties": {
                "status": item.get("status"),
                "coverage": item.get("coverage") or {},
                "evidenceRefs": item.get("evidence_refs") or [],
                "submissionId": report.get("submission", {}).get("id"),
                "reportSha256": report.get("report_sha256"),
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ShakerScan Model Intake", "informationUri": "https://github.com/andriyze/shakerscan", "rules": rules}},
            "results": results,
            "properties": {
                "schemaVersion": report.get("schema_version"),
                "outcome": report.get("outcome"),
                "reportSha256": report.get("report_sha256"),
                "authorityBindings": report.get("authority_bindings"),
                "licenseOutcome": _json(report.get("executive_summary"), {}).get("license_outcome"),
                "legalDisposition": _json(report.get("executive_summary"), {}).get("legal_disposition"),
            },
        }],
    }


__all__ = [
    "CONTROL_STATUSES", "REPORT_SCHEMA", "apply_automatic_review_context", "build_model_intake_report",
    "model_intake_report_to_sarif", "render_model_intake_html",
]
