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
        "question": "Did the required format, serialization, code, secret, malware, SBOM, dependency, binary, and license checks complete?",
        "method": "Evaluate digest-bound ShakerScan evidence produced by built-ins and applicable ModelScan, Fickling, Semgrep, and Trivy adapters.",
        "remediation": "Run every applicable required scanner against the complete snapshot with current rules/databases and resolve all non-pass results.",
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
        "category": "Corporate integration",
        "question": "Did the intended vector-store and knowledge-graph authorization path pass?",
        "method": "Verify trusted generated observations for ACL, tenant, graph, cache, deletion, and index/model compatibility controls.",
        "remediation": "Run the corporate data-plane test contract with representative principals, tenants, index, graph, and deletion flows.",
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
    {"id": "MI-01", "category": "Acquisition", "check": "Safe source resolution and complete acquisition", "implementation": "native", "applies_when": "all intake sources", "evidence_controls": ["immutable_subjects", "static_analysis"]},
    {"id": "MI-02", "category": "Integrity", "check": "Full SHA-256, expected-digest comparison, immutable quarantine identity", "implementation": "native", "applies_when": "all artifacts", "evidence_controls": ["immutable_subjects"]},
    {"id": "MI-03", "category": "Repository", "check": "Authoritative pinned repository manifest, complete snapshot, custom code and auto_map inventory", "implementation": "native", "applies_when": "the provider supports authoritative snapshots", "evidence_controls": ["immutable_subjects", "static_analysis"]},
    {"id": "MI-04", "category": "Artifact safety", "check": "Recursive archive, traversal, collision, symlink/device, bomb, truncation, and format-specific inspection", "implementation": "native", "applies_when": "archives or supported model formats are present", "evidence_controls": ["static_analysis"]},
    {"id": "MI-05", "category": "Serialization", "check": "Pickle opcode/callable analysis plus ModelScan and applicable Fickling", "implementation": "native + existing adapters", "applies_when": "serialized or pickle-capable artifacts are present", "evidence_controls": ["static_analysis"]},
    {"id": "MI-06", "category": "Source security", "check": "Python AST and Semgrep review of repository code and configuration", "implementation": "native + existing adapter", "applies_when": "code or configuration is present", "evidence_controls": ["static_analysis"]},
    {"id": "MI-07", "category": "Content safety", "check": "Secret rules, malware rules, and native-binary inventory", "implementation": "native", "applies_when": "complete subject material is available", "evidence_controls": ["static_analysis"]},
    {"id": "MI-08", "category": "Dependencies", "check": "CycloneDX SBOM, dependency inventory, and applicable offline Trivy SCA/misconfiguration scan", "implementation": "native + existing adapter", "applies_when": "dependency manifests or runtime components are present", "evidence_controls": ["static_analysis"]},
    {"id": "MI-09", "category": "Licensing", "check": "License inventory and declared-license policy evidence", "implementation": "native + existing adapter", "applies_when": "license files or dependency metadata are present", "evidence_controls": ["static_analysis"]},
    {"id": "MI-10", "category": "Provenance", "check": "Signature, signer trust, exact-subject attestation, lineage, and AIBOM evidence", "implementation": "native", "applies_when": "the policy requires or the source supplies this evidence", "evidence_controls": ["static_analysis", "frozen_evidence"]},
    {"id": "MI-11", "category": "Runtime", "check": "Firecracker import, tokenizer, load, warmup, inference, and teardown", "implementation": "Firecracker/KVM", "applies_when": "controlled admission requires runtime qualification", "evidence_controls": ["runtime_execution", "firecracker_runtime"]},
    {"id": "MI-12", "category": "Runtime", "check": "No-NIC egress prevention plus guest/host network-attempt telemetry", "implementation": "Firecracker/KVM", "applies_when": "runtime qualification runs", "evidence_controls": ["network_isolation"]},
    {"id": "MI-13", "category": "Runtime", "check": "Host-enforced resource limits and peak measurements", "implementation": "Firecracker/KVM", "applies_when": "runtime qualification runs", "evidence_controls": ["resource_envelope"]},
    {"id": "MI-14", "category": "Conversion", "check": "Controlled unsafe-format conversion, equivalence, new identity, and rescan", "implementation": "Firecracker/KVM", "applies_when": "policy prohibits the source serialization format", "evidence_controls": ["conversion_equivalence"]},
    {"id": "MI-15", "category": "Evaluation", "check": "Known-answer embeddings, output shape, stability, robustness, and approved quality thresholds", "implementation": "deterministic evaluator", "applies_when": "an approved benchmark is configured", "evidence_controls": ["embedding_evaluation"]},
    {"id": "MI-16", "category": "Data plane", "check": "Vector/graph ACL, tenant, cache, deletion, poisoning, and index/model compatibility observations", "implementation": "deterministic evaluator over trusted observations", "applies_when": "the intended corporate integration is available", "evidence_controls": ["data_plane_evaluation"]},
    {"id": "MI-17", "category": "Admission", "check": "Evidence freeze, separated approvals, deterministic policy, signed exact-subject admission, and lifecycle parity", "implementation": "native control plane", "applies_when": "controlled admission is requested", "evidence_controls": ["frozen_evidence", "human_approvals", "deterministic_policy", "signed_admission"]},
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
    attempts = network.get("attempted_operations")
    attempts = attempts if isinstance(attempts, list) else []
    by_family: dict[str, int] = {}
    by_operation: dict[str, int] = {}
    local_ipc_count = 0
    ip_network_count = 0
    for raw in attempts:
        item = raw if isinstance(raw, dict) else {}
        family = str(item.get("address_family") or "UNKNOWN")
        operation = str(item.get("operation") or "unknown")
        by_family[family] = by_family.get(family, 0) + 1
        by_operation[operation] = by_operation.get(operation, 0) + 1
        if family == "AF_UNIX":
            local_ipc_count += 1
        elif family in {"AF_INET", "AF_INET6"}:
            ip_network_count += 1
    return {
        "complete": network.get("complete"),
        "attempt_count": network.get("attempt_count"),
        "local_ipc_attempt_count": local_ipc_count,
        "ip_network_attempt_count": ip_network_count,
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
        observations = _runner_observations(job)
        phases = _json(observations.get("phases"), {})
        phase_rows = []
        for name, raw in phases.items():
            value = raw if isinstance(raw, dict) else {"status": raw}
            phase_rows.append({
                "phase": str(name),
                "status": _normalize_status(value.get("status")),
                "raw_status": value.get("status"),
                "duration_ms": value.get("duration_ms"),
                "detail": value.get("error") or value.get("detail"),
            })
        network = _json(observations.get("network_telemetry"), {})
        resources = _json(observations.get("resource_telemetry"), {})
        output.append({
            "job_id": str(job.get("id") or ""),
            "operation": job.get("operation"),
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
        attempt_count = _integer(network.get("attempt_count"))
        lost_events = _integer(network.get("lost_events"))
        firewall_drops = _integer(network.get("host_firewall_drop_count"))
        network_status = (
            "PASS"
            if network.get("complete") is True
            and attempt_count == 0
            and network.get("overflowed") is False
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
            "detail": "No network attempt or telemetry loss was observed." if network_status == "PASS" else "Network attempts or incomplete/lost telemetry require blocking review.",
            "coverage": network,
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
        "remediation": detail.get("remediation", "Resolve the non-pass result and generate fresh authoritative evidence."),
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
                "coverage": _json(item.get("coverage"), {}),
                "version": item.get("version"),
                "rules_sha256": item.get("rules_sha256"),
                "database_sha256": item.get("database_sha256"),
            }
            for item in scanner_results if isinstance(item, dict)
        ],
        "note": (
            "Per-check static evidence is available and content-free."
            if payload
            else "This evidence predates per-check report summaries; inspect the referenced scan result for scanner-level detail."
        ),
    }


def _check_catalog_with_evidence(controls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {str(item.get("id") or ""): item for item in controls}
    rows: list[dict[str, Any]] = []
    for catalog_item in SHAKERSCAN_CHECK_CATALOG:
        related = [by_id[item] for item in catalog_item["evidence_controls"] if item in by_id]
        rows.append({
            **catalog_item,
            "evidence_statuses": [
                {"control_id": item.get("id"), "status": item.get("status")}
                for item in related
            ],
            "execution_note": (
                "Catalog applicability describes product capability. Only the detailed control and scanner evidence proves what ran for this submission."
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
    timelines = _runner_timelines(runner_jobs)
    artifact_uri = str(artifact.get("immutable_uri") or "").lower() if artifact else ""
    conversion_required = any(
        artifact_uri.split("?", 1)[0].endswith(extension)
        for extension in (".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".joblib")
    )
    runner_controls = _runner_controls(timelines, conversion_required=conversion_required)
    controls.extend(runner_controls)
    # A runtime receipt has one overall status that also covers network and
    # resource containment. The report exposes those as independent controls,
    # so derive the runtime-execution answer from the fixed guest phases rather
    # than double-counting a containment failure as a model-load failure.
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
        receipt_overall_status = runtime_evidence_control.get("status")
        runtime_evidence_control["status"] = execution_status
        runtime_evidence_control["detail"] = (
            "Exact-subject model load, warmup, inference, and teardown passed; "
            "runtime containment is reported by separate network and resource controls."
            if execution_status == "PASS"
            else "One or more fixed exact-subject runtime phases did not pass."
        )
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
        statuses & {"FAIL", "ERROR", "INCOMPLETE", "NOT_RUN"}
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
        "executive_summary": {
            "shakerscan_decision": outcome,
            "deployable_under_configured_shakerscan_policy": outcome == "ALLOW",
            "full_corporate_approval": "NOT_DETERMINED_BY_SHAKERSCAN",
            "decision_statement": summary,
            "authorization_scope": (
                f"Exact registered subject for the {environment or 'unspecified'} environment"
                + (f" until {admission_expiry}" if admission_expiry else "; no active admission expiry exists")
            ),
            "scope_warning": (
                "ALLOW means the exact subject satisfies the configured ShakerScan admission policy. "
                "It is not, by itself, legal, privacy, business, regulatory, platform, or operational authorization."
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
                "external": "EXTERNAL_REQUIRED identifies corporate decisions or operational proofs ShakerScan does not make.",
            },
        },
        "controls": controls,
        "control_counts": control_counts,
        "detailed_review": {
            "control_matrix": controls,
            "static_analysis_detail": _static_check_detail(evidence),
            "shakerscan_check_catalog": _check_catalog_with_evidence(controls),
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
            "A clean static scan is not runtime, embedding-quality, privacy, or deployment approval.",
            "Corporate corpus and data-plane results are authoritative only when attached as trusted generated evidence.",
            "The optional coding-agent planner is advisory and never admission authority.",
            "ShakerScan does not determine legal, privacy, regulatory, supplier, business, safety/fairness, or residual-risk acceptability.",
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

    counts = {
        status: sum(item.get("status") == status for item in controls)
        for status in sorted(CONTROL_STATUSES)
    }
    performed = [item for item in controls if item.get("status") in {"PASS", "FAIL", "REVIEW"}]
    not_completed = [
        item for item in controls
        if item.get("status") in {"ERROR", "INCOMPLETE", "NOT_RUN"}
    ]
    not_applicable = [item for item in controls if item.get("status") == "NOT_APPLICABLE"]
    actions = _required_actions(controls)
    executive = _json(report.get("executive_summary"), {})
    executive.update({
        "shakerscan_decision": report.get("outcome"),
        "deployable_under_configured_shakerscan_policy": report.get("outcome") == "ALLOW",
        "decision_statement": report.get("plain_language"),
        "automatic_technical_review": {
            "state": automatic.get("state"),
            "current_step": current_step,
            "outcome": automatic.get("technical_outcome"),
            "pending_control_count": len(pending),
        },
        "coverage": {
            **_json(executive.get("coverage"), {}),
            "total_controls": len(controls),
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
            for item in controls
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
        "control_matrix": controls,
        "shakerscan_check_catalog": _check_catalog_with_evidence(controls),
        "required_actions": actions,
    })
    report["detailed_review"] = detail
    report.pop("report_sha256", None)
    digest_input = {key: value for key, value in report.items() if key != "generated_at"}
    report["report_sha256"] = hashlib.sha256(_canonical(digest_input)).hexdigest()
    return report


def render_model_intake_html(report: dict[str, Any]) -> str:
    def esc(value: Any) -> str:
        return html.escape(str(value if value is not None else ""))

    executive = _json(report.get("executive_summary"), {})
    coverage = _json(executive.get("coverage"), {})
    detail = _json(report.get("detailed_review"), {})
    performed_ids = set(_json(report.get("assessment_scope"), {}).get("checks_performed") or [])
    not_completed_ids = set(_json(report.get("assessment_scope"), {}).get("checks_not_completed") or [])
    not_applicable_ids = set(_json(report.get("assessment_scope"), {}).get("checks_not_applicable") or [])

    def control_rows(items: list[dict[str, Any]], *, empty: str) -> str:
        return "".join(
            "<tr>"
            f"<td>{esc(item.get('category'))}</td><td>{esc(item.get('label'))}</td>"
            f"<td class='status {esc(str(item.get('status') or '').lower())}'>{esc(item.get('status'))}</td>"
            f"<td>{esc(item.get('detail'))}</td><td>{esc(item.get('remediation'))}</td>"
            "</tr>"
            for item in items
        ) or f"<tr><td colspan='5'>{esc(empty)}</td></tr>"

    controls = report.get("controls", []) if isinstance(report.get("controls"), list) else []
    performed_rows = control_rows([item for item in controls if item.get("id") in performed_ids], empty="No determinate checks were recorded.")
    incomplete_rows = control_rows([item for item in controls if item.get("id") in not_completed_ids], empty="No supported checks are incomplete or not run.")
    not_applicable_rows = control_rows([item for item in controls if item.get("id") in not_applicable_ids], empty="No checks were marked not applicable.")
    rows = "".join(
        "<tr>"
        f"<td>{esc(item.get('category'))}</td><td>{esc(item.get('question'))}</td>"
        f"<td class='status {esc(str(item.get('status') or '').lower())}'>{esc(item.get('status'))}</td>"
        f"<td>{esc(item.get('detail'))}</td><td>{esc(item.get('method'))}</td>"
        f"<td><code>{esc(json.dumps(item.get('coverage') or {}, sort_keys=True, default=str))}</code></td>"
        "</tr>"
        for item in controls
    )
    action_rows = "".join(
        f"<li><strong>{esc(item.get('status'))} — {esc(item.get('control_id'))}:</strong> {esc(item.get('action'))}</li>"
        for item in executive.get("required_actions") or []
    ) or "<li>No unresolved ShakerScan control action is recorded.</li>"
    external_rows = "".join(
        "<tr>"
        f"<td>{esc(item.get('id'))}</td><td>{esc(item.get('status'))}</td><td>{esc(item.get('category'))}</td><td>{esc(item.get('requirement'))}</td>"
        f"<td>{esc(item.get('typical_owner'))}</td><td>{esc(item.get('expected_evidence'))}</td>"
        "</tr>"
        for item in detail.get("external_approval_requirements") or []
    )
    catalog_rows = "".join(
        "<tr>"
        f"<td>{esc(item.get('id'))}</td><td>{esc(item.get('category'))}</td><td>{esc(item.get('check'))}</td>"
        f"<td>{esc(item.get('implementation'))}</td><td>{esc(item.get('applies_when'))}</td>"
        "</tr>"
        for item in detail.get("shakerscan_check_catalog") or []
    )
    phases = "".join(
        f"<tr><td>{esc(job.get('operation'))}</td><td>{esc(phase.get('phase'))}</td><td>{esc(phase.get('status'))}</td><td>{esc(phase.get('duration_ms'))}</td><td>{esc(phase.get('detail'))}</td></tr>"
        for job in report.get("runner_timelines", []) for phase in job.get("phases", [])
    ) or "<tr><td colspan='5'>No Firecracker phase evidence recorded.</td></tr>"
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
<h1>Model Intake corporate review</h1><div class="meta">Submission {esc(report.get('submission', {}).get('id'))} · report sha256:{esc(report.get('report_sha256'))}</div>
<h2>Executive summary</h2>
<div class="verdict"><strong>ShakerScan decision: {esc(executive.get('shakerscan_decision') or report.get('outcome'))}</strong><p>{esc(executive.get('decision_statement') or report.get('plain_language'))}</p><p><strong>Scope:</strong> {esc(executive.get('authorization_scope'))}</p></div>
<div class="warning"><strong>Full corporate approval: {esc(executive.get('full_corporate_approval'))}</strong><p>{esc(executive.get('scope_warning'))}</p></div>
<div class="stats"><span class="stat">{esc(coverage.get('performed'))} performed</span><span class="stat">{esc(coverage.get('passed'))} passed</span><span class="stat">{esc(coverage.get('failed'))} failed</span><span class="stat">{esc(coverage.get('not_completed'))} not completed</span><span class="stat">{esc(coverage.get('external_corporate_requirements'))} external requirements</span></div>
<h3>Required next actions</h3><ol>{action_rows}</ol>
<h3>Checks performed</h3><table><thead><tr><th>Category</th><th>Control</th><th>Status</th><th>Result</th><th>Next step</th></tr></thead><tbody>{performed_rows}</tbody></table>
<h3>Supported checks not completed</h3><table><thead><tr><th>Category</th><th>Control</th><th>Status</th><th>Result</th><th>Next step</th></tr></thead><tbody>{incomplete_rows}</tbody></table>
<h3>Checks not applicable</h3><table><thead><tr><th>Category</th><th>Control</th><th>Status</th><th>Result</th><th>Reason/next step</th></tr></thead><tbody>{not_applicable_rows}</tbody></table>
<h2 class="page-break">Corporate requirements outside ShakerScan</h2><p>These are normal approval inputs, not hidden scan failures. ShakerScan may bind their resulting approvals or evidence, but it does not make these decisions.</p><table><thead><tr><th>ID</th><th>Status</th><th>Category</th><th>Required corporate review</th><th>Typical owner</th><th>Expected evidence</th></tr></thead><tbody>{external_rows}</tbody></table>
<h2 class="page-break">Detailed technical review</h2>
<h3>Control evidence matrix</h3><table><thead><tr><th>Category</th><th>Question</th><th>Status</th><th>Answer</th><th>Method</th><th>Coverage/evidence</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Firecracker phase timeline</h2><table><thead><tr><th>Operation</th><th>Phase</th><th>Status</th><th>Duration ms</th><th>Detail</th></tr></thead><tbody>{phases}</tbody></table>
<h2>ShakerScan check catalog</h2><p>This is the implemented capability catalog. The control and scanner evidence above—not catalog membership—proves what ran for this submission.</p><table><thead><tr><th>ID</th><th>Category</th><th>Check</th><th>Implementation</th><th>Applicability</th></tr></thead><tbody>{catalog_rows}</tbody></table>
<h2>Authority bindings</h2><pre>{esc(json.dumps(report.get('authority_bindings') or {}, indent=2, sort_keys=True, default=str))}</pre>
<h2>Limitations</h2><ul>{''.join(f'<li>{esc(item)}</li>' for item in report.get('limitations', []))}</ul>
</body></html>"""


def model_intake_report_to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    controls = report.get("controls") if isinstance(report.get("controls"), list) else []
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
            },
        }],
    }


__all__ = [
    "CONTROL_STATUSES", "REPORT_SCHEMA", "apply_automatic_review_context", "build_model_intake_report",
    "model_intake_report_to_sarif", "render_model_intake_html",
]
