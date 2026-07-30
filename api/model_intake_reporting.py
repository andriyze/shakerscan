"""Normalized, content-free controlled Model Intake reports and exports."""

from __future__ import annotations

import hashlib
import html
import json
from datetime import datetime, timezone
from typing import Any, Iterable


REPORT_SCHEMA = "model-intake-corporate-report/v1"
CONTROL_STATUSES = {
    "PASS", "FAIL", "REVIEW", "INCOMPLETE", "ERROR", "NOT_RUN", "NOT_APPLICABLE",
}
PRODUCTION_APPROVAL_ROLES = {
    "model_security_reviewer", "ml_platform_reviewer", "release_manager",
}


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
    return {
        "id": evidence_type,
        "label": label,
        "status": status,
        "detail": (
            f"{provenance} evidence expired at {_iso(expiry)}."
            if expiry is not None and expiry <= now
            else f"{provenance} evidence reported {record.get('status') or 'unknown'}."
        ),
        "coverage": {
            "provenance_class": provenance,
            "producer_id": record.get("producer_id"),
            "builder_id": record.get("builder_id"),
            "payload_sha256": record.get("payload_sha256"),
            "subject_bindings": bindings,
                "expires_at": _iso(expiry),
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
            "network": {
                "complete": network.get("complete"),
                "attempt_count": network.get("attempt_count"),
                "attempted_operations": network.get("attempted_operations"),
                "attempts_by_phase": network.get("attempts_by_phase"),
                "overflowed": network.get("overflowed"),
                "lost_events": network.get("lost_events"),
                "guest_interfaces": network.get("guest_interfaces"),
                "host_interfaces": network.get("host_interfaces"),
                "host_firewall_drop_count": network.get("host_firewall_drop_count"),
                "telemetry_sha256": network.get("telemetry_sha256"),
            },
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
            else "Fixed conversion/equivalence phase evidence is recorded."
        ),
        "coverage": {} if not conversion else {"phases": len(conversion.get("phases") or [])},
        "evidence_refs": [] if not conversion else [{"kind": "runner_job", "id": conversion["job_id"]}],
    }
    return [runtime_control, network_control, resource_control, conversion_control]


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
    controls.extend(_runner_controls(timelines, conversion_required=conversion_required))
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
        "controls": controls,
        "control_counts": {status: sum(item["status"] == status for item in controls) for status in sorted(CONTROL_STATUSES)},
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
        ],
    }
    digest_input = {key: value for key, value in report.items() if key != "generated_at"}
    report["report_sha256"] = hashlib.sha256(_canonical(digest_input)).hexdigest()
    return report


def render_model_intake_html(report: dict[str, Any]) -> str:
    def esc(value: Any) -> str:
        return html.escape(str(value if value is not None else ""))

    rows = "".join(
        "<tr>"
        f"<td>{esc(item['label'])}</td><td class='status {esc(item['status'].lower())}'>{esc(item['status'])}</td>"
        f"<td>{esc(item['detail'])}</td><td><code>{esc(json.dumps(item.get('coverage') or {}, sort_keys=True, default=str))}</code></td>"
        "</tr>"
        for item in report.get("controls", [])
    )
    phases = "".join(
        f"<tr><td>{esc(job.get('operation'))}</td><td>{esc(phase.get('phase'))}</td><td>{esc(phase.get('status'))}</td><td>{esc(phase.get('duration_ms'))}</td><td>{esc(phase.get('detail'))}</td></tr>"
        for job in report.get("runner_timelines", []) for phase in job.get("phases", [])
    ) or "<tr><td colspan='5'>No Firecracker phase evidence recorded.</td></tr>"
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Model Intake {esc(report.get('outcome'))}</title>
<style>
body{{font:14px system-ui,sans-serif;margin:32px;color:#172033}}h1{{margin-bottom:4px}}.meta{{color:#5b6475}}
.verdict{{padding:16px;border:2px solid #555;border-radius:8px;margin:20px 0}}table{{border-collapse:collapse;width:100%;margin:16px 0}}
th,td{{border:1px solid #ccd2dc;padding:8px;vertical-align:top;text-align:left}}code{{white-space:pre-wrap;word-break:break-all;font-size:11px}}
.status{{font-weight:700}}.pass{{color:#08783e}}.fail,.error{{color:#b42318}}.review,.incomplete,.not_run{{color:#9a6700}}
.no-print{{margin-right:8px}}@media print{{.no-print{{display:none}}body{{margin:12mm}}}}
</style></head><body>
<button class="no-print" onclick="window.print()">Print / Save PDF</button>
<h1>Model Intake corporate review</h1><div class="meta">Submission {esc(report.get('submission', {}).get('id'))} · report sha256:{esc(report.get('report_sha256'))}</div>
<div class="verdict"><strong>{esc(report.get('outcome'))}</strong><p>{esc(report.get('plain_language'))}</p></div>
<h2>Controls</h2><table><thead><tr><th>Control</th><th>Status</th><th>Answer</th><th>Coverage/evidence</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Firecracker phase timeline</h2><table><thead><tr><th>Operation</th><th>Phase</th><th>Status</th><th>Duration ms</th><th>Detail</th></tr></thead><tbody>{phases}</tbody></table>
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
    "CONTROL_STATUSES", "REPORT_SCHEMA", "build_model_intake_report",
    "model_intake_report_to_sarif", "render_model_intake_html",
]
