"""Content-safe public projections of durable canonical Scan execution state."""

from __future__ import annotations

from collections import Counter
from datetime import date, datetime
import json
from typing import Any, Mapping, Sequence


EXPLANATION_SCHEMA = "scan-execution-explanation/v1"
ACTION_LIST_SCHEMA = "scan-action-list/v1"
CAPABILITY_LIST_SCHEMA = "scan-capability-coverage/v1"
COVERAGE_SCHEMA = "scan-coverage-explanation/v1"

_TERMINAL = frozenset({
    "success", "partial", "skipped", "blocked", "failed", "cancelled",
    "timed_out",
})
_SUCCESS = frozenset({"success"})
_ACTIVE_VERIFIERS = frozenset({
    "templates.scan", "xss.verify", "sqli.verify", "authz.verify",
    "browser.proof",
})
_TRAFFIC_DIMENSIONS = frozenset({
    "http_requests", "state_changing_requests", "browser_actions",
    "tcp_ports_attempted", "hosts_attempted",
})

_REASON_LABELS = {
    "capability_unknown": "The action capability is not registered",
    "policy_disabled": "Disabled by scan policy",
    "insufficient_plan_budget": "Not enough admitted scan budget",
    "dependency_failed": "A required earlier action did not complete",
    "placement_unavailable": "No eligible worker placement was available",
    "authorization_expired": "Testing approval expired before execution",
    "authorization_revoked": "Testing approval was revoked",
    "scope_invalid": "Target scope no longer matched the approved scope",
    "cancelled": "The scan was cancelled",
    "timed_out": "The action reached its fixed time limit",
    "adapter_failed": "The capability adapter failed",
    "parser_failed": "The capability output could not be parsed safely",
    "output_truncated": "The bounded output limit was reached",
    "manifest_unavailable": "Required immutable work was unavailable",
    "unsupported_output_schema": "The worker returned an unsupported result format",
    "not_applicable": "The capability did not apply to this target",
    "active_verifier_zero_attempts": "An active verifier had candidates but made no bounded attempt",
    "missing_terminal_result": "A required capability has no terminal result",
}


def _json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value
    return value


def _object(value: Any) -> dict[str, Any]:
    decoded = _json(value)
    return dict(decoded) if isinstance(decoded, Mapping) else {}


def _array(value: Any) -> list[Any]:
    decoded = _json(value)
    return list(decoded) if isinstance(decoded, (list, tuple)) else []


def _text(value: Any, *, maximum: int = 200) -> str | None:
    normalized = str(value or "").strip()
    return normalized[:maximum] if normalized else None


def _timestamp(value: Any) -> str | None:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return _text(value, maximum=80)


def _integer(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def _budget(value: Any) -> dict[str, int]:
    result: dict[str, int] = {}
    for raw_name, raw_amount in _object(value).items():
        name = str(raw_name or "").strip()
        if not name:
            continue
        try:
            amount = int(raw_amount)
        except (TypeError, ValueError):
            continue
        if amount >= 0:
            result[name] = amount
    return {name: result[name] for name in sorted(result)}


def _label(value: Any) -> str:
    raw = str(value or "Action").replace(".", " ").replace("_", " ")
    aliases = {"tls": "TLS", "dns": "DNS", "http": "HTTP", "xss": "XSS", "sqli": "SQLi"}
    return " ".join(
        aliases.get(part.lower(), part.capitalize()) for part in raw.split() if part
    )


def _reason_label(value: Any) -> str | None:
    reason = _text(value, maximum=100)
    if reason is None:
        return None
    return _REASON_LABELS.get(reason, _label(reason))


def _observation_projection(value: Any, *, scan_id: str, action_id: str) -> dict[str, Any] | None:
    manifest = _object(value)
    manifest_id = _text(
        manifest.get("manifest_id") or manifest.get("id"), maximum=80,
    )
    if not manifest and not manifest_id:
        return None
    return {
        "manifest_id": manifest_id,
        "count": _integer(manifest.get("count") or manifest.get("observation_count")),
        "size_bytes": _integer(manifest.get("size_bytes")),
        "sha256": _text(
            manifest.get("sha256") or manifest.get("content_sha256"), maximum=64,
        ),
        "manifest_digest": _text(manifest.get("manifest_digest"), maximum=64),
        "href": f"/scans/{scan_id}/actions#{action_id}",
    }


def _receipt_projection(value: Any, row: Mapping[str, Any]) -> dict[str, Any] | None:
    receipt = _object(value)
    receipt_id = _text(receipt.get("receipt_id") or row.get("receipt_id"), maximum=80)
    receipt_hash = _text(receipt.get("receipt_hash") or row.get("receipt_hash"), maximum=64)
    if receipt_id is None and receipt_hash is None:
        return None
    execution = _object(receipt.get("redacted_execution"))
    raw_provenance = _object(execution.get("provenance"))
    provenance_keys = (
        "source_revision", "build_fingerprint", "image_digest", "binary_path",
        "binary_version", "binary_sha256", "adapter_version", "parser_version",
        "template_manifest_digest", "wordlist_manifest_digest", "accounting_mode",
    )
    provenance = {
        key: _text(raw_provenance.get(key), maximum=300)
        for key in provenance_keys if _text(raw_provenance.get(key), maximum=300)
    }
    return {
        "receipt_id": receipt_id,
        "receipt_hash": receipt_hash,
        "started_at": _timestamp(receipt.get("started_at") or row.get("started_at")),
        "finished_at": _timestamp(receipt.get("finished_at") or row.get("finished_at")),
        "parser_version": _text(receipt.get("parser_version"), maximum=200),
        "provenance": provenance,
    }


def _work_manifests(execution: Mapping[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for raw in _array(execution.get("work_manifests")):
        item = _object(raw)
        kind = _text(item.get("kind"), maximum=40)
        manifest_id = _text(item.get("manifest_id"), maximum=80)
        digest = _text(item.get("manifest_digest"), maximum=64)
        if not kind or not manifest_id or not digest:
            continue
        result.append({
            "kind": kind,
            "manifest_id": manifest_id,
            "manifest_digest": digest,
            "entry_count": _integer(item.get("entry_count")),
            "status": _text(item.get("status"), maximum=40) or "unknown",
        })
    result.sort(key=lambda item: (item["kind"], item["manifest_id"]))
    return result


def build_scan_execution_explanation(
    *,
    scan_id: str,
    scan_status: str,
    plan_payload: Mapping[str, Any] | None,
    action_rows: Sequence[Mapping[str, Any]],
    report: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Merge immutable plan, durable action index, and final report metadata.

    Capability arguments, observation bodies, private object keys, credentials,
    lease tokens, and raw receipts are intentionally absent from this projection.
    """
    plan = _object(plan_payload)
    report_payload = _object(report)
    execution = _object(report_payload.get("canonical_action_execution"))
    report_actions = {
        str(item.get("action_id")): item
        for item in (_object(raw) for raw in _array(execution.get("actions")))
        if item.get("action_id")
    }
    finalization = _object(execution.get("finalization_action"))
    if finalization.get("action_id"):
        report_actions.setdefault(str(finalization["action_id"]), finalization)
    indexed = {
        str(row.get("action_id")): dict(row)
        for row in action_rows if row.get("action_id")
    }
    planned = [
        _object(raw) for raw in _array(plan.get("actions"))
        if _object(raw).get("action_id")
    ]
    if not planned:
        planned = [
            {**row, "ordinal": row.get("ordinal", index)}
            for index, row in enumerate(sorted(
                indexed.values(), key=lambda item: _integer(item.get("ordinal")),
            ))
        ]

    actions: list[dict[str, Any]] = []
    parity_ok = True
    for fallback_ordinal, raw_plan in enumerate(planned):
        action_id = str(raw_plan.get("action_id") or "")
        row = indexed.get(action_id, {})
        terminal = report_actions.get(action_id, {})
        plan_status = _text(raw_plan.get("admission_status"), maximum=40) or "planned"
        row_status = _text(row.get("status"), maximum=40)
        report_status = _text(terminal.get("status"), maximum=40)
        status = (
            report_status
            if report_status in _TERMINAL and row_status not in _TERMINAL
            else row_status or report_status or plan_status
        )
        if row and terminal:
            if row_status in _TERMINAL and report_status in _TERMINAL and row_status != report_status:
                parity_ok = False
        reason = (
            _text(row.get("reason_code"), maximum=100)
            or _text(terminal.get("reason_code"), maximum=100)
            or _text(raw_plan.get("reason_code"), maximum=100)
        )
        placement = _object(raw_plan.get("placement") or row.get("placement_json"))
        result_payload = _object(row.get("result_json"))
        observation = (
            _observation_projection(
                terminal.get("observation_manifest")
                or result_payload.get("observation_manifest_ref"),
                scan_id=scan_id,
                action_id=action_id,
            )
            or (
                {
                    "manifest_id": _text(row.get("observation_manifest_id"), maximum=80),
                    "count": 0,
                    "size_bytes": 0,
                    "sha256": None,
                    "manifest_digest": None,
                    "href": f"/scans/{scan_id}/actions#{action_id}",
                }
                if row.get("observation_manifest_id") else None
            )
        )
        reserved = _budget(
            terminal.get("budget_reserved")
            or result_payload.get("budget_reserved")
            or row.get("requested_budget")
            or raw_plan.get("requested_budget")
        )
        consumed = _budget(
            terminal.get("budget_consumed")
            or result_payload.get("budget_consumed")
        )
        capability = str(
            raw_plan.get("capability_name") or row.get("capability_name") or "unknown"
        )
        action = {
            "action_id": action_id,
            "label": _label(action_id),
            "ordinal": _integer(raw_plan.get("ordinal"), fallback_ordinal),
            "stage": _text(raw_plan.get("stage") or row.get("stage"), maximum=128) or "unknown",
            "capability_name": capability,
            "capability_label": _label(capability),
            "required": bool(raw_plan.get("required", row.get("required", False))),
            "supporting": bool(raw_plan.get("supporting", row.get("supporting", False))),
            "status": status or "missing",
            "reason_code": reason,
            "reason": _reason_label(reason),
            "dependencies": [
                str(item) for item in _array(
                    raw_plan.get("dependencies") or row.get("dependencies_json")
                )[:64]
            ],
            "placement": {
                "eligible_backends": [
                    str(item) for item in _array(placement.get("eligible_backends"))[:8]
                ],
                "backend": _text(row.get("backend_name"), maximum=80),
                "worker_id": _text(row.get("worker_id"), maximum=200),
                "attempt": _integer(row.get("attempt")),
            },
            "budget": {"reserved": reserved, "consumed": consumed},
            "observation": observation,
            "receipt": _receipt_projection(row.get("receipt_json"), row),
            "result_digest": _text(row.get("result_digest"), maximum=64),
            "action_digest": _text(
                raw_plan.get("action_digest") or row.get("action_digest"), maximum=64,
            ),
        }
        actions.append(action)
    actions.sort(key=lambda item: (item["ordinal"], item["action_id"]))

    stage_order: list[str] = []
    for action in actions:
        if action["stage"] not in stage_order:
            stage_order.append(action["stage"])
    stages: list[dict[str, Any]] = []
    for index, stage in enumerate(stage_order):
        rows = [item for item in actions if item["stage"] == stage]
        counts = Counter(str(item["status"]) for item in rows)
        if any(status in counts for status in ("failed", "blocked")):
            status = "failed"
        elif "cancelled" in counts:
            status = "cancelled"
        elif any(status in counts for status in ("running", "leased")):
            status = "running"
        elif "planned" in counts or "missing" in counts:
            status = "pending"
        elif any(status in counts for status in ("partial", "timed_out")):
            status = "partial"
        elif "skipped" in counts:
            status = "complete_with_gaps"
        elif rows and all(item["status"] in _TERMINAL for item in rows):
            status = "complete"
        else:
            status = "pending"
        stages.append({
            "index": index,
            "stage": stage,
            "label": _label(stage),
            "status": status,
            "action_count": len(rows),
            "status_counts": dict(sorted(counts.items())),
        })

    capability_rows = [
        item for item in actions if item["action_id"] != "finalize.report"
    ]
    grouped: list[dict[str, Any]] = []
    for name in sorted({str(item["capability_name"]) for item in capability_rows}):
        rows = [item for item in capability_rows if item["capability_name"] == name]
        counts = Counter(str(item["status"]) for item in rows)
        grouped.append({
            "capability_name": name,
            "label": _label(name),
            "action_count": len(rows),
            "required_action_count": sum(1 for item in rows if item["required"]),
            "status_counts": dict(sorted(counts.items())),
            "reserved_budget": _sum_budgets(
                item["budget"]["reserved"] for item in rows
            ),
            "consumed_budget": _sum_budgets(
                item["budget"]["consumed"] for item in rows
            ),
            "observation_count": sum(
                _integer((item.get("observation") or {}).get("count")) for item in rows
            ),
        })

    counts = Counter(str(item["status"]) for item in capability_rows)
    required_rows = [item for item in capability_rows if item["required"]]
    required_incomplete = [
        item for item in required_rows if item["status"] not in _SUCCESS
    ]
    work_manifests = _work_manifests(execution)
    candidate_count = sum(
        item["entry_count"] for item in work_manifests
        if item["kind"] == "candidate" and item["status"] != "cancelled"
    )
    zero_attempt_verifiers = [
        item for item in capability_rows
        if candidate_count > 0
        and item["capability_name"] in _ACTIVE_VERIFIERS
        and item["status"] in {"success", "partial"}
        and not any(
            amount > 0 for name, amount in item["budget"]["consumed"].items()
            if name in _TRAFFIC_DIMENSIONS
        )
    ]
    reliability_reasons = sorted({
        str(item.get("reason_code") or "missing_terminal_result")
        for item in required_incomplete
    } | ({"active_verifier_zero_attempts"} if zero_attempt_verifiers else set()))
    report_coverage = _object(report_payload.get("coverage"))
    coverage_status = _text(report_coverage.get("status"), maximum=40)
    if not coverage_status:
        if str(scan_status) == "cancelled" or counts.get("cancelled"):
            coverage_status = "cancelled"
        elif counts.get("failed") or counts.get("blocked"):
            coverage_status = "failed"
        elif required_incomplete or zero_attempt_verifiers:
            coverage_status = "partial"
        elif any(item["status"] not in _TERMINAL for item in capability_rows):
            coverage_status = "in_progress"
        else:
            coverage_status = "complete"
    grade_reliable = not reliability_reasons and coverage_status == "complete"
    optional_gaps = [
        {
            "action_id": item["action_id"],
            "capability_name": item["capability_name"],
            "status": item["status"],
            "reason_code": item["reason_code"],
            "reason": item["reason"],
        }
        for item in capability_rows
        if not item["required"] and item["status"] != "success"
    ]
    capability_coverage = {
        "total": len(capability_rows),
        "required": len(required_rows),
        "completed": counts.get("success", 0),
        "partial": counts.get("partial", 0) + counts.get("timed_out", 0),
        "blocked": counts.get("blocked", 0),
        "failed": counts.get("failed", 0),
        "skipped": counts.get("skipped", 0),
        "cancelled": counts.get("cancelled", 0),
        "pending": sum(
            counts.get(status, 0) for status in ("planned", "leased", "running", "missing")
        ),
        "actions": [{
            "action_id": item["action_id"],
            "capability_name": item["capability_name"],
            "required": item["required"],
            "status": item["status"],
            "reason_code": item["reason_code"],
        } for item in capability_rows],
    }
    selected_backends = sorted({
        str(item["placement"]["backend"])
        for item in actions if item["placement"]["backend"]
    })
    plan_digest = _text(
        plan.get("plan_digest") or execution.get("plan_digest"), maximum=64,
    )
    transport_parity = {
        "contract": "identical_canonical_action_graph/v1",
        "consistent": parity_ok,
        "selected_backends": selected_backends,
        "local_eligible": all(
            not item["placement"]["eligible_backends"]
            or "local" in item["placement"]["eligible_backends"]
            for item in actions
        ),
        "broker_eligible": all(
            not item["placement"]["eligible_backends"]
            or "broker" in item["placement"]["eligible_backends"]
            for item in actions
        ),
    }
    return {
        "schema_version": EXPLANATION_SCHEMA,
        "scan_id": str(scan_id),
        "scan_status": str(scan_status or "unknown"),
        "plan_digest": plan_digest,
        "execution_plan_digest": _text(
            plan.get("execution_plan_digest") or execution.get("execution_plan_digest"),
            maximum=64,
        ),
        "target_binding_digest": _text(
            plan.get("target_binding_digest") or execution.get("target_binding_digest"),
            maximum=64,
        ),
        "stage_timeline": stages,
        "actions": actions,
        "capabilities": grouped,
        "coverage": {
            "status": coverage_status,
            "capability_coverage": capability_coverage,
            "grade_reliability": {
                "reliable": grade_reliable,
                "reasons": reliability_reasons,
                "reason_labels": [_reason_label(item) for item in reliability_reasons],
                "warning": (
                    None if grade_reliable
                    else "The grade is provisional because required coverage did not complete cleanly."
                ),
            },
            "optional_gaps": optional_gaps,
            "active_zero_attempt_actions": [
                item["action_id"] for item in zero_attempt_verifiers
            ],
            "work_manifests": work_manifests,
        },
        "transport_parity": transport_parity,
    }


def _sum_budgets(values: Sequence[Mapping[str, int]] | Any) -> dict[str, int]:
    totals: Counter[str] = Counter()
    for value in values:
        for name, amount in dict(value).items():
            totals[str(name)] += max(0, int(amount))
    return {name: totals[name] for name in sorted(totals)}


def action_list_response(explanation: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": ACTION_LIST_SCHEMA,
        "scan_id": explanation.get("scan_id"),
        "plan_digest": explanation.get("plan_digest"),
        "stage_timeline": list(explanation.get("stage_timeline") or []),
        "actions": list(explanation.get("actions") or []),
        "transport_parity": dict(explanation.get("transport_parity") or {}),
    }


def capability_list_response(explanation: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": CAPABILITY_LIST_SCHEMA,
        "scan_id": explanation.get("scan_id"),
        "plan_digest": explanation.get("plan_digest"),
        "capabilities": list(explanation.get("capabilities") or []),
        "capability_coverage": dict(
            _object(explanation.get("coverage")).get("capability_coverage") or {}
        ),
    }


def coverage_response(explanation: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": COVERAGE_SCHEMA,
        "scan_id": explanation.get("scan_id"),
        "plan_digest": explanation.get("plan_digest"),
        **dict(explanation.get("coverage") or {}),
        "transport_parity": dict(explanation.get("transport_parity") or {}),
    }
