"""Content-safe public projections of durable canonical Scan execution state."""

from __future__ import annotations

from collections import Counter
from datetime import date, datetime
import json
from typing import Any, Mapping, Sequence

from .parallel_compiler import (
    parallel_action_occurrence_id,
    summarize_parallel_action_coverage,
)


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
    "templates.active_batch", "xss.verify_batch", "sqli.verify_batch",
    "browser.proof",
})
_TRAFFIC_DIMENSIONS = frozenset({
    "http_requests", "state_changing_requests", "browser_actions",
    "tcp_ports_attempted", "hosts_attempted",
})
_SCAN_BUDGET_FIELDS = {
    "max_http_requests": "http_requests",
    "max_state_changing_requests": "state_changing_requests",
    "max_browser_actions": "browser_actions",
    "max_tcp_ports": "tcp_ports_attempted",
    "max_hosts": "hosts_attempted",
    "max_tool_wall_seconds": "tool_wall_seconds",
}

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
    "unproven_critical_high": "High or critical candidates still require deterministic proof",
    "report_grade_unreliable": "The final report marked the grade as provisional",
    "scan_in_progress": "Required actions are still running",
    "missing_terminal_result": "A required capability has no terminal result",
    "parallel_child_incomplete": "At least one parallel shard completed with partial coverage",
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


def _scan_budget_limits(value: Any) -> dict[str, int]:
    raw = _object(value)
    limits = _budget(raw)
    for source, target in _SCAN_BUDGET_FIELDS.items():
        if source in raw:
            limits[target] = _integer(raw[source])
    return {
        name: limits[name]
        for name in sorted(set(limits) & set(_SCAN_BUDGET_FIELDS.values()))
    }


def _budget_difference(
    left: Mapping[str, int], right: Mapping[str, int],
) -> dict[str, int]:
    names = set(left) | set(right)
    return {
        name: max(0, int(left.get(name, 0)) - int(right.get(name, 0)))
        for name in sorted(names)
        if int(left.get(name, 0)) - int(right.get(name, 0)) > 0
    }


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


def _observation_projection(
    value: Any, *, scan_id: str, occurrence_id: str,
) -> dict[str, Any] | None:
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
        "href": f"/scans/{scan_id}/actions#{occurrence_id}",
    }


def _occurrence_id(
    row: Mapping[str, Any], *, default_scan_id: str, action_id: str,
) -> str:
    supplied = str(row.get("occurrence_id") or "").strip().lower()
    if len(supplied) == 64 and all(char in "0123456789abcdef" for char in supplied):
        return supplied
    owner = str(row.get("scan_id") or default_scan_id).strip()
    return parallel_action_occurrence_id(owner, action_id)


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
    plan_revision: Mapping[str, Any] | None = None,
    plan_budget_limits: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Merge immutable plan, durable action index, and final report metadata.

    Capability arguments, observation bodies, private object keys, credentials,
    lease tokens, and raw receipts are intentionally absent from this projection.
    """
    plan = _object(plan_payload)
    report_payload = _object(report)
    report_execution = _object(report_payload.get("canonical_action_execution"))
    parallel_execution = _object(
        _object(report_payload.get("parallel")).get("canonical_action_execution")
    )
    parallel_actions = _array(parallel_execution.get("actions"))
    execution = parallel_execution if parallel_actions else report_execution
    raw_revision = _object(
        plan_revision or report_execution.get("plan_revision")
        or execution.get("plan_revision")
    )
    public_revision = {
        "schema_version": _text(raw_revision.get("schema_version"), maximum=80),
        "revision": _integer(raw_revision.get("revision")),
        "plan_digest": _text(raw_revision.get("plan_digest"), maximum=64),
        "parent_plan_digest": _text(
            raw_revision.get("parent_plan_digest"), maximum=64,
        ) or None,
        "continuation_allocation_digest": _text(
            raw_revision.get("continuation_allocation_digest"), maximum=64,
        ) or None,
        "discovery_result_digest": _text(
            raw_revision.get("discovery_result_digest"), maximum=64,
        ) or None,
        "work_manifest_references": _work_manifests({
            "work_manifests": raw_revision.get("work_manifest_references") or [],
        }),
        "continuation_plan_digest": _text(
            raw_revision.get("continuation_plan_digest"), maximum=64,
        ) or None,
        "revision_digest": _text(
            raw_revision.get("revision_digest"), maximum=64,
        ) or None,
    } if raw_revision else {}
    report_actions: dict[str, dict[str, Any]] = {}
    for item in (_object(raw) for raw in _array(execution.get("actions"))):
        action_id = str(item.get("action_id") or "")
        if action_id:
            report_actions[_occurrence_id(
                item, default_scan_id=scan_id, action_id=action_id,
            )] = item
    finalization = _object(
        execution.get("finalization_action")
        or report_execution.get("finalization_action")
    )
    if finalization.get("action_id"):
        final_action_id = str(finalization["action_id"])
        report_actions.setdefault(
            _occurrence_id(
                finalization,
                default_scan_id=scan_id,
                action_id=final_action_id,
            ),
            finalization,
        )
    indexed = {
        str(row.get("action_id")): dict(row)
        for row in action_rows if row.get("action_id")
    }
    indexed_occurrences = {
        _occurrence_id(
            row,
            default_scan_id=scan_id,
            action_id=str(row.get("action_id") or ""),
        ): dict(row)
        for row in action_rows if row.get("action_id")
    }
    planned = [
        _object(raw) for raw in _array(plan.get("actions"))
        if _object(raw).get("action_id")
    ]
    if parallel_actions:
        parent_actions = {
            str(item.get("action_id")): item for item in planned
            if item.get("action_id")
        }
        planned = []
        for ordinal, raw in enumerate(parallel_actions):
            terminal = _object(raw)
            action_id = str(terminal.get("action_id") or "")
            if not action_id:
                continue
            parent_action = parent_actions.get(action_id, {})
            planned.append({
                **parent_action,
                "action_id": action_id,
                "occurrence_id": _occurrence_id(
                    terminal,
                    default_scan_id=scan_id,
                    action_id=action_id,
                ),
                "ordinal": ordinal,
                "stage": terminal.get("stage") or parent_action.get("stage"),
                "capability_name": (
                    terminal.get("capability_name")
                    or parent_action.get("capability_name")
                ),
                "required": bool(
                    terminal.get("required", parent_action.get("required", False))
                ),
                "supporting": bool(
                    terminal.get("supporting", parent_action.get("supporting", False))
                ),
                "requested_budget": (
                    parent_action.get("requested_budget")
                    or terminal.get("budget_reserved")
                ),
                "admission_status": terminal.get("status") or "planned",
            })
        if finalization.get("action_id"):
            final_action_id = str(finalization["action_id"])
            parent_finalizer = parent_actions.get(final_action_id, {})
            planned.append({
                **parent_finalizer,
                "action_id": final_action_id,
                "occurrence_id": _occurrence_id(
                    finalization,
                    default_scan_id=scan_id,
                    action_id=final_action_id,
                ),
                "ordinal": len(planned),
                "stage": parent_finalizer.get("stage") or "finalize_evidence",
                "capability_name": (
                    parent_finalizer.get("capability_name") or "scan.finalize"
                ),
                "required": True,
                "supporting": False,
                "admission_status": finalization.get("status") or "planned",
            })
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
        occurrence_id = _occurrence_id(
            raw_plan,
            default_scan_id=scan_id,
            action_id=action_id,
        )
        row = (
            indexed_occurrences.get(occurrence_id, {})
            if parallel_actions else indexed.get(action_id, {})
        )
        terminal = report_actions.get(occurrence_id, {})
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
        if report_status in _TERMINAL:
            # The terminal receipt supersedes placeholder/admission reasons.  A
            # successful child action must not inherit a stale parent-plan gap.
            reason = _text(terminal.get("reason_code"), maximum=100)
        else:
            reason = (
                _text(row.get("reason_code"), maximum=100)
                or _text(raw_plan.get("reason_code"), maximum=100)
            )
        placement = _object(raw_plan.get("placement") or row.get("placement_json"))
        result_payload = _object(row.get("result_json"))
        observation = (
            _observation_projection(
                terminal.get("observation_manifest")
                or result_payload.get("observation_manifest_ref"),
                scan_id=scan_id,
                occurrence_id=occurrence_id,
            )
            or (
                {
                    "manifest_id": _text(row.get("observation_manifest_id"), maximum=80),
                    "count": 0,
                    "size_bytes": 0,
                    "sha256": None,
                    "manifest_digest": None,
                    "href": f"/scans/{scan_id}/actions#{occurrence_id}",
                }
                if row.get("observation_manifest_id") else None
            )
        )
        allocated = _budget(
            raw_plan.get("requested_budget") or row.get("requested_budget")
        )
        reservation_status = _text(row.get("reservation_status"), maximum=40)
        reservation_reserved = (
            _budget(row.get("reservation_requested"))
            if bool(row.get("reservation_hold_applied")) else {}
        )
        reserved = _budget(
            terminal.get("budget_reserved")
            or result_payload.get("budget_reserved")
            or reservation_reserved
        )
        consumed = _budget(
            terminal.get("budget_consumed")
            or result_payload.get("budget_consumed")
            or row.get("reservation_actual")
        )
        uncertain = reserved if bool(row.get("execution_uncertain")) else {}
        terminal_status = (status or "") in _TERMINAL
        released = (
            _budget_difference(reserved, consumed)
            if terminal_status and not uncertain else {}
        )
        capability = str(
            raw_plan.get("capability_name") or row.get("capability_name") or "unknown"
        )
        action = {
            "action_id": action_id,
            "occurrence_id": occurrence_id,
            "label": _label(action_id),
            "ordinal": _integer(raw_plan.get("ordinal"), fallback_ordinal),
            "stage": _text(raw_plan.get("stage") or row.get("stage"), maximum=128) or "unknown",
            "capability_name": capability,
            "capability_label": _label(capability),
            "output_schema": _text(
                raw_plan.get("output_schema") or row.get("output_schema"),
                maximum=200,
            ),
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
            "budget": {
                "allocated": allocated,
                "reserved": reserved,
                "consumed": consumed,
                "released": released,
                "uncertain": uncertain,
                "reservation_status": reservation_status,
            },
            "observation": observation,
            "receipt": _receipt_projection(
                terminal.get("receipt") or row.get("receipt_json"), row,
            ),
            "result_digest": _text(row.get("result_digest"), maximum=64),
            "action_digest": _text(
                raw_plan.get("action_digest") or row.get("action_digest"), maximum=64,
            ),
        }
        actions.append(action)
    actions.sort(key=lambda item: (item["ordinal"], item["occurrence_id"]))

    stage_order: list[str] = []
    for action in actions:
        if action["stage"] not in stage_order:
            stage_order.append(action["stage"])
    stages: list[dict[str, Any]] = []
    scan_is_terminal = str(scan_status or "").strip().lower() in {
        "completed", "failed", "cancelled",
    }
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
            observed = sum(
                amount for action_status, amount in counts.items()
                if action_status not in {"planned", "missing"}
            )
            status = (
                "partial" if scan_is_terminal and observed > 0
                else "not_run" if scan_is_terminal
                else "pending"
            )
        elif any(status in counts for status in ("partial", "timed_out")):
            status = "partial"
        elif "skipped" in counts:
            status = "complete_with_gaps"
        elif rows and all(item["status"] in _TERMINAL for item in rows):
            status = "complete"
        else:
            status = "not_run" if scan_is_terminal else "pending"
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
    work_manifests = _work_manifests(
        report_execution if parallel_actions else execution
    )
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
    report_coverage = (
        summarize_parallel_action_coverage(
            parallel_execution,
            additional_reliability_reasons=_array(
                _object(_object(report_payload.get("coverage")).get("grade_reliability"))
                .get("reasons")
            ),
        )
        if parallel_actions
        else _object(report_payload.get("coverage"))
    )
    report_reliability = _object(report_coverage.get("grade_reliability"))
    scan_terminal = str(scan_status) in {"completed", "failed", "cancelled"}
    required_nonterminal = [
        item for item in required_incomplete if item["status"] not in _TERMINAL
    ]
    reliability_reasons = sorted({
        (
            "scan_in_progress"
            if item["status"] not in _TERMINAL and not scan_terminal
            else str(item.get("reason_code") or "missing_terminal_result")
        )
        for item in required_incomplete
    } | ({"active_verifier_zero_attempts"} if zero_attempt_verifiers else set()) | {
        str(item)[:100]
        for item in _array(report_reliability.get("reasons"))
        if str(item).strip()
    })
    coverage_status = _text(report_coverage.get("status"), maximum=40)
    if not coverage_status:
        if str(scan_status) == "cancelled" or counts.get("cancelled"):
            coverage_status = "cancelled"
        elif counts.get("failed") or counts.get("blocked"):
            coverage_status = "failed"
        elif required_nonterminal and not scan_terminal:
            coverage_status = "in_progress"
        elif required_incomplete or zero_attempt_verifiers:
            coverage_status = "partial"
        elif any(item["status"] not in _TERMINAL for item in capability_rows):
            coverage_status = "in_progress"
        else:
            coverage_status = "complete"
    report_declares_unreliable = report_reliability.get("reliable") is False
    if report_declares_unreliable and not reliability_reasons:
        # The finalizer is authoritative. Historical reports did not always
        # persist a specific reason, so keep those fail-closed too.
        reliability_reasons = ["report_grade_unreliable"]
    grade_reliable = (
        not report_declares_unreliable
        and not reliability_reasons
        and coverage_status == "complete"
    )
    optional_gaps = [
        {
            "action_id": item["action_id"],
            "occurrence_id": item["occurrence_id"],
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
    allocated_budget = _sum_budgets(
        item["budget"]["allocated"] for item in actions
    )
    reserved_budget = _sum_budgets(
        item["budget"]["reserved"] for item in actions
    )
    consumed_budget = _sum_budgets(
        item["budget"]["consumed"] for item in actions
    )
    released_budget = _sum_budgets(
        item["budget"]["released"] for item in actions
    )
    uncertain_budget = _sum_budgets(
        item["budget"]["uncertain"] for item in actions
    )
    limit_budget = _scan_budget_limits(plan_budget_limits)
    if not limit_budget:
        limit_budget = dict(allocated_budget)
    budget_summary = {
        "limit": limit_budget,
        "allocated": allocated_budget,
        "reserved": reserved_budget,
        "consumed": consumed_budget,
        "released": released_budget,
        "uncertain": uncertain_budget,
        "unallocated": _budget_difference(limit_budget, allocated_budget),
    }
    return {
        "schema_version": EXPLANATION_SCHEMA,
        "scan_id": str(scan_id),
        "scan_status": str(scan_status or "unknown"),
        "plan_digest": plan_digest,
        "plan_revision": public_revision,
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
        "budget": budget_summary,
        "coverage": {
            "status": coverage_status,
            "capability_coverage": capability_coverage,
            "grade_reliability": {
                "reliable": grade_reliable,
                "reasons": reliability_reasons,
                "reason_labels": [_reason_label(item) for item in reliability_reasons],
                "warning": (
                    None
                    if grade_reliable
                    else (
                        "The grade will be finalized after required actions finish."
                        if coverage_status == "in_progress"
                        else (
                            "The grade is provisional because required coverage did not complete cleanly."
                            if coverage_status != "complete"
                            else "The grade is provisional until the listed verification conditions are resolved."
                        )
                    )
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
        "plan_revision": dict(explanation.get("plan_revision") or {}),
        "stage_timeline": list(explanation.get("stage_timeline") or []),
        "actions": list(explanation.get("actions") or []),
        "budget": dict(explanation.get("budget") or {}),
        "transport_parity": dict(explanation.get("transport_parity") or {}),
    }


def capability_list_response(explanation: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": CAPABILITY_LIST_SCHEMA,
        "scan_id": explanation.get("scan_id"),
        "plan_digest": explanation.get("plan_digest"),
        "plan_revision": dict(explanation.get("plan_revision") or {}),
        "capabilities": list(explanation.get("capabilities") or []),
        "budget": dict(explanation.get("budget") or {}),
        "capability_coverage": dict(
            _object(explanation.get("coverage")).get("capability_coverage") or {}
        ),
    }


def coverage_response(explanation: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": COVERAGE_SCHEMA,
        "scan_id": explanation.get("scan_id"),
        "plan_digest": explanation.get("plan_digest"),
        "plan_revision": dict(explanation.get("plan_revision") or {}),
        "budget": dict(explanation.get("budget") or {}),
        **dict(explanation.get("coverage") or {}),
        "transport_parity": dict(explanation.get("transport_parity") or {}),
    }
