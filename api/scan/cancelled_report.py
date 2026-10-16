"""The report a cancelled Scan keeps.

Cancellation stops execution: no action starts after it, and the running one is stopped. It
does not discard what the actions that had already settled confirmed. The worker finalizes
those receipts with the same pure finalizer (no target traffic), marks the report cancelled,
and keeps its findings; the Scan stays ``cancelled``.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Awaitable, Callable
import uuid

from .continuation_rounds import prepare_local_scan_continuation


CANCELLED_REPORT_KEPT = "cancelled_report_kept"


def mark_cancelled_scan_report(
    report: dict[str, Any], *, finalizer_completed: bool = False,
) -> dict[str, Any]:
    """Mark a report built after cancellation: cancelled coverage, findings kept.

    ``finalizer_completed`` marks a report whose finalizer had already run when the
    cancellation was seen (it arrived while the report was being finalized or stored): the
    finalization action keeps its own status, and the record says it ran before.
    """
    coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else {}
    reasons = [str(item) for item in coverage.get("reasons") or () if str(item).strip()]
    report["coverage"] = {
        **coverage,
        "status": "cancelled",
        "reasons": [*reasons, *([] if "cancelled" in reasons else ["cancelled"])],
    }
    metadata = report.get("scan_metadata") if isinstance(report.get("scan_metadata"), dict) else {}
    reliability = [str(item) for item in metadata.get("grade_reliability_reasons") or () if str(item).strip()]
    report["scan_metadata"] = {
        **metadata,
        "status": "cancelled",
        "partial": True,
        "cancelled": True,
        CANCELLED_REPORT_KEPT: True,
        "grade_reliable": False,
        "grade_reliability_reasons": [*reliability, *([] if "cancelled" in reliability else ["cancelled"])],
    }
    # The report was built without running the finalization action, which the cancellation
    # settled or never planned: the execution record says so instead of claiming success.
    execution = report.get("canonical_action_execution")
    if isinstance(execution, dict) and finalizer_completed:
        execution["finalized_before_cancellation"] = True
        return report
    if isinstance(execution, dict):
        finalization = execution.get("finalization_action")
        if isinstance(finalization, dict):
            execution["finalization_action"] = {**finalization, "status": "cancelled"}
            matrix = execution.get("status_matrix")
            action_id = finalization.get("action_id")
            if isinstance(matrix, dict) and action_id in matrix:
                execution["status_matrix"] = {**matrix, action_id: "cancelled"}
        execution["finalized_after_cancellation"] = True
    return report


def finalized_canonical_report(result: Any) -> bool:
    """A complete canonical Scan report (its finalizer ran), not yet marked cancelled."""
    return (
        isinstance(result, dict)
        and not result.get("error")
        and isinstance(result.get("canonical_action_execution"), dict)
        and not is_kept_cancelled_report(result)
    )


def keep_report_finalized_before_cancellation(result: Any, scan_status: Any) -> Any:
    """A report finalized before a cancellation was seen, kept for the cancelled Scan.

    The finalizer had already confirmed these findings (no traffic is sent after it), so a
    cancellation that arrives while the report is finalized or stored keeps them. Any other
    result, or a Scan that is not cancelled, is returned unchanged.
    """
    if str(scan_status or "") not in {"cancelled", "cancelling"} or not finalized_canonical_report(result):
        return result
    return mark_cancelled_scan_report(result, finalizer_completed=True)


def cancelled_parallel_parent_report(
    *, target_url: Any, children: Any, merge_key: Callable[[dict[str, Any]], str],
    extra_findings: Any = (),
) -> dict[str, Any]:
    """The kept report of a cancelled parallel Scan: the union of what its shards kept.

    ``children`` are the shard rows (``id``, ``status``, ``shard_index``, ``result``). A
    completed shard and a cancelled shard with a kept report contribute their findings; a
    shard cancelled before it ran, or one that failed, contributes none. Pure: the caller
    persists it under the parent, which stays cancelled.
    """
    union: dict[str, dict[str, Any]] = {}
    shards = []
    kept = 0

    def add(finding: Any) -> None:
        if isinstance(finding, dict):
            union.setdefault(merge_key(finding), finding)

    for child in children or ():
        result = child.get("result")
        if isinstance(result, str):
            try:
                result = json.loads(result)
            except ValueError:
                result = None
        status = str(child.get("status") or "")
        contributes = isinstance(result, dict) and not result.get("error") and (
            status == "completed" or (status == "cancelled" and is_kept_cancelled_report(result))
        )
        findings = (result.get("findings") if contributes else None) or []
        if contributes:
            kept += 1
            for finding in findings:
                add(finding)
        shards.append({
            "scan_id": str(child.get("id") or ""),
            "shard_index": child.get("shard_index"),
            "status": status,
            "findings_kept": len(findings) if isinstance(findings, list) else 0,
        })
    for finding in extra_findings or ():
        add(finding)
    report = {
        "target": target_url,
        "findings": list(union.values()),
        "result": {"score": None, "grade": None},
        "coverage": {"status": "cancelled", "reasons": ["cancelled"]},
        "scan_metadata": {},
        "parallel": {"shards": shards, "shards_total": len(shards), "shards_kept": kept},
    }
    return mark_cancelled_scan_report(report)


def is_kept_cancelled_report(result: Any) -> bool:
    metadata = result.get("scan_metadata") if isinstance(result, dict) else None
    return isinstance(metadata, dict) and metadata.get(CANCELLED_REPORT_KEPT) is True and not result.get("error")


async def build_cancelled_scan_report(
    dispatcher: Any, *, scan_id: str, finalization: Any = None,
) -> dict[str, Any]:
    """The report of a cancelled Scan from its settled receipts (no target traffic).

    ``finalization`` is ``(plan, revision)`` of a finalize-only revision compiled for a work
    round that was cancelled before its finalizer was planned; it is not persisted, because a
    cancelled Scan's plan is frozen. A report that cannot be built (an action of the plan is not
    terminal) falls back to the earlier outcome: the cancellation error, with no findings kept.
    """
    try:
        if finalization is None:
            report = await dispatcher.build_scan_report()
        else:
            plan, revision = finalization
            report = await dispatcher.build_scan_report(plan=plan, plan_revision=revision)
            # Its finalize-only revision was compiled for this report and never stored: a
            # reader must not look for it among the Scan's stored revisions.
            execution = report.get("canonical_action_execution")
            if isinstance(execution, dict):
                execution["plan_revision_stored"] = False
    except Exception as exc:
        print(
            f"[scan] cancelled scan {str(scan_id)[:8]} report could not be built "
            f"({type(exc).__name__}); no findings are kept",
            file=sys.stderr, flush=True,
        )
        raise ValueError("Cancelled by user") from exc
    return mark_cancelled_scan_report(report)


async def cancelled_scan_report(
    dispatcher: Any, *, scan_id: str, load_allocation: Callable[[], Awaitable[Any]], runtime: Any,
) -> dict[str, Any]:
    """The kept report of a Scan cancelled in any round.

    A round that planned the finalizer reports over its own plan. A work round has none: the
    finalize-only revision the normal path would have run is compiled (never persisted) and the
    report is built over it. Anything missing falls back to the cancellation error.
    """
    finalization = None
    if not any(action.action_id == "finalize.report" for action in dispatcher.plan.actions):
        try:
            allocation = await load_allocation()
            results = {
                action.action_id: await dispatcher.backend.load_result(action.action_id)
                for action in dispatcher.plan.actions
            }
            revision = dispatcher.plan_revision
            prepared = await prepare_local_scan_continuation(
                runtime, parent_plan=dispatcher.plan, allocation=allocation,
                parent_results=results,
                revision_number=(int(revision.revision) if revision is not None else 0) + 1,
                include_finalizer=True, finalize_only=True,
            ) if allocation is not None and None not in results.values() else None
            if prepared is not None:
                finalization = (prepared.plan, prepared.revision)
        except Exception as exc:
            print(f"[scan] cancelled scan {str(scan_id)[:8]} finalization revision could not be "
                  f"compiled ({type(exc).__name__})", file=sys.stderr, flush=True)
        if finalization is None:
            raise ValueError("Cancelled by user")
    return await build_cancelled_scan_report(dispatcher, scan_id=scan_id, finalization=finalization)


async def persist_kept_cancelled_scan(
    pool: Any, *, scan_id: str, result: dict[str, Any], completed_at: Any, duration: int,
    coverage: dict[str, Any], budget_used: dict[str, Any] | None,
) -> bool:
    """Store a cancelled Scan's kept report; the row stays cancelled. False if it is not.

    ``budget_used`` None keeps the row's ledger (a shard's is reconciled by its actions).
    """
    findings = result.get("findings") if isinstance(result.get("findings"), list) else []
    async with pool.acquire() as conn:
        kept = await conn.fetchval(
            """UPDATE scans SET status='cancelled', result=$2, findings_count=$3,
                      completed_at=COALESCE(completed_at, $4), duration_seconds=$5,
                      progress=100, current_phase='cancelled',
                      error_message=COALESCE(error_message, 'Cancelled by user'),
                      score=NULL, grade=NULL,
                      coverage_status=$6, coverage_json=$7,
                      budget_used_json=COALESCE($8::jsonb, budget_used_json),
                      assurance_score=COALESCE(assurance_score, 0)
                WHERE id=$1 AND status IN ('cancelled','cancelling')
            RETURNING id""",
            uuid.UUID(str(scan_id)), json.dumps(result), len(findings), completed_at,
            duration, str(coverage.get("status") or "cancelled"), json.dumps(coverage),
            json.dumps(budget_used) if budget_used is not None else None,
        )
    return kept is not None


__all__ = [
    "CANCELLED_REPORT_KEPT",
    "build_cancelled_scan_report",
    "cancelled_parallel_parent_report",
    "cancelled_scan_report",
    "finalized_canonical_report",
    "keep_report_finalized_before_cancellation",
    "is_kept_cancelled_report",
    "mark_cancelled_scan_report",
    "persist_kept_cancelled_scan",
]
