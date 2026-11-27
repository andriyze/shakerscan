"""Truthful parent-result normalization for parallel Scan execution."""

from __future__ import annotations

from typing import Any, Mapping


def mark_parallel_parent_degraded(
    merged: dict[str, Any],
    *,
    failed_count: int,
    total_count: int,
    cancelled_count: int = 0,
    partial_count: int = 0,
) -> bool:
    """Mark a merged parent incomplete when any required shard is not complete."""
    incomplete_count = max(0, failed_count) + max(0, cancelled_count) + max(0, partial_count)
    if incomplete_count <= 0 or total_count <= 0:
        return False
    completed_count = max(0, total_count - incomplete_count)
    details = ", ".join(
        item for item in (
            f"{failed_count} failed" if failed_count else "",
            f"{cancelled_count} cancelled" if cancelled_count else "",
            f"{partial_count} partial" if partial_count else "",
        ) if item
    )
    if completed_count:
        reason = (
            f"Parallel scan has incomplete execution ({details}; {incomplete_count}/{total_count} shard(s)); "
            "grade is not reliable for full shard coverage"
        )
    else:
        reason = (
            f"Parallel scan has no fully completed shard ({details}); "
            "grade is not reliable"
        )

    parallel = merged.setdefault("parallel", {})
    if isinstance(parallel, dict):
        parallel["degraded"] = True
        parallel["degrade_reason"] = reason

    meta = merged.setdefault("scan_metadata", {})
    if isinstance(meta, dict):
        meta["partial"] = True
        meta["degraded"] = True
        meta["grade_reliable"] = False
        meta["parallel_shards_failed"] = failed_count
        meta["parallel_shards_cancelled"] = cancelled_count
        meta["parallel_shards_partial"] = partial_count
        meta["parallel_shards_total"] = total_count

    result = merged.setdefault("result", {})
    if isinstance(result, dict):
        result["grade_reliable"] = False
        result["degraded"] = True
        result["grade_warning"] = reason
        issues = result.get("coverage_issues")
        if not isinstance(issues, list):
            issues = [str(issues)] if issues else []
        if reason not in issues:
            issues.append(reason)
        result["coverage_issues"] = issues
        grade = result.get("grade")
        if grade is not None:
            grade_text = str(grade)
            if not grade_text.endswith("*"):
                result.setdefault("original_grade", grade_text)
                result["grade"] = f"{grade_text}*"
    return True


def mark_parallel_parent_coverage_incomplete(merged: dict[str, Any]) -> bool:
    """Make a requested non-shard coverage failure authoritative on the parent."""
    coverage = merged.get("coverage") if isinstance(merged.get("coverage"), dict) else {}
    status = str(coverage.get("status") or "").strip().lower()
    if status not in {"partial", "failed", "cancelled"}:
        return False
    reasons = sorted({
        str(item).strip() for item in coverage.get("reasons") or ()
        if str(item).strip()
    } or {f"coverage_{status}"})
    coverage["grade_reliability"] = {
        "reliable": False,
        "reasons": reasons,
    }
    merged["coverage"] = coverage

    meta = merged.setdefault("scan_metadata", {})
    if isinstance(meta, dict):
        meta["partial"] = True
        meta["degraded"] = True
        meta["grade_reliable"] = False
        meta["grade_reliability_reasons"] = reasons

    result = merged.setdefault("result", {})
    if isinstance(result, dict):
        result["grade_reliable"] = False
        result["degraded"] = True
        reason = "Requested scan coverage did not complete: " + ", ".join(reasons)
        result["grade_warning"] = reason
        issues = result.get("coverage_issues")
        if not isinstance(issues, list):
            issues = [str(issues)] if issues else []
        if reason not in issues:
            issues.append(reason)
        result["coverage_issues"] = issues
        grade = result.get("grade")
        if grade is not None and not str(grade).endswith("*"):
            result.setdefault("original_grade", str(grade))
            result["grade"] = f"{grade}*"
    return True


def apply_parallel_action_budget(
    merged: dict[str, Any],
    canonical_action_merge: Mapping[str, Any],
) -> dict[str, int]:
    """Make parent summary usage agree with the merged action ledger."""
    budget_used: dict[str, int] = {}
    for action in canonical_action_merge.get("actions") or ():
        if not isinstance(action, Mapping):
            continue
        for name, amount in (action.get("budget_consumed") or {}).items():
            try:
                value = max(0, int(amount or 0))
            except (TypeError, ValueError):
                continue
            budget_used[str(name)] = budget_used.get(str(name), 0) + value
    metadata = merged.setdefault("scan_metadata", {})
    if isinstance(metadata, dict):
        metadata["budget_used"] = budget_used
    return budget_used


__all__ = (
    "apply_parallel_action_budget",
    "mark_parallel_parent_coverage_incomplete",
    "mark_parallel_parent_degraded",
)
