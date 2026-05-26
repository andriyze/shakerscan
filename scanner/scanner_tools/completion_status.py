"""Build explicit scan completion and budget-limitation metadata."""

from __future__ import annotations

from typing import Any


ACTIVE_SKIP_FIELDS: dict[str, str] = {
    "auxiliary_injection_skipped": "auxiliary_injection",
    "stored_xss_skipped": "stored_xss",
    "sqlmap_skipped": "sqlmap",
    "nosql_skipped": "nosql_injection",
    "dom_xss_skipped": "dom_xss",
    "smart_bola_skipped": "bola_idor",
}

BUDGET_REASON_TOKENS = ("budget", "exhausted", "time_budget")


def _clean_reason(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("reason", "candidate_reason", "skip_reason", "error"):
            if value.get(key):
                return str(value[key])
        return None
    if isinstance(value, list):
        reasons = []
        for item in value:
            reason = _clean_reason(item)
            if reason and reason not in reasons:
                reasons.append(reason)
        return ", ".join(reasons) if reasons else None
    return str(value)


def _skip_entry(
    module: str,
    *,
    reason: str | None,
    phase: str,
    impact: str,
    configured: bool = False,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "module": module,
        "phase": phase,
        "impact": impact,
        "configured": configured,
    }
    if reason:
        entry["reason"] = reason
    return entry


def _append_unique(items: list[dict[str, Any]], entry: dict[str, Any]) -> None:
    key = (
        entry.get("module"),
        entry.get("phase"),
        entry.get("reason"),
        entry.get("impact"),
    )
    for existing in items:
        existing_key = (
            existing.get("module"),
            existing.get("phase"),
            existing.get("reason"),
            existing.get("impact"),
        )
        if existing_key == key:
            return
    items.append(entry)


def _int_or_none(value: Any) -> int | None:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _reason_is_budget_limited(reason: str | None) -> bool:
    reason_l = (reason or "").lower()
    return any(token in reason_l for token in BUDGET_REASON_TOKENS)


def _checks_skipped_entries(checks_skipped: list[Any] | None) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for raw in checks_skipped or []:
        if isinstance(raw, str):
            module = raw
            reason = None
            impact = "not_run"
            configured = False
        elif isinstance(raw, dict):
            module = str(raw.get("check") or raw.get("name") or raw.get("module") or "unknown")
            reason = _clean_reason(raw)
            impact = str(raw.get("impact") or "not_run")
            configured = bool(raw.get("configured", True))
        else:
            module = str(raw)
            reason = None
            impact = "not_run"
            configured = False
        _append_unique(
            entries,
            _skip_entry(
                module,
                reason=reason,
                phase="configuration",
                impact=impact,
                configured=configured,
            ),
        )
    return entries


def _active_skip_entries(active_block: dict[str, Any] | None) -> tuple[list[dict[str, Any]], bool, str | None]:
    active_block = active_block or {}
    entries: list[dict[str, Any]] = []
    budget_exhausted_at = None
    budget_exhausted = False

    post_reason = _clean_reason(active_block.get("post_active_enrichment_skipped"))
    if post_reason:
        budget_exhausted = True
        budget_exhausted_at = "active_enrichment"

    for field, module in ACTIVE_SKIP_FIELDS.items():
        if field not in active_block:
            continue
        reason = _clean_reason(active_block.get(field)) or post_reason or "not_run"
        if _reason_is_budget_limited(reason):
            budget_exhausted = True
            budget_exhausted_at = budget_exhausted_at or "active_enrichment"
        _append_unique(
            entries,
            _skip_entry(
                module,
                reason=reason,
                phase="active_enrichment",
                impact="not_tested",
            ),
        )

    return entries, budget_exhausted, budget_exhausted_at


def _active_endpoint_cap(active_block: dict[str, Any] | None) -> dict[str, Any] | None:
    active_block = active_block or {}
    discovered = _int_or_none(active_block.get("active_endpoints_discovered"))
    selected = _int_or_none(active_block.get("active_endpoints_selected"))
    budget = _int_or_none(active_block.get("active_endpoint_budget"))
    if discovered is None and selected is None and budget is None:
        return None

    tested = _int_or_none(active_block.get("smart_total_endpoints_tested"))
    capped = bool(active_block.get("active_endpoint_budget_capped"))
    if discovered is not None and selected is not None:
        capped = capped or selected < discovered

    entry: dict[str, Any] = {
        "discovered": discovered,
        "selected": selected,
        "tested": tested,
        "budget": budget,
        "capped": capped,
    }
    return {k: v for k, v in entry.items() if v is not None}


def _discovery_url_cap(discovery_summary: dict[str, Any] | None) -> dict[str, Any] | None:
    discovery_summary = discovery_summary or {}
    caps = discovery_summary.get("url_budget_caps") or []
    if not isinstance(caps, list) or not caps:
        return None

    capped_caps = [cap for cap in caps if isinstance(cap, dict) and cap.get("capped")]
    if not capped_caps:
        return None

    discovered_values = [_int_or_none(cap.get("discovered")) for cap in capped_caps]
    selected_values = [_int_or_none(cap.get("selected")) for cap in capped_caps]
    budget_values = [_int_or_none(cap.get("budget")) for cap in capped_caps]
    reasons = [
        str(cap.get("reason"))
        for cap in capped_caps
        if cap.get("reason")
    ]
    return {
        "discovered": max([v for v in discovered_values if v is not None], default=None),
        "selected": min([v for v in selected_values if v is not None], default=None),
        "budget": max([v for v in budget_values if v is not None], default=None),
        "capped": True,
        "reasons": reasons,
    }


def build_scan_completion_status(
    *,
    coverage_status: str | None,
    checks_skipped: list[Any] | None = None,
    active_block: dict[str, Any] | None = None,
    discovery_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return root-level report metadata describing incomplete or limited scans."""
    skipped_modules = _checks_skipped_entries(checks_skipped)
    active_entries, budget_exhausted, budget_exhausted_at = _active_skip_entries(active_block)
    for entry in active_entries:
        _append_unique(skipped_modules, entry)

    capped_lists: dict[str, Any] = {}
    active_cap = _active_endpoint_cap(active_block)
    if active_cap:
        capped_lists["active_endpoints"] = active_cap
    discovery_cap = _discovery_url_cap(discovery_summary)
    if discovery_cap:
        capped_lists["urls"] = {k: v for k, v in discovery_cap.items() if v is not None}

    any_capped = any(bool(value.get("capped")) for value in capped_lists.values() if isinstance(value, dict))
    if any_capped and not budget_exhausted:
        budget_exhausted = True
        budget_exhausted_at = (
            "active_endpoint_selection"
            if (capped_lists.get("active_endpoints") or {}).get("capped")
            else "discovery"
        )
    limited = bool(skipped_modules or any_capped)
    normalized_coverage = coverage_status or "unknown"

    return {
        "complete": normalized_coverage == "complete" and not budget_exhausted,
        "limited": limited,
        "coverage_status": normalized_coverage,
        "budget_exhausted": budget_exhausted,
        "budget_exhausted_at": budget_exhausted_at,
        "skipped_modules": skipped_modules,
        "capped_lists": capped_lists,
        "summary": {
            "skipped_modules": len(skipped_modules),
            "capped_lists": sum(
                1
                for value in capped_lists.values()
                if isinstance(value, dict) and value.get("capped")
            ),
        },
    }
