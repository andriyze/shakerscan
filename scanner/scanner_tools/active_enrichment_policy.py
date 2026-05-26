"""Shared decisions for optional post-active DAST enrichment modules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


ACTIVE_ENRICHMENT_SKIP_KEYS: dict[str, str] = {
    "auxiliary_injection": "auxiliary_injection_skipped",
    "stored_xss": "stored_xss_skipped",
    "sqlmap": "sqlmap_skipped",
    "nosql_injection": "nosql_skipped",
    "dom_xss": "dom_xss_skipped",
    "bola_idor": "smart_bola_skipped",
}


@dataclass(frozen=True)
class ActiveEnrichmentDecision:
    module: str
    run: bool
    reason: str | None = None


def post_active_skip_reason(active_block: dict[str, Any] | None) -> str:
    """Return the canonical reason for skipping optional post-active modules."""
    active_block = active_block or {}
    return str(active_block.get("post_active_enrichment_skipped") or "active_time_budget_exhausted")


def should_run_active_enrichment(
    module: str,
    *,
    post_active_budget_exhausted: bool,
    active_block: dict[str, Any] | None,
) -> ActiveEnrichmentDecision:
    """Decide whether a post-active enrichment module should run."""
    if post_active_budget_exhausted:
        decision = ActiveEnrichmentDecision(
            module=module,
            run=False,
            reason=post_active_skip_reason(active_block),
        )
    else:
        decision = ActiveEnrichmentDecision(module=module, run=True)

    if active_block is not None:
        active_block.setdefault("active_enrichment_decisions", {})[module] = {
            "run": decision.run,
            "reason": decision.reason,
        }
    return decision


def record_active_enrichment_skip(
    active_block: dict[str, Any],
    module: str,
    reason: str,
    *,
    candidate_reason: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Record a skip reason using the report fields existing consumers expect."""
    skip_key = ACTIVE_ENRICHMENT_SKIP_KEYS.get(module, f"{module}_skipped")
    if skip_key == "sqlmap_skipped":
        entry = {
            "skip_reason": reason,
            "candidate_reason": candidate_reason or "post_active_budget",
        }
        if details:
            entry.update(details)
        active_block.setdefault(skip_key, []).append(entry)
        return

    active_block[skip_key] = reason
